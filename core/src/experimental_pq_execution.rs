//! Bounded native SVM execution for experimental PQ blocks.
//!
//! A wave contains only transactions whose complete account accesses commute.
//! Waves preserve FIFO conflict order, and every worker uses the ordinary Bank
//! account locks, authentication gate, SVM and commit path. Cost reservations
//! and refunds are applied in input order between waves. An already committed
//! transaction can never be silently removed from a block.
use {
    anyhow::{Result, ensure},
    rayon::prelude::*,
    solana_account::ReadableAccount,
    solana_cost_model::{cost_model::CostModel, transaction_cost::TransactionCost},
    solana_ledger::blockstore::ExperimentalPqTransaction,
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_pubkey::Pubkey,
    solana_runtime::{bank::Bank, pq},
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction,
        transaction_with_meta::{TransactionWithMeta, writable_accounts},
    },
    solana_svm::{
        transaction_commit_result::TransactionCommitResult,
        transaction_processor::ExecutionRecordingConfig,
    },
    solana_svm_timings::ExecuteTimings,
    solana_svm_transaction::svm_message::SVMMessage,
    solana_transaction::{
        sanitized::{MessageHash, SanitizedTransaction},
        versioned::VersionedTransaction,
    },
    solana_transaction_error::TransactionError,
    solana_transaction_status::TransactionStatusMeta,
    std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    },
};

const MAX_TRANSACTIONS: usize = 8192;
const MAX_WORKERS: usize = 32;
// Bound scheduling and simultaneous worst-case compute reservations even when
// all transactions are independent. Each worker executes a native batch.
const TRANSACTIONS_PER_WORKER: usize = 16;
const MAX_POLICY_ADDRESSES: usize = 4096;

/// Memoize only the deterministic address derivation, never AUTH account data
/// or its authorization result. This map lives for one execute call, needs no
/// synchronization, and retains at most 4096 complete signer/address pairs.
#[derive(Default)]
struct PolicyAddresses {
    addresses: HashMap<Pubkey, Pubkey>,
}

impl PolicyAddresses {
    fn derive(&mut self, signer: &Pubkey) -> Pubkey {
        if let Some(address) = self.addresses.get(signer) {
            return *address;
        }
        let address = pq::policy_address(signer);
        if self.addresses.len() < MAX_POLICY_ADDRESSES {
            self.addresses.insert(*signer, address);
        }
        address
    }
}

pub(crate) struct PqExecutor {
    pool: Arc<rayon::ThreadPool>,
}

#[derive(Default, Debug)]
pub(crate) struct PqExecutionTimings {
    /// Sum of each wave's longest worker SVM call, an execution wall estimate.
    pub native_us: u64,
    /// Remaining execution wall time, including unmeasured parallel framing.
    /// This residual is neither a CPU total nor exclusively serial work.
    pub bridge_us: u64,
    /// Sum of all worker SVM call durations, for parallelism diagnostics.
    pub native_worker_us: u64,
    /// Serial preparation wall, including repeated boundary/budget attempts
    /// and noncommitted preparation errors.
    pub prepare_us: u64,
    /// Serial explicit/implicit dependency discovery, conflict checks and
    /// dependency-cache bookkeeping.
    pub access_discovery_us: u64,
    /// Serial native cost reservation, including cost-tracker lock waits.
    pub cost_reserve_us: u64,
    /// Complete pool dispatch/join wall, including the native SVM calls.
    /// Do not add this interval to native_us or pool_overhead_us.
    pub pool_dispatch_join_us: u64,
    /// Pool wall minus its longest native call for each wave. Includes
    /// parallel locking, balance reads and framing; this is not CPU time.
    pub pool_overhead_us: u64,
    /// Serial native cost refunds and committed receipt reconciliation.
    pub reconcile_us: u64,
    /// Bridge wall outside the disjoint measured bridge intervals. Includes
    /// serial partitioning/allocation and timer/bookkeeping overhead.
    pub bridge_residual_us: u64,
}

pub(crate) struct PqExecutionOutput {
    /// Applied input prefix, in exact input order. An Ok can contain a charged
    /// instruction error; an Err was not committed and has no account writes.
    pub records: Vec<std::result::Result<ExperimentalPqTransaction, TransactionError>>,
    /// This transaction and the entire following suffix were not executed.
    pub stopped_at: Option<usize>,
    pub timings: PqExecutionTimings,
    pub waves: usize,
    pub max_parallel_transactions: usize,
    pub peak_active_batches: usize,
}

#[derive(Debug)]
pub(crate) struct CommittedCostMismatch {
    pub reserved: u64,
    pub executed: u64,
}

impl std::fmt::Display for CommittedCostMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "committed PQ transaction cost {} exceeds reservation {}",
            self.executed, self.reserved
        )
    }
}

impl std::error::Error for CommittedCostMismatch {}

struct Prepared {
    index: usize,
    transaction: VersionedTransaction,
    sanitized: RuntimeTransaction<SanitizedTransaction>,
    keys: Vec<(Pubkey, bool)>,
    reservation: TransactionCost,
}

struct Executed {
    prepared: Prepared,
    committed: TransactionCommitResult,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
}

#[derive(Default)]
struct Accesses {
    // true is write access, false is read access. Shared reads commute.
    keys: HashMap<Pubkey, bool>,
    barrier: bool,
}

impl Accesses {
    fn conflicts(&self, other: &Self) -> bool {
        self.barrier
            || other.barrier
            || other.keys.iter().any(|(key, writable)| {
                self.keys
                    .get(key)
                    .is_some_and(|previous| *previous || *writable)
            })
    }

    fn extend(&mut self, other: Self) {
        self.barrier |= other.barrier;
        for (key, writable) in other.keys {
            *self.keys.entry(key).or_default() |= writable;
        }
    }
}

impl PqExecutor {
    pub fn new(workers: usize) -> Result<Self> {
        ensure!((1..=MAX_WORKERS).contains(&workers), "PQ execution workers");
        Ok(Self::with_pool(Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .thread_name(|index| format!("solPqSvm{index:02}"))
                .build()?,
        )))
    }

    pub fn with_pool(pool: Arc<rayon::ThreadPool>) -> Self {
        Self { pool }
    }

    /// Execute an ordered block or producer selection prefix. Only a fatal
    /// error can follow committed writes; callers must then discard the whole
    /// candidate. In particular they must not publish a shortened payload.
    pub fn execute(
        &self,
        bank: &Bank,
        transactions: &[VersionedTransaction],
    ) -> Result<PqExecutionOutput> {
        ensure!(transactions.len() <= MAX_TRANSACTIONS, "PQ execution count");
        ensure!(!bank.is_frozen(), "PQ execution requires an active Bank");
        let started = Instant::now();
        let mut records = (0..transactions.len()).map(|_| None).collect::<Vec<_>>();
        let mut next = 0;
        let mut programdata = HashMap::new();
        let mut policy_addresses = PolicyAddresses::default();
        let mut stopped_at = None;
        let mut timings = PqExecutionTimings::default();
        // Accumulate monotonic durations before converting to microseconds;
        // per-transaction truncation would hide short repeated phases.
        let mut prepare_wall = Duration::ZERO;
        let mut access_wall = Duration::ZERO;
        let mut reserve_wall = Duration::ZERO;
        let mut pool_wall = Duration::ZERO;
        let mut reconcile_wall = Duration::ZERO;
        let mut waves = 0;
        let mut max_parallel_transactions = 0;
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let max_wave = self.pool.current_num_threads().min(MAX_WORKERS) * TRANSACTIONS_PER_WORKER;
        while next < transactions.len() {
            let mut wave = Vec::new();
            let mut accesses = Accesses::default();
            while next < transactions.len() && wave.len() < max_wave {
                // ALT contents can change in a preceding transaction. Detect
                // that conflict before resolving addresses against this Bank.
                let access_started = Instant::now();
                let lookup_conflict = !wave.is_empty()
                    && lookup_tables(&transactions[next])
                        .any(|key| accesses.keys.get(key).is_some_and(|write| *write));
                access_wall = access_wall.saturating_add(access_started.elapsed());
                if lookup_conflict {
                    break;
                }
                let prepare_started = Instant::now();
                let prepared = prepare(bank, next, &transactions[next]);
                prepare_wall = prepare_wall.saturating_add(prepare_started.elapsed());
                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        records[next] = Some(Err(error));
                        next += 1;
                        continue;
                    }
                };
                let access_started = Instant::now();
                let candidate_accesses =
                    transaction_accesses(bank, &prepared, &mut programdata, &mut policy_addresses);
                let conflict = !wave.is_empty() && accesses.conflicts(&candidate_accesses);
                access_wall = access_wall.saturating_add(access_started.elapsed());
                if conflict {
                    break;
                }
                let reserve_started = Instant::now();
                let reservation = bank.write_cost_tracker().unwrap().try_add(
                    &prepared.reservation,
                    writable_accounts(&prepared.sanitized),
                );
                reserve_wall = reserve_wall.saturating_add(reserve_started.elapsed());
                if reservation.is_err() {
                    if wave.is_empty() {
                        stopped_at = Some(next);
                    }
                    // If a wave is pending, first apply its actual-cost
                    // refunds and retry this unchanged index. Only an empty
                    // wave proves that the remaining Bank budget cannot fit.
                    break;
                }
                let access_started = Instant::now();
                accesses.extend(candidate_accesses);
                access_wall = access_wall.saturating_add(access_started.elapsed());
                wave.push(prepared);
                next += 1;
                if accesses.barrier {
                    break;
                }
            }
            if wave.is_empty() {
                if stopped_at.is_some() {
                    break;
                }
                continue;
            }
            waves += 1;
            max_parallel_transactions = max_parallel_transactions.max(wave.len());
            let workers = self.pool.current_num_threads().min(MAX_WORKERS);
            let batch_size = wave.len().div_ceil(workers);
            let mut batches = Vec::new();
            let mut iterator = wave.into_iter();
            loop {
                let batch = iterator.by_ref().take(batch_size).collect::<Vec<_>>();
                if batch.is_empty() {
                    break;
                }
                batches.push(batch);
            }
            let pool_started = Instant::now();
            let batches = self.pool.install(|| {
                batches
                    .into_par_iter()
                    .map(|batch| execute_batch(bank, batch, &active, &peak))
                    .collect::<Vec<_>>()
            });
            pool_wall = pool_wall.saturating_add(pool_started.elapsed());
            let native_us = batches.iter().map(|(_, time)| *time).max().unwrap_or(0);
            timings.native_us = timings.native_us.saturating_add(native_us);
            let reconcile_started = Instant::now();
            for (results, native_us) in batches {
                timings.native_worker_us = timings.native_worker_us.saturating_add(native_us);
                for executed in results {
                    let index = executed.prepared.index;
                    records[index] = Some(reconcile(bank, executed)?);
                }
            }
            reconcile_wall = reconcile_wall.saturating_add(reconcile_started.elapsed());
            // A program account can be changed by a loader or another native
            // instruction. Resolve its ProgramData pointer again next wave.
            let access_started = Instant::now();
            programdata.retain(|key, _| !accesses.keys.get(key).is_some_and(|write| *write));
            access_wall = access_wall.saturating_add(access_started.elapsed());
        }
        records.truncate(stopped_at.unwrap_or(transactions.len()));
        let records = records
            .into_iter()
            .map(|record| record.expect("every applied PQ input has a result"))
            .collect();
        timings.bridge_us = elapsed_us(started).saturating_sub(timings.native_us);
        let duration_us =
            |duration: Duration| u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        timings.prepare_us = duration_us(prepare_wall);
        timings.access_discovery_us = duration_us(access_wall);
        timings.cost_reserve_us = duration_us(reserve_wall);
        timings.pool_dispatch_join_us = duration_us(pool_wall);
        timings.pool_overhead_us = timings
            .pool_dispatch_join_us
            .saturating_sub(timings.native_us);
        timings.reconcile_us = duration_us(reconcile_wall);
        let measured_bridge_us = timings
            .prepare_us
            .saturating_add(timings.access_discovery_us)
            .saturating_add(timings.cost_reserve_us)
            .saturating_add(timings.pool_overhead_us)
            .saturating_add(timings.reconcile_us);
        timings.bridge_residual_us = timings.bridge_us.saturating_sub(measured_bridge_us);
        Ok(PqExecutionOutput {
            records,
            stopped_at,
            timings,
            waves,
            max_parallel_transactions,
            peak_active_batches: peak.load(Ordering::Relaxed),
        })
    }
}

fn prepare(
    bank: &Bank,
    index: usize,
    transaction: &VersionedTransaction,
) -> std::result::Result<Prepared, TransactionError> {
    // Legacy migration transactions do not traverse classic TPU sigverify.
    // PQ witnesses are authenticated again under native account locks below.
    let message_hash = if pq::is_pq_transaction(transaction) {
        MessageHash::Precomputed(pq::canonical_message_hash(transaction)?)
    } else {
        bank.verify_pq_transaction_for_ingress(transaction)?;
        MessageHash::Compute
    };
    let sanitized = RuntimeTransaction::<SanitizedTransaction>::try_create(
        transaction.clone(),
        message_hash,
        None,
        bank,
        bank.get_reserved_account_keys(),
    )?;
    let keys = sanitized
        .account_keys()
        .iter()
        .enumerate()
        .map(|(index, key)| (*key, sanitized.is_writable(index)))
        .collect();
    let mut reservation = CostModel::calculate_cost(&sanitized, &bank.feature_set);
    reservation.loaded_accounts_data_size_cost = reservation
        .loaded_accounts_data_size_cost
        .max(CostModel::calculate_pages_cost(1));
    Ok(Prepared {
        index,
        transaction: transaction.clone(),
        sanitized,
        keys,
        reservation,
    })
}

fn lookup_tables(transaction: &VersionedTransaction) -> impl Iterator<Item = &Pubkey> {
    transaction
        .message
        .address_table_lookups()
        .unwrap_or_default()
        .iter()
        .map(|lookup| &lookup.account_key)
}

fn transaction_accesses(
    bank: &Bank,
    prepared: &Prepared,
    programdata: &mut HashMap<Pubkey, Option<Pubkey>>,
    policy_addresses: &mut PolicyAddresses,
) -> Accesses {
    let mut accesses = Accesses {
        keys: prepared.keys.iter().copied().collect(),
        barrier: prepared.keys.iter().any(|(program, _)| {
            // Deployment/upgrade has implicit ProgramData/cache effects. A
            // loader account anywhere in the message is a global barrier,
            // including custom programs that invoke a loader through CPI.
            program == &solana_sdk_ids::bpf_loader::id()
                || program == &solana_sdk_ids::bpf_loader_deprecated::id()
                || program == &solana_sdk_ids::bpf_loader_upgradeable::id()
                || program == &solana_sdk_ids::loader_v4::id()
        }),
    };
    // SBF program loading implicitly reads the UpgradeableLoader ProgramData
    // account. Include programs passed to CPI as well as top-level programs.
    // The per-block cache is invalidated for every declared account write.
    for (key, _) in &prepared.keys {
        let dependency = programdata.entry(*key).or_insert_with(|| {
            let account = bank.get_account(key)?;
            if account.owner() != &solana_sdk_ids::bpf_loader_upgradeable::id() {
                return None;
            }
            match wincode::deserialize::<UpgradeableLoaderState>(account.data()).ok()? {
                UpgradeableLoaderState::Program {
                    programdata_address,
                } => Some(programdata_address),
                _ => None,
            }
        });
        if let Some(key) = *dependency {
            accesses.keys.entry(key).or_default();
        }
    }
    for key in lookup_tables(&prepared.transaction) {
        accesses.keys.entry(*key).or_default();
    }
    // Pre-cutoff Ed messages also read these policies to reject a retired Ed
    // key. Their old ABI does not declare that account, so add its dependency.
    for signer in prepared
        .transaction
        .message
        .static_account_keys()
        .iter()
        .take(usize::from(
            prepared
                .transaction
                .message
                .header()
                .num_required_signatures,
        ))
    {
        // Always preserve the dependency, including on a memo hit. Policy
        // owner/data/generation and signature checks still read the live Bank.
        accesses
            .keys
            .entry(policy_addresses.derive(signer))
            .or_default();
    }
    accesses
}

fn execute_batch(
    bank: &Bank,
    batch: Vec<Prepared>,
    active: &AtomicUsize,
    peak: &AtomicUsize,
) -> (Vec<Executed>, u64) {
    let (sanitized, metadata): (Vec<_>, Vec<_>) = batch
        .into_iter()
        .map(|prepared| {
            (
                prepared.sanitized,
                (
                    prepared.index,
                    prepared.transaction,
                    prepared.keys,
                    prepared.reservation,
                ),
            )
        })
        .unzip();
    let locked = bank.prepare_sanitized_batch(&sanitized);
    let pre_balances = metadata
        .iter()
        .map(|(_, _, keys, _)| keys.iter().map(|(key, _)| bank.get_balance(key)).collect())
        .collect::<Vec<Vec<u64>>>();
    peak.fetch_max(
        active.fetch_add(1, Ordering::Relaxed) + 1,
        Ordering::Relaxed,
    );
    let started = Instant::now();
    let (committed, _) = bank.load_execute_and_commit_transactions(
        &locked,
        ExecutionRecordingConfig {
            enable_cpi_recording: false,
            enable_log_recording: true,
            enable_return_data_recording: true,
            enable_transaction_balance_recording: false,
        },
        &mut ExecuteTimings::default(),
        Some(1_000_000),
    );
    let native_us = elapsed_us(started);
    active.fetch_sub(1, Ordering::Relaxed);
    let post_balances = metadata
        .iter()
        .map(|(_, _, keys, _)| keys.iter().map(|(key, _)| bank.get_balance(key)).collect())
        .collect::<Vec<Vec<u64>>>();
    drop(locked);
    let executed = sanitized
        .into_iter()
        .zip(metadata)
        .zip(committed)
        .zip(pre_balances.into_iter().zip(post_balances))
        .map(
            |(
                ((sanitized, (index, transaction, keys, reservation)), committed),
                (pre_balances, post_balances),
            )| {
                Executed {
                    prepared: Prepared {
                        index,
                        transaction,
                        sanitized,
                        keys,
                        reservation,
                    },
                    committed,
                    pre_balances,
                    post_balances,
                }
            },
        )
        .collect();
    (executed, native_us)
}

fn reconcile(
    bank: &Bank,
    executed: Executed,
) -> Result<std::result::Result<ExperimentalPqTransaction, TransactionError>> {
    let Executed {
        prepared,
        committed,
        pre_balances,
        post_balances,
    } = executed;
    let committed = match committed {
        Ok(committed) => committed,
        Err(error) => {
            bank.write_cost_tracker().unwrap().remove(
                &prepared.reservation,
                writable_accounts(&prepared.sanitized),
            );
            return Ok(Err(error));
        }
    };
    let actual_cost = CostModel::calculate_cost_for_executed_transaction(
        &prepared.sanitized,
        committed.executed_units,
        committed.loaded_account_stats.loaded_accounts_data_size,
        &bank.feature_set,
    );
    let reserved_execution = prepared
        .reservation
        .programs_execution_cost()
        .saturating_add(prepared.reservation.loaded_accounts_data_size_cost());
    let actual_execution = actual_cost
        .programs_execution_cost()
        .saturating_add(actual_cost.loaded_accounts_data_size_cost());
    if actual_execution > reserved_execution {
        return Err(CommittedCostMismatch {
            reserved: reserved_execution,
            executed: actual_execution,
        }
        .into());
    }
    bank.write_cost_tracker().unwrap().update_cost(
        reserved_execution,
        actual_execution,
        writable_accounts(&prepared.sanitized),
    );
    let status = TransactionStatusMeta {
        status: committed.status,
        fee: committed.fee_details.total_fee(),
        pre_balances,
        post_balances,
        log_messages: committed.log_messages,
        loaded_addresses: prepared
            .sanitized
            .as_sanitized_transaction()
            .get_loaded_addresses(),
        return_data: committed.return_data,
        compute_units_consumed: Some(committed.executed_units),
        cost_units: Some(actual_cost.sum()),
        ..TransactionStatusMeta::default()
    };
    Ok(Ok((prepared.transaction, status, prepared.keys)))
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        agave_pq_crypto::{
            auth::{AuthRecord, Origin},
            crypto::FalconKeypair,
        },
        solana_account::Account,
        solana_address_lookup_table_interface::{
            instruction::freeze_lookup_table,
            state::{AddressLookupTable, LookupTableMeta},
        },
        solana_compute_budget_interface::ComputeBudgetInstruction,
        solana_cost_model::cost_tracker::CostTrackerLimits,
        solana_fee_calculator::FeeRateGovernor,
        solana_instruction::{AccountMeta, Instruction},
        solana_keypair::Keypair,
        solana_message::{AddressLookupTableAccount, Message, VersionedMessage, v0},
        solana_runtime::{
            bank_forks::BankForks, genesis_utils::create_genesis_config_with_leader,
            pq_workload as app,
        },
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
        std::sync::RwLock,
    };

    struct Fixture {
        root: Arc<Bank>,
        // Program-cache ancestry is supplied by the genuine BankForks graph.
        _forks: Arc<RwLock<BankForks>>,
        wallets: Vec<(Pubkey, FalconKeypair)>,
        recipients: Vec<Pubkey>,
        config: pq::Config,
        mint: Pubkey,
        token_sources: Vec<Pubkey>,
        token_destinations: Vec<Pubkey>,
        apps: Vec<app::Accounts>,
        lookup_table: Pubkey,
    }

    impl Fixture {
        fn new(wallet_count: usize) -> Self {
            let mut genesis = create_genesis_config_with_leader(
                10_000_000_000,
                &Pubkey::new_unique(),
                1_000_000_000,
            )
            .genesis_config;
            genesis.rent = solana_rent::Rent::default();
            genesis.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
            let config = pq::Config {
                chain_id: [0xe1; 32],
                migration_context: [0xe2; 32],
                cutoff_slot: 1,
            };
            genesis.accounts.insert(
                pq::CONFIG_ADDRESS,
                config.account(genesis.rent.minimum_balance(80)),
            );
            let wallets = (0..wallet_count)
                .map(|_| (Pubkey::new_unique(), FalconKeypair::generate()))
                .collect::<Vec<_>>();
            let recipients = (0..wallet_count)
                .map(|_| Pubkey::new_unique())
                .collect::<Vec<_>>();
            for ((authority, key), recipient) in wallets.iter().zip(&recipients) {
                for address in [authority, recipient] {
                    genesis.accounts.insert(
                        *address,
                        Account {
                            lamports: 100_000_000,
                            ..Account::default()
                        },
                    );
                }
                let data = AuthRecord::new(
                    authority.to_bytes(),
                    key.public_key(),
                    Origin::FreshIdentity,
                )
                .encode();
                genesis.accounts.insert(
                    pq::policy_address(authority),
                    Account {
                        lamports: genesis.rent.minimum_balance(data.len()),
                        data,
                        owner: pq::PROGRAM_ID,
                        rent_epoch: u64::MAX,
                        ..Account::default()
                    },
                );
            }
            let lookup_table = Pubkey::new_unique();
            let table_data = AddressLookupTable {
                meta: LookupTableMeta {
                    authority: Some(wallets[0].0),
                    ..LookupTableMeta::default()
                },
                addresses: recipients.clone().into(),
            }
            .serialize_for_tests()
            .unwrap();
            genesis.accounts.insert(
                lookup_table,
                Account {
                    lamports: genesis.rent.minimum_balance(table_data.len()),
                    data: table_data,
                    owner: solana_address_lookup_table_interface::program::id(),
                    ..Account::default()
                },
            );
            for (address, account) in solana_program_binaries::spl_programs(&genesis.rent) {
                genesis.accounts.insert(address, account.into());
            }
            for (address, account) in solana_program_binaries::by_id(
                &solana_address_lookup_table_interface::program::id(),
                &genesis.rent,
            )
            .unwrap()
            {
                genesis.accounts.insert(address, account.into());
            }
            for (address, account) in app::program_accounts(&genesis.rent) {
                genesis.accounts.insert(address, account);
            }
            let token = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
            let mint = Pubkey::new_unique();
            let mut mint_data = vec![0; 82];
            mint_data[..4].copy_from_slice(&1u32.to_le_bytes());
            mint_data[4..36].copy_from_slice(wallets[0].0.as_ref());
            mint_data[36..44].copy_from_slice(&(wallet_count as u64 * 1_000_000).to_le_bytes());
            mint_data[44] = 6;
            mint_data[45] = 1;
            genesis.accounts.insert(
                mint,
                Account {
                    lamports: genesis.rent.minimum_balance(mint_data.len()),
                    data: mint_data,
                    owner: token,
                    ..Account::default()
                },
            );
            let mut token_sources = Vec::new();
            let mut token_destinations = Vec::new();
            for (authority, _) in &wallets {
                for (amount, addresses) in [
                    (1_000_000u64, &mut token_sources),
                    (0u64, &mut token_destinations),
                ] {
                    let address = Pubkey::new_unique();
                    let mut data = vec![0; 165];
                    data[..32].copy_from_slice(mint.as_ref());
                    data[32..64].copy_from_slice(authority.as_ref());
                    data[64..72].copy_from_slice(&amount.to_le_bytes());
                    data[108] = 1;
                    genesis.accounts.insert(
                        address,
                        Account {
                            lamports: genesis.rent.minimum_balance(data.len()),
                            data,
                            owner: token,
                            ..Account::default()
                        },
                    );
                    addresses.push(address);
                }
            }
            let mut apps = Vec::new();
            for group in wallets.as_chunks::<3>().0 {
                let state = Pubkey::new_unique();
                let accounts = app::Accounts {
                    state,
                    sponsor: group[0].0,
                    primary: group[1].0,
                    secondary: group[2].0,
                    recipient: Pubkey::new_unique(),
                };
                genesis.accounts.insert(
                    state,
                    Account {
                        lamports: 10_000_000,
                        data: app::State::new(accounts.primary, accounts.secondary).encode(4096),
                        owner: app::PROGRAM_ID,
                        ..Account::default()
                    },
                );
                genesis.accounts.insert(
                    accounts.recipient,
                    Account {
                        lamports: 1_000_000,
                        ..Account::default()
                    },
                );
                apps.push(accounts);
            }
            let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis));
            let root = forks.read().unwrap().root_bank();
            root.freeze();
            Self {
                root,
                _forks: forks,
                wallets,
                recipients,
                config,
                mint,
                token_sources,
                token_destinations,
                apps,
                lookup_table,
            }
        }

        fn child(&self) -> Arc<Bank> {
            Arc::new(
                Bank::new_isolated_pq_child(
                    self.root.clone(),
                    *self.root.leader(),
                    self.root.slot() + 1,
                )
                .unwrap(),
            )
        }

        fn sign(&self, signers: &[usize], instructions: &[Instruction]) -> VersionedTransaction {
            let addresses = signers
                .iter()
                .map(|&index| self.wallets[index].0)
                .collect::<Vec<_>>();
            let mut all = vec![pq::authenticate_instruction(&addresses)];
            all.extend_from_slice(instructions);
            pq::sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &all,
                    Some(&addresses[0]),
                    &self.root.last_blockhash(),
                )),
                &self.config,
                &signers
                    .iter()
                    .map(|&index| &self.wallets[index].1)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        }

        fn transfer(&self, index: usize, recipient: Pubkey, amount: u64) -> VersionedTransaction {
            self.sign(
                &[index],
                &[system_instruction::transfer(
                    &self.wallets[index].0,
                    &recipient,
                    amount,
                )],
            )
        }

        fn token_transfer(&self, index: usize, amount: u64) -> VersionedTransaction {
            let mut data = vec![12]; // SPL TransferChecked, six decimals.
            data.extend_from_slice(&amount.to_le_bytes());
            data.push(6);
            self.sign(
                &[index],
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(100_000),
                    Instruction {
                        program_id: solana_pubkey::pubkey!(
                            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                        ),
                        accounts: vec![
                            AccountMeta::new(self.token_sources[index], false),
                            AccountMeta::new_readonly(self.mint, false),
                            AccountMeta::new(self.token_destinations[index], false),
                            AccountMeta::new_readonly(self.wallets[index].0, true),
                        ],
                        data,
                    },
                ],
            )
        }

        fn app_transaction(
            &self,
            group: usize,
            instruction: Instruction,
            multisig: bool,
        ) -> VersionedTransaction {
            let mut signers = vec![group * 3, group * 3 + 1];
            if multisig {
                signers.push(group * 3 + 2);
            }
            self.sign(
                &signers,
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(150_000),
                    instruction,
                ],
            )
        }
    }

    fn assert_serial_equal(
        fixture: &Fixture,
        transactions: &[VersionedTransaction],
    ) -> PqExecutionOutput {
        let serial = fixture.child();
        let expected = transactions
            .iter()
            .cloned()
            .map(|transaction| crate::experimental_pq::process_with_status(&serial, transaction))
            .collect::<Vec<_>>();
        let parallel = fixture.child();
        let actual = PqExecutor::new(4)
            .unwrap()
            .execute(&parallel, transactions)
            .unwrap();
        assert_eq!(actual.stopped_at, None);
        assert_eq!(actual.records.len(), expected.len());
        for (actual, expected) in actual.records.iter().zip(expected) {
            match (actual, expected) {
                (Ok(actual), Ok(expected)) => {
                    assert_eq!(actual.0, expected.0);
                    assert_eq!(actual.1, expected.1);
                    assert_eq!(actual.2, expected.2);
                }
                (Err(actual), Err(expected)) => {
                    assert_eq!(Some(actual), expected.downcast_ref::<TransactionError>());
                }
                pair => panic!("parallel/serial commit classification differs: {pair:?}"),
            }
        }
        assert_eq!(parallel.transaction_count(), serial.transaction_count());
        assert_eq!(parallel.signature_count(), serial.signature_count());
        assert_eq!(
            parallel.read_cost_tracker().unwrap().block_cost(),
            serial.read_cost_tracker().unwrap().block_cost()
        );
        parallel.freeze();
        serial.freeze();
        assert_eq!(parallel.pq_state_commitment(), serial.pq_state_commitment());
        actual
    }

    #[test]
    fn policy_address_memo_is_exact_bounded_and_recomputes_uncached_signers() {
        let mut memo = PolicyAddresses::default();
        let signers = (0..MAX_POLICY_ADDRESSES + 3)
            .map(|_| Pubkey::new_unique())
            .collect::<Vec<_>>();
        for signer in &signers {
            assert_eq!(memo.derive(signer), pq::policy_address(signer));
        }
        assert_eq!(memo.addresses.len(), MAX_POLICY_ADDRESSES);
        assert!(!memo.addresses.contains_key(&signers[MAX_POLICY_ADDRESSES]));
        let retained = memo.addresses.clone();
        for signer in signers.iter().rev() {
            assert_eq!(memo.derive(signer), pq::policy_address(signer));
        }
        assert_eq!(memo.addresses, retained);
        assert!(PolicyAddresses::default().addresses.is_empty());
    }

    #[test]
    fn memo_hits_preserve_all_multisigner_policy_access_dependencies() {
        let fixture = Fixture::new(3);
        let bank = fixture.child();
        let transaction = fixture.sign(&[0, 1, 2], &[app::nonce_instruction(17, 1)]);
        let prepared = prepare(&bank, 0, &transaction).unwrap();
        let mut memo = PolicyAddresses::default();
        let mut programdata = HashMap::new();
        let first = transaction_accesses(&bank, &prepared, &mut programdata, &mut memo);
        let second = transaction_accesses(&bank, &prepared, &mut programdata, &mut memo);
        assert_eq!(memo.addresses.len(), 3);
        assert_eq!(first.keys, second.keys);
        assert_eq!(first.barrier, second.barrier);
        for (signer, _) in &fixture.wallets {
            assert_eq!(
                second.keys.get(&pq::policy_address(signer)),
                Some(&false),
                "every readonly policy remains an access dependency after a memo hit"
            );
        }
        // Declared policy writes must remain writes rather than being reduced
        // to the implicit readonly dependency by a cached derivation.
        let authority = fixture.wallets[0].0;
        let rotation = fixture.sign(
            &[0],
            &[pq::rotate_instruction(&authority, &Pubkey::new_unique(), 1)],
        );
        let prepared = prepare(&bank, 0, &rotation).unwrap();
        let accesses = transaction_accesses(&bank, &prepared, &mut programdata, &mut memo);
        assert_eq!(
            accesses.keys.get(&pq::policy_address(&authority)),
            Some(&true)
        );
    }

    #[test]
    fn legacy_enrollment_with_warm_address_memo_retires_ed_and_preserves_falcon() {
        let classical = Keypair::new();
        let authority = classical.pubkey();
        let falcon = FalconKeypair::generate();
        let recipient = Pubkey::new_unique();
        let config = pq::Config {
            chain_id: [0xe1; 32],
            migration_context: [0xe2; 32],
            cutoff_slot: 1000,
        };
        let mut genesis =
            create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000_000)
                .genesis_config;
        genesis.rent = solana_rent::Rent::default();
        genesis.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        genesis.accounts.insert(
            pq::CONFIG_ADDRESS,
            config.account(genesis.rent.minimum_balance(80)),
        );
        for address in [authority, recipient] {
            genesis.accounts.insert(
                address,
                Account {
                    lamports: 100_000_000,
                    ..Account::default()
                },
            );
        }
        let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis));
        let root = forks.read().unwrap().root_bank();
        root.freeze();
        let fixture = Fixture {
            root,
            _forks: forks,
            wallets: vec![(authority, falcon)],
            recipients: vec![recipient],
            config,
            mint: Pubkey::new_unique(),
            token_sources: Vec::new(),
            token_destinations: Vec::new(),
            apps: Vec::new(),
            lookup_table: Pubkey::new_unique(),
        };
        let sign_ed = |instructions: &[Instruction]| {
            VersionedTransaction::from(Transaction::new_signed_with_payer(
                instructions,
                Some(&authority),
                &[&classical],
                fixture.root.last_blockhash(),
            ))
        };
        let first = sign_ed(&[system_instruction::transfer(&authority, &recipient, 1)]);
        let bank = fixture.child();
        let prepared = prepare(&bank, 0, &first).unwrap();
        let policy = pq::policy_address(&authority);
        assert!(!prepared.keys.iter().any(|(key, _)| *key == policy));
        let mut memo = PolicyAddresses::default();
        let accesses = transaction_accesses(&bank, &prepared, &mut HashMap::new(), &mut memo);
        assert_eq!(accesses.keys.get(&policy), Some(&false));
        assert_eq!(memo.addresses.len(), 1);
        let nonce = [0xe4; 32];
        let upload = pq::upload_address(&authority, &nonce);
        let public = fixture.wallets[0].1.public_key();
        let create = sign_ed(&[
            pq::create_upload_instruction(&authority, &nonce, public.as_bytes().len() as u32),
            pq::write_upload_instruction(&authority, &upload, 0, public.as_bytes()),
            pq::seal_upload_instruction(&authority, &upload),
        ]);
        let install = sign_ed(&[pq::install_legacy_instruction(
            &authority,
            &authority,
            &upload,
            &pq::sealed_upload_commitment(&authority, &nonce, public.as_bytes()),
        )]);
        let retired = sign_ed(&[system_instruction::transfer(&authority, &recipient, 2)]);
        let fresh = fixture.transfer(0, recipient, 3);
        let output = assert_serial_equal(&fixture, &[first, create, install, retired, fresh]);
        for index in [0, 1, 2, 4] {
            assert!(output.records[index].as_ref().unwrap().1.status.is_ok());
        }
        assert_eq!(
            output.records[3].as_ref().unwrap_err(),
            &TransactionError::SignatureFailure
        );
    }

    #[test]
    fn independent_system_transactions_execute_concurrently_and_match_serial() {
        let fixture = Fixture::new(16);
        let transactions = fixture
            .wallets
            .iter()
            .enumerate()
            .map(|(index, _)| fixture.transfer(index, fixture.recipients[index], index as u64 + 1))
            .collect::<Vec<_>>();
        let result = assert_serial_equal(&fixture, &transactions);
        assert_eq!(result.waves, 1);
        assert_eq!(result.max_parallel_transactions, 16);
        assert!(
            result.peak_active_batches > 1,
            "native SVM batches must overlap"
        );
        assert!(result.records.iter().all(|record| record.is_ok()));
    }

    #[test]
    fn dependent_system_order_duplicate_replay_and_failures_match_serial() {
        let fixture = Fixture::new(6);
        let first = fixture.transfer(0, fixture.wallets[1].0, 700_000);
        let mut corrupted = fixture.transfer(3, fixture.recipients[3], 11);
        if let VersionedMessage::Legacy(message) = &mut corrupted.message {
            message.instructions[0].data[12] ^= 1;
        }
        let transactions = vec![
            first.clone(),
            fixture.transfer(2, fixture.recipients[2], 7),
            fixture.transfer(1, fixture.recipients[1], 100_500_000),
            first,
            fixture.transfer(4, fixture.recipients[4], u64::MAX),
            corrupted,
            fixture.transfer(3, fixture.recipients[3], 9),
        ];
        let result = assert_serial_equal(&fixture, &transactions);
        assert!(result.waves > 1);
        assert_eq!(
            result.records[3].as_ref().unwrap_err(),
            &TransactionError::AlreadyProcessed
        );
        assert!(result.records[4].as_ref().unwrap().1.status.is_err());
        assert_eq!(
            result.records[5].as_ref().unwrap_err(),
            &TransactionError::SignatureFailure
        );
        assert!(result.records[6].as_ref().unwrap().1.status.is_ok());
    }

    #[test]
    fn real_spl_shared_readonly_mint_and_conflicting_token_writes_match_serial() {
        let fixture = Fixture::new(12);
        let mut transactions = (0..12)
            .map(|index| fixture.token_transfer(index, 100 + index as u64))
            .collect::<Vec<_>>();
        transactions.push(fixture.token_transfer(0, u64::MAX));
        transactions.push(fixture.token_transfer(0, 17));
        let result = assert_serial_equal(&fixture, &transactions);
        assert_eq!(result.max_parallel_transactions, 12);
        assert!(result.peak_active_batches > 1);
        assert!(result.records[12].as_ref().unwrap().1.status.is_err());
        assert!(result.records[13].as_ref().unwrap().1.status.is_ok());
    }

    #[test]
    fn native_alt_mutation_precedes_v0_resolution_and_independent_loaded_writes() {
        let fixture = Fixture::new(3);
        let mutation = fixture.sign(
            &[0],
            &[freeze_lookup_table(
                fixture.lookup_table,
                fixture.wallets[0].0,
            )],
        );
        let make_v0 = |index: usize| {
            let authority = fixture.wallets[index].0;
            let message = v0::Message::try_compile(
                &authority,
                &[
                    pq::authenticate_instruction(&[authority]),
                    system_instruction::transfer(
                        &authority,
                        &fixture.recipients[index],
                        index as u64 + 1,
                    ),
                ],
                &[AddressLookupTableAccount {
                    key: fixture.lookup_table,
                    addresses: fixture.recipients.clone(),
                }],
                fixture.root.last_blockhash(),
            )
            .unwrap();
            assert_eq!(message.address_table_lookups.len(), 1);
            // Lookup dependencies are not transaction lock account keys.
            assert!(!message.account_keys.contains(&fixture.lookup_table));
            pq::sign_transaction(
                VersionedMessage::V0(message),
                &fixture.config,
                &[&fixture.wallets[index].1],
            )
            .unwrap()
        };
        let result = assert_serial_equal(&fixture, &[mutation, make_v0(1), make_v0(2)]);
        assert_eq!(result.waves, 2);
        assert_eq!(result.max_parallel_transactions, 2);
        assert!(
            result
                .records
                .iter()
                .all(|record| record.as_ref().unwrap().1.status.is_ok()),
            "ALT execution statuses: {:?}",
            result
                .records
                .iter()
                .map(|record| &record.as_ref().unwrap().1.status)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn genuine_sbf_pda_cpi_failures_keep_fees_and_rollback_in_fifo_order() {
        let fixture = Fixture::new(12);
        let mut transactions = Vec::new();
        for (group, accounts) in fixture.apps.iter().copied().enumerate() {
            transactions.push(fixture.app_transaction(
                group,
                accounts.initialize(fixture.root.get_minimum_balance_for_rent_exemption(0), 1),
                false,
            ));
        }
        for (group, accounts) in fixture.apps.iter().copied().enumerate() {
            transactions.push(fixture.app_transaction(
                group,
                accounts.deposit(2_000_000, 2),
                false,
            ));
        }
        for (group, accounts) in fixture.apps.iter().copied().enumerate() {
            transactions.push(fixture.app_transaction(
                group,
                accounts.failed_withdraw(1_000_000, 3),
                true,
            ));
        }
        for (group, accounts) in fixture.apps.iter().copied().enumerate() {
            // Failed sequence three must have rolled back. It can be reused
            // by this valid transaction, along with the unchanged PDA balance.
            transactions.push(fixture.app_transaction(
                group,
                accounts.withdraw(1_000_000, 3),
                true,
            ));
        }
        let result = assert_serial_equal(&fixture, &transactions);
        assert!(result.max_parallel_transactions >= 4);
        assert!(result.peak_active_batches > 1);
        for record in &result.records[8..12] {
            let status = &record.as_ref().unwrap().1;
            assert!(matches!(
                status.status,
                Err(TransactionError::InstructionError(
                    _,
                    solana_instruction_error::InstructionError::Custom(app::EXPECTED_ROLLBACK)
                ))
            ));
            assert_eq!(status.fee, 15_000);
        }
        assert!(
            result.records[12..]
                .iter()
                .all(|record| record.as_ref().unwrap().1.status.is_ok())
        );
    }

    #[test]
    fn cost_budget_retries_after_wave_refund_and_never_executes_stopped_suffix() {
        let fixture = Fixture::new(3);
        let bank = fixture.child();
        let transactions = (0..3)
            .map(|index| {
                fixture.sign(
                    &[index],
                    &[
                        ComputeBudgetInstruction::set_compute_unit_limit(100_000),
                        system_instruction::transfer(
                            &fixture.wallets[index].0,
                            &fixture.recipients[index],
                            7,
                        ),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let reservation = prepare(&bank, 0, &transactions[0])
            .unwrap()
            .reservation
            .sum();
        bank.write_cost_tracker()
            .unwrap()
            .set_limits(CostTrackerLimits {
                account_cost: u64::MAX,
                block_cost: reservation + 50_000,
                allocated_data_size: u64::MAX,
            });
        let result = PqExecutor::new(4)
            .unwrap()
            .execute(&bank, &transactions)
            .unwrap();
        assert_eq!(result.stopped_at, None);
        assert!(
            result.waves >= 3,
            "retry reservations after actual SVM cost refunds"
        );
        assert!(
            result
                .records
                .iter()
                .all(|record| record.as_ref().unwrap().1.status.is_ok())
        );

        let bank = fixture.child();
        bank.write_cost_tracker()
            .unwrap()
            .set_limits(CostTrackerLimits {
                account_cost: u64::MAX,
                block_cost: reservation - 1,
                allocated_data_size: u64::MAX,
            });
        let before = fixture
            .recipients
            .iter()
            .map(|address| bank.get_balance(address))
            .collect::<Vec<_>>();
        let stopped = PqExecutor::new(4)
            .unwrap()
            .execute(&bank, &transactions)
            .unwrap();
        assert_eq!(stopped.stopped_at, Some(0));
        assert!(stopped.records.is_empty());
        assert_eq!(
            before,
            fixture
                .recipients
                .iter()
                .map(|address| bank.get_balance(address))
                .collect::<Vec<_>>()
        );
        assert_eq!(bank.read_cost_tracker().unwrap().block_cost(), 0);
    }

    #[test]
    fn shared_readonly_auth_policies_rotate_before_the_next_native_authorization() {
        let mut fixture = Fixture::new(3);
        let replacement = FalconKeypair::generate();
        let nonce = [0xe3; 32];
        let authority = fixture.wallets[0].0;
        let upload = pq::upload_address(&authority, &nonce);
        let setup = fixture.child();
        for instruction in [
            pq::create_upload_instruction(
                &authority,
                &nonce,
                replacement.public_key().as_bytes().len() as u32,
            ),
            pq::write_upload_instruction(
                &authority,
                &upload,
                0,
                replacement.public_key().as_bytes(),
            ),
            pq::seal_upload_instruction(&authority, &upload),
        ] {
            let result = setup
                .process_transaction_with_metadata(fixture.sign(&[0], &[instruction]))
                .unwrap();
            assert!(result.status.is_ok());
        }
        setup.freeze();
        fixture.root = setup;
        let nonce_instructions = |counter| {
            vec![
                ComputeBudgetInstruction::set_compute_unit_limit(100_000),
                app::nonce_instruction(91, counter),
            ]
        };
        // Different fee payers share the same readonly authority and policy.
        let first = fixture.sign(&[1, 0], &nonce_instructions(1));
        let second = fixture.sign(&[2, 0], &nonce_instructions(2));
        let rotate = fixture.sign(&[0], &[pq::rotate_instruction(&authority, &upload, 1)]);
        let retired = fixture.sign(&[1, 0], &nonce_instructions(3));
        fixture.wallets[0].1 = replacement;
        let fresh = fixture.sign(&[1, 0], &nonce_instructions(4));
        let loader = fixture.sign(
            &[2],
            &[Instruction {
                program_id: solana_sdk_ids::bpf_loader_upgradeable::id(),
                accounts: vec![],
                data: vec![],
            }],
        );
        let result =
            assert_serial_equal(&fixture, &[first, second, rotate, retired, fresh, loader]);
        assert_eq!(result.max_parallel_transactions, 2);
        assert!(result.peak_active_batches > 1);
        assert!(result.records[0].as_ref().unwrap().1.status.is_ok());
        assert!(result.records[1].as_ref().unwrap().1.status.is_ok());
        assert!(result.records[2].as_ref().unwrap().1.status.is_ok());
        assert_eq!(
            result.records[3].as_ref().unwrap_err(),
            &TransactionError::SignatureFailure
        );
        assert!(result.records[4].as_ref().unwrap().1.status.is_ok());
        assert!(result.records[5].as_ref().unwrap().1.status.is_err());
        assert_eq!(result.waves, 5);
    }
}
