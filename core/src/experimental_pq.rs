//! Explicit experimental PQ data plane for an Agave validator.
//!
//! Quantumglow authorizes roots, Falcon authenticates block data and native
//! QUIC peers, and durable Ax keys authorize all consensus evidence. Execution
//! uses `solana_runtime::Bank`, SVM, AccountsDB and the actual RocksDB Blockstore.
//! The classical TPU, TVU, PoH and BLS voter must not run alongside this service.
use {
    crate::experimental_pq_execution::PqExecutor,
    agave_pq_crypto::{
        ax_state::{DurableConsensusSigner, FileMonotonicStore, IntentReconciliation},
        consensus::{
            ConsensusPublicKey, PreparedEvidence, SignedEvidence, Validator as PqValidator,
        },
        crypto::{Domain, FalconKeypair, FalconPublicKey, hash_commitment},
        network::{
            AuthenticatedShred, BatchContext, CandidateAssembler, FinalMarker,
            MAX_AUTHENTICATION_BATCH, NetworkError, PreparedBatch, VerifiedCandidate,
            VerifiedShred, prepared_block_commitment,
        },
        quantumglow::{
            Action, BlockRef, Config, Error as QuantumglowError, ExecutionCandidate,
            ExecutionState, Quantumglow,
        },
    },
    anyhow::{Context, Result, anyhow, bail, ensure},
    crossbeam_channel::{Receiver, Sender, bounded},
    rayon::prelude::*,
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    solana_account::ReadableAccount,
    solana_hash::Hash,
    solana_ledger::blockstore::{
        Blockstore, ExperimentalPqTransaction, MAX_EXPERIMENTAL_PQ_JOURNAL_BYTES,
    },
    solana_pubkey::Pubkey,
    solana_rpc::optimistically_confirmed_bank_tracker::OptimisticallyConfirmedBank,
    solana_runtime::{
        bank::{Bank, SlotLeader},
        bank_forks::BankForks,
        commitment::BlockCommitmentCache,
        installed_scheduler_pool::BankWithScheduler,
    },
    solana_tls_utils::pq::{PqQuicConfig, PqQuicTransport, PqTraceConfig},
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
    std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        net::SocketAddr,
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};
#[cfg(test)]
use {
    solana_cost_model::cost_model::CostModel,
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction,
        transaction_with_meta::{TransactionWithMeta, writable_accounts},
    },
    solana_svm_transaction::svm_message::SVMMessage,
    solana_transaction::sanitized::{MessageHash, SanitizedTransaction},
    solana_transaction_status::TransactionStatusMeta,
};

#[path = "experimental_pq_pipeline.rs"]
mod pipeline;
use pipeline::{
    CandidateBodyJob, CandidateJob, CandidateOutput, FinalizationJob, JournalBarrier, JournalJob,
    PqPipeline, PreparationJob, ProducerJob, PublicationJob, ReconstructionJob,
};

type Commitment = [u8; 48];
const MAX_TRANSACTION_BYTES: usize = 16 * 1024;
const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;
const MAX_BLOCK_TRANSACTIONS: usize = 8192;
const MAX_MEMPOOL_BYTES: usize = 256 * 1024 * 1024;
const MAX_MEMPOOL_TRANSACTIONS: usize = 250_000;
const MAX_BUFFERED_CANDIDATES: usize = 32;
const MAX_REPAIR_BYTES: usize = 64 * 1024 * 1024;
const MAX_PARENT_REPAIRS: usize = MAX_BUFFERED_CANDIDATES * 4;
const MAX_PEER_REPAIR_RESPONSES: usize = 32;
const MAX_NATIVE_CANDIDATE_BANKS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RepairTier {
    Certified,
    Weak,
    Signed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RepairPriority {
    tier: RepairTier,
    slot: u64,
}

impl Default for RepairPriority {
    fn default() -> Self {
        Self {
            tier: RepairTier::Signed,
            slot: u64::MAX,
        }
    }
}

#[derive(Default)]
struct RepairRetry {
    due: u64,
    delay: u64,
    priority: RepairPriority,
}

impl RepairRetry {
    fn ready(&self, now: u64) -> bool {
        now >= self.due
    }

    fn defer(&mut self, now: u64, base: u64) {
        let base = base.max(1000);
        self.delay = self.delay.max(base).min(base.saturating_mul(8));
        self.due = now.saturating_add(self.delay);
        self.delay = self.delay.saturating_mul(2).min(base.saturating_mul(8));
    }
}

#[derive(Default)]
struct RepairResponse {
    retry: RepairRetry,
    requested: bool,
    admission: u64,
}

#[derive(Clone, Copy)]
struct DeferredRefetch {
    slot: u64,
    parent: Commitment,
    candidate: Commitment,
    tier: RepairTier,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalPqPeer {
    /// Actual validator identity, used as an identifier, never as an Ed signer.
    pub id: String,
    pub address: SocketAddr,
    pub network_key: String,
    pub leader_key: String,
    pub consensus_key: String,
    pub stake: u64,
    #[serde(default)]
    pub vote_account: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalPqConfig {
    /// Immutable on-chain signature domain. PQ roles are not learned from gossip.
    pub chain: String,
    /// Independently pinned actual genesis hash (base58), separate from the
    /// signature domain so genesis accounts need no self-referential hash.
    pub genesis_hash: String,
    /// Independently trusted wide state checkpoint for the activation Bank.
    /// Kept outside the on-chain registry to avoid a self-referential hash.
    pub activation_state: String,
    pub local_id: String,
    pub epoch: u64,
    pub first_slot: u64,
    pub slot_count: u64,
    pub window_size: u64,
    pub network_delay_ms: u64,
    pub block_time_ms: u64,
    pub target_block_bytes: usize,
    pub max_transactions: usize,
    #[serde(default = "default_execution_threads")]
    pub execution_threads: usize,
    /// Local proposal limits may be lower than the immutable validation limits.
    /// They do not change the execution rules or the authenticated committee.
    #[serde(default)]
    pub proposal_target_block_bytes: Option<usize>,
    #[serde(default)]
    pub proposal_max_transactions: Option<usize>,
    pub listen: SocketAddr,
    pub key_directory: PathBuf,
    pub peers: Vec<ExperimentalPqPeer>,
    #[serde(default)]
    pub start_unix_ms: u64,
    #[serde(default)]
    pub prewarm_seed_verifier: bool,
}

fn default_execution_threads() -> usize {
    8
}

impl ExperimentalPqConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context("read experimental PQ configuration")?;
        ensure!(bytes.len() <= 8 * 1024 * 1024, "PQ configuration bounds");
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (4..=2048).contains(&self.peers.len()),
            "PQ membership bounds"
        );
        ensure!(
            self.first_slot > 0
                && (1..=agave_pq_crypto::consensus::MAX_EPOCH_SLOTS).contains(&self.slot_count),
            "PQ finite epoch bounds"
        );
        ensure!(
            self.window_size == 4 && self.slot_count.is_multiple_of(4),
            "PQ leader window"
        );
        ensure!(
            self.block_time_ms >= 10 && self.network_delay_ms > 0,
            "PQ timing bounds"
        );
        ensure!(
            (64..=MAX_BLOCK_BYTES).contains(&self.target_block_bytes),
            "PQ block target bounds"
        );
        ensure!(
            (1..=MAX_BLOCK_TRANSACTIONS).contains(&self.max_transactions),
            "PQ transaction count bounds"
        );
        ensure!(
            (1..=32).contains(&self.execution_threads),
            "PQ execution worker bounds"
        );
        ensure!(
            self.proposal_target_block_bytes
                .is_none_or(|limit| (64..=self.target_block_bytes).contains(&limit))
                && self
                    .proposal_max_transactions
                    .is_none_or(|limit| (1..=self.max_transactions).contains(&limit)),
            "PQ local proposal limits exceed immutable validation bounds"
        );
        let chain: [u8; 32] = decode_hex(&self.chain)?
            .try_into()
            .map_err(|_| anyhow!("PQ chain length"))?;
        Hash::from_str(&self.genesis_hash)?;
        ensure!(
            decode_hex(&self.activation_state)?.len() == 48,
            "PQ activation checkpoint width"
        );
        let local = Pubkey::from_str(&self.local_id)?;
        let mut identifiers = BTreeSet::new();
        let mut total = 0u64;
        for peer in &self.peers {
            let id = Pubkey::from_str(&peer.id)?;
            ensure!(identifiers.insert(id), "duplicate PQ validator");
            ensure!(peer.stake > 0, "zero PQ validator stake");
            total = total
                .checked_add(peer.stake)
                .ok_or_else(|| anyhow!("PQ stake overflow"))?;
            FalconPublicKey::from_bytes(&decode_hex(&peer.network_key)?)?;
            FalconPublicKey::from_bytes(&decode_hex(&peer.leader_key)?)?;
            let key = ConsensusPublicKey::from_bytes(&decode_hex(&peer.consensus_key)?)?;
            ensure!(
                key.epoch().chain == chain && key.epoch().validator == id.to_bytes(),
                "PQ Ax role binding"
            );
            ensure!(
                key.epoch().epoch == self.epoch
                    && key.epoch().first_slot == self.first_slot
                    && u64::from(key.epoch().slots) == self.slot_count,
                "PQ Ax epoch binding"
            );
            if let Some(vote) = &peer.vote_account {
                Pubkey::from_str(vote)?;
            }
        }
        ensure!(identifiers.contains(&local), "PQ local validator absent");
        Ok(())
    }
}

/// Interface attached to the actual Validator lifecycle and its RPC ingress.
pub struct ExperimentalPqService {
    pub transaction_sender: Sender<Vec<u8>>,
    pub status: Arc<RwLock<Value>>,
    thread: JoinHandle<Result<()>>,
}

impl ExperimentalPqService {
    pub fn spawn(
        config: ExperimentalPqConfig,
        bank_forks: Arc<RwLock<BankForks>>,
        blockstore: Arc<Blockstore>,
        exit: Arc<AtomicBool>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    ) -> Result<Self> {
        config.validate()?;
        let (transaction_sender, ingress) = bounded(4096);
        let status = Arc::new(RwLock::new(json!({"starting": true})));
        // Fail startup synchronously if keys, recovery or role authentication fail.
        let mut node = PqNode::new(
            config,
            bank_forks,
            blockstore,
            exit.clone(),
            ingress,
            status.clone(),
            block_commitment_cache,
            optimistically_confirmed_bank,
        )?;
        let thread = thread::Builder::new()
            .name("agavePqVotor".into())
            .spawn(move || {
                let result = node.run();
                if let Err(error) = &result {
                    error!("experimental PQ validator stopped: {error:#}");
                    *node.status.write().unwrap() = json!({"fatal_error": format!("{error:#}")});
                    exit.store(true, Ordering::Release);
                }
                node.transport
                    .take()
                    .unwrap()
                    .join()
                    .map_err(|e| anyhow!("PQ transport shutdown: {e:?}"))?;
                result
            })?;
        Ok(Self {
            transaction_sender,
            status,
            thread,
        })
    }

    pub fn join(self) -> thread::Result<Result<()>> {
        self.thread.join()
    }
}

struct RuntimeForks {
    banks: BTreeMap<Commitment, Arc<Bank>>,
    states: BTreeMap<Commitment, Commitment>,
    executions: BTreeMap<Commitment, ExecutedCandidate>,
    archives: BTreeMap<Commitment, Arc<Vec<ExperimentalPqTransaction>>>,
    leaders: Vec<SlotLeader>,
    first_slot: u64,
    chain: [u8; 32],
    max_block_bytes: usize,
    max_transactions: usize,
    executor: Arc<PqExecutor>,
}

// This capability can only be created after native SVM execution and Bank
// freeze. Cache hits bind the complete candidate context, rather than trusting
// that a caller's block identifier also identifies its supplied payload.
#[derive(Clone)]
struct ExecutedCandidate {
    chain: [u8; 32],
    slot: u64,
    parent: Commitment,
    parent_state: Commitment,
    payload: Commitment,
    state: Commitment,
}

impl ExecutedCandidate {
    fn new(
        chain: [u8; 32],
        parent_hash: Commitment,
        parent: &Arc<Bank>,
        bank: &Arc<Bank>,
        payload: &[u8],
    ) -> Result<Self> {
        ensure!(
            parent.is_frozen() && bank.is_frozen(),
            "PQ execution cache requires frozen Banks"
        );
        ensure!(
            bank.parent()
                .is_some_and(|actual| Arc::ptr_eq(&actual, parent)),
            "PQ execution cache parent Bank differs"
        );
        Ok(Self {
            chain,
            slot: bank.slot(),
            parent: parent_hash,
            parent_state: bank_state(parent),
            payload: hash_commitment(b"agave-pq-executed-payload-v1", &[&chain, payload]),
            state: bank_state(bank),
        })
    }

    fn matches(
        &self,
        chain: &[u8; 32],
        candidate: &ExecutionCandidate<'_>,
        parent_state: &Commitment,
        state: &Commitment,
    ) -> bool {
        self.chain == *chain
            && self.slot == candidate.reference.slot
            && self.parent == candidate.parent
            && self.parent_state == *parent_state
            && self.state == *state
            && self.payload
                == hash_commitment(b"agave-pq-executed-payload-v1", &[chain, candidate.payload])
    }
}

#[cfg(test)]
#[derive(Debug)]
struct CommittedCostMismatch {
    reserved: u64,
    executed: u64,
}

#[cfg(test)]
impl std::fmt::Display for CommittedCostMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "committed PQ execution exceeded its native reservation: {} > {}",
            self.executed, self.reserved
        )
    }
}

#[cfg(test)]
impl std::error::Error for CommittedCostMismatch {}

fn bank_state(bank: &Bank) -> Commitment {
    bank.pq_state_commitment()
}

#[derive(Debug)]
struct RejectedCandidateExecution {
    block: Commitment,
    reason: &'static str,
}

impl std::fmt::Display for RejectedCandidateExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "rejected PQ candidate {:?}: {}",
            self.block, self.reason
        )
    }
}

impl std::error::Error for RejectedCandidateExecution {}

fn authenticate_shred_group(
    existing: Option<&CandidateAssembler>,
    chain: [u8; 32],
    leader: FalconPublicKey,
    epoch: u64,
    shreds: Vec<AuthenticatedShred>,
) -> std::result::Result<Vec<std::result::Result<VerifiedShred, NetworkError>>, NetworkError> {
    if shreds.len() > MAX_AUTHENTICATION_BATCH {
        let mut incoming = shreds.into_iter();
        let mut authenticated = Vec::new();
        loop {
            let batch = incoming
                .by_ref()
                .take(MAX_AUTHENTICATION_BATCH)
                .collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            authenticated.extend(authenticate_shred_group(
                existing,
                chain,
                leader.clone(),
                epoch,
                batch,
            )?);
        }
        return Ok(authenticated);
    }
    if let Some(assembler) = existing {
        return assembler.authenticate_batch(shreds);
    }
    // A malformed first frame must not choose a conflicting parent for later
    // valid frames. Select the first authenticated context in arrival order.
    let context = &shreds
        .iter()
        .find(|shred| {
            shred.metadata.context.leader_epoch == epoch && shred.verify(&chain, &leader).is_ok()
        })
        .or_else(|| shreds.first())
        .ok_or(NetworkError::Incomplete)?
        .metadata
        .context;
    let assembler = CandidateAssembler::new(
        chain,
        leader,
        epoch,
        context.slot,
        context.candidate,
        context.parent,
    );
    assembler.authenticate_batch(shreds)
}

fn complete_bank(bank: &Bank, chain: &[u8; 32], parent: &Commitment, payload: &[u8]) {
    let digest = hash_commitment(
        b"agave-pq-recent-blockhash-v1",
        &[chain, &bank.slot().to_le_bytes(), parent, payload],
    );
    let hash = Hash::new_from_array(digest[..32].try_into().unwrap());
    let scheduler = BankWithScheduler::no_scheduler_available();
    while bank.tick_height() < bank.max_tick_height() {
        bank.register_tick(&hash, &scheduler);
    }
    bank.freeze();
}

impl RuntimeForks {
    fn validate(&mut self, candidate: &ExecutionCandidate<'_>) -> Option<ExecutionState> {
        self.validate_checked(candidate).ok()
    }

    fn validate_checked(&mut self, candidate: &ExecutionCandidate<'_>) -> Result<ExecutionState> {
        ensure!(
            candidate.payload.len() <= self.max_block_bytes,
            "PQ candidate byte limit"
        );
        let reject = |reason| RejectedCandidateExecution {
            block: candidate.reference.hash,
            reason,
        };
        let parent_state_root = *self
            .states
            .get(&candidate.parent)
            .context(InternalPqError("PQ candidate parent state missing"))?;
        if let Some(state_root) = self.states.get(&candidate.reference.hash) {
            if !self
                .executions
                .get(&candidate.reference.hash)
                .context(InternalPqError("PQ cached execution missing"))?
                .matches(&self.chain, candidate, &parent_state_root, state_root)
            {
                bail!(InternalPqError("PQ cached execution mismatch"));
            }
            return Ok(ExecutionState {
                parent_state_root,
                state_root: *state_root,
            });
        }
        ensure!(
            self.banks.len() < MAX_NATIVE_CANDIDATE_BANKS,
            "PQ candidate bank capacity"
        );
        let parent = self
            .banks
            .get(&candidate.parent)
            .context(InternalPqError("PQ candidate parent Bank missing"))?
            .clone();
        ensure!(
            parent.slot() < candidate.reference.slot,
            "PQ candidate native ancestry"
        );
        let leader = *self
            .leaders
            .get(
                (candidate
                    .reference
                    .slot
                    .checked_sub(self.first_slot)
                    .context("PQ candidate slot before epoch")?) as usize,
            )
            .context(InternalPqError("PQ candidate leader missing"))?;
        let started = Instant::now();
        let decode_started = Instant::now();
        let transactions = decode_block(candidate.payload, self.max_transactions)
            .map_err(|_| reject("malformed canonical native block"))?;
        let decode_us = elapsed_us(decode_started);
        let transaction_count = transactions.len();
        let private_started = Instant::now();
        let bank = Arc::new(Bank::new_isolated_pq_child(
            parent.clone(),
            leader,
            candidate.reference.slot,
        )?);
        let private_child_us = elapsed_us(private_started);
        let execution = self.executor.execute(&bank, &transactions)?;
        if execution.stopped_at.is_some() {
            return Err(reject("native block cost budget exceeded").into());
        }
        ensure!(
            execution.records.len() == transactions.len(),
            "PQ native execution record count mismatch"
        );
        // A committed instruction failure preserves native fees and rollback.
        // A noncommitted error invalidates this entire candidate.
        let archive = execution
            .records
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| reject("noncommitted native transaction"))?;
        let freeze_started = Instant::now();
        complete_bank(&bank, &self.chain, &candidate.parent, candidate.payload);
        let state_root = bank_state(&bank);
        let freeze_us = elapsed_us(freeze_started);
        let capability_started = Instant::now();
        let executed = ExecutedCandidate::new(
            self.chain,
            candidate.parent,
            &parent,
            &bank,
            candidate.payload,
        )?;
        bank.detach_isolated_pq_parent()?;
        self.banks.insert(candidate.reference.hash, bank);
        self.states.insert(candidate.reference.hash, state_root);
        self.executions.insert(candidate.reference.hash, executed);
        self.archives
            .insert(candidate.reference.hash, Arc::new(archive));
        info!(
            "PQ phases stage=candidate slot={} transactions={} bytes={} decode_us={} \
             private_child_us={} native_execute_us={} bridge_us={} freeze_us={} capability_us={} \
             native_worker_us={} parallel_waves={} max_parallel_transactions={} \
             peak_active_batches={} native_prepare_us={} native_access_discovery_us={} \
             native_cost_reserve_us={} native_pool_dispatch_join_us={} native_reconcile_us={} \
             native_pool_overhead_us={} native_bridge_residual_us={} total_us={}",
            candidate.reference.slot,
            transaction_count,
            candidate.payload.len(),
            decode_us,
            private_child_us,
            execution.timings.native_us,
            execution.timings.bridge_us,
            freeze_us,
            elapsed_us(capability_started),
            execution.timings.native_worker_us,
            execution.waves,
            execution.max_parallel_transactions,
            execution.peak_active_batches,
            execution.timings.prepare_us,
            execution.timings.access_discovery_us,
            execution.timings.cost_reserve_us,
            execution.timings.pool_dispatch_join_us,
            execution.timings.reconcile_us,
            execution.timings.pool_overhead_us,
            execution.timings.bridge_residual_us,
            elapsed_us(started)
        );
        Ok(ExecutionState {
            parent_state_root,
            state_root,
        })
    }
}

// Called only after the consensus execution capability and certified parent
// have been checked. Publish executed state before exposing finalized receipts.
fn promote_and_archive(
    forks: &RwLock<BankForks>,
    blockstore: &Blockstore,
    block: BlockRef,
    candidate: Arc<Bank>,
    parent_state: Commitment,
    previous_blockhash: Hash,
    records: &[ExperimentalPqTransaction],
) -> Result<(Arc<Bank>, u64, u64)> {
    promote_and_archive_with_hook(
        forks,
        blockstore,
        block,
        candidate,
        parent_state,
        previous_blockhash,
        records,
        || Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
fn promote_and_archive_with_hook(
    forks: &RwLock<BankForks>,
    blockstore: &Blockstore,
    block: BlockRef,
    candidate: Arc<Bank>,
    parent_state: Commitment,
    previous_blockhash: Hash,
    records: &[ExperimentalPqTransaction],
    after_promotion: impl FnOnce() -> Result<()>,
) -> Result<(Arc<Bank>, u64, u64)> {
    ensure!(
        candidate.slot() == block.slot,
        "PQ promotion slot differs from certificate"
    );
    let promotion_started = Instant::now();
    let bank = forks
        .write()
        .unwrap()
        .promote_pq_candidate(candidate.clone(), parent_state)?;
    ensure!(
        Arc::ptr_eq(&bank, &candidate),
        "PQ promotion changed the executed Bank"
    );
    let promotion_us = elapsed_us(promotion_started);
    after_promotion()?;
    let archive_started = Instant::now();
    blockstore.put_experimental_pq_rpc_block(
        bank.slot(),
        block.hash,
        bank.parent_slot(),
        previous_blockhash,
        bank.last_blockhash(),
        bank.block_height(),
        bank.clock().unix_timestamp,
        records,
    )?;
    // Archive failure is fail-stop: the certified root is never rolled back,
    // and the caller must not advance counters or compact repair history.
    Ok((bank, promotion_us, elapsed_us(archive_started)))
}

#[cfg(test)]
#[derive(Default)]
struct ExecutionTimings {
    native_us: u64,
    bridge_us: u64,
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
pub(crate) fn process_with_status(
    bank: &Bank,
    transaction: VersionedTransaction,
) -> Result<ExperimentalPqTransaction> {
    process_with_status_timed(bank, transaction, &mut ExecutionTimings::default())
}

#[cfg(test)]
fn process_with_status_timed(
    bank: &Bank,
    transaction: VersionedTransaction,
    timings: &mut ExecutionTimings,
) -> Result<ExperimentalPqTransaction> {
    let started = Instant::now();
    let mut native_us = 0;
    let result = (|| {
        if !solana_runtime::pq::is_pq_transaction(&transaction) {
            bank.verify_pq_transaction_for_ingress(&transaction)?;
        }
        let message_hash = if solana_runtime::pq::is_pq_transaction(&transaction) {
            MessageHash::Precomputed(solana_runtime::pq::canonical_message_hash(&transaction)?)
        } else {
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
            .collect::<Vec<_>>();
        let pre_balances = keys.iter().map(|(key, _)| bank.get_balance(key)).collect();
        let mut reserved_cost = CostModel::calculate_cost(&sanitized, &bank.feature_set);
        reserved_cost.loaded_accounts_data_size_cost = reserved_cost
            .loaded_accounts_data_size_cost
            .max(CostModel::calculate_pages_cost(1));
        bank.write_cost_tracker()
            .unwrap()
            .try_add(&reserved_cost, writable_accounts(&sanitized))
            .map_err(TransactionError::from)?;
        let native_started = Instant::now();
        let native_result = bank.process_transaction_with_metadata(transaction.clone());
        native_us = elapsed_us(native_started);
        let committed = match native_result {
            Ok(committed) => committed,
            Err(error) => {
                bank.write_cost_tracker()
                    .unwrap()
                    .remove(&reserved_cost, writable_accounts(&sanitized));
                return Err(error.into());
            }
        };
        let actual_cost = CostModel::calculate_cost_for_executed_transaction(
            &sanitized,
            committed.executed_units,
            committed.loaded_account_stats.loaded_accounts_data_size,
            &bank.feature_set,
        );
        let reserved_execution = reserved_cost
            .programs_execution_cost()
            .saturating_add(reserved_cost.loaded_accounts_data_size_cost());
        let actual_execution = actual_cost
            .programs_execution_cost()
            .saturating_add(actual_cost.loaded_accounts_data_size_cost());
        if actual_execution > reserved_execution {
            // The SVM has already committed. A producer must abort this isolated
            // candidate, never omit this transaction while retaining its writes.
            return Err(CommittedCostMismatch {
                reserved: reserved_execution,
                executed: actual_execution,
            }
            .into());
        }
        bank.write_cost_tracker().unwrap().update_cost(
            reserved_execution,
            actual_execution,
            writable_accounts(&sanitized),
        );
        let post_balances = keys.iter().map(|(key, _)| bank.get_balance(key)).collect();
        let status = TransactionStatusMeta {
            status: committed.status,
            fee: committed.fee_details.total_fee(),
            pre_balances,
            post_balances,
            log_messages: committed.log_messages,
            loaded_addresses: sanitized.as_sanitized_transaction().get_loaded_addresses(),
            return_data: committed.return_data,
            compute_units_consumed: Some(committed.executed_units),
            cost_units: Some(actual_cost.sum()),
            ..TransactionStatusMeta::default()
        };
        Ok((transaction, status, keys))
    })();
    timings.native_us = timings.native_us.saturating_add(native_us);
    timings.bridge_us = timings
        .bridge_us
        .saturating_add(elapsed_us(started).saturating_sub(native_us));
    result
}

#[derive(Clone)]
struct BlockWitness {
    marker: FinalMarker,
    shreds: Vec<AuthenticatedShred>,
}

fn repair_witness_bytes(witness: &BlockWitness) -> usize {
    witness
        .shreds
        .iter()
        .map(|shred| shred.payload.len() + 4096)
        .sum()
}

/// Only authenticated parent metadata can prove a fork obsolete. Unknown
/// ancestry remains eligible for targeted repair; an unsigned disk key cannot
/// make a legitimate candidate disappear.
fn obsolete_witness(
    witness: &BlockWitness,
    anchor: BlockRef,
    authenticated_slots: &BTreeMap<Commitment, u64>,
    blocks: &BTreeMap<Commitment, BlockWitness>,
    deferred: &BTreeMap<Commitment, BlockWitness>,
) -> bool {
    obsolete_parent_ancestry(
        witness.marker.slot,
        witness.marker.parent,
        anchor,
        authenticated_slots,
        blocks,
        deferred,
        None,
    )
}

fn obsolete_parent_ancestry(
    mut slot: u64,
    mut parent: Commitment,
    anchor: BlockRef,
    authenticated_slots: &BTreeMap<Commitment, u64>,
    blocks: &BTreeMap<Commitment, BlockWitness>,
    deferred: &BTreeMap<Commitment, BlockWitness>,
    local_proposals: Option<&BTreeMap<u64, BlockWitness>>,
) -> bool {
    if slot <= anchor.slot {
        return true;
    }
    loop {
        if parent == anchor.hash {
            return false;
        }
        let previous = blocks
            .get(&parent)
            .or_else(|| deferred.get(&parent))
            .or_else(|| {
                local_proposals.and_then(|proposals| {
                    proposals
                        .values()
                        .find(|witness| witness.marker.block_commitment == parent)
                })
            });
        let Some(parent_slot) = previous
            .map(|body| body.marker.slot)
            .or_else(|| authenticated_slots.get(&parent).copied())
        else {
            return false;
        };
        if parent_slot <= anchor.slot || parent_slot >= slot {
            return true;
        }
        let Some(previous) = previous else {
            return false;
        };
        slot = parent_slot;
        parent = previous.marker.parent;
    }
}

fn prune_deferred_witnesses(
    actual: BlockRef,
    authenticated_slots: &BTreeMap<Commitment, u64>,
    blocks: &BTreeMap<Commitment, BlockWitness>,
    deferred: &mut BTreeMap<Commitment, BlockWitness>,
    bytes: &mut usize,
) -> Result<()> {
    let stale = deferred
        .iter()
        .filter(|(_, witness)| {
            obsolete_witness(witness, actual, authenticated_slots, blocks, deferred)
        })
        .map(|(hash, _)| *hash)
        .collect::<Vec<_>>();
    for hash in stale {
        let witness = deferred.remove(&hash).unwrap();
        *bytes = bytes
            .checked_sub(witness.encoded_len()?)
            .context(InternalPqError("PQ deferred parent byte accounting"))?;
    }
    Ok(())
}

impl BlockWitness {
    fn encoded_len(&self) -> Result<usize> {
        let size = self.shreds.iter().try_fold(
            8 + 4 + self.marker.encode().len() + 4,
            |size, shred| -> Result<usize> {
                size.checked_add(4 + shred.encoded_len()?)
                    .context("PQ witness bounds")
            },
        )?;
        ensure!(size <= 64 * 1024 * 1024, "PQ witness bounds");
        Ok(size)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = b"AGVPQBW1".to_vec();
        put_bytes(&mut out, &self.marker.encode())?;
        out.extend_from_slice(&(self.shreds.len() as u32).to_le_bytes());
        for shred in &self.shreds {
            let len = shred.encoded_len()?;
            out.extend_from_slice(&u32::try_from(len)?.to_le_bytes());
            shred.encode_into(&mut out)?;
        }
        ensure!(out.len() <= 64 * 1024 * 1024, "PQ witness bounds");
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 64 * 1024 * 1024 && bytes.starts_with(b"AGVPQBW1"),
            "PQ witness header"
        );
        let mut reader = Reader { bytes, at: 8 };
        let marker = FinalMarker::decode(reader.bytes(4096)?)?;
        let count = reader.u32()? as usize;
        ensure!(
            count <= 32_768 && count <= bytes.len() / 16,
            "PQ witness shred count"
        );
        let shreds = (0..count)
            .map(|_| Ok(AuthenticatedShred::decode(reader.bytes(4096)?)?))
            .collect::<Result<Vec<_>>>()?;
        ensure!(reader.at == bytes.len(), "PQ witness trailing bytes");
        Ok(Self { marker, shreds })
    }
}

#[derive(Clone, Copy)]
struct Production {
    first: u64,
    next: u64,
    parent: Commitment,
    due: u64,
}

struct StreamingProposal {
    slot: u64,
    frames: Vec<Arc<Vec<u8>>>,
    cursors: BTreeMap<Pubkey, usize>,
}

struct MempoolEntry {
    raw: Vec<u8>,
    transaction: VersionedTransaction,
    intent: Option<Commitment>,
}

// A bounded-prefix readiness observation, not a transaction selection. A held
// unsigned result already owns its exact selected payload and native Bank.
#[derive(Default)]
struct PreparedReuseReadiness {
    full_ready: bool,
    fifo_rows_scanned: usize,
    eligible_entries_lower_bound: usize,
    eligible_bytes_lower_bound: usize,
    speculative_selected: usize,
    deferred_blockhash_entries_scanned: usize,
}

#[cfg(test)]
thread_local! {
    static PROPOSAL_SNAPSHOT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn take_proposal_snapshot_calls() -> usize {
    PROPOSAL_SNAPSHOT_CALLS.with(|calls| calls.replace(0))
}

// One proposal's metadata-only view of its exact immutable parent. This
// cache contains neither AUTH policy nor authorization/replay decisions.
struct ParentHashEligibility<'a> {
    parent: &'a Bank,
    hashes: BTreeMap<Hash, bool>,
}
impl<'a> ParentHashEligibility<'a> {
    const MAX_HASHES: usize = 4096;

    fn new(parent: &'a Bank) -> Self {
        Self {
            parent,
            hashes: BTreeMap::new(),
        }
    }

    fn eligible(&mut self, transaction: &VersionedTransaction) -> bool {
        let hash = transaction.message.recent_blockhash();
        let valid = match self.hashes.get(hash) {
            Some(valid) => *valid,
            None => {
                let valid = self.parent.is_blockhash_valid(hash);
                if self.hashes.len() < Self::MAX_HASHES {
                    self.hashes.insert(*hash, valid);
                }
                valid
            }
        };
        valid || may_use_native_nonce(transaction)
    }
}

fn may_use_native_nonce(transaction: &VersionedTransaction) -> bool {
    let Some(first) = transaction.message.instructions().first() else {
        return false;
    };
    // The native SVM recognizes this four-byte prefix, including trailing
    // data. Do not decode/sanitize or resolve any account during selection.
    if !first.data.starts_with(&4u32.to_le_bytes()) {
        return false;
    }
    match transaction
        .message
        .static_account_keys()
        .get(usize::from(first.program_id_index))
    {
        Some(program) => solana_sdk_ids::system_program::check_id(program),
        // A V0 program supplied by an ALT must undergo the original native
        // resolution/nonce/authorization checks, rather than being omitted.
        None => true,
    }
}

fn verify_ingress_authentication(root: &Arc<Bank>, tx: &VersionedTransaction) -> Result<()> {
    #[cfg(test)]
    let _probe = ingress_authentication_probe(Arc::as_ptr(root) as usize);
    root.verify_pq_transaction_for_ingress(tx)?;
    Ok(())
}

// A private capability for one exact wire on one immutable root. Workers may
// read AUTH and do signature mathematics; only the coordinator admits entries.
// Even a failed old-root authorization must be redone after a root change.
struct PreparedIngress {
    wire: Commitment,
    root: Arc<Bank>,
    outcome: Result<(VersionedTransaction, Option<Commitment>)>,
}

fn prepare_ingress(root: Arc<Bank>, chain: &[u8; 32], raw: &[u8]) -> PreparedIngress {
    let wire = hash_commitment(b"agave-pq-transaction-wire-v1", &[raw]);
    let outcome = (|| {
        let transaction = decode_transaction(raw)?;
        verify_ingress_authentication(&root, &transaction)?;
        let intent = solana_runtime::pq::is_pq_transaction(&transaction)
            .then(|| solana_runtime::pq::transaction_intent_identity(&transaction, chain))
            .transpose()?;
        Ok((transaction, intent))
    })();
    PreparedIngress {
        wire,
        root,
        outcome,
    }
}

#[cfg(test)]
#[derive(Default)]
struct IngressAuthenticationProbe {
    state: Mutex<(usize, usize, usize, bool)>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
fn ingress_authentication_probes()
-> &'static Mutex<BTreeMap<usize, Arc<IngressAuthenticationProbe>>> {
    static PROBES: std::sync::OnceLock<Mutex<BTreeMap<usize, Arc<IngressAuthenticationProbe>>>> =
        std::sync::OnceLock::new();
    PROBES.get_or_init(Mutex::default)
}

#[cfg(test)]
struct IngressAuthenticationGuard(Arc<IngressAuthenticationProbe>);

#[cfg(test)]
impl Drop for IngressAuthenticationGuard {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().0 -= 1;
    }
}

#[cfg(test)]
fn ingress_authentication_probe(bank_pointer: usize) -> Option<IngressAuthenticationGuard> {
    let probe = ingress_authentication_probes()
        .lock()
        .unwrap()
        .get(&bank_pointer)
        .cloned()?;
    let mut state = probe.state.lock().unwrap();
    state.0 += 1;
    state.1 = state.1.max(state.0);
    state.2 += 1;
    probe.changed.notify_all();
    let deadline = Instant::now() + Duration::from_secs(2);
    while state.2 < 2 && !state.3 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            state.3 = true;
            break;
        }
        let (next, _) = probe.changed.wait_timeout(state, remaining).unwrap();
        state = next;
    }
    drop(state);
    Some(IngressAuthenticationGuard(probe))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MempoolReplayKey {
    Pq(Commitment),
    Legacy(solana_signature::Signature),
}

impl MempoolReplayKey {
    fn committed(transaction: &VersionedTransaction, chain: &[u8; 32]) -> Result<Self> {
        if solana_runtime::pq::is_pq_transaction(transaction) {
            Ok(Self::Pq(solana_runtime::pq::transaction_intent_identity(
                transaction,
                chain,
            )?))
        } else {
            Ok(Self::Legacy(*transaction.signatures.first().context(
                "committed legacy transaction signature missing",
            )?))
        }
    }
}

/// Admission is authenticated separately. This index never authorizes execution;
/// it only associates admitted wire aliases with exact native replay identities.
#[derive(Default)]
struct IndexedMempool {
    entries: BTreeMap<Commitment, Arc<MempoolEntry>>,
    replay: BTreeMap<MempoolReplayKey, BTreeSet<Commitment>>,
    bytes: usize,
}

/// Backpressure owns the exact dequeued wire bytes so local RPC ingress can
/// retry without copying, replacing or losing an already queued transaction.
struct MempoolFull(Vec<u8>);

impl std::fmt::Debug for MempoolFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MempoolFull")
            .field("wire_bytes", &self.0.len())
            .finish()
    }
}
impl std::fmt::Display for MempoolFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PQ mempool full")
    }
}
impl std::error::Error for MempoolFull {}

impl std::ops::Deref for IndexedMempool {
    type Target = BTreeMap<Commitment, Arc<MempoolEntry>>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl IndexedMempool {
    fn insert(&mut self, id: Commitment, entry: MempoolEntry) -> Result<()> {
        ensure!(
            !self.entries.contains_key(&id),
            "PQ duplicate mempool wire identity"
        );
        let key = entry.replay_key()?;
        self.bytes += entry.len();
        self.replay.entry(key).or_default().insert(id);
        self.entries.insert(id, Arc::new(entry));
        Ok(())
    }

    fn remove(&mut self, id: &Commitment) -> Option<Arc<MempoolEntry>> {
        let entry = self.entries.remove(id)?;
        let key = entry
            .replay_key()
            .expect("admitted mempool replay identity");
        let aliases = self.replay.get_mut(&key).expect("indexed mempool identity");
        assert!(aliases.remove(id), "indexed mempool wire identity");
        if aliases.is_empty() {
            self.replay.remove(&key);
        }
        self.bytes -= entry.len();
        Some(entry)
    }

    /// Only the certified, committed archive supplies these identities. Failed
    /// instructions with charged fees are committed and remove their aliases;
    /// uncommitted or speculative transactions are absent from this archive.
    fn prune_committed(
        &mut self,
        records: &[ExperimentalPqTransaction],
        chain: &[u8; 32],
    ) -> Result<Vec<Commitment>> {
        let keys = records
            .iter()
            .map(|(transaction, _, _)| MempoolReplayKey::committed(transaction, chain))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut removed = Vec::new();
        for key in keys {
            if let Some(aliases) = self.replay.remove(&key) {
                for id in aliases {
                    let entry = self.entries.remove(&id).expect("indexed mempool alias");
                    self.bytes -= entry.len();
                    removed.push(id);
                }
            }
        }
        Ok(removed)
    }
}

impl std::ops::Deref for MempoolEntry {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}
impl MempoolEntry {
    fn replay_key(&self) -> Result<MempoolReplayKey> {
        self.intent.map_or_else(
            || {
                Ok(MempoolReplayKey::Legacy(
                    *self
                        .transaction
                        .signatures
                        .first()
                        .context("admitted legacy transaction signature missing")?,
                ))
            },
            |intent| Ok(MempoolReplayKey::Pq(intent)),
        )
    }

    fn processed(&self, bank: &Bank) -> Result<bool> {
        if let Some(intent) = self.intent {
            Ok(bank.pq_intent_processed(&intent)?)
        } else {
            // This path only handles authenticated pre-cutoff Ed transactions.
            // Post-cutoff authorization still rejects them under native locks.
            Ok(bank
                .get_signature_status(&self.transaction.signatures[0])
                .is_some())
        }
    }
}

/// Local admission sequence numbers never enter signed protocol bytes. Deleting
/// committed aliases leaves stable holes for each peer's range cursor.
struct IndexedAdmissionOrder {
    by_sequence: BTreeMap<u64, Commitment>,
    by_id: BTreeMap<Commitment, u64>,
    next_sequence: u64,
}

impl Default for IndexedAdmissionOrder {
    fn default() -> Self {
        Self {
            by_sequence: BTreeMap::new(),
            by_id: BTreeMap::new(),
            next_sequence: 1,
        }
    }
}

impl IndexedAdmissionOrder {
    /// Preflight before mutating the mempool. MAX is never assigned, preserving
    /// the existing peer cursor's checked-by-construction sequence + 1.
    fn reserve(&self, id: Commitment) -> Result<u64> {
        if self.by_id.contains_key(&id) {
            return Err(InternalPqError("PQ duplicate admission order ID").into());
        }
        self.next_sequence
            .checked_add(1)
            .ok_or(InternalPqError("PQ local admission sequence exhausted"))?;
        Ok(self.next_sequence)
    }

    fn insert_reserved(&mut self, id: Commitment, sequence: u64) {
        assert_eq!(
            sequence, self.next_sequence,
            "PQ admission reservation changed"
        );
        assert!(
            !self.by_id.contains_key(&id),
            "PQ duplicate admission order ID"
        );
        self.next_sequence = sequence
            .checked_add(1)
            .expect("preflighted admission sequence");
        assert!(self.by_sequence.insert(sequence, id).is_none());
        assert!(self.by_id.insert(id, sequence).is_none());
    }

    fn iter(&self) -> impl Iterator<Item = &Commitment> {
        self.by_sequence.values()
    }

    fn remove(&mut self, id: &Commitment) -> Option<u64> {
        let sequence = self.by_id.remove(id)?;
        assert_eq!(self.by_sequence.remove(&sequence), Some(*id));
        Some(sequence)
    }
}

fn remove_admission_queue_row(
    order: &mut IndexedAdmissionOrder,
    gossip: &mut BTreeMap<u64, Commitment>,
    id: &Commitment,
) {
    let sequence = order.remove(id).expect("removed alias admission order");
    if let Some(gossiped) = gossip.remove(&sequence) {
        assert_eq!(gossiped, *id, "PQ gossip admission sequence mismatch");
    }
}

/// Producer rejection removes only the exact wire ID, never every replay alias.
/// A later valid ingress of the same wire receives a fresh stable sequence.
fn remove_admitted_wire(
    mempool: &mut IndexedMempool,
    order: &mut IndexedAdmissionOrder,
    gossip: &mut BTreeMap<u64, Commitment>,
    id: &Commitment,
) -> Option<Arc<MempoolEntry>> {
    let entry = mempool.remove(id)?;
    remove_admission_queue_row(order, gossip, id);
    Some(entry)
}

/// Exact certified-archive aliases only. Charged errors remove aliases; losing
/// speculative Bank effects are absent. Never scan or renumber pending rows.
fn prune_committed_admission(
    mempool: &mut IndexedMempool,
    order: &mut IndexedAdmissionOrder,
    gossip: &mut BTreeMap<u64, Commitment>,
    records: &[ExperimentalPqTransaction],
    chain: &[u8; 32],
) -> Result<Vec<Commitment>> {
    let removed = mempool.prune_committed(records, chain)?;
    for id in &removed {
        remove_admission_queue_row(order, gossip, id);
    }
    Ok(removed)
}

#[derive(Default)]
struct PeerOutbound {
    evidence: VecDeque<Commitment>,
    queued_evidence: BTreeSet<Commitment>,
    repair_evidence: BTreeSet<Commitment>,
    repairs: VecDeque<Commitment>,
    queued_repairs: BTreeSet<Commitment>,
    blocks: VecDeque<(Commitment, usize)>,
    queued_blocks: BTreeSet<Commitment>,
    repair_blocks: BTreeSet<Commitment>,
    next_transaction: u64,
}

impl PeerOutbound {
    fn flush(
        &mut self,
        evidence: &BTreeMap<Commitment, (u64, Vec<u8>)>,
        blocks: &BTreeMap<Commitment, BlockWitness>,
        outgoing: &BTreeMap<Commitment, BlockWitness>,
        gossip: &BTreeMap<u64, Commitment>,
        mempool: &BTreeMap<Commitment, Arc<MempoolEntry>>,
        mut send: impl FnMut(&[u8]) -> bool,
    ) -> Result<bool> {
        // Causal repair must have an opportunity before routine evidence can
        // consume the available control reservation. Failed control sends do
        // not suppress the independent, still bounded bulk sender.
        let mut complete = true;
        // A completed data prefix needs its authenticated terminal before its
        // parent can execute. Reserve that ready marker ahead of a continually
        // refilled evidence queue, while preserving per-witness prefix order.
        let mut first_block_frame = 0;
        let mut terminal_blocked = false;
        if let Some(&(hash, index)) = self.blocks.front()
            && let Some(witness) = blocks.get(&hash).or_else(|| outgoing.get(&hash))
            && index >= witness.shreds.len()
        {
            let mut frame = vec![2];
            frame.extend(witness.marker.encode());
            if send(&frame) {
                self.blocks.pop_front();
                self.queued_blocks.remove(&hash);
                self.repair_blocks.remove(&hash);
                first_block_frame = 1;
            } else {
                complete = false;
                terminal_blocked = true;
            }
        }
        for _ in 0..2 {
            let Some(&hash) = self.repairs.front() else {
                break;
            };
            let mut frame = vec![5];
            frame.extend_from_slice(&hash);
            if !send(&frame) {
                complete = false;
                break;
            }
            self.repairs.pop_front();
            self.queued_repairs.remove(&hash);
        }
        for _ in 0..16 {
            let Some(&id) = self.evidence.front() else {
                break;
            };
            let frame = &evidence
                .get(&id)
                .ok_or_else(|| anyhow!("PQ evidence retention missing"))?
                .1;
            if !send(frame) {
                complete = false;
                break;
            }
            self.evidence.pop_front();
            self.queued_evidence.remove(&id);
            self.repair_evidence.remove(&id);
        }
        let mut bulk_blocked = false;
        for _ in first_block_frame..256 {
            if terminal_blocked {
                break;
            }
            let Some(&(hash, index)) = self.blocks.front() else {
                break;
            };
            let Some(witness) = blocks.get(&hash).or_else(|| outgoing.get(&hash)) else {
                // A bounded historical cache can release its body while the
                // exact hash and partial cursor remain queued for lazy reload.
                ensure!(
                    self.repair_blocks.contains(&hash),
                    "PQ deferred witness missing"
                );
                break;
            };
            let (frame, terminal) = if let Some(shred) = witness.shreds.get(index) {
                let mut frame = vec![1];
                frame.extend(shred.encode()?);
                (frame, false)
            } else {
                let mut frame = vec![2];
                frame.extend(witness.marker.encode());
                (frame, true)
            };
            if !send(&frame) {
                complete = false;
                bulk_blocked = !terminal;
                break;
            }
            if terminal {
                self.blocks.pop_front();
                self.queued_blocks.remove(&hash);
                self.repair_blocks.remove(&hash);
            } else {
                self.blocks.front_mut().unwrap().1 += 1;
            }
        }
        for _ in 0..64 {
            if bulk_blocked {
                break;
            }
            let Some((&sequence, &id)) = gossip.range(self.next_transaction..).next() else {
                break;
            };
            let Some(raw) = mempool.get(&id) else {
                self.next_transaction = sequence + 1;
                continue;
            };
            let mut frame = vec![4];
            frame.extend_from_slice(raw);
            if !send(&frame) {
                return Ok(false);
            }
            self.next_transaction = sequence + 1;
        }
        Ok(complete)
    }
}

fn compact_evidence_packets(
    through: u64,
    packets: &mut BTreeMap<Commitment, (u64, Vec<u8>)>,
    outbound: &mut BTreeMap<Pubkey, PeerOutbound>,
) {
    packets.retain(|id, (slot, _)| {
        *slot > through
            || outbound
                .values()
                .any(|queue| queue.repair_evidence.contains(id))
    });
    for queue in outbound.values_mut() {
        queue.evidence.retain(|id| packets.contains_key(id));
        queue.queued_evidence = queue.evidence.iter().copied().collect();
        queue
            .repair_evidence
            .retain(|id| queue.queued_evidence.contains(id));
    }
}

#[derive(Default)]
struct CandidateCryptoTimings {
    authentication_us: u64,
    reconstruction_us: u64,
}

struct CoordinatorTimings {
    window_started: Instant,
    turns: u64,
    active_us: u64,
    max_turn_us: u64,
    phase_us: [u64; 9],
    phase_max_us: [u64; 9],
    records: [u64; 4],
}

#[derive(Debug)]
struct InternalPqError(&'static str);
impl std::fmt::Display for InternalPqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for InternalPqError {}

#[derive(Debug)]
struct JournalShutdownResolved;
impl std::fmt::Display for JournalShutdownResolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PQ requested shutdown after resolving the outstanding append")
    }
}
impl std::error::Error for JournalShutdownResolved {}

fn fatal_receive_error(error: &anyhow::Error) -> bool {
    // Peer encoding/signature/admission failures may be rejected. A durable
    // ledger failure or internal recovery-journal limit must stop the service
    // before any resulting consensus action or subsequent frame is applied.
    error
        .downcast_ref::<solana_ledger::blockstore::error::BlockstoreError>()
        .is_some()
        || error.downcast_ref::<InternalPqError>().is_some()
        || matches!(
            error.downcast_ref::<QuantumglowError>(),
            Some(
                QuantumglowError::JournalBounds
                    | QuantumglowError::Journal
                    | QuantumglowError::SafetyViolation
                    | QuantumglowError::Clock
                    | QuantumglowError::Config
                    | QuantumglowError::EpochTransition
                    | QuantumglowError::InvalidExecution
            )
        )
}

impl CoordinatorTimings {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            turns: 0,
            active_us: 0,
            max_turn_us: 0,
            phase_us: [0; 9],
            phase_max_us: [0; 9],
            records: [0; 4],
        }
    }

    fn record(&mut self, phases: [u64; 9], records: [u64; 4], active_us: u64) {
        self.turns += 1;
        self.active_us = self.active_us.saturating_add(active_us);
        self.max_turn_us = self.max_turn_us.max(active_us);
        for (index, duration) in phases.into_iter().enumerate() {
            self.phase_us[index] = self.phase_us[index].saturating_add(duration);
            self.phase_max_us[index] = self.phase_max_us[index].max(duration);
        }
        for (sum, count) in self.records.iter_mut().zip(records) {
            *sum = sum.saturating_add(count);
        }
        if self.window_started.elapsed() >= Duration::from_secs(1) {
            info!(
                "PQ coordinator window_us={} turns={} active_us={} max_turn_us={} ingress_us={} \
                 frame_collect_us={} poll_pipeline_us={} receive_batch_us={} \
                 tick_persist_drive_us={} compact_us={} produce_us={} outbound_stream_us={} \
                 retry_status_us={} ingress_max_us={} frame_collect_max_us={} \
                 poll_pipeline_max_us={} receive_batch_max_us={} tick_persist_drive_max_us={} \
                 compact_max_us={} produce_max_us={} outbound_stream_max_us={} \
                 retry_status_max_us={} ingress_records={} received_frames={} tick_calls={} \
                 retry_calls={}",
                elapsed_us(self.window_started),
                self.turns,
                self.active_us,
                self.max_turn_us,
                self.phase_us[0],
                self.phase_us[1],
                self.phase_us[2],
                self.phase_us[3],
                self.phase_us[4],
                self.phase_us[5],
                self.phase_us[6],
                self.phase_us[7],
                self.phase_us[8],
                self.phase_max_us[0],
                self.phase_max_us[1],
                self.phase_max_us[2],
                self.phase_max_us[3],
                self.phase_max_us[4],
                self.phase_max_us[5],
                self.phase_max_us[6],
                self.phase_max_us[7],
                self.phase_max_us[8],
                self.records[0],
                self.records[1],
                self.records[2],
                self.records[3]
            );
            *self = Self::new();
        }
    }
}

#[derive(Default)]
struct ReceivedEvidenceGroup {
    ids: BTreeSet<Commitment>,
    actions: Vec<Action>,
}

#[cfg(test)]
struct EvidenceAuthenticationProbe {
    entered: Sender<thread::ThreadId>,
    release: Receiver<()>,
}

struct PqNode {
    public: ExperimentalPqConfig,
    local: Pubkey,
    chain: [u8; 32],
    leader: Arc<FalconKeypair>,
    signer: DurableConsensusSigner,
    machine: Quantumglow,
    durable_journal_records: u32,
    runtime: Arc<Mutex<RuntimeForks>>,
    bank_forks: Arc<RwLock<BankForks>>,
    block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
    optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    blockstore: Arc<Blockstore>,
    transport: Option<PqQuicTransport>,
    authentication_pool: Arc<rayon::ThreadPool>,
    ingress: Receiver<Vec<u8>>,
    pending_local_ingress: Option<Vec<u8>>,
    local_ingress_full_events: u64,
    local_ingress_retry_attempts: u64,
    peer_ingress_full_events: u64,
    #[cfg(test)]
    mempool_test_limits: Option<(usize, usize)>,
    #[cfg(test)]
    evidence_authentication_probe: Option<Arc<EvidenceAuthenticationProbe>>,
    #[cfg(test)]
    shred_decode_probe: Option<Arc<EvidenceAuthenticationProbe>>,
    #[cfg(test)]
    shred_decode_work: Arc<std::sync::atomic::AtomicUsize>,
    exit: Arc<AtomicBool>,
    status: Arc<RwLock<Value>>,
    pending: VecDeque<Action>,
    production: Option<Production>,
    pipeline: Option<PqPipeline>,
    pending_finalizations: VecDeque<BlockRef>,
    speculative_ids: BTreeMap<u64, BTreeSet<Commitment>>,
    streaming: BTreeMap<Commitment, StreamingProposal>,
    resume_intents: BTreeMap<u64, solana_ledger::blockstore::ExperimentalPqProposalIntent>,
    receiving_batch: bool,
    received_evidence: Option<ReceivedEvidenceGroup>,
    completion_attempts: BTreeSet<(u64, Commitment)>,
    assemblers: BTreeMap<(u64, Commitment), CandidateAssembler>,
    candidate_timings: BTreeMap<(u64, Commitment), CandidateCryptoTimings>,
    markers: BTreeMap<(u64, Commitment), FinalMarker>,
    blocks: BTreeMap<Commitment, BlockWitness>,
    block_slots: BTreeMap<Commitment, u64>,
    durable_block_slots: BTreeMap<Commitment, u64>,
    outbound_witnesses: BTreeMap<Commitment, BlockWitness>,
    waiting_parents: BTreeMap<Commitment, BlockWitness>,
    waiting_parent_bytes: usize,
    // Full bodies remain bounded separately. These authenticated descriptors
    // allow evicted ancestors to be reacquired after their native parent exists.
    deferred_refetches: BTreeMap<Commitment, DeferredRefetch>,
    parent_repairs: BTreeMap<Commitment, RepairRetry>,
    repair_responses: BTreeMap<(Pubkey, Commitment), RepairResponse>,
    repair_response_cursor: Option<(Pubkey, Commitment)>,
    next_repair_admission: u64,
    repair_progress: BTreeMap<Commitment, u64>,
    completed_candidates: BTreeSet<(u64, Commitment)>,
    proposed: BTreeMap<u64, BlockWitness>,
    mempool: IndexedMempool,
    mempool_order: IndexedAdmissionOrder,
    seen_evidence: BTreeSet<Commitment>,
    outbound: BTreeMap<Pubkey, PeerOutbound>,
    evidence_packets: BTreeMap<Commitment, (u64, Vec<u8>)>,
    gossip_log: BTreeMap<u64, Commitment>,
    submitted: u64,
    finalized_transactions: u64,
    invalid_packets: u64,
    send_rejected: u64,
    last_retry: Instant,
}

impl PqNode {
    fn new(
        mut public: ExperimentalPqConfig,
        bank_forks: Arc<RwLock<BankForks>>,
        blockstore: Arc<Blockstore>,
        exit: Arc<AtomicBool>,
        ingress: Receiver<Vec<u8>>,
        status: Arc<RwLock<Value>>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    ) -> Result<Self> {
        if public.start_unix_ms == 0 {
            public.start_unix_ms = wall_ms();
        }
        let chain: [u8; 32] = decode_hex(&public.chain)?
            .try_into()
            .map_err(|_| anyhow!("PQ chain length"))?;
        let local = Pubkey::from_str(&public.local_id)?;
        let network = Arc::new(FalconKeypair::load_private(
            public.key_directory.join("network.key"),
        )?);
        let leader = Arc::new(FalconKeypair::load_private(
            public.key_directory.join("leader.key"),
        )?);
        let mut validators = Vec::new();
        let mut registry = BTreeMap::new();
        let mut peers = BTreeMap::new();
        let mut leader_keys = BTreeMap::new();
        let mut peer_leaders = Vec::new();
        let mut local_key = None;
        for peer in &public.peers {
            let id = Pubkey::from_str(&peer.id)?;
            let net = FalconPublicKey::from_bytes(&decode_hex(&peer.network_key)?)?;
            let block_key = FalconPublicKey::from_bytes(&decode_hex(&peer.leader_key)?)?;
            let consensus = ConsensusPublicKey::from_bytes(&decode_hex(&peer.consensus_key)?)?;
            if id == local {
                ensure!(
                    net == network.public_key() && block_key == leader.public_key(),
                    "PQ private role key mismatch"
                );
                local_key = Some(consensus.clone());
            }
            registry.insert(id, net);
            if id != local {
                peers.insert(id, peer.address);
            }
            leader_keys.insert(id.to_bytes(), block_key);
            peer_leaders.push(SlotLeader {
                id,
                vote_address: peer
                    .vote_account
                    .as_ref()
                    .map(|x| Pubkey::from_str(x))
                    .transpose()?
                    .unwrap_or(id),
            });
            validators.push(PqValidator {
                id: id.to_bytes(),
                stake: peer.stake,
                key: consensus,
            });
        }
        let monotonic = Arc::new(FileMonotonicStore::open(
            public.key_directory.join("monotonic.store"),
        )?);
        let signer = DurableConsensusSigner::recover(
            public.key_directory.join("ax.state"),
            local_key.ok_or_else(|| anyhow!("PQ local role absent"))?,
            monotonic,
        )?;
        let root = bank_forks.read().unwrap().root_bank();
        let runtime_config = root
            .pq_config()?
            .ok_or_else(|| anyhow!("PQ genesis authentication configuration missing"))?;
        ensure!(
            runtime_config.chain_id == chain,
            "PQ runtime chain differs from consensus role chain"
        );
        let role_registry = root
            .get_account(&solana_runtime::pq::ROLE_REGISTRY_ADDRESS)
            .ok_or_else(|| anyhow!("PQ on-chain role registry missing"))?;
        ensure!(
            role_registry.owner() == &solana_runtime::pq::PROGRAM_ID && !role_registry.executable(),
            "PQ role registry account ownership"
        );
        ensure!(
            role_registry.data() == genesis_role_registry_bytes(&public)?,
            "PQ role registry differs from trusted on-chain state"
        );
        ensure!(
            root.slot() + 1 == public.first_slot,
            "PQ startup must load the authenticated activation anchor, then replay PQ history"
        );
        let vote_accounts = root.vote_accounts();
        for leader in &peer_leaders {
            let (_, vote) = vote_accounts
                .get(&leader.vote_address)
                .ok_or_else(|| anyhow!("PQ scheduled leader has no native vote account"))?;
            ensure!(
                vote.node_pubkey() == &leader.id,
                "PQ native vote account belongs to a different validator"
            );
        }
        root.freeze();
        let state = bank_state(&root);
        ensure!(
            decode_hex(&public.activation_state)? == state,
            "PQ activation Bank differs from the independently trusted wide checkpoint"
        );
        let anchor = hash_commitment(b"agave-pq-activation-anchor-v1", &[&chain, &state]);
        let leaders: Vec<_> = (0..public.slot_count)
            .map(|slot| peer_leaders[(slot / public.window_size) as usize % peer_leaders.len()])
            .collect();
        let runtime = Arc::new(Mutex::new(RuntimeForks {
            banks: BTreeMap::from([(anchor, root.clone())]),
            states: BTreeMap::from([(anchor, state)]),
            executions: BTreeMap::new(),
            archives: BTreeMap::new(),
            leaders: leaders.clone(),
            first_slot: public.first_slot,
            chain,
            max_block_bytes: public.target_block_bytes,
            max_transactions: public.max_transactions,
            executor: Arc::new(PqExecutor::new(public.execution_threads)?),
        }));
        let callback = runtime.clone();
        let config = Config {
            chain,
            epoch: public.epoch,
            first_slot: public.first_slot,
            slot_count: public.slot_count,
            window_size: public.window_size,
            network_delay_ms: public.network_delay_ms,
            block_time_ms: public.block_time_ms,
            leaders: leaders.iter().map(|x| x.id.to_bytes()).collect(),
            leader_keys,
            finalized_anchor: BlockRef {
                slot: root.slot(),
                hash: anchor,
            },
            finalized_state_root: state,
            execution_rules: hash_commitment(
                b"agave-pq-svm-execution-v1",
                &[&chain, &state, &genesis_role_registry_bytes(&public)?],
            ),
            validate_execution: Arc::new(move |candidate| {
                callback.lock().ok()?.validate(candidate)
            }),
        };
        let machine = Quantumglow::new(config, local.to_bytes(), validators)?;
        let mut node = Self {
            outbound: public
                .peers
                .iter()
                .filter_map(|peer| {
                    let id = Pubkey::from_str(&peer.id).ok()?;
                    (id != local).then_some((
                        id,
                        PeerOutbound {
                            next_transaction: 1,
                            ..PeerOutbound::default()
                        },
                    ))
                })
                .collect(),
            public,
            local,
            chain,
            leader,
            signer,
            durable_journal_records: machine.recovery_record_count(),
            machine,
            runtime,
            bank_forks,
            block_commitment_cache,
            optimistically_confirmed_bank,
            blockstore,
            transport: None,
            authentication_pool: Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(
                        thread::available_parallelism().map_or(1, |count| count.get().min(8)),
                    )
                    .thread_name(|index| format!("agavePqAuth{index}"))
                    .build()?,
            ),
            ingress,
            pending_local_ingress: None,
            local_ingress_full_events: 0,
            local_ingress_retry_attempts: 0,
            peer_ingress_full_events: 0,
            #[cfg(test)]
            mempool_test_limits: None,
            #[cfg(test)]
            evidence_authentication_probe: None,
            #[cfg(test)]
            shred_decode_probe: None,
            #[cfg(test)]
            shred_decode_work: Arc::default(),
            exit,
            status,
            pending: VecDeque::new(),
            production: None,
            pipeline: None,
            pending_finalizations: VecDeque::new(),
            speculative_ids: BTreeMap::new(),
            streaming: BTreeMap::new(),
            resume_intents: BTreeMap::new(),
            receiving_batch: false,
            received_evidence: None,
            completion_attempts: BTreeSet::new(),
            assemblers: BTreeMap::new(),
            candidate_timings: BTreeMap::new(),
            markers: BTreeMap::new(),
            blocks: BTreeMap::new(),
            block_slots: BTreeMap::from([(anchor, root.slot())]),
            durable_block_slots: BTreeMap::new(),
            outbound_witnesses: BTreeMap::new(),
            waiting_parents: BTreeMap::new(),
            waiting_parent_bytes: 0,
            deferred_refetches: BTreeMap::new(),
            parent_repairs: BTreeMap::new(),
            repair_responses: BTreeMap::new(),
            repair_response_cursor: None,
            next_repair_admission: 1,
            repair_progress: BTreeMap::new(),
            completed_candidates: BTreeSet::new(),
            proposed: BTreeMap::new(),
            mempool: IndexedMempool::default(),
            mempool_order: IndexedAdmissionOrder::default(),
            seen_evidence: BTreeSet::new(),
            evidence_packets: BTreeMap::new(),
            gossip_log: BTreeMap::new(),
            submitted: 0,
            finalized_transactions: 0,
            invalid_packets: 0,
            send_rejected: 0,
            last_retry: Instant::now(),
        };
        // Public verifier preparation must precede native journal replay: a
        // historical VerifySeed transaction still executes and verifies in
        // the SVM, with immutable public preparation already available.
        if node.public.prewarm_seed_verifier {
            let started = Instant::now();
            agave_pq_crypto::seed_proof::prewarm_seed_verifier()?;
            info!(
                "PQ seed verifier prewarm completed elapsed_us={}",
                elapsed_us(started)
            );
        }
        let storage = node.blockstore.clone();
        let header = storage.visit_experimental_pq_journal(|header, bytes| {
            if header[1..49] != node.machine.journal_binding() {
                return Err(
                    solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                        "PQ recovery binding".into(),
                    ),
                );
            }
            let mut at = 0;
            while at < bytes.len() {
                let (consumed, actions, block) =
                    node.machine.replay_record(&bytes[at..]).map_err(|error| {
                        solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                            format!("PQ replay: {error}"),
                        )
                    })?;
                at += consumed;
                if let Some(block) = block {
                    let raw = storage
                        .get_experimental_pq_block(block.slot, block.hash)?
                        .ok_or_else(|| {
                            solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                                "PQ recovery witness missing".into(),
                            )
                        })?;
                    let witness = BlockWitness::decode(&raw).map_err(|error| {
                        solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                            error.to_string(),
                        )
                    })?;
                    node.completed_candidates
                        .insert((block.slot, witness.marker.candidate));
                    node.block_slots.insert(block.hash, block.slot);
                    node.blocks.insert(block.hash, witness);
                }
                for action in actions {
                    if let Action::Finalized(block) = action {
                        node.finalize_sync(block).map_err(|error| {
                            solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                                error.to_string(),
                            )
                        })?;
                    }
                }
                node.compact().map_err(|error| {
                    solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                        error.to_string(),
                    )
                })?;
                let count = node.machine.recovery_record_count();
                node.machine
                    .discard_durable_records(count)
                    .map_err(|error| {
                        solana_ledger::blockstore::error::BlockstoreError::InvalidShredData(
                            error.to_string(),
                        )
                    })?;
            }
            Ok(())
        })?;
        if let Some(header) = header {
            ensure!(
                node.machine.recovery_record_count()
                    == u32::from_le_bytes(header[49..53].try_into().unwrap()),
                "PQ recovery record count"
            );
        }
        node.durable_journal_records = node.machine.recovery_record_count();
        node.blockstore.visit_experimental_pq_block_index(
            node.public.first_slot,
            node.public.first_slot + node.public.slot_count - 1,
            node.public.slot_count as usize * 5,
            |slot, hash| {
                // A crash can leave a body before its journal record. This
                // key-only index is an untrusted read hint, never ancestry.
                node.durable_block_slots.insert(hash, slot);
                Ok(())
            },
        )?;
        for slot in node.public.first_slot..node.public.first_slot + node.public.slot_count {
            for evidence in node.machine.pool().retained_evidence(slot) {
                node.seen_evidence.insert(hash_commitment(
                    b"agave-pq-evidence-wire-v1",
                    &[&evidence.encode()?],
                ));
            }
        }
        for slot in node.public.first_slot..node.public.first_slot + node.public.slot_count {
            if slot
                < node
                    .bank_forks
                    .read()
                    .unwrap()
                    .root_bank()
                    .slot()
                    .saturating_sub(16)
            {
                continue;
            }
            if let Some(bytes) = node.blockstore.get_experimental_pq_block(slot, [0; 48])? {
                let witness = BlockWitness::decode(&bytes)?;
                ensure!(witness.marker.slot == slot, "PQ proposal slot mismatch");
                node.proposed.insert(slot, witness);
            }
        }
        let recovered_root = node.bank_forks.read().unwrap().root();
        for slot in node.public.first_slot..node.public.first_slot + node.public.slot_count {
            if slot <= recovered_root || node.proposed.contains_key(&slot) {
                continue;
            }
            if let Some(intent) = node.blockstore.get_experimental_pq_proposal_intent(slot)? {
                ensure!(
                    intent.chain == node.chain
                        && intent.epoch == node.public.epoch
                        && intent.slot == slot,
                    "PQ recovered proposal intent role binding differs"
                );
                node.resume_intents.insert(slot, intent);
            }
        }
        node.pending.extend(
            node.machine
                .retransmission_intents()
                .into_iter()
                .map(Action::Broadcast),
        );
        for slot in (node.public.first_slot..node.public.first_slot + node.public.slot_count)
            .step_by(node.public.window_size as usize)
        {
            if let Some(parent) = node.production_parent(slot) {
                node.pending.push_back(Action::ParentReady { slot, parent });
            }
        }
        node.transport = Some(PqQuicTransport::spawn(
            PqQuicConfig {
                chain,
                identity: local,
                signer: network,
                registry,
                peers,
                listen: node.public.listen,
            },
            node.exit.clone(),
        )?);
        node.transport
            .as_ref()
            .unwrap()
            .configure_block_tracing(PqTraceConfig {
                first_slot: node.public.first_slot,
                slot_count: node.public.slot_count,
                window_size: node.public.window_size,
            })?;
        node.pipeline = Some(PqPipeline::new()?);
        node.update_status();
        Ok(node)
    }

    fn now(&self) -> u64 {
        wall_ms()
            .saturating_sub(self.public.start_unix_ms)
            .max(self.machine.clock())
    }

    fn production_parent(&self, slot: u64) -> Option<Commitment> {
        let parents = self.machine.ready_parents(slot);
        let fixed = self
            .proposed
            .get(&slot)
            .map(|witness| witness.marker.parent)
            .or_else(|| self.resume_intents.get(&slot).map(|intent| intent.parent));
        // Authorization is additive. A recovered immutable proposal must use
        // its original authorized parent, rather than the first sorted hash.
        fixed
            .filter(|parent| parents.contains(parent))
            .or_else(|| parents.first().copied())
    }

    fn obsolete_local_ancestry(&self, slot: u64, parent: Commitment, anchor: BlockRef) -> bool {
        // Follow exact sealed witnesses and bounded private construction
        // capabilities. A raw payload intent's candidate hash is never a
        // final block identity and must not be used as a parent alias.
        if slot <= anchor.slot {
            return true;
        }
        let mut slot = slot;
        let mut parent = parent;
        if let Some(pipeline) = &self.pipeline {
            for _ in 0..=pipeline::MAX_PENDING_NATIVE_CANDIDATES {
                if parent == anchor.hash {
                    return false;
                }
                if let Some(private) = pipeline
                    .private_producer_parent
                    .as_ref()
                    .filter(|private| private.block.hash == parent)
                {
                    if private.block.slot >= slot || private.block.slot <= anchor.slot {
                        return true;
                    }
                    slot = private.block.slot;
                    parent = private.production.parent;
                    continue;
                }
                let Some(private) = pipeline.private_parents.get(&parent) else {
                    break;
                };
                if private.block.slot >= slot || private.block.slot <= anchor.slot {
                    return true;
                }
                slot = private.block.slot;
                parent = private.parent;
            }
        }
        obsolete_parent_ancestry(
            slot,
            parent,
            anchor,
            &self.block_slots,
            &self.blocks,
            &self.waiting_parents,
            Some(&self.proposed),
        )
    }

    fn local_proposal_ancestors_for_compaction(
        &self,
        anchor: BlockRef,
    ) -> Result<BTreeSet<Commitment>> {
        let mut pending = Vec::new();
        if let Some(production) = self.production {
            pending.push(production.parent);
        }
        if let Some(pipeline) = &self.pipeline {
            if let Some(production) = pipeline.producer_reservation {
                pending.push(production.parent);
            }
            if let Some(production) = pipeline.unsigned_reservation {
                pending.push(production.parent);
            }
            if let Some(prepared) = &pipeline.unsigned_ready {
                pending.push(prepared.production.parent);
            }
            // This set includes the active publisher and every pending job.
            pending.extend(pipeline.publishing.iter().copied());
            pending.extend(pipeline.private_parents.keys().copied());
            if let Some(private) = &pipeline.private_producer_parent {
                pending.push(private.block.hash);
            }
        }
        let mut retained = BTreeSet::new();
        let mut visited = BTreeSet::new();
        while let Some(hash) = pending.pop() {
            if hash == anchor.hash || !visited.insert(hash) {
                continue;
            }
            if let Some(private) = self
                .pipeline
                .as_ref()
                .and_then(|pipeline| pipeline.private_producer_parent.as_ref())
                .filter(|private| private.block.hash == hash)
            {
                pending.push(private.production.parent);
                continue;
            }
            if let Some(private) = self
                .pipeline
                .as_ref()
                .and_then(|pipeline| pipeline.private_parents.get(&hash))
            {
                // Compute-only parent metadata bridges to an exact local
                // signed ancestor; raw peer obsolete_witness rules stay unchanged.
                pending.push(private.parent);
                continue;
            }
            let Some(witness) = self
                .proposed
                .values()
                .find(|witness| witness.marker.block_commitment == hash)
            else {
                continue;
            };
            retained.insert(hash);
            // Keep the closest conflicting ancestor at/below the certified
            // root until bounded outstanding work is fenced. Its earlier
            // history is unnecessary to prove that the descendant is stale.
            if witness.marker.slot > anchor.slot {
                pending.push(witness.marker.parent);
            }
        }
        ensure!(
            retained.len() <= MAX_NATIVE_CANDIDATE_BANKS
                && visited.len() <= MAX_NATIVE_CANDIDATE_BANKS,
            "PQ retained local ancestry exceeds shared native bound"
        );
        Ok(retained)
    }

    fn native_bank_capacity(&self) -> usize {
        #[cfg(test)]
        if let Some(pipeline) = &self.pipeline {
            return pipeline.native_bank_capacity;
        }
        MAX_NATIVE_CANDIDATE_BANKS
    }

    fn reject_peer_candidate(
        &mut self,
        hash: Commitment,
        index: (u64, Commitment),
        reason: &str,
    ) -> Result<()> {
        self.invalidate_private_parent(hash)?;
        ensure!(
            self.machine.payload(&hash).is_none(),
            "cannot discard an accepted native execution capability"
        );
        {
            let mut runtime = self.runtime.lock().unwrap();
            runtime.banks.remove(&hash);
            runtime.states.remove(&hash);
            runtime.executions.remove(&hash);
            runtime.archives.remove(&hash);
        }
        self.completed_candidates.remove(&index);
        self.candidate_timings.remove(&index);
        self.assemblers.remove(&index);
        self.markers.remove(&index);
        self.deferred_refetches.remove(&hash);
        self.durable_block_slots.remove(&hash);
        self.parent_repairs.remove(&hash);
        if let Some(witness) = self.waiting_parents.remove(&hash) {
            self.waiting_parent_bytes = self
                .waiting_parent_bytes
                .checked_sub(witness.encoded_len()?)
                .context(InternalPqError("PQ rejected peer deferred byte accounting"))?;
        }
        if let Some(pipeline) = &mut self.pipeline {
            pipeline.executing.remove(&hash);
        }
        self.invalid_packets += 1;
        warn!(
            "PQ rejected peer candidate slot={} reason={}",
            index.0, reason
        );
        Ok(())
    }

    fn invalidate_private_parent(&mut self, hash: Commitment) -> Result<()> {
        if let Some(pipeline) = &mut self.pipeline {
            let mut discarded = BTreeSet::from([hash]);
            loop {
                let previous = discarded.len();
                for (hash, parent) in &pipeline.private_parents {
                    if discarded.contains(&parent.parent) {
                        discarded.insert(*hash);
                    }
                }
                if let Some(parent) = &pipeline.private_producer_parent
                    && discarded.contains(&parent.production.parent)
                {
                    discarded.insert(parent.block.hash);
                }
                for (hash, witness) in &self.waiting_parents {
                    if discarded.contains(&witness.marker.parent) {
                        discarded.insert(*hash);
                    }
                }
                if previous == discarded.len() {
                    break;
                }
            }
            for (hash, parent) in &pipeline.private_parents {
                if discarded.contains(hash) {
                    let index = (parent.block.slot, parent.payload_candidate);
                    self.completed_candidates.remove(&index);
                    self.candidate_timings.remove(&index);
                }
            }
            for hash in &discarded {
                if let Some(witness) = self.waiting_parents.remove(hash) {
                    self.waiting_parent_bytes = self
                        .waiting_parent_bytes
                        .checked_sub(witness.encoded_len()?)
                        .context(InternalPqError(
                            "PQ discarded private witness byte accounting",
                        ))?;
                    let index = (witness.marker.slot, witness.marker.candidate);
                    self.completed_candidates.remove(&index);
                    self.candidate_timings.remove(&index);
                }
            }
            pipeline
                .private_parents
                .retain(|hash, _| !discarded.contains(hash));
            pipeline
                .pending_candidates
                .retain(|output| !discarded.contains(&output.witness.marker.block_commitment));
            if pipeline
                .private_producer_parent
                .as_ref()
                .is_some_and(|parent| discarded.contains(&parent.block.hash))
            {
                pipeline.private_producer_parent = None;
            }
            if pipeline
                .unsigned_ready
                .as_ref()
                .is_some_and(|prepared| discarded.contains(&prepared.production.parent))
            {
                pipeline.unsigned_ready = None;
            }
            // Inflight compute has no effects. Its parent is checked again
            // when its capability/result returns, including after rejection.
        }
        Ok(())
    }

    fn ensure_journal_ready(&self) -> Result<()> {
        ensure!(
            self.pipeline.as_ref().is_none_or(|pipeline| {
                !pipeline.journal_failed
                    && pipeline.journal_barrier.is_none()
                    && !pipeline.journal.busy
            }),
            InternalPqError("PQ journal semantic barrier active or failed")
        );
        Ok(())
    }

    fn persist(&mut self, actions: &[Action]) -> Result<()> {
        let result = self.persist_journal(actions);
        if result.is_err()
            && let Some(pipeline) = &mut self.pipeline
        {
            pipeline.journal_failed = true;
            pipeline.stop.store(true, Ordering::Release);
        }
        // Preserve the original cause while classifying every append/worker/
        // service/ACK failure as fatal at peer receive boundaries immediately.
        result.context(InternalPqError("PQ journal persistence failed"))
    }

    fn persist_journal(&mut self, actions: &[Action]) -> Result<()> {
        self.ensure_journal_ready()?;
        let started = Instant::now();
        let finalized = actions
            .iter()
            .filter_map(|x| {
                if let Action::Finalized(block) = x {
                    Some((block.slot, block.hash))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let update = self
            .machine
            .recovery_update_since(self.durable_journal_records)?;
        let target_records = self.machine.recovery_record_count();
        let encode_us = elapsed_us(started);
        if let Some(pipeline) = &mut self.pipeline {
            let sequence = pipeline
                .journal_sequence
                .checked_add(1)
                .context("PQ journal barrier sequence exhausted")?;
            let barrier = JournalBarrier {
                sequence,
                header: update.header,
                previous_records: update.previous_records,
                target_records,
                body_bytes: update.body.len(),
            };
            let job = JournalJob {
                barrier: barrier.clone(),
                body: update.body,
                finalized,
                blockstore: self.blockstore.clone(),
                queued: Instant::now(),
                #[cfg(test)]
                gate: pipeline.journal_gate.take(),
                #[cfg(test)]
                bad_ack: std::mem::take(&mut pipeline.journal_bad_ack),
            };
            pipeline.journal_sequence = sequence;
            pipeline.journal_barrier = Some(barrier.clone());
            if let Err(error) = pipeline.journal.submit(job) {
                pipeline.journal_failed = true;
                pipeline.stop.store(true, Ordering::Release);
                return Err(error);
            }
            let waiting = Instant::now();
            let mut service_error: Option<anyhow::Error> = None;
            let mut drained_events = 0usize;
            let mut service_turns = 0usize;
            let mut wait = Duration::ZERO;
            let ack = loop {
                // A ready or newly arriving ACK wakes immediately. The timeout
                // only bounds how long signed stream service waits for a job
                // that is still blocked; it is never an unconditional sleep.
                match self.pipeline.as_mut().unwrap().journal.wait(wait) {
                    Ok(Some(ack)) => break ack,
                    Err(error) => {
                        let pipeline = self.pipeline.as_mut().unwrap();
                        pipeline.journal_failed = true;
                        pipeline.stop.store(true, Ordering::Release);
                        return Err(match service_error {
                            Some(original) => original
                                .context(format!("PQ journal append also failed: {error:#}")),
                            None => error,
                        });
                    }
                    Ok(None) => {}
                }
                // Do not run poll_pipeline, receive, admission, drive, produce,
                // compaction or promotion here. The machine already includes
                // the unacknowledged transition. Existing worker threads may
                // finish their owned jobs, but no new dispatch consumes it.
                if service_error.is_none() && !self.exit.load(Ordering::Acquire) {
                    match self.service_journal_wait() {
                        Ok(events) => {
                            drained_events = drained_events.saturating_add(events);
                            service_turns = service_turns.saturating_add(1);
                        }
                        Err(error) => {
                            #[cfg(test)]
                            if let Some(observer) =
                                &self.pipeline.as_ref().unwrap().journal_service_error
                            {
                                let _ = observer.try_send(format!("{error:#}"));
                            }
                            service_error = Some(error);
                        }
                    }
                }
                wait = Duration::from_millis(1);
            };
            let pipeline = self.pipeline.as_mut().unwrap();
            if ack.barrier != barrier
                || pipeline.journal_barrier.as_ref() != Some(&barrier)
                || self.machine.recovery_record_count() != target_records
                || self.durable_journal_records != barrier.previous_records
            {
                pipeline.journal_failed = true;
                pipeline.stop.store(true, Ordering::Release);
                bail!(InternalPqError("PQ journal ACK context differs"));
            }
            if let Some(error) = service_error {
                // The append has been resolved before failure/shutdown. Leave
                // in-memory records intact and fail-stop; replay reconciles
                // a committed suffix after any fatal service error.
                pipeline.journal_failed = true;
                pipeline.stop.store(true, Ordering::Release);
                return Err(error);
            }
            if self.exit.load(Ordering::Acquire) {
                pipeline.journal_failed = true;
                pipeline.stop.store(true, Ordering::Release);
                return Err(JournalShutdownResolved.into());
            }
            pipeline.journal_barrier = None;
            info!(
                "PQ pipeline stage=journal_ack barrier={} previous_records={} target_records={} \
                 body_bytes={} encode_us={} queue_us={} worker_append_us={} ack_wait_us={} \
                 service_turns={} drained_stream_events={} shutdown={}",
                sequence,
                barrier.previous_records,
                target_records,
                barrier.body_bytes,
                encode_us,
                ack.queue_us,
                ack.append_us,
                elapsed_us(waiting),
                service_turns,
                drained_events,
                self.exit.load(Ordering::Acquire)
            );
        } else {
            self.blockstore.append_experimental_pq_checkpoint(
                &update.header,
                update.previous_records,
                &update.body,
                &finalized,
            )?;
        }
        self.durable_journal_records = target_records;
        self.machine
            .discard_durable_records(self.durable_journal_records)?;
        Ok(())
    }

    fn service_journal_wait(&mut self) -> Result<usize> {
        ensure!(
            self.pipeline.as_ref().is_some_and(|pipeline| {
                pipeline.journal_barrier.is_some() && !pipeline.journal_failed
            }),
            InternalPqError("PQ journal wait service without active barrier")
        );
        // No inbound dequeue: the original bounded caller batch remains held
        // in arrival order, and transport keeps its independent backpressure.
        let drained = self.drain_stream_events()?;
        self.flush_streaming()?;
        Ok(drained)
    }

    fn run(&mut self) -> Result<()> {
        let result = self.run_coordinator();
        // persist still unwinds every caller before releasing its actions. Only
        // this exact successful-ACK cancellation is clean at the service edge;
        // an IO/service/ACK error during exit must remain a fatal result.
        if self.exit.load(Ordering::Acquire)
            && result
                .as_ref()
                .err()
                .is_some_and(|error| error.downcast_ref::<JournalShutdownResolved>().is_some())
        {
            Ok(())
        } else {
            result
        }
    }

    fn run_coordinator(&mut self) -> Result<()> {
        let mut last_tick = Instant::now();
        let mut coordinator = CoordinatorTimings::new();
        while !self.exit.load(Ordering::Acquire) {
            if wall_ms() < self.public.start_unix_ms {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            let turn_started = Instant::now();
            let mut phase_us = [0; 9];
            let mut records = [0; 4];
            let phase_started = Instant::now();
            records[0] = self.poll_local_ingress(128)?;
            phase_us[0] = elapsed_us(phase_started);
            let phase_started = Instant::now();
            let mut frames = Vec::new();
            let mut frame_bytes = 0usize;
            for _ in 0..256 {
                match self.transport.as_ref().unwrap().receiver.try_recv() {
                    Ok((peer, frame)) => {
                        frame_bytes += frame.len();
                        frames.push((peer, frame));
                        if frame_bytes >= MAX_BLOCK_BYTES {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            records[1] = frames.len() as u64;
            phase_us[1] = elapsed_us(phase_started);
            let (poll_us, early_produce_us) = self.poll_and_dispatch()?;
            phase_us[2] = poll_us;
            phase_us[6] = early_produce_us;
            let phase_started = Instant::now();
            self.receive_batch(frames)?;
            phase_us[3] = elapsed_us(phase_started);
            let phase_started = Instant::now();
            if last_tick.elapsed() >= Duration::from_millis(50) {
                records[2] += 1;
                let actions = self.machine.tick(self.now())?;
                self.persist(&actions)?;
                self.pending.extend(actions);
                last_tick = Instant::now();
            }
            self.drive()?;
            phase_us[4] = elapsed_us(phase_started);
            let phase_started = Instant::now();
            self.compact()?;
            phase_us[5] = elapsed_us(phase_started);
            let phase_started = Instant::now();
            self.produce()?;
            phase_us[6] = phase_us[6].saturating_add(elapsed_us(phase_started));
            let phase_started = Instant::now();
            self.flush_outbound()?;
            self.flush_streaming()?;
            phase_us[7] = elapsed_us(phase_started);
            let phase_started = Instant::now();
            if self.last_retry.elapsed() >= Duration::from_millis(300) {
                records[3] += 1;
                self.retry()?;
                self.last_retry = Instant::now();
                self.update_status();
            }
            phase_us[8] = elapsed_us(phase_started);
            coordinator.record(phase_us, records, elapsed_us(turn_started));
            thread::sleep(Duration::from_millis(1));
        }
        self.update_status();
        Ok(())
    }

    /// Dispatch a ready same-leader child before processing a collected frame
    /// batch. Transport/consensus work can then overlap the bounded producer;
    /// the later run-loop production call still handles new ParentReady actions.
    fn poll_and_dispatch(&mut self) -> Result<(u64, u64)> {
        self.ensure_journal_ready()?;
        let started = Instant::now();
        self.poll_pipeline()?;
        let poll_us = elapsed_us(started);
        let started = Instant::now();
        self.produce()?;
        Ok((poll_us, elapsed_us(started)))
    }

    fn adopted_anchor(&self) -> Result<BlockRef> {
        let slot = self.bank_forks.read().unwrap().root();
        self.machine
            .finalized_chain()
            .iter()
            .rev()
            .find(|block| block.slot == slot)
            .copied()
            .context(InternalPqError("PQ adopted root has no certified block"))
    }

    fn request_repair(&mut self, hash: Commitment) -> Result<()> {
        let anchor = self.adopted_anchor()?;
        let priority = self
            .needed_parent_repairs(anchor)
            .get(&hash)
            .copied()
            .unwrap_or_default();
        self.request_repair_with_priority(hash, priority)
    }

    fn repair_certificate_tier(&self, slot: u64, hash: Commitment) -> RepairTier {
        if self
            .machine
            .finalized_chain()
            .binary_search_by_key(&slot, |block| block.slot)
            .is_ok_and(|index| self.machine.finalized_chain()[index].hash == hash)
            || self.machine.pool().finalized(slot) == Some(hash)
            || self
                .machine
                .pool()
                .certificate_blocks(slot, true)
                .contains(&hash)
        {
            RepairTier::Certified
        } else if self
            .machine
            .pool()
            .certificate_blocks(slot, false)
            .contains(&hash)
        {
            RepairTier::Weak
        } else {
            RepairTier::Signed
        }
    }

    #[cfg(test)]
    fn has_repair_certificate(&self, slot: u64, hash: Commitment) -> bool {
        self.repair_certificate_tier(slot, hash) != RepairTier::Signed
    }

    fn certified_ancestry(
        &self,
        incoming: Option<&FinalMarker>,
    ) -> BTreeMap<Commitment, RepairTier> {
        let mut links = BTreeMap::new();
        let mut certified = BTreeMap::new();
        for (&hash, reference) in &self.deferred_refetches {
            links.insert(hash, (reference.slot, reference.parent));
            if reference.tier != RepairTier::Signed {
                certified.insert(hash, reference.tier);
            }
        }
        for witness in self.waiting_parents.values() {
            links.insert(
                witness.marker.block_commitment,
                (witness.marker.slot, witness.marker.parent),
            );
        }
        // Every stored marker has already passed the scheduled Falcon check.
        // These links affect service priority only, never native ancestry.
        for marker in self.markers.values().chain(incoming) {
            links.insert(marker.block_commitment, (marker.slot, marker.parent));
        }
        for (&hash, &(slot, _)) in &links {
            let tier = self.repair_certificate_tier(slot, hash);
            if tier != RepairTier::Signed {
                let current = certified.entry(hash).or_insert(tier);
                *current = (*current).min(tier);
            }
        }
        let mut pending = certified
            .iter()
            .map(|(hash, tier)| (*hash, *tier))
            .collect::<Vec<_>>();
        while let Some((hash, tier)) = pending.pop() {
            if let Some((_, parent)) = links.get(&hash) {
                let current = certified.entry(*parent).or_insert(RepairTier::Signed);
                if tier < *current {
                    *current = tier;
                    pending.push((*parent, tier));
                }
            }
        }
        certified
    }

    fn marker_priority(
        marker: &FinalMarker,
        certified: &BTreeMap<Commitment, RepairTier>,
    ) -> RepairPriority {
        RepairPriority {
            tier: certified
                .get(&marker.block_commitment)
                .copied()
                .unwrap_or(RepairTier::Signed),
            slot: marker.slot,
        }
    }

    fn forget_parent_request(&mut self, hash: Commitment) {
        self.parent_repairs.remove(&hash);
        for queue in self.outbound.values_mut() {
            queue.repairs.retain(|queued| *queued != hash);
            queue.queued_repairs.remove(&hash);
        }
    }

    fn request_repair_with_priority(
        &mut self,
        hash: Commitment,
        priority: RepairPriority,
    ) -> Result<()> {
        let anchor = self.adopted_anchor()?;
        if self.waiting_parents.contains_key(&hash)
            || self.runtime.lock().unwrap().banks.contains_key(&hash)
            || self
                .block_slots
                .get(&hash)
                .is_some_and(|slot| *slot <= anchor.slot && hash != anchor.hash)
        {
            self.forget_parent_request(hash);
            return Ok(());
        }
        if !self.parent_repairs.contains_key(&hash)
            && self.parent_repairs.len() >= MAX_PARENT_REPAIRS
        {
            let (evict, worst) = self
                .parent_repairs
                .iter()
                .max_by_key(|(hash, retry)| (retry.priority, **hash))
                .map(|(hash, retry)| (*hash, retry.priority))
                .unwrap();
            if priority >= worst {
                return Ok(());
            }
            self.forget_parent_request(evict);
        }
        let now = self.now();
        let retry = self.parent_repairs.entry(hash).or_default();
        retry.priority = retry.priority.min(priority);
        if !retry.ready(now) {
            return Ok(());
        }
        retry.defer(now, self.public.network_delay_ms);
        let mut frame = vec![5];
        frame.extend_from_slice(&hash);
        self.broadcast(&frame);
        let requests = &self.parent_repairs;
        for queue in self.outbound.values_mut() {
            queue.repairs.make_contiguous().sort_by_key(|hash| {
                requests
                    .get(hash)
                    .map_or_else(RepairPriority::default, |retry| retry.priority)
            });
        }
        Ok(())
    }

    fn needed_parent_repairs(&self, actual: BlockRef) -> BTreeMap<Commitment, RepairPriority> {
        let certified = self.certified_ancestry(None);
        let mut needed = BTreeMap::new();
        let mut add = |hash, priority: RepairPriority| {
            let current = needed.entry(hash).or_insert(priority);
            *current = (*current).min(priority);
        };
        for witness in self.waiting_parents.values() {
            let mut priority = Self::marker_priority(&witness.marker, &certified);
            priority.slot = priority.slot.saturating_sub(1);
            add(witness.marker.parent, priority);
        }
        let runtime = self.runtime.lock().unwrap();
        for (&hash, reference) in &self.deferred_refetches {
            let priority = RepairPriority {
                tier: certified.get(&hash).copied().unwrap_or(RepairTier::Signed),
                slot: reference.slot,
            };
            if runtime.banks.contains_key(&reference.parent) {
                add(hash, priority);
            } else {
                add(
                    reference.parent,
                    RepairPriority {
                        slot: reference.slot.saturating_sub(1),
                        ..priority
                    },
                );
            }
        }
        if let Some(production) = self.production {
            add(
                production.parent,
                RepairPriority {
                    tier: certified
                        .get(&production.parent)
                        .copied()
                        .unwrap_or(RepairTier::Signed),
                    slot: production.next.saturating_sub(1),
                },
            );
        }
        for slot in self.machine.pool().active_slots() {
            if slot > actual.slot {
                // Weak notar certificates also legitimately request withheld
                // bodies. Their repair must survive drive -> compact -> flush.
                for hash in self.machine.pool().certificate_blocks(slot, false) {
                    // A deferred body must wait for its parent, not repeatedly
                    // consume the full body cache while ancestry descends.
                    if !self.waiting_parents.contains_key(&hash)
                        && self
                            .deferred_refetches
                            .get(&hash)
                            .is_none_or(|reference| runtime.banks.contains_key(&reference.parent))
                    {
                        add(
                            hash,
                            RepairPriority {
                                tier: self.repair_certificate_tier(slot, hash),
                                slot,
                            },
                        );
                    }
                }
            }
        }
        needed
    }

    fn schedule_repair_response(&mut self, peer: Pubkey, hash: Commitment) -> Result<()> {
        let queue = self.outbound.get(&peer).context("PQ unknown repair peer")?;
        if queue.queued_blocks.contains(&hash)
            && (self.blocks.contains_key(&hash)
                || self.outbound_witnesses.contains_key(&hash)
                || !queue.repair_blocks.contains(&hash))
        {
            return Ok(());
        }
        if !self.blocks.contains_key(&hash)
            && !self.block_slots.contains_key(&hash)
            && !self.durable_block_slots.contains_key(&hash)
        {
            return Ok(());
        }
        let key = (peer, hash);
        // Unsigned durable keys locate a body but cannot establish its age or
        // certification. Authentication on reload remains mandatory.
        let slot = self
            .blocks
            .get(&hash)
            .or_else(|| self.outbound_witnesses.get(&hash))
            .map(|witness| witness.marker.slot)
            .or_else(|| self.block_slots.get(&hash).copied());
        let priority = slot.map_or_else(RepairPriority::default, |slot| RepairPriority {
            tier: self.repair_certificate_tier(slot, hash),
            slot,
        });
        if !self.repair_responses.contains_key(&key)
            && self
                .repair_responses
                .keys()
                .filter(|(id, _)| *id == peer)
                .count()
                >= MAX_PEER_REPAIR_RESPONSES
        {
            let evict = self
                .repair_responses
                .iter()
                .filter(|((id, hash), response)| {
                    *id == peer
                        && ((!queue.queued_blocks.contains(hash)
                            && (!response.requested || priority < response.retry.priority))
                            || (priority < response.retry.priority
                                && queue.repair_blocks.contains(hash)
                                && queue
                                    .blocks
                                    .iter()
                                    .any(|(queued, cursor)| queued == hash && *cursor == 0)))
                })
                .max_by_key(|(_, response)| {
                    (
                        !response.requested,
                        response.retry.priority,
                        response.admission,
                    )
                })
                .map(|(key, response)| {
                    (
                        *key,
                        response.requested,
                        response.retry.priority,
                        queue.queued_blocks.contains(&key.1),
                    )
                });
            match evict {
                Some((key, requested, worst, queued))
                    if (!queued && !requested) || priority < worst =>
                {
                    // An untouched, lower-priority historical response can
                    // yield its bounded scheduler slot to a causal predecessor.
                    // The requester retains its exact repair intent and retries;
                    // partially transmitted cursors are never removed or reset.
                    if queued {
                        let queue = self.outbound.get_mut(&peer).unwrap();
                        queue.blocks.retain(|(hash, _)| *hash != key.1);
                        queue.queued_blocks.remove(&key.1);
                        queue.repair_blocks.remove(&key.1);
                        if !self
                            .outbound
                            .values()
                            .any(|queue| queue.queued_blocks.contains(&key.1))
                        {
                            self.outbound_witnesses.remove(&key.1);
                            self.repair_progress.remove(&key.1);
                        }
                    }
                    self.repair_responses.remove(&key);
                }
                // Honest retries may exceed scheduler space. The requester
                // retains its bounded intent; saturation is not invalid data.
                _ => return Ok(()),
            }
        }
        if !self.repair_responses.contains_key(&key) {
            let admission = self.next_repair_admission;
            self.next_repair_admission = admission
                .checked_add(1)
                .context("PQ repair admission sequence exhausted")?;
            self.repair_responses.insert(
                key,
                RepairResponse {
                    admission,
                    ..RepairResponse::default()
                },
            );
        }
        let response = self.repair_responses.get_mut(&key).unwrap();
        response.requested = true;
        response.retry.priority = response.retry.priority.min(priority);
        Ok(())
    }

    fn missing_repair_front(&self, peer: Pubkey) -> Option<Commitment> {
        let queue = &self.outbound[&peer];
        queue.blocks.front().and_then(|(hash, _)| {
            (queue.repair_blocks.contains(hash)
                && !self.blocks.contains_key(hash)
                && !self.outbound_witnesses.contains_key(hash))
            .then_some(*hash)
        })
    }

    fn schedule_missing_repair_fronts(&mut self) -> Result<()> {
        let missing = self
            .outbound
            .keys()
            .filter_map(|peer| self.missing_repair_front(*peer).map(|hash| (*peer, hash)))
            .collect::<Vec<_>>();
        for (peer, hash) in missing {
            // Reuse the same bounded per-peer scheduler entry. Compaction or
            // cache eviction cannot leave a retained front cursor without a
            // reload intent, even if no new network request arrives.
            self.schedule_repair_response(peer, hash)?;
        }
        Ok(())
    }

    fn authenticate_witness(&self, witness: &BlockWitness) -> Result<VerifiedCandidate> {
        let marker = &witness.marker;
        ensure!(
            marker.leader_epoch == self.public.epoch
                && (self.public.first_slot..self.public.first_slot + self.public.slot_count)
                    .contains(&marker.slot)
                && marker.total_payload_bytes <= self.public.target_block_bytes as u64,
            "PQ durable witness context"
        );
        let leader = self.machine.config().leaders[(marker.slot - self.public.first_slot) as usize];
        let key = self.machine.config().leader_keys[&leader].clone();
        self.authentication_pool.install(|| {
            let mut assembler = CandidateAssembler::new(
                self.chain,
                key,
                self.public.epoch,
                marker.slot,
                marker.candidate,
                marker.parent,
            );
            for shreds in witness.shreds.chunks(MAX_AUTHENTICATION_BATCH) {
                for shred in assembler.authenticate_batch(shreds.to_vec())? {
                    assembler.insert_verified(shred?)?;
                }
            }
            Ok(assembler.finish_verified(marker.clone())?)
        })
    }

    fn serve_pending_repair(&mut self) -> Result<()> {
        self.schedule_missing_repair_fronts()?;
        let now = self.now();
        let eligible = self
            .repair_responses
            .iter()
            .filter(|((peer, hash), response)| {
                response.requested
                    && response.retry.ready(now)
                    && (!self.outbound[peer].queued_blocks.contains(hash)
                        || (!self.blocks.contains_key(hash)
                            && !self.outbound_witnesses.contains_key(hash)))
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        let peer = eligible
            .iter()
            .find(|key| {
                self.repair_response_cursor
                    .is_none_or(|cursor| key.0 > cursor.0)
            })
            .or_else(|| eligible.first())
            .map(|key| key.0);
        let key = eligible
            .iter()
            .filter(|key| Some(key.0) == peer)
            .min_by_key(|key| {
                let response = &self.repair_responses[key];
                (
                    self.missing_repair_front(key.0) != Some(key.1),
                    response.retry.priority,
                    response.admission,
                )
            })
            .copied();
        let Some((peer, hash)) = key else {
            return Ok(());
        };
        self.repair_response_cursor = key;
        self.repair_responses
            .get_mut(&(peer, hash))
            .unwrap()
            .retry
            .defer(now, self.public.network_delay_ms);
        let witness = if let Some(witness) = self.blocks.get(&hash) {
            witness.clone()
        } else if let Some(witness) = self.outbound_witnesses.get(&hash) {
            witness.clone()
        } else {
            let Some(slot) = self
                .block_slots
                .get(&hash)
                .or_else(|| self.durable_block_slots.get(&hash))
                .copied()
            else {
                self.repair_responses.remove(&(peer, hash));
                return Ok(());
            };
            let Some(bytes) = self.blockstore.get_experimental_pq_block(slot, hash)? else {
                self.repair_responses.remove(&(peer, hash));
                return Ok(());
            };
            let witness = BlockWitness::decode(&bytes)?;
            ensure!(
                witness.marker.slot == slot && witness.marker.block_commitment == hash,
                "PQ indexed repair witness mismatch"
            );
            self.authenticate_witness(&witness)?;
            witness
        };
        let incoming = if self.outbound_witnesses.contains_key(&hash) {
            0
        } else {
            repair_witness_bytes(&witness)
        };
        let priority = RepairPriority {
            tier: self.repair_certificate_tier(witness.marker.slot, hash),
            slot: witness.marker.slot,
        };
        let response = self.repair_responses.get_mut(&(peer, hash)).unwrap();
        response.retry.priority = response.retry.priority.min(priority);
        ensure!(incoming <= MAX_REPAIR_BYTES, "PQ individual repair budget");
        while self
            .outbound_witnesses
            .values()
            .map(repair_witness_bytes)
            .sum::<usize>()
            + incoming
            > MAX_REPAIR_BYTES
            || (incoming != 0 && self.outbound_witnesses.len() >= MAX_BUFFERED_CANDIDATES)
        {
            let evict = self
                .outbound_witnesses
                .keys()
                .filter(|hash| {
                    now.saturating_sub(self.repair_progress.get(*hash).copied().unwrap_or(0))
                        >= self.public.network_delay_ms.max(1000)
                })
                .max_by_key(|hash| {
                    let body = &self.outbound_witnesses[*hash];
                    (
                        RepairPriority {
                            tier: self.repair_certificate_tier(body.marker.slot, **hash),
                            slot: body.marker.slot,
                        },
                        u64::MAX - self.repair_progress.get(*hash).copied().unwrap_or(0),
                    )
                })
                .copied();
            let Some(evict) = evict else {
                // Retain the request, not another full decoded body. A later
                // bounded service turn retries after existing cursors advance.
                return Ok(());
            };
            self.outbound_witnesses.remove(&evict);
            self.repair_progress.remove(&evict);
            for (&id, queue) in &self.outbound {
                if queue.repair_blocks.contains(&evict)
                    && queue.queued_blocks.contains(&evict)
                    && let Some(response) = self.repair_responses.get_mut(&(id, evict))
                {
                    response.requested = true;
                    response.retry.defer(now, self.public.network_delay_ms);
                }
            }
        }
        let mut evidence = self.machine.pool().retained_evidence(witness.marker.slot);
        evidence.extend(
            self.signer
                .released_evidence_for_slot(witness.marker.slot)?,
        );
        let new_ids = evidence
            .iter()
            .map(|evidence| {
                Ok(hash_commitment(
                    b"agave-pq-evidence-wire-v1",
                    &[&evidence.encode()?],
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let queue = &self.outbound[&peer];
        if queue.repair_evidence.union(&new_ids).count() > 512 {
            return Ok(());
        }
        self.send_witness(Some(peer), &witness)?;
        self.repair_progress.entry(hash).or_insert(now);
        for evidence in evidence {
            let mut frame = vec![3];
            frame.extend(evidence.encode()?);
            self.queue_evidence(Some(peer), frame)?;
        }
        self.repair_responses
            .get_mut(&(peer, hash))
            .unwrap()
            .requested = false;
        Ok(())
    }

    fn mempool_limits(&self) -> (usize, usize) {
        #[cfg(test)]
        if let Some(limits) = self.mempool_test_limits {
            return limits;
        }
        (MAX_MEMPOOL_TRANSACTIONS, MAX_MEMPOOL_BYTES)
    }

    /// Retry the single held local front before dequeuing another item. A full
    /// mempool leaves the bounded RPC channel queued and lets consensus, peer
    /// reception and ordered archive/promotion run normally this turn.
    fn poll_local_ingress(&mut self, maximum: usize) -> Result<u64> {
        self.ensure_journal_ready()?;
        let mut attempted = 0;
        for _ in 0..maximum {
            let raw = match self.pending_local_ingress.take() {
                Some(raw) => {
                    self.local_ingress_retry_attempts += 1;
                    raw
                }
                None => match self.ingress.try_recv() {
                    Ok(raw) => raw,
                    Err(_) => break,
                },
            };
            attempted += 1;
            if let Err(error) = self.admit(raw, true) {
                if fatal_receive_error(&error) {
                    return Err(error);
                }
                match error.downcast::<MempoolFull>() {
                    Ok(MempoolFull(raw)) => {
                        self.pending_local_ingress = Some(raw);
                        self.local_ingress_full_events += 1;
                        break;
                    }
                    Err(error) => {
                        self.invalid_packets += 1;
                        debug!("rejected PQ local ingress: {error:#}");
                    }
                }
            }
        }
        Ok(attempted)
    }

    fn admit(&mut self, raw: Vec<u8>, relay: bool) -> Result<()> {
        self.ensure_journal_ready()?;
        ensure!(raw.len() <= MAX_TRANSACTION_BYTES, "PQ transaction bytes");
        let id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&raw]);
        if self.mempool.contains_key(&id) {
            return Ok(());
        }
        let tx = decode_transaction(&raw)?;
        let root = self.bank_forks.read().unwrap().root_bank();
        verify_ingress_authentication(&root, &tx)?;
        let intent = if solana_runtime::pq::is_pq_transaction(&tx) {
            Some(solana_runtime::pq::transaction_intent_identity(
                &tx,
                &self.chain,
            )?)
        } else {
            None
        };
        let entry = MempoolEntry {
            raw,
            transaction: tx,
            intent,
        };
        self.install_admitted_entry(id, entry, &root, relay)
    }

    fn admit_prepared(&mut self, raw: Vec<u8>, prepared: PreparedIngress) -> Result<()> {
        self.ensure_journal_ready()?;
        ensure!(
            hash_commitment(b"agave-pq-transaction-wire-v1", &[&raw]) == prepared.wire,
            InternalPqError("PQ prepared ingress wire differs")
        );
        // Match the existing exact-wire mempool dedup before current policy
        // authentication. This does not trust a nonce or a truncated locator.
        if self.mempool.contains_key(&prepared.wire) {
            return Ok(());
        }
        let root = self.bank_forks.read().unwrap().root_bank();
        if !Arc::ptr_eq(&root, &prepared.root) {
            return self.admit(raw, false);
        }
        let (transaction, intent) = prepared.outcome?;
        self.install_admitted_entry(
            prepared.wire,
            MempoolEntry {
                raw,
                transaction,
                intent,
            },
            &root,
            false,
        )
    }

    fn install_admitted_entry(
        &mut self,
        id: Commitment,
        entry: MempoolEntry,
        root: &Arc<Bank>,
        relay: bool,
    ) -> Result<()> {
        if entry.processed(root)? {
            return Ok(());
        }
        let (maximum_transactions, maximum_bytes) = self.mempool_limits();
        if self.mempool.len() >= maximum_transactions
            || self.mempool.bytes + entry.len() > maximum_bytes
        {
            return Err(MempoolFull(entry.raw).into());
        }
        let sequence = self.mempool_order.reserve(id)?;
        self.mempool.insert(id, entry)?;
        self.mempool_order.insert_reserved(id, sequence);
        self.submitted += 1;
        if relay {
            assert!(self.gossip_log.insert(sequence, id).is_none());
        }
        Ok(())
    }

    fn decode_received_shred(&self, wire: &[u8]) -> Result<AuthenticatedShred> {
        #[cfg(test)]
        self.shred_decode_work.fetch_add(1, Ordering::Relaxed);
        Ok(AuthenticatedShred::decode(wire)?)
    }

    fn decode_shred_frames(
        &self,
        frames: &[(Pubkey, Vec<u8>)],
    ) -> BTreeMap<usize, Result<AuthenticatedShred>> {
        // Canonical Falcon signature parsing belongs to the existing workers;
        // completed/duplicate filtering remains AFTER decoding as before.
        self.authentication_pool.install(|| {
            frames
                .par_iter()
                .enumerate()
                .filter_map(|(position, (_, frame))| {
                    if frame.first() != Some(&1) {
                        return None;
                    }
                    let decoded = (|| -> Result<_> {
                        #[cfg(test)]
                        if let Some(probe) = &self.shred_decode_probe {
                            probe
                                .entered
                                .send(thread::current().id())
                                .context(InternalPqError("PQ shred decode probe disconnected"))?;
                            probe
                                .release
                                .recv_timeout(Duration::from_secs(5))
                                .context(InternalPqError("PQ shred decode probe timed out"))?;
                        }
                        let shred = self.decode_received_shred(&frame[1..])?;
                        let slot = shred.metadata.context.slot;
                        ensure!(
                            (self.public.first_slot
                                ..self.public.first_slot + self.public.slot_count)
                                .contains(&slot),
                            "PQ shred slot"
                        );
                        Ok(shred)
                    })();
                    Some((position, decoded))
                })
                .collect()
        })
    }

    fn receive_batch(&mut self, frames: Vec<(Pubkey, Vec<u8>)>) -> Result<()> {
        self.ensure_journal_ready()?;
        ensure!(
            frames.len() <= 256,
            InternalPqError("PQ coordinator frame batch exceeds its bounded contract")
        );
        let gossip_root = self.bank_forks.read().unwrap().root_bank();
        ensure!(
            !frames.iter().any(|(_, frame)| {
                frame.first() == Some(&4) && frame.len() <= MAX_TRANSACTION_BYTES + 1
            }) || gossip_root.is_frozen(),
            InternalPqError("PQ ingress authentication requires an immutable root")
        );
        // The existing collector can cross its 8 MiB stopping threshold by
        // one transport frame. Oversized transactions still take the original
        // bounded decoder/error path in arrival order. At most 256 inputs each
        // decode at most 16 KiB, so prepared raw inputs occupy at most 4 MiB.
        let mut gossip = self.authentication_pool.install(|| {
            frames
                .par_iter()
                .enumerate()
                .filter_map(|(position, (_, frame))| {
                    if frame.first() != Some(&4) || frame.len() > MAX_TRANSACTION_BYTES + 1 {
                        return None;
                    }
                    // Preserve the original cheap exact-wire mempool dedup.
                    // Arrival-ordered apply still runs admit for these frames;
                    // no policy or replay decision is cached by this probe.
                    let wire = hash_commitment(b"agave-pq-transaction-wire-v1", &[&frame[1..]]);
                    if self.mempool.contains_key(&wire) {
                        return None;
                    }
                    Some((
                        position,
                        prepare_ingress(gossip_root.clone(), &self.chain, &frame[1..]),
                    ))
                })
                .collect::<BTreeMap<_, _>>()
        });
        // Only this already-collected batch is authenticated. Public epoch
        // credentials are immutable; pool application, errors and WAL groups
        // stay in arrival order below. No new frame/transport credit is taken.
        let verifier = frames
            .iter()
            .any(|(_, frame)| frame.first() == Some(&3))
            .then(|| self.machine.evidence_verifier());
        #[cfg(test)]
        let probe = self.evidence_authentication_probe.clone();
        let mut evidence = self.authentication_pool.install(|| {
            frames
                .par_iter()
                .enumerate()
                .filter_map(|(position, (_, frame))| {
                    if frame.first() != Some(&3) {
                        return None;
                    }
                    let prepared = (|| -> Result<_> {
                        let decoded = SignedEvidence::decode(&frame[1..])?;
                        let id = hash_commitment(b"agave-pq-evidence-wire-v1", &[&frame[1..]]);
                        // Preserve the old cheap exact-wire dedup. The serial path
                        // repeats decode/dedup for these already seen inputs.
                        if self.seen_evidence.contains(&id) {
                            return Ok(None);
                        }
                        #[cfg(test)]
                        if let Some(probe) = &probe {
                            probe
                                .entered
                                .send(thread::current().id())
                                .context(InternalPqError(
                                    "PQ evidence authentication probe disconnected",
                                ))?;
                            probe.release.recv_timeout(Duration::from_secs(5)).context(
                                InternalPqError("PQ evidence authentication probe timed out"),
                            )?;
                        }
                        Ok(Some((id, verifier.as_ref().unwrap().prepare(decoded))))
                    })();
                    Some((position, prepared))
                })
                .collect::<BTreeMap<_, _>>()
        });
        let mut groups = BTreeMap::<(u64, Commitment), Vec<(usize, AuthenticatedShred)>>::new();
        let mut authenticated = BTreeMap::<usize, Result<VerifiedShred>>::new();
        let mut ungrouped_decodes = BTreeMap::new();
        for (position, decoded) in self.decode_shred_frames(&frames) {
            match decoded {
                Ok(shred) => {
                    let index = (
                        shred.metadata.context.slot,
                        shred.metadata.context.candidate,
                    );
                    if !self.completed_candidates.contains(&index) {
                        groups.entry(index).or_default().push((position, shred));
                    } else {
                        // Retain the exact parsed value, not a stale decision
                        // to ignore it. The arrival path rechecks current state.
                        ungrouped_decodes.insert(position, shred);
                    }
                }
                Err(error) => {
                    authenticated.insert(position, Err(error));
                }
            }
        }
        for (index, group) in groups {
            let (positions, shreds): (Vec<_>, Vec<_>) = group.into_iter().unzip();
            let scheduled =
                self.machine.config().leaders[(index.0 - self.public.first_slot) as usize];
            let leader = self.machine.config().leader_keys[&scheduled].clone();
            let authentication_started = Instant::now();
            let results = self.authentication_pool.install(|| {
                authenticate_shred_group(
                    self.assemblers.get(&index),
                    self.chain,
                    leader,
                    self.public.epoch,
                    shreds,
                )
            });
            self.record_crypto_timing(index, elapsed_us(authentication_started), 0);
            match results {
                Ok(results) => {
                    for (position, result) in positions.into_iter().zip(results) {
                        authenticated.insert(position, result.map_err(Into::into));
                    }
                }
                Err(error) => {
                    for position in positions {
                        authenticated.insert(position, Err(error.clone().into()));
                    }
                }
            }
        }
        self.receiving_batch = true;
        self.received_evidence = Some(ReceivedEvidenceGroup::default());
        // Authentication workers never mutate the event machine. Apply all
        // frames, including errors, in their original arrival order.
        for (position, (peer, frame)) in frames.into_iter().enumerate() {
            // Commit an arrival-ordered consensus group before applying a
            // different frame class. In particular a failed WAL append must
            // stop a subsequent transaction admission or completion attempt.
            if frame.first() != Some(&3)
                && let Err(error) = self.commit_received_evidence()
            {
                self.receiving_batch = false;
                self.received_evidence = None;
                return Err(error);
            }
            let result = match evidence.remove(&position) {
                Some(Ok(Some((id, prepared)))) => self.receive_prepared_evidence(id, prepared),
                Some(Err(error)) => Err(error),
                Some(Ok(None)) | None => match authenticated.remove(&position) {
                    Some(Ok(shred)) => self.receive_verified_shred(shred),
                    Some(Err(error)) => Err(error),
                    None => match ungrouped_decodes.remove(&position) {
                        Some(shred) => self.receive_decoded_shred(shred),
                        None => match gossip.remove(&position) {
                            Some(prepared) => self.admit_prepared(frame[1..].to_vec(), prepared),
                            None => self.receive(peer, &frame),
                        },
                    },
                },
            };
            if let Err(error) = result {
                if fatal_receive_error(&error) {
                    self.receiving_batch = false;
                    self.received_evidence = None;
                    return Err(error);
                }
                if error.downcast_ref::<MempoolFull>().is_some() {
                    // Gossip is best effort; its originating local ingress
                    // remains queued on pressure. A full receiver is a
                    // capacity event, never invalid cryptographic evidence.
                    self.peer_ingress_full_events += 1;
                } else {
                    self.invalid_packets += 1;
                    debug!("rejected PQ frame: {error:#}");
                }
            }
        }
        if let Err(error) = self.commit_received_evidence() {
            self.receiving_batch = false;
            self.received_evidence = None;
            return Err(error);
        }
        self.receiving_batch = false;
        self.received_evidence = None;
        for index in std::mem::take(&mut self.completion_attempts) {
            if let Err(error) = self.try_complete(index) {
                if fatal_receive_error(&error) {
                    return Err(error);
                }
                self.invalid_packets += 1;
                debug!("rejected PQ completed frame batch: {error:#}");
            }
        }
        Ok(())
    }

    fn receive_prepared_evidence(
        &mut self,
        id: Commitment,
        prepared: PreparedEvidence,
    ) -> Result<()> {
        self.ensure_journal_ready()?;
        ensure!(
            prepared.wire_commitment() == Some(id),
            InternalPqError("PQ prepared evidence wire differs")
        );
        if self.seen_evidence.contains(&id)
            || self
                .received_evidence
                .as_ref()
                .is_some_and(|group| group.ids.contains(&id))
        {
            return Ok(());
        }
        let actions = self.machine.receive_prepared(prepared, self.now())?;
        self.stage_received_evidence(id, actions)
    }

    fn stage_received_evidence(&mut self, id: Commitment, actions: Vec<Action>) -> Result<()> {
        if self.receiving_batch {
            let group = self
                .received_evidence
                .as_mut()
                .context(InternalPqError("PQ missing received evidence staging"))?;
            group.ids.insert(id);
            group.actions.extend(actions);
        } else {
            self.persist(&actions)?;
            self.seen_evidence.insert(id);
            self.pending.extend(actions);
        }
        Ok(())
    }

    fn commit_received_evidence(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let group = std::mem::take(
            self.received_evidence
                .as_mut()
                .context(InternalPqError("PQ missing received evidence group"))?,
        );
        if group.ids.is_empty() {
            return Ok(());
        }
        // No new action signing/publication, native promotion dispatch or
        // authoritative completion is allowed before the synced append. Only
        // already signed streams under prior durable intents may advance.
        // persist includes every Finalized reference across the entire group.
        self.persist(&group.actions)?;
        self.seen_evidence.extend(group.ids);
        self.pending.extend(group.actions);
        Ok(())
    }

    fn receive_verified_shred(&mut self, verified: VerifiedShred) -> Result<()> {
        let context = &verified.shred().metadata.context;
        let index = (context.slot, context.candidate);
        if self.completed_candidates.contains(&index)
            || self
                .pipeline
                .as_ref()
                .is_some_and(|pipeline| pipeline.reconstructing == Some(index))
            || context.slot <= self.adopted_anchor()?.slot
        {
            return Ok(());
        }
        if !self.assemblers.contains_key(&index) {
            if !self.admit_incomplete(index, context.parent, None, false) {
                return Ok(());
            }
            let leader =
                self.machine.config().leaders[(context.slot - self.public.first_slot) as usize];
            self.assemblers.insert(
                index,
                CandidateAssembler::new(
                    self.chain,
                    self.machine.config().leader_keys[&leader].clone(),
                    self.public.epoch,
                    context.slot,
                    context.candidate,
                    context.parent,
                ),
            );
        }
        self.assemblers
            .get_mut(&index)
            .unwrap()
            .insert_verified(verified)?;
        self.try_complete(index)
    }

    fn admit_incomplete(
        &mut self,
        index: (u64, Commitment),
        parent: Commitment,
        incoming: Option<&FinalMarker>,
        marker: bool,
    ) -> bool {
        let keys = if marker {
            self.markers.keys().copied().collect::<Vec<_>>()
        } else {
            self.assemblers.keys().copied().collect::<Vec<_>>()
        };
        if keys.contains(&index) || keys.len() < MAX_BUFFERED_CANDIDATES {
            return true;
        }
        let certified = self.certified_ancestry(incoming);
        let priority = |index: (u64, Commitment), marker: Option<&FinalMarker>| {
            marker.map_or(
                RepairPriority {
                    tier: RepairTier::Signed,
                    slot: index.0,
                },
                |marker| Self::marker_priority(marker, &certified),
            )
        };
        let incoming_priority = incoming
            .or_else(|| {
                self.markers
                    .get(&index)
                    .filter(|marker| marker.parent == parent)
            })
            .map_or_else(
                || {
                    self.deferred_refetches
                        .iter()
                        .find(|(_, reference)| {
                            reference.slot == index.0
                                && reference.candidate == index.1
                                && reference.parent == parent
                        })
                        .map_or_else(
                            || priority(index, None),
                            |(hash, reference)| RepairPriority {
                                tier: certified.get(hash).copied().unwrap_or(RepairTier::Signed),
                                slot: reference.slot,
                            },
                        )
                },
                |marker| priority(index, Some(marker)),
            );
        let (evict, worst) = keys
            .iter()
            .map(|index| (*index, priority(*index, self.markers.get(index))))
            .max_by_key(|(index, priority)| (*priority, *index))
            .unwrap();
        if incoming_priority >= worst {
            return false;
        }
        // No accepted block or native execution is lost here. A subsequent
        // exact repair must reconstruct all fragments, including discarded
        // prefixes; neither an old cursor nor a marker proves completion.
        self.assemblers.remove(&evict);
        self.markers.remove(&evict);
        self.candidate_timings.remove(&evict);
        true
    }

    fn receive_decoded_shred(&mut self, shred: AuthenticatedShred) -> Result<()> {
        self.ensure_journal_ready()?;
        let context = &shred.metadata.context;
        ensure!(
            context.slot >= self.public.first_slot
                && context.slot < self.public.first_slot + self.public.slot_count,
            "PQ shred slot"
        );
        let leader =
            self.machine.config().leaders[(context.slot - self.public.first_slot) as usize];
        let key = self
            .machine
            .config()
            .leader_keys
            .get(&leader)
            .ok_or_else(|| anyhow!("PQ scheduled leader"))?
            .clone();
        let index = (context.slot, context.candidate);
        if self.completed_candidates.contains(&index) {
            return Ok(());
        }
        if !self.assemblers.contains_key(&index) {
            shred.verify(&self.chain, &key)?;
            if context.slot <= self.adopted_anchor()?.slot
                || !self.admit_incomplete(index, context.parent, None, false)
            {
                return Ok(());
            }
            self.assemblers.insert(
                index,
                CandidateAssembler::new(
                    self.chain,
                    key,
                    self.public.epoch,
                    context.slot,
                    context.candidate,
                    context.parent,
                ),
            );
        }
        self.assemblers.get_mut(&index).unwrap().insert(shred)?;
        self.try_complete(index)?;
        Ok(())
    }

    fn receive(&mut self, peer: Pubkey, frame: &[u8]) -> Result<()> {
        self.ensure_journal_ready()?;
        ensure!(!frame.is_empty(), "empty PQ frame");
        match frame[0] {
            1 => {
                let shred = self.decode_received_shred(&frame[1..])?;
                self.receive_decoded_shred(shred)?;
            }
            2 => {
                let marker = FinalMarker::decode(&frame[1..])?;
                ensure!(
                    marker.slot >= self.public.first_slot
                        && marker.slot < self.public.first_slot + self.public.slot_count,
                    "PQ marker slot"
                );
                let index = (marker.slot, marker.candidate);
                if self.completed_candidates.contains(&index)
                    || self
                        .pipeline
                        .as_ref()
                        .is_some_and(|pipeline| pipeline.reconstructing == Some(index))
                {
                    return Ok(());
                }
                let leader =
                    self.machine.config().leaders[(marker.slot - self.public.first_slot) as usize];
                let key = self
                    .machine
                    .config()
                    .leader_keys
                    .get(&leader)
                    .ok_or_else(|| anyhow!("PQ scheduled marker leader"))?;
                let authentication_started = Instant::now();
                let encoded = marker.encode();
                key.verify(
                    &self.chain,
                    Domain::LeaderBatch,
                    &encoded[..encoded.len() - 666],
                    &marker.signature,
                )?;
                self.record_crypto_timing(index, elapsed_us(authentication_started), 0);
                if marker.slot <= self.adopted_anchor()?.slot
                    || !self.admit_incomplete(index, marker.parent, Some(&marker), true)
                {
                    return Ok(());
                }
                self.markers.insert(index, marker);
                self.try_complete(index)?;
            }
            3 => {
                let evidence = SignedEvidence::decode(&frame[1..])?;
                let id = hash_commitment(b"agave-pq-evidence-wire-v1", &[&frame[1..]]);
                if self.seen_evidence.contains(&id)
                    || self
                        .received_evidence
                        .as_ref()
                        .is_some_and(|group| group.ids.contains(&id))
                {
                    return Ok(());
                }
                let actions = self.machine.receive(evidence, self.now())?;
                self.stage_received_evidence(id, actions)?;
            }
            4 => self.admit(frame[1..].to_vec(), false)?,
            5 => {
                ensure!(frame.len() == 49, "PQ repair request bounds");
                let hash: Commitment = frame[1..].try_into().unwrap();
                self.schedule_repair_response(peer, hash)?;
            }
            _ => bail!("unknown PQ frame tag"),
        }
        Ok(())
    }

    fn record_crypto_timing(
        &mut self,
        index: (u64, Commitment),
        authentication_us: u64,
        reconstruction_us: u64,
    ) {
        // Profiling buffers never affect packet admission or protocol decisions.
        if self.candidate_timings.contains_key(&index)
            || self.candidate_timings.len() < MAX_BUFFERED_CANDIDATES
        {
            let timings = self.candidate_timings.entry(index).or_default();
            timings.authentication_us = timings.authentication_us.saturating_add(authentication_us);
            timings.reconstruction_us = timings.reconstruction_us.saturating_add(reconstruction_us);
        }
    }

    fn try_complete(&mut self, index: (u64, Commitment)) -> Result<()> {
        if self.receiving_batch {
            self.completion_attempts.insert(index);
            return Ok(());
        }
        let Some(marker) = self.markers.get(&index).cloned() else {
            return Ok(());
        };
        if let Some(pipeline) = self.pipeline.as_ref() {
            if pipeline.reconstruction.busy
                || !self
                    .assemblers
                    .get(&index)
                    .is_some_and(|assembler| assembler.is_reconstructable(&marker))
            {
                return Ok(());
            }
            let assembler = self.assemblers.remove(&index).unwrap();
            self.markers.remove(&index);
            let pipeline = self.pipeline.as_mut().unwrap();
            pipeline.reconstruction.submit(ReconstructionJob {
                assembler,
                marker,
                authentication_pool: self.authentication_pool.clone(),
            })?;
            pipeline.reconstructing = Some(index);
            return Ok(());
        }
        let Some(assembler) = self.assemblers.remove(&index) else {
            return Ok(());
        };
        let reconstruction_started = Instant::now();
        let result = self
            .authentication_pool
            .install(|| assembler.try_finish_verified(marker));
        self.record_crypto_timing(index, 0, elapsed_us(reconstruction_started));
        match result {
            Ok(candidate) => {
                self.markers.remove(&index);
                self.complete_verified(candidate)
            }
            Err((NetworkError::Incomplete, assembler)) => {
                self.assemblers.insert(index, *assembler);
                Ok(())
            }
            Err((error, _)) => {
                self.markers.remove(&index);
                Err(error.into())
            }
        }
    }

    fn complete(&mut self, witness: BlockWitness) -> Result<()> {
        self.complete_candidate(witness, None)
    }

    fn complete_verified(&mut self, candidate: VerifiedCandidate) -> Result<()> {
        let witness = BlockWitness {
            marker: candidate.marker().clone(),
            shreds: candidate.shreds().to_vec(),
        };
        self.complete_candidate(witness, Some(candidate))
    }

    fn remember_refetch(&mut self, marker: &FinalMarker, priority: RepairPriority) {
        let hash = marker.block_commitment;
        if !self.deferred_refetches.contains_key(&hash)
            && self.deferred_refetches.len() >= MAX_BUFFERED_CANDIDATES
        {
            let certified = self.certified_ancestry(Some(marker));
            let (evict, worst) = self
                .deferred_refetches
                .iter()
                .max_by_key(|(hash, reference)| {
                    (
                        RepairPriority {
                            tier: certified.get(*hash).copied().unwrap_or(RepairTier::Signed),
                            slot: reference.slot,
                        },
                        **hash,
                    )
                })
                .map(|(hash, reference)| {
                    (
                        *hash,
                        RepairPriority {
                            tier: certified.get(hash).copied().unwrap_or(RepairTier::Signed),
                            slot: reference.slot,
                        },
                    )
                })
                .unwrap();
            if priority >= worst {
                return;
            }
            self.deferred_refetches.remove(&evict);
        }
        self.deferred_refetches.insert(
            hash,
            DeferredRefetch {
                slot: marker.slot,
                parent: marker.parent,
                candidate: marker.candidate,
                tier: priority.tier,
            },
        );
    }

    fn defer_candidate(&mut self, witness: BlockWitness) -> Result<()> {
        let hash = witness.marker.block_commitment;
        if self.waiting_parents.contains_key(&hash) {
            return Ok(());
        }
        let size = witness.encoded_len()?;
        ensure!(
            size <= MAX_REPAIR_BYTES,
            "PQ individual deferred witness budget"
        );
        let certified = self.certified_ancestry(Some(&witness.marker));
        let priority = Self::marker_priority(&witness.marker, &certified);
        while self.waiting_parents.len() >= MAX_BUFFERED_CANDIDATES
            || self.waiting_parent_bytes + size > MAX_REPAIR_BYTES
        {
            let (evict, worst) = self
                .waiting_parents
                .iter()
                .max_by_key(|(hash, body)| {
                    (Self::marker_priority(&body.marker, &certified), **hash)
                })
                .map(|(hash, body)| (*hash, Self::marker_priority(&body.marker, &certified)))
                .context(InternalPqError("PQ deferred witness accounting"))?;
            if priority >= worst {
                // Keep an exact, bounded authenticated re-fetch intent without
                // retaining another body. Pressure is not an invalid packet.
                self.remember_refetch(&witness.marker, priority);
                if self.deferred_refetches.contains_key(&hash) {
                    self.request_repair_with_priority(
                        witness.marker.parent,
                        RepairPriority {
                            slot: witness.marker.slot.saturating_sub(1),
                            ..priority
                        },
                    )?;
                }
                return Ok(());
            }
            let old = self.waiting_parents.remove(&evict).unwrap();
            self.waiting_parent_bytes =
                self.waiting_parent_bytes
                    .checked_sub(old.encoded_len()?)
                    .context(InternalPqError("PQ deferred parent byte accounting"))?;
            self.completed_candidates
                .remove(&(old.marker.slot, old.marker.candidate));
            self.candidate_timings
                .remove(&(old.marker.slot, old.marker.candidate));
            self.remember_refetch(&old.marker, worst);
        }
        self.deferred_refetches.remove(&hash);
        self.waiting_parent_bytes += size;
        self.completed_candidates
            .insert((witness.marker.slot, witness.marker.candidate));
        let parent = witness.marker.parent;
        self.waiting_parents.insert(hash, witness);
        // Admission precedes the request so drive -> compact -> flush cannot
        // discard this authenticated causal dependency under buffer pressure.
        self.request_repair_with_priority(
            parent,
            RepairPriority {
                slot: priority.slot.saturating_sub(1),
                ..priority
            },
        )
    }

    fn complete_candidate(
        &mut self,
        witness: BlockWitness,
        candidate: Option<VerifiedCandidate>,
    ) -> Result<()> {
        self.ensure_journal_ready()?;
        let slot = witness.marker.slot;
        let index = (slot, witness.marker.candidate);
        let shred_count = witness.shreds.len();
        let hash = witness.marker.block_commitment;
        let candidate = match candidate {
            Some(candidate) => candidate,
            None => self.authenticate_witness(&witness)?,
        };
        let anchor = self.adopted_anchor()?;
        if obsolete_witness(
            &witness,
            anchor,
            &self.block_slots,
            &self.blocks,
            &self.waiting_parents,
        ) {
            self.deferred_refetches.remove(&hash);
            return Ok(());
        }
        if self.blocks.contains_key(&hash) {
            return Ok(());
        }
        if self
            .pipeline
            .as_ref()
            .is_some_and(|pipeline| pipeline.publishing.contains(&hash))
        {
            // A peer's retransmission cannot bypass the local ordered body WAL
            // publisher or observe a child before its producer parent.
            return Ok(());
        }
        let accepted_parent = self
            .runtime
            .lock()
            .unwrap()
            .banks
            .get(&witness.marker.parent)
            .cloned();
        let parent = accepted_parent.or_else(|| {
            self.pipeline
                .as_ref()?
                .private_parents
                .get(&witness.marker.parent)
                .and_then(|parent| {
                    (parent.block.hash == witness.marker.parent).then(|| parent.bank.clone())
                })
        });
        let Some(parent) = parent else {
            return self.defer_candidate(witness);
        };
        self.deferred_refetches.remove(&hash);
        if self.pipeline.is_some() && !self.runtime.lock().unwrap().executions.contains_key(&hash) {
            let pipeline = self.pipeline.as_ref().unwrap();
            if pipeline.executing.contains_key(&hash) {
                return Ok(());
            }
            if pipeline.private_parents.contains_key(&hash) {
                return Ok(());
            }
            if pipeline.candidate.busy
                || pipeline.pending_candidates.len() >= pipeline::MAX_PENDING_NATIVE_CANDIDATES
            {
                return self.defer_candidate(witness);
            }
            let runtime = self.runtime.lock().unwrap();
            let reserved = usize::from(pipeline.producer.busy)
                + pipeline.unsigned_bank_reservation()
                + pipeline.candidate_bank_reservations(&runtime.banks);
            let at_capacity =
                runtime.banks.len().saturating_add(reserved) >= self.native_bank_capacity();
            drop(runtime);
            if at_capacity {
                return self.reject_peer_candidate(hash, index, "shared native Bank capacity");
            }
            let job = {
                let runtime = self.runtime.lock().unwrap();
                CandidateJob {
                    witness,
                    candidate,
                    parent_state: bank_state(&parent),
                    parent,
                    chain: self.chain,
                    leaders: runtime.leaders.clone(),
                    first_slot: runtime.first_slot,
                    max_block_bytes: runtime.max_block_bytes,
                    max_transactions: runtime.max_transactions,
                    executor: runtime.executor.clone(),
                    native_parent_sender: pipeline.native_parent_sender.clone(),
                    stop: pipeline.stop.clone(),
                }
            };
            let pipeline = self.pipeline.as_mut().unwrap();
            pipeline.candidate.submit(job)?;
            pipeline.executing.insert(hash, index);
            self.completed_candidates.insert(index);
            info!(
                "PQ pipeline stage=candidate_dispatch slot={} candidate={} clock_ms={}",
                slot,
                encode_hex(&hash),
                self.now()
            );
            return Ok(());
        }
        let execution_started = Instant::now();
        // This pre-WAL check distinguishes malformed or noncommitted native
        // transactions from internal/cache/storage failures. The consensus
        // callback reuses the exact bound execution capability inserted here;
        // it does not execute the candidate a second time.
        self.runtime
            .lock()
            .unwrap()
            .validate_checked(&ExecutionCandidate {
                reference: BlockRef { slot, hash },
                parent: witness.marker.parent,
                payload: candidate.payload(),
            })?;
        let actions = self.machine.observe_verified(candidate, self.now())?;
        let observe_us = elapsed_us(execution_started);
        let block_wal_started = Instant::now();
        self.blockstore
            .put_experimental_pq_block(slot, hash, &witness.encode()?)?;
        let block_wal_us = elapsed_us(block_wal_started);
        self.block_slots.insert(hash, slot);
        self.blocks.insert(hash, witness);
        if !self
            .outbound
            .values()
            .any(|queue| queue.repair_blocks.contains(&hash))
        {
            self.outbound_witnesses.remove(&hash);
        }
        let marker = &self.blocks[&hash].marker;
        self.completed_candidates
            .insert((marker.slot, marker.candidate));
        let journal_started = Instant::now();
        self.persist(&actions)?;
        let journal_wal_us = elapsed_us(journal_started);
        self.pending.extend(actions);
        let crypto = self.candidate_timings.remove(&index).unwrap_or_default();
        info!(
            "PQ phases stage=receive slot={} shreds={} authentication_us={} reconstruction_us={} \
             observe_us={} block_wal_us={} journal_wal_us={} observe_persist_us={}",
            slot,
            shred_count,
            crypto.authentication_us,
            crypto.reconstruction_us,
            observe_us,
            block_wal_us,
            journal_wal_us,
            elapsed_us(execution_started)
        );
        info!(
            "PQ validated candidate slot={} elapsed_ms={}",
            slot,
            execution_started.elapsed().as_millis()
        );
        Ok(())
    }

    fn drive(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        while let Some(action) = self.pending.pop_front() {
            match action {
                Action::Broadcast(message) => {
                    let evidence = match self.signer.reconcile_intent(&message)? {
                        IntentReconciliation::Released(evidence) => *evidence,
                        IntentReconciliation::Available { .. } => self.signer.sign(message)?,
                        IntentReconciliation::CrashBurned { .. }
                        | IntentReconciliation::Conflict(_) => {
                            continue;
                        }
                    };
                    let mut frame = vec![3];
                    frame.extend_from_slice(&evidence.encode()?);
                    let id = hash_commitment(b"agave-pq-evidence-wire-v1", &[&frame[1..]]);
                    if !self.seen_evidence.contains(&id) {
                        let actions = self.machine.receive(evidence, self.now())?;
                        self.persist(&actions)?;
                        self.pending.extend(actions);
                        self.seen_evidence.insert(id);
                    }
                    self.broadcast(&frame);
                }
                Action::ParentReady { slot, mut parent } => {
                    info!(
                        "PQ pipeline stage=parent_ready slot={} parent={} clock_ms={} \
                         native_root={}",
                        slot,
                        encode_hex(&parent),
                        self.now(),
                        self.bank_forks.read().unwrap().root()
                    );
                    let leader =
                        self.machine.config().leaders[(slot - self.public.first_slot) as usize];
                    if leader != self.local.to_bytes() {
                        continue;
                    }
                    if slot + self.public.window_size - 1
                        <= self.machine.finalized_chain().last().unwrap().slot
                        || self
                            .production
                            .is_some_and(|production| production.first > slot)
                    {
                        continue;
                    }
                    if self.pipeline.as_ref().is_some_and(|pipeline| {
                        pipeline
                            .producer_reservation
                            .is_some_and(|reserved| reserved.first == slot)
                    }) {
                        // A later strong parent does not revoke the original
                        // authorization. The worker may already have persisted
                        // and streamed its exact proposal. Even if compaction
                        // cleared production, retain its slot reservation until
                        // the result installs a used-slot fence.
                        continue;
                    }
                    if let Some(fixed) = self
                        .proposed
                        .get(&slot)
                        .map(|witness| witness.marker.parent)
                        .or_else(|| self.resume_intents.get(&slot).map(|intent| intent.parent))
                    {
                        if !self.machine.ready_parents(slot).contains(&fixed) {
                            // The slot remains used even if its original parent
                            // is no longer authorized after certified compaction.
                            continue;
                        }
                        parent = fixed;
                    }
                    let parent_available = self.runtime.lock().unwrap().banks.contains_key(&parent);
                    if let Some(production) = self.production.filter(|p| p.first == slot)
                        && (production.parent == parent
                            || production.next != slot
                            || self.proposed.contains_key(&slot)
                            || !parent_available)
                    {
                        continue;
                    }
                    if !parent_available {
                        self.request_repair(parent)?;
                    }
                    let mut next = slot;
                    let mut previous = parent;
                    let certified = *self.machine.finalized_chain().last().unwrap();
                    while next < slot + self.public.window_size {
                        match self.proposed.get(&next) {
                            Some(witness)
                                if witness.marker.parent == previous
                                    && !self.obsolete_local_ancestry(
                                        witness.marker.slot,
                                        witness.marker.parent,
                                        certified,
                                    ) =>
                            {
                                previous = witness.marker.block_commitment;
                                next += 1;
                            }
                            Some(_) => {
                                next = slot + self.public.window_size;
                                break;
                            }
                            None => break,
                        }
                    }
                    if next < slot + self.public.window_size {
                        self.production = Some(Production {
                            first: slot,
                            next,
                            parent: previous,
                            due: self.now(),
                        });
                    }
                }
                Action::Repair { block, .. } => {
                    self.request_repair(block)?;
                }
                Action::Finalized(block) => self.finalize(block)?,
                Action::Equivocation { validator, slot } => {
                    warn!("PQ equivocation at slot {slot} from {validator:?}")
                }
            }
        }
        Ok(())
    }

    fn proposal_entries(
        &self,
        production: Production,
        parent: &Bank,
    ) -> (Vec<(Commitment, Arc<MempoolEntry>)>, usize, usize) {
        #[cfg(test)]
        PROPOSAL_SNAPSHOT_CALLS.with(|calls| calls.set(calls.get() + 1));
        // Retain immutable admission entries, never an account snapshot or a
        // copy of the entire wire pool. These exact-window selections only
        // save redundant FIFO visits; native replay checks remain mandatory.
        let selected = self
            .speculative_ids
            .range(production.first..production.next)
            .flat_map(|(_, ids)| ids.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut hash_eligibility = ParentHashEligibility::new(parent);
        let mut deferred_blockhash_entries = 0usize;
        let entries = self
            .mempool_order
            .iter()
            .filter(|id| !selected.contains(*id))
            .filter_map(|id| self.mempool.get(id).map(|entry| (*id, entry)))
            .filter(|(_, entry)| {
                let eligible = hash_eligibility.eligible(&entry.transaction);
                deferred_blockhash_entries += usize::from(!eligible);
                eligible
            })
            .map(|(id, entry)| (id, entry.clone()))
            .collect::<Vec<_>>();
        (entries, selected.len(), deferred_blockhash_entries)
    }

    fn proposal_full_ready(&self, entries: &[(Commitment, Arc<MempoolEntry>)]) -> bool {
        let maximum = self
            .public
            .proposal_max_transactions
            .unwrap_or(self.public.max_transactions);
        let target = self
            .public
            .proposal_target_block_bytes
            .unwrap_or(self.public.target_block_bytes);
        entries.len() >= maximum
            || entries
                .iter()
                .take(maximum)
                .map(|(_, entry)| entry.len() + 4)
                .sum::<usize>()
                >= target.saturating_sub(MAX_TRANSACTION_BYTES)
    }

    fn prepared_reuse_readiness(
        &self,
        production: Production,
        parent: &Bank,
    ) -> PreparedReuseReadiness {
        let maximum = self
            .public
            .proposal_max_transactions
            .unwrap_or(self.public.max_transactions);
        let target = self
            .public
            .proposal_target_block_bytes
            .unwrap_or(self.public.target_block_bytes)
            .saturating_sub(MAX_TRANSACTION_BYTES);
        let selected = self
            .speculative_ids
            .range(production.first..production.next)
            .flat_map(|(_, ids)| ids.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut observation = PreparedReuseReadiness {
            full_ready: maximum == 0 || target == 0,
            speculative_selected: selected.len(),
            ..PreparedReuseReadiness::default()
        };
        let mut hash_eligibility = ParentHashEligibility::new(parent);
        if observation.full_ready {
            return observation;
        }
        for id in self.mempool_order.iter() {
            observation.fifo_rows_scanned += 1;
            if selected.contains(id) {
                continue;
            }
            let Some(entry) = self.mempool.get(id) else {
                continue;
            };
            if !hash_eligibility.eligible(&entry.transaction) {
                observation.deferred_blockhash_entries_scanned += 1;
                continue;
            }
            observation.eligible_entries_lower_bound += 1;
            observation.eligible_bytes_lower_bound += entry.len() + 4;
            observation.full_ready = observation.eligible_entries_lower_bound >= maximum
                || observation.eligible_bytes_lower_bound >= target;
            if observation.full_ready {
                break;
            }
        }
        observation
    }

    fn prepare_next_leader(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let Some(pipeline) = &self.pipeline else {
            return Ok(());
        };
        if pipeline.unsigned_preparation.busy || pipeline.unsigned_ready.is_some() {
            return Ok(());
        }
        let anchor = *self.machine.finalized_chain().last().unwrap();
        let current_first = self.public.first_slot
            + anchor.slot.saturating_sub(self.public.first_slot) / self.public.window_size
                * self.public.window_size;
        let private = pipeline
            .private_parents
            .values()
            .filter(|parent| {
                parent.block.slot >= self.public.first_slot
                    && (parent.block.slot > anchor.slot || parent.block.hash == anchor.hash)
                    && (parent.block.slot + 1 - self.public.first_slot)
                        .is_multiple_of(self.public.window_size)
            })
            .min_by_key(|parent| parent.block.slot);
        let first = private.map_or(current_first + self.public.window_size, |parent| {
            parent.block.slot + 1
        });
        let ready_parents = self.machine.ready_parents(first);
        let at_capacity = {
            let runtime = self.runtime.lock().unwrap();
            runtime.banks.len()
                + usize::from(pipeline.producer.busy)
                + pipeline.candidate_bank_reservations(&runtime.banks)
                >= self.native_bank_capacity()
        };
        if first >= self.public.first_slot + self.public.slot_count
            || self.machine.config().leaders[(first - self.public.first_slot) as usize]
                != self.local.to_bytes()
            || pipeline.unsigned_attempted == Some(first)
            || self.proposed.contains_key(&first)
            || self.resume_intents.contains_key(&first)
            || (!ready_parents.is_empty()
                && !private.is_some_and(|parent| ready_parents.contains(&parent.block.hash)))
            || pipeline
                .producer_reservation
                .is_some_and(|reserved| reserved.next == first)
            || at_capacity
        {
            return Ok(());
        }
        // This is a prediction only: an earlier strong skipped-window parent
        // can still win. The exact signed/native-validated last Bank is immutable.
        let parent = private
            .map(|parent| (parent.block.hash, parent.bank.clone()))
            .or_else(|| {
                let runtime = self.runtime.lock().unwrap();
                runtime
                    .banks
                    .iter()
                    .find(|(hash, bank)| {
                        bank.slot() == first - 1
                            && bank.is_frozen()
                            && self.machine.payload(hash).is_some()
                    })
                    .map(|(hash, bank)| (*hash, bank.clone()))
            });
        let Some((parent_hash, parent)) = parent else {
            return Ok(());
        };
        if self.obsolete_local_ancestry(first, parent_hash, anchor) {
            return Ok(());
        }
        let production = Production {
            first,
            next: first,
            parent: parent_hash,
            due: self.now(),
        };
        self.dispatch_unsigned_preparation(production, parent, &BTreeSet::new())
    }

    fn dispatch_unsigned_preparation(
        &mut self,
        production: Production,
        parent: Arc<Bank>,
        excluded: &BTreeSet<Commitment>,
    ) -> Result<()> {
        let first = production.next;
        let parent_hash = production.parent;
        let (mut entries, _, _) = self.proposal_entries(production, &parent);
        entries.retain(|(id, _)| !excluded.contains(id));
        // Idle work stays in the ordinary coalescing path. Never reserve an
        // empty speculative payload ahead of newly arriving offered traffic.
        if !self.proposal_full_ready(&entries) {
            return Ok(());
        }
        let (slot_leader, executor) = {
            let runtime = self.runtime.lock().unwrap();
            (
                runtime.leaders[(first - self.public.first_slot) as usize],
                runtime.executor.clone(),
            )
        };
        let pipeline = self.pipeline.as_mut().unwrap();
        pipeline.unsigned_preparation.submit(PreparationJob {
            production,
            parent,
            rooted: self.bank_forks.read().unwrap().root_bank(),
            slot_leader,
            chain: self.chain,
            public: self.public.clone(),
            entries,
            executor,
            authentication_pool: self.authentication_pool.clone(),
            stop: pipeline.stop.clone(),
            fixed_payload: None,
            queued_at: Instant::now(),
            unsigned: true,
        })?;
        pipeline.unsigned_reservation = Some(production);
        pipeline.unsigned_attempted = Some(first);
        info!(
            "PQ pipeline stage=unsigned_dispatch slot={} parent={}",
            first,
            encode_hex(&parent_hash)
        );
        Ok(())
    }

    fn poll_private_producer_parent(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let pipeline = self.pipeline.as_ref().unwrap();
        let Ok(parent) = pipeline.producer_parent_receiver.try_recv() else {
            return Ok(());
        };
        let production = parent.production;
        ensure!(
            pipeline.producer_reservation.is_some_and(|reserved| {
                reserved.first == production.first
                    && reserved.next == production.next
                    && reserved.parent == production.parent
            }),
            "PQ private producer parent lacks exact reserved producer"
        );
        let runtime = self.runtime.lock().unwrap();
        let Some(original) = runtime.banks.get(&production.parent) else {
            return Ok(());
        };
        ensure!(
            Arc::ptr_eq(original, &parent.parent)
                && parent.bank.is_frozen()
                && parent.bank.slot() == production.next
                && parent.block.slot == production.next
                && parent.profile == pipeline::local_preparation_profile(&self.public)?
                && parent.executed.chain == self.chain
                && parent.executed.slot == production.next
                && parent.executed.parent == production.parent
                && parent.executed.parent_state == bank_state(original)
                && parent.executed.state == bank_state(&parent.bank),
            "PQ private producer parent context differs"
        );
        drop(runtime);
        let anchor = *self.machine.finalized_chain().last().unwrap();
        if self.obsolete_local_ancestry(production.next, production.parent, anchor) {
            return Ok(());
        }
        let pipeline = self.pipeline.as_mut().unwrap();
        ensure!(
            pipeline.private_producer_parent.is_none(),
            "PQ private producer parent bound"
        );
        pipeline.private_producer_parent = Some(parent);
        Ok(())
    }

    fn prepare_same_leader(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let pipeline = self.pipeline.as_ref().unwrap();
        if pipeline.unsigned_preparation.busy || pipeline.unsigned_ready.is_some() {
            return Ok(());
        }
        let Some(parent) = &pipeline.private_producer_parent else {
            return Ok(());
        };
        let current = parent.production;
        let next = current.next + 1;
        let anchor = *self.machine.finalized_chain().last().unwrap();
        if next >= current.first + self.public.window_size
            || pipeline.unsigned_attempted == Some(next)
            || self.proposed.contains_key(&next)
            || self.resume_intents.contains_key(&next)
            || !self.production.is_some_and(|active| {
                active.first == current.first
                    && active.next == current.next
                    && active.parent == current.parent
            })
            || self.obsolete_local_ancestry(next, parent.block.hash, anchor)
        {
            return Ok(());
        }
        let runtime = self.runtime.lock().unwrap();
        if runtime.banks.len()
            + usize::from(pipeline.producer.busy)
            + pipeline.candidate_bank_reservations(&runtime.banks)
            >= self.native_bank_capacity()
        {
            return Ok(());
        }
        drop(runtime);
        let production = Production {
            first: current.first,
            next,
            parent: parent.block.hash,
            due: self.now(),
        };
        let bank = parent.bank.clone();
        // Match ordinary post-output selection without retiring any wire early.
        let selected = parent
            .selected_ids
            .union(&parent.rejected_ids)
            .copied()
            .collect();
        self.dispatch_unsigned_preparation(production, bank, &selected)
    }

    fn poll_private_native_parent(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let Some(pipeline) = &self.pipeline else {
            return Ok(());
        };
        let Ok(parent) = pipeline.native_parent_receiver.try_recv() else {
            return Ok(());
        };
        ensure!(
            pipeline
                .executing
                .get(&parent.block.hash)
                .is_some_and(|index| index.0 == parent.block.slot),
            "PQ private native capability lacks exact execution reservation"
        );
        let runtime = self.runtime.lock().unwrap();
        let expected_parent_state = runtime.states.get(&parent.parent).copied().or_else(|| {
            pipeline
                .private_parents
                .get(&parent.parent)
                .map(|parent| parent.state)
        });
        let Some(expected_parent_state) = expected_parent_state else {
            return Ok(());
        };
        ensure!(
            parent.bank.is_frozen()
                && parent.bank.slot() == parent.block.slot
                && parent.executed.chain == self.chain
                && parent.executed.slot == parent.block.slot
                && parent.executed.parent == parent.parent
                && parent.executed.parent_state == expected_parent_state
                && parent.executed.state == parent.state
                && bank_state(&parent.bank) == parent.state,
            "PQ private native capability context differs"
        );
        drop(runtime);
        let anchor = *self.machine.finalized_chain().last().unwrap();
        if self.obsolete_local_ancestry(parent.block.slot, parent.parent, anchor) {
            return Ok(());
        }
        let pipeline = self.pipeline.as_mut().unwrap();
        ensure!(
            pipeline.private_parents.len() < pipeline::MAX_PENDING_NATIVE_CANDIDATES,
            "PQ private native capability bound"
        );
        info!(
            "PQ pipeline stage=native_parent_ready slot={} block_commitment={} \
             payload_candidate={} parent={} durable=0",
            parent.block.slot,
            encode_hex(&parent.block.hash),
            encode_hex(&parent.payload_candidate),
            encode_hex(&parent.parent)
        );
        pipeline.private_parents.insert(parent.block.hash, parent);
        Ok(())
    }

    fn poll_unsigned_preparation(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        if let Some(prepared) = self
            .pipeline
            .as_mut()
            .unwrap()
            .unsigned_preparation
            .poll()?
        {
            let reserved = self
                .pipeline
                .as_mut()
                .unwrap()
                .unsigned_reservation
                .take()
                .context("PQ unsigned result lacks reservation")?;
            ensure!(
                reserved.first == prepared.production.first
                    && reserved.next == prepared.production.next
                    && reserved.parent == prepared.production.parent,
                "PQ unsigned result context differs"
            );
            let anchor = *self.machine.finalized_chain().last().unwrap();
            if !self.obsolete_local_ancestry(reserved.next, reserved.parent, anchor)
                && (self
                    .runtime
                    .lock()
                    .unwrap()
                    .banks
                    .get(&reserved.parent)
                    .is_some_and(|bank| Arc::ptr_eq(bank, &prepared.parent))
                    || self
                        .pipeline
                        .as_ref()
                        .unwrap()
                        .private_parents
                        .get(&reserved.parent)
                        .is_some_and(|parent| {
                            parent.block.hash == reserved.parent
                                && Arc::ptr_eq(&parent.bank, &prepared.parent)
                        })
                    || self
                        .pipeline
                        .as_ref()
                        .unwrap()
                        .private_producer_parent
                        .as_ref()
                        .is_some_and(|parent| {
                            parent.block.hash == reserved.parent
                                && Arc::ptr_eq(&parent.bank, &prepared.parent)
                        }))
                && !self.proposed.contains_key(&reserved.next)
                && !self.resume_intents.contains_key(&reserved.next)
                && !self.production.is_some_and(|authorized| {
                    authorized.next == reserved.next && authorized.parent != reserved.parent
                })
            {
                ensure!(
                    self.pipeline.as_ref().unwrap().unsigned_ready.is_none(),
                    "PQ unsigned prepared Bank bound"
                );
                self.pipeline.as_mut().unwrap().unsigned_ready = Some(prepared);
            }
        }
        Ok(())
    }

    fn produce(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        self.retire_unowned_streams();
        let Some(pipeline) = self.pipeline.as_ref() else {
            return Ok(());
        };
        if pipeline.producer.busy
            || pipeline.publishing.len() >= pipeline::MAX_STREAMING_CANDIDATES
            || self.streaming.len() >= pipeline::MAX_STREAMING_CANDIDATES
            || self.pending_finalizations.len() >= 32
        {
            return Ok(());
        }
        let Some(production) = self.production else {
            return Ok(());
        };
        if pipeline.unsigned_ready.as_ref().is_some_and(|prepared| {
            prepared.production.next == production.next
                && (prepared.production.parent != production.parent
                    || self.resume_intents.contains_key(&production.next))
        }) {
            // Release an unauthorized prediction before capacity admission;
            // it must never hold the only free Bank slot ahead of a real parent.
            self.pipeline.as_mut().unwrap().unsigned_ready = None;
        }
        let pipeline = self.pipeline.as_ref().unwrap();
        let matching_unsigned = pipeline.unsigned_ready.as_ref().is_some_and(|prepared| {
            prepared.production.next == production.next
                && prepared.production.first == production.first
                && prepared.production.parent == production.parent
        });
        if pipeline.unsigned_preparation.busy
            && pipeline.unsigned_reservation.is_some_and(|reserved| {
                reserved.next == production.next && reserved.parent == production.parent
            })
            && !self.resume_intents.contains_key(&production.next)
        {
            return Ok(());
        }
        let at_capacity = {
            let runtime = self.runtime.lock().unwrap();
            runtime.banks.len()
                + pipeline.candidate_bank_reservations(&runtime.banks)
                + pipeline
                    .unsigned_bank_reservation()
                    .saturating_sub(usize::from(matching_unsigned))
                >= self.native_bank_capacity()
        };
        if at_capacity {
            return Ok(());
        }
        let anchor = *self.machine.finalized_chain().last().unwrap();
        if self.obsolete_local_ancestry(production.next, production.parent, anchor) {
            self.production = None;
            return Ok(());
        }
        if self.proposed.contains_key(&production.next) {
            // An obsolete or superseded local result is still a used slot.
            // Never dispatch a fresh payload after its signed intent escaped.
            self.production = None;
            return Ok(());
        }
        let (parent, slot_leader, executor) = {
            let runtime = self.runtime.lock().unwrap();
            (
                runtime.banks.get(&production.parent).cloned(),
                runtime.leaders[(production.next - self.public.first_slot) as usize],
                runtime.executor.clone(),
            )
        };
        let Some(parent) = parent else {
            self.request_repair(production.parent)?;
            return Ok(());
        };
        ensure!(
            parent.is_frozen(),
            "PQ asynchronous producer parent is not frozen"
        );
        if let Some(intent) = self.resume_intents.get(&production.next)
            && intent.parent != production.parent
        {
            // Bytes may already have escaped before the crash. A new parent
            // must never turn the immutable slot intent into a second signed
            // candidate. Another authorized window can continue normally.
            self.production = None;
            return Ok(());
        }
        let snapshot_started = Instant::now();
        let reuse_prepared = matching_unsigned
            && !self.resume_intents.contains_key(&production.next)
            && ((production.next == production.first
                && self
                    .machine
                    .ready_parents(production.first)
                    .contains(&production.parent)
                && (self.machine.payload(&production.parent).is_some()
                    || self.machine.finalized_chain().last().unwrap().hash == production.parent))
                || (production.next > production.first
                    && self
                        .proposed
                        .get(&(production.next - 1))
                        .is_some_and(|previous| {
                            previous.marker.block_commitment == production.parent
                        })));
        // Decide the exact existing reuse predicate before snapshotting. A
        // reused PreparedProposal never reads ProducerJob.entries. Preserve
        // coalescing with the same metadata-only FIFO test, without cloning
        // every eligible admission row into that unused vector.
        let reuse_readiness =
            reuse_prepared.then(|| self.prepared_reuse_readiness(production, &parent));
        let (mut entries, speculative_selected, deferred_blockhash_entries) =
            if let Some(observation) = &reuse_readiness {
                (
                    Vec::new(),
                    observation.speculative_selected,
                    observation.deferred_blockhash_entries_scanned,
                )
            } else {
                self.proposal_entries(production, &parent)
            };
        if let Some(intent) = self.resume_intents.get(&production.next) {
            entries = decode_block(&intent.payload, self.public.max_transactions)?
                .into_iter()
                .map(|transaction| {
                    let raw = bincode::serialize(&transaction)?;
                    let id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&raw]);
                    let intent = solana_runtime::pq::is_pq_transaction(&transaction)
                        .then(|| {
                            solana_runtime::pq::transaction_intent_identity(
                                &transaction,
                                &self.chain,
                            )
                        })
                        .transpose()?;
                    Ok((
                        id,
                        Arc::new(MempoolEntry {
                            raw,
                            transaction,
                            intent,
                        }),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
        }
        let target = self
            .public
            .proposal_target_block_bytes
            .unwrap_or(self.public.target_block_bytes);
        let maximum = self
            .public
            .proposal_max_transactions
            .unwrap_or(self.public.max_transactions);
        let eligible_bytes = entries
            .iter()
            .take(maximum)
            .map(|(_, entry)| entry.len() + 4)
            .sum::<usize>();
        let ready = reuse_readiness.as_ref().map_or_else(
            || {
                entries.len() >= maximum
                    || eligible_bytes >= target.saturating_sub(MAX_TRANSACTION_BYTES)
            },
            |observation| observation.full_ready,
        );
        // Full offered traffic streams without cadence sleeps. Empty/small
        // work coalesces so idle finite-epoch keys are not burned in a spin.
        if !ready
            && !self.resume_intents.contains_key(&production.next)
            && self.now() < production.due
        {
            return Ok(());
        }
        let eligible_entries = entries.len();
        let coalesce_remaining_ms = production.due.saturating_sub(self.now());
        let prepared = if reuse_prepared {
            self.pipeline.as_mut().unwrap().unsigned_ready.take()
        } else {
            // A different authorization discards only unsigned computation.
            // No admission row, used-slot fence or signer state has escaped.
            if self
                .pipeline
                .as_ref()
                .unwrap()
                .unsigned_ready
                .as_ref()
                .is_some_and(|prepared| prepared.production.next == production.next)
            {
                self.pipeline.as_mut().unwrap().unsigned_ready = None;
            }
            None
        };
        let job = ProducerJob {
            production,
            parent,
            rooted: self.bank_forks.read().unwrap().root_bank(),
            slot_leader,
            chain: self.chain,
            public: self.public.clone(),
            entries,
            executor,
            authentication_pool: self.authentication_pool.clone(),
            leader: self.leader.clone(),
            blockstore: self.blockstore.clone(),
            stream_sender: self.pipeline.as_ref().unwrap().stream_sender.clone(),
            producer_parent_sender: self
                .pipeline
                .as_ref()
                .unwrap()
                .producer_parent_sender
                .clone(),
            stop: self.pipeline.as_ref().unwrap().stop.clone(),
            fixed_payload: self
                .resume_intents
                .get(&production.next)
                .map(|intent| intent.payload.clone()),
            queued_at: Instant::now(),
            prepared,
            #[cfg(test)]
            intent_gate: self.pipeline.as_mut().unwrap().producer_intent_gate.take(),
        };
        let pipeline = self.pipeline.as_mut().unwrap();
        ensure!(
            pipeline.producer_reservation.is_none(),
            "PQ completed producer reservation missing result"
        );
        pipeline.producer.submit(job)?;
        pipeline.producer_reservation = Some(production);
        if let Some(observation) = reuse_readiness {
            info!(
                "PQ pipeline stage=producer_dispatch slot={} parent={} clock_ms={} snapshot_us={} \
                 snapshot_mode=prepared_reuse_probe eligible_entries_lower_bound={} \
                 eligible_bytes_lower_bound={} full_ready={} coalesce_remaining_ms={} \
                 speculative_selected={} mempool_entries={} readiness_fifo_rows_scanned={} \
                 deferred_blockhash_entries_in_scanned_prefix={}",
                production.next,
                encode_hex(&production.parent),
                self.now(),
                elapsed_us(snapshot_started),
                observation.eligible_entries_lower_bound,
                observation.eligible_bytes_lower_bound,
                usize::from(ready),
                coalesce_remaining_ms,
                speculative_selected,
                self.mempool.len(),
                observation.fifo_rows_scanned,
                observation.deferred_blockhash_entries_scanned
            );
        } else {
            info!(
                "PQ pipeline stage=producer_dispatch slot={} parent={} clock_ms={} snapshot_us={} \
                 eligible_entries={} eligible_bytes={} full_ready={} coalesce_remaining_ms={} \
                 speculative_selected={} mempool_entries={} deferred_blockhash_entries={}",
                production.next,
                encode_hex(&production.parent),
                self.now(),
                elapsed_us(snapshot_started),
                eligible_entries,
                eligible_bytes,
                usize::from(ready),
                coalesce_remaining_ms,
                speculative_selected,
                self.mempool.len(),
                deferred_blockhash_entries
            );
        }
        Ok(())
    }

    fn owns_stream(&self, slot: u64, candidate: &Commitment) -> bool {
        self.pipeline.as_ref().is_some_and(|pipeline| {
            pipeline
                .producer_reservation
                .is_some_and(|reserved| reserved.next == slot)
                || self.proposed.get(&slot).is_some_and(|witness| {
                    witness.marker.candidate == *candidate
                        && pipeline
                            .publishing
                            .contains(&witness.marker.block_commitment)
                })
        })
    }

    fn retire_unowned_streams(&mut self) {
        let retired = self
            .streaming
            .iter()
            .filter_map(|(candidate, stream)| {
                (!self.owns_stream(stream.slot, candidate)).then_some(*candidate)
            })
            .collect::<Vec<_>>();
        for candidate in retired {
            self.streaming.remove(&candidate);
        }
    }

    fn drain_stream_events(&mut self) -> Result<usize> {
        let mut drained = 0usize;
        for _ in 0..pipeline::MAX_STREAM_EVENTS {
            let event = self
                .pipeline
                .as_ref()
                .unwrap()
                .stream_receiver
                .as_ref()
                .unwrap()
                .try_recv();
            let Ok(event) = event else { break };
            drained += 1;
            // The producer and stream channels are independent. An obsolete
            // result can retire its stream before late DATA/terminal messages
            // are drained; those messages must not recreate an ownerless map.
            if !self.owns_stream(event.slot, &event.candidate) {
                continue;
            }
            if !self.streaming.contains_key(&event.candidate) {
                ensure!(
                    self.streaming.len() < pipeline::MAX_STREAMING_CANDIDATES,
                    InternalPqError("PQ active stream reservation capacity differs")
                );
            }
            let stream =
                self.streaming
                    .entry(event.candidate)
                    .or_insert_with(|| StreamingProposal {
                        slot: event.slot,
                        frames: Vec::new(),
                        cursors: self.outbound.keys().map(|peer| (*peer, 0)).collect(),
                    });
            ensure!(
                stream.slot == event.slot
                    && stream.frames.len() + event.frames.len() <= pipeline::MAX_STREAM_FRAMES,
                "PQ streaming shred bound"
            );
            stream.frames.extend(event.frames);
        }
        Ok(drained)
    }

    fn poll_pipeline(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        if self.pipeline.is_none() {
            return Ok(());
        }
        self.retire_unowned_streams();
        self.poll_private_native_parent()?;
        self.poll_private_producer_parent()?;
        self.prepare_same_leader()?;
        self.prepare_next_leader()?;
        self.poll_unsigned_preparation()?;
        self.drain_stream_events()?;
        #[cfg(test)]
        if let Some(gate) = self
            .pipeline
            .as_mut()
            .unwrap()
            .after_stream_drain_gate
            .take()
        {
            gate.entered.send(())?;
            gate.release
                .recv_timeout(Duration::from_secs(10))
                .context("test post-stream-drain producer race barrier")?;
        }
        match self.pipeline.as_mut().unwrap().reconstruction.poll() {
            Ok(Some(candidate)) => {
                self.pipeline.as_mut().unwrap().reconstructing = None;
                self.complete_verified(candidate)?;
            }
            Err(error) if error.downcast_ref::<NetworkError>().is_some() => {
                let index = self.pipeline.as_mut().unwrap().reconstructing.take();
                if let Some(index) = index {
                    self.completed_candidates.remove(&index);
                    self.candidate_timings.remove(&index);
                }
                self.invalid_packets += 1;
                warn!("PQ rejected asynchronous reconstruction: {error:#}");
            }
            Err(error) => return Err(error),
            Ok(None) => {}
        }
        if !self.pipeline.as_ref().unwrap().reconstruction.busy
            && let Some(index) = self
                .markers
                .keys()
                .find(|index| {
                    self.assemblers
                        .get(index)
                        .is_some_and(|assembler| assembler.is_reconstructable(&self.markers[index]))
                })
                .copied()
        {
            self.try_complete(index)?;
        }
        let candidate = self.pipeline.as_mut().unwrap().candidate.poll();
        match candidate {
            Ok(Some(output)) => {
                self.poll_private_native_parent()?;
                let hash = output.witness.marker.block_commitment;
                let pipeline = self.pipeline.as_mut().unwrap();
                pipeline.executing.remove(&hash);
                if pipeline.private_parents.contains_key(&hash) {
                    ensure!(
                        pipeline.pending_candidates.len() < pipeline::MAX_PENDING_NATIVE_CANDIDATES,
                        "PQ pending native result bound"
                    );
                    pipeline.pending_candidates.push_back(output);
                } else {
                    self.completed_candidates
                        .remove(&(output.witness.marker.slot, output.witness.marker.candidate));
                    self.candidate_timings
                        .remove(&(output.witness.marker.slot, output.witness.marker.candidate));
                }
            }
            Err(error) if error.downcast_ref::<RejectedCandidateExecution>().is_some() => {
                let rejected = error
                    .downcast_ref::<RejectedCandidateExecution>()
                    .unwrap()
                    .block;
                if let Some(index) = self.pipeline.as_mut().unwrap().executing.remove(&rejected) {
                    self.completed_candidates.remove(&index);
                    self.candidate_timings.remove(&index);
                }
                self.invalidate_private_parent(rejected)?;
                self.invalid_packets += 1;
                warn!("PQ rejected asynchronous native candidate: {error:#}");
            }
            Err(error) => return Err(error),
            Ok(None) => {}
        }
        self.dispatch_ready_candidates()?;
        self.prepare_next_leader()?;
        self.poll_candidate_bodies()?;
        let produced = match self.pipeline.as_mut().unwrap().producer.poll() {
            Ok(output) => output,
            Err(error) => {
                if let Some(hash) = self
                    .pipeline
                    .as_ref()
                    .unwrap()
                    .private_producer_parent
                    .as_ref()
                    .map(|parent| parent.block.hash)
                {
                    self.invalidate_private_parent(hash)?;
                }
                return Err(error);
            }
        };
        if let Some(output) = produced {
            // A fast producer may have emitted its private capability after
            // this turn's first drain. Bind it before releasing the reservation.
            self.poll_private_producer_parent()?;
            let production = output.production;
            let reserved = self
                .pipeline
                .as_mut()
                .unwrap()
                .producer_reservation
                .take()
                .context("PQ producer result missing slot reservation")?;
            ensure!(
                reserved.first == production.first
                    && reserved.next == production.next
                    && reserved.parent == production.parent,
                "PQ producer result differs from reserved slot and parent"
            );
            let marker = output.witness.marker.clone();
            if let Some(private) = self
                .pipeline
                .as_mut()
                .unwrap()
                .private_producer_parent
                .take()
            {
                ensure!(
                    private.block.hash == marker.block_commitment
                        && private.block.slot == marker.slot
                        && private.candidate == marker.candidate
                        && private.production.parent == marker.parent
                        && Arc::ptr_eq(&private.bank, &output.bank)
                        && private.executed.state == output.executed.state
                        && private.executed.payload == output.executed.payload
                        && private.selected_ids == output.selected_ids
                        && private.rejected_ids == output.rejected.iter().copied().collect(),
                    "PQ signed producer output differs from private construction capability"
                );
            }
            // The durable local slot intent survives even if certification
            // selected another branch while execution was in flight.
            self.proposed
                .insert(production.next, output.witness.clone());
            let anchor = self.adopted_anchor()?;
            let certified = *self.machine.finalized_chain().last().unwrap();
            if !self.obsolete_local_ancestry(
                output.witness.marker.slot,
                output.witness.marker.parent,
                certified,
            ) {
                // A discarded branch has no authority to retire admitted
                // transactions. Keep the durable used-slot fence above even
                // when none of this result's execution outcomes are applied.
                for id in output.rejected {
                    remove_admitted_wire(
                        &mut self.mempool,
                        &mut self.mempool_order,
                        &mut self.gossip_log,
                        &id,
                    );
                }
                {
                    let mut runtime = self.runtime.lock().unwrap();
                    ensure!(
                        runtime.banks.contains_key(&marker.block_commitment)
                            || runtime.banks.len()
                                + self
                                    .pipeline
                                    .as_ref()
                                    .unwrap()
                                    .candidate_bank_reservations(&runtime.banks)
                                + self.pipeline.as_ref().unwrap().unsigned_bank_reservation()
                                < self.native_bank_capacity(),
                        "PQ reserved local Bank installation capacity differs"
                    );
                    runtime
                        .states
                        .insert(marker.block_commitment, output.executed.state);
                    runtime
                        .executions
                        .insert(marker.block_commitment, output.executed);
                    runtime.banks.insert(marker.block_commitment, output.bank);
                    runtime
                        .archives
                        .insert(marker.block_commitment, output.archive);
                }
                self.speculative_ids
                    .insert(production.next, output.selected_ids);
                self.completed_candidates
                    .insert((production.next, marker.candidate));
                let pipeline = self.pipeline.as_mut().unwrap();
                pipeline.publishing.insert(marker.block_commitment);
                pipeline.pending_publications.push_back(PublicationJob {
                    witness: output.witness,
                    verified: output.verified,
                    blockstore: self.blockstore.clone(),
                });
                if self.production.is_some_and(|active| {
                    active.first == production.first
                        && active.next == production.next
                        && active.parent == production.parent
                }) {
                    self.production = (production.next + 1
                        < production.first + self.public.window_size)
                        .then_some(Production {
                            next: production.next + 1,
                            parent: marker.block_commitment,
                            due: self.now() + self.public.block_time_ms,
                            ..production
                        });
                }
            } else {
                self.invalidate_private_parent(marker.block_commitment)?;
                self.streaming.remove(&marker.candidate);
                if self
                    .production
                    .is_some_and(|active| active.next == production.next)
                {
                    self.production = None;
                }
            }
            info!(
                "PQ pipeline stage=producer_complete slot={} clock_ms={} native_root={}",
                production.next,
                self.now(),
                anchor.slot
            );
        }
        if let Some(output) = self.pipeline.as_mut().unwrap().publisher.poll()? {
            let hash = output.witness.marker.block_commitment;
            let slot = output.witness.marker.slot;
            self.pipeline.as_mut().unwrap().publishing.remove(&hash);
            self.resume_intents.remove(&slot);
            let anchor = *self.machine.finalized_chain().last().unwrap();
            if !self.obsolete_local_ancestry(
                output.witness.marker.slot,
                output.witness.marker.parent,
                anchor,
            ) {
                self.observe_cached(
                    output.witness.clone(),
                    output.verified,
                    Instant::now(),
                    output.block_wal_us,
                    true,
                    0,
                )?;
                self.send_witness(None, &output.witness)?;
                if let Some(stream) = self.streaming.remove(&output.witness.marker.candidate) {
                    ensure!(
                        stream.slot == slot
                            && stream.frames.len() == output.witness.shreds.len() + 1,
                        "PQ streamed witness extent differs"
                    );
                    for (peer, cursor) in stream.cursors {
                        if let Some(queue) = self.outbound.get_mut(&peer)
                            && let Some((_, index)) =
                                queue.blocks.iter_mut().find(|(id, _)| *id == hash)
                        {
                            *index = (*index).max(cursor.min(output.witness.shreds.len()));
                            if cursor > output.witness.shreds.len() {
                                queue.blocks.retain(|(id, _)| *id != hash);
                                queue.queued_blocks.remove(&hash);
                                queue.repair_blocks.remove(&hash);
                            }
                        }
                    }
                }
            } else {
                self.streaming.remove(&output.witness.marker.candidate);
            }
            info!(
                "PQ pipeline stage=proposal_published slot={} clock_ms={} witness_wal_us={}",
                slot,
                self.now(),
                output.block_wal_us
            );
        }
        if !self.pipeline.as_ref().unwrap().publisher.busy
            && let Some(job) = self
                .pipeline
                .as_mut()
                .unwrap()
                .pending_publications
                .pop_front()
        {
            self.pipeline.as_mut().unwrap().publisher.submit(job)?;
        }
        if let Some(output) = self.pipeline.as_mut().unwrap().archive.poll()? {
            let publish_started = Instant::now();
            self.finalized_transactions += output.records.len() as u64;
            self.runtime
                .lock()
                .unwrap()
                .banks
                .insert(output.block.hash, output.bank.clone());
            self.block_commitment_cache
                .write()
                .unwrap()
                .set_all_slots(output.bank.slot(), output.bank.slot());
            self.optimistically_confirmed_bank.write().unwrap().bank = output.bank;
            let root_publish_us = elapsed_us(publish_started);
            let prune_started = Instant::now();
            prune_committed_admission(
                &mut self.mempool,
                &mut self.mempool_order,
                &mut self.gossip_log,
                &output.records,
                &self.chain,
            )?;
            self.speculative_ids
                .retain(|slot, _| *slot > output.block.slot);
            info!(
                "PQ phases stage=finalize slot={} transactions={} decode_us=0 live_child_us=0 \
                 native_execute_us=0 bridge_us=0 freeze_us=0 archive_wal_us={} root_publish_us={} \
                 mempool_prune_us={} promotion_us={} duplicate_execution_count=0 total_us={}",
                output.block.slot,
                output.records.len(),
                output.archive_wal_us,
                root_publish_us,
                elapsed_us(prune_started),
                output.promotion_us,
                elapsed_us(output.started)
            );
        }
        self.dispatch_finalization()?;
        self.dispatch_ready_candidates()?;
        self.prepare_next_leader()?;
        Ok(())
    }

    fn poll_candidate_bodies(&mut self) -> Result<()> {
        if let Some(durable) = self.pipeline.as_mut().unwrap().candidate_body.poll()?
            && let Some(output) = self
                .pipeline
                .as_mut()
                .unwrap()
                .pending_candidates
                .iter_mut()
                .find(|output| output.witness.marker.block_commitment == durable.block.hash)
        {
            ensure!(
                output.witness.marker.slot == durable.block.slot && !output.body_durable,
                "PQ native body durability context differs"
            );
            output.body_durable = true;
            output.block_wal_us = durable.block_wal_us;
        }
        // The independent writer stays ordered but never occupies the native
        // execution worker. Start the next write before coordinator journal IO.
        let pipeline = self.pipeline.as_mut().unwrap();
        if !pipeline.candidate_body.busy
            && let Some(output) = pipeline
                .pending_candidates
                .iter_mut()
                .find(|output| output.encoded_witness.is_some())
        {
            let job = CandidateBodyJob {
                block: BlockRef {
                    slot: output.witness.marker.slot,
                    hash: output.witness.marker.block_commitment,
                },
                payload_candidate: output.witness.marker.candidate,
                bytes: output.encoded_witness.take().unwrap(),
                blockstore: self.blockstore.clone(),
                stop: pipeline.stop.clone(),
                #[cfg(test)]
                gate: pipeline.candidate_body_gate.take(),
            };
            pipeline.candidate_body.submit(job)?;
        }
        while let Some(output) = self.pipeline.as_ref().unwrap().pending_candidates.front() {
            let certified = *self.machine.finalized_chain().last().unwrap();
            if obsolete_witness(
                &output.witness,
                certified,
                &self.block_slots,
                &self.blocks,
                &self.waiting_parents,
            ) {
                let hash = output.witness.marker.block_commitment;
                self.invalidate_private_parent(hash)?;
                continue;
            }
            if !output.body_durable {
                break;
            }
            let parent_hash = output.witness.marker.parent;
            let adopted = self.adopted_anchor()?;
            let runtime = self.runtime.lock().unwrap();
            let parent_accepted = runtime.banks.get(&parent_hash).is_some_and(|parent| {
                Arc::ptr_eq(parent, &output.parent)
                    && (self.machine.payload(&parent_hash).is_some() || adopted.hash == parent_hash)
            });
            let parent_pending = self
                .pipeline
                .as_ref()
                .unwrap()
                .private_parents
                .contains_key(&parent_hash)
                || (runtime.banks.contains_key(&parent_hash)
                    && self.machine.payload(&parent_hash).is_none());
            drop(runtime);
            if !parent_accepted && parent_pending {
                break;
            }
            let output = self
                .pipeline
                .as_mut()
                .unwrap()
                .pending_candidates
                .pop_front()
                .unwrap();
            let hash = output.witness.marker.block_commitment;
            if !parent_accepted {
                self.invalidate_private_parent(hash)?;
                self.completed_candidates
                    .remove(&(output.witness.marker.slot, output.witness.marker.candidate));
                continue;
            }
            self.accept_durable_candidate(output)?;
        }
        Ok(())
    }

    fn accept_durable_candidate(&mut self, output: CandidateOutput) -> Result<()> {
        ensure!(
            output.body_durable,
            "PQ authoritative candidate body is not durable"
        );
        let hash = output.witness.marker.block_commitment;
        let anchor = self.adopted_anchor()?;
        if obsolete_witness(
            &output.witness,
            anchor,
            &self.block_slots,
            &self.blocks,
            &self.waiting_parents,
        ) {
            self.invalidate_private_parent(hash)?;
            return Ok(());
        }
        // Release a pending slot before scheduling more computation. The exact
        // private parent remains reserved until its authoritative observation.
        self.dispatch_ready_candidates()?;
        self.prepare_next_leader()?;
        let install_started = Instant::now();
        {
            let mut runtime = self.runtime.lock().unwrap();
            runtime.banks.insert(hash, output.bank);
            runtime.states.insert(hash, output.state);
            runtime.executions.insert(hash, output.executed);
            runtime.archives.insert(hash, output.archive);
        }
        self.observe_cached(
            output.witness,
            output.candidate,
            output.started,
            output.block_wal_us,
            false,
            elapsed_us(install_started),
        )?;
        if self.machine.payload(&hash).is_some() {
            self.pipeline
                .as_mut()
                .unwrap()
                .private_parents
                .remove(&hash);
        } else {
            self.invalidate_private_parent(hash)?;
        }
        Ok(())
    }

    fn observe_cached(
        &mut self,
        witness: BlockWitness,
        candidate: VerifiedCandidate,
        started: Instant,
        block_wal_us: u64,
        local: bool,
        native_install_us: u64,
    ) -> Result<()> {
        #[cfg(test)]
        if let Some(gate) = self
            .pipeline
            .as_mut()
            .and_then(|pipeline| pipeline.candidate_observe_gate.take())
        {
            gate.entered.send(())?;
            gate.release
                .recv_timeout(Duration::from_secs(10))
                .context("test candidate consensus observation barrier")?;
            ensure!(!gate.fail, "test candidate observation failure");
        }
        let receive_started = Instant::now();
        let hash = witness.marker.block_commitment;
        let slot = witness.marker.slot;
        let index = (slot, witness.marker.candidate);
        let shred_count = witness.shreds.len();
        // Native execution and the complete body are already durable. The
        // Quantumglow callback only checks the cached, full-width capability.
        let observe_started = Instant::now();
        let observed = self.machine.observe_verified(candidate, self.now());
        let consensus_observe_us = elapsed_us(observe_started);
        let actions = match observed {
            Ok(actions) => actions,
            Err(error)
                if !local
                    && matches!(
                        error,
                        QuantumglowError::Bounds
                            | QuantumglowError::BlockAuthentication
                            | QuantumglowError::InvalidAncestry
                    ) =>
            {
                return self.reject_peer_candidate(
                    hash,
                    index,
                    &format!("consensus admission: {error}"),
                );
            }
            Err(error) => return Err(error.into()),
        };
        let install_started = Instant::now();
        self.block_slots.insert(hash, slot);
        self.completed_candidates.insert(index);
        self.blocks.insert(hash, witness);
        self.deferred_refetches.remove(&hash);
        if !self
            .outbound
            .values()
            .any(|queue| queue.repair_blocks.contains(&hash))
        {
            self.outbound_witnesses.remove(&hash);
        }
        let coordinator_install_us = native_install_us.saturating_add(elapsed_us(install_started));
        let journal_started = Instant::now();
        self.persist(&actions)?;
        self.pending.extend(actions);
        let timings = self.candidate_timings.remove(&index).unwrap_or_default();
        info!(
            "PQ phases stage=receive slot={} shreds={} authentication_us={} reconstruction_us={} \
             observe_us={} block_wal_us={} journal_wal_us={} observe_persist_us={} \
             consensus_observe_us={} coordinator_install_us={} coordinator_receive_us={}",
            slot,
            shred_count,
            timings.authentication_us,
            timings.reconstruction_us,
            elapsed_us(started),
            block_wal_us,
            elapsed_us(journal_started),
            elapsed_us(started),
            consensus_observe_us,
            coordinator_install_us,
            elapsed_us(receive_started)
        );
        Ok(())
    }

    fn finalize(&mut self, block: BlockRef) -> Result<()> {
        if self.pipeline.is_none() {
            return self.finalize_sync(block);
        }
        if block.slot <= self.bank_forks.read().unwrap().root() {
            return Ok(());
        }
        ensure!(
            self.pending_finalizations.len() < 128,
            "PQ ordered finalization queue capacity"
        );
        if self.pending_finalizations.back() != Some(&block) {
            self.pending_finalizations.push_back(block);
        }
        self.dispatch_finalization()
    }

    fn dispatch_finalization(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let Some(pipeline) = self.pipeline.as_ref() else {
            return Ok(());
        };
        if pipeline.archive.busy {
            return Ok(());
        }
        let Some(block) = self.pending_finalizations.pop_front() else {
            return Ok(());
        };
        let parent = self.bank_forks.read().unwrap().root_bank();
        if block.slot <= parent.slot() {
            return self.dispatch_finalization();
        }
        let parent_commitment = self
            .blocks
            .get(&block.hash)
            .context("PQ finalized block witness missing")?
            .marker
            .parent;
        let payload = self
            .machine
            .payload(&block.hash)
            .context("PQ finalized payload missing")?
            .to_vec();
        let job = {
            let runtime = self.runtime.lock().unwrap();
            FinalizationJob {
                block,
                candidate: runtime
                    .banks
                    .get(&block.hash)
                    .context("PQ finalized real Bank missing")?
                    .clone(),
                parent,
                parent_commitment,
                parent_state: runtime.states[&parent_commitment],
                chain: self.chain,
                payload,
                executed: runtime
                    .executions
                    .get(&block.hash)
                    .context("PQ finalized execution capability missing")?
                    .clone(),
                records: runtime
                    .archives
                    .get(&block.hash)
                    .context("PQ finalized native archive missing")?
                    .clone(),
                bank_forks: self.bank_forks.clone(),
                blockstore: self.blockstore.clone(),
                #[cfg(test)]
                archive_gate: self.pipeline.as_ref().unwrap().archive_gate.clone(),
            }
        };
        self.pipeline.as_mut().unwrap().archive.submit(job)?;
        info!(
            "PQ pipeline stage=finalize_dispatch slot={} clock_ms={}",
            block.slot,
            self.now()
        );
        Ok(())
    }

    fn finalize_sync(&mut self, block: BlockRef) -> Result<()> {
        let started = Instant::now();
        let certified_bank = self
            .runtime
            .lock()
            .unwrap()
            .banks
            .get(&block.hash)
            .cloned()
            .ok_or_else(|| anyhow!("PQ finalized real Bank missing"))?;
        let parent = self.bank_forks.read().unwrap().root_bank();
        if certified_bank.slot() <= parent.slot() {
            return Ok(());
        }
        let witness = self
            .blocks
            .get(&block.hash)
            .ok_or_else(|| anyhow!("PQ finalized block witness missing"))?;
        let parent_commitment = witness.marker.parent;
        ensure!(
            parent.pq_state_commitment() == self.runtime.lock().unwrap().states[&parent_commitment],
            "PQ native root differs from certified replay parent"
        );
        let previous_blockhash = parent.last_blockhash();
        let payload = self
            .machine
            .payload(&block.hash)
            .ok_or_else(|| anyhow!("PQ finalized payload missing"))?;
        let expected_parent_state = parent.pq_state_commitment();
        let records = {
            let runtime = self.runtime.lock().unwrap();
            let execution = runtime
                .executions
                .get(&block.hash)
                .ok_or_else(|| anyhow!("PQ finalized execution capability missing"))?;
            ensure!(
                execution.matches(
                    &self.chain,
                    &ExecutionCandidate {
                        reference: block,
                        parent: parent_commitment,
                        payload
                    },
                    &expected_parent_state,
                    &certified_bank.pq_state_commitment(),
                ),
                "PQ finalized payload, parent, Bank or execution state differs from certificate"
            );
            runtime
                .archives
                .get(&block.hash)
                .ok_or_else(|| anyhow!("PQ finalized native archive missing"))?
                .clone()
        };
        let transaction_count = records.len();
        ensure!(
            certified_bank
                .transaction_count()
                .checked_sub(parent.transaction_count())
                == Some(transaction_count as u64),
            "PQ finalized native transaction count differs"
        );
        let (bank, promotion_us, archive_wal_us) = promote_and_archive(
            &self.bank_forks,
            &self.blockstore,
            block,
            certified_bank,
            expected_parent_state,
            previous_blockhash,
            &records,
        )?;
        // No receipts or progress counters precede adopted state and its
        // synced native history. Durable QG witnesses remain on any failure.
        let publish_started = Instant::now();
        self.finalized_transactions += transaction_count as u64;
        self.runtime
            .lock()
            .unwrap()
            .banks
            .insert(block.hash, bank.clone());
        self.block_commitment_cache
            .write()
            .unwrap()
            .set_all_slots(bank.slot(), bank.slot());
        self.optimistically_confirmed_bank.write().unwrap().bank = bank.clone();
        let root_publish_us = elapsed_us(publish_started);
        let prune_started = Instant::now();
        prune_committed_admission(
            &mut self.mempool,
            &mut self.mempool_order,
            &mut self.gossip_log,
            &records,
            &self.chain,
        )?;
        self.update_status();
        info!(
            "PQ phases stage=finalize slot={} transactions={} decode_us={} live_child_us={} \
             native_execute_us={} bridge_us={} freeze_us={} archive_wal_us={} root_publish_us={} \
             mempool_prune_us={} promotion_us={} duplicate_execution_count=0 total_us={}",
            block.slot,
            transaction_count,
            0,
            0,
            0,
            0,
            0,
            archive_wal_us,
            root_publish_us,
            elapsed_us(prune_started),
            promotion_us,
            elapsed_us(started)
        );
        Ok(())
    }

    fn compact(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        if self
            .pipeline
            .as_ref()
            .is_some_and(|pipeline| pipeline.archive.busy)
        {
            // Native state may have been promoted while its RPC archive WAL is
            // still being written. Neither a successful promotion nor a queued
            // worker result proves durable receipt publication. Failure must
            // remain fail-stop with the complete certified repair history.
            return Ok(());
        }
        let actual = *self.machine.finalized_chain().last().unwrap();
        let root = self.bank_forks.read().unwrap().root_bank();
        if root.slot() < actual.slot && self.pipeline.is_some() {
            // Certified roots are promoted and archived in order by the worker.
            // Retain their execution capabilities and repair bodies until the
            // native root has caught up; consensus compaction cannot lead it.
            return Ok(());
        }
        ensure!(
            root.slot() == actual.slot,
            "PQ compaction requires actual rooted replay"
        );
        let obsolete_private = self
            .pipeline
            .as_ref()
            .map(|pipeline| {
                pipeline
                    .private_parents
                    .values()
                    .filter(|parent| {
                        parent.block.slot <= actual.slot && parent.block.hash != actual.hash
                            || self.obsolete_local_ancestry(
                                parent.block.slot,
                                parent.parent,
                                actual,
                            )
                    })
                    .map(|parent| parent.block.hash)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for hash in obsolete_private {
            self.invalidate_private_parent(hash)?;
        }
        if let Some(hash) = self
            .pipeline
            .as_ref()
            .and_then(|pipeline| pipeline.private_producer_parent.as_ref())
            .filter(|parent| {
                parent.block.slot <= actual.slot && parent.block.hash != actual.hash
                    || self.obsolete_local_ancestry(
                        parent.block.slot,
                        parent.production.parent,
                        actual,
                    )
            })
            .map(|parent| parent.block.hash)
        {
            self.invalidate_private_parent(hash)?;
        }
        if self.pipeline.as_ref().is_some_and(|pipeline| {
            pipeline.unsigned_ready.as_ref().is_some_and(|prepared| {
                self.obsolete_local_ancestry(
                    prepared.production.next,
                    prepared.production.parent,
                    actual,
                )
            })
        }) {
            self.pipeline.as_mut().unwrap().unsigned_ready = None;
        }
        let anchor = self.machine.compact_finalized(actual, bank_state(&root))?;
        let deferred_before = self
            .waiting_parents
            .iter()
            .map(|(hash, witness)| (*hash, (witness.marker.slot, witness.marker.candidate)))
            .collect::<Vec<_>>();
        prune_deferred_witnesses(
            actual,
            &self.block_slots,
            &self.blocks,
            &mut self.waiting_parents,
            &mut self.waiting_parent_bytes,
        )?;
        for (hash, index) in deferred_before {
            if !self.waiting_parents.contains_key(&hash) {
                self.completed_candidates.remove(&index);
                self.candidate_timings.remove(&index);
            }
        }
        let mut obsolete = Vec::new();
        for (&hash, reference) in &self.deferred_refetches {
            let mut slot = reference.slot;
            let mut parent = reference.parent;
            let stale = loop {
                if slot <= actual.slot {
                    break true;
                }
                if parent == actual.hash {
                    break false;
                }
                let previous = self
                    .waiting_parents
                    .get(&parent)
                    .map(|witness| (witness.marker.slot, witness.marker.parent))
                    .or_else(|| {
                        self.deferred_refetches
                            .get(&parent)
                            .map(|reference| (reference.slot, reference.parent))
                    });
                let parent_slot = previous
                    .map(|(slot, _)| slot)
                    .or_else(|| self.block_slots.get(&parent).copied());
                let Some(parent_slot) = parent_slot else {
                    break false;
                };
                if parent_slot <= actual.slot || parent_slot >= slot {
                    break true;
                }
                let Some((_, next)) = previous else {
                    break false;
                };
                slot = parent_slot;
                parent = next;
            };
            if stale || self.runtime.lock().unwrap().banks.contains_key(&hash) {
                obsolete.push(hash);
            }
        }
        for hash in obsolete {
            let reference = self.deferred_refetches.remove(&hash).unwrap();
            self.candidate_timings
                .remove(&(reference.slot, reference.candidate));
            if !self.runtime.lock().unwrap().banks.contains_key(&hash) {
                self.completed_candidates
                    .remove(&(reference.slot, reference.candidate));
            }
        }
        self.assemblers.retain(|(slot, _), _| *slot > actual.slot);
        self.markers.retain(|(slot, _), _| *slot > actual.slot);
        if self.production.is_some_and(|production| {
            self.obsolete_local_ancestry(production.next, production.parent, actual)
        }) {
            self.production = None;
        }
        let needed = self.needed_parent_repairs(actual);
        self.parent_repairs.retain(|hash, retry| {
            if let Some(priority) = needed.get(hash) {
                retry.priority = retry.priority.min(*priority);
                true
            } else {
                false
            }
        });
        for queue in self.outbound.values_mut() {
            queue
                .repairs
                .retain(|hash| self.parent_repairs.contains_key(hash));
            queue.queued_repairs = queue.repairs.iter().copied().collect();
        }
        {
            let mut runtime = self.runtime.lock().unwrap();
            runtime
                .banks
                .retain(|hash, bank| *hash == actual.hash || bank.slot() > actual.slot);
            let hashes = runtime.banks.keys().copied().collect::<BTreeSet<_>>();
            runtime.archives.retain(|hash, _| hashes.contains(hash));
            runtime.executions.retain(|hash, _| hashes.contains(hash));
        }
        let slots = self
            .blocks
            .iter()
            .map(|(hash, witness)| (*hash, witness.marker.slot))
            .collect::<BTreeMap<_, _>>();
        for queue in self.outbound.values_mut() {
            queue.blocks.retain(|(hash, _)| {
                queue.repair_blocks.contains(hash)
                    || slots.get(hash).is_none_or(|slot| *slot > anchor.slot)
            });
            queue.queued_blocks = queue.blocks.iter().map(|(hash, _)| *hash).collect();
            queue
                .repair_blocks
                .retain(|hash| queue.queued_blocks.contains(hash));
        }
        let retained_local = self.local_proposal_ancestors_for_compaction(actual)?;
        self.blocks
            .retain(|_, witness| witness.marker.slot > anchor.slot);
        self.proposed.retain(|slot, witness| {
            *slot > anchor.slot || retained_local.contains(&witness.marker.block_commitment)
        });
        self.candidate_timings
            .retain(|(slot, _), _| *slot > anchor.slot);
        compact_evidence_packets(anchor.slot, &mut self.evidence_packets, &mut self.outbound);
        self.outbound_witnesses.retain(|hash, _| {
            self.outbound
                .values()
                .any(|queue| queue.queued_blocks.contains(hash))
        });
        self.repair_progress
            .retain(|hash, _| self.outbound_witnesses.contains_key(hash));
        let now = self.now();
        self.repair_responses.retain(|(peer, hash), response| {
            response.requested
                || self.outbound[peer].queued_blocks.contains(hash)
                || !response.retry.ready(now)
        });
        self.schedule_missing_repair_fronts()?;
        Ok(())
    }

    fn broadcast(&mut self, frame: &[u8]) {
        match frame.first() {
            Some(3) => {
                if let Err(error) = self.queue_evidence(None, frame.to_vec()) {
                    error!("failed to retain PQ consensus evidence: {error:#}");
                    self.exit.store(true, Ordering::Release);
                }
            }
            Some(5) if frame.len() == 49 => {
                let hash: Commitment = frame[1..].try_into().unwrap();
                for queue in self.outbound.values_mut() {
                    if queue.queued_repairs.insert(hash) {
                        queue.repairs.push_back(hash);
                    }
                }
            }
            _ => {
                self.send_rejected += 1;
            }
        }
    }

    fn queue_evidence(&mut self, peer: Option<Pubkey>, frame: Vec<u8>) -> Result<()> {
        let evidence = SignedEvidence::decode(&frame[1..])?;
        let id = hash_commitment(b"agave-pq-evidence-wire-v1", &[&frame[1..]]);
        if !self.evidence_packets.contains_key(&id) {
            let bytes = self
                .evidence_packets
                .values()
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>();
            ensure!(
                bytes + frame.len() <= 64 * 1024 * 1024,
                "PQ retained evidence budget"
            );
            self.evidence_packets
                .insert(id, (evidence.message.slot, frame));
        }
        for (&id_peer, queue) in &mut self.outbound {
            if peer.is_none_or(|peer| peer == id_peer) {
                if peer.is_some() && !queue.repair_evidence.contains(&id) {
                    ensure!(
                        queue.repair_evidence.len() < 512,
                        "PQ retained repair evidence budget"
                    );
                    queue.repair_evidence.insert(id);
                }
                if queue.queued_evidence.insert(id) {
                    queue.evidence.push_back(id);
                }
            }
        }
        Ok(())
    }

    fn send_witness(&mut self, peer: Option<Pubkey>, witness: &BlockWitness) -> Result<()> {
        let hash = witness.marker.block_commitment;
        // Explicit repair must survive live-history compaction even when the
        // same witness is presently in the ordinary block map. Old repair
        // bodies are independently bounded; the durable archive keeps history.
        if peer.is_some() && !self.outbound_witnesses.contains_key(&hash) {
            let retained = self
                .outbound_witnesses
                .values()
                .map(repair_witness_bytes)
                .sum::<usize>();
            let incoming = repair_witness_bytes(witness);
            ensure!(
                self.outbound_witnesses.len() < MAX_BUFFERED_CANDIDATES
                    && retained + incoming <= MAX_REPAIR_BYTES,
                "PQ retained repair budget"
            );
            self.outbound_witnesses.insert(hash, witness.clone());
        }
        for (&id, queue) in &mut self.outbound {
            if peer.is_some_and(|peer| peer == id) {
                queue.repair_blocks.insert(hash);
            }
            if peer.is_none_or(|peer| peer == id) && queue.queued_blocks.insert(hash) {
                ensure!(
                    queue.blocks.len() < self.public.slot_count as usize * 5,
                    "PQ deferred block budget"
                );
                if peer.is_none() {
                    // Current proposals must progress ahead of deferred old
                    // repair bodies; partial repair cursors remain intact.
                    queue.blocks.push_front((hash, 0));
                } else {
                    let position = queue
                        .blocks
                        .iter()
                        .position(|(queued, _)| {
                            queue.repair_blocks.contains(queued)
                                && self
                                    .blocks
                                    .get(queued)
                                    .or_else(|| self.outbound_witnesses.get(queued))
                                    .map(|body| body.marker.slot)
                                    .or_else(|| self.block_slots.get(queued).copied())
                                    .unwrap_or(u64::MAX)
                                    > witness.marker.slot
                        })
                        .unwrap_or(queue.blocks.len());
                    queue.blocks.insert(position, (hash, 0));
                }
            }
        }
        Ok(())
    }

    fn flush_outbound(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        let now = self.now();
        for (&peer, queue) in &mut self.outbound {
            let previous = queue.blocks.iter().copied().collect::<BTreeMap<_, _>>();
            if !queue.flush(
                &self.evidence_packets,
                &self.blocks,
                &self.outbound_witnesses,
                &self.gossip_log,
                &self.mempool,
                |frame| {
                    let transport = self.transport.as_ref().unwrap();
                    if matches!(frame.first(), Some(2 | 3 | 5)) {
                        transport.send_control(peer, frame).is_ok()
                    } else {
                        transport.send(peer, frame).is_ok()
                    }
                },
            )? {
                self.send_rejected += 1;
            }
            for (hash, index) in previous {
                if queue
                    .blocks
                    .iter()
                    .find(|(id, _)| *id == hash)
                    .is_none_or(|(_, next)| *next > index)
                {
                    self.repair_progress.insert(hash, now);
                }
            }
        }
        Ok(())
    }

    fn flush_streaming(&mut self) -> Result<()> {
        ensure!(
            self.pipeline
                .as_ref()
                .is_none_or(|pipeline| !pipeline.journal_failed),
            InternalPqError("PQ streaming after journal failure")
        );
        let Some(transport) = self.transport.as_ref() else {
            return Ok(());
        };
        // Work has a strict per-turn bound. Bulk cannot keep the coordinator
        // away from certificates, timers and worker completions indefinitely.
        // Both transport streams share one bounded byte/record budget.
        for stream in self.streaming.values_mut() {
            for (&peer, cursor) in &mut stream.cursors {
                for _ in 0..256 {
                    let Some(frame) = stream.frames.get(*cursor) else {
                        break;
                    };
                    let result = if frame.first() == Some(&2) {
                        transport.send_control(peer, frame)
                    } else {
                        transport.send(peer, frame)
                    };
                    if result.is_err() {
                        self.send_rejected += 1;
                        break;
                    }
                    *cursor += 1;
                }
            }
        }
        Ok(())
    }

    /// Retry only already reconstructed causal children as soon as their
    /// executed parent is installed. Network repair remains separately paced.
    fn dispatch_ready_candidates(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        loop {
            if self.pipeline.as_ref().is_some_and(|pipeline| {
                pipeline.candidate.busy
                    || pipeline.pending_candidates.len() >= pipeline::MAX_PENDING_NATIVE_CANDIDATES
            }) {
                break;
            }
            let ready = self.waiting_parents.iter().find_map(|(hash, witness)| {
                self.runtime
                    .lock()
                    .unwrap()
                    .banks
                    .contains_key(&witness.marker.parent)
                    .then_some(*hash)
                    .or_else(|| {
                        self.pipeline
                            .as_ref()
                            .is_some_and(|pipeline| {
                                pipeline
                                    .private_parents
                                    .contains_key(&witness.marker.parent)
                            })
                            .then_some(*hash)
                    })
            });
            let Some(hash) = ready else { break };
            let witness = self.waiting_parents.remove(&hash).unwrap();
            let index = (witness.marker.slot, witness.marker.candidate);
            self.waiting_parent_bytes = self
                .waiting_parent_bytes
                .checked_sub(witness.encoded_len()?)
                .context(InternalPqError("PQ deferred parent byte accounting"))?;
            if let Err(error) = self.complete(witness) {
                if error.downcast_ref::<RejectedCandidateExecution>().is_none() {
                    return Err(error);
                }
                self.completed_candidates.remove(&index);
                self.candidate_timings.remove(&index);
                self.invalid_packets = self.invalid_packets.saturating_add(1);
                warn!("PQ rejected deferred native candidate: {error:#}");
            }
        }
        Ok(())
    }

    fn retry(&mut self) -> Result<()> {
        self.ensure_journal_ready()?;
        // At most one full repair body is loaded/authenticated per service
        // turn. Repeated requests coalesce before any CF read or decode.
        self.serve_pending_repair()?;
        self.dispatch_ready_candidates()?;
        let mut missing = self
            .needed_parent_repairs(self.adopted_anchor()?)
            .into_iter()
            .collect::<Vec<_>>();
        missing.sort_by_key(|(hash, priority)| (*priority, *hash));
        for (parent, priority) in missing {
            self.request_repair_with_priority(parent, priority)?;
        }
        let finalized = self.machine.finalized_chain().last().unwrap().slot;
        for evidence in self.signer.released_evidence_after(finalized)? {
            let mut frame = vec![3];
            frame.extend(evidence.encode()?);
            self.broadcast(&frame);
        }
        let witnesses = self
            .proposed
            .values()
            .filter(|w| w.marker.slot > finalized)
            .cloned()
            .collect::<Vec<_>>();
        for witness in witnesses {
            if !self.blocks.contains_key(&witness.marker.block_commitment)
                && !self.pipeline.as_ref().is_some_and(|pipeline| {
                    pipeline
                        .publishing
                        .contains(&witness.marker.block_commitment)
                })
            {
                self.complete(witness.clone())?;
                self.send_witness(None, &witness)?;
            }
        }
        Ok(())
    }

    fn update_status(&self) {
        if let Some(transport) = &self.transport {
            for trace in transport.drain_block_traces() {
                info!("PQ transport stage=block_timing {trace}");
            }
        }
        // Read only the small durable header. These counters are diagnostics;
        // they do not certify journal contents or replace authenticated replay.
        let journal = match self.blockstore.experimental_pq_journal_usage() {
            Ok(usage) => json!({
                "body_bytes": usage.as_ref().map_or(0, |usage| usage.body_bytes),
                "records": usage.as_ref().map_or(0, |usage| usage.records),
                "chunks": usage.as_ref().map_or(0, |usage| usage.chunks),
                "limit_bytes": MAX_EXPERIMENTAL_PQ_JOURNAL_BYTES,
                "error": null,
            }),
            Err(error) => json!({
                "body_bytes": null,
                "records": null,
                "chunks": null,
                "limit_bytes": MAX_EXPERIMENTAL_PQ_JOURNAL_BYTES,
                "error": error.to_string(),
            }),
        };
        let bank = self.bank_forks.read().unwrap().root_bank();
        let pending_evidence = self
            .outbound
            .values()
            .map(|queue| queue.evidence.len())
            .sum::<usize>();
        let pending_blocks = self
            .outbound
            .values()
            .map(|queue| queue.blocks.len())
            .sum::<usize>();
        let missing_queued_bodies = self
            .outbound
            .values()
            .map(|queue| {
                queue
                    .blocks
                    .iter()
                    .filter(|(hash, _)| {
                        !self.blocks.contains_key(hash)
                            && !self.outbound_witnesses.contains_key(hash)
                    })
                    .count()
            })
            .sum::<usize>();
        let missing_repair_fronts = self
            .outbound
            .keys()
            .filter(|peer| self.missing_repair_front(**peer).is_some())
            .count();
        let transport = self.transport.as_ref().map(|transport| json!({
            "sent_control_frames": transport.stats.sent_control_frames.load(Ordering::Relaxed),
            "sent_bulk_frames": transport.stats.sent_bulk_frames.load(Ordering::Relaxed),
            "control_queue_wait_us": transport.stats.control_queue_wait_us.load(Ordering::Relaxed),
            "maximum_control_queue_wait_us": transport.stats.maximum_control_queue_wait_us.load(Ordering::Relaxed),
            "queue_full": transport.stats.queue_full.load(Ordering::Relaxed),
            "reconnects": transport.stats.reconnects.load(Ordering::Relaxed),
            "inbound_budget_wait_frames": transport.stats.inbound_budget_wait_frames.load(Ordering::Relaxed),
            "inbound_budget_wait_us": transport.stats.inbound_budget_wait_us.load(Ordering::Relaxed),
            "inbound_budget_wait_max_us": transport.stats.inbound_budget_wait_max_us.load(Ordering::Relaxed),
            "inbound_channel_wait_frames": transport.stats.inbound_channel_wait_frames.load(Ordering::Relaxed),
            "inbound_channel_wait_us": transport.stats.inbound_channel_wait_us.load(Ordering::Relaxed),
            "inbound_channel_wait_max_us": transport.stats.inbound_channel_wait_max_us.load(Ordering::Relaxed),
            "block_trace_evictions": transport.stats.block_trace_evictions(),
        }));
        let persisted_accounts_cache = bank.pq_persisted_accounts_cache_stats();
        let pipeline = self.pipeline.as_ref().map(|pipeline| json!({
            "producer_busy": pipeline.producer.busy, "candidate_busy": pipeline.candidate.busy,
            "unsigned_preparation_busy": pipeline.unsigned_preparation.busy,
            "unsigned_prepared_banks": usize::from(pipeline.unsigned_ready.is_some()),
            "private_native_parent_banks": pipeline.private_parents.len(),
            "pending_native_bodies": pipeline.pending_candidates.len(),
            "candidate_body_busy": pipeline.candidate_body.busy,
            "reconstruction_busy": pipeline.reconstruction.busy,
            "publisher_busy": pipeline.publisher.busy, "archive_busy": pipeline.archive.busy,
            "pending_publications": pipeline.pending_publications.len(),
            "publishing_candidates": pipeline.publishing.len(),
            "ordered_finalizations": self.pending_finalizations.len(),
            "streaming_candidates": self.streaming.len(),
            "streaming_frames": self.streaming.values().map(|stream| stream.frames.len()).sum::<usize>(),
            "candidate_jobs": pipeline.executing.len(), "recovered_proposal_intents": self.resume_intents.len(),
        }));
        let runtime = self.runtime.lock().unwrap();
        let candidate_banks = runtime.banks.len().saturating_sub(1);
        let candidate_max_slot = runtime
            .banks
            .values()
            .map(|bank| bank.slot())
            .max()
            .unwrap();
        let candidate_transactions = runtime
            .banks
            .values()
            .map(|bank| bank.transaction_count())
            .max()
            .unwrap();
        *self.status.write().unwrap() = json!({"experimental_pq": true, "started": wall_ms() >= self.public.start_unix_ms, "validator": self.local.to_string(), "slot": bank.slot(), "bank_hash": bank.hash().to_string(), "last_blockhash": bank.last_blockhash().to_string(), "state_root": encode_hex(&bank_state(&bank)), "transactions": bank.transaction_count(), "finalized_transactions": self.finalized_transactions, "submitted": self.submitted, "mempool": self.mempool.len(), "mempool_bytes": self.mempool.bytes, "local_ingress_queued": self.ingress.len(), "pending_local_ingress": usize::from(self.pending_local_ingress.is_some()), "local_ingress_held": self.pending_local_ingress.is_some(), "local_ingress_full_events": self.local_ingress_full_events, "local_ingress_retry_attempts": self.local_ingress_retry_attempts, "peer_ingress_full_events": self.peer_ingress_full_events, "invalid_packets": self.invalid_packets, "send_rejected": self.send_rejected, "send_queue_retries": self.send_rejected, "pending_evidence": pending_evidence, "pending_block_cursors": pending_blocks, "pending_parent_blocks": self.waiting_parents.len(), "repair": {"waiting_parent_bytes": self.waiting_parent_bytes, "parent_requests": self.parent_repairs.len(), "responses": self.repair_responses.len(), "pending_responses": self.repair_responses.values().filter(|response| response.requested).count(), "cache_bodies": self.outbound_witnesses.len(), "cache_bytes": self.outbound_witnesses.values().map(repair_witness_bytes).sum::<usize>(), "cache_limit_bytes": MAX_REPAIR_BYTES, "durable_lookup_hints": self.durable_block_slots.len(), "deferred_refetch_descriptors": self.deferred_refetches.len(), "missing_queued_bodies": missing_queued_bodies, "missing_repair_fronts": missing_repair_fronts, "incomplete_assemblers": self.assemblers.len(), "incomplete_markers": self.markers.len()}, "gossip_retained_transactions": self.gossip_log.len(), "candidate_banks": candidate_banks, "candidate_max_slot": candidate_max_slot, "candidate_transactions": candidate_transactions, "consensus_clock_ms": self.machine.clock(), "epoch_slots": self.public.slot_count, "execution_threads": self.public.execution_threads, "execution_backend": "parallel_native_batches", "candidate_storage": "immutable_snapshot_delta", "certified_commit": "promote_frozen_bank", "duplicate_execution_count": 0, "proposal_target_block_bytes": self.public.proposal_target_block_bytes.unwrap_or(self.public.target_block_bytes), "proposal_max_transactions": self.public.proposal_max_transactions.unwrap_or(self.public.max_transactions), "validation_max_block_bytes": self.public.target_block_bytes, "validation_max_transactions": self.public.max_transactions, "pipeline": pipeline, "transport": transport, "journal": journal, "persisted_accounts_cache": persisted_accounts_cache});
    }
}

pub fn encode_block(transactions: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(
        transactions.len() <= MAX_BLOCK_TRANSACTIONS,
        "PQ block transaction count"
    );
    let mut out = b"AGVPQTX1".to_vec();
    out.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for transaction in transactions {
        ensure!(
            transaction.len() <= MAX_TRANSACTION_BYTES,
            "PQ transaction size"
        );
        put_bytes(&mut out, transaction)?;
    }
    ensure!(out.len() <= MAX_BLOCK_BYTES, "PQ block bytes");
    Ok(out)
}

/// Common constitutional configuration stored in the immutable PQ role account
/// in actual genesis. Local paths, process addresses and wall-clock start gates
/// and local worker/proposal limits are excluded. Every authority, stake, peer
/// address and consensus execution bound is authenticated. Peer order determines
/// this finite epoch's leader windows.
pub fn genesis_role_registry_bytes(config: &ExperimentalPqConfig) -> Result<Vec<u8>> {
    let mut out = b"AGVPQR01".to_vec();
    let chain: [u8; 32] = decode_hex(&config.chain)?
        .try_into()
        .map_err(|_| anyhow!("PQ registry chain"))?;
    out.extend_from_slice(&chain);
    for value in [
        config.epoch,
        config.first_slot,
        config.slot_count,
        config.window_size,
        config.network_delay_ms,
        config.block_time_ms,
        config.target_block_bytes as u64,
        config.max_transactions as u64,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&u32::try_from(config.peers.len())?.to_le_bytes());
    for peer in &config.peers {
        let id = Pubkey::from_str(&peer.id)?;
        out.extend_from_slice(id.as_ref());
        let vote = peer
            .vote_account
            .as_ref()
            .map(|x| Pubkey::from_str(x))
            .transpose()?
            .unwrap_or(id);
        out.extend_from_slice(vote.as_ref());
        out.extend_from_slice(&peer.stake.to_le_bytes());
        match peer.address {
            SocketAddr::V4(address) => {
                out.push(4);
                out.extend_from_slice(&address.ip().octets());
                out.extend_from_slice(&address.port().to_le_bytes());
            }
            SocketAddr::V6(address) => {
                out.push(6);
                out.extend_from_slice(&address.ip().octets());
                out.extend_from_slice(&address.port().to_le_bytes());
                out.extend_from_slice(&address.scope_id().to_le_bytes());
                out.extend_from_slice(&address.flowinfo().to_le_bytes());
            }
        }
        for descriptor in [&peer.network_key, &peer.leader_key, &peer.consensus_key] {
            put_bytes(&mut out, &decode_hex(descriptor)?)?;
        }
    }
    ensure!(out.len() <= 8 * 1024 * 1024, "PQ registry bounds");
    Ok(out)
}

fn decode_block(bytes: &[u8], maximum: usize) -> Result<Vec<VersionedTransaction>> {
    ensure!(
        bytes.len() <= MAX_BLOCK_BYTES && bytes.starts_with(b"AGVPQTX1"),
        "PQ block header"
    );
    let mut reader = Reader { bytes, at: 8 };
    let count = reader.u32()? as usize;
    ensure!(
        count <= maximum && count <= MAX_BLOCK_TRANSACTIONS && count <= bytes.len() / 4,
        "PQ block count"
    );
    let transactions = (0..count)
        .map(|_| decode_transaction(reader.bytes(MAX_TRANSACTION_BYTES)?))
        .collect::<Result<Vec<_>>>()?;
    ensure!(reader.at == bytes.len(), "PQ block trailing bytes");
    Ok(transactions)
}

fn decode_transaction(bytes: &[u8]) -> Result<VersionedTransaction> {
    ensure!(bytes.len() <= MAX_TRANSACTION_BYTES, "PQ transaction bytes");
    let transaction: VersionedTransaction =
        bincode::deserialize(bytes).context("PQ transaction decode")?;
    ensure!(
        bincode::serialize(&transaction)? == bytes,
        "PQ transaction noncanonical encoding"
    );
    Ok(transaction)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    out.extend_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32> {
        let value = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| anyhow!("PQ truncated length"))?;
        self.at += 4;
        Ok(u32::from_le_bytes(value.try_into().unwrap()))
    }
    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        ensure!(length <= maximum, "PQ decoded length bounds");
        let value = self
            .bytes
            .get(
                self.at
                    ..self
                        .at
                        .checked_add(length)
                        .ok_or_else(|| anyhow!("PQ length overflow"))?,
            )
            .ok_or_else(|| anyhow!("PQ truncated bytes"))?;
        self.at += length;
        Ok(value)
    }
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>> {
    ensure!(value.len().is_multiple_of(2), "PQ hexadecimal length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let nibble = |c: u8| -> Result<u8> {
                match c {
                    b'0'..=b'9' => Ok(c - b'0'),
                    b'a'..=b'f' => Ok(c - b'a' + 10),
                    _ => bail!("PQ canonical hexadecimal"),
                }
            };
            Ok(nibble(pair[0])? * 16 + nibble(pair[1])?)
        })
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        agave_pq_crypto::{
            auth::{AuthRecord, Origin},
            ax::AxEpoch,
            ax_state::MemoryMonotonicStore,
            consensus::{ConsensusMessage, MessageKind},
            network::SignedBatch,
        },
        solana_account::Account,
        solana_fee_calculator::FeeRateGovernor,
        solana_message::{Message, VersionedMessage},
        solana_runtime::{
            genesis_utils::{GenesisConfigInfo, create_genesis_config_with_leader},
            pq::{self, authenticate_instruction, sign_transaction},
        },
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
    };

    fn repair_fixture() -> (tempfile::TempDir, PqNode) {
        repair_fixture_with_slots(32)
    }

    fn repair_fixture_with_slots(slots: u32) -> (tempfile::TempDir, PqNode) {
        let (directory, node, _signers) = repair_fixture_with_signers(slots);
        (directory, node)
    }

    fn repair_fixture_with_signers(
        slots: u32,
    ) -> (tempfile::TempDir, PqNode, Vec<DurableConsensusSigner>) {
        repair_fixture_with_signers_and_fee(slots, None)
    }

    fn repair_fixture_with_signers_and_fee(
        slots: u32,
        lamports_per_signature: Option<u64>,
    ) -> (tempfile::TempDir, PqNode, Vec<DurableConsensusSigner>) {
        repair_fixture_configured(slots, lamports_per_signature, 1, |_| {})
    }

    fn repair_fixture_configured(
        slots: u32,
        lamports_per_signature: Option<u64>,
        cutoff_slot: u64,
        configure: impl FnOnce(&mut solana_genesis_config::GenesisConfig),
    ) -> (tempfile::TempDir, PqNode, Vec<DurableConsensusSigner>) {
        let directory = tempfile::tempdir().unwrap();
        let chain = [0x81; 32];
        let leader = FalconKeypair::generate();
        let ids = (0..4).map(|_| Pubkey::new_unique()).collect::<Vec<_>>();
        let signer = DurableConsensusSigner::create(
            directory.path().join("ax"),
            AxEpoch {
                chain,
                validator: ids[0].to_bytes(),
                epoch: 7,
                generation: 0,
                first_slot: 1,
                slots,
            },
            &leader,
            Arc::new(MemoryMonotonicStore::default()),
        )
        .unwrap();
        let mut validators = vec![PqValidator {
            id: ids[0].to_bytes(),
            stake: 1,
            key: signer.public_key(),
        }];
        let mut other_signers = Vec::new();
        for (index, id) in ids.iter().enumerate().skip(1) {
            let other = DurableConsensusSigner::create(
                directory.path().join(format!("ax-{index}")),
                AxEpoch {
                    chain,
                    validator: id.to_bytes(),
                    epoch: 7,
                    generation: 0,
                    first_slot: 1,
                    slots,
                },
                &FalconKeypair::generate(),
                Arc::new(MemoryMonotonicStore::default()),
            )
            .unwrap();
            validators.push(PqValidator {
                id: id.to_bytes(),
                stake: 1,
                key: other.public_key(),
            });
            other_signers.push(other);
        }
        let mut genesis =
            create_genesis_config_with_leader(1_000_000_000, &ids[0], 1_000_000).genesis_config;
        if let Some(lamports) = lamports_per_signature {
            genesis.fee_rate_governor = FeeRateGovernor::new(lamports, 0);
        }
        genesis.accounts.insert(
            pq::CONFIG_ADDRESS,
            pq::Config {
                chain_id: chain,
                migration_context: [0x82; 32],
                cutoff_slot,
            }
            .account(10_000_000),
        );
        let policy = AuthRecord::new(
            ids[0].to_bytes(),
            leader.public_key(),
            Origin::FreshIdentity,
        )
        .encode();
        genesis.accounts.insert(
            ids[0],
            Account {
                lamports: 1_000_000_000,
                ..Account::default()
            },
        );
        genesis.accounts.insert(
            pq::policy_address(&ids[0]),
            Account {
                lamports: genesis.rent.minimum_balance(policy.len()).max(1),
                data: policy,
                owner: pq::PROGRAM_ID,
                rent_epoch: u64::MAX,
                ..Account::default()
            },
        );
        genesis.accounts.insert(
            Pubkey::new_from_array([0xa8; 32]),
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        );
        configure(&mut genesis);
        let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis));
        let root = forks.read().unwrap().root_bank();
        root.freeze();
        let anchor = BlockRef {
            slot: 0,
            hash: [0x83; 48],
        };
        let runtime = Arc::new(Mutex::new(RuntimeForks {
            banks: BTreeMap::from([(anchor.hash, root.clone())]),
            states: BTreeMap::from([(anchor.hash, bank_state(&root))]),
            archives: BTreeMap::new(),
            executions: BTreeMap::new(),
            chain,
            first_slot: 1,
            leaders: vec![*root.leader(); slots as usize],
            max_transactions: 8192,
            max_block_bytes: MAX_BLOCK_BYTES,
            executor: Arc::new(PqExecutor::new(2).unwrap()),
        }));
        let execution_runtime = runtime.clone();
        let machine = Quantumglow::new(
            Config {
                chain,
                epoch: 7,
                first_slot: 1,
                slot_count: slots as u64,
                window_size: 4,
                network_delay_ms: 1000,
                block_time_ms: 500,
                leaders: vec![ids[0].to_bytes(); slots as usize],
                leader_keys: BTreeMap::from([(ids[0].to_bytes(), leader.public_key())]),
                finalized_anchor: anchor,
                finalized_state_root: bank_state(&root),
                execution_rules: [0x84; 48],
                validate_execution: Arc::new(move |candidate| {
                    execution_runtime.lock().unwrap().validate(candidate)
                }),
            },
            ids[0].to_bytes(),
            validators,
        )
        .unwrap();
        let public = ExperimentalPqConfig {
            chain: encode_hex(&chain),
            genesis_hash: genesis.hash().to_string(),
            activation_state: encode_hex(&bank_state(&root)),
            local_id: ids[0].to_string(),
            epoch: 7,
            first_slot: 1,
            slot_count: slots as u64,
            window_size: 4,
            network_delay_ms: 1000,
            block_time_ms: 500,
            target_block_bytes: MAX_BLOCK_BYTES,
            max_transactions: 8192,
            execution_threads: 2,
            proposal_target_block_bytes: None,
            proposal_max_transactions: None,
            listen: "127.0.0.1:0".parse().unwrap(),
            key_directory: directory.path().to_path_buf(),
            peers: Vec::new(),
            start_unix_ms: wall_ms().saturating_sub(10_000),
            prewarm_seed_verifier: false,
        };
        let node = PqNode {
            public,
            local: ids[0],
            chain,
            leader: Arc::new(leader),
            signer,
            machine,
            durable_journal_records: 0,
            runtime,
            bank_forks: forks.clone(),
            block_commitment_cache: Arc::new(RwLock::new(BlockCommitmentCache::default())),
            optimistically_confirmed_bank: OptimisticallyConfirmedBank::locked_from_bank_forks_root(
                &forks,
            ),
            blockstore: Arc::new(Blockstore::open(&directory.path().join("ledger")).unwrap()),
            transport: None,
            authentication_pool: Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(2)
                    .build()
                    .unwrap(),
            ),
            ingress: bounded(1).1,
            pending_local_ingress: None,
            local_ingress_full_events: 0,
            local_ingress_retry_attempts: 0,
            peer_ingress_full_events: 0,
            mempool_test_limits: None,
            #[cfg(test)]
            evidence_authentication_probe: None,
            #[cfg(test)]
            shred_decode_probe: None,
            #[cfg(test)]
            shred_decode_work: Arc::default(),
            exit: Arc::new(AtomicBool::new(false)),
            status: Arc::new(RwLock::new(json!({}))),
            pending: VecDeque::new(),
            production: None,
            pipeline: None,
            pending_finalizations: VecDeque::new(),
            speculative_ids: BTreeMap::new(),
            streaming: BTreeMap::new(),
            resume_intents: BTreeMap::new(),
            receiving_batch: false,
            received_evidence: None,
            completion_attempts: BTreeSet::new(),
            assemblers: BTreeMap::new(),
            candidate_timings: BTreeMap::new(),
            markers: BTreeMap::new(),
            blocks: BTreeMap::new(),
            block_slots: BTreeMap::from([(anchor.hash, anchor.slot)]),
            durable_block_slots: BTreeMap::new(),
            outbound_witnesses: BTreeMap::new(),
            waiting_parents: BTreeMap::new(),
            waiting_parent_bytes: 0,
            deferred_refetches: BTreeMap::new(),
            parent_repairs: BTreeMap::new(),
            repair_responses: BTreeMap::new(),
            repair_response_cursor: None,
            next_repair_admission: 1,
            repair_progress: BTreeMap::new(),
            completed_candidates: BTreeSet::new(),
            proposed: BTreeMap::new(),
            mempool: IndexedMempool::default(),
            mempool_order: IndexedAdmissionOrder::default(),
            seen_evidence: BTreeSet::new(),
            outbound: ids[1..]
                .iter()
                .map(|id| (*id, PeerOutbound::default()))
                .collect(),
            evidence_packets: BTreeMap::new(),
            gossip_log: BTreeMap::new(),
            submitted: 0,
            finalized_transactions: 0,
            invalid_packets: 0,
            send_rejected: 0,
            last_retry: Instant::now(),
        };
        (directory, node, other_signers)
    }

    fn repair_witness(
        node: &PqNode,
        slot: u64,
        parent: Commitment,
        payload: &[u8],
    ) -> BlockWitness {
        let batch = SignedBatch::build(
            &node.chain,
            &node.leader,
            BatchContext {
                leader_epoch: 7,
                slot,
                candidate: [slot as u8; 48],
                parent,
                batch_index: 0,
                previous: [0; 48],
            },
            payload,
            64,
            64,
        )
        .unwrap();
        let marker = FinalMarker::build(
            &node.chain,
            &node.leader,
            std::slice::from_ref(&batch),
            payload,
        )
        .unwrap();
        BlockWitness {
            marker,
            shreds: batch.shreds[..64].to_vec(),
        }
    }

    fn legacy_witness_encoding(witness: &BlockWitness) -> Result<Vec<u8>> {
        let mut out = b"AGVPQBW1".to_vec();
        put_bytes(&mut out, &witness.marker.encode())?;
        out.extend_from_slice(&(witness.shreds.len() as u32).to_le_bytes());
        for shred in &witness.shreds {
            put_bytes(&mut out, &shred.encode()?)?;
        }
        ensure!(out.len() <= 64 * 1024 * 1024, "PQ witness bounds");
        Ok(out)
    }

    #[test]
    fn native_witness_validated_length_preserves_wire_errors_and_size_boundary() {
        let (_directory, node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap().hash;
        for bytes in [1, 8192, 64 * agave_pq_crypto::network::MAX_SHARD_PAYLOAD] {
            let witness = repair_witness(&node, 1, parent, &vec![0xe4; bytes]);
            let encoded = witness.encode().unwrap();
            assert_eq!(encoded, legacy_witness_encoding(&witness).unwrap());
            assert_eq!(witness.encoded_len().unwrap(), encoded.len());
            assert_eq!(
                BlockWitness::decode(&encoded).unwrap().encode().unwrap(),
                encoded
            );
            let mut trailing = encoded;
            trailing.push(0);
            assert!(BlockWitness::decode(&trailing).is_err());
            for case in 0..5 {
                let mut invalid = witness.clone();
                match case {
                    0 => invalid.shreds[0].metadata.data_shards = 0,
                    1 => invalid.shreds[0].metadata.shard_bytes = 0,
                    2 => {
                        invalid.shreds[0].payload.pop();
                    }
                    3 => {
                        invalid.shreds[0].proof.pop();
                    }
                    _ => invalid.shreds[0].is_parity = true,
                }
                assert_eq!(
                    invalid.encode().unwrap_err().to_string(),
                    legacy_witness_encoding(&invalid).unwrap_err().to_string(),
                );
                assert_eq!(
                    invalid.encoded_len().unwrap_err().to_string(),
                    invalid.encode().unwrap_err().to_string(),
                );
            }
        }
        let witness = repair_witness(
            &node,
            1,
            parent,
            &vec![0xe5; 64 * agave_pq_crypto::network::MAX_SHARD_PAYLOAD],
        );
        let shred = witness.shreds[0].clone();
        let mut boundary = BlockWitness {
            marker: witness.marker,
            shreds: vec![],
        };
        let header = boundary.encode().unwrap().len();
        assert_eq!(boundary.encoded_len().unwrap(), header);
        let per_shred = 4 + shred.encode().unwrap().len();
        let count = (64 * 1024 * 1024 - header) / per_shred;
        // This is an encoder-size oracle, not a candidate authentication claim:
        // duplicated signed shreds exercise the exact existing container limit.
        boundary.shreds = vec![shred.clone(); count];
        assert_eq!(
            boundary.encoded_len().unwrap(),
            boundary.encode().unwrap().len()
        );
        assert!(boundary.encoded_len().unwrap() <= 64 * 1024 * 1024);
        assert_eq!(
            boundary.encode().unwrap(),
            legacy_witness_encoding(&boundary).unwrap()
        );
        boundary.shreds.push(shred);
        assert_eq!(
            boundary.encoded_len().unwrap_err().to_string(),
            "PQ witness bounds"
        );
        assert_eq!(
            boundary.encode().unwrap_err().to_string(),
            "PQ witness bounds"
        );
        assert_eq!(
            boundary.encode().unwrap_err().to_string(),
            legacy_witness_encoding(&boundary).unwrap_err().to_string()
        );
    }

    #[test]
    fn native_pipeline_journal_ack_keeps_native_work_private_and_later_ingress_queued() {
        let (directory, mut node, _signers) = repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap().hash;
        let witness = pipeline_peer_witness(&node, &root, 1, anchor, u64::MAX);
        let hash = witness.marker.block_commitment;
        let mut pipeline = PqPipeline::new().unwrap();
        let (native_entered, native_entering) = bounded(1);
        let (native_release, native_released) = bounded(1);
        pipeline
            .gate_candidate_before_execution(native_entered, native_released)
            .unwrap();
        let finished_native = pipeline.candidate.result_observer();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.journal_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        node.pipeline = Some(pipeline);
        node.complete(witness.clone()).unwrap();
        native_entering
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        let (sender, receiver) = bounded(2);
        node.ingress = receiver.clone();
        let later = bincode::serialize(&pipeline_transfer(&node, &root, 7)).unwrap();
        sender.try_send(later.clone()).unwrap();
        sender.try_send(later.clone()).unwrap();
        assert!(matches!(
            sender.try_send(later.clone()),
            Err(crossbeam_channel::TrySendError::Full(_))
        ));
        let actions = node.machine.tick(0).unwrap();
        let expected_journal = node.machine.recovery_journal().encode().unwrap();
        let target = node.machine.recovery_record_count();
        let storage = node.blockstore.clone();
        let runtime = node.runtime.clone();
        let forks = node.bank_forks.clone();
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        let thread = thread::spawn(move || {
            let result = node.persist(&actions);
            (node, result)
        });
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        native_release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while finished_native.is_empty() {
            assert!(
                Instant::now() < deadline,
                "real native work did not finish under append gate"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!thread.is_finished());
        assert!(!runtime.lock().unwrap().banks.contains_key(&hash));
        assert!(
            storage
                .get_experimental_pq_block(1, hash)
                .unwrap()
                .is_none()
        );
        assert!(storage.get_experimental_pq_checkpoint().unwrap().is_none());
        assert_eq!(forks.read().unwrap().root(), 0);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        assert_eq!(receiver.len(), 2);
        release.send(()).unwrap();
        let (mut node, result) = thread.join().unwrap();
        result.unwrap();
        assert_eq!(node.durable_journal_records, target);
        assert!(node.pipeline.as_ref().unwrap().journal_barrier.is_none());
        assert_eq!(
            storage.get_experimental_pq_checkpoint().unwrap().unwrap(),
            expected_journal
        );
        assert_eq!(node.submitted, 0);
        assert!(node.mempool.is_empty());
        assert!(node.pending.is_empty());
        assert!(node.machine.payload(&hash).is_none());
        pump_pipeline_until(&mut node, |node| node.machine.payload(&hash).is_some());
        let runtime = node.runtime.lock().unwrap();
        let actual = &runtime.banks[&hash];
        let payload = node.machine.payload(&hash).unwrap();
        let serial = Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap();
        let expected = decode_block(payload, 1)
            .unwrap()
            .into_iter()
            .map(|tx| process_with_status(&serial, tx).unwrap())
            .collect::<Vec<_>>();
        complete_bank(&serial, &node.chain, &anchor, payload);
        assert_eq!(bank_state(&serial), bank_state(actual));
        assert_eq!(runtime.archives[&hash].as_ref(), &expected);
        assert_eq!(expected.len(), 1);
        assert!(expected[0].1.status.is_err());
        assert_eq!(expected[0].1.fee, 5000);
        assert_eq!(receiver.len(), 2);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
    }

    #[test]
    fn native_pipeline_journal_two_acks_gate_new_vote_while_signed_data_crosses_real_quic() {
        let (directory, mut node, signers) = repair_fixture_with_signers(32);
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap().hash;
        let witness = pipeline_peer_witness(&node, &root, 1, anchor, 7);
        let candidate = node.authenticate_witness(&witness).unwrap();
        let block_payload = candidate.payload().to_vec();
        node.runtime
            .lock()
            .unwrap()
            .validate_checked(&ExecutionCandidate {
                reference: BlockRef {
                    slot: 1,
                    hash: witness.marker.block_commitment,
                },
                parent: anchor,
                payload: candidate.payload(),
            })
            .unwrap();
        node.blockstore
            .put_experimental_pq_block(
                1,
                witness.marker.block_commitment,
                &witness.encode().unwrap(),
            )
            .unwrap();
        let actions = node.machine.observe_verified(candidate, 0).unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Broadcast(_)))
        );
        let first_wire = node.machine.recovery_journal().encode().unwrap();
        let first_target = node.machine.recovery_record_count();
        let peer = *node.outbound.keys().next().unwrap();
        let peer_key = Arc::new(FalconKeypair::generate());
        let registry = BTreeMap::from([
            (node.local, node.leader.public_key()),
            (peer, peer_key.public_key()),
        ]);
        let local_identity = node.local;
        let remote_exit = Arc::new(AtomicBool::new(false));
        let remote = PqQuicTransport::spawn(
            PqQuicConfig {
                chain: node.chain,
                identity: peer,
                signer: peer_key,
                registry: registry.clone(),
                peers: BTreeMap::new(),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            remote_exit,
        )
        .unwrap();
        node.transport = Some(
            PqQuicTransport::spawn(
                PqQuicConfig {
                    chain: node.chain,
                    identity: node.local,
                    signer: node.leader.clone(),
                    registry,
                    peers: BTreeMap::from([(peer, remote.local_addr)]),
                    listen: "127.0.0.1:0".parse().unwrap(),
                },
                node.exit.clone(),
            )
            .unwrap(),
        );
        let mut pipeline = PqPipeline::new().unwrap();
        pipeline.producer_reservation = Some(Production {
            first: 1,
            next: 1,
            parent: anchor,
            due: 0,
        });
        let intent = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            chain: node.chain,
            epoch: 7,
            slot: 1,
            parent: anchor,
            candidate: witness.marker.candidate,
            payload: block_payload,
        };
        node.blockstore
            .put_experimental_pq_proposal_intent(&intent)
            .unwrap();
        let expected_data = witness
            .shreds
            .iter()
            .map(|shred| {
                let mut frame = vec![1];
                frame.extend(shred.encode().unwrap());
                frame
            })
            .collect::<Vec<_>>();
        let mut terminal = vec![2];
        terminal.extend(witness.marker.encode());
        pipeline
            .stream_sender
            .try_send(pipeline::StreamBatch {
                slot: 1,
                candidate: witness.marker.candidate,
                frames: expected_data
                    .iter()
                    .cloned()
                    .chain(std::iter::once(terminal.clone()))
                    .map(Arc::new)
                    .collect(),
            })
            .unwrap();
        let (first_entered, first_entering) = bounded(1);
        let (first_release, first_released) = bounded(1);
        let (second_entered, second_entering) = bounded(1);
        let (second_release, second_released) = bounded(1);
        pipeline.journal_gate = Some(pipeline::ArchiveGate {
            entered: first_entered,
            release: first_released,
            fail: false,
        });
        node.pipeline = Some(pipeline);
        let storage = node.blockstore.clone();
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        let candidate_id = witness.marker.candidate;
        let thread = thread::spawn(move || {
            node.persist(&actions).unwrap();
            assert_eq!(node.durable_journal_records, first_target);
            let stream = &node.streaming[&candidate_id];
            assert_eq!(stream.slot, 1);
            assert!(node.owns_stream(1, &candidate_id));
            let cursors = stream.cursors.clone();
            node.pending.extend(actions);
            node.pipeline.as_mut().unwrap().journal_gate = Some(pipeline::ArchiveGate {
                entered: second_entered,
                release: second_released,
                fail: false,
            });
            node.drive().unwrap();
            assert!(node.owns_stream(1, &candidate_id));
            assert!(
                node.streaming[&candidate_id]
                    .cursors
                    .iter()
                    .all(|(peer, cursor)| *cursor >= cursors[peer])
            );
            (node, signers)
        });
        first_entering.recv_timeout(Duration::from_secs(3)).unwrap();
        let mut data = Vec::new();
        let mut saw_terminal = false;
        while data.len() < expected_data.len() || !saw_terminal {
            let (from, frame) = remote
                .receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert_eq!(from, local_identity);
            match frame.first() {
                Some(1) => data.push(frame),
                Some(2) => {
                    assert_eq!(frame, terminal);
                    saw_terminal = true;
                }
                _ => panic!("new consensus action escaped first journal ACK"),
            }
        }
        assert_eq!(data, expected_data);
        assert!(storage.get_experimental_pq_checkpoint().unwrap().is_none());
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        first_release.send(()).unwrap();
        second_entering
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            storage.get_experimental_pq_checkpoint().unwrap().unwrap(),
            first_wire
        );
        assert_ne!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        assert!(remote.receiver.try_recv().is_err());
        second_release.send(()).unwrap();
        let (mut node, signers) = thread.join().unwrap();
        assert!(node.durable_journal_records > first_target);
        let wire = storage.get_experimental_pq_checkpoint().unwrap().unwrap();
        // Timers/certificates can legitimately authorize further own votes
        // during drive. Compare every exact released wire to the complete
        // authenticated journal, rather than assuming a one-vote outcome.
        agave_pq_crypto::quantumglow::RecoveryJournal::decode(&wire).unwrap();
        let mut reader = Reader {
            bytes: &wire,
            at: 53,
        };
        let count = u32::from_le_bytes(wire[49..53].try_into().unwrap());
        let mut expected_evidence = BTreeMap::new();
        for _ in 0..count {
            let tag = wire[reader.at];
            reader.at += 9; // Record tag and unchanged u64 observation time.
            match tag {
                0 => {}
                1 => {
                    let raw = reader.bytes(4 * 1024 * 1024).unwrap();
                    let evidence = SignedEvidence::decode(raw).unwrap();
                    if evidence.validator == node.local.to_bytes() {
                        let id = hash_commitment(b"agave-pq-evidence-wire-v1", &[raw]);
                        let mut frame = vec![3];
                        frame.extend_from_slice(raw);
                        assert!(
                            expected_evidence
                                .insert(id, (evidence.message.slot, frame))
                                .is_none()
                        );
                    }
                }
                2 => {
                    reader.bytes(4096).unwrap();
                    for _ in 0..reader.u32().unwrap() {
                        reader.bytes(4096).unwrap();
                    }
                }
                _ => panic!("unexpected authenticated journal record"),
            }
        }
        assert_eq!(reader.at, wire.len());
        assert!(!expected_evidence.is_empty());
        assert_eq!(node.evidence_packets, expected_evidence);
        let mut delivered = BTreeMap::new();
        while delivered.len() < expected_evidence.len() {
            node.flush_outbound().unwrap();
            let (from, frame) = remote
                .receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert_eq!(from, local_identity);
            assert_eq!(frame.first(), Some(&3));
            let evidence = SignedEvidence::decode(&frame[1..]).unwrap();
            assert_eq!(evidence.validator, node.local.to_bytes());
            let id = hash_commitment(b"agave-pq-evidence-wire-v1", &[&frame[1..]]);
            assert!(
                delivered
                    .insert(id, (evidence.message.slot, frame))
                    .is_none()
            );
        }
        assert_eq!(delivered, expected_evidence);
        let validators = std::iter::once(PqValidator {
            id: node.local.to_bytes(),
            stake: 1,
            key: node.signer.public_key(),
        })
        .chain(signers.iter().map(|signer| PqValidator {
            id: signer.public_key().epoch().validator,
            stake: 1,
            key: signer.public_key(),
        }))
        .collect();
        let restored = Quantumglow::restore(
            node.machine.config().clone(),
            node.local.to_bytes(),
            validators,
            agave_pq_crypto::quantumglow::RecoveryJournal::decode(&wire).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.recovery_journal().encode().unwrap(), wire);
        assert_eq!(
            restored.retransmission_intents(),
            node.machine.retransmission_intents()
        );
        assert_eq!(restored.finalized_chain(), node.machine.finalized_chain());
        assert_eq!(restored.clock(), node.machine.clock());
        assert!(
            storage
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn native_pipeline_journal_failures_and_bad_ack_stop_before_later_inputs() {
        for mode in 0..5 {
            let (directory, mut node, signers) = repair_fixture_with_signers(32);
            let peer = *node.outbound.keys().next().unwrap();
            let root = node.bank_forks.read().unwrap().root_bank();
            let later = bincode::serialize(&pipeline_transfer(&node, &root, 7)).unwrap();
            let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
            if mode == 4 {
                // Genuine existing-prefix mismatch at the unchanged Blockstore
                // append boundary, in addition to injected pre-write errors.
                let mut header = node.machine.recovery_update_since(0).unwrap().header;
                header[49..53].copy_from_slice(&1u32.to_le_bytes());
                node.blockstore
                    .append_experimental_pq_checkpoint(&header, 0, &[0; 9], &[])
                    .unwrap();
            }
            let previous_disk = node.blockstore.get_experimental_pq_checkpoint().unwrap();
            let mut pipeline = PqPipeline::new().unwrap();
            let (entered, entering) = bounded(1);
            let (release, released) = bounded(1);
            if mode == 2 {
                pipeline.disconnect_journal_requests();
            } else {
                pipeline.journal_gate = Some(pipeline::ArchiveGate {
                    entered,
                    release: released,
                    fail: mode == 0 || mode == 3,
                });
            }
            pipeline.journal_bad_ack = mode == 1;
            let (service_error, saw_service_error) = bounded(1);
            if mode == 3 {
                pipeline.producer_reservation = Some(Production {
                    first: 1,
                    next: 1,
                    parent: node.adopted_anchor().unwrap().hash,
                    due: 0,
                });
                pipeline.journal_service_error = Some(service_error);
                let shared_frame = Arc::new(vec![1]);
                pipeline
                    .stream_sender
                    .try_send(pipeline::StreamBatch {
                        slot: 1,
                        candidate: [0xea; 48],
                        frames: vec![shared_frame; pipeline::MAX_STREAM_FRAMES + 1],
                    })
                    .unwrap();
            }
            node.pipeline = Some(pipeline);
            let evidence = signers[0]
                .sign(ConsensusMessage {
                    epoch: 7,
                    slot: 1,
                    kind: MessageKind::NotarVote,
                    block: Some([0xe9; 48]),
                })
                .unwrap();
            let mut evidence_frame = vec![3];
            evidence_frame.extend(evidence.encode().unwrap());
            let mut following = vec![4];
            following.extend(later.clone());
            let frames = vec![(peer, evidence_frame), (peer, following)];
            let handle = thread::spawn(move || {
                let error = node.receive_batch(frames).unwrap_err();
                (node, error)
            });
            if mode != 2 {
                entering.recv_timeout(Duration::from_secs(3)).unwrap();
                if mode == 3 {
                    assert!(
                        saw_service_error
                            .recv_timeout(Duration::from_secs(3))
                            .unwrap()
                            .contains("PQ streaming shred bound")
                    );
                }
                release.send(()).unwrap();
            }
            let (mut node, error) = handle.join().unwrap();
            assert!(
                fatal_receive_error(&error),
                "not immediately fatal: {error:#}"
            );
            assert!(error.downcast_ref::<InternalPqError>().is_some());
            let text = format!("{error:#}");
            match mode {
                0 => assert!(text.contains("test journal append failure")),
                1 => assert!(text.contains("PQ journal ACK context differs")),
                2 => assert!(text.contains("PQ worker stopped")),
                4 => {
                    assert!(text.contains("PQ incremental journal stale cursor or binding"));
                    assert!(
                        error
                            .downcast_ref::<solana_ledger::blockstore::error::BlockstoreError>()
                            .is_some()
                    );
                }
                _ => {
                    assert!(text.contains("PQ streaming shred bound"));
                    assert!(text.contains("test journal append failure"));
                }
            }
            assert!(node.pipeline.as_ref().unwrap().journal_failed);
            assert_eq!(node.durable_journal_records, 0);
            assert_eq!(node.machine.recovery_record_count(), 1);
            assert_eq!(node.submitted, 0);
            assert!(node.mempool.is_empty());
            assert!(node.seen_evidence.is_empty());
            assert!(node.pending.is_empty());
            assert!(node.evidence_packets.is_empty());
            assert_eq!(node.bank_forks.read().unwrap().root(), 0);
            assert_eq!(
                std::fs::read(directory.path().join("ax")).unwrap(),
                ax_before
            );
            assert!(node.admit(later.clone(), true).is_err());
            assert!(node.drive().is_err());
            assert!(node.produce().is_err());
            assert!(node.poll_pipeline().is_err());
            assert!(node.receive_batch(vec![]).is_err());
            assert!(node.persist(&[]).is_err());
            assert!(node.flush_outbound().is_err());
            assert!(node.flush_streaming().is_err());
            if mode == 1 {
                let wire = node
                    .blockstore
                    .get_experimental_pq_checkpoint()
                    .unwrap()
                    .unwrap();
                assert_eq!(wire, node.machine.recovery_journal().encode().unwrap());
                let validators = std::iter::once(PqValidator {
                    id: node.local.to_bytes(),
                    stake: 1,
                    key: node.signer.public_key(),
                })
                .chain(signers.iter().map(|signer| PqValidator {
                    id: signer.public_key().epoch().validator,
                    stake: 1,
                    key: signer.public_key(),
                }))
                .collect();
                let restored = Quantumglow::restore(
                    node.machine.config().clone(),
                    node.local.to_bytes(),
                    validators,
                    agave_pq_crypto::quantumglow::RecoveryJournal::decode(&wire).unwrap(),
                )
                .unwrap();
                assert_eq!(restored.recovery_journal().encode().unwrap(), wire);
            } else {
                assert_eq!(
                    node.blockstore.get_experimental_pq_checkpoint().unwrap(),
                    previous_disk
                );
            }
        }
    }

    #[test]
    fn native_pipeline_journal_reentry_is_rejected_and_shutdown_resolves_real_append() {
        let (directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let wire = bincode::serialize(&pipeline_transfer(&node, &root, 7)).unwrap();
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        let mut pipeline = PqPipeline::new().unwrap();
        pipeline.journal_barrier = Some(JournalBarrier {
            sequence: 1,
            header: [0; 53],
            previous_records: 0,
            target_records: 1,
            body_bytes: 9,
        });
        node.pipeline = Some(pipeline);
        assert!(node.admit(wire, true).is_err());
        assert!(node.poll_pipeline().is_err());
        assert!(node.drive().is_err());
        assert!(node.produce().is_err());
        assert!(node.compact().is_err());
        assert!(node.dispatch_finalization().is_err());
        assert!(node.receive_batch(vec![]).is_err());
        assert!(node.service_journal_wait().is_ok());
        assert!(node.persist(&[]).is_err());
        assert_eq!(node.machine.recovery_record_count(), 0);
        assert!(node.mempool.is_empty());
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        // A distinct real append is already in flight when shutdown arrives.
        // Shutdown cannot abandon it or publish an ambiguous ACK as success.
        node.pipeline = Some(PqPipeline::new().unwrap());
        let actions = node.machine.tick(0).unwrap();
        let expected = node.machine.recovery_journal().encode().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().journal_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        let exit = node.exit.clone();
        let storage = node.blockstore.clone();
        let handle = thread::spawn(move || {
            let result = node.persist(&actions);
            (node, result)
        });
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        exit.store(true, Ordering::Release);
        assert!(!handle.is_finished());
        assert!(storage.get_experimental_pq_checkpoint().unwrap().is_none());
        release.send(()).unwrap();
        let (node, result) = handle.join().unwrap();
        assert!(fatal_receive_error(&result.unwrap_err()));
        assert!(node.pipeline.as_ref().unwrap().journal_failed);
        assert!(!node.pipeline.as_ref().unwrap().journal.busy);
        assert_eq!(node.durable_journal_records, 0);
        assert_eq!(
            storage.get_experimental_pq_checkpoint().unwrap().unwrap(),
            expected
        );
        assert_eq!(node.machine.recovery_journal().encode().unwrap(), expected);
        assert!(node.pending.is_empty());
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        drop(node); // Joins the resolved append worker; no queued second append.
    }

    #[test]
    fn native_pipeline_journal_outer_run_cleans_only_successful_resolved_shutdown() {
        for mode in 0..5 {
            let (directory, mut node) = repair_fixture();
            let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
            if mode == 3 {
                let mut header = node.machine.recovery_update_since(0).unwrap().header;
                header[49..53].copy_from_slice(&1u32.to_le_bytes());
                node.blockstore
                    .append_experimental_pq_checkpoint(&header, 0, &[0; 9], &[])
                    .unwrap();
            }
            let previous = node.blockstore.get_experimental_pq_checkpoint().unwrap();
            let mut pipeline = PqPipeline::new().unwrap();
            let (entered, entering) = bounded(1);
            let (release, released) = bounded(1);
            pipeline.journal_gate = Some(pipeline::ArchiveGate {
                entered,
                release: released,
                fail: mode == 1,
            });
            pipeline.journal_bad_ack = mode == 2;
            let (service_error, saw_service_error) = bounded(1);
            if mode == 4 {
                pipeline.producer_reservation = Some(Production {
                    first: 1,
                    next: 1,
                    parent: node.adopted_anchor().unwrap().hash,
                    due: 0,
                });
                pipeline.journal_service_error = Some(service_error);
            }
            let stream_sender = pipeline.stream_sender.clone();
            node.pipeline = Some(pipeline);
            // Exercise the actual run/receive/tick/persist outer boundary with
            // a real transport, without external peers or a mocked run result.
            node.transport = Some(
                PqQuicTransport::spawn(
                    PqQuicConfig {
                        chain: node.chain,
                        identity: node.local,
                        signer: node.leader.clone(),
                        registry: BTreeMap::from([(node.local, node.leader.public_key())]),
                        peers: BTreeMap::new(),
                        listen: "127.0.0.1:0".parse().unwrap(),
                    },
                    node.exit.clone(),
                )
                .unwrap(),
            );
            let exit = node.exit.clone();
            let storage = node.blockstore.clone();
            let handle = thread::spawn(move || {
                let result = node.run();
                (node, result)
            });
            entering.recv_timeout(Duration::from_secs(5)).unwrap();
            if mode == 4 {
                let shared_frame = Arc::new(vec![1]);
                stream_sender
                    .try_send(pipeline::StreamBatch {
                        slot: 1,
                        candidate: [0xeb; 48],
                        frames: vec![shared_frame; pipeline::MAX_STREAM_FRAMES + 1],
                    })
                    .unwrap();
                assert!(
                    saw_service_error
                        .recv_timeout(Duration::from_secs(3))
                        .unwrap()
                        .contains("PQ streaming shred bound")
                );
            }
            exit.store(true, Ordering::Release);
            assert!(!handle.is_finished());
            assert_eq!(storage.get_experimental_pq_checkpoint().unwrap(), previous);
            release.send(()).unwrap();
            let (node, result) = handle.join().unwrap();
            if mode == 0 {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert!(fatal_receive_error(&error));
                assert!(error.downcast_ref::<JournalShutdownResolved>().is_none());
                let text = format!("{error:#}");
                match mode {
                    1 => assert!(text.contains("test journal append failure")),
                    2 => assert!(text.contains("PQ journal ACK context differs")),
                    3 => assert!(
                        error
                            .downcast_ref::<solana_ledger::blockstore::error::BlockstoreError>()
                            .is_some()
                    ),
                    _ => assert!(text.contains("PQ streaming shred bound")),
                }
            }
            assert!(node.pipeline.as_ref().unwrap().journal_failed);
            assert!(!node.pipeline.as_ref().unwrap().journal.busy);
            assert_eq!(node.durable_journal_records, 0);
            assert_eq!(node.machine.recovery_record_count(), 1);
            assert!(node.pending.is_empty());
            assert!(node.mempool.is_empty());
            assert_eq!(node.submitted, 0);
            assert_eq!(node.finalized_transactions, 0);
            assert_eq!(node.bank_forks.read().unwrap().root(), 0);
            assert_eq!(
                std::fs::read(directory.path().join("ax")).unwrap(),
                ax_before
            );
            let actual = storage.get_experimental_pq_checkpoint().unwrap();
            if matches!(mode, 0 | 2 | 4) {
                let wire = actual.unwrap();
                assert_eq!(wire, node.machine.recovery_journal().encode().unwrap());
                assert_eq!(
                    agave_pq_crypto::quantumglow::RecoveryJournal::decode(&wire)
                        .unwrap()
                        .encode()
                        .unwrap(),
                    wire
                );
            } else {
                assert_eq!(actual, previous);
            }
            drop(node); // Existing transport and resolved append threads join.
        }
    }

    fn weak_repair_certificate(node: &mut PqNode, witness: &BlockWitness) {
        let evidence = node
            .signer
            .sign(ConsensusMessage {
                epoch: 7,
                slot: witness.marker.slot,
                kind: MessageKind::NotarApproval,
                block: Some(witness.marker.block_commitment),
            })
            .unwrap();
        let actions = node.machine.receive(evidence, node.now()).unwrap();
        node.pending.extend(actions);
        assert!(node.has_repair_certificate(witness.marker.slot, witness.marker.block_commitment));
    }

    fn receive_witness(node: &mut PqNode, peer: Pubkey, witness: &BlockWitness) {
        for shred in &witness.shreds {
            let mut frame = vec![1];
            frame.extend(shred.encode().unwrap());
            node.receive(peer, &frame).unwrap();
        }
        let mut frame = vec![2];
        frame.extend(witness.marker.encode());
        node.receive(peer, &frame).unwrap();
    }

    fn pump_pipeline_until(node: &mut PqNode, mut finished: impl FnMut(&PqNode) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !finished(node) {
            assert!(
                Instant::now() < deadline,
                "native PQ pipeline did not progress"
            );
            node.poll_pipeline().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
    }

    // Only tests intentionally advancing ordinary authorized production use
    // this real run-loop path. Compute-only/no-signing gates keep poll-only.
    fn pump_pipeline_and_dispatch_until(
        node: &mut PqNode,
        mut finished: impl FnMut(&PqNode) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !finished(node) {
            assert!(
                Instant::now() < deadline,
                "native PQ authorized producer did not progress"
            );
            node.poll_and_dispatch().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn pipeline_transfer(node: &PqNode, root: &Bank, amount: u64) -> VersionedTransaction {
        sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[node.local]),
                    system_instruction::transfer(
                        &node.local,
                        &Pubkey::new_from_array([0xa8; 32]),
                        amount,
                    ),
                ],
                Some(&node.local),
                &root.last_blockhash(),
            )),
            &root.pq_config().unwrap().unwrap(),
            &[&node.leader],
        )
        .unwrap()
    }

    fn pipeline_lock_limit_transfer(node: &PqNode, root: &Bank) -> VersionedTransaction {
        let mut instruction =
            system_instruction::transfer(&node.local, &Pubkey::new_from_array([0xa8; 32]), 9);
        instruction.accounts.extend(
            (0..140).map(|_| {
                solana_instruction::AccountMeta::new_readonly(Pubkey::new_unique(), false)
            }),
        );
        sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[authenticate_instruction(&[node.local]), instruction],
                Some(&node.local),
                &root.last_blockhash(),
            )),
            &root.pq_config().unwrap().unwrap(),
            &[&node.leader],
        )
        .unwrap()
    }

    #[test]
    fn native_pipeline_frame4_authentication_runs_concurrently_and_preserves_fifo() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let wires = [31, 32]
            .map(|amount| bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap());
        let probe = Arc::new(IngressAuthenticationProbe::default());
        assert!(
            ingress_authentication_probes()
                .lock()
                .unwrap()
                .insert(Arc::as_ptr(&root) as usize, probe.clone())
                .is_none()
        );
        let frames = wires
            .iter()
            .map(|wire| {
                let mut frame = vec![4];
                frame.extend(wire);
                (node.local, frame)
            })
            .collect();
        node.receive_batch(frames).unwrap();
        // Repeated exact wires already in the pool must not add AUTH work.
        let duplicates = wires
            .iter()
            .map(|wire| {
                let mut frame = vec![4];
                frame.extend(wire);
                (node.local, frame)
            })
            .collect();
        node.receive_batch(duplicates).unwrap();
        ingress_authentication_probes()
            .lock()
            .unwrap()
            .remove(&(Arc::as_ptr(&root) as usize));
        let state = *probe.state.lock().unwrap();
        assert_eq!(state.0, 0);
        assert_eq!(state.2, 2);
        assert!(
            state.1 >= 2 && !state.3,
            "actual Falcon ingress calls must overlap; serial authentication timed out: {state:?}"
        );
        let expected = wires
            .iter()
            .map(|wire| hash_commitment(b"agave-pq-transaction-wire-v1", &[wire]))
            .collect::<Vec<_>>();
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            expected
        );
        assert_eq!(node.mempool.len(), 2);
        assert_eq!(node.submitted, 2);
        assert_eq!(node.invalid_packets, 0);
        assert!(node.gossip_log.is_empty());
        assert_eq!(root.get_balance(&node.local), 1_000_000_000);
        assert!(node.proposed.is_empty() && node.pending.is_empty());
    }

    #[test]
    fn native_pipeline_prepared_ingress_rechecks_success_and_failure_after_real_auth_rotation() {
        let (_directory, mut node, _signers) = repair_fixture_with_signers_and_fee(32, Some(5000));
        let original = node.bank_forks.read().unwrap().root_bank();
        let replacement = FalconKeypair::generate();
        let old_wire = bincode::serialize(&pipeline_transfer(&node, &original, 141)).unwrap();
        let new_transaction = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[node.local]),
                    system_instruction::transfer(
                        &node.local,
                        &Pubkey::new_from_array([0xa8; 32]),
                        142,
                    ),
                ],
                Some(&node.local),
                &original.last_blockhash(),
            )),
            &original.pq_config().unwrap().unwrap(),
            &[&replacement],
        )
        .unwrap();
        let new_wire = bincode::serialize(&new_transaction).unwrap();
        let old_prepared = prepare_ingress(original.clone(), &node.chain, &old_wire);
        let new_prepared = prepare_ingress(original.clone(), &node.chain, &new_wire);
        assert!(old_prepared.outcome.is_ok());
        assert!(new_prepared.outcome.is_err());
        let child =
            Arc::new(Bank::new_isolated_pq_child(original.clone(), *original.leader(), 1).unwrap());
        let nonce = [0x39; 32];
        let upload = pq::upload_address(&node.local, &nonce);
        let bytes = replacement.public_key().as_bytes().to_vec();
        let mut executed_wires = Vec::new();
        for instruction in [
            pq::create_upload_instruction(&node.local, &nonce, bytes.len() as u32),
            pq::write_upload_instruction(&node.local, &upload, 0, &bytes),
            pq::seal_upload_instruction(&node.local, &upload),
            pq::rotate_instruction(&node.local, &upload, 1),
        ] {
            let transaction = sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[authenticate_instruction(&[node.local]), instruction],
                    Some(&node.local),
                    &child.last_blockhash(),
                )),
                &child.pq_config().unwrap().unwrap(),
                &[&node.leader],
            )
            .unwrap();
            executed_wires.push(bincode::serialize(&transaction).unwrap());
            assert!(
                child
                    .process_transaction_with_metadata(transaction)
                    .unwrap()
                    .status
                    .is_ok()
            );
        }
        complete_bank(
            &child,
            &node.chain,
            &[0x83; 48],
            &encode_block(&executed_wires).unwrap(),
        );
        let before_state = bank_state(&original);
        node.bank_forks
            .write()
            .unwrap()
            .promote_pq_candidate(child.clone(), before_state)
            .unwrap();
        assert!(Arc::ptr_eq(
            &node.bank_forks.read().unwrap().root_bank(),
            &child
        ));
        assert!(node.admit_prepared(old_wire, old_prepared).is_err());
        assert!(node.mempool.is_empty());
        node.admit_prepared(new_wire.clone(), new_prepared).unwrap();
        let id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&new_wire]);
        assert!(node.mempool.contains_key(&id));
        assert_eq!(node.submitted, 1);
        assert_eq!(original.pq_state_commitment(), before_state);
        assert_eq!(
            child.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            1_000_000
        );
        // AUTH must still be enforced by authoritative native execution on
        // the live child, despite mathematical cache hits during preparation.
        let execution_child =
            Bank::new_isolated_pq_child(child.clone(), *child.leader(), 2).unwrap();
        let committed = execution_child
            .process_transaction_with_metadata(new_transaction)
            .unwrap();
        assert!(committed.status.is_ok());
        assert_eq!(committed.fee_details.total_fee(), 5000);
        assert_eq!(
            execution_child.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            1_000_142
        );
    }

    #[test]
    fn native_pipeline_prepared_ingress_binds_full_wire_and_orders_errors_under_pressure() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let wires = [151, 152, 153]
            .map(|amount| bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap());
        let prepared = prepare_ingress(root.clone(), &node.chain, &wires[0]);
        let error = node.admit_prepared(wires[1].clone(), prepared).unwrap_err();
        assert!(fatal_receive_error(&error));
        assert!(node.mempool.is_empty() && node.gossip_log.is_empty());
        node.mempool_test_limits = Some((2, MAX_MEMPOOL_BYTES));
        let mut forged = decode_transaction(&wires[1]).unwrap();
        forged.signatures[0] = decode_transaction(&wires[0]).unwrap().signatures[0];
        let raws = [
            wires[0].clone(),
            bincode::serialize(&forged).unwrap(),
            wires[1].clone(),
            wires[0].clone(),
            wires[2].clone(),
        ];
        let frames = raws
            .into_iter()
            .map(|raw| {
                let mut frame = vec![4];
                frame.extend(raw);
                (node.local, frame)
            })
            .collect();
        node.receive_batch(frames).unwrap();
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            wires[..2]
                .iter()
                .map(|wire| hash_commitment(b"agave-pq-transaction-wire-v1", &[wire]))
                .collect::<Vec<_>>()
        );
        assert_eq!(node.submitted, 2);
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.peer_ingress_full_events, 1);
        assert_eq!(node.pending_local_ingress, None);
        assert!(node.gossip_log.is_empty());
        let mut oversized = vec![4];
        oversized.resize(MAX_TRANSACTION_BYTES + 2, 0);
        node.receive_batch(vec![(node.local, oversized)]).unwrap();
        assert_eq!(node.invalid_packets, 2);
        let too_many = vec![(node.local, vec![4]); 257];
        assert!(
            node.receive_batch(too_many)
                .unwrap_err()
                .downcast_ref::<InternalPqError>()
                .is_some()
        );
        assert_eq!(node.invalid_packets, 2);
        assert_eq!(node.submitted, 2);
        assert_eq!(root.get_balance(&node.local), 1_000_000_000);
    }

    #[test]
    fn native_pipeline_rpc_queued_ingress_survives_count_and_byte_pressure_and_certified_commit() {
        for byte_limited in [false, true] {
            let (_directory, mut node) = repair_fixture();
            node.machine = Quantumglow::new(
                node.machine.config().clone(),
                node.local.to_bytes(),
                vec![PqValidator {
                    id: node.local.to_bytes(),
                    stake: 1,
                    key: node.signer.public_key(),
                }],
            )
            .unwrap();
            let original = node.bank_forks.read().unwrap().root_bank();
            let transactions = [1, 2, 3].map(|amount| pipeline_transfer(&node, &original, amount));
            let wires = transactions
                .iter()
                .map(|tx| bincode::serialize(tx).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(wires[0].len(), wires[1].len());
            node.mempool_test_limits = Some(if byte_limited {
                (MAX_MEMPOOL_TRANSACTIONS, wires[0].len())
            } else {
                (1, MAX_MEMPOOL_BYTES)
            });
            node.admit(wires[0].clone(), true).unwrap();
            // This is the same public ingress and 4096-item bounded channel
            // attached to production sendTransaction; its ACK means queued.
            let (sender, receiver) = bounded(4096);
            let rpc_ingress = solana_rpc::rpc::PqRpcIngress {
                sender,
                status: node.status.clone(),
            };
            assert_eq!(rpc_ingress.sender.capacity(), Some(4096));
            node.ingress = receiver;
            for wire in [&wires[1], &wires[2], &wires[1]] {
                original
                    .verify_pq_transaction_for_ingress(&decode_transaction(wire).unwrap())
                    .unwrap();
                rpc_ingress.sender.try_send(wire.clone()).unwrap();
            }
            let initial_order = node.mempool_order.iter().copied().collect::<Vec<_>>();
            let initial_gossip = node.gossip_log.clone();
            for attempts in 1..=3 {
                assert_eq!(node.poll_local_ingress(128).unwrap(), 1);
                assert_eq!(node.pending_local_ingress.as_ref(), Some(&wires[1]));
                assert_eq!(node.ingress.len(), 2);
                assert_eq!(node.local_ingress_full_events, attempts);
                assert_eq!(node.local_ingress_retry_attempts, attempts - 1);
                assert_eq!(node.invalid_packets, 0);
                assert_eq!(node.submitted, 1);
                assert_eq!(
                    node.mempool_order.iter().copied().collect::<Vec<_>>(),
                    initial_order
                );
                assert_eq!(node.gossip_log, initial_gossip);
                assert_eq!(node.mempool.bytes, wires[0].len());
            }
            // Auth still runs before a Full result. A forged wire cannot hold
            // the local front or enter any index under capacity pressure.
            let mut forged = transactions[1].clone();
            forged.signatures[0] = transactions[0].signatures[0];
            let forged_error = node
                .admit(bincode::serialize(&forged).unwrap(), true)
                .unwrap_err();
            assert!(forged_error.downcast_ref::<MempoolFull>().is_none());
            assert_eq!(node.mempool.len(), 1);

            node.pipeline = Some(PqPipeline::new().unwrap());
            let peer = *node.outbound.keys().next().unwrap();
            let recipient = Pubkey::new_from_array([0xa8; 32]);
            let original_balance = original.get_balance(&recipient);
            for (index, amount) in [1, 2, 3].into_iter().enumerate() {
                let anchor = node.adopted_anchor().unwrap();
                let witness = pipeline_peer_witness(
                    &node,
                    &original,
                    (index + 1) as u64,
                    anchor.hash,
                    amount,
                );
                // Genuine network reconstruction, native candidate execution,
                // signed certificate and ordered archive can progress while
                // local ingress is held. No test removes or fakes pool rows.
                receive_witness(&mut node, peer, &witness);
                let deadline = Instant::now() + Duration::from_secs(10);
                while node.finalized_transactions != (index + 1) as u64 {
                    assert!(
                        Instant::now() < deadline,
                        "certified commit stalled under ingress pressure"
                    );
                    node.poll_pipeline().unwrap();
                    node.drive().unwrap();
                    thread::sleep(Duration::from_millis(1));
                }
                assert!(node.mempool.is_empty());
                assert!(node.mempool_order.by_sequence.is_empty());
                assert!(node.mempool_order.by_id.is_empty());
                assert!(node.gossip_log.is_empty());
                node.poll_local_ingress(128).unwrap();
                assert_eq!(node.invalid_packets, 0);
                if index == 0 {
                    assert_eq!(node.mempool.len(), 1);
                    assert_eq!(node.pending_local_ingress.as_ref(), Some(&wires[2]));
                    assert_eq!(node.ingress.len(), 1);
                } else if index == 1 {
                    // The duplicate second wire was already certified: the
                    // exact root replay identity retires it without admission.
                    assert_eq!(node.mempool.len(), 1);
                    assert!(node.pending_local_ingress.is_none());
                    assert!(node.ingress.is_empty());
                    assert_eq!(node.submitted, 3);
                } else {
                    assert!(node.mempool.is_empty());
                    assert!(node.pending_local_ingress.is_none());
                    assert!(node.ingress.is_empty());
                }
            }
            let final_bank = node.bank_forks.read().unwrap().root_bank();
            assert_eq!(final_bank.get_balance(&recipient), original_balance + 6);
            assert_eq!(
                final_bank.transaction_count(),
                original.transaction_count() + 3
            );
            assert!(
                transactions
                    .iter()
                    .all(|tx| final_bank.pq_transaction_processed(tx).unwrap())
            );
            node.update_status();
            assert_eq!(node.status.read().unwrap()["pending_local_ingress"], 0);
            assert_eq!(node.status.read().unwrap()["local_ingress_queued"], 0);
            assert!(!node.exit.load(Ordering::Acquire));
        }
    }

    #[test]
    fn native_pipeline_ingress_sequence_failure_is_fatal_without_following_admission() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let first = bincode::serialize(&pipeline_transfer(&node, &root, 1)).unwrap();
        let following = bincode::serialize(&pipeline_transfer(&node, &root, 2)).unwrap();
        let (sender, receiver) = bounded(4096);
        node.ingress = receiver;
        sender.try_send(first).unwrap();
        sender.try_send(following.clone()).unwrap();
        node.mempool_order.next_sequence = u64::MAX;
        let error = node.poll_local_ingress(128).unwrap_err();
        assert!(error.downcast_ref::<InternalPqError>().is_some());
        assert!(fatal_receive_error(&error));
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(node.submitted, 0);
        assert!(node.mempool.is_empty());
        assert!(node.mempool_order.by_id.is_empty());
        assert!(node.gossip_log.is_empty());
        assert_eq!(node.ingress.len(), 1);
        assert_eq!(node.ingress.try_recv().unwrap(), following);
        assert!(node.pending_local_ingress.is_none());
    }

    #[test]
    fn native_pipeline_peer_pool_pressure_is_counted_without_hiding_invalid_authentication() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let first = pipeline_transfer(&node, &root, 1);
        let second = pipeline_transfer(&node, &root, 2);
        node.mempool_test_limits = Some((1, MAX_MEMPOOL_BYTES));
        node.admit(bincode::serialize(&first).unwrap(), true)
            .unwrap();
        let original_gossip = node.gossip_log.clone();
        let original_order = node.mempool_order.iter().copied().collect::<Vec<_>>();
        let peer = *node.outbound.keys().next().unwrap();
        let mut pressure = vec![4];
        pressure.extend(bincode::serialize(&second).unwrap());
        let mut forged = second;
        forged.signatures[0] = first.signatures[0];
        let mut invalid = vec![4];
        invalid.extend(bincode::serialize(&forged).unwrap());
        node.receive_batch(vec![(peer, pressure), (peer, invalid)])
            .unwrap();
        assert_eq!(node.peer_ingress_full_events, 1);
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.submitted, 1);
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.gossip_log, original_gossip);
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            original_order
        );
        assert!(node.pending_local_ingress.is_none());
        assert_eq!(node.local_ingress_full_events, 0);
        assert_eq!(node.local_ingress_retry_attempts, 0);
        assert_eq!(node.finalized_transactions, 0);
    }

    #[test]
    fn native_pipeline_rejected_wire_clears_indexes_and_readmits_at_fresh_sequence() {
        let (_directory, mut node) = repair_fixture();
        let anchor = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        // This genuine Falcon message exceeds native account lock limits.
        // Unlike an unknown recent hash, this remains an ordinary rejection.
        let transaction = pipeline_lock_limit_transfer(&node, &root);
        let raw = bincode::serialize(&transaction).unwrap();
        let id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&raw]);
        node.admit(raw.clone(), true).unwrap();
        let first_sequence = node.mempool_order.by_id[&id];
        let peer = *node.outbound.keys().next().unwrap();
        let mut sent = Vec::new();
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &node.gossip_log,
                &node.mempool,
                |frame| {
                    if frame[0] == 4 {
                        sent.push(frame[1..].to_vec());
                    }
                    true
                },
            )
            .unwrap();
        assert_eq!(sent, vec![raw.clone()]);
        assert_eq!(node.outbound[&peer].next_transaction, first_sequence + 1);
        let balance = root.get_balance(&node.local);
        let actions = node.machine.tick(node.now()).unwrap();
        node.persist(&actions).unwrap();
        node.pending.extend(actions);
        node.drive().unwrap();
        assert_eq!(node.production.unwrap().parent, anchor.hash);
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&1));
        assert!(!node.mempool.contains_key(&id));
        assert!(!node.mempool_order.by_id.contains_key(&id));
        assert!(!node.mempool_order.by_sequence.contains_key(&first_sequence));
        assert!(!node.gossip_log.contains_key(&first_sequence));
        assert_eq!(node.mempool.bytes, 0);
        assert_eq!(root.get_balance(&node.local), balance);
        assert_eq!(node.bank_forks.read().unwrap().root(), root.slot());
        node.admit(raw.clone(), true).unwrap();
        let fresh_sequence = node.mempool_order.by_id[&id];
        assert!(fresh_sequence > first_sequence);
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            vec![id]
        );
        assert_eq!(node.gossip_log.get(&fresh_sequence), Some(&id));
        sent.clear();
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &node.gossip_log,
                &node.mempool,
                |frame| {
                    if frame[0] == 4 {
                        sent.push(frame[1..].to_vec());
                    }
                    true
                },
            )
            .unwrap();
        assert_eq!(sent, vec![raw]);
        assert_eq!(node.outbound[&peer].next_transaction, fresh_sequence + 1);
        assert_eq!(node.mempool.len(), 1);
    }

    #[test]
    fn native_pipeline_finishes_multibatch_production_without_coordinator_stream_drain() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        for amount in 1..=512 {
            let transaction = pipeline_transfer(&node, &root, amount);
            node.admit(bincode::serialize(&transaction).unwrap(), false)
                .unwrap();
        }
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: parent.hash,
            due: node.now(),
        });
        node.produce().unwrap();
        // Deliberately never poll the coordinator or drain its stream queue.
        // The old two-event queue prevented this actual native result from
        // ever becoming ready once a proposal needed more than two batches.
        let deadline = Instant::now() + Duration::from_secs(30);
        let output = loop {
            if let Some(output) = node.pipeline.as_mut().unwrap().producer.poll().unwrap() {
                break output;
            }
            assert!(
                Instant::now() < deadline,
                "producer depended on stream drain"
            );
            thread::sleep(Duration::from_millis(1));
        };
        let pipeline = node.pipeline.as_ref().unwrap();
        let receiver = pipeline.stream_receiver.as_ref().unwrap();
        assert!(receiver.len() > 2);
        assert!(receiver.len() <= pipeline.stream_sender.capacity().unwrap());
        assert_eq!(output.archive.len(), 512);
        assert_eq!(
            output.bank.transaction_count(),
            root.transaction_count() + 512
        );
        assert!(output.bank.is_frozen());
        assert_eq!(node.bank_forks.read().unwrap().root(), root.slot());
        assert!(
            node.blockstore
                .get_experimental_pq_block(1, [0; 48])
                .unwrap()
                .is_none()
        );
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
                .unwrap()
                .payload,
            output.verified.payload()
        );
    }

    fn pipeline_peer_witness(
        node: &PqNode,
        root: &Bank,
        slot: u64,
        parent: Commitment,
        amount: u64,
    ) -> BlockWitness {
        let payload =
            encode_block(&[bincode::serialize(&pipeline_transfer(node, root, amount)).unwrap()])
                .unwrap();
        let candidate = hash_commitment(
            b"agave-pq-candidate-v1",
            &[&node.chain, &slot.to_le_bytes(), &parent, &payload],
        );
        let batch = SignedBatch::build(
            &node.chain,
            &node.leader,
            BatchContext {
                leader_epoch: node.public.epoch,
                slot,
                candidate,
                parent,
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            64,
            64,
        )
        .unwrap();
        let marker = FinalMarker::build(
            &node.chain,
            &node.leader,
            std::slice::from_ref(&batch),
            &payload,
        )
        .unwrap();
        BlockWitness {
            marker,
            shreds: batch.shreds[..64].to_vec(),
        }
    }

    fn early_parent_body_fixture(
        authorize_before: bool,
    ) -> (
        tempfile::TempDir,
        PqNode,
        Vec<DurableConsensusSigner>,
        Arc<Bank>,
        BlockWitness,
        Sender<()>,
    ) {
        let (directory, mut node, mut signers) =
            repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let parent = pipeline_peer_witness(&node, &root, 4, node.adopted_anchor().unwrap().hash, 4);
        node.public.proposal_max_transactions = Some(2);
        for amount in [7, u64::MAX] {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        let mut pipeline = PqPipeline::new().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.candidate_body_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        node.pipeline = Some(pipeline);
        if authorize_before {
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarVote,
                Some(parent.marker.block_commitment),
            );
        }
        let peer = *node.outbound.keys().next().unwrap();
        receive_witness(&mut node, peer, &parent);
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().candidate_body.busy
        });
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        if !authorize_before {
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarVote,
                Some(parent.marker.block_commitment),
            );
        }
        (directory, node, signers, root, parent, release)
    }

    #[test]
    fn native_pipeline_early_unsigned_finishes_before_parent_body_wal_with_early_authorization() {
        for authorize_before in [false, true] {
            let (directory, mut node, _signers, root, parent, release) =
                early_parent_body_fixture(authorize_before);
            let hash = parent.marker.block_commitment;
            let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
            let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
            pump_pipeline_until(&mut node, |node| {
                node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
            });
            let prepared = node
                .pipeline
                .as_ref()
                .unwrap()
                .unsigned_ready
                .as_ref()
                .unwrap();
            let prepared_bank = prepared.bank.clone();
            let serial =
                Bank::new_isolated_pq_child(prepared.parent.clone(), *prepared_bank.leader(), 5)
                    .unwrap();
            let records = decode_block(prepared.payload(), 2)
                .unwrap()
                .into_iter()
                .map(|tx| process_with_status(&serial, tx).unwrap())
                .collect::<Vec<_>>();
            complete_bank(&serial, &node.chain, &hash, prepared.payload());
            assert_eq!(bank_state(&serial), bank_state(&prepared_bank));
            assert_eq!(records.as_slice(), prepared.records());
            assert!(records[0].1.status.is_ok() && records[1].1.status.is_err());
            assert!(records.iter().all(|record| record.1.fee == 5000));
            assert!(node.machine.ready_parents(5).contains(&hash));
            assert!(node.machine.payload(&hash).is_none());
            assert!(!node.runtime.lock().unwrap().banks.contains_key(&hash));
            assert!(
                node.blockstore
                    .get_experimental_pq_block(4, hash)
                    .unwrap()
                    .is_none()
            );
            node.produce().unwrap();
            assert!(!node.pipeline.as_ref().unwrap().producer.busy);
            assert!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .is_none()
            );
            assert!(
                node.pipeline
                    .as_ref()
                    .unwrap()
                    .stream_receiver
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                std::fs::read(directory.path().join("ax")).unwrap(),
                ax_before
            );
            assert_eq!(
                node.mempool_order.iter().copied().collect::<Vec<_>>(),
                admitted
            );
            assert_eq!(node.bank_forks.read().unwrap().root(), root.slot());
            release.send(()).unwrap();
            pump_pipeline_until(&mut node, |node| node.machine.payload(&hash).is_some());
            node.produce().unwrap();
            pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
            let child = &node.proposed[&5];
            assert!(Arc::ptr_eq(
                &prepared_bank,
                &node.runtime.lock().unwrap().banks[&child.marker.block_commitment]
            ));
            assert_eq!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .unwrap()
                    .parent,
                hash
            );
        }
    }

    #[test]
    fn native_pipeline_early_private_replay_runs_ahead_of_parent_body_wal_and_respects_bounds() {
        let (directory, mut node, _signers) = repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let peer = *node.outbound.keys().next().unwrap();
        let mut parent_hash = node.adopted_anchor().unwrap().hash;
        let witnesses = (1..=5)
            .map(|slot| {
                let witness = pipeline_peer_witness(&node, &root, slot, parent_hash, slot + 20);
                parent_hash = witness.marker.block_commitment;
                witness
            })
            .collect::<Vec<_>>();
        let mut pipeline = PqPipeline::new().unwrap();
        pipeline.native_bank_capacity = 5;
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.candidate_body_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        node.pipeline = Some(pipeline);
        // Deliver the causal child FIRST. It must leave waiting_parents as
        // soon as the private parent exists, while that parent's WAL is held.
        receive_witness(&mut node, peer, &witnesses[1]);
        pump_pipeline_until(&mut node, |node| {
            node.waiting_parents
                .contains_key(&witnesses[1].marker.block_commitment)
        });
        receive_witness(&mut node, peer, &witnesses[0]);
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().candidate_body.busy
        });
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().pending_candidates.len() == 2
        });
        assert!(
            !node
                .waiting_parents
                .contains_key(&witnesses[1].marker.block_commitment)
        );
        for (index, witness) in witnesses.iter().enumerate().skip(2).take(2) {
            receive_witness(&mut node, peer, witness);
            pump_pipeline_until(&mut node, |node| {
                node.pipeline.as_ref().unwrap().pending_candidates.len() == index + 1
            });
        }
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        let state_before = bank_state(&root);
        let expected = node.pipeline.as_ref().unwrap().private_parents
            [&witnesses[3].marker.block_commitment]
            .bank
            .clone();
        assert_eq!(expected.transaction_count(), root.transaction_count() + 4);
        assert_eq!(node.pipeline.as_ref().unwrap().private_parents.len(), 4);
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 1);
        assert_eq!(node.machine.finalized_chain().last().unwrap().slot, 0);
        for witness in witnesses.iter().take(4) {
            assert!(
                node.machine
                    .payload(&witness.marker.block_commitment)
                    .is_none()
            );
            assert!(
                node.blockstore
                    .get_experimental_pq_block(witness.marker.slot, witness.marker.block_commitment)
                    .unwrap()
                    .is_none()
            );
        }
        receive_witness(&mut node, peer, &witnesses[4]);
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().reconstruction.busy
        });
        assert!(!node.pipeline.as_ref().unwrap().candidate.busy);
        assert_eq!(node.pipeline.as_ref().unwrap().pending_candidates.len(), 4);
        assert!(
            node.waiting_parents
                .contains_key(&witnesses[4].marker.block_commitment)
        );
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        assert_eq!(bank_state(&root), state_before);
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.machine
                .payload(&witnesses[3].marker.block_commitment)
                .is_some()
        });
        assert!(Arc::ptr_eq(
            &expected,
            &node.runtime.lock().unwrap().banks[&witnesses[3].marker.block_commitment]
        ));
        assert_eq!(
            bank_state(&expected),
            node.runtime.lock().unwrap().states[&witnesses[3].marker.block_commitment]
        );
        assert_eq!(node.finalized_transactions, 0);
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
    }

    #[test]
    fn native_pipeline_early_body_wal_failure_stops_after_private_work_without_signing() {
        let (directory, mut node, _signers, _root, parent, release) =
            early_parent_body_fixture(true);
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        node.blockstore
            .put_experimental_pq_block(
                4,
                parent.marker.block_commitment,
                b"actual immutable body conflict",
            )
            .unwrap();
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = loop {
            if let Err(error) = node.poll_and_dispatch() {
                break error;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        };
        assert!(
            error
                .downcast_ref::<solana_ledger::blockstore::error::BlockstoreError>()
                .is_some()
        );
        assert!(
            node.machine
                .payload(&parent.marker.block_commitment)
                .is_none()
        );
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .banks
                .contains_key(&parent.marker.block_commitment)
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        assert!(node.proposed.is_empty());
        assert!(node.streaming.is_empty());
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
    }

    #[test]
    fn native_pipeline_early_consensus_rejection_discards_private_descendants_and_unsigned_work() {
        let (directory, mut node, mut signers) =
            repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let peer = *node.outbound.keys().next().unwrap();
        node.pipeline = Some(PqPipeline::new().unwrap());
        for amount in 1..=5 {
            let witness = pipeline_peer_witness(&node, &root, 4, anchor.hash, amount);
            receive_witness(&mut node, peer, &witness);
            pump_pipeline_until(&mut node, |node| {
                node.machine
                    .payload(&witness.marker.block_commitment)
                    .is_some()
            });
        }
        node.public.proposal_max_transactions = Some(2);
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().candidate_body_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        node.pipeline.as_mut().unwrap().native_bank_capacity = 9;
        let rejected = pipeline_peer_witness(&node, &root, 4, anchor.hash, 6);
        let rejected_hash = rejected.marker.block_commitment;
        receive_witness(&mut node, peer, &rejected);
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().candidate_body.busy
        });
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        for amount in [17, u64::MAX] {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(rejected_hash),
        );
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
        let child = pipeline_peer_witness(&node, &root, 5, rejected_hash, 33);
        let child_hash = child.marker.block_commitment;
        receive_witness(&mut node, peer, &child);
        pump_pipeline_until(&mut node, |node| {
            let pipeline = node.pipeline.as_ref().unwrap();
            pipeline.pending_candidates.len() == 2 && pipeline.unsigned_ready.is_some()
        });
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .private_parents
                .contains_key(&child_hash)
        );
        assert!(node.machine.payload(&rejected_hash).is_none());
        assert!(node.machine.payload(&child_hash).is_none());
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| node.invalid_packets == 1);
        pump_pipeline_until(&mut node, |node| {
            let pipeline = node.pipeline.as_ref().unwrap();
            !pipeline.candidate_body.busy
                && !pipeline.candidate.busy
                && !pipeline.unsigned_preparation.busy
        });
        let pipeline = node.pipeline.as_ref().unwrap();
        assert!(pipeline.private_parents.is_empty());
        assert!(pipeline.pending_candidates.is_empty());
        assert!(pipeline.unsigned_ready.is_none());
        for witness in [&rejected, &child] {
            let hash = witness.marker.block_commitment;
            let index = (witness.marker.slot, witness.marker.candidate);
            assert!(node.machine.payload(&hash).is_none());
            assert!(!node.runtime.lock().unwrap().banks.contains_key(&hash));
            assert!(!node.completed_candidates.contains(&index));
            assert!(!node.candidate_timings.contains_key(&index));
        }
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 6);
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        assert!(node.proposed.is_empty());
        assert!(node.streaming.is_empty());
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        assert_eq!(node.invalid_packets, 1);
    }

    #[test]
    fn native_pipeline_early_terminal_and_all_stream_events_precede_ready_body_publisher() {
        let (_directory, mut node) = repair_fixture();
        node.public.proposal_max_transactions = Some(256);
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        for amount in 1..=256 {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                false,
            )
            .unwrap();
        }
        let mut pipeline = PqPipeline::new().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.gate_first_publication(entered, released).unwrap();
        node.pipeline = Some(pipeline);
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: anchor.hash,
            due: node.now(),
        });
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&1));
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        node.poll_pipeline().unwrap();
        let witness = node.proposed[&1].clone();
        let stream = node.streaming.remove(&witness.marker.candidate).unwrap();
        assert_eq!(stream.frames.len(), witness.shreds.len() + 1);
        let terminal = stream.frames.last().unwrap().clone();
        assert_eq!(terminal[0], 2);
        assert_eq!(
            FinalMarker::decode(&terminal[1..]).unwrap().encode(),
            witness.marker.encode()
        );
        let mut receiver = CandidateAssembler::new(
            node.chain,
            node.leader.public_key(),
            node.public.epoch,
            1,
            witness.marker.candidate,
            anchor.hash,
        );
        for frame in &stream.frames[..stream.frames.len() - 1] {
            assert_eq!(frame[0], 1);
            receiver
                .insert(AuthenticatedShred::decode(&frame[1..]).unwrap())
                .unwrap();
        }
        let received = receiver
            .finish_verified(FinalMarker::decode(&terminal[1..]).unwrap())
            .unwrap();
        let intent = node
            .blockstore
            .get_experimental_pq_proposal_intent(1)
            .unwrap()
            .unwrap();
        assert_eq!(received.payload(), intent.payload);
        assert!(
            node.blockstore
                .get_experimental_pq_block(1, [0; 48])
                .unwrap()
                .is_none()
        );
        assert!(
            node.machine
                .payload(&witness.marker.block_commitment)
                .is_none()
        );
        // Repartition the authentic DATA into the maximum supported event
        // count, preserving exact order/bytes. Have the REAL publisher result
        // ready before polling this full65-event queue;64-drain used to fail.
        let data = &stream.frames[..stream.frames.len() - 1];
        let sender = node.pipeline.as_ref().unwrap().stream_sender.clone();
        assert!(data.len() >= 64);
        for index in 0usize..64 {
            let start = index.checked_mul(data.len()).unwrap() / 64;
            let end = index
                .checked_add(1)
                .unwrap()
                .checked_mul(data.len())
                .unwrap()
                / 64;
            let frames = &data[start..end];
            assert!(!frames.is_empty());
            sender
                .send(pipeline::StreamBatch {
                    slot: 1,
                    candidate: witness.marker.candidate,
                    frames: frames.to_vec(),
                })
                .unwrap();
        }
        sender
            .send(pipeline::StreamBatch {
                slot: 1,
                candidate: witness.marker.candidate,
                frames: vec![terminal],
            })
            .unwrap();
        assert_eq!(sender.len(), pipeline::MAX_STREAM_EVENTS);
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !node.pipeline.as_ref().unwrap().publisher.result_ready() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        node.poll_pipeline().unwrap();
        assert!(
            node.machine
                .payload(&witness.marker.block_commitment)
                .is_some()
        );
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .stream_receiver
                .as_ref()
                .unwrap()
                .is_empty()
        );
        assert!(!node.streaming.contains_key(&witness.marker.candidate));
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
                .unwrap(),
            intent
        );
        assert_eq!(
            node.blockstore
                .get_experimental_pq_block(1, witness.marker.block_commitment)
                .unwrap()
                .unwrap(),
            witness.encode().unwrap()
        );
    }

    #[test]
    fn native_pipeline_early_private_metadata_retains_local_signed_ancestor_until_fenced() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        node.admit(
            bincode::serialize(&pipeline_transfer(&node, &root, 7)).unwrap(),
            false,
        )
        .unwrap();
        node.public.proposal_max_transactions = Some(1);
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: anchor.hash,
            due: node.now(),
        });
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed.get(&1).is_some_and(|witness| {
                node.machine
                    .payload(&witness.marker.block_commitment)
                    .is_some()
            })
        });
        node.production = None;
        let local = node.proposed[&1].clone();
        let local_bank = node.runtime.lock().unwrap().banks[&local.marker.block_commitment].clone();
        let peer = *node.outbound.keys().next().unwrap();
        let private =
            pipeline_peer_witness(&node, &local_bank, 4, local.marker.block_commitment, 13);
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().candidate_body_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        receive_witness(&mut node, peer, &private);
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().candidate_body.busy
        });
        entering.recv_timeout(Duration::from_secs(3)).unwrap();
        // Exercise the real metadata walker with a certified-frontier input.
        // This does not claim a synthetic BlockRef is a live certificate.
        let conflicting_frontier = BlockRef {
            slot: 1,
            hash: [0xfa; 48],
        };
        assert!(node.obsolete_local_ancestry(1, conflicting_frontier.hash, conflicting_frontier));
        let retained = node
            .local_proposal_ancestors_for_compaction(conflicting_frontier)
            .unwrap();
        assert!(retained.contains(&local.marker.block_commitment));
        assert!(node.obsolete_local_ancestry(
            5,
            private.marker.block_commitment,
            conflicting_frontier
        ));
        let original_wires = node.mempool_order.iter().copied().collect::<Vec<_>>();
        node.invalidate_private_parent(private.marker.block_commitment)
            .unwrap();
        assert!(
            !node
                .completed_candidates
                .contains(&(4, private.marker.candidate))
        );
        assert!(
            !node
                .candidate_timings
                .contains_key(&(4, private.marker.candidate))
        );
        assert!(
            !node
                .local_proposal_ancestors_for_compaction(conflicting_frontier)
                .unwrap()
                .contains(&local.marker.block_commitment)
        );
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            original_wires
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().candidate_body.busy
        });
        assert!(
            node.machine
                .payload(&private.marker.block_commitment)
                .is_none()
        );
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .banks
                .contains_key(&private.marker.block_commitment)
        );
        assert!(node.proposed.contains_key(&1));
    }

    fn unsigned_next_leader_fixture() -> (
        tempfile::TempDir,
        PqNode,
        Vec<DurableConsensusSigner>,
        Arc<Bank>,
        Commitment,
    ) {
        let (directory, mut node, signers) = repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let parent = pipeline_peer_witness(&node, &root, 4, anchor.hash, 4);
        let hash = parent.marker.block_commitment;
        node.pipeline = Some(PqPipeline::new().unwrap());
        let peer = *node.outbound.keys().next().unwrap();
        receive_witness(&mut node, peer, &parent);
        pump_pipeline_until(&mut node, |node| node.machine.payload(&hash).is_some());
        node.drive().unwrap();
        assert!(node.machine.ready_parents(5).is_empty());
        node.public.proposal_max_transactions = Some(2);
        for amount in [7, u64::MAX] {
            let wire = bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap();
            node.admit(wire, true).unwrap();
        }
        (directory, node, signers, root, hash)
    }

    fn prepared_reuse_fixture(
        amounts: &[u64],
    ) -> (
        tempfile::TempDir,
        PqNode,
        Vec<DurableConsensusSigner>,
        Arc<Bank>,
        Commitment,
    ) {
        let (directory, mut node, signers) = repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let parent = pipeline_peer_witness(&node, &root, 4, anchor.hash, 4);
        let hash = parent.marker.block_commitment;
        node.pipeline = Some(PqPipeline::new().unwrap());
        let peer = *node.outbound.keys().next().unwrap();
        receive_witness(&mut node, peer, &parent);
        pump_pipeline_until(&mut node, |node| node.machine.payload(&hash).is_some());
        node.drive().unwrap();
        node.public.proposal_max_transactions = Some(2);
        for amount in amounts {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, *amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        (directory, node, signers, root, hash)
    }

    fn prepare_reuse_test_result(
        node: &PqNode,
        parent_hash: Commitment,
    ) -> pipeline::PreparedProposal {
        let parent = node.runtime.lock().unwrap().banks[&parent_hash].clone();
        let production = Production {
            first: 5,
            next: 5,
            parent: parent_hash,
            due: node.now(),
        };
        let entries = node.proposal_entries(production, &parent).0;
        let (slot_leader, executor) = {
            let runtime = node.runtime.lock().unwrap();
            (runtime.leaders[4], runtime.executor.clone())
        };
        let job = PreparationJob {
            production,
            parent,
            rooted: node.bank_forks.read().unwrap().root_bank(),
            slot_leader,
            chain: node.chain,
            public: node.public.clone(),
            entries,
            executor,
            authentication_pool: node.authentication_pool.clone(),
            stop: node.pipeline.as_ref().unwrap().stop.clone(),
            fixed_payload: None,
            queued_at: Instant::now(),
            unsigned: true,
        };
        job.execute().unwrap()
    }

    #[test]
    fn native_pipeline_prepared_reuse_probe_preserves_blocked_replay_prefix_and_full_selection() {
        let (_directory, mut node, _signers, root, parent_hash) = prepared_reuse_fixture(&[]);
        let parent = node.runtime.lock().unwrap().banks[&parent_hash].clone();
        let blocked_hash = Hash::new_unique();
        for amount in 100..164 {
            let transaction = sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[
                        authenticate_instruction(&[node.local]),
                        system_instruction::transfer(
                            &node.local,
                            &Pubkey::new_from_array([0xa8; 32]),
                            amount,
                        ),
                    ],
                    Some(&node.local),
                    &blocked_hash,
                )),
                &root.pq_config().unwrap().unwrap(),
                &[&node.leader],
            )
            .unwrap();
            node.admit(bincode::serialize(&transaction).unwrap(), true)
                .unwrap();
        }
        // A genuinely executed parent transaction stays in this admitted
        // prefix; readiness must not invent a different replay filter.
        let replay = node.runtime.lock().unwrap().archives[&parent_hash][0]
            .0
            .clone();
        let replay_raw = bincode::serialize(&replay).unwrap();
        node.admit(replay_raw, true).unwrap();
        let fresh = [7, 8].map(|amount| pipeline_transfer(&node, &root, amount));
        for transaction in &fresh {
            node.admit(bincode::serialize(transaction).unwrap(), true)
                .unwrap();
        }
        let production = Production {
            first: 5,
            next: 5,
            parent: parent_hash,
            due: node.now(),
        };
        let (full, _, deferred) = node.proposal_entries(production, &parent);
        assert_eq!(full.len(), 3);
        assert_eq!(deferred, 64);
        assert!(full[0].1.processed(&parent).unwrap());
        let observation = node.prepared_reuse_readiness(production, &parent);
        assert!(observation.full_ready);
        assert_eq!(observation.fifo_rows_scanned, 66);
        assert_eq!(observation.eligible_entries_lower_bound, 2);
        assert_eq!(observation.deferred_blockhash_entries_scanned, 64);
        assert_eq!(observation.full_ready, node.proposal_full_ready(&full));
        for maximum in [1, 2, 8] {
            for bytes in [
                MAX_BLOCK_BYTES,
                MAX_TRANSACTION_BYTES + full[0].1.len() + 4,
                MAX_TRANSACTION_BYTES,
            ] {
                node.public.proposal_max_transactions = Some(maximum);
                node.public.proposal_target_block_bytes = Some(bytes);
                assert_eq!(
                    node.prepared_reuse_readiness(production, &parent)
                        .full_ready,
                    node.proposal_full_ready(&full),
                    "bounded probe must preserve the exact full-snapshot readiness boolean"
                );
            }
        }
        node.public.proposal_max_transactions = Some(2);
        node.public.proposal_target_block_bytes = None;
        let prepared = prepare_reuse_test_result(&node, parent_hash);
        assert_eq!(
            decode_block(prepared.payload(), 2).unwrap().as_slice(),
            fresh.as_slice()
        );
        let serial = Bank::new_isolated_pq_child(parent.clone(), *parent.leader(), 5).unwrap();
        let records = fresh
            .into_iter()
            .map(|transaction| process_with_status(&serial, transaction).unwrap())
            .collect::<Vec<_>>();
        complete_bank(&serial, &node.chain, &parent_hash, prepared.payload());
        assert_eq!(records.as_slice(), prepared.records());
        assert_eq!(bank_state(&serial), bank_state(&prepared.bank));
        assert!(
            records
                .iter()
                .all(|record| record.1.status.is_ok() && record.1.fee == 5000)
        );
        assert_eq!(
            node.mempool.len(),
            67,
            "metadata probing cannot prune any admitted wire"
        );
    }

    #[test]
    fn native_pipeline_prepared_reuse_avoids_full_snapshot_and_keeps_exact_native_result() {
        let (directory, mut node, mut signers, root, parent_hash) = unsigned_next_leader_fixture();
        node.prepare_next_leader().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let prepared = node
            .pipeline
            .as_ref()
            .unwrap()
            .unsigned_ready
            .as_ref()
            .unwrap();
        let prepared_bank = prepared.bank.clone();
        let payload = prepared.payload().to_vec();
        let records = prepared.records().to_vec();
        let prepared_parent = prepared.parent.clone();
        for amount in 10_000..11_024 {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        let last = *node.mempool_order.iter().last().unwrap();
        let tail = node.mempool.get(&last).unwrap().clone();
        assert_eq!(Arc::strong_count(&tail), 2);
        let production = Production {
            first: 5,
            next: 5,
            parent: parent_hash,
            due: node.now(),
        };
        let legacy = node.proposal_entries(production, &prepared_parent).0;
        assert_eq!(legacy.len(), 1026);
        assert_eq!(
            Arc::strong_count(&tail),
            3,
            "legacy unused snapshot retains the irrelevant tail"
        );
        drop(legacy);
        let observation = node.prepared_reuse_readiness(production, &prepared_parent);
        assert_eq!(observation.fifo_rows_scanned, 2);
        assert_eq!(Arc::strong_count(&tail), 2);
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().producer_intent_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        let ax_before = std::fs::read(directory.path().join("ax")).unwrap();
        take_proposal_snapshot_calls();
        node.produce().unwrap();
        assert_eq!(
            take_proposal_snapshot_calls(),
            0,
            "real prepared reuse must never call the full snapshot"
        );
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            Arc::strong_count(&tail),
            2,
            "the actual blocked producer owns no unused tail Arc"
        );
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        assert_eq!(node.mempool.len(), 1026);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            ax_before,
            "the blocked intent cannot advance the durable vote signer"
        );
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed.get(&5).is_some_and(|witness| {
                node.machine
                    .payload(&witness.marker.block_commitment)
                    .is_some()
            })
        });
        let hash = node.proposed[&5].marker.block_commitment;
        assert!(Arc::ptr_eq(
            &prepared_bank,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
        assert_eq!(
            node.runtime.lock().unwrap().archives[&hash].as_ref(),
            &records
        );
        let serial =
            Bank::new_isolated_pq_child(prepared_parent.clone(), *prepared_parent.leader(), 5)
                .unwrap();
        let serial_records = decode_block(&payload, 2)
            .unwrap()
            .into_iter()
            .map(|transaction| process_with_status(&serial, transaction).unwrap())
            .collect::<Vec<_>>();
        complete_bank(&serial, &node.chain, &parent_hash, &payload);
        assert_eq!(serial_records, records);
        assert_eq!(bank_state(&serial), bank_state(&prepared_bank));
        assert!(records[0].1.status.is_ok() && records[1].1.status.is_err());
        assert!(records.iter().all(|record| record.1.fee == 5000));
        assert!(node.mempool.contains_key(&last));
    }

    #[test]
    fn native_pipeline_prepared_reuse_preserves_sparse_due_and_full_ready_coalescing() {
        for full_ready in [false, true] {
            let (_directory, mut node, mut signers, root, parent_hash) =
                prepared_reuse_fixture(&[7]);
            // An actual native PreparedProposal is a trusted compute result,
            // even when its selected payload is sparse. This control directly
            // supplies that real result to exercise the unchanged due guard.
            let prepared = prepare_reuse_test_result(&node, parent_hash);
            let bank = prepared.bank.clone();
            node.pipeline.as_mut().unwrap().unsigned_ready = Some(prepared);
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarVote,
                Some(parent_hash),
            );
            let due = node.now() + 60_000;
            node.production.as_mut().unwrap().due = due;
            take_proposal_snapshot_calls();
            node.produce().unwrap();
            assert_eq!(take_proposal_snapshot_calls(), 0);
            assert!(!node.pipeline.as_ref().unwrap().producer.busy);
            assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_some());
            assert!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .is_none()
            );
            if full_ready {
                node.admit(
                    bincode::serialize(&pipeline_transfer(&node, &root, 8)).unwrap(),
                    true,
                )
                .unwrap();
            } else {
                let due = node.now();
                node.production.as_mut().unwrap().due = due;
            }
            take_proposal_snapshot_calls();
            node.produce().unwrap();
            assert_eq!(take_proposal_snapshot_calls(), 0);
            assert!(node.pipeline.as_ref().unwrap().producer.busy);
            assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
            pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
            let hash = node.proposed[&5].marker.block_commitment;
            assert!(Arc::ptr_eq(
                &bank,
                &node.runtime.lock().unwrap().banks[&hash]
            ));
            assert_eq!(node.runtime.lock().unwrap().archives[&hash].len(), 1);
            assert!(
                node.runtime.lock().unwrap().archives[&hash][0]
                    .1
                    .status
                    .is_ok()
            );
            assert_eq!(node.runtime.lock().unwrap().archives[&hash][0].1.fee, 5000);
        }
    }

    #[test]
    fn native_pipeline_prepared_reuse_wrong_parent_and_fixed_intent_keep_full_snapshot() {
        for fixed in [false, true] {
            let (_directory, mut node, mut signers, root, parent_hash) =
                unsigned_next_leader_fixture();
            node.prepare_next_leader().unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
            });
            let discarded = node
                .pipeline
                .as_ref()
                .unwrap()
                .unsigned_ready
                .as_ref()
                .unwrap()
                .bank
                .clone();
            let mut fixed_intent = None;
            let chosen_parent = if fixed {
                let payload = encode_block(&[]).unwrap();
                let intent = solana_ledger::blockstore::ExperimentalPqProposalIntent {
                    chain: node.chain,
                    epoch: node.public.epoch,
                    slot: 5,
                    parent: parent_hash,
                    candidate: hash_commitment(
                        b"agave-pq-candidate-v1",
                        &[&node.chain, &5u64.to_le_bytes(), &parent_hash, &payload],
                    ),
                    payload,
                };
                node.blockstore
                    .put_experimental_pq_proposal_intent(&intent)
                    .unwrap();
                node.resume_intents.insert(5, intent.clone());
                fixed_intent = Some(intent);
                receive_test_quorum(
                    &mut node,
                    &mut signers,
                    4,
                    MessageKind::NotarVote,
                    Some(parent_hash),
                );
                parent_hash
            } else {
                let anchor = node.adopted_anchor().unwrap();
                let alternative = pipeline_peer_witness(&node, &root, 1, anchor.hash, 1);
                let hash = alternative.marker.block_commitment;
                node.complete(alternative).unwrap();
                pump_pipeline_until(&mut node, |node| node.machine.payload(&hash).is_some());
                node.drive().unwrap();
                receive_test_quorum(
                    &mut node,
                    &mut signers,
                    1,
                    MessageKind::NotarVote,
                    Some(hash),
                );
                for slot in 2..=4 {
                    receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
                }
                assert!(!node.machine.ready_parents(5).contains(&parent_hash));
                hash
            };
            assert_eq!(node.production.unwrap().parent, chosen_parent);
            let order = node.mempool_order.iter().copied().collect::<Vec<_>>();
            take_proposal_snapshot_calls();
            node.produce().unwrap();
            assert_eq!(
                take_proposal_snapshot_calls(),
                1,
                "nonreusable preparation retains the original full snapshot path"
            );
            assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
            pump_pipeline_until(&mut node, |node| {
                node.proposed.get(&5).is_some_and(|witness| {
                    node.machine
                        .payload(&witness.marker.block_commitment)
                        .is_some()
                })
            });
            let hash = node.proposed[&5].marker.block_commitment;
            assert_eq!(node.proposed[&5].marker.parent, chosen_parent);
            assert!(!Arc::ptr_eq(
                &discarded,
                &node.runtime.lock().unwrap().banks[&hash]
            ));
            assert_eq!(
                node.mempool_order.iter().copied().collect::<Vec<_>>(),
                order
            );
            if let Some(intent) = fixed_intent {
                assert_eq!(
                    node.blockstore
                        .get_experimental_pq_proposal_intent(5)
                        .unwrap()
                        .unwrap(),
                    intent
                );
                assert!(node.runtime.lock().unwrap().archives[&hash].is_empty());
            } else {
                let archive = node.runtime.lock().unwrap().archives[&hash].clone();
                assert_eq!(archive.len(), 2);
                assert!(archive[0].1.status.is_ok() && archive[1].1.status.is_err());
                assert!(archive.iter().all(|record| record.1.fee == 5000));
            }
        }
    }

    #[test]
    fn native_pipeline_same_leader_child_finishes_before_parent_intent_and_reuses_once() {
        let (directory, mut node, mut signers, _root, parent_hash) = unsigned_next_leader_fixture();
        node.public.proposal_max_transactions = Some(1);
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().producer_intent_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
        let order_before = node.mempool_order.iter().copied().collect::<Vec<_>>();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let pipeline = node.pipeline.as_ref().unwrap();
        let private = pipeline.private_producer_parent.as_ref().unwrap();
        let predicted_parent = private.block.hash;
        let parent_bank = private.bank.clone();
        let child = pipeline.unsigned_ready.as_ref().unwrap();
        let child_bank = child.bank.clone();
        let child_payload = child.payload().to_vec();
        let child_records = child.records().to_vec();
        assert_eq!(private.selected_ids.len(), 1);
        assert_eq!(child_records.len(), 1);
        assert!(child_records[0].1.status.is_err());
        assert_eq!(child_records[0].1.fee, 5000);
        assert_eq!(child.production.first, 5);
        assert_eq!(child.production.next, 6);
        assert_eq!(child.production.parent, predicted_parent);
        assert!(Arc::ptr_eq(&child.parent, &parent_bank));
        let serial =
            Bank::new_isolated_pq_child(parent_bank.clone(), *child_bank.leader(), 6).unwrap();
        let records = decode_block(&child_payload, 1)
            .unwrap()
            .into_iter()
            .map(|transaction| process_with_status(&serial, transaction).unwrap())
            .collect::<Vec<_>>();
        complete_bank(&serial, &node.chain, &predicted_parent, &child_payload);
        assert_eq!(bank_state(&serial), bank_state(&child_bank));
        assert_eq!(records, child_records);
        assert_eq!(
            child_bank.transaction_count(),
            parent_bank.transaction_count() + 1
        );
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            order_before
        );
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signer_before
        );
        for slot in [5, 6] {
            assert!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(slot)
                    .unwrap()
                    .is_none()
            );
            assert!(
                node.blockstore
                    .get_experimental_pq_block(slot, [0; 48])
                    .unwrap()
                    .is_none()
            );
            assert!(!node.proposed.contains_key(&slot));
        }
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .banks
                .contains_key(&predicted_parent)
        );
        assert!(node.machine.payload(&predicted_parent).is_none());
        assert!(pipeline.stream_receiver.as_ref().unwrap().is_empty());
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
        assert_eq!(node.proposed[&5].marker.block_commitment, predicted_parent);
        assert!(Arc::ptr_eq(
            &parent_bank,
            &node.runtime.lock().unwrap().banks[&predicted_parent]
        ));
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&6)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let hash = node.proposed[&6].marker.block_commitment;
        assert!(Arc::ptr_eq(
            &child_bank,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
        assert_eq!(
            node.runtime.lock().unwrap().archives[&hash].as_ref(),
            &child_records
        );
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .unwrap()
                .payload,
            child_payload
        );
        assert_eq!(node.speculative_ids[&5].len(), 1);
        assert_eq!(node.speculative_ids[&6].len(), 1);
        assert!(node.speculative_ids[&5].is_disjoint(&node.speculative_ids[&6]));
        receive_test_quorum(
            &mut node,
            &mut signers,
            6,
            MessageKind::NotarVote,
            Some(hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 6 && node.finalized_transactions == 3
        });
        assert!(Arc::ptr_eq(
            &child_bank,
            &node.bank_forks.read().unwrap().root_bank()
        ));
        assert!(node.mempool.is_empty());
    }

    #[test]
    fn native_pipeline_same_leader_parent_intent_conflict_discards_unsigned_without_effects() {
        let (directory, mut node, mut signers, _root, parent_hash) = unsigned_next_leader_fixture();
        node.public.proposal_max_transactions = Some(1);
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().producer_intent_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
        let ids = node.mempool_order.iter().copied().collect::<Vec<_>>();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let predicted = node
            .pipeline
            .as_ref()
            .unwrap()
            .private_producer_parent
            .as_ref()
            .unwrap()
            .block
            .hash;
        let payload = encode_block(&[]).unwrap();
        let fixed = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            chain: node.chain,
            epoch: node.public.epoch,
            slot: 5,
            parent: parent_hash,
            candidate: hash_commitment(
                b"agave-pq-candidate-v1",
                &[&node.chain, &5u64.to_le_bytes(), &parent_hash, &payload],
            ),
            payload,
        };
        node.blockstore
            .put_experimental_pq_proposal_intent(&fixed)
            .unwrap();
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let failure = loop {
            match node.poll_pipeline() {
                Err(error) => break error,
                Ok(()) => assert!(Instant::now() < deadline),
            }
            thread::sleep(Duration::from_millis(1));
        };
        assert!(
            failure.to_string().contains("proposal intent overwrite"),
            "{failure:#}"
        );
        let pipeline = node.pipeline.as_ref().unwrap();
        assert!(pipeline.private_producer_parent.is_none());
        assert!(pipeline.unsigned_ready.is_none());
        assert!(pipeline.stream_receiver.as_ref().unwrap().is_empty());
        assert!(node.proposed.is_empty());
        assert!(node.machine.payload(&predicted).is_none());
        assert!(!node.runtime.lock().unwrap().banks.contains_key(&predicted));
        assert_eq!(node.mempool_order.iter().copied().collect::<Vec<_>>(), ids);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signer_before
        );
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap(),
            fixed
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn native_pipeline_same_leader_shared_capacity_and_recovered_child_intent_override() {
        let (_directory, mut node, mut signers, _root, parent_hash) =
            unsigned_next_leader_fixture();
        node.public.proposal_max_transactions = Some(1);
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().producer_intent_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        let capacity = node.runtime.lock().unwrap().banks.len() + 1;
        node.pipeline.as_mut().unwrap().native_bank_capacity = capacity;
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline
                .as_ref()
                .unwrap()
                .private_producer_parent
                .is_some()
        });
        for _ in 0..4 {
            node.poll_pipeline().unwrap();
        }
        assert!(!node.pipeline.as_ref().unwrap().unsigned_preparation.busy);
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        assert!(node.pipeline.as_ref().unwrap().unsigned_attempted.is_none());
        node.pipeline.as_mut().unwrap().native_bank_capacity = capacity + 1;
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let pipeline = node.pipeline.as_ref().unwrap();
        assert_eq!(
            node.runtime.lock().unwrap().banks.len()
                + usize::from(pipeline.producer.busy)
                + pipeline.unsigned_bank_reservation(),
            capacity + 1
        );
        let predicted_parent = pipeline
            .private_producer_parent
            .as_ref()
            .unwrap()
            .block
            .hash;
        let discarded = pipeline.unsigned_ready.as_ref().unwrap().bank.clone();
        let payload = encode_block(&[]).unwrap();
        let fixed = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            chain: node.chain,
            epoch: node.public.epoch,
            slot: 6,
            parent: predicted_parent,
            candidate: hash_commitment(
                b"agave-pq-candidate-v1",
                &[
                    &node.chain,
                    &6u64.to_le_bytes(),
                    &predicted_parent,
                    &payload,
                ],
            ),
            payload,
        };
        node.blockstore
            .put_experimental_pq_proposal_intent(&fixed)
            .unwrap();
        node.resume_intents.insert(6, fixed.clone());
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&6)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let hash = node.proposed[&6].marker.block_commitment;
        let runtime = node.runtime.lock().unwrap();
        assert!(!Arc::ptr_eq(&discarded, &runtime.banks[&hash]));
        assert!(runtime.archives[&hash].is_empty());
        assert_eq!(
            runtime.banks[&hash].transaction_count(),
            runtime.banks[&predicted_parent].transaction_count()
        );
        drop(runtime);
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .unwrap(),
            fixed
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(7)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            node.mempool.len(),
            2,
            "pure prediction/recovery cannot retire the pending transaction before canonical \
             commit"
        );
    }

    #[test]
    fn native_pipeline_same_leader_certified_frontier_compaction_and_restart_fence_prediction() {
        let (directory, mut node, mut signers, original, later) =
            native_parent_reauthorization_fixture_with_fee(Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        for amount in [21, 22] {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                false,
            )
            .unwrap();
        }
        node.public.proposal_max_transactions = Some(1);
        let mut pipeline = PqPipeline::new().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.producer_intent_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        node.pipeline = Some(pipeline);
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let predicted = node
            .pipeline
            .as_ref()
            .unwrap()
            .private_producer_parent
            .as_ref()
            .unwrap()
            .block
            .hash;
        let ids = node.mempool_order.iter().copied().collect::<Vec<_>>();
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarFallbackVote,
            Some(later),
        );
        // Fallback authorization by itself does not finalize its parent.
        // Certify a real competing child, exactly as the existing race oracle.
        let competing = pipeline_peer_witness(&node, &root, 5, later, 31);
        let competing_hash = competing.marker.block_commitment;
        node.complete(competing).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.machine.payload(&competing_hash).is_some()
        });
        receive_test_quorum(
            &mut node,
            &mut signers,
            5,
            MessageKind::NotarVote,
            Some(competing_hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 5
                && !node.pipeline.as_ref().unwrap().archive.busy
        });
        node.compact().unwrap();
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .private_producer_parent
                .is_none()
        );
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        assert!(!node.runtime.lock().unwrap().banks.contains_key(&predicted));
        assert!(node.machine.payload(&predicted).is_none());
        let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().producer.busy
        });
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        assert_eq!(node.mempool_order.iter().copied().collect::<Vec<_>>(), ids);
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signer_before
        );
        let fixed = node
            .blockstore
            .get_experimental_pq_proposal_intent(5)
            .unwrap()
            .unwrap();
        assert_eq!(fixed.parent, original);
        // Drop all volatile prediction state, retaining only the real immutable
        // ledger intent. A different genuine strong parent cannot reuse slot5.
        drop(node.pipeline.take());
        node.proposed.remove(&5);
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.resume_intents.insert(5, fixed.clone());
        assert!(node.machine.ready_parents(5).contains(&later));
        node.production = Some(Production {
            first: 5,
            next: 5,
            parent: later,
            due: node.now(),
        });
        node.produce().unwrap();
        assert!(node.production.is_none());
        assert!(!node.pipeline.as_ref().unwrap().producer.busy);
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap(),
            fixed
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .is_none()
        );
        assert_eq!(node.mempool_order.iter().copied().collect::<Vec<_>>(), ids);
    }

    #[test]
    fn native_pipeline_same_leader_excludes_parent_hard_reject_without_early_pruning() {
        let (directory, mut node, mut signers) =
            repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let parent = pipeline_peer_witness(&node, &root, 4, node.adopted_anchor().unwrap().hash, 4);
        let parent_hash = parent.marker.block_commitment;
        node.pipeline = Some(PqPipeline::new().unwrap());
        let peer = *node.outbound.keys().next().unwrap();
        receive_witness(&mut node, peer, &parent);
        pump_pipeline_until(&mut node, |node| {
            node.machine.payload(&parent_hash).is_some()
        });
        node.public.proposal_max_transactions = Some(1);
        let invalid = bincode::serialize(&pipeline_lock_limit_transfer(&node, &root)).unwrap();
        let invalid_id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&invalid]);
        node.admit(invalid, true).unwrap();
        for amount in [7, u64::MAX] {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline.as_mut().unwrap().producer_intent_gate = Some(pipeline::ArchiveGate {
            entered,
            release: released,
            fail: false,
        });
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let ids = node.mempool_order.iter().copied().collect::<Vec<_>>();
        let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let pipeline = node.pipeline.as_ref().unwrap();
        let parent = pipeline.private_producer_parent.as_ref().unwrap();
        assert!(parent.selected_ids.is_empty());
        assert!(parent.rejected_ids.contains(&invalid_id));
        let child = pipeline.unsigned_ready.as_ref().unwrap();
        assert_eq!(child.records().len(), 1);
        assert!(child.records()[0].1.status.is_ok());
        let predicted = parent.block.hash;
        let child_bank = child.bank.clone();
        let serial =
            Bank::new_isolated_pq_child(parent.bank.clone(), *child_bank.leader(), 6).unwrap();
        let records = decode_block(child.payload(), 1)
            .unwrap()
            .into_iter()
            .map(|tx| process_with_status(&serial, tx).unwrap())
            .collect::<Vec<_>>();
        complete_bank(&serial, &node.chain, &predicted, child.payload());
        assert_eq!(bank_state(&serial), bank_state(&child_bank));
        assert_eq!(records.as_slice(), child.records());
        assert!(node.mempool.contains_key(&invalid_id));
        assert_eq!(node.mempool_order.iter().copied().collect::<Vec<_>>(), ids);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signer_before
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .is_none()
        );
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
        assert!(!node.mempool.contains_key(&invalid_id));
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&6));
        let hash = node.proposed[&6].marker.block_commitment;
        assert!(Arc::ptr_eq(
            &child_bank,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
    }

    #[test]
    fn native_pipeline_unsigned_before_authorization_reuses_same_bank_and_charged_execution_once() {
        let (directory, mut node, mut signers, root, parent_hash) = unsigned_next_leader_fixture();
        let original_state = bank_state(&root);
        let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
        let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
        node.prepare_next_leader().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let prepared = node
            .pipeline
            .as_ref()
            .unwrap()
            .unsigned_ready
            .as_ref()
            .unwrap();
        let bank = prepared.bank.clone();
        let state = bank_state(&bank);
        let serial =
            Bank::new_isolated_pq_child(prepared.parent.clone(), *bank.leader(), 5).unwrap();
        let serial_records = decode_block(prepared.payload(), 2)
            .unwrap()
            .into_iter()
            .map(|transaction| process_with_status(&serial, transaction).unwrap())
            .collect::<Vec<_>>();
        complete_bank(&serial, &node.chain, &parent_hash, prepared.payload());
        assert_eq!(
            bank_state(&serial),
            state,
            "unsigned work must equal serial native full-state oracle"
        );
        assert_eq!(serial_records.as_slice(), prepared.records());
        assert!(bank.is_frozen());
        assert_eq!(bank.slot(), 5);
        assert_eq!(bank.transaction_count(), root.transaction_count() + 3);
        assert_eq!(node.bank_forks.read().unwrap().root(), root.slot());
        assert_eq!(bank_state(&root), original_state);
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signer_before
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        assert!(
            node.blockstore
                .get_experimental_pq_block(5, [0; 48])
                .unwrap()
                .is_none()
        );
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .stream_receiver
                .as_ref()
                .unwrap()
                .is_empty()
        );
        assert!(node.proposed.is_empty());
        assert!(
            !node
                .production
                .is_some_and(|production| production.first == 5)
        );
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        assert!(node.machine.ready_parents(5).contains(&parent_hash));
        node.produce().unwrap();
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&5)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let witness = node.proposed[&5].clone();
        let hash = witness.marker.block_commitment;
        assert_eq!(witness.marker.parent, parent_hash);
        assert!(Arc::ptr_eq(
            &bank,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
        assert_eq!(
            bank_state(&node.runtime.lock().unwrap().banks[&hash]),
            state
        );
        let records = node.runtime.lock().unwrap().archives[&hash].clone();
        assert_eq!(records.len(), 2);
        assert!(records[0].1.status.is_ok() && records[1].1.status.is_err());
        assert!(records.iter().all(|record| record.1.fee == 5000));
        let fixed = node
            .blockstore
            .get_experimental_pq_proposal_intent(5)
            .unwrap()
            .unwrap();
        assert_eq!(fixed.parent, parent_hash);
        receive_test_quorum(
            &mut node,
            &mut signers,
            5,
            MessageKind::NotarVote,
            Some(hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 5 && node.finalized_transactions == 3
        });
        assert!(Arc::ptr_eq(
            &bank,
            &node.bank_forks.read().unwrap().root_bank()
        ));
        assert_eq!(bank_state(&bank), state);
        assert!(node.mempool.is_empty());
        for record in records.iter() {
            assert!(bank.pq_transaction_processed(&record.0).unwrap());
        }
        node.compact().unwrap();
        assert_eq!(node.finalized_transactions, 3);
    }

    #[test]
    fn native_pipeline_unsigned_capacity_and_fixed_recovery_intent_win_without_signing() {
        let (_directory, mut node, mut signers, _root, parent_hash) =
            unsigned_next_leader_fixture();
        node.pipeline.as_mut().unwrap().native_bank_capacity = 2;
        node.prepare_next_leader().unwrap();
        assert!(!node.pipeline.as_ref().unwrap().unsigned_preparation.busy);
        node.pipeline.as_mut().unwrap().native_bank_capacity = 3;
        node.prepare_next_leader().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        assert_eq!(
            node.pipeline.as_ref().unwrap().unsigned_bank_reservation(),
            1
        );
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let alternative = pipeline_peer_witness(&node, &root, 1, anchor.hash, 99);
        node.complete(alternative.clone()).unwrap();
        assert!(!node.pipeline.as_ref().unwrap().candidate.busy);
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .banks
                .contains_key(&alternative.marker.block_commitment)
        );
        let payload = encode_block(&[]).unwrap();
        let intent = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            chain: node.chain,
            epoch: node.public.epoch,
            slot: 5,
            parent: parent_hash,
            candidate: hash_commitment(
                b"agave-pq-candidate-v1",
                &[&node.chain, &5u64.to_le_bytes(), &parent_hash, &payload],
            ),
            payload,
        };
        node.blockstore
            .put_experimental_pq_proposal_intent(&intent)
            .unwrap();
        node.resume_intents.insert(5, intent.clone());
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        assert!(node.machine.ready_parents(5).contains(&parent_hash));
        // Restored fixed bytes supersede all unpublished prediction work.
        node.production = Some(Production {
            first: 5,
            next: 5,
            parent: parent_hash,
            due: node.now(),
        });
        node.produce().unwrap();
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        assert!(node.pipeline.as_ref().unwrap().producer.busy);
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap(),
            intent
        );
        assert_eq!(node.proposed[&5].marker.parent, parent_hash);
        assert_eq!(node.mempool.len(), 2);
    }

    #[test]
    fn native_pipeline_unsigned_alternate_strong_parent_discards_without_pruning_or_burning() {
        let (_directory, mut node, mut signers, root, guessed_parent) =
            unsigned_next_leader_fixture();
        node.pipeline.as_mut().unwrap().native_bank_capacity = 4;
        node.prepare_next_leader().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let discarded = node
            .pipeline
            .as_ref()
            .unwrap()
            .unsigned_ready
            .as_ref()
            .unwrap()
            .bank
            .clone();
        let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
        let anchor = node.adopted_anchor().unwrap();
        let first = pipeline_peer_witness(&node, &root, 1, anchor.hash, 1);
        let first_hash = first.marker.block_commitment;
        node.complete(first).unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.machine.payload(&first_hash).is_some()
        });
        node.drive().unwrap();
        receive_test_quorum(
            &mut node,
            &mut signers,
            1,
            MessageKind::NotarVote,
            Some(first_hash),
        );
        for slot in 2..=4 {
            receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
        }
        assert!(node.machine.ready_parents(5).contains(&first_hash));
        assert!(!node.machine.ready_parents(5).contains(&guessed_parent));
        assert_eq!(node.production.unwrap().parent, first_hash);
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        node.produce().unwrap();
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&5)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let hash = node.proposed[&5].marker.block_commitment;
        assert_eq!(node.proposed[&5].marker.parent, first_hash);
        assert!(!Arc::ptr_eq(
            &discarded,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        let current = node.runtime.lock().unwrap().banks[&hash].clone();
        let state = bank_state(&current);
        receive_test_quorum(
            &mut node,
            &mut signers,
            5,
            MessageKind::NotarVote,
            Some(hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 5 && node.finalized_transactions == 3
        });
        assert_eq!(
            bank_state(&node.bank_forks.read().unwrap().root_bank()),
            state
        );
        assert!(node.mempool.is_empty());
    }

    #[test]
    fn native_pipeline_unsigned_inflight_certified_frontier_compaction_discards_without_escape() {
        let (_directory, mut node, mut signers, root, guessed_parent) =
            unsigned_next_leader_fixture();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        node.pipeline
            .as_mut()
            .unwrap()
            .gate_first_unsigned_preparation(entered, released)
            .unwrap();
        let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
        node.prepare_next_leader().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(node.pipeline.as_ref().unwrap().unsigned_preparation.busy);
        let competing = pipeline_peer_witness(&node, &root, 5, guessed_parent, 99);
        let hash = competing.marker.block_commitment;
        node.complete(competing).unwrap();
        pump_pipeline_until(&mut node, |node| node.machine.payload(&hash).is_some());
        node.drive().unwrap();
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(guessed_parent),
        );
        receive_test_quorum(
            &mut node,
            &mut signers,
            5,
            MessageKind::NotarVote,
            Some(hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 5 && node.finalized_transactions == 2
        });
        node.compact().unwrap();
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().unsigned_preparation.busy
        });
        assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .unsigned_reservation
                .is_none()
        );
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        assert!(!node.proposed.contains_key(&5));
        assert!(node.streaming.is_empty());
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .stream_receiver
                .as_ref()
                .unwrap()
                .is_empty()
        );
        for slot in 6..=8 {
            receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
        }
        assert!(node.machine.ready_parents(9).contains(&hash));
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&9)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        assert_eq!(node.proposed[&9].marker.parent, hash);
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
    }

    #[test]
    fn native_pipeline_unsigned_volatile_restart_and_unknown_hash_keep_exact_wires() {
        let (directory, mut node, mut signers, root, parent_hash) = unsigned_next_leader_fixture();
        let known = node.mempool_order.iter().copied().collect::<Vec<_>>();
        for id in &known {
            remove_admitted_wire(
                &mut node.mempool,
                &mut node.mempool_order,
                &mut node.gossip_log,
                id,
            );
        }
        let message = VersionedMessage::Legacy(Message::new_with_blockhash(
            &[
                authenticate_instruction(&[node.local]),
                system_instruction::transfer(&node.local, &Pubkey::new_from_array([0xa8; 32]), 11),
            ],
            Some(&node.local),
            &Hash::new_unique(),
        ));
        let transaction = sign_transaction(
            message,
            &root.pq_config().unwrap().unwrap(),
            &[&node.leader],
        )
        .unwrap();
        let unknown = bincode::serialize(&transaction).unwrap();
        let unknown_id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&unknown]);
        node.admit(unknown.clone(), true).unwrap();
        node.prepare_next_leader().unwrap();
        assert!(!node.pipeline.as_ref().unwrap().unsigned_preparation.busy);
        assert!(node.pipeline.as_ref().unwrap().unsigned_attempted.is_none());
        for amount in [7, u64::MAX] {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
        let sequence = node.mempool_order.by_id[&unknown_id];
        node.prepare_next_leader().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let first = node
            .pipeline
            .as_ref()
            .unwrap()
            .unsigned_ready
            .as_ref()
            .unwrap()
            .bank
            .clone();
        let state = bank_state(&first);
        let payload = node
            .pipeline
            .as_ref()
            .unwrap()
            .unsigned_ready
            .as_ref()
            .unwrap()
            .payload()
            .to_vec();
        // Dropping the bounded service loses only volatile speculation. With
        // no intent/signature emitted, the same immutable inputs can prepare
        // again; canonical state and native receipts have never moved.
        drop(node.pipeline.take());
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signer_before
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        assert_eq!(node.bank_forks.read().unwrap().root(), root.slot());
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.prepare_next_leader().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.pipeline.as_ref().unwrap().unsigned_ready.is_some()
        });
        let restored = node
            .pipeline
            .as_ref()
            .unwrap()
            .unsigned_ready
            .as_ref()
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &restored.bank));
        assert_eq!(bank_state(&restored.bank), state);
        assert_eq!(restored.payload(), payload);
        let used = restored.bank.clone();
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarVote,
            Some(parent_hash),
        );
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&5)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let hash = node.proposed[&5].marker.block_commitment;
        receive_test_quorum(
            &mut node,
            &mut signers,
            5,
            MessageKind::NotarVote,
            Some(hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 5 && node.finalized_transactions == 3
        });
        assert!(Arc::ptr_eq(
            &used,
            &node.bank_forks.read().unwrap().root_bank()
        ));
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.mempool[&unknown_id].raw, unknown);
        assert_eq!(node.mempool_order.by_id[&unknown_id], sequence);
        assert_eq!(node.gossip_log[&sequence], unknown_id);
        assert_eq!(node.finalized_transactions, 3);
    }

    #[test]
    fn native_pipeline_unsigned_matching_authorization_and_fixed_intent_during_busy_work() {
        for recover_fixed in [false, true] {
            let (_directory, mut node, mut signers, _root, parent_hash) =
                unsigned_next_leader_fixture();
            node.pipeline.as_mut().unwrap().native_bank_capacity = 3;
            let (entered, entering) = bounded(1);
            let (release, released) = bounded(1);
            node.pipeline
                .as_mut()
                .unwrap()
                .gate_unsigned_before_execution(entered, released)
                .unwrap();
            node.prepare_next_leader().unwrap();
            entering.recv_timeout(Duration::from_secs(5)).unwrap();
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarVote,
                Some(parent_hash),
            );
            assert!(node.machine.ready_parents(5).contains(&parent_hash));
            let fixed = recover_fixed.then(|| {
                let payload = encode_block(&[]).unwrap();
                solana_ledger::blockstore::ExperimentalPqProposalIntent {
                    chain: node.chain,
                    epoch: node.public.epoch,
                    slot: 5,
                    parent: parent_hash,
                    candidate: hash_commitment(
                        b"agave-pq-candidate-v1",
                        &[&node.chain, &5u64.to_le_bytes(), &parent_hash, &payload],
                    ),
                    payload,
                }
            });
            if let Some(intent) = &fixed {
                node.blockstore
                    .put_experimental_pq_proposal_intent(intent)
                    .unwrap();
                node.resume_intents.insert(5, intent.clone());
            }
            node.produce().unwrap();
            assert!(node.pipeline.as_ref().unwrap().unsigned_preparation.busy);
            assert!(!node.pipeline.as_ref().unwrap().producer.busy);
            assert!(node.proposed.is_empty());
            assert_eq!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap(),
                fixed
            );
            release.send(()).unwrap();
            pump_pipeline_until(&mut node, |node| {
                !node.pipeline.as_ref().unwrap().unsigned_preparation.busy
            });
            let prepared_bank = node
                .pipeline
                .as_ref()
                .unwrap()
                .unsigned_ready
                .as_ref()
                .map(|ready| ready.bank.clone());
            assert_eq!(prepared_bank.is_some(), !recover_fixed);
            node.produce().unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.proposed
                    .get(&5)
                    .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
            });
            let hash = node.proposed[&5].marker.block_commitment;
            let bank = node.runtime.lock().unwrap().banks[&hash].clone();
            if let Some(prepared) = prepared_bank {
                assert!(Arc::ptr_eq(&prepared, &bank));
            }
            if let Some(intent) = &fixed {
                assert_eq!(
                    node.blockstore
                        .get_experimental_pq_proposal_intent(5)
                        .unwrap()
                        .as_ref(),
                    Some(intent)
                );
                assert!(node.runtime.lock().unwrap().archives[&hash].is_empty());
            } else {
                assert_eq!(node.runtime.lock().unwrap().archives[&hash].len(), 2);
            }
            assert_eq!(node.mempool.len(), 2);
        }
    }

    #[test]
    fn native_pipeline_unsigned_worker_cancellation_and_disconnect_fail_stop_without_effects() {
        for disconnect in [false, true] {
            let (directory, mut node, _signers, root, _parent_hash) =
                unsigned_next_leader_fixture();
            let signer_before = std::fs::read(directory.path().join("ax")).unwrap();
            let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
            if disconnect {
                node.pipeline
                    .as_mut()
                    .unwrap()
                    .disconnect_unsigned_requests();
                let error = node.prepare_next_leader().unwrap_err();
                assert!(error.downcast_ref::<InternalPqError>().is_some());
            } else {
                let (entered, entering) = bounded(1);
                let (release, released) = bounded(1);
                node.pipeline
                    .as_mut()
                    .unwrap()
                    .gate_unsigned_before_execution(entered, released)
                    .unwrap();
                node.prepare_next_leader().unwrap();
                entering.recv_timeout(Duration::from_secs(5)).unwrap();
                node.pipeline
                    .as_ref()
                    .unwrap()
                    .stop
                    .store(true, Ordering::Release);
                release.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    assert!(
                        Instant::now() < deadline,
                        "unsigned worker cancellation did not surface"
                    );
                    if let Err(error) = node.poll_pipeline() {
                        assert!(error.to_string().contains("PQ preparation cancelled"));
                        break;
                    }
                    thread::yield_now();
                }
            }
            assert!(node.pipeline.as_ref().unwrap().unsigned_ready.is_none());
            assert!(node.proposed.is_empty() && node.streaming.is_empty());
            assert!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .is_none()
            );
            assert!(
                node.pipeline
                    .as_ref()
                    .unwrap()
                    .stream_receiver
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                node.mempool_order.iter().copied().collect::<Vec<_>>(),
                admitted
            );
            assert_eq!(
                std::fs::read(directory.path().join("ax")).unwrap(),
                signer_before
            );
            assert_eq!(node.bank_forks.read().unwrap().root(), root.slot());
        }
    }

    #[test]
    fn native_pipeline_capacity_rejects_peer_work_pauses_production_and_recovers_after_root() {
        let (_directory, mut node) = repair_fixture();
        node.machine = Quantumglow::new(
            node.machine.config().clone(),
            node.local.to_bytes(),
            vec![PqValidator {
                id: node.local.to_bytes(),
                stake: 1,
                key: node.signer.public_key(),
            }],
        )
        .unwrap();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let peer = *node.outbound.keys().next().unwrap();
        let mut pipeline = PqPipeline::new().unwrap();
        assert_eq!(pipeline.native_bank_capacity, 128);
        // The identical production guard uses a lower test-only capacity, so
        // real alternative native Banks exercise pressure without 127 forks.
        pipeline.native_bank_capacity = 6;
        node.pipeline = Some(pipeline);
        let mut first = None;
        for amount in 1..=5 {
            let witness = pipeline_peer_witness(&node, &root, 1, parent.hash, amount);
            receive_witness(&mut node, peer, &witness);
            pump_pipeline_until(&mut node, |node| {
                node.blocks.contains_key(&witness.marker.block_commitment)
            });
            if first.is_none() {
                first = Some(witness);
            }
        }
        let first = first.unwrap();
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 6);
        let transaction = pipeline_transfer(&node, &root, 99);
        node.admit(bincode::serialize(&transaction).unwrap(), false)
            .unwrap();
        node.public.proposal_max_transactions = Some(1);
        node.production = Some(Production {
            first: 1,
            next: 2,
            parent: first.marker.block_commitment,
            due: node.now(),
        });
        node.produce().unwrap();
        assert!(!node.pipeline.as_ref().unwrap().producer.busy);
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(2)
                .unwrap()
                .is_none()
        );
        let rejected = repair_witness(
            &node,
            2,
            first.marker.block_commitment,
            &encode_block(&[]).unwrap(),
        );
        receive_witness(&mut node, peer, &rejected);
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().reconstruction.busy
        });
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 6);
        assert!(!node.pipeline.as_ref().unwrap().candidate.busy);
        assert!(
            node.blockstore
                .get_experimental_pq_block(2, rejected.marker.block_commitment)
                .unwrap()
                .is_none()
        );
        // A genuine certificate roots one branch; successful archive followed
        // by normal compaction releases the obsolete alternatives.
        node.drive().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while node.finalized_transactions != 1 {
            assert!(Instant::now() < deadline);
            node.poll_pipeline().unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        node.compact().unwrap();
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 1);
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&2));
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 2);
        assert_eq!(
            node.runtime.lock().unwrap().banks[&node.proposed[&2].marker.block_commitment]
                .transaction_count(),
            root.transaction_count() + 2
        );
        assert_eq!(node.invalid_packets, 1);
        assert!(!node.exit.load(Ordering::Acquire));
    }

    #[test]
    fn native_pipeline_reserves_shared_capacity_for_inflight_producer_before_peer_dispatch() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let peer = *node.outbound.keys().next().unwrap();
        let mut pipeline = PqPipeline::new().unwrap();
        pipeline.native_bank_capacity = 3;
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.gate_first_production(entered, released).unwrap();
        node.pipeline = Some(pipeline);
        let first = pipeline_peer_witness(&node, &root, 1, parent.hash, 1);
        receive_witness(&mut node, peer, &first);
        pump_pipeline_until(&mut node, |node| {
            node.blocks.contains_key(&first.marker.block_commitment)
        });
        let transaction = pipeline_transfer(&node, &root, 99);
        node.admit(bincode::serialize(&transaction).unwrap(), false)
            .unwrap();
        node.public.proposal_max_transactions = Some(1);
        node.production = Some(Production {
            first: 1,
            next: 2,
            parent: first.marker.block_commitment,
            due: node.now(),
        });
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 2);
        assert!(node.pipeline.as_ref().unwrap().producer.busy);
        let rejected = repair_witness(
            &node,
            2,
            first.marker.block_commitment,
            &encode_block(&[]).unwrap(),
        );
        node.complete(rejected.clone()).unwrap();
        assert!(!node.pipeline.as_ref().unwrap().candidate.busy);
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 2);
        assert!(
            node.blockstore
                .get_experimental_pq_block(2, rejected.marker.block_commitment)
                .unwrap()
                .is_none()
        );
        release.send(()).unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&2));
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 3);
        assert_eq!(
            node.runtime.lock().unwrap().banks[&node.proposed[&2].marker.block_commitment]
                .transaction_count(),
            root.transaction_count() + 2
        );
        assert_eq!(node.invalid_packets, 1);
    }

    #[test]
    fn native_pipeline_recovers_exact_unfinished_stream_intent_and_preserves_other_transactions() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let fixed = pipeline_transfer(&node, &root, 7);
        let unrelated = pipeline_transfer(&node, &root, 8);
        let payload = encode_block(&[bincode::serialize(&fixed).unwrap()]).unwrap();
        let candidate = hash_commitment(
            b"agave-pq-candidate-v1",
            &[&node.chain, &1u64.to_le_bytes(), &parent.hash, &payload],
        );
        let intent = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            chain: node.chain,
            epoch: node.public.epoch,
            slot: 1,
            parent: parent.hash,
            candidate,
            payload: payload.clone(),
        };
        let data = payload.len().div_ceil(2048).max(1) as u16;
        let original_batch = SignedBatch::build(
            &node.chain,
            &node.leader,
            BatchContext {
                leader_epoch: node.public.epoch,
                slot: 1,
                candidate,
                parent: parent.hash,
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            data,
            data,
        )
        .unwrap();
        let original_marker = FinalMarker::build(
            &node.chain,
            &node.leader,
            std::slice::from_ref(&original_batch),
            &payload,
        )
        .unwrap();
        node.blockstore
            .put_experimental_pq_proposal_intent(&intent)
            .unwrap();
        // Simulate recovery before a complete witness exists, after a fixed
        // signed batch could have escaped. The new mempool differs entirely.
        node.resume_intents.insert(
            1,
            node.blockstore
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
                .unwrap(),
        );
        node.admit(bincode::serialize(&unrelated).unwrap(), false)
            .unwrap();
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.public.proposal_max_transactions = Some(1);
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: parent.hash,
            due: u64::MAX,
        });
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.blocks.contains_key(
                &node
                    .proposed
                    .get(&1)
                    .map_or([0; 48], |witness| witness.marker.block_commitment),
            )
        });
        let witness = &node.proposed[&1];
        assert_eq!(witness.marker.candidate, candidate);
        assert_eq!(
            witness.marker.block_commitment,
            original_marker.block_commitment
        );
        assert_eq!(
            node.machine.payload(&witness.marker.block_commitment),
            Some(payload.as_slice())
        );
        assert_eq!(
            node.runtime.lock().unwrap().archives[&witness.marker.block_commitment][0].0,
            fixed
        );
        assert_eq!(node.mempool.len(), 1);
        assert!(!node.resume_intents.contains_key(&1));
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
                .unwrap()
                .payload,
            payload
        );
        // A conflicting recovered parent is skipped, never overwritten or
        // resigned as a second candidate in the same slot.
        let conflicting_parent = [0xfe; 48];
        let conflicting = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            slot: 2,
            parent: conflicting_parent,
            candidate: hash_commitment(
                b"agave-pq-candidate-v1",
                &[
                    &node.chain,
                    &2u64.to_le_bytes(),
                    &conflicting_parent,
                    &intent.payload,
                ],
            ),
            ..intent
        };
        node.blockstore
            .put_experimental_pq_proposal_intent(&conflicting)
            .unwrap();
        node.resume_intents.insert(
            2,
            node.blockstore
                .get_experimental_pq_proposal_intent(2)
                .unwrap()
                .unwrap(),
        );
        node.produce().unwrap();
        assert!(node.production.is_none());
        assert!(!node.pipeline.as_ref().unwrap().producer.busy);
    }

    #[test]
    fn native_pipeline_shutdown_unblocks_stream_and_preserves_immutable_intent() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let transaction = pipeline_transfer(&node, &root, 7);
        node.admit(bincode::serialize(&transaction).unwrap(), false)
            .unwrap();
        node.public.proposal_max_transactions = Some(1);
        let pipeline = PqPipeline::new().unwrap();
        for _ in 0..pipeline.stream_sender.capacity().unwrap() {
            pipeline
                .stream_sender
                .send(pipeline::StreamBatch {
                    slot: 0,
                    candidate: [0; 48],
                    frames: Vec::new(),
                })
                .unwrap();
        }
        node.pipeline = Some(pipeline);
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: parent.hash,
            due: node.now(),
        });
        node.produce().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let intent = loop {
            assert!(Instant::now() < deadline);
            if let Some(intent) = node
                .blockstore
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
            {
                break intent;
            }
            thread::sleep(Duration::from_millis(1));
        };
        let shutdown_started = Instant::now();
        drop(node.pipeline.take());
        assert!(shutdown_started.elapsed() < Duration::from_secs(2));
        assert!(
            node.blockstore
                .get_experimental_pq_block(1, [0; 48])
                .unwrap()
                .is_none()
        );
        assert_eq!(
            root.transaction_count(),
            node.bank_forks
                .read()
                .unwrap()
                .root_bank()
                .transaction_count()
        );
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(1)
                .unwrap()
                .unwrap()
                .payload,
            intent.payload
        );
        // Restart the bounded services with the already used immutable intent;
        // no key, epoch, native parent or signer state is reset.
        node.resume_intents.insert(1, intent.clone());
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&1));
        assert_eq!(node.proposed[&1].marker.candidate, intent.candidate);
        assert_eq!(
            node.runtime.lock().unwrap().archives[&node.proposed[&1].marker.block_commitment][0].0,
            transaction
        );
    }

    #[test]
    fn native_pipeline_compaction_waits_for_archive_after_native_promotion_and_keeps_failures_fatal()
     {
        for fail in [false, true] {
            let (_directory, mut node) = repair_fixture();
            node.machine = Quantumglow::new(
                node.machine.config().clone(),
                node.local.to_bytes(),
                vec![PqValidator {
                    id: node.local.to_bytes(),
                    stake: 1,
                    key: node.signer.public_key(),
                }],
            )
            .unwrap();
            let parent = node.adopted_anchor().unwrap();
            let root = node.bank_forks.read().unwrap().root_bank();
            let transaction = pipeline_transfer(&node, &root, 7);
            let payload = encode_block(&[bincode::serialize(&transaction).unwrap()]).unwrap();
            let witness = repair_witness(&node, 1, parent.hash, &payload);
            let (entered, entering) = bounded(1);
            let (release, released) = bounded(1);
            let mut pipeline = PqPipeline::new().unwrap();
            pipeline.archive_gate = Some(pipeline::ArchiveGate {
                entered,
                release: released,
                fail,
            });
            node.pipeline = Some(pipeline);
            node.complete(witness.clone()).unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.blocks.contains_key(&witness.marker.block_commitment)
            });
            node.drive().unwrap();
            entering.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(node.bank_forks.read().unwrap().root(), 1);
            assert_eq!(node.machine.finalized_chain().last().unwrap().slot, 1);
            assert!(node.pipeline.as_ref().unwrap().archive.busy);
            assert_eq!(node.finalized_transactions, 0);
            let before = node
                .runtime
                .lock()
                .unwrap()
                .banks
                .keys()
                .copied()
                .collect::<Vec<_>>();
            let journal = node.blockstore.get_experimental_pq_checkpoint().unwrap();
            assert!(before.contains(&parent.hash));
            node.compact().unwrap();
            assert_eq!(
                node.runtime
                    .lock()
                    .unwrap()
                    .banks
                    .keys()
                    .copied()
                    .collect::<Vec<_>>(),
                before
            );
            assert_eq!(
                node.blockstore.get_experimental_pq_checkpoint().unwrap(),
                journal
            );
            assert_eq!(
                node.machine.payload(&witness.marker.block_commitment),
                Some(payload.as_slice())
            );
            assert!(
                node.blockstore
                    .get_experimental_pq_rooted_transaction_statuses(
                        &[transaction.signatures[0]],
                        1
                    )
                    .unwrap()[0]
                    .is_none()
            );
            release.send(()).unwrap();
            if fail {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    assert!(Instant::now() < deadline);
                    if let Err(error) = node.poll_pipeline() {
                        assert!(error.to_string().contains("test archive WAL failure"));
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(node.finalized_transactions, 0);
                assert_eq!(
                    node.runtime
                        .lock()
                        .unwrap()
                        .banks
                        .keys()
                        .copied()
                        .collect::<Vec<_>>(),
                    before
                );
                assert_eq!(
                    node.blockstore.get_experimental_pq_checkpoint().unwrap(),
                    journal
                );
                assert!(node.blocks.contains_key(&witness.marker.block_commitment));
                assert_eq!(node.bank_forks.read().unwrap().root(), 1);
            } else {
                pump_pipeline_until(&mut node, |node| node.finalized_transactions == 1);
                node.compact().unwrap();
                assert!(
                    !node
                        .runtime
                        .lock()
                        .unwrap()
                        .banks
                        .contains_key(&parent.hash)
                );
                assert_eq!(
                    node.blockstore
                        .get_experimental_pq_rooted_transaction_statuses(
                            &[transaction.signatures[0]],
                            1
                        )
                        .unwrap()[0]
                        .as_ref()
                        .unwrap()
                        .1
                        .status,
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn native_pipeline_discards_finished_candidate_after_certified_root_race() {
        let (_directory, mut node) = repair_fixture();
        node.machine = Quantumglow::new(
            node.machine.config().clone(),
            node.local.to_bytes(),
            vec![PqValidator {
                id: node.local.to_bytes(),
                stake: 1,
                key: node.signer.public_key(),
            }],
        )
        .unwrap();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let losing_payload =
            encode_block(&[bincode::serialize(&pipeline_transfer(&node, &root, 7)).unwrap()])
                .unwrap();
        let winning_payload =
            encode_block(&[bincode::serialize(&pipeline_transfer(&node, &root, 8)).unwrap()])
                .unwrap();
        let losing = repair_witness(&node, 1, parent.hash, &losing_payload);
        let winning = repair_witness(&node, 1, parent.hash, &winning_payload);
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.complete(losing.clone()).unwrap();
        assert!(node.pipeline.as_ref().unwrap().candidate.busy);
        // A real signed certificate roots another independently executed Bank
        // before the asynchronous result can be installed by the coordinator.
        let pipeline = node.pipeline.take();
        node.complete(winning.clone()).unwrap();
        node.drive().unwrap();
        node.compact().unwrap();
        let adopted = node.bank_forks.read().unwrap().root_bank();
        assert_eq!(adopted.slot(), 1);
        node.pipeline = pipeline;
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().candidate.busy
        });
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .banks
                .contains_key(&losing.marker.block_commitment)
        );
        assert!(
            node.machine
                .payload(&losing.marker.block_commitment)
                .is_none()
        );
        assert!(Arc::ptr_eq(
            &adopted,
            &node.bank_forks.read().unwrap().root_bank()
        ));
        assert_eq!(
            adopted.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            root.get_balance(&Pubkey::new_from_array([0xa8; 32])) + 8
        );
        assert_eq!(adopted.transaction_count(), root.transaction_count() + 1);
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn native_pipeline_rejects_bad_transaction_and_handles_early_terminal() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let valid = pipeline_transfer(&node, &root, 7);
        let mut invalid = valid.clone();
        let VersionedMessage::Legacy(message) = &mut invalid.message else {
            unreachable!()
        };
        *message.instructions[0].data.last_mut().unwrap() ^= 1;
        let bad = repair_witness(
            &node,
            1,
            parent.hash,
            &encode_block(&[bincode::serialize(&invalid).unwrap()]).unwrap(),
        );
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.complete(bad.clone()).unwrap();
        pump_pipeline_until(&mut node, |node| {
            !node.pipeline.as_ref().unwrap().candidate.busy
        });
        assert_eq!(node.invalid_packets, 1);
        assert!(
            !node
                .completed_candidates
                .contains(&(1, bad.marker.candidate))
        );
        assert!(node.machine.payload(&bad.marker.block_commitment).is_none());
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 1);
        let good = repair_witness(
            &node,
            2,
            parent.hash,
            &encode_block(&[bincode::serialize(&valid).unwrap()]).unwrap(),
        );
        let peer = *node.outbound.keys().next().unwrap();
        let mut terminal = vec![2];
        terminal.extend(good.marker.encode());
        node.receive(peer, &terminal).unwrap();
        assert!(!node.pipeline.as_ref().unwrap().reconstruction.busy);
        for shred in &good.shreds[..good.shreds.len() - 1] {
            let mut frame = vec![1];
            frame.extend(shred.encode().unwrap());
            node.receive(peer, &frame).unwrap();
            assert!(!node.pipeline.as_ref().unwrap().reconstruction.busy);
        }
        let mut frame = vec![1];
        frame.extend(good.shreds.last().unwrap().encode().unwrap());
        node.receive(peer, &frame).unwrap();
        assert!(node.pipeline.as_ref().unwrap().reconstruction.busy);
        pump_pipeline_until(&mut node, |node| {
            node.blocks.contains_key(&good.marker.block_commitment)
        });
        let bank = node.runtime.lock().unwrap().banks[&good.marker.block_commitment].clone();
        assert_eq!(bank.transaction_count(), root.transaction_count() + 1);
        assert_eq!(
            bank.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            root.get_balance(&Pubkey::new_from_array([0xa8; 32])) + 7
        );
        assert_eq!(
            node.machine.payload(&good.marker.block_commitment),
            Some(
                encode_block(&[bincode::serialize(&valid).unwrap()])
                    .unwrap()
                    .as_slice()
            )
        );
        assert_eq!(node.invalid_packets, 1);
    }

    #[test]
    fn native_pipeline_rejects_sixth_authentic_peer_alternative_and_keeps_progressing() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let peer = *node.outbound.keys().next().unwrap();
        node.pipeline = Some(PqPipeline::new().unwrap());
        let mut rejected = None;
        for amount in 1..=6 {
            let payload =
                encode_block(&[
                    bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap()
                ])
                .unwrap();
            let candidate = hash_commitment(
                b"agave-pq-candidate-v1",
                &[&node.chain, &1u64.to_le_bytes(), &parent.hash, &payload],
            );
            let batch = SignedBatch::build(
                &node.chain,
                &node.leader,
                BatchContext {
                    leader_epoch: node.public.epoch,
                    slot: 1,
                    candidate,
                    parent: parent.hash,
                    batch_index: 0,
                    previous: [0; 48],
                },
                &payload,
                64,
                64,
            )
            .unwrap();
            let marker = FinalMarker::build(
                &node.chain,
                &node.leader,
                std::slice::from_ref(&batch),
                &payload,
            )
            .unwrap();
            let witness = BlockWitness {
                marker,
                shreds: batch.shreds[..64].to_vec(),
            };
            receive_witness(&mut node, peer, &witness);
            pump_pipeline_until(&mut node, |node| {
                let pipeline = node.pipeline.as_ref().unwrap();
                !pipeline.reconstruction.busy
                    && !pipeline.candidate.busy
                    && !pipeline.candidate_body.busy
                    && pipeline.pending_candidates.is_empty()
            });
            if amount < 6 {
                assert!(node.blocks.contains_key(&witness.marker.block_commitment));
            } else {
                rejected = Some(witness);
            }
        }
        let rejected = rejected.unwrap();
        assert_eq!(node.blocks.len(), 5);
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 6);
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .states
                .contains_key(&rejected.marker.block_commitment)
        );
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .executions
                .contains_key(&rejected.marker.block_commitment)
        );
        assert!(
            !node
                .runtime
                .lock()
                .unwrap()
                .archives
                .contains_key(&rejected.marker.block_commitment)
        );
        assert!(
            !node
                .completed_candidates
                .contains(&(1, rejected.marker.candidate))
        );
        assert!(
            node.machine
                .payload(&rejected.marker.block_commitment)
                .is_none()
        );
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        assert!(
            !node
                .deferred_refetches
                .contains_key(&rejected.marker.block_commitment)
        );
        assert!(
            !node
                .waiting_parents
                .contains_key(&rejected.marker.block_commitment)
        );
        node.retry().unwrap();
        assert_eq!(node.invalid_packets, 1);
        let next = repair_witness(&node, 2, parent.hash, &encode_block(&[]).unwrap());
        receive_witness(&mut node, peer, &next);
        pump_pipeline_until(&mut node, |node| {
            node.blocks.contains_key(&next.marker.block_commitment)
        });
        assert!(
            node.machine
                .payload(&next.marker.block_commitment)
                .is_some()
        );
        assert_eq!(node.invalid_packets, 1);
        assert!(!node.exit.load(Ordering::Acquire));
    }

    #[test]
    fn parent_ready_starts_authorized_native_production_without_extra_cadence() {
        let (_directory, mut node) = repair_fixture();
        let parent = node.adopted_anchor().unwrap().hash;
        let before = node.now();
        node.pending
            .push_back(Action::ParentReady { slot: 1, parent });
        node.drive().unwrap();
        let production = node.production.unwrap();
        assert_eq!(production.next, 1);
        assert_eq!(production.parent, parent);
        assert!(production.due >= before && production.due <= node.now());
        assert!(production.due < before + node.public.block_time_ms);
    }

    fn receive_test_quorum(
        node: &mut PqNode,
        signers: &mut [DurableConsensusSigner],
        slot: u64,
        kind: MessageKind,
        block: Option<Commitment>,
    ) {
        let peer = *node.outbound.keys().next().unwrap();
        for signer in signers.iter_mut() {
            let evidence = signer
                .sign(ConsensusMessage {
                    epoch: node.public.epoch,
                    slot,
                    kind,
                    block,
                })
                .unwrap();
            let mut frame = vec![3];
            frame.extend(evidence.encode().unwrap());
            node.receive(peer, &frame).unwrap();
            node.drive().unwrap();
        }
        let approval = match kind {
            MessageKind::NotarVote => Some(MessageKind::NotarApproval),
            MessageKind::SkipVote => Some(MessageKind::SkipApproval),
            MessageKind::NotarFallbackVote => Some(MessageKind::NotarFallbackApproval),
            _ => None,
        };
        if let Some(approval) = approval {
            receive_test_quorum(node, signers, slot, approval, block);
        }
    }

    fn native_parent_reauthorization_fixture() -> (
        tempfile::TempDir,
        PqNode,
        Vec<DurableConsensusSigner>,
        Commitment,
        Commitment,
    ) {
        native_parent_reauthorization_fixture_with_fee(None)
    }

    fn native_parent_reauthorization_fixture_with_fee(
        lamports_per_signature: Option<u64>,
    ) -> (
        tempfile::TempDir,
        PqNode,
        Vec<DurableConsensusSigner>,
        Commitment,
        Commitment,
    ) {
        let (directory, mut node, mut signers) =
            repair_fixture_with_signers_and_fee(32, lamports_per_signature);
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let first = pipeline_peer_witness(&node, &root, 1, anchor.hash, 1);
        let first_hash = first.marker.block_commitment;
        node.complete(first).unwrap();
        node.drive().unwrap();
        receive_test_quorum(
            &mut node,
            &mut signers,
            1,
            MessageKind::NotarVote,
            Some(first_hash),
        );
        for slot in 2..=4 {
            receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
        }
        assert!(node.machine.ready_parents(5).contains(&first_hash));
        let later = pipeline_peer_witness(&node, &root, 4, first_hash, 4);
        let later_hash = later.marker.block_commitment;
        node.complete(later).unwrap();
        node.drive().unwrap();
        assert_eq!(node.production.unwrap().parent, first_hash);
        (directory, node, signers, first_hash, later_hash)
    }

    #[test]
    fn native_pipeline_parent_reauthorization_preserves_intent_during_work_and_before_publication()
    {
        for during_work in [true, false] {
            let (_directory, mut node, mut signers, original, later) =
                native_parent_reauthorization_fixture();
            let root = node.bank_forks.read().unwrap().root_bank();
            for amount in [21, 22] {
                let transaction = pipeline_transfer(&node, &root, amount);
                node.admit(bincode::serialize(&transaction).unwrap(), false)
                    .unwrap();
            }
            node.public.proposal_max_transactions = Some(1);
            let mut pipeline = PqPipeline::new().unwrap();
            let (entered, entering) = bounded(1);
            let (release, released) = bounded(1);
            if during_work {
                pipeline.gate_first_production(entered, released).unwrap();
            } else {
                pipeline.gate_first_publication(entered, released).unwrap();
            }
            node.pipeline = Some(pipeline);
            node.produce().unwrap();
            if !during_work {
                pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
            }
            entering.recv_timeout(Duration::from_secs(5)).unwrap();
            let intent = node
                .blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap();
            assert_eq!(intent.parent, original);
            assert!(
                node.blockstore
                    .get_experimental_pq_block(5, [0; 48])
                    .unwrap()
                    .is_none()
            );
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarFallbackVote,
                Some(later),
            );
            assert!(node.machine.ready_parents(5).contains(&original));
            assert!(node.machine.ready_parents(5).contains(&later));
            if during_work {
                assert_eq!(node.production.unwrap().parent, original);
                assert_eq!(
                    node.pipeline
                        .as_ref()
                        .unwrap()
                        .producer_reservation
                        .unwrap()
                        .parent,
                    original
                );
            } else {
                assert_eq!(node.production.unwrap().next, 6);
                assert_eq!(node.proposed[&5].marker.parent, original);
            }
            release.send(()).unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.proposed.get(&5).is_some_and(|witness| {
                    node.machine
                        .payload(&witness.marker.block_commitment)
                        .is_some()
                })
            });
            let first = node.proposed[&5].clone();
            assert_eq!(first.marker.parent, original);
            assert_eq!(first.marker.candidate, intent.candidate);
            assert_eq!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .unwrap(),
                intent
            );
            node.produce().unwrap();
            pump_pipeline_and_dispatch_until(&mut node, |node| {
                node.proposed.get(&6).is_some_and(|witness| {
                    node.machine
                        .payload(&witness.marker.block_commitment)
                        .is_some()
                })
            });
            assert_eq!(
                node.proposed[&6].marker.parent,
                first.marker.block_commitment
            );
            assert_eq!(
                node.runtime.lock().unwrap().banks[&node.proposed[&6].marker.block_commitment]
                    .transaction_count(),
                root.transaction_count() + 2
            );
            assert_eq!(node.invalid_packets, 0);
        }
    }

    #[test]
    fn native_pipeline_recovery_prefers_original_authorized_parent_over_sorted_alternative() {
        let (_directory, mut node, mut signers, _original, later) =
            native_parent_reauthorization_fixture();
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarFallbackVote,
            Some(later),
        );
        let parents = node.machine.ready_parents(5);
        assert_eq!(parents.len(), 2);
        let fixed = parents[1];
        let root = node.bank_forks.read().unwrap().root_bank();
        let payload =
            encode_block(&[bincode::serialize(&pipeline_transfer(&node, &root, 21)).unwrap()])
                .unwrap();
        let intent = solana_ledger::blockstore::ExperimentalPqProposalIntent {
            chain: node.chain,
            epoch: node.public.epoch,
            slot: 5,
            parent: fixed,
            candidate: hash_commitment(
                b"agave-pq-candidate-v1",
                &[&node.chain, &5u64.to_le_bytes(), &fixed, &payload],
            ),
            payload,
        };
        node.blockstore
            .put_experimental_pq_proposal_intent(&intent)
            .unwrap();
        node.resume_intents.insert(5, intent.clone());
        assert_eq!(node.production_parent(5), Some(fixed));
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.pending.push_back(Action::ParentReady {
            slot: 5,
            parent: parents[0],
        });
        node.drive().unwrap();
        assert_eq!(node.production.unwrap().parent, fixed);
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed.get(&5).is_some_and(|witness| {
                node.machine
                    .payload(&witness.marker.block_commitment)
                    .is_some()
            })
        });
        assert_eq!(node.proposed[&5].marker.parent, fixed);
        assert_eq!(node.proposed[&5].marker.candidate, intent.candidate);
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap(),
            intent
        );
    }

    #[test]
    fn native_pipeline_used_slot_survives_certified_frontier_and_compaction_races() {
        for compact_before_result in [true, false] {
            let (_directory, mut node, mut signers, original, later) =
                native_parent_reauthorization_fixture();
            let root = node.bank_forks.read().unwrap().root_bank();
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, 21)).unwrap(),
                false,
            )
            .unwrap();
            node.public.proposal_max_transactions = Some(1);
            let mut pipeline = PqPipeline::new().unwrap();
            let (entered, entering) = bounded(1);
            let (release, released) = bounded(1);
            pipeline.gate_first_production(entered, released).unwrap();
            let (archive_entered, archive_entering) = bounded(1);
            let (archive_release, archive_released) = bounded(1);
            pipeline
                .gate_first_finalization(archive_entered, archive_released)
                .unwrap();
            node.pipeline = Some(pipeline);
            node.produce().unwrap();
            entering.recv_timeout(Duration::from_secs(5)).unwrap();
            let intent = node
                .blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap();
            assert_eq!(intent.parent, original);
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarFallbackVote,
                Some(later),
            );
            let competing = pipeline_peer_witness(&node, &root, 5, later, 31);
            let competing_hash = competing.marker.block_commitment;
            node.complete(competing).unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.machine.payload(&competing_hash).is_some()
            });
            node.drive().unwrap();
            receive_test_quorum(
                &mut node,
                &mut signers,
                5,
                MessageKind::NotarVote,
                Some(competing_hash),
            );
            assert_eq!(node.machine.finalized_chain().last().unwrap().slot, 5);
            archive_entering
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            assert_eq!(node.bank_forks.read().unwrap().root(), 1);
            if compact_before_result {
                archive_release.send(()).unwrap();
                pump_pipeline_until(&mut node, |node| node.finalized_transactions == 3);
                node.compact().unwrap();
                assert!(node.production.is_none());
                node.pending.push_back(Action::ParentReady {
                    slot: 5,
                    parent: later,
                });
                node.drive().unwrap();
                assert!(node.production.is_none());
            }
            release.send(()).unwrap();
            pump_pipeline_until(&mut node, |node| {
                !node.pipeline.as_ref().unwrap().producer.busy
            });
            assert!(node.proposed.contains_key(&5));
            assert!(
                node.pipeline
                    .as_ref()
                    .unwrap()
                    .producer_reservation
                    .is_none()
            );
            assert!(
                !node
                    .runtime
                    .lock()
                    .unwrap()
                    .banks
                    .contains_key(&node.proposed[&5].marker.block_commitment)
            );
            assert!(
                node.machine
                    .payload(&node.proposed[&5].marker.block_commitment)
                    .is_none()
            );
            if !compact_before_result {
                assert_eq!(node.bank_forks.read().unwrap().root(), 1);
                archive_release.send(()).unwrap();
                pump_pipeline_until(&mut node, |node| node.finalized_transactions == 3);
                node.compact().unwrap();
            }
            node.pending.push_back(Action::ParentReady {
                slot: 5,
                parent: later,
            });
            node.drive().unwrap();
            node.produce().unwrap();
            assert!(!node.pipeline.as_ref().unwrap().producer.busy);
            assert_eq!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .unwrap(),
                intent
            );
            assert!(
                node.blockstore
                    .get_experimental_pq_block(5, [0; 48])
                    .unwrap()
                    .is_none()
            );
            for slot in 6..=8 {
                receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
            }
            assert_eq!(node.production.unwrap().first, 9);
            node.produce().unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.proposed.get(&9).is_some_and(|witness| {
                    node.machine
                        .payload(&witness.marker.block_commitment)
                        .is_some()
                })
            });
            assert_eq!(node.proposed[&9].marker.parent, competing_hash);
            assert_eq!(
                node.blockstore
                    .get_experimental_pq_proposal_intent(5)
                    .unwrap()
                    .unwrap(),
                intent
            );
            assert_eq!(node.invalid_packets, 0);
        }
    }

    #[test]
    fn native_pipeline_unknown_blockhash_retains_exact_wire_under_bounded_pressure() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let mut transaction = pipeline_transfer(&node, &root, 41);
        transaction.message = VersionedMessage::Legacy(Message::new_with_blockhash(
            &[
                authenticate_instruction(&[node.local]),
                system_instruction::transfer(&node.local, &Pubkey::new_from_array([0xa8; 32]), 41),
            ],
            Some(&node.local),
            &Hash::new_unique(),
        ));
        transaction = sign_transaction(
            transaction.message,
            &root.pq_config().unwrap().unwrap(),
            &[&node.leader],
        )
        .unwrap();
        let raw = bincode::serialize(&transaction).unwrap();
        let id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&raw]);
        node.admit(raw.clone(), true).unwrap();
        let sequence = node.mempool_order.by_id[&id];
        node.mempool_test_limits = Some((1, MAX_MEMPOOL_BYTES));
        node.public.proposal_max_transactions = Some(1);
        let actions = node.machine.tick(node.now()).unwrap();
        node.persist(&actions).unwrap();
        node.pending.extend(actions);
        node.drive().unwrap();
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&1));
        assert!(
            node.mempool.contains_key(&id),
            "unknown hash must retain its admitted full wire"
        );
        assert_eq!(node.mempool[&id].raw, raw);
        assert_eq!(node.mempool_order.by_id[&id], sequence);
        assert_eq!(node.gossip_log[&sequence], id);
        assert_eq!(node.mempool.bytes, raw.len());
        node.produce().unwrap();
        assert!(!node.pipeline.as_ref().unwrap().producer.busy);
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(2)
                .unwrap()
                .is_none()
        );
        node.public.start_unix_ms -= node.public.block_time_ms;
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&2));
        assert_eq!(node.mempool[&id].raw, raw);
        assert_eq!(
            node.runtime.lock().unwrap().archives[&node.proposed[&2].marker.block_commitment].len(),
            0
        );
        let following = bincode::serialize(&pipeline_transfer(&node, &root, 42)).unwrap();
        assert!(
            node.admit(following, false)
                .unwrap_err()
                .downcast_ref::<MempoolFull>()
                .is_some()
        );
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(root.transaction_count(), 0);
        assert_eq!(node.finalized_transactions, 0);
    }

    #[test]
    fn native_pipeline_unknown_hash_heads_do_not_starve_valid_wire_or_changed_parent() {
        let (_directory, mut node, mut signers) =
            repair_fixture_with_signers_and_fee(32, Some(5_000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let valid = pipeline_transfer(&node, &root, 7);
        let valid_wire = bincode::serialize(&valid).unwrap();
        let predicted =
            Arc::new(Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap());
        let first_record = process_with_status(&predicted, valid.clone()).unwrap();
        complete_bank(
            &predicted,
            &node.chain,
            &anchor.hash,
            &encode_block(std::slice::from_ref(&valid_wire)).unwrap(),
        );
        let future = pipeline_transfer(&node, &predicted, 11);
        let unknown = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[node.local]),
                    system_instruction::transfer(
                        &node.local,
                        &Pubkey::new_from_array([0xa8; 32]),
                        13,
                    ),
                ],
                Some(&node.local),
                &Hash::new_unique(),
            )),
            &root.pq_config().unwrap().unwrap(),
            &[&node.leader],
        )
        .unwrap();
        let wires = [
            bincode::serialize(&future).unwrap(),
            bincode::serialize(&unknown).unwrap(),
            valid_wire,
        ];
        let ids = wires
            .iter()
            .map(|raw| hash_commitment(b"agave-pq-transaction-wire-v1", &[raw]))
            .collect::<Vec<_>>();
        for wire in &wires {
            node.admit(wire.clone(), true).unwrap();
        }
        let sequences = ids
            .iter()
            .map(|id| node.mempool_order.by_id[id])
            .collect::<Vec<_>>();
        node.public.proposal_max_transactions = Some(2);
        let actions = node.machine.tick(node.now()).unwrap();
        node.persist(&actions).unwrap();
        node.pending.extend(actions);
        node.drive().unwrap();
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&1)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let first = node.proposed[&1].clone();
        let first_bank = node.runtime.lock().unwrap().banks[&first.marker.block_commitment].clone();
        assert_eq!(
            node.runtime.lock().unwrap().archives[&first.marker.block_commitment].as_ref(),
            &vec![first_record]
        );
        assert_eq!(
            first_bank.pq_state_commitment(),
            predicted.pq_state_commitment()
        );
        for (id, sequence) in ids[..2].iter().zip(&sequences) {
            assert!(node.mempool.contains_key(id));
            assert_eq!(node.mempool_order.by_id[id], *sequence);
            assert_eq!(node.gossip_log[sequence], *id);
        }
        node.produce().unwrap();
        assert!(
            !node.pipeline.as_ref().unwrap().producer.busy,
            "one eligible wire must obey sparse cadence despite full unusable pool"
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(2)
                .unwrap()
                .is_none()
        );
        node.public.start_unix_ms -= node.public.block_time_ms;
        let serial =
            Bank::new_isolated_pq_child(first_bank.clone(), *first_bank.leader(), 2).unwrap();
        let second_record = process_with_status(&serial, future.clone()).unwrap();
        complete_bank(
            &serial,
            &node.chain,
            &first.marker.block_commitment,
            &encode_block(std::slice::from_ref(&wires[0])).unwrap(),
        );
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed
                .get(&2)
                .is_some_and(|w| node.machine.payload(&w.marker.block_commitment).is_some())
        });
        let second = node.proposed[&2].clone();
        let second_bank =
            node.runtime.lock().unwrap().banks[&second.marker.block_commitment].clone();
        assert_eq!(
            node.runtime.lock().unwrap().archives[&second.marker.block_commitment].as_ref(),
            &vec![second_record]
        );
        assert_eq!(
            second_bank.pq_state_commitment(),
            serial.pq_state_commitment()
        );
        node.produce().unwrap();
        assert!(
            !node.pipeline.as_ref().unwrap().producer.busy,
            "only unusable hashes must not spin finite signing keys"
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(3)
                .unwrap()
                .is_none()
        );
        node.drive().unwrap();
        receive_test_quorum(
            &mut node,
            &mut signers,
            2,
            MessageKind::NotarVote,
            Some(second.marker.block_commitment),
        );
        pump_pipeline_until(&mut node, |node| node.finalized_transactions == 2);
        assert_eq!(node.bank_forks.read().unwrap().root(), 2);
        assert_eq!(
            second_bank.transaction_count(),
            root.transaction_count() + 2
        );
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.mempool[&ids[1]].raw, wires[1]);
        assert_eq!(node.mempool_order.by_id[&ids[1]], sequences[1]);
        assert_eq!(node.gossip_log[&sequences[1]], ids[1]);
        let statuses = node
            .blockstore
            .get_experimental_pq_rooted_transaction_statuses(
                &[
                    future.signatures[0],
                    unknown.signatures[0],
                    valid.signatures[0],
                ],
                2,
            )
            .unwrap();
        assert_eq!(statuses[0].as_ref().unwrap().0, 2);
        assert_eq!(statuses[2].as_ref().unwrap().0, 1);
        assert!(statuses[1].is_none());
    }

    #[test]
    fn native_pipeline_parent_hash_filter_preserves_real_precut_native_nonce_execution() {
        use {
            solana_account::state_traits::StateMutWincode,
            solana_nonce::{
                state::{Data, DurableNonce, State},
                versions::Versions,
            },
        };
        let authority = solana_keypair::Keypair::new();
        let address = authority.pubkey();
        let nonce_address = Pubkey::new_unique();
        let nonce = Data::new(
            address,
            DurableNonce::from_blockhash(&Hash::new_unique()),
            5_000,
        );
        let nonce_versions = Versions::new(State::Initialized(nonce.clone()));
        let (directory, mut node, _signers) =
            repair_fixture_configured(32, Some(5_000), 1000, |genesis| {
                genesis.accounts.insert(
                    address,
                    Account {
                        lamports: 10_000_000,
                        ..Account::default()
                    },
                );
                genesis.accounts.insert(
                    nonce_address,
                    solana_account::AccountSharedData::new_data(
                        genesis.rent.minimum_balance(State::size()).max(1),
                        &nonce_versions,
                        &solana_sdk_ids::system_program::id(),
                    )
                    .unwrap()
                    .into(),
                );
            });
        let root = node.bank_forks.read().unwrap().root_bank();
        assert!(!root.is_blockhash_valid(&nonce.blockhash()));
        let transaction = VersionedTransaction::from(Transaction::new_signed_with_payer(
            &[
                system_instruction::advance_nonce_account(&nonce_address, &address),
                system_instruction::transfer(&address, &Pubkey::new_from_array([0xa8; 32]), 17),
            ],
            Some(&address),
            &[&authority],
            nonce.blockhash(),
        ));
        let mut eligibility = ParentHashEligibility::new(&root);
        assert!(eligibility.eligible(&transaction));
        let mut padded = transaction.clone();
        match &mut padded.message {
            VersionedMessage::Legacy(message) => message.instructions[0].data.push(0),
            _ => unreachable!(),
        }
        assert!(
            eligibility.eligible(&padded),
            "native nonce prefix permits trailing data"
        );
        let mut unresolved = transaction.clone();
        if let VersionedMessage::Legacy(message) = unresolved.message {
            let mut v0 = solana_message::v0::Message {
                header: message.header,
                account_keys: vec![address],
                recent_blockhash: nonce.blockhash(),
                instructions: message.instructions,
                address_table_lookups: vec![],
            };
            v0.instructions[0].program_id_index = 1;
            unresolved.message = VersionedMessage::V0(v0);
        }
        assert!(
            eligibility.eligible(&unresolved),
            "unresolved V0 nonce program remains native-checked"
        );
        if let VersionedMessage::V0(message) = &mut unresolved.message {
            message.instructions[0].data = vec![1, 2, 3];
        }
        assert!(
            !eligibility.eligible(&unresolved),
            "unknown V0 programs with non-nonce data must not admit the whole pool"
        );
        let mut normal = pipeline_transfer(&node, &root, 1);
        for _ in 0..ParentHashEligibility::MAX_HASHES + 1 {
            normal.message.set_recent_blockhash(Hash::new_unique());
            assert!(!eligibility.eligible(&normal));
        }
        assert_eq!(eligibility.hashes.len(), ParentHashEligibility::MAX_HASHES);
        assert!(!eligibility.eligible(&normal));
        let raw = bincode::serialize(&transaction).unwrap();
        node.admit(raw.clone(), false).unwrap();
        let anchor = node.adopted_anchor().unwrap();
        let serial = Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap();
        let account = serial.get_account_with_fixed_root(&nonce_address).unwrap();
        assert!(
            solana_nonce_account::verify_nonce_account(&account, &nonce.blockhash()).is_some(),
            "actual initialized nonce account must bind its original hash"
        );
        let sanitized = RuntimeTransaction::<SanitizedTransaction>::try_create(
            transaction.clone(),
            MessageHash::Compute,
            None,
            &serial,
            serial.get_reserved_account_keys(),
        )
        .unwrap();
        assert_eq!(sanitized.get_durable_nonce(), Some(&nonce_address));
        let record = process_with_status(&serial, transaction.clone()).unwrap();
        assert_eq!(record.1.status, Ok(()));
        assert_eq!(record.1.fee, 5_000);
        complete_bank(
            &serial,
            &node.chain,
            &anchor.hash,
            &encode_block(&[raw]).unwrap(),
        );
        let actions = node.machine.tick(node.now()).unwrap();
        node.persist(&actions).unwrap();
        node.pending.extend(actions);
        node.drive().unwrap();
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&1));
        let hash = node.proposed[&1].marker.block_commitment;
        let bank = node.runtime.lock().unwrap().banks[&hash].clone();
        assert_eq!(bank.pq_state_commitment(), serial.pq_state_commitment());
        assert_eq!(
            node.runtime.lock().unwrap().archives[&hash].as_ref(),
            &vec![record]
        );
        assert_eq!(
            bank.get_balance(&address),
            root.get_balance(&address) - 17 - 5_000
        );
        assert_eq!(
            bank.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            root.get_balance(&Pubkey::new_from_array([0xa8; 32])) + 17
        );
        assert_ne!(
            bank.get_account(&nonce_address).unwrap().data(),
            root.get_account(&nonce_address).unwrap().data()
        );
        assert_eq!(root.transaction_count(), 0);
        assert!(directory.path().is_dir());
    }

    #[test]
    fn native_pipeline_obsolete_result_retains_future_hash_and_other_rejects_until_valid_parent() {
        let (_directory, mut node, mut signers, original, later) =
            native_parent_reauthorization_fixture_with_fee(Some(5_000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let competing = pipeline_peer_witness(&node, &root, 5, later, 31);
        let competing_hash = competing.marker.block_commitment;
        node.complete(competing).unwrap();
        node.drive().unwrap();
        let matching = node.runtime.lock().unwrap().banks[&competing_hash].clone();
        assert_ne!(matching.last_blockhash(), root.last_blockhash());
        let transactions = [
            pipeline_transfer(&node, &matching, 41),
            pipeline_transfer(&node, &matching, u64::MAX),
            pipeline_lock_limit_transfer(&node, &root),
        ];
        let wires = transactions
            .iter()
            .map(|tx| bincode::serialize(tx).unwrap())
            .collect::<Vec<_>>();
        let ids = wires
            .iter()
            .map(|raw| hash_commitment(b"agave-pq-transaction-wire-v1", &[raw]))
            .collect::<Vec<_>>();
        for wire in &wires {
            node.admit(wire.clone(), true).unwrap();
        }
        let sequences = ids
            .iter()
            .map(|id| node.mempool_order.by_id[id])
            .collect::<Vec<_>>();
        node.public.proposal_max_transactions = Some(3);
        let mut pipeline = PqPipeline::new().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.gate_first_production(entered, released).unwrap();
        node.pipeline = Some(pipeline);
        assert_eq!(node.production.unwrap().parent, original);
        node.produce().unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        // Delay the REAL producer's authenticated channel messages. Its
        // separate result remains held while a competing branch certifies.
        let held_stream = node
            .pipeline
            .as_ref()
            .unwrap()
            .stream_receiver
            .as_ref()
            .unwrap()
            .try_iter()
            .collect::<Vec<_>>();
        assert!(!held_stream.is_empty());
        let intent = node
            .blockstore
            .get_experimental_pq_proposal_intent(5)
            .unwrap()
            .unwrap();
        assert_eq!(intent.parent, original);
        assert_eq!(intent.payload, encode_block(&[]).unwrap());
        receive_test_quorum(
            &mut node,
            &mut signers,
            4,
            MessageKind::NotarFallbackVote,
            Some(later),
        );
        receive_test_quorum(
            &mut node,
            &mut signers,
            5,
            MessageKind::NotarVote,
            Some(competing_hash),
        );
        pump_pipeline_until(&mut node, |node| {
            node.bank_forks.read().unwrap().root() == 5 && node.finalized_transactions == 3
        });
        assert!(Arc::ptr_eq(
            &matching,
            &node.bank_forks.read().unwrap().root_bank()
        ));
        // Reproduce the exact cross-channel race: after the coordinator's
        // initial drain, deliver all held DATA/terminal events and make the
        // obsolete ProducerOutput ready before the same turn polls it.
        let (drained, at_drain) = bounded(1);
        let (continue_poll, continue_after_drain) = bounded(1);
        let pipeline = node.pipeline.as_mut().unwrap();
        let output_ready = pipeline.producer.result_observer();
        let sender = pipeline.stream_sender.clone();
        pipeline.after_stream_drain_gate = Some(pipeline::ArchiveGate {
            entered: drained,
            release: continue_after_drain,
            fail: false,
        });
        let delivery = thread::spawn(move || {
            at_drain.recv_timeout(Duration::from_secs(5)).unwrap();
            for event in held_stream {
                sender.send(event).unwrap();
            }
            release.send(()).unwrap();
            let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
            while output_ready.is_empty() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(1));
            }
            continue_poll.send(()).unwrap();
        });
        let polled = node.poll_pipeline();
        delivery.join().unwrap();
        polled.unwrap();
        assert!(!node.pipeline.as_ref().unwrap().producer.busy);
        assert!(node.streaming.is_empty());
        assert!(
            !node
                .pipeline
                .as_ref()
                .unwrap()
                .stream_receiver
                .as_ref()
                .unwrap()
                .is_empty()
        );
        node.poll_pipeline().unwrap();
        assert!(
            node.streaming.is_empty(),
            "retired producer stream resurrected from late channel events"
        );
        for ((id, wire), sequence) in ids.iter().zip(&wires).zip(&sequences) {
            assert!(
                node.mempool.contains_key(id),
                "obsolete result pruned an admitted wire"
            );
            assert_eq!(node.mempool[id].raw, *wire);
            assert_eq!(node.mempool_order.by_id[id], *sequence);
            assert_eq!(node.gossip_log[sequence], *id);
        }
        let obsolete = node.proposed[&5].marker.block_commitment;
        assert!(node.machine.payload(&obsolete).is_none());
        assert!(!node.runtime.lock().unwrap().banks.contains_key(&obsolete));
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap(),
            intent
        );
        assert_eq!(node.finalized_transactions, 3);
        for slot in 6..=8 {
            receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
        }
        assert_eq!(node.production.unwrap().parent, competing_hash);
        let serial = Bank::new_isolated_pq_child(matching.clone(), *matching.leader(), 9).unwrap();
        let serial_records = transactions[..2]
            .iter()
            .map(|tx| process_with_status(&serial, tx.clone()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(serial_records[0].1.status, Ok(()));
        assert!(serial_records[1].1.status.is_err());
        assert_eq!(serial_records[0].1.fee, 5_000);
        assert_eq!(serial_records[1].1.fee, 5_000);
        complete_bank(
            &serial,
            &node.chain,
            &competing_hash,
            &encode_block(&wires[..2]).unwrap(),
        );
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| {
            node.proposed.get(&9).is_some_and(|witness| {
                node.machine
                    .payload(&witness.marker.block_commitment)
                    .is_some()
            })
        });
        let witness = node.proposed[&9].clone();
        let bank = node.runtime.lock().unwrap().banks[&witness.marker.block_commitment].clone();
        assert_eq!(bank.pq_state_commitment(), serial.pq_state_commitment());
        assert_eq!(
            node.runtime.lock().unwrap().archives[&witness.marker.block_commitment].as_ref(),
            &serial_records
        );
        assert!(
            !node.mempool.contains_key(&ids[2]),
            "ordinary applicable lock-limit rejection must still prune"
        );
        receive_test_quorum(
            &mut node,
            &mut signers,
            9,
            MessageKind::NotarVote,
            Some(witness.marker.block_commitment),
        );
        pump_pipeline_until(&mut node, |node| node.finalized_transactions == 5);
        assert_eq!(node.bank_forks.read().unwrap().root(), 9);
        assert_eq!(bank.transaction_count(), matching.transaction_count() + 2);
        assert_eq!(
            bank.get_balance(&node.local),
            matching.get_balance(&node.local) - 41 - 5_000
        );
        assert_eq!(
            bank.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            matching.get_balance(&Pubkey::new_from_array([0xa8; 32])) + 41
        );
        let statuses = node
            .blockstore
            .get_experimental_pq_rooted_transaction_statuses(
                &transactions[..2]
                    .iter()
                    .map(|tx| tx.signatures[0])
                    .collect::<Vec<_>>(),
                9,
            )
            .unwrap();
        assert_eq!(statuses[0].as_ref().unwrap().1.status, Ok(()));
        assert!(statuses[1].as_ref().unwrap().1.status.is_err());
        assert_eq!(node.mempool.len(), 0);
        let submitted = node.submitted;
        for wire in &wires[..2] {
            node.admit(wire.clone(), true).unwrap();
        }
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.submitted, submitted);
        let replay = Bank::new_isolated_pq_child(bank.clone(), *bank.leader(), 10).unwrap();
        for transaction in &transactions[..2] {
            let error = process_with_status(&replay, transaction.clone()).unwrap_err();
            assert_eq!(
                error.downcast_ref::<TransactionError>(),
                Some(&TransactionError::AlreadyProcessed)
            );
        }
        assert_eq!(replay.transaction_count(), bank.transaction_count());
        assert_eq!(
            replay.get_balance(&node.local),
            bank.get_balance(&node.local)
        );
        assert_eq!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap(),
            intent
        );
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn native_pipeline_private_descendants_remain_fenced_through_compaction_and_later_progress() {
        for descendant_in_flight in [true, false] {
            let (_directory, mut node, mut signers, original, later) =
                native_parent_reauthorization_fixture();
            let root = node.bank_forks.read().unwrap().root_bank();
            for amount in [21, 22] {
                node.admit(
                    bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                    false,
                )
                .unwrap();
            }
            node.public.proposal_max_transactions = Some(1);
            let mut pipeline = PqPipeline::new().unwrap();
            let (published, publishing) = bounded(1);
            let (publish_release, publish_released) = bounded(1);
            pipeline
                .gate_first_publication(published, publish_released)
                .unwrap();
            let (produced, producing) = bounded(1);
            let (produce_release, produce_released) = bounded(1);
            if descendant_in_flight {
                pipeline
                    .gate_production_slot(6, produced, produce_released)
                    .unwrap();
            }
            node.pipeline = Some(pipeline);
            node.produce().unwrap();
            pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
            publishing.recv_timeout(Duration::from_secs(5)).unwrap();
            let private_parent = node.proposed[&5].marker.block_commitment;
            let first_intent = node
                .blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .unwrap();
            assert_eq!(first_intent.parent, original);
            assert!(!node.block_slots.contains_key(&private_parent));
            assert!(node.machine.payload(&private_parent).is_none());
            assert!(!node.obsolete_local_ancestry(
                6,
                private_parent,
                *node.machine.finalized_chain().last().unwrap(),
            ));
            node.produce().unwrap();
            if descendant_in_flight {
                pump_pipeline_and_dispatch_until(&mut node, |node| {
                    node.pipeline
                        .as_ref()
                        .unwrap()
                        .producer_reservation
                        .is_some_and(|reserved| reserved.next == 6)
                });
                producing.recv_timeout(Duration::from_secs(5)).unwrap();
            } else {
                pump_pipeline_and_dispatch_until(&mut node, |node| node.proposed.contains_key(&6));
                assert_eq!(node.proposed[&6].marker.parent, private_parent);
                assert_eq!(node.pipeline.as_ref().unwrap().publishing.len(), 2);
            }
            let second_intent = node
                .blockstore
                .get_experimental_pq_proposal_intent(6)
                .unwrap()
                .unwrap();
            assert_eq!(second_intent.parent, private_parent);
            assert!(
                node.blockstore
                    .get_experimental_pq_block(5, [0; 48])
                    .unwrap()
                    .is_none()
            );
            receive_test_quorum(
                &mut node,
                &mut signers,
                4,
                MessageKind::NotarFallbackVote,
                Some(later),
            );
            let competing = pipeline_peer_witness(&node, &root, 5, later, 31);
            let competing_hash = competing.marker.block_commitment;
            node.complete(competing).unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.machine.payload(&competing_hash).is_some()
            });
            receive_test_quorum(
                &mut node,
                &mut signers,
                5,
                MessageKind::NotarVote,
                Some(competing_hash),
            );
            pump_pipeline_until(&mut node, |node| node.finalized_transactions == 3);
            let anchor = *node.machine.finalized_chain().last().unwrap();
            assert_eq!(anchor.hash, competing_hash);
            assert!(node.obsolete_local_ancestry(6, private_parent, anchor));
            if !descendant_in_flight {
                // Private knowledge is not inserted into raw-peer ancestry:
                // a peer's genuinely unknown parent still remains repairable.
                assert!(!obsolete_witness(
                    &node.proposed[&6],
                    anchor,
                    &node.block_slots,
                    &node.blocks,
                    &node.waiting_parents,
                ));
            }
            assert!(
                node.local_proposal_ancestors_for_compaction(anchor)
                    .unwrap()
                    .contains(&private_parent)
            );
            node.compact().unwrap();
            assert!(node.proposed.contains_key(&5));
            assert!(node.production.is_none());
            assert_eq!(node.bank_forks.read().unwrap().root(), 5);
            assert!(node.obsolete_local_ancestry(6, private_parent, anchor));
            if descendant_in_flight {
                produce_release.send(()).unwrap();
                pump_pipeline_until(&mut node, |node| {
                    !node.pipeline.as_ref().unwrap().producer.busy
                });
                assert!(node.proposed.contains_key(&6));
                assert!(
                    !node
                        .runtime
                        .lock()
                        .unwrap()
                        .banks
                        .contains_key(&node.proposed[&6].marker.block_commitment)
                );
            }
            let private_child = node.proposed[&6].marker.block_commitment;
            publish_release.send(()).unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.pipeline.as_ref().unwrap().publishing.is_empty()
            });
            assert!(node.machine.payload(&private_parent).is_none());
            assert!(node.machine.payload(&private_child).is_none());
            assert_eq!(node.finalized_transactions, 3);
            for (slot, intent) in [(5, first_intent), (6, second_intent)] {
                assert_eq!(
                    node.blockstore
                        .get_experimental_pq_proposal_intent(slot)
                        .unwrap()
                        .unwrap(),
                    intent
                );
            }
            assert!(
                node.local_proposal_ancestors_for_compaction(anchor)
                    .unwrap()
                    .is_empty()
            );
            node.compact().unwrap();
            // QG retains four windows of checkpoint history: at certified5
            // the durable checkpoint is still1, independently of private
            // worker ancestry. Preserve that ordinary history retention.
            assert!(node.proposed.contains_key(&5));
            for slot in 6..=8 {
                receive_test_quorum(&mut node, &mut signers, slot, MessageKind::SkipVote, None);
            }
            assert_eq!(node.production.unwrap().first, 9);
            node.produce().unwrap();
            pump_pipeline_until(&mut node, |node| {
                node.proposed.get(&9).is_some_and(|witness| {
                    node.machine
                        .payload(&witness.marker.block_commitment)
                        .is_some()
                })
            });
            let next = node.proposed[&9].marker.block_commitment;
            assert_eq!(node.proposed[&9].marker.parent, competing_hash);
            receive_test_quorum(
                &mut node,
                &mut signers,
                9,
                MessageKind::NotarVote,
                Some(next),
            );
            pump_pipeline_until(&mut node, |node| node.finalized_transactions == 4);
            assert_eq!(node.bank_forks.read().unwrap().root(), 9);
            assert_eq!(node.invalid_packets, 0);
        }
    }

    #[test]
    fn native_pipeline_dispatches_deferred_child_immediately_after_parent_installation() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let parent = pipeline_peer_witness(&node, &root, 1, anchor.hash, 7);
        let child = pipeline_peer_witness(&node, &root, 2, parent.marker.block_commitment, 8);
        let child_hash = child.marker.block_commitment;
        let child_payload = node
            .authenticate_witness(&child)
            .unwrap()
            .payload()
            .to_vec();
        node.pipeline = Some(PqPipeline::new().unwrap());
        let last_retry = node.last_retry;
        node.complete(child.clone()).unwrap();
        assert!(node.waiting_parents.contains_key(&child_hash));
        assert!(!node.pipeline.as_ref().unwrap().candidate.busy);
        node.complete(parent.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !node.blocks.contains_key(&parent.marker.block_commitment) {
            assert!(Instant::now() < deadline);
            node.poll_pipeline().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(node.last_retry, last_retry);
        assert!(node.pipeline.as_ref().unwrap().candidate.busy);
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .executing
                .contains_key(&child_hash)
        );
        assert!(!node.waiting_parents.contains_key(&child_hash));
        assert_eq!(node.waiting_parent_bytes, 0);
        assert!(
            node.machine
                .payload(&parent.marker.block_commitment)
                .is_some()
        );
        assert!(node.machine.payload(&child_hash).is_none());
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        pump_pipeline_until(&mut node, |node| node.blocks.contains_key(&child_hash));
        let banks = node.runtime.lock().unwrap();
        let bank = &banks.banks[&child_hash];
        assert!(bank.is_frozen());
        assert_eq!(bank.parent_slot(), 1);
        assert_eq!(bank.transaction_count(), root.transaction_count() + 2);
        assert_eq!(
            bank.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            root.get_balance(&Pubkey::new_from_array([0xa8; 32])) + 15
        );
        assert_eq!(
            node.machine.payload(&child_hash),
            Some(child_payload.as_slice())
        );
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn native_pipeline_parallel_shred_decode_preserves_canonical_errors_and_completed_order() {
        let (directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let witness = pipeline_peer_witness(&node, &root, 1, anchor.hash, 7);
        let peer = *node.outbound.keys().next().unwrap();
        let frames = witness.shreds[..2]
            .iter()
            .map(|shred| {
                let mut frame = vec![1];
                frame.extend(shred.encode().unwrap());
                (peer, frame)
            })
            .collect::<Vec<_>>();
        let storage = node.blockstore.clone();
        let before = storage.get_experimental_pq_checkpoint().unwrap();
        let ax = std::fs::read(directory.path().join("ax")).unwrap();
        let state = bank_state(&root);
        let (entered, entering) = bounded(2);
        let (release, released) = bounded(2);
        node.shred_decode_probe = Some(Arc::new(EvidenceAuthenticationProbe {
            entered,
            release: released,
        }));
        let owner = thread::spawn(move || {
            let id = thread::current().id();
            node.receive_batch(frames).unwrap();
            (id, node)
        });
        let first = entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(
            first, second,
            "canonical signature decoders must run on distinct existing workers"
        );
        assert_eq!(storage.get_experimental_pq_checkpoint().unwrap(), before);
        assert_eq!(std::fs::read(directory.path().join("ax")).unwrap(), ax);
        assert_eq!(bank_state(&root), state);
        release.send(()).unwrap();
        release.send(()).unwrap();
        let (owner_id, mut node) = owner.join().unwrap();
        assert_ne!(first, owner_id);
        assert_ne!(second, owner_id);
        assert_eq!(node.assemblers.len(), 1);
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(storage.get_experimental_pq_checkpoint().unwrap(), before);
        node.shred_decode_probe = None;
        let mut good = vec![1];
        good.extend(witness.shreds[0].encode().unwrap());
        let mut bad_signature = good.clone();
        bad_signature[1 + witness.shreds[0].metadata.encode().len()] = 0;
        let mut bad_nonce = good.clone();
        bad_nonce[1 + witness.shreds[0].metadata.encode().len() + 1] ^= 1;
        let mut outside = witness.shreds[0].clone();
        outside.metadata.context.slot = node.public.first_slot + node.public.slot_count;
        let mut bad_slot = vec![1];
        bad_slot.extend(outside.encode().unwrap());
        let mut trailing = good.clone();
        trailing.push(0);
        let frames = vec![
            (peer, good),
            (peer, bad_signature),
            (peer, bad_slot),
            (peer, trailing),
            (peer, bad_nonce),
            (peer, vec![3, 0]),
        ];
        // Exact old serial decode/range order, retained only as a parser oracle.
        let serial = frames
            .iter()
            .enumerate()
            .filter_map(|(position, (_, frame))| {
                if frame.first() != Some(&1) {
                    return None;
                }
                let decoded = (|| -> Result<_> {
                    let shred = AuthenticatedShred::decode(&frame[1..])?;
                    ensure!(
                        (node.public.first_slot..node.public.first_slot + node.public.slot_count)
                            .contains(&shred.metadata.context.slot),
                        "PQ shred slot"
                    );
                    Ok(shred.encode().unwrap())
                })()
                .map_err(|error| format!("{error:#}"));
                Some((position, decoded))
            })
            .collect::<Vec<_>>();
        let parallel = node
            .decode_shred_frames(&frames)
            .into_iter()
            .map(|(position, decoded)| {
                (
                    position,
                    decoded
                        .map(|shred| shred.encode().unwrap())
                        .map_err(|error| format!("{error:#}")),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(parallel, serial);
        node.completed_candidates
            .insert((witness.marker.slot, witness.marker.candidate));
        let decodes = node.shred_decode_work.load(Ordering::Relaxed);
        node.receive_batch(frames[..5].to_vec()).unwrap();
        assert_eq!(
            node.shred_decode_work.load(Ordering::Relaxed) - decodes,
            5,
            "each actual DATA frame decodes once, including completed fallback"
        );
        assert_eq!(
            node.invalid_packets, 3,
            "completed candidates reject malformed canonical/range/trailing inputs but ignore \
             canonical bad nonce before verification"
        );
        assert_eq!(storage.get_experimental_pq_checkpoint().unwrap(), before);
        assert_eq!(bank_state(&root), state);
        assert_eq!(std::fs::read(directory.path().join("ax")).unwrap(), ax);
    }

    #[test]
    fn native_pipeline_saved_completed_decode_rechecks_removal_before_verification() {
        let (directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let witness = pipeline_peer_witness(&node, &root, 1, anchor.hash, 7);
        let index = (witness.marker.slot, witness.marker.candidate);
        let peer = *node.outbound.keys().next().unwrap();
        let mut frame = vec![1];
        frame.extend(witness.shreds[0].encode().unwrap());
        // The nonce is outside the canonical coefficients but inside the signed
        // message. Parsing succeeds; actual Falcon authentication must reject it.
        frame[1 + witness.shreds[0].metadata.encode().len() + 1] ^= 1;
        node.completed_candidates.insert(index);
        let mut decoded = node.decode_shred_frames(&[(peer, frame.clone())]);
        let saved = decoded.remove(&0).unwrap().unwrap();
        let ax = std::fs::read(directory.path().join("ax")).unwrap();
        let before = node.blockstore.get_experimental_pq_checkpoint().unwrap();
        let state = bank_state(&root);
        // Controlled lifetime change between preparation and arrival. This is
        // deliberately not a claim that compaction runs concurrently in a batch.
        node.completed_candidates.remove(&index);
        let expected = node.receive(peer, &frame).unwrap_err();
        assert!(!fatal_receive_error(&expected));
        let parses = node.shred_decode_work.load(Ordering::Relaxed);
        let actual = node.receive_decoded_shred(saved).unwrap_err();
        assert_eq!(format!("{actual:#}"), format!("{expected:#}"));
        assert_eq!(
            node.shred_decode_work.load(Ordering::Relaxed),
            parses,
            "current eligibility recheck must reuse the parsed object"
        );
        assert!(node.assemblers.is_empty() && node.markers.is_empty());
        assert!(node.pending.is_empty() && node.seen_evidence.is_empty());
        assert_eq!(
            node.blockstore.get_experimental_pq_checkpoint().unwrap(),
            before
        );
        assert_eq!(std::fs::read(directory.path().join("ax")).unwrap(), ax);
        assert_eq!(bank_state(&root), state);
        assert_eq!(node.machine.recovery_record_count(), 0);
    }

    #[test]
    fn native_pipeline_evidence_authentication_runs_on_distinct_workers_before_ordered_apply() {
        let (directory, mut node, signers) = repair_fixture_with_signers(32);
        let peer = *node.outbound.keys().next().unwrap();
        let mut frames = Vec::new();
        for slot in [1, 2] {
            let evidence = signers[0]
                .sign(ConsensusMessage {
                    epoch: node.public.epoch,
                    slot,
                    kind: MessageKind::NotarVote,
                    block: Some([slot as u8; 48]),
                })
                .unwrap();
            let mut frame = vec![3];
            frame.extend(evidence.encode().unwrap());
            frames.push((peer, frame));
        }
        let storage = node.blockstore.clone();
        let before = storage.get_experimental_pq_checkpoint().unwrap();
        let ax = std::fs::read(directory.path().join("ax")).unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let state = bank_state(&root);
        let (entered, entering) = bounded(2);
        let (release, released) = bounded(2);
        node.evidence_authentication_probe = Some(Arc::new(EvidenceAuthenticationProbe {
            entered,
            release: released,
        }));
        let owner = thread::spawn(move || {
            let owner_id = thread::current().id();
            node.receive_batch(frames).unwrap();
            (owner_id, node)
        });
        let first = entering.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(
            first, second,
            "two real Ax inputs must dispatch on different existing pool workers"
        );
        assert_eq!(
            storage.get_experimental_pq_checkpoint().unwrap(),
            before,
            "authentication alone cannot append or apply the input group"
        );
        assert_eq!(std::fs::read(directory.path().join("ax")).unwrap(), ax);
        assert_eq!(bank_state(&root), state);
        release.send(()).unwrap();
        release.send(()).unwrap();
        let (owner_id, node) = owner.join().unwrap();
        assert_ne!(first, owner_id);
        assert_ne!(second, owner_id);
        assert_eq!(node.seen_evidence.len(), 2);
        assert_eq!(node.machine.recovery_record_count(), 2);
        assert_eq!(node.durable_journal_records, 2);
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        assert_eq!(bank_state(&root), state);
        let validators = std::iter::once(PqValidator {
            id: node.local.to_bytes(),
            stake: 1,
            key: node.signer.public_key(),
        })
        .chain(signers.iter().map(|s| PqValidator {
            id: s.public_key().epoch().validator,
            stake: 1,
            key: s.public_key(),
        }))
        .collect();
        let raw = storage.get_experimental_pq_checkpoint().unwrap().unwrap();
        let restored = Quantumglow::restore(
            node.machine.config().clone(),
            node.local.to_bytes(),
            validators,
            agave_pq_crypto::quantumglow::RecoveryJournal::decode(&raw).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.recovery_journal().encode().unwrap(), raw);
        assert_eq!(
            restored.retransmission_intents(),
            node.machine.retransmission_intents()
        );
    }

    #[test]
    fn native_pipeline_prepared_evidence_wire_guard_and_real_wal_failure_have_no_external_effects()
    {
        let (directory, mut node, signers) = repair_fixture_with_signers_and_fee(32, Some(5000));
        let root = node.bank_forks.read().unwrap().root_bank();
        let state = bank_state(&root);
        let evidence = signers[0]
            .sign(ConsensusMessage {
                epoch: node.public.epoch,
                slot: 1,
                kind: MessageKind::SkipVote,
                block: None,
            })
            .unwrap();
        let raw = evidence.encode().unwrap();
        let prepared = node.machine.evidence_verifier().prepare(evidence);
        let mut wrong = hash_commitment(b"agave-pq-evidence-wire-v1", &[&raw]);
        wrong[47] ^= 1;
        let ax = std::fs::read(directory.path().join("ax")).unwrap();
        assert!(fatal_receive_error(
            &node.receive_prepared_evidence(wrong, prepared).unwrap_err()
        ));
        assert_eq!(node.machine.recovery_record_count(), 0);
        assert!(node.pending.is_empty() && node.seen_evidence.is_empty());
        assert!(
            node.blockstore
                .get_experimental_pq_checkpoint()
                .unwrap()
                .is_none()
        );
        node.pipeline = Some(PqPipeline::new().unwrap());
        node.durable_journal_records = 1;
        let mut frame = vec![3];
        frame.extend(raw);
        let wire = bincode::serialize(&pipeline_transfer(&node, &root, 21)).unwrap();
        let mut transaction = vec![4];
        transaction.extend_from_slice(&wire);
        let peer = *node.outbound.keys().next().unwrap();
        let error = node
            .receive_batch(vec![(peer, frame), (peer, vec![1, 0]), (peer, transaction)])
            .unwrap_err();
        assert!(fatal_receive_error(&error));
        assert!(
            error
                .downcast_ref::<solana_ledger::blockstore::error::BlockstoreError>()
                .is_some()
        );
        assert!(node.pipeline.as_ref().unwrap().journal_failed);
        assert!(node.pipeline.as_ref().unwrap().stop.load(Ordering::Acquire));
        assert!(
            node.mempool.is_empty() && node.pending.is_empty() && node.seen_evidence.is_empty()
        );
        assert!(node.received_evidence.is_none());
        assert_eq!(
            node.invalid_packets, 0,
            "failed group WAL precedes later prepared DATA error"
        );
        assert!(
            node.blockstore
                .get_experimental_pq_checkpoint()
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(directory.path().join("ax")).unwrap(), ax);
        assert_eq!(bank_state(&root), state);
        assert!(fatal_receive_error(&node.admit(wire, true).unwrap_err()));
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
    }

    #[test]
    fn native_pipeline_commits_authentic_consensus_group_once_with_exact_recovery_and_roots() {
        let (_directory, mut node, signers) = repair_fixture_with_signers(32);
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let first = pipeline_peer_witness(&node, &root, 1, anchor.hash, 7);
        let second = pipeline_peer_witness(&node, &root, 2, first.marker.block_commitment, 8);
        node.complete(first.clone()).unwrap();
        node.complete(second.clone()).unwrap();
        let before = node
            .blockstore
            .get_experimental_pq_checkpoint()
            .unwrap()
            .unwrap();
        let before_usage = node
            .blockstore
            .experimental_pq_journal_usage()
            .unwrap()
            .unwrap();
        let peer = *node.outbound.keys().next().unwrap();
        let mut frames = Vec::new();
        for (slot, hash) in [
            (1, first.marker.block_commitment),
            (2, second.marker.block_commitment),
        ] {
            for kind in [
                MessageKind::NotarVote,
                MessageKind::NotarApproval,
                MessageKind::FinalVote,
            ] {
                for signer in &signers {
                    let evidence = signer
                        .sign(ConsensusMessage {
                            epoch: node.public.epoch,
                            slot,
                            kind,
                            block: (kind != MessageKind::FinalVote).then_some(hash),
                        })
                        .unwrap();
                    let mut frame = vec![3];
                    frame.extend(evidence.encode().unwrap());
                    frames.push((peer, frame));
                }
            }
        }
        let count = frames.len();
        frames.insert(9, (peer, vec![3, 0]));
        frames.push(frames[0].clone());
        node.receive_batch(frames).unwrap();
        let after = node
            .blockstore
            .get_experimental_pq_checkpoint()
            .unwrap()
            .unwrap();
        let after_usage = node
            .blockstore
            .experimental_pq_journal_usage()
            .unwrap()
            .unwrap();
        assert_eq!(after_usage.chunks, before_usage.chunks + 1);
        assert_eq!(after_usage.records, before_usage.records + count as u32);
        assert_eq!(&after[53..before.len()], &before[53..]);
        assert_eq!(node.durable_journal_records, after_usage.records);
        assert_eq!(node.seen_evidence.len(), count);
        assert_eq!(node.invalid_packets, 1);
        assert!(node.blockstore.is_root(1) && node.blockstore.is_root(2));
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        let finalized = node
            .pending
            .iter()
            .filter_map(|action| {
                if let Action::Finalized(block) = action {
                    Some(block.slot)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(finalized, [1, 2]);
        let validators = std::iter::once(PqValidator {
            id: node.local.to_bytes(),
            stake: 1,
            key: node.signer.public_key(),
        })
        .chain(signers.iter().map(|signer| PqValidator {
            id: signer.public_key().epoch().validator,
            stake: 1,
            key: signer.public_key(),
        }))
        .collect();
        let journal = agave_pq_crypto::quantumglow::RecoveryJournal::decode(&after).unwrap();
        let restored = Quantumglow::restore(
            node.machine.config().clone(),
            node.local.to_bytes(),
            validators,
            journal.clone(),
        )
        .unwrap();
        assert_eq!(restored.recovery_journal().encode().unwrap(), after);
        assert_eq!(restored.finalized_chain(), node.machine.finalized_chain());
        assert_eq!(
            restored.payload(&second.marker.block_commitment),
            node.machine.payload(&second.marker.block_commitment)
        );
        assert!(node.received_evidence.is_none());
        node.drive().unwrap();
        assert_eq!(node.bank_forks.read().unwrap().root(), 2);
        assert_eq!(node.finalized_transactions, 2);
    }

    #[test]
    fn native_pipeline_authentic_evidence_ledger_failure_stops_frame_batch_before_actions() {
        for phantom_cursor in [1, 2] {
            let (_directory, mut node, signers) = repair_fixture_with_signers(32);
            let root = node.bank_forks.read().unwrap().root_bank();
            let peer = *node.outbound.keys().next().unwrap();
            let evidence = signers[0]
                .sign(ConsensusMessage {
                    epoch: node.public.epoch,
                    slot: 1,
                    kind: MessageKind::SkipVote,
                    block: None,
                })
                .unwrap();
            let mut frame = vec![3];
            frame.extend(evidence.encode().unwrap());
            let mut transaction = vec![4];
            transaction.extend(bincode::serialize(&pipeline_transfer(&node, &root, 21)).unwrap());
            // Inject a phantom durable cursor. The actual Blockstore append rejects
            // it, without a mock error or a test-only storage implementation.
            node.durable_journal_records = phantom_cursor;
            let error = node
                .receive_batch(vec![(peer, frame), (peer, transaction)])
                .unwrap_err();
            if phantom_cursor == 1 {
                assert!(
                    error
                        .downcast_ref::<solana_ledger::blockstore::error::BlockstoreError>()
                        .is_some()
                );
            } else {
                assert_eq!(
                    error.downcast_ref::<QuantumglowError>(),
                    Some(&QuantumglowError::Journal)
                );
            }
            assert!(
                node.blockstore
                    .get_experimental_pq_checkpoint()
                    .unwrap()
                    .is_none()
            );
            assert!(node.pending.is_empty());
            assert!(node.production.is_none());
            assert!(node.proposed.is_empty());
            assert!(node.mempool.is_empty());
            assert!(node.seen_evidence.is_empty());
            assert!(!node.receiving_batch);
            assert_eq!(node.invalid_packets, 0);
        }
    }
    #[test]
    fn native_pipeline_malformed_peer_evidence_does_not_stop_following_valid_admission() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let peer = *node.outbound.keys().next().unwrap();
        let mut transaction = vec![4];
        transaction.extend(bincode::serialize(&pipeline_transfer(&node, &root, 21)).unwrap());
        node.receive_batch(vec![(peer, vec![3, 0]), (peer, transaction)])
            .unwrap();
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.mempool.len(), 1);
    }

    #[test]
    fn native_pipeline_authenticated_reconstruction_disconnect_remains_fatal() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let witness = pipeline_peer_witness(&node, &root, 1, anchor.hash, 21);
        let peer = *node.outbound.keys().next().unwrap();
        let mut pipeline = PqPipeline::new().unwrap();
        pipeline.disconnect_reconstruction_requests();
        node.pipeline = Some(pipeline);
        let mut frames = witness
            .shreds
            .iter()
            .map(|shred| {
                let mut frame = vec![1];
                frame.extend(shred.encode().unwrap());
                (peer, frame)
            })
            .collect::<Vec<_>>();
        let mut marker = vec![2];
        marker.extend(witness.marker.encode());
        frames.push((peer, marker));
        let error = node.receive_batch(frames).unwrap_err();
        assert!(error.downcast_ref::<InternalPqError>().is_some());
        assert!(!node.pipeline.as_ref().unwrap().reconstruction.busy);
        assert!(
            node.machine
                .payload(&witness.marker.block_commitment)
                .is_none()
        );
        assert!(
            node.blockstore
                .get_experimental_pq_block(1, witness.marker.block_commitment)
                .unwrap()
                .is_none()
        );
        assert!(node.proposed.is_empty());
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn native_pipeline_four_stream_reservations_preserve_partial_cursors_and_resume() {
        let (directory, mut node, _) = repair_fixture_with_signers_and_fee(32, Some(5_000));
        node.machine = Quantumglow::new(
            node.machine.config().clone(),
            node.local.to_bytes(),
            vec![PqValidator {
                id: node.local.to_bytes(),
                stake: 1,
                key: node.signer.public_key(),
            }],
        )
        .unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        node.public.proposal_max_transactions = Some(1);
        node.public.block_time_ms = 5_000;
        for amount in [7, u64::MAX, 9, u64::MAX - 1] {
            node.admit(
                bincode::serialize(&pipeline_transfer(&node, &root, amount)).unwrap(),
                true,
            )
            .unwrap();
        }
        let mut pipeline = PqPipeline::new().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.gate_first_publication(entered, released).unwrap();
        node.pipeline = Some(pipeline);
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: anchor.hash,
            due: node.now(),
        });
        let deadline = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
        while node.proposed.len() < pipeline::MAX_STREAMING_CANDIDATES {
            assert!(Instant::now() < deadline);
            node.poll_and_dispatch().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        entering.recv_timeout(Duration::from_secs(2)).unwrap();
        node.poll_pipeline().unwrap();
        assert_eq!(node.streaming.len(), pipeline::MAX_STREAMING_CANDIDATES);
        assert_eq!(
            node.pipeline.as_ref().unwrap().publishing.len(),
            pipeline::MAX_STREAMING_CANDIDATES
        );
        let first = node.proposed[&1].clone();
        let last = node.proposed[&4].clone();
        let peer = *node.outbound.keys().next().unwrap();
        let stream = node.streaming.get_mut(&first.marker.candidate).unwrap();
        assert_eq!(stream.frames.len(), first.shreds.len() + 1);
        // Model successful delivery of an authenticated prefix while every
        // later transport send is backpressured. A capacity check cannot reset it.
        stream.cursors.insert(peer, 1);
        let cursors = stream.cursors.clone();
        for witness in node.proposed.values() {
            let stream = &node.streaming[&witness.marker.candidate];
            assert_eq!(stream.frames.len(), witness.shreds.len() + 1);
            assert_eq!(
                FinalMarker::decode(&stream.frames.last().unwrap()[1..])
                    .unwrap()
                    .encode(),
                witness.marker.encode()
            );
            for frame in &stream.frames[..stream.frames.len() - 1] {
                AuthenticatedShred::decode(&frame[1..])
                    .unwrap()
                    .verify(&node.chain, &node.leader.public_key())
                    .unwrap();
            }
        }
        let signed_before = std::fs::read(directory.path().join("ax")).unwrap();
        let admitted = node.mempool_order.iter().copied().collect::<Vec<_>>();
        node.production = Some(Production {
            first: 5,
            next: 5,
            parent: last.marker.block_commitment,
            due: node.now(),
        });
        node.produce().unwrap();
        assert!(!node.pipeline.as_ref().unwrap().producer.busy);
        assert!(
            node.pipeline
                .as_ref()
                .unwrap()
                .producer_reservation
                .is_none()
        );
        assert_eq!(node.streaming[&first.marker.candidate].cursors, cursors);
        assert_eq!(node.streaming.len(), pipeline::MAX_STREAMING_CANDIDATES);
        assert_eq!(
            std::fs::read(directory.path().join("ax")).unwrap(),
            signed_before
        );
        assert_eq!(
            node.mempool_order.iter().copied().collect::<Vec<_>>(),
            admitted
        );
        assert!(
            node.blockstore
                .get_experimental_pq_proposal_intent(5)
                .unwrap()
                .is_none()
        );
        // The actual machine authorizes the next window only after the held
        // publishers are released. Do not turn the synthetic pending capacity
        // probe above into authorization.
        let signatures = (1..=4)
            .map(|slot| {
                let hash = node.proposed[&slot].marker.block_commitment;
                node.runtime.lock().unwrap().archives[&hash][0].0.signatures[0]
            })
            .collect::<Vec<_>>();
        // The next-window unsigned worker may start during release of the
        // first four publishers. Admit its workload before that legitimate
        // early snapshot rather than expecting a prepared empty bank to change.
        let next_transaction = pipeline_transfer(&node, &root, 11);
        let next_signature = next_transaction.signatures[0];
        node.admit(bincode::serialize(&next_transaction).unwrap(), true)
            .unwrap();
        node.production = None;
        release.send(()).unwrap();
        let deadline = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
        while node.bank_forks.read().unwrap().root() < 4 || node.finalized_transactions < 4 {
            assert!(Instant::now() < deadline);
            node.poll_pipeline().unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(node.streaming.is_empty());
        assert!(node.pipeline.as_ref().unwrap().publishing.is_empty());
        let rooted = node.bank_forks.read().unwrap().root_bank();
        assert_eq!(rooted.transaction_count(), root.transaction_count() + 4);
        let statuses = node
            .blockstore
            .get_experimental_pq_rooted_transaction_statuses(&signatures, 4)
            .unwrap();
        assert_eq!(statuses.len(), 4);
        let mut charged = 0u64;
        for ((index, status), success) in
            statuses.iter().enumerate().zip([true, false, true, false])
        {
            let (slot, record) = status.as_ref().unwrap();
            assert_eq!(*slot, u64::try_from(index).unwrap().checked_add(1).unwrap());
            assert_eq!(record.status.is_ok(), success);
            assert_eq!(record.fee, 5_000);
            charged = charged.checked_add(record.fee).unwrap();
        }
        assert_eq!(charged, 20_000);
        // This fixture's payer is also the sole block leader. The bank burns
        // half the fee and credits the other half to that same account.
        assert_eq!(
            rooted.get_balance(&node.local),
            root.get_balance(&node.local) - 16 - charged / 2
        );
        assert!(
            node.machine
                .ready_parents(5)
                .contains(&last.marker.block_commitment)
        );
        assert_eq!(
            node.production.unwrap().parent,
            last.marker.block_commitment
        );
        node.produce().unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&5));
        let next = node.proposed[&5].clone();
        assert_eq!(next.marker.parent, last.marker.block_commitment);
        assert!(node.streaming.len() <= pipeline::MAX_STREAMING_CANDIDATES);
        {
            let runtime = node.runtime.lock().unwrap();
            let archive = &runtime.archives[&next.marker.block_commitment];
            assert_eq!(archive.len(), 1);
            assert_eq!(archive[0].0.signatures[0], next_signature);
        }
        // Producing the fifth candidate is already complete. Rooting it
        // additionally needs the coordinator's consensus action service;
        // poll-only helpers deliberately do not vote or finalize blocks.
        let deadline = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
        while node.bank_forks.read().unwrap().root() < 5 || node.finalized_transactions < 5 {
            assert!(
                Instant::now() < deadline,
                "fifth candidate did not finalize: root={}, finalized={}, proposed={}",
                node.bank_forks.read().unwrap().root(),
                node.finalized_transactions,
                node.proposed.len()
            );
            node.poll_pipeline().unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(node.bank_forks.read().unwrap().root(), 5);
        assert_eq!(node.finalized_transactions, 5);
        let next_status = node
            .blockstore
            .get_experimental_pq_rooted_transaction_statuses(&[next_signature], 5)
            .unwrap();
        let (slot, record) = next_status[0].as_ref().unwrap();
        assert_eq!(*slot, 5);
        assert!(record.status.is_ok());
        assert_eq!(record.fee, 5_000);
        let final_root = node.bank_forks.read().unwrap().root_bank();
        assert_eq!(final_root.transaction_count(), root.transaction_count() + 5);
        assert_eq!(
            final_root.get_balance(&node.local),
            rooted.get_balance(&node.local) - 11 - record.fee / 2
        );
        assert!(node.mempool.is_empty());
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn native_pipeline_extends_frozen_bank_while_first_witness_wal_is_blocked() {
        let (_directory, mut node) = repair_fixture_with_slots(16);
        node.machine = Quantumglow::new(
            node.machine.config().clone(),
            node.local.to_bytes(),
            vec![PqValidator {
                id: node.local.to_bytes(),
                stake: 1,
                key: node.signer.public_key(),
            }],
        )
        .unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let recipient = Pubkey::new_from_array([0xa8; 32]);
        let config = root.pq_config().unwrap().unwrap();
        for amount in [7, u64::MAX] {
            let transaction = sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[
                        authenticate_instruction(&[node.local]),
                        system_instruction::transfer(&node.local, &recipient, amount),
                    ],
                    Some(&node.local),
                    &root.last_blockhash(),
                )),
                &config,
                &[&node.leader],
            )
            .unwrap();
            node.admit(bincode::serialize(&transaction).unwrap(), false)
                .unwrap();
        }
        node.public.proposal_max_transactions = Some(1);
        node.public.block_time_ms = 5_000;
        let mut pipeline = PqPipeline::new().unwrap();
        let (entered, entering) = bounded(1);
        let (release, released) = bounded(1);
        pipeline.gate_first_publication(entered, released).unwrap();
        node.pipeline = Some(pipeline);
        let anchor = node.adopted_anchor().unwrap();
        node.production = Some(Production {
            first: 1,
            next: 1,
            parent: anchor.hash,
            due: node.now(),
        });
        node.produce().unwrap();
        // The actual run-loop helper installs N and dispatches N+1 before
        // processing its collected frame batch. Keep an authentic duplicate
        // transaction frame pending while N's complete WAL is blocked.
        let mut pending_frame = vec![4];
        pending_frame.extend(node.mempool.values().next().unwrap().raw.iter());
        let peer = *node.outbound.keys().next().unwrap();
        let pending_frames = vec![(peer, pending_frame)];
        let deadline = Instant::now() + Duration::from_secs(10);
        while !node.proposed.contains_key(&1)
            || !node
                .pipeline
                .as_ref()
                .unwrap()
                .producer_reservation
                .is_some_and(|reserved| reserved.next == 2)
        {
            assert!(Instant::now() < deadline);
            node.poll_and_dispatch().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pending_frames.len(), 1);
        assert!(node.pipeline.as_ref().unwrap().producer.busy);
        assert_eq!(
            node.pipeline
                .as_ref()
                .unwrap()
                .producer_reservation
                .unwrap()
                .next,
            2
        );
        entering.recv_timeout(Duration::from_secs(2)).unwrap();
        let first = node.proposed[&1].clone();
        let first_bank = node.runtime.lock().unwrap().banks[&first.marker.block_commitment].clone();
        assert!(first_bank.is_frozen());
        assert_eq!(first_bank.transaction_count(), root.transaction_count() + 1);
        assert!(
            node.machine
                .payload(&first.marker.block_commitment)
                .is_none()
        );
        assert!(
            node.blockstore
                .get_experimental_pq_block(1, [0; 48])
                .unwrap()
                .is_none()
        );
        let intent = node
            .blockstore
            .get_experimental_pq_proposal_intent(1)
            .unwrap()
            .unwrap();
        assert_eq!(intent.candidate, first.marker.candidate);
        // Signed batches are available while the complete witness is still
        // blocked. The exact immutable payload intent preceded every batch.
        let frames = &node.streaming[&first.marker.candidate].frames;
        assert_eq!(frames.len(), first.shreds.len() + 1);
        for frame in &frames[..frames.len() - 1] {
            assert_eq!(frame[0], 1);
            let shred = AuthenticatedShred::decode(&frame[1..]).unwrap();
            shred
                .verify(&node.chain, &node.leader.public_key())
                .unwrap();
            assert_eq!(shred.metadata.context.candidate, intent.candidate);
            assert_eq!(shred.metadata.context.parent, intent.parent);
        }
        assert_eq!(frames.last().unwrap()[0], 2);
        let terminal = FinalMarker::decode(&frames.last().unwrap()[1..]).unwrap();
        assert_eq!(terminal.encode(), first.marker.encode());
        // The next full proposal ignores the idle cadence and every peer's
        // delivery cursor. No parent certificate or archived root exists yet.
        for queue in node.outbound.values_mut() {
            queue.blocks.push_back((first.marker.block_commitment, 0));
            queue.queued_blocks.insert(first.marker.block_commitment);
        }
        node.receive_batch(pending_frames).unwrap();
        pump_pipeline_until(&mut node, |node| node.proposed.contains_key(&2));
        let second = node.proposed[&2].clone();
        let second_bank =
            node.runtime.lock().unwrap().banks[&second.marker.block_commitment].clone();
        assert_eq!(second.marker.parent, first.marker.block_commitment);
        assert_eq!(second_bank.parent_slot(), first_bank.slot());
        assert_eq!(
            second_bank.transaction_count(),
            root.transaction_count() + 2
        );
        let first_record =
            node.runtime.lock().unwrap().archives[&first.marker.block_commitment][0].clone();
        let second_record =
            node.runtime.lock().unwrap().archives[&second.marker.block_commitment][0].clone();
        assert_eq!(first_record.1.status, Ok(()));
        assert!(second_record.1.status.is_err());
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
        assert!(
            node.machine
                .payload(&second.marker.block_commitment)
                .is_none()
        );
        assert_eq!(node.pipeline.as_ref().unwrap().publishing.len(), 2);
        release.send(()).unwrap();
        node.production = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while node.bank_forks.read().unwrap().root() < 2 || node.finalized_transactions < 2 {
            assert!(Instant::now() < deadline);
            node.poll_pipeline().unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        let adopted = node.bank_forks.read().unwrap().root_bank();
        assert!(Arc::ptr_eq(&adopted, &second_bank));
        assert_eq!(
            adopted.get_balance(&recipient),
            root.get_balance(&recipient) + 7
        );
        // Both the successful transfer and charged instruction failure are
        // committed exactly once; canonical state and RPC archive agree.
        assert_eq!(adopted.transaction_count(), root.transaction_count() + 2);
        assert_eq!(node.finalized_transactions, 2);
        let statuses = node
            .blockstore
            .get_experimental_pq_rooted_transaction_statuses(
                &[first_record.0.signatures[0], second_record.0.signatures[0]],
                2,
            )
            .unwrap();
        assert_eq!(statuses[0].as_ref().unwrap().0, 1);
        assert_eq!(statuses[0].as_ref().unwrap().1.status, Ok(()));
        assert_eq!(statuses[1].as_ref().unwrap().0, 2);
        assert!(statuses[1].as_ref().unwrap().1.status.is_err());
        assert_eq!(
            adopted.get_balance(&node.local),
            root.get_balance(&node.local) - 7 - first_record.1.fee - second_record.1.fee
        );
        assert_eq!(node.mempool.len(), 0);
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn causal_ancestry_crosses_full_deferred_and_request_bounds_and_refetches() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        let anchor = node.adopted_anchor().unwrap();
        let root = node.bank_forks.read().unwrap().root_bank();
        let root_state = bank_state(&root);
        let payload = encode_block(&[]).unwrap();
        let mut chain = Vec::new();
        let mut parent = anchor.hash;
        for slot in 1..=48 {
            let witness = repair_witness(&node, slot, parent, &payload);
            parent = witness.marker.block_commitment;
            chain.push(witness);
        }
        for slot in 80..112 {
            let far = repair_witness(&node, slot, [0xf1; 48], &payload);
            node.complete(far).unwrap();
        }
        assert_eq!(node.waiting_parents.len(), MAX_BUFFERED_CANDIDATES);
        for ordinal in 0..MAX_PARENT_REPAIRS {
            let mut hash = [0xf2; 48];
            hash[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            node.parent_repairs.insert(
                hash,
                RepairRetry {
                    priority: RepairPriority {
                        tier: RepairTier::Signed,
                        slot: 1000,
                    },
                    ..RepairRetry::default()
                },
            );
        }
        // Keep the existing legitimate request too: the map must never exceed
        // its cap, including entries the live machine still references.
        while node.parent_repairs.len() > MAX_PARENT_REPAIRS {
            let hash = *node.parent_repairs.keys().next_back().unwrap();
            node.parent_repairs.remove(&hash);
        }
        weak_repair_certificate(&mut node, &chain[47]);
        let predecessor = chain[46].marker.block_commitment;
        // A corrupt unsigned key hint cannot establish a zero-slot parent.
        node.durable_block_slots.insert(predecessor, 0);
        node.complete(chain[47].clone()).unwrap();
        assert!(node.parent_repairs.contains_key(&predecessor));
        assert_eq!(
            node.outbound.values().next().unwrap().repairs.front(),
            Some(&predecessor)
        );
        for witness in chain[1..47].iter().rev() {
            node.complete(witness.clone()).unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            assert!(node.parent_repairs.contains_key(&witness.marker.parent));
            assert!(
                node.outbound
                    .values()
                    .all(|queue| queue.queued_repairs.contains(&witness.marker.parent))
            );
            assert!(node.waiting_parents.len() <= MAX_BUFFERED_CANDIDATES);
            assert!(node.waiting_parent_bytes <= MAX_REPAIR_BYTES);
            assert!(node.parent_repairs.len() <= MAX_PARENT_REPAIRS);
            assert!(node.deferred_refetches.len() <= MAX_BUFFERED_CANDIDATES);
        }
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 1);
        assert_eq!(bank_state(&root), root_state);
        let sidefork = repair_witness(&node, 1, [0xf3; 48], &payload);
        node.complete(sidefork.clone()).unwrap();
        assert!(
            !node
                .waiting_parents
                .contains_key(&sidefork.marker.block_commitment)
        );
        assert!(
            node.waiting_parents
                .contains_key(&chain[1].marker.block_commitment)
        );
        let refetch = node
            .deferred_refetches
            .iter()
            .find(|(_, reference)| reference.slot == 34)
            .unwrap();
        assert!(
            !node
                .completed_candidates
                .contains(&(refetch.1.slot, refetch.1.candidate))
        );
        node.complete(chain[0].clone()).unwrap();
        node.retry().unwrap();
        assert!(
            node.runtime
                .lock()
                .unwrap()
                .banks
                .contains_key(&chain[32].marker.block_commitment)
        );
        for witness in &chain[33..] {
            let hash = witness.marker.block_commitment;
            assert!(node.needed_parent_repairs(anchor).contains_key(&hash));
            let peer = *node.outbound.keys().next().unwrap();
            receive_witness(&mut node, peer, witness);
            node.retry().unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
        }
        let hash = chain[47].marker.block_commitment;
        let bank = node.runtime.lock().unwrap().banks[&hash].clone();
        assert_eq!(bank.slot(), 48);
        assert_eq!(node.machine.payload(&hash), Some(payload.as_slice()));
        node.complete(chain[47].clone()).unwrap();
        assert!(Arc::ptr_eq(
            &bank,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(node.bank_forks.read().unwrap().root(), anchor.slot);
        assert!(Arc::ptr_eq(
            &root,
            &node.bank_forks.read().unwrap().root_bank()
        ));
    }

    #[test]
    fn recent_repair_body_eviction_then_compaction_reloads_exact_partial_cursor() {
        let (_directory, mut node, mut signers) = repair_fixture_with_signers(128);
        let peer = *node.outbound.keys().next().unwrap();
        let other_peer = *node.outbound.keys().nth(1).unwrap();
        let payload = encode_block(&[]).unwrap();
        let mut parent = node.adopted_anchor().unwrap().hash;
        let mut witnesses = Vec::new();
        for slot in 1..=32 {
            let witness = repair_witness(&node, slot, parent, &payload);
            parent = witness.marker.block_commitment;
            node.complete(witness.clone()).unwrap();
            node.send_witness(Some(peer), &witness).unwrap();
            node.repair_responses
                .insert((peer, parent), RepairResponse::default());
            node.repair_progress.insert(parent, node.now());
            witnesses.push(witness);
        }
        let first = &witnesses[0];
        let first_hash = first.marker.block_commitment;
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .blocks
            .front_mut()
            .unwrap()
            .1 = 7;
        // Only this recent witness is eligible for historical-cache eviction.
        // Its independent live-map copy still exists during eviction.
        let now = node.now();
        for progress in node.repair_progress.values_mut() {
            *progress = now;
        }
        node.repair_progress.insert(first_hash, 0);
        let far = repair_witness(&node, 100, parent, &payload);
        let far_hash = far.marker.block_commitment;
        node.blockstore
            .put_experimental_pq_block(100, far_hash, &far.encode().unwrap())
            .unwrap();
        node.durable_block_slots.insert(far_hash, 100);
        node.schedule_repair_response(other_peer, far_hash).unwrap();
        node.serve_pending_repair().unwrap();
        assert!(!node.outbound_witnesses.contains_key(&first_hash));
        assert!(node.blocks.contains_key(&first_hash));

        // Real consensus certification promotes the already executed chain.
        // Compaction then retires the live copy while preserving the repair
        // cursor; no synthetic root or account state is installed.
        let message = ConsensusMessage {
            epoch: 7,
            slot: 32,
            kind: MessageKind::NotarVote,
            block: Some(parent),
        };
        let evidence = node.signer.sign(message.clone()).unwrap();
        let actions = node.machine.receive(evidence, node.now()).unwrap();
        node.persist(&actions).unwrap();
        node.pending.extend(actions);
        for signer in &mut signers {
            let evidence = signer.sign(message.clone()).unwrap();
            let actions = node.machine.receive(evidence, node.now()).unwrap();
            node.persist(&actions).unwrap();
            node.pending.extend(actions);
        }
        node.drive().unwrap();
        node.compact().unwrap();
        assert_eq!(node.bank_forks.read().unwrap().root(), 32);
        assert!(!node.blocks.contains_key(&first_hash));
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(first_hash, 7)));
        let root = node.bank_forks.read().unwrap().root_bank();
        let root_state = bank_state(&root);

        for _ in 0..200 {
            node.schedule_repair_response(peer, first_hash).unwrap();
        }
        assert!(node.repair_responses[&(peer, first_hash)].requested);
        for progress in node.repair_progress.values_mut() {
            *progress = 0;
        }
        node.repair_responses
            .get_mut(&(peer, first_hash))
            .unwrap()
            .retry
            .due = 0;
        node.serve_pending_repair().unwrap();
        assert!(node.outbound_witnesses.contains_key(&first_hash));
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(first_hash, 7)));
        let mut frames = Vec::new();
        let remaining = first.shreds.len() - 7 + 1;
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    if frame[0] != 1 && frame[0] != 2 {
                        return true;
                    }
                    if frames.len() == remaining {
                        return false;
                    }
                    frames.push(frame.to_vec());
                    true
                },
            )
            .unwrap();
        assert_eq!(frames.len(), remaining);
        assert!(!node.outbound[&peer].queued_blocks.contains(&first_hash));
        let mut assembler = CandidateAssembler::new(
            node.chain,
            node.leader.public_key(),
            7,
            1,
            first.marker.candidate,
            first.marker.parent,
        );
        for shred in &first.shreds[..7] {
            assembler.insert(shred.clone()).unwrap();
        }
        for frame in &frames[..frames.len() - 1] {
            assert_eq!(frame[0], 1);
            assembler
                .insert(AuthenticatedShred::decode(&frame[1..]).unwrap())
                .unwrap();
        }
        let terminal = frames.last().unwrap();
        assert_eq!(terminal[0], 2);
        assert_eq!(
            assembler
                .finish(&FinalMarker::decode(&terminal[1..]).unwrap())
                .unwrap(),
            payload
        );
        assert_eq!(node.invalid_packets, 0);
        assert!(Arc::ptr_eq(
            &root,
            &node.bank_forks.read().unwrap().root_bank()
        ));
        assert_eq!(bank_state(&root), root_state);
        assert!(node.outbound_witnesses.len() <= MAX_BUFFERED_CANDIDATES);
        assert!(
            node.outbound_witnesses
                .values()
                .map(repair_witness_bytes)
                .sum::<usize>()
                <= MAX_REPAIR_BYTES
        );
    }

    #[test]
    fn missing_repair_front_reloads_before_certified_future_work_without_starving_it() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        let peer = *node.outbound.keys().next().unwrap();
        let payload = encode_block(&[]).unwrap();
        let anchor = node.adopted_anchor().unwrap();
        let first = repair_witness(&node, 3, anchor.hash, &payload);
        let first_hash = first.marker.block_commitment;
        node.blockstore
            .put_experimental_pq_block(3, first_hash, &first.encode().unwrap())
            .unwrap();
        node.durable_block_slots.insert(first_hash, 3);
        node.send_witness(Some(peer), &first).unwrap();
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .blocks
            .front_mut()
            .unwrap()
            .1 = 7;
        node.outbound_witnesses.remove(&first_hash);
        node.schedule_repair_response(peer, first_hash).unwrap();
        let future = repair_witness(&node, 80, anchor.hash, &payload);
        let future_hash = future.marker.block_commitment;
        weak_repair_certificate(&mut node, &future);
        node.blocks.insert(future_hash, future);
        node.block_slots.insert(future_hash, 80);
        node.schedule_repair_response(peer, future_hash).unwrap();
        assert!(
            node.repair_responses[&(peer, future_hash)].retry.priority
                < node.repair_responses[&(peer, first_hash)].retry.priority
        );
        node.update_status();
        assert_eq!(
            node.status.read().unwrap()["repair"]["missing_queued_bodies"],
            1
        );
        assert_eq!(
            node.status.read().unwrap()["repair"]["missing_repair_fronts"],
            1
        );
        node.serve_pending_repair().unwrap();
        assert!(node.outbound_witnesses.contains_key(&first_hash));
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(first_hash, 7)));
        assert!(node.repair_responses[&(peer, future_hash)].requested);
        node.serve_pending_repair().unwrap();
        assert!(node.outbound[&peer].blocks.contains(&(future_hash, 0)));
        let mut sent = 0;
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    if frame[0] == 1 || frame[0] == 2 {
                        sent += 1;
                    }
                    true
                },
            )
            .unwrap();
        assert_eq!(sent, first.shreds.len() - 7 + 1 + 65);
        assert!(node.outbound[&peer].blocks.is_empty());
        node.update_status();
        assert_eq!(
            node.status.read().unwrap()["repair"]["missing_queued_bodies"],
            0
        );
        assert_eq!(
            node.status.read().unwrap()["repair"]["missing_repair_fronts"],
            0
        );
        assert_eq!(node.bank_forks.read().unwrap().root(), anchor.slot);
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn full_queued_repair_responses_admit_causal_parent_without_resetting_partial_cursor() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        let peer = *node.outbound.keys().next().unwrap();
        let payload = encode_block(&[]).unwrap();
        let anchor = node.adopted_anchor().unwrap();
        let mut hashes = Vec::new();
        for slot in 80..112 {
            let witness = repair_witness(&node, slot, anchor.hash, &payload);
            let hash = witness.marker.block_commitment;
            node.blocks.insert(hash, witness.clone());
            node.block_slots.insert(hash, slot);
            node.schedule_repair_response(peer, hash).unwrap();
            node.send_witness(Some(peer), &witness).unwrap();
            node.repair_responses
                .get_mut(&(peer, hash))
                .unwrap()
                .requested = false;
            hashes.push(hash);
        }
        let partial = hashes[0];
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .blocks
            .front_mut()
            .unwrap()
            .1 = 7;
        let old = repair_witness(&node, 1, anchor.hash, &payload);
        let old_hash = old.marker.block_commitment;
        weak_repair_certificate(&mut node, &old);
        node.blocks.insert(old_hash, old);
        node.block_slots.insert(old_hash, 1);
        node.schedule_repair_response(peer, old_hash).unwrap();
        assert!(node.repair_responses.contains_key(&(peer, old_hash)));
        assert_eq!(node.repair_responses.len(), MAX_PEER_REPAIR_RESPONSES);
        assert!(node.outbound[&peer].blocks.contains(&(partial, 7)));
        assert_eq!(
            node.outbound[&peer].queued_blocks.len(),
            MAX_PEER_REPAIR_RESPONSES - 1
        );
        node.serve_pending_repair().unwrap();
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(old_hash, 0)));
        assert!(node.outbound[&peer].blocks.contains(&(partial, 7)));
        assert!(node.outbound_witnesses.len() <= MAX_BUFFERED_CANDIDATES);
        assert!(
            node.outbound_witnesses
                .values()
                .map(repair_witness_bytes)
                .sum::<usize>()
                <= MAX_REPAIR_BYTES
        );
        assert_eq!(node.bank_forks.read().unwrap().root(), anchor.slot);
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn repair_response_full_queue_prioritizes_causal_requests_and_preserves_cursors() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        let peers = node.outbound.keys().copied().collect::<Vec<_>>();
        let payload = encode_block(&[]).unwrap();
        let anchor = node.adopted_anchor().unwrap();
        let mut far = Vec::new();
        for slot in 80..112 {
            let witness = repair_witness(&node, slot, anchor.hash, &payload);
            node.authenticate_witness(&witness).unwrap();
            weak_repair_certificate(&mut node, &witness);
            let hash = witness.marker.block_commitment;
            node.blocks.insert(hash, witness.clone());
            node.block_slots.insert(hash, slot);
            node.schedule_repair_response(peers[0], hash).unwrap();
            far.push(witness);
        }
        let active = &far[31];
        let active_hash = active.marker.block_commitment;
        node.send_witness(Some(peers[0]), active).unwrap();
        node.outbound
            .get_mut(&peers[0])
            .unwrap()
            .blocks
            .front_mut()
            .unwrap()
            .1 = 7;
        let old = repair_witness(&node, 1, anchor.hash, &payload);
        let old_hash = old.marker.block_commitment;
        node.authenticate_witness(&old).unwrap();
        weak_repair_certificate(&mut node, &old);
        node.blocks.insert(old_hash, old);
        node.block_slots.insert(old_hash, 1);
        for _ in 0..200 {
            node.schedule_repair_response(peers[0], old_hash).unwrap();
        }
        assert_eq!(node.repair_responses.len(), MAX_PEER_REPAIR_RESPONSES);
        assert!(node.repair_responses.contains_key(&(peers[0], old_hash)));
        assert!(node.repair_responses.contains_key(&(peers[0], active_hash)));
        node.serve_pending_repair().unwrap();
        assert_eq!(
            node.outbound[&peers[0]].blocks.front(),
            Some(&(old_hash, 0))
        );
        assert!(node.outbound[&peers[0]].blocks.contains(&(active_hash, 7)));
        let other = repair_witness(&node, 2, anchor.hash, &payload);
        let other_hash = other.marker.block_commitment;
        node.authenticate_witness(&other).unwrap();
        node.blocks.insert(other_hash, other);
        node.block_slots.insert(other_hash, 2);
        node.schedule_repair_response(peers[1], other_hash).unwrap();
        node.serve_pending_repair().unwrap();
        assert!(node.outbound[&peers[1]].queued_blocks.contains(&other_hash));
        for ordinal in 0..1000u64 {
            let mut hash = [0xf4; 48];
            hash[..8].copy_from_slice(&ordinal.to_le_bytes());
            // Unknown hashes do not cause scans or speculative CF reads.
            node.schedule_repair_response(peers[2], hash).unwrap();
            node.durable_block_slots.insert(hash, 1);
            node.schedule_repair_response(peers[2], hash).unwrap();
        }
        assert!(
            node.repair_responses
                .keys()
                .filter(|(peer, _)| *peer == peers[2])
                .count()
                <= MAX_PEER_REPAIR_RESPONSES
        );
        assert!(
            node.repair_responses
                .iter()
                .filter(|((peer, _), _)| *peer == peers[2])
                .all(|(_, response)| response.retry.priority == RepairPriority::default())
        );
        assert!(node.outbound_witnesses.len() <= MAX_BUFFERED_CANDIDATES);
        assert!(
            node.outbound_witnesses
                .values()
                .map(repair_witness_bytes)
                .sum::<usize>()
                <= MAX_REPAIR_BYTES
        );
        assert_eq!(node.invalid_packets, 0);
    }

    #[test]
    fn evicted_partial_candidate_requires_and_completes_whole_body_refetch() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        let peer = *node.outbound.keys().next().unwrap();
        let payload = encode_block(&[]).unwrap();
        let anchor = node.adopted_anchor().unwrap();
        let target = repair_witness(&node, 50, anchor.hash, &payload);
        let hash = target.marker.block_commitment;
        let index = (target.marker.slot, target.marker.candidate);
        weak_repair_certificate(&mut node, &target);
        node.blockstore
            .put_experimental_pq_block(50, hash, &target.encode().unwrap())
            .unwrap();
        node.durable_block_slots.insert(hash, 50);
        node.send_witness(Some(peer), &target).unwrap();
        let mut frames = Vec::new();
        let mut sent = 0;
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    sent += 1;
                    if sent > 7 {
                        return false;
                    }
                    frames.push(frame.to_vec());
                    true
                },
            )
            .unwrap();
        for frame in frames.drain(..) {
            node.receive(peer, &frame).unwrap();
        }
        assert!(node.assemblers.contains_key(&index));
        for slot in 64..96 {
            let far = repair_witness(&node, slot, [0xf5; 48], &payload);
            weak_repair_certificate(&mut node, &far);
            let mut marker = vec![2];
            marker.extend(far.marker.encode());
            node.receive(peer, &marker).unwrap();
            let mut shred = vec![1];
            shred.extend(far.shreds[0].encode().unwrap());
            node.receive(peer, &shred).unwrap();
        }
        assert_eq!(node.assemblers.len(), MAX_BUFFERED_CANDIDATES);
        assert_eq!(node.markers.len(), MAX_BUFFERED_CANDIDATES);
        assert!(!node.assemblers.contains_key(&index));
        node.schedule_repair_response(peer, hash).unwrap();
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(hash, 7)));
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    frames.push(frame.to_vec());
                    true
                },
            )
            .unwrap();
        for frame in frames.drain(..) {
            node.receive(peer, &frame).unwrap();
        }
        assert!(node.markers.contains_key(&index));
        assert!(!node.runtime.lock().unwrap().banks.contains_key(&hash));
        assert!(node.machine.payload(&hash).is_none());
        assert!(!node.outbound[&peer].queued_blocks.contains(&hash));
        node.schedule_repair_response(peer, hash).unwrap();
        node.serve_pending_repair().unwrap();
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(hash, 0)));
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    frames.push(frame.to_vec());
                    true
                },
            )
            .unwrap();
        for frame in frames {
            node.receive(peer, &frame).unwrap();
        }
        let bank = node.runtime.lock().unwrap().banks[&hash].clone();
        assert_eq!(bank.slot(), 50);
        assert_eq!(node.machine.payload(&hash), Some(payload.as_slice()));
        assert!(!node.assemblers.contains_key(&index));
        assert!(!node.markers.contains_key(&index));
        node.complete(target).unwrap();
        assert!(Arc::ptr_eq(
            &bank,
            &node.runtime.lock().unwrap().banks[&hash]
        ));
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(node.bank_forks.read().unwrap().root(), anchor.slot);
    }

    #[test]
    fn canonical_repair_priority_survives_pool_and_body_compaction() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        // A singleton test committee exercises real signed certificates,
        // native promotion, persistence and compaction without fabricated roots.
        node.machine = Quantumglow::new(
            node.machine.config().clone(),
            node.local.to_bytes(),
            vec![PqValidator {
                id: node.local.to_bytes(),
                stake: 1,
                key: node.signer.public_key(),
            }],
        )
        .unwrap();
        let peer = *node.outbound.keys().next().unwrap();
        let payload = encode_block(&[]).unwrap();
        let mut old = None;
        for slot in 1..=24 {
            let parent = node.adopted_anchor().unwrap().hash;
            let witness = repair_witness(&node, slot, parent, &payload);
            if slot == 1 {
                old = Some(witness.clone());
            }
            node.complete(witness).unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            assert_eq!(node.bank_forks.read().unwrap().root(), slot);
        }
        let old = old.unwrap();
        let old_hash = old.marker.block_commitment;
        assert!(node.machine.pool().certificate_blocks(1, false).is_empty());
        assert!(!node.blocks.contains_key(&old_hash));
        assert!(node.has_repair_certificate(1, old_hash));
        assert!(!node.has_repair_certificate(1, [0xf9; 48]));
        for slot in 80..112 {
            let witness = repair_witness(&node, slot, [0xfa; 48], &payload);
            node.authenticate_witness(&witness).unwrap();
            weak_repair_certificate(&mut node, &witness);
            let hash = witness.marker.block_commitment;
            node.block_slots.insert(hash, slot);
            node.blocks.insert(hash, witness);
            node.schedule_repair_response(peer, hash).unwrap();
        }
        assert_eq!(node.repair_responses.len(), MAX_PEER_REPAIR_RESPONSES);
        node.schedule_repair_response(peer, old_hash).unwrap();
        assert_eq!(node.repair_responses.len(), MAX_PEER_REPAIR_RESPONSES);
        assert_eq!(
            node.repair_responses[&(peer, old_hash)].retry.priority,
            RepairPriority {
                tier: RepairTier::Certified,
                slot: 1
            }
        );
        node.serve_pending_repair().unwrap();
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&(old_hash, 0)));
        assert_eq!(
            node.outbound_witnesses[&old_hash].encode().unwrap(),
            old.encode().unwrap()
        );
        assert_eq!(node.bank_forks.read().unwrap().root(), 24);
        assert_eq!(node.adopted_anchor().unwrap().slot, 24);
    }

    #[test]
    fn deferred_byte_pressure_keeps_older_authentication_and_exact_accounting() {
        let (_directory, mut node) = repair_fixture_with_slots(128);
        let payload = vec![0xf6; 128 * 1024];
        for slot in (100..104).rev() {
            let mut witness = repair_witness(&node, slot, [0xf7; 48], &payload);
            // Duplicate authenticated fragments still consume physical memory;
            // assembly deduplicates them, but deferred accounting must not.
            witness.shreds = witness
                .shreds
                .iter()
                .cloned()
                .cycle()
                .take(64 * 120)
                .collect();
            assert!(witness.encode().unwrap().len() > MAX_REPAIR_BYTES / 4);
            node.complete(witness).unwrap();
            node.drive().unwrap();
            node.compact().unwrap();
            assert!(node.waiting_parent_bytes <= MAX_REPAIR_BYTES);
        }
        assert!(node.waiting_parents.len() < MAX_BUFFERED_CANDIDATES);
        let oldest = node
            .waiting_parents
            .values()
            .map(|witness| witness.marker.slot)
            .min()
            .unwrap();
        assert_eq!(oldest, 100);
        assert_eq!(
            node.waiting_parent_bytes,
            node.waiting_parents
                .values()
                .map(|witness| witness.encode().unwrap().len())
                .sum::<usize>()
        );
        assert!(
            node.deferred_refetches
                .values()
                .any(|reference| reference.slot == 103)
        );
        assert!(!node.completed_candidates.contains(&(103, [103; 48])));
        let prior = node.waiting_parent_bytes;
        let mut forged = repair_witness(&node, 2, [0xf8; 48], &payload);
        forged.shreds[0].payload[0] ^= 1;
        assert!(node.complete(forged).is_err());
        assert_eq!(node.waiting_parent_bytes, prior);
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 1);
    }

    #[test]
    fn strong_certified_ancestry_outranks_older_weak_sideforks() {
        let (_directory, mut node, mut signers) = repair_fixture_with_signers(128);
        let payload = encode_block(&[]).unwrap();
        let parent = [0xfb; 48];
        let predecessor = repair_witness(&node, 63, parent, &payload);
        let child = repair_witness(&node, 64, predecessor.marker.block_commitment, &payload);
        for slot in 2..34 {
            let weak = repair_witness(&node, slot, [0xfc; 48], &payload);
            weak_repair_certificate(&mut node, &weak);
            assert_eq!(
                node.repair_certificate_tier(slot, weak.marker.block_commitment),
                RepairTier::Weak
            );
            node.complete(weak).unwrap();
        }
        weak_repair_certificate(&mut node, &child);
        for signer in &mut signers {
            let evidence = signer
                .sign(ConsensusMessage {
                    epoch: 7,
                    slot: 64,
                    kind: MessageKind::NotarVote,
                    block: Some(child.marker.block_commitment),
                })
                .unwrap();
            let actions = node.machine.receive(evidence, node.now()).unwrap();
            node.pending.extend(actions);
        }
        assert_eq!(
            node.repair_certificate_tier(64, child.marker.block_commitment),
            RepairTier::Weak
        );
        let evidence = node
            .signer
            .sign(ConsensusMessage {
                epoch: 7,
                slot: 64,
                kind: MessageKind::NotarVote,
                block: Some(child.marker.block_commitment),
            })
            .unwrap();
        let actions = node.machine.receive(evidence, node.now()).unwrap();
        node.pending.extend(actions);
        assert_eq!(
            node.machine.pool().finalized(64),
            Some(child.marker.block_commitment)
        );
        // Fast notar finality is strong evidence even without the separate
        // strong approval certificate returned by certificate_blocks(true).
        assert!(node.machine.pool().certificate_blocks(64, true).is_empty());
        assert_eq!(
            node.repair_certificate_tier(64, child.marker.block_commitment),
            RepairTier::Certified
        );
        node.complete(child.clone()).unwrap();
        node.complete(predecessor.clone()).unwrap();
        let priorities = node.certified_ancestry(None);
        assert_eq!(
            priorities[&predecessor.marker.block_commitment],
            RepairTier::Certified
        );
        assert_eq!(priorities[&parent], RepairTier::Certified);
        let weak_side = repair_witness(&node, 1, [0xfd; 48], &payload);
        weak_repair_certificate(&mut node, &weak_side);
        node.complete(weak_side).unwrap();
        assert_eq!(node.waiting_parents.len(), MAX_BUFFERED_CANDIDATES);
        assert!(
            node.waiting_parents
                .contains_key(&child.marker.block_commitment)
        );
        assert!(
            node.waiting_parents
                .contains_key(&predecessor.marker.block_commitment)
        );
        // Raw key hints still cannot convert a genuine missing predecessor to
        // an obsolete zero-slot fork while drive -> compact -> flush runs.
        node.durable_block_slots.insert(parent, 0);
        node.drive().unwrap();
        node.compact().unwrap();
        assert!(
            node.waiting_parents
                .contains_key(&predecessor.marker.block_commitment)
        );
        assert_eq!(
            node.parent_repairs[&parent].priority.tier,
            RepairTier::Certified
        );
        assert_eq!(
            node.outbound.values().next().unwrap().repairs.front(),
            Some(&parent)
        );
        assert_eq!(node.runtime.lock().unwrap().banks.len(), 1);
        assert_eq!(node.bank_forks.read().unwrap().root(), 0);
    }

    #[test]
    fn orphan_witness_authentication_precedes_deferral_and_unknown_descendants_survive() {
        let (_directory, mut node) = repair_fixture();
        let parent = [0xa1; 48];
        let payload = encode_block(&[]).unwrap();
        let witness = repair_witness(&node, 5, parent, &payload);
        let hash = witness.marker.block_commitment;
        let mut forged = witness.clone();
        forged.shreds[0].payload[0] ^= 1;
        assert!(node.complete(forged).is_err());
        assert!(node.waiting_parents.is_empty());
        node.complete(witness.clone()).unwrap();
        assert!(node.waiting_parents.contains_key(&hash));
        assert_eq!(node.waiting_parent_bytes, witness.encode().unwrap().len());
        node.compact().unwrap();
        assert!(node.waiting_parents.contains_key(&hash));
        assert!(node.parent_repairs.contains_key(&parent));
        let anchor = BlockRef {
            slot: 4,
            hash: [0xa2; 48],
        };
        assert!(!obsolete_witness(
            &witness,
            anchor,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new()
        ));
        let authenticated = BTreeMap::from([(parent, 3)]);
        assert!(obsolete_witness(
            &witness,
            anchor,
            &authenticated,
            &BTreeMap::new(),
            &BTreeMap::new()
        ));
        let direct = repair_witness(&node, 6, anchor.hash, &payload);
        assert!(!obsolete_witness(
            &direct,
            anchor,
            &authenticated,
            &BTreeMap::new(),
            &BTreeMap::new()
        ));
    }

    #[test]
    fn deferred_pruning_uses_current_certified_root_and_preserves_future_ancestry() {
        let (_directory, node) = repair_fixture();
        let payload = encode_block(&[]).unwrap();
        let actual = BlockRef {
            slot: 8,
            hash: [0xa3; 48],
        };
        // This parent is newer than the retained history floor (slot 4), but
        // older than the certified native root. Keeping it would strand its
        // descendants once the native Bank is pruned.
        let old_parent = [0xa4; 48];
        let stale_slot = repair_witness(&node, 7, old_parent, &payload);
        let sibling = repair_witness(&node, 9, old_parent, &payload);
        let descendant = repair_witness(&node, 10, sibling.marker.block_commitment, &payload);
        let direct = repair_witness(&node, 11, actual.hash, &payload);
        let live_descendant = repair_witness(&node, 12, direct.marker.block_commitment, &payload);
        let unknown = repair_witness(&node, 13, [0xa5; 48], &payload);
        let expected = BTreeSet::from([
            direct.marker.block_commitment,
            live_descendant.marker.block_commitment,
            unknown.marker.block_commitment,
        ]);
        let mut deferred = [
            stale_slot,
            sibling,
            descendant,
            direct,
            live_descendant,
            unknown,
        ]
        .into_iter()
        .map(|witness| (witness.marker.block_commitment, witness))
        .collect::<BTreeMap<_, _>>();
        for witness in deferred.values() {
            node.authenticate_witness(witness).unwrap();
        }
        let mut bytes = deferred
            .values()
            .map(|witness| witness.encode().unwrap().len())
            .sum();
        prune_deferred_witnesses(
            actual,
            &BTreeMap::from([(old_parent, 6)]),
            &BTreeMap::new(),
            &mut deferred,
            &mut bytes,
        )
        .unwrap();
        assert_eq!(deferred.keys().copied().collect::<BTreeSet<_>>(), expected);
        assert_eq!(
            bytes,
            deferred
                .values()
                .map(|witness| witness.encode().unwrap().len())
                .sum::<usize>()
        );
        // Pruning is idempotent and never consults unsigned disk index hints.
        prune_deferred_witnesses(
            actual,
            &BTreeMap::from([(old_parent, 6)]),
            &BTreeMap::new(),
            &mut deferred,
            &mut bytes,
        )
        .unwrap();
        assert_eq!(deferred.keys().copied().collect::<BTreeSet<_>>(), expected);
    }

    #[test]
    fn deferred_native_rejection_is_pre_wal_and_valid_candidate_executes_once() {
        let (_directory, mut node) = repair_fixture();
        let root = node.bank_forks.read().unwrap().root_bank();
        let anchor = node.adopted_anchor().unwrap();
        let parent = repair_witness(&node, 1, anchor.hash, &encode_block(&[]).unwrap());
        let parent_hash = parent.marker.block_commitment;
        let transaction = Transaction::new_unsigned(Message::new_with_blockhash(
            &[system_instruction::transfer(
                &node.local,
                &Pubkey::new_from_array([0xa8; 32]),
                7,
            )],
            Some(&node.local),
            &root.last_blockhash(),
        ));
        let invalid_payload =
            encode_block(&[bincode::serialize(&VersionedTransaction::from(transaction)).unwrap()])
                .unwrap();
        let invalid = repair_witness(&node, 2, parent_hash, &invalid_payload);
        let invalid_hash = invalid.marker.block_commitment;
        node.complete(invalid).unwrap();
        assert!(node.waiting_parents.contains_key(&invalid_hash));
        assert_eq!(node.machine.recovery_record_count(), 0);
        node.complete(parent).unwrap();
        let clock = node.machine.clock();
        let records = node.machine.recovery_record_count();
        let runtime_hashes = node
            .runtime
            .lock()
            .unwrap()
            .banks
            .keys()
            .copied()
            .collect::<Vec<_>>();
        node.retry().unwrap();
        assert!(!node.waiting_parents.contains_key(&invalid_hash));
        assert_eq!(node.waiting_parent_bytes, 0);
        assert_eq!(node.invalid_packets, 1);
        assert_eq!(node.machine.clock(), clock);
        assert_eq!(node.machine.recovery_record_count(), records);
        assert!(node.machine.payload(&invalid_hash).is_none());
        assert_eq!(
            node.runtime
                .lock()
                .unwrap()
                .banks
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            runtime_hashes
        );
        {
            let runtime = node.runtime.lock().unwrap();
            assert!(!runtime.states.contains_key(&invalid_hash));
            assert!(!runtime.executions.contains_key(&invalid_hash));
            assert!(!runtime.archives.contains_key(&invalid_hash));
        }
        assert!(
            node.blockstore
                .get_experimental_pq_block(2, invalid_hash)
                .unwrap()
                .is_none()
        );
        assert_eq!(root.transaction_count(), 0);
        assert_eq!(
            root.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            1_000_000
        );

        let config =
            pq::Config::decode(root.get_account(&pq::CONFIG_ADDRESS).unwrap().data()).unwrap();
        let transaction = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[node.local]),
                    system_instruction::transfer(
                        &node.local,
                        &Pubkey::new_from_array([0xa8; 32]),
                        9,
                    ),
                ],
                Some(&node.local),
                &root.last_blockhash(),
            )),
            &config,
            &[&node.leader],
        )
        .unwrap();
        let valid = repair_witness(
            &node,
            3,
            parent_hash,
            &encode_block(&[bincode::serialize(&transaction).unwrap()]).unwrap(),
        );
        let valid_hash = valid.marker.block_commitment;
        node.complete(valid.clone()).unwrap();
        let bank = node.runtime.lock().unwrap().banks[&valid_hash].clone();
        assert_eq!(bank.transaction_count(), 1);
        assert_eq!(
            bank.get_balance(&Pubkey::new_from_array([0xa8; 32])),
            1_000_009
        );
        let state = bank_state(&bank);
        node.complete(valid).unwrap();
        assert!(Arc::ptr_eq(
            &bank,
            &node.runtime.lock().unwrap().banks[&valid_hash]
        ));
        assert_eq!(bank.transaction_count(), 1);
        assert_eq!(bank_state(&bank), state);
    }

    #[test]
    fn deferred_native_internal_failure_remains_fatal() {
        let (_directory, mut node) = repair_fixture();
        let anchor = node.adopted_anchor().unwrap();
        let payload = encode_block(&[]).unwrap();
        let parent = repair_witness(&node, 1, anchor.hash, &payload);
        let parent_hash = parent.marker.block_commitment;
        let child = repair_witness(&node, 2, parent_hash, &payload);
        let child_hash = child.marker.block_commitment;
        node.complete(child).unwrap();
        node.complete(parent).unwrap();
        let records = node.machine.recovery_record_count();
        let clock = node.machine.clock();
        // A native Bank without its state/capability is an internal invariant
        // failure. It must never be downgraded to a rejected peer packet.
        node.runtime.lock().unwrap().states.remove(&parent_hash);
        let error = node.retry().unwrap_err();
        assert!(error.downcast_ref::<RejectedCandidateExecution>().is_none());
        assert!(error.to_string().contains("parent state missing"));
        assert_eq!(node.invalid_packets, 0);
        assert_eq!(node.machine.recovery_record_count(), records);
        assert_eq!(node.machine.clock(), clock);
        assert!(node.machine.payload(&child_hash).is_none());
        assert!(
            node.blockstore
                .get_experimental_pq_block(2, child_hash)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn weak_missing_body_repair_survives_compaction_and_requests_back_off() {
        let (_directory, mut node) = repair_fixture();
        let hash = [0xb1; 48];
        let evidence = node
            .signer
            .sign(ConsensusMessage {
                epoch: 7,
                slot: 2,
                kind: MessageKind::NotarApproval,
                block: Some(hash),
            })
            .unwrap();
        let actions = node.machine.receive(evidence, node.now()).unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action,Action::Repair{block,..} if *block==hash))
        );
        assert!(node.machine.pool().certificate_blocks(2, true).is_empty());
        node.pending.extend(actions);
        node.drive().unwrap();
        node.compact().unwrap();
        assert!(node.parent_repairs.contains_key(&hash));
        assert!(
            node.outbound
                .values()
                .all(|queue| queue.queued_repairs.contains(&hash))
        );
        let due = node.parent_repairs[&hash].due;
        node.request_repair(hash).unwrap();
        assert_eq!(node.parent_repairs[&hash].due, due);
        let mut retry = RepairRetry::default();
        retry.defer(0, 1000);
        assert!(!retry.ready(999));
        assert!(retry.ready(1000));
        retry.defer(1000, 1000);
        assert_eq!(retry.due, 3000);
    }

    #[test]
    fn repair_requests_coalesce_before_decode_and_partial_cursors_survive_backpressure() {
        let (_directory, mut node) = repair_fixture();
        let peer = *node.outbound.keys().next().unwrap();
        let payload = vec![0xc1; 128 * 1024];
        let witness = repair_witness(&node, 3, [0xc2; 48], &payload);
        let hash = witness.marker.block_commitment;
        node.blockstore
            .put_experimental_pq_block(3, hash, &witness.encode().unwrap())
            .unwrap();
        node.durable_block_slots.insert(hash, 3);
        for _ in 0..200 {
            node.schedule_repair_response(peer, hash).unwrap();
        }
        assert_eq!(node.repair_responses.len(), 1);
        assert!(node.outbound_witnesses.is_empty());
        node.serve_pending_repair().unwrap();
        assert_eq!(node.outbound_witnesses.len(), 1);
        let queue = node.outbound.get_mut(&peer).unwrap();
        let mut accepted = 0;
        queue
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |_| {
                    accepted += 1;
                    accepted <= 5
                },
            )
            .unwrap();
        let cursor = queue.blocks.front().copied().unwrap();
        assert_eq!(cursor, (hash, 5));
        for _ in 0..200 {
            node.schedule_repair_response(peer, hash).unwrap();
        }
        assert_eq!(node.repair_responses.len(), 1);
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&cursor));
        node.outbound_witnesses.remove(&hash);
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |_| true,
            )
            .unwrap();
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&cursor));
        let response = node.repair_responses.get_mut(&(peer, hash)).unwrap();
        response.requested = true;
        response.retry.due = 0;
        node.serve_pending_repair().unwrap();
        assert_eq!(node.outbound[&peer].blocks.front(), Some(&cursor));
        let mut assembler = CandidateAssembler::new(
            node.chain,
            node.leader.public_key(),
            7,
            3,
            [3; 48],
            [0xc2; 48],
        );
        for shred in &witness.shreds[..5] {
            assembler.insert(shred.clone()).unwrap();
        }
        let mut terminal = None;
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &node.blocks,
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    match frame[0] {
                        1 => {
                            assembler
                                .insert(AuthenticatedShred::decode(&frame[1..]).unwrap())
                                .unwrap();
                        }
                        2 => terminal = Some(FinalMarker::decode(&frame[1..]).unwrap()),
                        _ => {}
                    }
                    true
                },
            )
            .unwrap();
        assert_eq!(assembler.finish(&terminal.unwrap()).unwrap(), payload);
    }

    #[test]
    fn repair_cache_pressure_defers_bodies_without_dropping_active_cursors() {
        for byte_pressure in [false, true] {
            let (_directory, mut node) = repair_fixture();
            let peers = node.outbound.keys().copied().collect::<Vec<_>>();
            let count = if byte_pressure {
                2
            } else {
                MAX_BUFFERED_CANDIDATES
            };
            let payload = vec![0xd1; if byte_pressure { 128 * 1024 } else { 1024 }];
            let mut first = None;
            for slot in 1..=count {
                let mut witness = repair_witness(&node, slot as u64, [0xd2; 48], &payload);
                if byte_pressure {
                    // Repeated individually valid witnesses are conservatively
                    // counted, even though assembly deduplicates their shards.
                    witness.shreds = witness
                        .shreds
                        .iter()
                        .cloned()
                        .cycle()
                        .take(64 * 80)
                        .collect();
                }
                let hash = witness.marker.block_commitment;
                node.blockstore
                    .put_experimental_pq_block(slot as u64, hash, &witness.encode().unwrap())
                    .unwrap();
                node.durable_block_slots.insert(hash, slot as u64);
                node.send_witness(Some(peers[0]), &witness).unwrap();
                node.repair_responses
                    .insert((peers[0], hash), RepairResponse::default());
                node.repair_progress.insert(hash, 0);
                if first.is_none() {
                    first = Some((hash, witness));
                }
            }
            let (old_hash, old_witness) = first.unwrap();
            let queue = node.outbound.get_mut(&peers[0]).unwrap();
            queue
                .blocks
                .iter_mut()
                .find(|(hash, _)| *hash == old_hash)
                .unwrap()
                .1 = 7;
            let mut next = repair_witness(&node, 1, [0xd3; 48], &payload);
            if byte_pressure {
                next.shreds = next.shreds.iter().cloned().cycle().take(64 * 80).collect();
            }
            let next_hash = next.marker.block_commitment;
            node.blockstore
                .put_experimental_pq_block(1, next_hash, &next.encode().unwrap())
                .unwrap();
            node.durable_block_slots.insert(next_hash, 1);
            node.schedule_repair_response(peers[1], next_hash).unwrap();
            node.serve_pending_repair().unwrap();
            assert!(node.outbound_witnesses.len() <= MAX_BUFFERED_CANDIDATES);
            assert!(
                node.outbound_witnesses
                    .values()
                    .map(repair_witness_bytes)
                    .sum::<usize>()
                    <= MAX_REPAIR_BYTES
            );
            assert_eq!(
                node.outbound[&peers[0]]
                    .blocks
                    .iter()
                    .find(|(hash, _)| *hash == old_hash),
                Some(&(old_hash, 7))
            );
            let evicted = node
                .repair_responses
                .iter()
                .find(|((peer, hash), response)| {
                    *peer == peers[0]
                        && response.requested
                        && !node.outbound_witnesses.contains_key(hash)
                })
                .map(|(key, _)| *key)
                .unwrap();
            assert!(
                node.repair_responses
                    .keys()
                    .filter(|(peer, _)| *peer == peers[0])
                    .count()
                    <= MAX_PEER_REPAIR_RESPONSES
            );
            node.repair_responses.get_mut(&evicted).unwrap().retry.due = 0;
            node.serve_pending_repair().unwrap();
            assert!(node.outbound_witnesses.contains_key(&evicted.1));
            assert_eq!(
                node.outbound[&peers[0]]
                    .blocks
                    .iter()
                    .find(|(hash, _)| *hash == old_hash),
                Some(&(old_hash, 7))
            );
            // The original body remains cryptographically valid after lazy
            // reload; no signing, state advance or cursor reset occurred.
            node.authenticate_witness(&old_witness).unwrap();
        }
    }

    #[test]
    fn native_authentication_workers_keep_order_and_recover_partial_candidates() {
        let chain = [0x71; 32];
        let leader = FalconKeypair::generate();
        let payload = vec![0x72; 128 * 1024];
        let batch = SignedBatch::build(
            &chain,
            &leader,
            BatchContext {
                leader_epoch: 7,
                slot: 1,
                candidate: [0x73; 48],
                parent: [0x74; 48],
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            64,
            64,
        )
        .unwrap();
        let marker =
            FinalMarker::build(&chain, &leader, std::slice::from_ref(&batch), &payload).unwrap();
        for workers in [1, 4, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            let mut wrong_parent = batch.shreds[0].clone();
            wrong_parent.metadata.context.parent[0] ^= 1;
            let mut incoming = vec![wrong_parent];
            incoming.extend(batch.shreds.clone());
            let mut verified = pool
                .install(|| authenticate_shred_group(None, chain, leader.public_key(), 7, incoming))
                .unwrap()
                .into_iter();
            assert!(verified.next().unwrap().is_err());
            let mut assembler =
                CandidateAssembler::new(chain, leader.public_key(), 7, 1, [0x73; 48], [0x74; 48]);
            for _ in 0..2 {
                assembler
                    .insert_verified(verified.next().unwrap().unwrap())
                    .unwrap();
            }
            let mut assembler = match pool.install(|| assembler.try_finish_verified(marker.clone()))
            {
                Err((NetworkError::Incomplete, assembler)) => *assembler,
                _ => panic!("partial candidate must retain its authenticated assembler"),
            };
            for shred in verified {
                assembler.insert_verified(shred.unwrap()).unwrap();
            }
            let candidate = match pool.install(|| assembler.try_finish_verified(marker.clone())) {
                Ok(candidate) => candidate,
                Err((error, _)) => panic!("complete authenticated candidate failed: {error:?}"),
            };
            assert!(
                candidate
                    .clone()
                    .into_parts(&chain, &FalconKeypair::generate().public_key())
                    .is_err()
            );
            let (actual_marker, _, actual_payload) =
                candidate.into_parts(&chain, &leader.public_key()).unwrap();
            assert_eq!(actual_marker.block_commitment, marker.block_commitment);
            assert_eq!(actual_payload, payload);
        }
    }

    fn outbound_control_pressure_fixture() -> (
        tempfile::TempDir,
        PqNode,
        Pubkey,
        BlockWitness,
        Vec<Vec<u8>>,
    ) {
        let (directory, mut node) = repair_fixture();
        let peer = *node.outbound.keys().next().unwrap();
        let payload = vec![0x76; 128 * 1024];
        let witness = repair_witness(&node, 1, node.adopted_anchor().unwrap().hash, &payload);
        node.send_witness(Some(peer), &witness).unwrap();
        let mut request = vec![5];
        request.extend_from_slice(&witness.marker.block_commitment);
        node.broadcast(&request);
        let frames = (1..=24)
            .map(|slot| {
                let evidence = node
                    .signer
                    .sign(ConsensusMessage {
                        epoch: 7,
                        slot,
                        kind: MessageKind::SkipVote,
                        block: None,
                    })
                    .unwrap();
                evidence
                    .verify(&node.chain, &node.signer.public_key())
                    .unwrap();
                let mut frame = vec![3];
                frame.extend(evidence.encode().unwrap());
                node.queue_evidence(None, frame.clone()).unwrap();
                frame
            })
            .collect();
        (directory, node, peer, witness, frames)
    }

    #[test]
    fn control_pressure_does_not_stop_available_authenticated_repair_bulk() {
        let (_directory, mut node, peer, witness, _frames) = outbound_control_pressure_fixture();
        let hash = witness.marker.block_commitment;
        let mut assembler = CandidateAssembler::new(
            node.chain,
            node.leader.public_key(),
            7,
            1,
            witness.marker.candidate,
            witness.marker.parent,
        );
        let evidence_count = node.outbound[&peer].evidence.len();
        let mut data_frames = 0;
        for turn in 0..16 {
            let mut accepted = Vec::new();
            let queue = node.outbound.get_mut(&peer).unwrap();
            let complete = queue
                .flush(
                    &node.evidence_packets,
                    &BTreeMap::new(),
                    &node.outbound_witnesses,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    |frame| {
                        // The actual transport has independent control and bulk
                        // senders under shared bounds. Saturated control must not
                        // suppress the available bounded bulk reservation.
                        if frame[0] != 1 || accepted.len() == 4 {
                            return false;
                        }
                        accepted.push(frame.to_vec());
                        true
                    },
                )
                .unwrap();
            assert!(!complete, "control is still full");
            assert_eq!(
                accepted.len(),
                4,
                "available repair bulk must progress even when control is full"
            );
            assert!(accepted.iter().map(Vec::len).sum::<usize>() <= 32 * 1024);
            assert_eq!(queue.evidence.len(), evidence_count);
            assert_eq!(queue.repairs.front(), Some(&hash));
            assert_eq!(queue.blocks.front(), Some(&(hash, (turn + 1) * 4)));
            for frame in accepted {
                assembler
                    .insert(AuthenticatedShred::decode(&frame[1..]).unwrap())
                    .unwrap();
                data_frames += 1;
            }
        }
        assert_eq!(data_frames, witness.shreds.len());
        assert!(node.outbound[&peer].repair_blocks.contains(&hash));
        let mut terminal = None;
        node.outbound
            .get_mut(&peer)
            .unwrap()
            .flush(
                &node.evidence_packets,
                &BTreeMap::new(),
                &node.outbound_witnesses,
                &BTreeMap::new(),
                &BTreeMap::new(),
                |frame| {
                    if frame[0] == 2 {
                        terminal = Some(FinalMarker::decode(&frame[1..]).unwrap());
                    }
                    true
                },
            )
            .unwrap();
        assert_eq!(
            assembler.finish(&terminal.unwrap()).unwrap(),
            vec![0x76; 128 * 1024]
        );
        assert!(!node.outbound[&peer].queued_blocks.contains(&hash));
        assert!(!node.outbound[&peer].repair_blocks.contains(&hash));
    }

    #[test]
    fn control_pressure_reserves_causal_request_and_terminal_amid_evidence_refill() {
        let (_directory, mut node, peer, witness, frames) = outbound_control_pressure_fixture();
        let hash = witness.marker.block_commitment;
        let other_hash = repair_witness(&node, 2, hash, &encode_block(&[]).unwrap())
            .marker
            .block_commitment;
        let mut assembler = CandidateAssembler::new(
            node.chain,
            node.leader.public_key(),
            7,
            1,
            witness.marker.candidate,
            witness.marker.parent,
        );
        let mut terminal = None;
        let mut data_frames = 0;
        let mut requested = false;
        let mut evidence_sent = 0;
        for turn in 0..18 {
            // Model the existing retry path: sent evidence IDs can be queued
            // again, so the finite authenticated evidence set stays nonempty.
            for frame in &frames {
                node.queue_evidence(None, frame.clone()).unwrap();
            }
            // A bounded causal request backlog can be due when the terminal
            // becomes ready. Both hashes identify actually signed witnesses.
            if data_frames == witness.shreds.len() {
                for requested_hash in [hash, other_hash] {
                    let mut frame = vec![5];
                    frame.extend_from_slice(&requested_hash);
                    node.broadcast(&frame);
                }
            }
            let mut accepted = Vec::new();
            let mut control = 0;
            let mut bulk = 0;
            node.outbound
                .get_mut(&peer)
                .unwrap()
                .flush(
                    &node.evidence_packets,
                    &BTreeMap::new(),
                    &node.outbound_witnesses,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    |frame| {
                        if matches!(frame[0], 2 | 3 | 5) {
                            if control == 2 {
                                return false;
                            }
                            control += 1;
                        } else {
                            if bulk == 4 {
                                return false;
                            }
                            bulk += 1;
                        }
                        accepted.push(frame.to_vec());
                        true
                    },
                )
                .unwrap();
            assert!(control <= 2 && bulk <= 4);
            assert!(accepted.iter().map(Vec::len).sum::<usize>() <= 32 * 1024);
            if turn == 0 {
                assert!(
                    accepted.iter().any(|frame| frame[0] == 5),
                    "continuous evidence must not consume every causal repair reservation"
                );
            }
            for frame in accepted {
                match frame[0] {
                    1 => {
                        assembler
                            .insert(AuthenticatedShred::decode(&frame[1..]).unwrap())
                            .unwrap();
                        data_frames += 1;
                    }
                    2 => {
                        assert_eq!(
                            data_frames,
                            witness.shreds.len(),
                            "terminal follows complete data prefix"
                        );
                        terminal = Some(FinalMarker::decode(&frame[1..]).unwrap());
                    }
                    3 => {
                        SignedEvidence::decode(&frame[1..])
                            .unwrap()
                            .verify(&node.chain, &node.signer.public_key())
                            .unwrap();
                        evidence_sent += 1;
                    }
                    5 => {
                        assert!(frame[1..] == hash || frame[1..] == other_hash);
                        requested |= frame[1..] == hash;
                    }
                    _ => panic!("unexpected outbound frame"),
                }
            }
            assert!(node.outbound[&peer].evidence.len() <= frames.len());
            if terminal.is_some() {
                break;
            }
        }
        assert!(requested && evidence_sent > 0);
        assert!(
            terminal.is_some(),
            "causal repair must complete while evidence continually refills"
        );
        assert_eq!(
            assembler.finish(&terminal.unwrap()).unwrap(),
            vec![0x76; 128 * 1024]
        );
        assert!(node.outbound[&peer].blocks.is_empty());
        assert!(!node.outbound[&peer].repair_blocks.contains(&hash));
    }

    #[test]
    fn bounded_outbound_preserves_control_witness_and_live_quorum() {
        let chain = [0x75; 32];
        let signer = FalconKeypair::generate();
        let payload = vec![0x76; 128 * 1024];
        let batch = SignedBatch::build(
            &chain,
            &signer,
            BatchContext {
                leader_epoch: 7,
                slot: 1,
                candidate: [0x77; 48],
                parent: [0x78; 48],
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            64,
            64,
        )
        .unwrap();
        let marker =
            FinalMarker::build(&chain, &signer, std::slice::from_ref(&batch), &payload).unwrap();
        let hash = marker.block_commitment;
        let witnesses = BTreeMap::from([(
            hash,
            BlockWitness {
                marker: marker.clone(),
                shreds: batch.shreds,
            },
        )]);
        let evidence = BTreeMap::from([([1; 48], (1, vec![3, 1])), ([2; 48], (1, vec![3, 2]))]);
        let mut queue = PeerOutbound::default();
        queue.evidence.extend(evidence.keys().copied());
        queue.queued_evidence.extend(evidence.keys().copied());
        queue.repairs.push_back([3; 48]);
        queue.queued_repairs.insert([3; 48]);
        queue.blocks.push_back((hash, 0));
        queue.queued_blocks.insert(hash);
        queue.repair_blocks.insert(hash);
        let mut assembler =
            CandidateAssembler::new(chain, signer.public_key(), 7, 1, [0x77; 48], [0x78; 48]);
        let mut terminal = None;
        let mut first = true;
        let mut rounds = 0;
        while !queue.blocks.is_empty() {
            rounds += 1;
            assert!(rounds < 128);
            let mut accepted = Vec::new();
            let mut bytes = 0;
            let complete = queue
                .flush(
                    &evidence,
                    &BTreeMap::new(),
                    &witnesses,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    |frame| {
                        if accepted.len() == 4 || bytes + frame.len() > 16 * 1024 {
                            return false;
                        }
                        bytes += frame.len();
                        accepted.push(frame.to_vec());
                        true
                    },
                )
                .unwrap();
            assert!(bytes <= 16 * 1024 && accepted.len() <= 4);
            if first {
                assert!(!complete);
                assert_eq!(
                    accepted.iter().map(|frame| frame[0]).collect::<Vec<_>>(),
                    [5, 3, 3, 1]
                );
                assert_eq!(queue.blocks.front(), Some(&(hash, 1)));
                assert!(queue.queued_blocks.contains(&hash));
                first = false;
            }
            for frame in accepted {
                match frame[0] {
                    1 => {
                        assembler
                            .insert(AuthenticatedShred::decode(&frame[1..]).unwrap())
                            .unwrap();
                    }
                    2 => terminal = Some(FinalMarker::decode(&frame[1..]).unwrap()),
                    _ => {}
                }
            }
        }
        assert!(!queue.queued_blocks.contains(&hash));
        assert!(!queue.repair_blocks.contains(&hash));
        assert_eq!(assembler.finish(&terminal.unwrap()).unwrap(), payload);
    }

    #[test]
    fn compaction_preserves_old_explicit_repair_until_bounded_handoff() {
        let peer = Pubkey::new_unique();
        let ids = [[1; 48], [2; 48], [3; 48]];
        let mut packets = BTreeMap::from([
            (ids[0], (1, vec![3, 1])),
            (ids[1], (2, vec![3, 2])),
            (ids[2], (101, vec![3, 3])),
        ]);
        let mut queue = PeerOutbound::default();
        queue.evidence.extend(ids);
        queue.queued_evidence.extend(ids);
        queue.repair_evidence.insert(ids[0]);
        let mut outbound = BTreeMap::from([(peer, queue)]);
        compact_evidence_packets(100, &mut packets, &mut outbound);
        assert_eq!(
            packets.keys().copied().collect::<Vec<_>>(),
            [ids[0], ids[2]]
        );
        let mut accepted = Vec::new();
        let queue = outbound.get_mut(&peer).unwrap();
        assert!(
            !queue
                .flush(
                    &packets,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    |_| false
                )
                .unwrap()
        );
        assert!(queue.repair_evidence.contains(&ids[0]));
        assert!(
            queue
                .flush(
                    &packets,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    |frame| {
                        accepted.push(frame.to_vec());
                        true
                    }
                )
                .unwrap()
        );
        assert_eq!(accepted, [vec![3, 1], vec![3, 3]]);
        assert!(queue.repair_evidence.is_empty());
        compact_evidence_packets(100, &mut packets, &mut outbound);
        assert_eq!(packets.keys().copied().collect::<Vec<_>>(), [ids[2]]);
    }

    #[test]
    #[ignore = "requires AGAVE_PQ_CLUSTER_MANIFEST from the native initializer"]
    fn persisted_native_genesis_accepts_its_actual_load_transactions() {
        let path = std::env::var("AGAVE_PQ_CLUSTER_MANIFEST").unwrap();
        let manifest: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let node = &manifest["nodes"][0];
        let genesis =
            solana_genesis_config::GenesisConfig::load(Path::new(node["ledger"].as_str().unwrap()))
                .unwrap();
        let bank_forks = BankForks::new_rw_arc(Bank::new_from_genesis(
            &genesis,
            Arc::default(),
            vec![],
            None,
            solana_accounts_db::accounts_db::AccountsDbConfig::default(),
            None,
            None,
            Arc::default(),
            None,
            None,
        ));
        let parent = bank_forks.read().unwrap().root_bank();
        parent.freeze();
        let wallet = &manifest["wallets"][0];
        let authority = Pubkey::from_str(wallet["address"].as_str().unwrap()).unwrap();
        let key = FalconKeypair::load_private(Path::new(wallet["private_key"].as_str().unwrap()))
            .unwrap();
        let recipient = Pubkey::from_str(manifest["recipient"].as_str().unwrap()).unwrap();
        let config = pq::Config {
            chain_id: decode_hex(manifest["chain"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            migration_context: decode_hex(manifest["migration_context"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            cutoff_slot: manifest["cutoff_slot"].as_u64().unwrap(),
        };
        let bank = Bank::new_isolated_pq_child(
            parent.clone(),
            SlotLeader {
                id: Pubkey::from_str(node["id"].as_str().unwrap()).unwrap(),
                vote_address: Pubkey::from_str(node["vote_account"].as_str().unwrap()).unwrap(),
            },
            1,
        )
        .unwrap();
        let tx = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[authority]),
                    system_instruction::transfer(&authority, &recipient, 7),
                ],
                Some(&authority),
                &parent.last_blockhash(),
            )),
            &config,
            &[&key],
        )
        .unwrap();
        parent.verify_pq_transaction_for_ingress(&tx).unwrap();
        let before = bank.get_balance(&recipient);
        let result = process_with_status(&bank, tx);
        assert!(
            result.is_ok(),
            "actual native load execution failed: {result:?}"
        );
        assert_eq!(result.unwrap().1.status, Ok(()));
        assert_eq!(bank.get_balance(&recipient), before + 7);
        assert_eq!(parent.get_balance(&recipient), before);
    }

    #[test]
    fn authenticated_candidates_execute_real_svm_and_preserve_charged_failures() {
        authenticated_candidates_with_genesis_features(true);
    }

    #[test]
    fn default_genesis_candidates_preserve_committed_execution() {
        authenticated_candidates_with_genesis_features(false);
    }

    #[test]
    fn native_block_bridge_authenticates_legacy_before_cutoff_and_rejects_after() {
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(1_000_000_000, &Pubkey::new_unique(), 1_000_000);
        genesis_config.rent = solana_rent::Rent::default();
        let config = pq::Config {
            chain_id: [0x61; 32],
            migration_context: [0x62; 32],
            cutoff_slot: 2,
        };
        genesis_config
            .accounts
            .insert(pq::CONFIG_ADDRESS, config.account(10_000_000));
        let recipient = Pubkey::new_unique();
        genesis_config.accounts.insert(
            recipient,
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        );
        let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let root = forks.read().unwrap().root_bank();
        root.freeze();
        let before =
            Arc::new(Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap());
        let signed = |amount| {
            VersionedTransaction::from(Transaction::new_signed_with_payer(
                &[system_instruction::transfer(
                    &mint_keypair.pubkey(),
                    &recipient,
                    amount,
                )],
                Some(&mint_keypair.pubkey()),
                &[&mint_keypair],
                root.last_blockhash(),
            ))
        };
        let valid = signed(7);
        let entry = MempoolEntry {
            raw: bincode::serialize(&valid).unwrap(),
            transaction: valid.clone(),
            intent: None,
        };
        assert!(!entry.processed(&before).unwrap());
        let mut forged = signed(8);
        forged.signatures[0] = valid.signatures[0];
        assert!(process_with_status(&before, forged).is_err());
        assert_eq!(before.get_balance(&recipient), 1_000_000);
        assert_eq!(
            process_with_status(&before, valid).unwrap().1.status,
            Ok(())
        );
        assert!(entry.processed(&before).unwrap());
        before.freeze();
        before.detach_isolated_pq_parent().unwrap();
        let after = Bank::new_isolated_pq_child(before.clone(), *before.leader(), 2).unwrap();
        assert!(process_with_status(&after, signed(9)).is_err());
        assert_eq!(after.get_balance(&recipient), 1_000_007);
    }

    #[test]
    fn committed_archive_pruning_removes_pq_aliases_and_preserves_uncommitted_intents() {
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000);
        genesis_config.rent = solana_rent::Rent::default();
        genesis_config.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        let config = pq::Config {
            chain_id: [0x65; 32],
            migration_context: [0x66; 32],
            cutoff_slot: 2,
        };
        genesis_config.accounts.insert(
            pq::CONFIG_ADDRESS,
            config.account(genesis_config.rent.minimum_balance(80)),
        );
        let authority = mint_keypair.pubkey();
        let key = FalconKeypair::generate();
        let policy = AuthRecord::new(
            authority.to_bytes(),
            key.public_key(),
            Origin::FreshIdentity,
        )
        .encode();
        genesis_config.accounts.insert(
            pq::policy_address(&authority),
            Account {
                lamports: genesis_config.rent.minimum_balance(policy.len()),
                data: policy,
                owner: pq::PROGRAM_ID,
                rent_epoch: u64::MAX,
                ..Account::default()
            },
        );
        let recipient = Pubkey::new_unique();
        let legacy_key = solana_keypair::Keypair::new();
        for address in [recipient, legacy_key.pubkey()] {
            genesis_config.accounts.insert(
                address,
                Account {
                    lamports: 1_000_000_000,
                    ..Account::default()
                },
            );
        }
        let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let root = forks.read().unwrap().root_bank();
        root.freeze();
        let signed = |amount| {
            sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[
                        authenticate_instruction(&[authority]),
                        system_instruction::transfer(&authority, &recipient, amount),
                    ],
                    Some(&authority),
                    &root.last_blockhash(),
                )),
                &config,
                &[&key],
            )
            .unwrap()
        };
        let legacy = |amount| {
            VersionedTransaction::from(Transaction::new_signed_with_payer(
                &[system_instruction::transfer(
                    &legacy_key.pubkey(),
                    &recipient,
                    amount,
                )],
                Some(&legacy_key.pubkey()),
                &[&legacy_key],
                root.last_blockhash(),
            ))
        };
        let good = signed(7);
        let alias = signed(7);
        let failure = signed(u64::MAX);
        let failure_alias = signed(u64::MAX);
        let unrelated = signed(8);
        let rejected = signed(9);
        let legacy_good = legacy(10);
        let legacy_pending = legacy(11);
        assert_ne!(
            bincode::serialize(&good).unwrap(),
            bincode::serialize(&alias).unwrap()
        );
        assert_eq!(
            pq::transaction_intent_identity(&good, &config.chain_id).unwrap(),
            pq::transaction_intent_identity(&alias, &config.chain_id).unwrap()
        );
        let mut mempool = IndexedMempool::default();
        let add = |pool: &mut IndexedMempool, transaction: &VersionedTransaction| {
            root.verify_pq_transaction_for_ingress(transaction).unwrap();
            let raw = bincode::serialize(transaction).unwrap();
            let id = hash_commitment(b"agave-pq-transaction-wire-v1", &[&raw]);
            pool.insert(
                id,
                MempoolEntry {
                    raw,
                    transaction: transaction.clone(),
                    intent: pq::is_pq_transaction(transaction).then(|| {
                        pq::transaction_intent_identity(transaction, &config.chain_id).unwrap()
                    }),
                },
            )
            .unwrap();
            id
        };
        let ids = [
            &good,
            &alias,
            &failure,
            &failure_alias,
            &unrelated,
            &legacy_good,
            &legacy_pending,
        ]
        .map(|transaction| add(&mut mempool, transaction));
        let removed = add(&mut mempool, &rejected);
        let mut order = IndexedAdmissionOrder::default();
        let mut gossip = BTreeMap::new();
        for (position, id) in ids.iter().chain(std::iter::once(&removed)).enumerate() {
            let sequence = order.reserve(*id).unwrap();
            order.insert_reserved(*id, sequence);
            // Peer-only ingress creates valid stable holes in the gossip subset.
            if position % 2 == 0 {
                gossip.insert(sequence, *id);
            }
        }
        let check_index = |pool: &IndexedMempool| {
            let mut expected = BTreeMap::<_, BTreeSet<_>>::new();
            for (id, entry) in &pool.entries {
                expected
                    .entry(entry.replay_key().unwrap())
                    .or_default()
                    .insert(*id);
            }
            assert_eq!(pool.replay, expected);
            assert_eq!(
                pool.bytes,
                pool.entries
                    .values()
                    .map(|entry| entry.len())
                    .sum::<usize>()
            );
        };
        check_index(&mempool);
        assert!(remove_admitted_wire(&mut mempool, &mut order, &mut gossip, &removed).is_some());
        assert!(remove_admitted_wire(&mut mempool, &mut order, &mut gossip, &removed).is_none());
        check_index(&mempool);
        // Execution on a losing same-slot branch is not a certified commit.
        let alternate = Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap();
        process_with_status(&alternate, unrelated.clone()).unwrap();
        assert!(alternate.pq_transaction_processed(&unrelated).unwrap());
        let winner = Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap();
        let records = [&good, &failure, &legacy_good]
            .map(|transaction| process_with_status(&winner, transaction.clone()).unwrap());
        assert_eq!(records[0].1.status, Ok(()));
        assert!(records[1].1.status.is_err());
        assert_eq!(records[2].1.status, Ok(()));
        assert!(winner.pq_transaction_processed(&alias).unwrap());
        assert!(winner.pq_transaction_processed(&failure_alias).unwrap());
        assert!(!winner.pq_transaction_processed(&unrelated).unwrap());
        // A native telemetry-cache positive must never trigger a pending scan
        // or remove a distinct full-width intent from this index.
        winner.status_cache.write().unwrap().insert(
            &winner.last_blockhash(),
            unrelated.signatures[0],
            winner.slot(),
            Ok(()),
        );
        assert!(
            winner
                .get_signature_status(&unrelated.signatures[0])
                .is_some()
        );
        assert!(!winner.pq_transaction_processed(&unrelated).unwrap());
        winner.freeze();
        let frozen_state = winner.pq_state_commitment();
        let removed_aliases = prune_committed_admission(
            &mut mempool,
            &mut order,
            &mut gossip,
            &records,
            &config.chain_id,
        )
        .unwrap();
        assert_eq!(
            removed_aliases.into_iter().collect::<BTreeSet<_>>(),
            [ids[0], ids[1], ids[2], ids[3], ids[5]]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            order.iter().copied().collect::<Vec<_>>(),
            vec![ids[4], ids[6]]
        );
        assert_eq!(order.by_id[&ids[4]], 5);
        assert_eq!(order.by_id[&ids[6]], 7);
        assert_eq!(gossip.keys().copied().collect::<Vec<_>>(), vec![5, 7]);
        // Each peer independently skips removed and peer-only sequence holes.
        for (cursor, expected) in [(0, vec![ids[4], ids[6]]), (6, vec![ids[6]]), (8, vec![])] {
            let mut peer = PeerOutbound {
                next_transaction: cursor,
                ..PeerOutbound::default()
            };
            let mut delivered = Vec::new();
            peer.flush(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &BTreeMap::new(),
                &gossip,
                &mempool,
                |frame| {
                    assert_eq!(frame[0], 4);
                    delivered.push(hash_commitment(
                        b"agave-pq-transaction-wire-v1",
                        &[&frame[1..]],
                    ));
                    true
                },
            )
            .unwrap();
            assert_eq!(delivered, expected);
        }
        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains_key(&ids[4]));
        assert!(mempool.contains_key(&ids[6]));
        check_index(&mempool);
        assert!(
            prune_committed_admission(
                &mut mempool,
                &mut order,
                &mut gossip,
                &records,
                &config.chain_id,
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(winner.pq_state_commitment(), frozen_state);
        assert!(remove_admitted_wire(&mut mempool, &mut order, &mut gossip, &ids[4]).is_some());
        assert!(remove_admitted_wire(&mut mempool, &mut order, &mut gossip, &ids[6]).is_some());
        assert!(order.by_sequence.is_empty() && order.by_id.is_empty() && gossip.is_empty());
        assert!(mempool.is_empty() && mempool.replay.is_empty());
        assert_eq!(mempool.bytes, 0);
    }

    #[test]
    fn indexed_admission_bounds_preflight_without_mutation() {
        let mut order = IndexedAdmissionOrder::default();
        let id = [0x45; 48];
        order.next_sequence = u64::MAX - 1;
        let sequence = order.reserve(id).unwrap();
        order.insert_reserved(id, sequence);
        assert_eq!(order.by_id[&id], u64::MAX - 1);
        assert!(order.reserve([0x46; 48]).is_err());
        assert!(order.reserve(id).is_err());
        assert_eq!(order.iter().copied().collect::<Vec<_>>(), vec![id]);
        assert_eq!(order.remove(&id), Some(u64::MAX - 1));
        assert!(order.by_sequence.is_empty() && order.by_id.is_empty());
        // Emptying queues cannot reuse a previously consumed admission sequence.
        assert_eq!(order.next_sequence, u64::MAX);
        assert!(order.reserve([0x47; 48]).is_err());
    }

    fn authenticated_candidates_with_genesis_features(enable_features: bool) {
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000_000);
        if !enable_features {
            genesis_config
                .accounts
                .retain(|key, _| !agave_feature_set::FEATURE_NAMES.contains_key(key));
            genesis_config
                .accounts
                .remove(&agave_votor_messages::migration::GENESIS_CERTIFICATE_ACCOUNT);
        }
        genesis_config.rent = solana_rent::Rent::default();
        genesis_config.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        let chain = [0x22; 32];
        let config = pq::Config {
            chain_id: chain,
            migration_context: [0x23; 32],
            cutoff_slot: 1,
        };
        genesis_config.accounts.insert(
            pq::CONFIG_ADDRESS,
            config.account(genesis_config.rent.minimum_balance(80)),
        );
        let key = FalconKeypair::generate();
        let authority = mint_keypair.pubkey();
        let record = AuthRecord::new(
            authority.to_bytes(),
            key.public_key(),
            Origin::FreshIdentity,
        )
        .encode();
        genesis_config.accounts.insert(
            pq::policy_address(&authority),
            Account {
                lamports: genesis_config.rent.minimum_balance(record.len()),
                data: record,
                owner: pq::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        let recipient = Pubkey::new_unique();
        let initial_recipient = 1_000_000;
        genesis_config.accounts.insert(
            recipient,
            Account {
                lamports: initial_recipient,
                ..Account::default()
            },
        );
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let root = bank_forks.read().unwrap().root_bank();
        root.freeze();
        let parent = [0x33; 48];
        let initial_authority = root.get_balance(&authority);
        let signed = |amount| {
            let instructions = [
                authenticate_instruction(&[authority]),
                system_instruction::transfer(&authority, &recipient, amount),
            ];
            let message = VersionedMessage::Legacy(Message::new_with_blockhash(
                &instructions,
                Some(&authority),
                &root.last_blockhash(),
            ));
            sign_transaction(message, &config, &[&key]).unwrap()
        };
        let good = signed(7);
        let charged_failure = signed(u64::MAX);
        let cached = MempoolEntry {
            raw: bincode::serialize(&good).unwrap(),
            transaction: good.clone(),
            intent: Some(pq::transaction_intent_identity(&good, &chain).unwrap()),
        };
        assert!(!cached.processed(&root).unwrap());
        assert!(!root.pq_transaction_processed(&good).unwrap());
        let mut alias: [u8; 64] = good.signatures[0].as_ref().try_into().unwrap();
        // Native telemetry caches a twenty-byte slice, excluding the final
        // byte. An unrelated identifier can therefore yield a positive native
        // status without this exact PQ intent ever having committed.
        alias[63] ^= 1;
        root.status_cache.write().unwrap().insert(
            &root.last_blockhash(),
            solana_signature::Signature::from(alias),
            root.slot(),
            Ok(()),
        );
        assert!(root.get_signature_status(&good.signatures[0]).is_some());
        assert!(!root.pq_transaction_processed(&good).unwrap());
        assert!(!cached.processed(&root).unwrap());
        let payload = encode_block(&[
            bincode::serialize(&good).unwrap(),
            bincode::serialize(&charged_failure).unwrap(),
        ])
        .unwrap();
        let mut runtime = RuntimeForks {
            banks: BTreeMap::from([(parent, root.clone())]),
            states: BTreeMap::from([(parent, root.pq_state_commitment())]),
            executions: BTreeMap::new(),
            archives: BTreeMap::new(),
            leaders: vec![*root.leader()],
            first_slot: 1,
            chain,
            max_block_bytes: MAX_BLOCK_BYTES,
            max_transactions: 4096,
            executor: Arc::new(PqExecutor::new(2).unwrap()),
        };
        let reference = BlockRef {
            slot: 1,
            hash: [0x44; 48],
        };
        if !enable_features {
            // Exercise the producer path: it executes once before building
            // the signed witness, then lends the private capability to QG.
            let bank = Arc::new(
                Bank::new_isolated_pq_child(root.clone(), *root.leader(), reference.slot).unwrap(),
            );
            let records = vec![
                process_with_status(&bank, good.clone()).unwrap(),
                process_with_status(&bank, charged_failure.clone()).unwrap(),
            ];
            complete_bank(&bank, &chain, &parent, &payload);
            let binding = ExecutedCandidate::new(chain, parent, &root, &bank, &payload).unwrap();
            runtime.states.insert(reference.hash, bank_state(&bank));
            runtime.banks.insert(reference.hash, bank);
            runtime.executions.insert(reference.hash, binding);
            runtime.archives.insert(reference.hash, Arc::new(records));
        }
        runtime.max_block_bytes = payload.len() - 1;
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference,
                    parent,
                    payload: &payload,
                })
                .is_none()
        );
        runtime.max_block_bytes = payload.len();
        let execution = runtime
            .validate(&ExecutionCandidate {
                reference,
                parent,
                payload: &payload,
            })
            .unwrap();
        let cached_bank = runtime.banks[&reference.hash].clone();
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference,
                    parent,
                    payload: &payload
                })
                .is_some()
        );
        assert!(Arc::ptr_eq(&cached_bank, &runtime.banks[&reference.hash]));
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference,
                    parent,
                    payload: b"changed payload"
                })
                .is_none()
        );
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference: BlockRef {
                        slot: 2,
                        ..reference
                    },
                    parent,
                    payload: &payload
                })
                .is_none()
        );
        let alternate_parent = [0x34; 48];
        runtime
            .states
            .insert(alternate_parent, root.pq_state_commitment());
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference,
                    parent: alternate_parent,
                    payload: &payload
                })
                .is_none()
        );
        runtime.chain[0] ^= 1;
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference,
                    parent,
                    payload: &payload
                })
                .is_none()
        );
        runtime.chain = chain;
        runtime.states.get_mut(&reference.hash).unwrap()[0] ^= 1;
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference,
                    parent,
                    payload: &payload
                })
                .is_none()
        );
        runtime.states.insert(reference.hash, execution.state_root);
        assert!(
            ExecutedCandidate::new(chain, parent, &cached_bank, &cached_bank, &payload).is_err()
        );
        let child = &runtime.banks[&reference.hash];
        assert!(child.is_frozen());
        assert!(child.pq_transaction_processed(&good).unwrap());
        assert!(cached.processed(child).unwrap());
        assert!(!root.pq_transaction_processed(&good).unwrap());
        assert!(child.pq_transaction_processed(&charged_failure).unwrap());
        assert_eq!(child.get_balance(&recipient), initial_recipient + 7);
        assert_eq!(root.get_balance(&recipient), initial_recipient);
        assert_eq!(
            child.get_balance(&authority),
            initial_authority - 7 - 10_000
        );
        assert!(
            child
                .get_signature_status(&charged_failure.signatures[0])
                .unwrap()
                .is_err()
        );
        assert_ne!(execution.state_root, execution.parent_state_root);
        let legacy = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&authority, &recipient, 1)],
            Some(&authority),
            &[&mint_keypair],
            root.last_blockhash(),
        );
        let invalid_payload =
            encode_block(&[bincode::serialize(&VersionedTransaction::from(legacy)).unwrap()])
                .unwrap();
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference: BlockRef {
                        slot: 1,
                        hash: [0x55; 48]
                    },
                    parent,
                    payload: &invalid_payload
                })
                .is_none()
        );
        let mut bad = good;
        match &mut bad.message {
            VersionedMessage::Legacy(message) => {
                let last = message.instructions[0].data.last_mut().unwrap();
                *last ^= 1;
            }
            _ => unreachable!(),
        }
        let bad_payload = encode_block(&[bincode::serialize(&bad).unwrap()]).unwrap();
        assert!(
            runtime
                .validate(&ExecutionCandidate {
                    reference: BlockRef {
                        slot: 1,
                        hash: [0x66; 48]
                    },
                    parent,
                    payload: &bad_payload
                })
                .is_none()
        );
        assert_eq!(root.get_balance(&authority), initial_authority);
    }

    #[test]
    fn pq_signature_executes_real_sbf_and_live_winner_matches_isolated_state() {
        use solana_instruction::{AccountMeta, Instruction};
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000_000);
        genesis_config.rent = solana_rent::Rent::default();
        genesis_config.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        let config = pq::Config {
            chain_id: [0x62; 32],
            migration_context: [0x63; 32],
            cutoff_slot: 1,
        };
        genesis_config.accounts.insert(
            pq::CONFIG_ADDRESS,
            config.account(genesis_config.rent.minimum_balance(80)),
        );
        let payer = mint_keypair.pubkey();
        let payer_key = FalconKeypair::generate();
        let source_key = FalconKeypair::generate();
        let source = Pubkey::new_from_array(agave_pq_crypto::auth::fresh_address(
            &config.chain_id,
            &source_key.public_key(),
            &[0x64; 32],
        ));
        for (authority, key) in [(payer, &payer_key), (source, &source_key)] {
            let data = AuthRecord::new(
                authority.to_bytes(),
                key.public_key(),
                Origin::FreshIdentity,
            )
            .encode();
            genesis_config.accounts.insert(
                pq::policy_address(&authority),
                Account {
                    lamports: genesis_config.rent.minimum_balance(data.len()),
                    data,
                    owner: pq::PROGRAM_ID,
                    executable: false,
                    rent_epoch: u64::MAX,
                },
            );
        }
        let program = Pubkey::new_unique();
        let elf = include_bytes!("../tests/fixtures/pq-svm/move_funds.so").to_vec();
        genesis_config.accounts.insert(
            program,
            Account {
                lamports: genesis_config.rent.minimum_balance(elf.len()),
                data: elf,
                owner: solana_sdk_ids::bpf_loader::id(),
                executable: true,
                rent_epoch: u64::MAX,
            },
        );
        genesis_config.accounts.insert(
            source,
            Account {
                lamports: 10_000_000,
                owner: program,
                ..Account::default()
            },
        );
        let recipient = Pubkey::new_unique();
        genesis_config.accounts.insert(
            recipient,
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        );
        let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
        let root = forks.read().unwrap().root_bank();
        root.freeze();
        let instructions = [
            authenticate_instruction(&[payer, source]),
            Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(source, true),
                    AccountMeta::new_readonly(program, false),
                    AccountMeta::new(recipient, false),
                ],
                data: 7u64.to_le_bytes().to_vec(),
            },
        ];
        let transaction = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &instructions,
                Some(&payer),
                &root.last_blockhash(),
            )),
            &config,
            &[&payer_key, &source_key],
        )
        .unwrap();
        let mut runtime = RuntimeForks {
            banks: BTreeMap::from([([0x65; 48], root.clone())]),
            states: BTreeMap::from([([0x65; 48], root.pq_state_commitment())]),
            executions: BTreeMap::new(),
            archives: BTreeMap::new(),
            leaders: vec![*root.leader()],
            first_slot: 1,
            chain: config.chain_id,
            max_block_bytes: MAX_BLOCK_BYTES,
            max_transactions: 4096,
            executor: Arc::new(PqExecutor::new(2).unwrap()),
        };
        let payload = encode_block(&[bincode::serialize(&transaction).unwrap()]).unwrap();
        let candidate = ExecutionCandidate {
            reference: BlockRef {
                slot: 1,
                hash: [0x66; 48],
            },
            parent: [0x65; 48],
            payload: &payload,
        };
        let executed = runtime.validate(&candidate).unwrap();
        let record = &runtime.archives[&candidate.reference.hash][0];
        assert_eq!(record.1.status, Ok(()));
        assert!(
            record
                .1
                .log_messages
                .as_ref()
                .unwrap()
                .iter()
                .any(|line| line.contains("consumed"))
        );
        assert!(record.1.compute_units_consumed.unwrap() > 0);
        assert_eq!(
            runtime.banks[&candidate.reference.hash].get_balance(&source),
            9_999_993
        );
        assert_eq!(
            runtime.banks[&candidate.reference.hash].get_balance(&recipient),
            1_000_007
        );
        assert_eq!(root.get_balance(&source), 10_000_000);
        let candidate_bank = runtime.banks[&candidate.reference.hash].clone();
        let count_before = candidate_bank.transaction_count();
        let rooted = forks
            .write()
            .unwrap()
            .promote_pq_candidate(candidate_bank.clone(), root.pq_state_commitment())
            .unwrap();
        assert!(Arc::ptr_eq(&rooted, &candidate_bank));
        assert_eq!(rooted.transaction_count(), count_before);
        assert_eq!(rooted.pq_state_commitment(), executed.state_root);
        assert!(rooted.pq_transaction_processed(&transaction).unwrap());
        assert_eq!(rooted.get_balance(&source), 9_999_993);
        assert_eq!(
            forks.read().unwrap().root_bank().get_balance(&recipient),
            1_000_007
        );
    }

    #[test]
    fn certified_promotion_exposes_state_before_receipts_and_never_reexecutes() {
        for corrupt_archive in [false, true] {
            let GenesisConfigInfo {
                mut genesis_config,
                mint_keypair,
                ..
            } = create_genesis_config_with_leader(
                10_000_000_000,
                &Pubkey::new_unique(),
                1_000_000_000,
            );
            let recipient = Pubkey::new_unique();
            genesis_config.accounts.insert(
                recipient,
                Account {
                    lamports: 1_000_000,
                    ..Account::default()
                },
            );
            let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
            let root = forks.read().unwrap().root_bank();
            root.freeze();
            let transaction = VersionedTransaction::from(Transaction::new_signed_with_payer(
                &[system_instruction::transfer(
                    &mint_keypair.pubkey(),
                    &recipient,
                    7,
                )],
                Some(&mint_keypair.pubkey()),
                &[&mint_keypair],
                root.last_blockhash(),
            ));
            let signature = transaction.signatures[0];
            let candidate =
                Arc::new(Bank::new_isolated_pq_child(root.clone(), *root.leader(), 1).unwrap());
            let mut record = process_with_status(&candidate, transaction.clone()).unwrap();
            let payload = encode_block(&[bincode::serialize(&transaction).unwrap()]).unwrap();
            complete_bank(
                &candidate,
                &[0x92; 32],
                &root.pq_state_commitment(),
                &payload,
            );
            candidate.detach_isolated_pq_parent().unwrap();
            let expected_count = candidate.transaction_count();
            let expected_state = candidate.pq_state_commitment();
            let directory = tempfile::TempDir::new().unwrap();
            let store = Blockstore::open(directory.path()).unwrap();
            let block = BlockRef {
                slot: 1,
                hash: [0x93; 48],
            };
            // The ledger layer's trusted-root fixture isolates publication;
            // cryptographic certificate checks remain in the caller.
            store
                .put_experimental_pq_block(1, block.hash, b"certified publication fixture")
                .unwrap();
            let mut journal = vec![0u8; 53];
            journal[0] = 1;
            store
                .put_experimental_pq_checkpoint(&journal, &[(1, block.hash)])
                .unwrap();
            if corrupt_archive {
                record.0.signatures.clear();
            }
            assert_eq!(root.get_balance(&recipient), 1_000_000);
            let result = promote_and_archive(
                &forks,
                &store,
                block,
                candidate.clone(),
                root.pq_state_commitment(),
                root.last_blockhash(),
                &[record],
            );
            let adopted = forks.read().unwrap().root_bank();
            assert!(Arc::ptr_eq(&adopted, &candidate));
            assert_eq!(adopted.get_balance(&recipient), 1_000_007);
            assert_eq!(adopted.transaction_count(), expected_count);
            assert_eq!(adopted.pq_state_commitment(), expected_state);
            if corrupt_archive {
                assert!(result.is_err());
                assert!(
                    store
                        .get_complete_transaction(signature, 1)
                        .unwrap()
                        .is_none()
                );
                assert!(store.get_experimental_pq_checkpoint().unwrap().is_some());
            } else {
                assert!(result.is_ok());
                let receipt = store
                    .get_complete_transaction(signature, 1)
                    .unwrap()
                    .unwrap();
                assert_eq!(receipt.slot, adopted.slot());
            }
        }
    }

    #[test]
    fn canonical_payload_rejects_trailing_lengths_and_counts() {
        let empty = encode_block(&[]).unwrap();
        assert!(decode_block(&empty, 4096).unwrap().is_empty());
        let mut trailing = empty.clone();
        trailing.push(0);
        assert!(decode_block(&trailing, 4096).is_err());
        let mut count = empty;
        count[8..12].copy_from_slice(&4097u32.to_le_bytes());
        assert!(decode_block(&count, 4096).is_err());
        assert!(decode_block(b"AGVPQTX1", 4096).is_err());
        assert!(decode_transaction(&vec![0; MAX_TRANSACTION_BYTES + 1]).is_err());
    }

    #[test]
    fn hexadecimal_has_one_canonical_representation() {
        assert_eq!(decode_hex("0001ff").unwrap(), vec![0, 1, 255]);
        assert!(decode_hex("FF").is_err());
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("gg").is_err());
    }
}
