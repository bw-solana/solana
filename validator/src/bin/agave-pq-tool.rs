//! Actual Agave GenesisConfig and RPC/SVM client for the experimental PQ branch.
//! No reference Bank, reference server, or reference ledger is used here.

#[path = "agave_pq_tool/migrate.rs"]
mod migrate;
#[path = "agave_pq_tool/soak.rs"]
mod soak;
#[path = "agave_pq_tool/transport.rs"]
mod transport;

use {
    agave_pq_crypto::{
        auth::{AuthRecord, Origin, fresh_address},
        ax::AxEpoch,
        ax_state::{DurableConsensusSigner, FileMonotonicStore},
        crypto::{FalconKeypair, FalconPublicKey},
        migration::{MigrationIntent, SeedClaimStatement},
    },
    anyhow::{Context, Result, anyhow, bail, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    rayon::prelude::*,
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    solana_account::{Account, AccountSharedData},
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_core::experimental_pq::{
        ExperimentalPqConfig, ExperimentalPqPeer, genesis_role_registry_bytes,
    },
    solana_fee_calculator::FeeRateGovernor,
    solana_genesis_config::GenesisConfig,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_keypair::{Keypair, write_keypair},
    solana_message::{Message, VersionedMessage},
    solana_pubkey::Pubkey,
    solana_runtime::pq::{
        self, Config as RuntimeConfig, authenticate_instruction, close_upload_instruction,
        create_upload_instruction, finalize_seed_instruction, policy_address,
        seal_upload_instruction, sign_transaction, upload_address, verify_seed_instruction,
        write_upload_instruction,
    },
    solana_signer::Signer,
    solana_system_interface::{instruction as system_instruction, program as system_program},
    solana_transaction::versioned::VersionedTransaction,
    std::{
        collections::BTreeSet,
        fs::{self, OpenOptions},
        io::Write,
        net::{IpAddr, SocketAddr},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

fn default_slots() -> u64 {
    128
}
fn default_block_time() -> u64 {
    1000
}
fn default_network_delay() -> u64 {
    500
}
fn default_block_bytes() -> usize {
    2 * 1024 * 1024
}
fn default_transactions() -> usize {
    4096
}
fn default_execution_threads() -> usize {
    8
}
fn default_wallets() -> usize {
    1
}
fn default_recipients() -> usize {
    1
}
fn default_state_bytes() -> usize {
    2048
}
fn default_timeout() -> u64 {
    180
}
fn default_connections() -> usize {
    16
}
fn default_signing_threads() -> usize {
    64
}
fn default_batch() -> usize {
    16
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitSpec {
    directory: PathBuf,
    hosts: Vec<IpAddr>,
    pq_port: u16,
    rpc_port: u16,
    #[serde(default)]
    start_unix_ms: u64,
    #[serde(default)]
    cutoff_slot: u64,
    #[serde(default = "default_slots")]
    slot_count: u64,
    #[serde(default = "default_block_time")]
    block_time_ms: u64,
    #[serde(default = "default_network_delay")]
    network_delay_ms: u64,
    #[serde(default = "default_block_bytes")]
    target_block_bytes: usize,
    #[serde(default = "default_transactions")]
    max_transactions: usize,
    #[serde(default = "default_execution_threads")]
    execution_threads: usize,
    #[serde(default)]
    proposal_target_block_bytes: Option<usize>,
    #[serde(default)]
    proposal_max_transactions: Option<usize>,
    #[serde(default = "default_wallets")]
    wallet_count: usize,
    #[serde(default)]
    legacy_wallet_count: usize,
    #[serde(default = "default_recipients")]
    recipient_count: usize,
    #[serde(default)]
    enable_spl_programs: bool,
    #[serde(default)]
    enable_workload: bool,
    #[serde(default)]
    workload_state_count: usize,
    #[serde(default)]
    background_state_accounts: usize,
    #[serde(default = "default_state_bytes")]
    state_data_bytes: usize,
    #[serde(default)]
    rich_seed_fixture: bool,
    #[serde(default)]
    public_seed_fixture: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
struct NodeManifest {
    index: usize,
    host: IpAddr,
    config: PathBuf,
    identity: PathBuf,
    id: String,
    ledger: PathBuf,
    keys: PathBuf,
    rpc_port: u16,
    rpc_url: String,
    pq_address: SocketAddr,
    vote_account: String,
    stake_account: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct WalletManifest {
    index: usize,
    address: String,
    private_key: PathBuf,
    nonce: String,
    #[serde(default)]
    legacy_private_key: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
struct WorkloadStateManifest {
    state: String,
    primary_wallet: usize,
    secondary_wallet: usize,
    escrow: String,
    data_bytes: usize,
    authority_is_state_address: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Manifest {
    format: String,
    directory: PathBuf,
    genesis_hash: String,
    chain: String,
    migration_context: String,
    cutoff_slot: u64,
    recipient: String,
    #[serde(default)]
    recipients: Vec<String>,
    #[serde(default)]
    recipient_wallets: Vec<WalletManifest>,
    nodes: Vec<NodeManifest>,
    wallets: Vec<WalletManifest>,
    #[serde(default)]
    token_mint: Option<String>,
    #[serde(default)]
    wallet_token_accounts: Vec<String>,
    #[serde(default)]
    recipient_token_accounts: Vec<String>,
    #[serde(default)]
    workload_program: Option<String>,
    #[serde(default)]
    workload_states: Vec<WorkloadStateManifest>,
    #[serde(default)]
    seed_escrow: Option<String>,
    #[serde(default)]
    seed_token_account: Option<String>,
    #[serde(default)]
    seed_secondary_wallet: Option<usize>,
    public_seed_fixture: Option<PathBuf>,
    legacy_authority: Option<String>,
}

#[derive(Deserialize)]
struct SeedFixture {
    authority: [u8; 32],
    chain: [u8; 32],
    context: [u8; 32],
    nonce: [u8; 32],
    replacement_key: Vec<u8>,
    proof: Vec<u8>,
    secret_commitment: Vec<u8>,
}

#[derive(Clone)]
struct Rpc {
    client: reqwest::blocking::Client,
    retry_policy: transport::RetryPolicy,
    retry_metrics: Arc<transport::RetryMetrics>,
}

#[derive(Debug)]
struct FinalizationFailure {
    report: Value,
}

impl std::fmt::Display for FinalizationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "finalization observation failed: {}",
            self.report
        )
    }
}

impl std::error::Error for FinalizationFailure {}

fn next_status_positions(remaining: &BTreeSet<usize>, cursor: &mut usize) -> (Vec<usize>, bool) {
    let count = remaining.len().min(256);
    let mut positions: Vec<_> = remaining.range(*cursor..).copied().take(count).collect();
    let wrapped = positions.len() < count;
    if wrapped {
        positions.extend(
            remaining
                .iter()
                .copied()
                .take(count.saturating_sub(positions.len())),
        );
    }
    *cursor = positions.last().copied().unwrap_or(0).saturating_add(1);
    (positions, wrapped)
}

fn finalization_failure(
    ids: &[String],
    remaining: &BTreeSet<usize>,
    elapsed: Duration,
    reason: impl std::fmt::Display,
) -> anyhow::Error {
    FinalizationFailure {
        report: json!({"requested":ids.len(),"observed_finalized":ids.len().saturating_sub(remaining.len()),
            "pending_count":remaining.len(),"elapsed_seconds":elapsed.as_secs_f64(),
            "pending_examples":remaining.iter().take(64).map(|index|&ids[*index]).collect::<Vec<_>>(),
            "reason":reason.to_string().chars().take(2048).collect::<String>(),
            "counts_are_observed_signature_statuses":true}),
    }.into()
}

fn decode_balance_batch(response: &Value, count: usize) -> Result<Vec<u64>> {
    let rows = response.as_array().context("RPC balance batch response")?;
    ensure!(rows.len() == count, "RPC balance batch count mismatch");
    let mut balances = vec![None; count];
    for row in rows {
        ensure!(
            row["jsonrpc"] == "2.0",
            "RPC balance batch version mismatch"
        );
        let index = usize::try_from(row["id"].as_u64().context("RPC balance batch id")?)?;
        ensure!(
            index < count && balances[index].is_none(),
            "RPC balance batch id mismatch"
        );
        if let Some(error) = row.get("error") {
            bail!("RPC balance batch failed: {error}");
        }
        balances[index] = Some(
            row["result"]["value"]
                .as_u64()
                .context("RPC balance value")?,
        );
    }
    balances
        .into_iter()
        .map(|value| value.context("RPC balance batch missing row"))
        .collect()
}

impl Rpc {
    fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?,
            retry_policy: transport::RetryPolicy::default(),
            retry_metrics: Arc::default(),
        })
    }
    fn call(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        self.call_cancellable(url, method, params, None)
    }
    fn call_cancellable(
        &self,
        url: &str,
        method: &str,
        params: Value,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Value> {
        let request = serde_json::to_vec(
            &json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}),
        )?;
        let value = self.post_json_retry(url, &request, method, cancelled)?;
        ensure!(
            value["jsonrpc"] == "2.0" && value["id"].as_u64() == Some(1),
            "{method}: RPC response ID/version mismatch"
        );
        if let Some(error) = value.get("error") {
            bail!("{method}: {error}");
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: missing result"))
    }
    fn balances(&self, url: &str, addresses: &[String]) -> Result<Vec<u64>> {
        self.balances_cancellable(url, addresses, None)
    }
    fn balances_cancellable(
        &self,
        url: &str,
        addresses: &[String],
        cancelled: Option<&AtomicBool>,
    ) -> Result<Vec<u64>> {
        ensure!(
            !addresses.is_empty() && addresses.len() <= 1024,
            "balance address bounds"
        );
        let mut balances = Vec::with_capacity(addresses.len());
        for chunk in addresses.chunks(128) {
            let requests: Vec<_> = chunk.iter().enumerate().map(|(index, address)| {
                json!({"jsonrpc":"2.0","id":index,"method":"getBalance","params":[address,{"commitment":"finalized"}]})
            }).collect();
            let serialized = serde_json::to_vec(&requests)?;
            let response = self.post_json_retry(url, &serialized, "getBalance batch", cancelled)?;
            balances.extend(decode_balance_batch(&response, chunk.len())?);
        }
        Ok(balances)
    }
    fn hash(&self, url: &str) -> Result<Hash> {
        let result = self.call(
            url,
            "getLatestBlockhash",
            json!([{"commitment":"finalized"}]),
        )?;
        Hash::from_str(
            result["value"]["blockhash"]
                .as_str()
                .context("RPC blockhash")?,
        )
        .map_err(Into::into)
    }
    fn balance(&self, url: &str, address: &str) -> Result<u64> {
        self.call(
            url,
            "getBalance",
            json!([address,{"commitment":"finalized"}]),
        )?["value"]
            .as_u64()
            .context("RPC balance")
    }
    fn submit(&self, url: &str, tx: &VersionedTransaction) -> Result<String> {
        let encoded = BASE64_STANDARD.encode(wincode::serialize(tx)?);
        let result = self.call(
            url,
            "sendTransaction",
            json!([encoded,{"encoding":"base64","skipPreflight":true}]),
        )?;
        let id = result
            .as_str()
            .map(str::to_owned)
            .context("RPC transaction id")?;
        ensure!(
            tx.signatures
                .first()
                .is_some_and(|signature| signature.to_string() == id),
            "RPC returned wrong transaction identity"
        );
        Ok(id)
    }
    fn wait(&self, url: &str, ids: &[String], timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut remaining: BTreeSet<usize> = (0..ids.len()).collect();
        let mut cursor = 0;
        let mut search_history = true;
        while !remaining.is_empty() {
            if start.elapsed() >= timeout {
                return Err(finalization_failure(
                    ids,
                    &remaining,
                    start.elapsed(),
                    "timeout",
                ));
            }
            let (positions, wrapped) = next_status_positions(&remaining, &mut cursor);
            let subset: Vec<_> = positions.iter().map(|index| &ids[*index]).collect();
            let response = match self.call(
                url,
                "getSignatureStatuses",
                json!([subset, {"searchTransactionHistory":search_history}]),
            ) {
                Ok(response) => response,
                Err(error)
                    if search_history
                        && error
                            .to_string()
                            .contains("Transaction history is not available") =>
                {
                    search_history = false;
                    // Retry this exact batch using the live native Bank cache.
                    cursor = positions[0];
                    continue;
                }
                Err(error) => {
                    return Err(finalization_failure(
                        ids,
                        &remaining,
                        start.elapsed(),
                        error,
                    ));
                }
            };
            let statuses = response["value"].as_array().ok_or_else(|| {
                finalization_failure(ids, &remaining, start.elapsed(), "RPC status array missing")
            })?;
            let before_poll = remaining.len();
            if statuses.len() != positions.len() {
                return Err(finalization_failure(
                    ids,
                    &remaining,
                    start.elapsed(),
                    "RPC status count mismatch",
                ));
            }
            for (position, status) in positions.iter().zip(statuses) {
                if status.is_null() {
                    continue;
                }
                if !status["err"].is_null() {
                    return Err(finalization_failure(
                        ids,
                        &remaining,
                        start.elapsed(),
                        format!("transaction {} failed: {}", ids[*position], status["err"]),
                    ));
                }
                if status["confirmationStatus"] == "finalized" {
                    remaining.remove(position);
                }
            }
            if !remaining.is_empty() && remaining.len() == before_poll && wrapped {
                thread::sleep(Duration::from_millis(100));
            }
        }
        Ok(())
    }
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let metadata = fs::metadata(path)?;
    ensure!(metadata.len() <= 64 * 1024 * 1024, "JSON input bound");
    serde_json::from_slice(&fs::read(path)?).map_err(Into::into)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn identity_file(path: &Path, key: &Keypair) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    write_keypair(key, &mut file).map_err(|_| anyhow!("write identity identifier keypair"))?;
    file.sync_all()?;
    Ok(())
}

fn install_spl_state(
    genesis: &mut GenesisConfig,
    wallets: &[WalletManifest],
    recipients: &[WalletManifest],
) -> Result<(Option<String>, Vec<String>, Vec<String>)> {
    use {
        solana_program_option::COption,
        solana_program_pack::Pack,
        spl_token_interface::state::{Account as TokenAccount, AccountState, Mint},
    };
    for (address, account) in solana_program_binaries::spl_programs(&genesis.rent) {
        genesis.accounts.insert(address, Account::from(account));
    }
    let token_program = spl_generic_token::token::id();
    let mint = Pubkey::new_unique();
    let authority = Pubkey::from_str(&wallets[0].address)?;
    let supply = u64::try_from(wallets.len())?
        .checked_mul(1_000_000_000_000)
        .context("token supply overflow")?;
    let mut data = vec![0; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::Some(authority),
            supply,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::Some(authority),
        },
        &mut data,
    )?;
    genesis.accounts.insert(
        mint,
        Account {
            lamports: genesis.rent.minimum_balance(data.len()),
            data,
            owner: token_program,
            executable: false,
            rent_epoch: u64::MAX,
        },
    );
    let mut create = |wallet: &WalletManifest, amount: u64| -> Result<String> {
        let owner = Pubkey::from_str(&wallet.address)?;
        let address=spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(&owner,&mint,&token_program);
        let mut data = vec![0; TokenAccount::LEN];
        TokenAccount::pack(
            TokenAccount {
                mint,
                owner,
                amount,
                delegate: COption::None,
                state: AccountState::Initialized,
                is_native: COption::None,
                delegated_amount: 0,
                close_authority: COption::None,
            },
            &mut data,
        )?;
        genesis.accounts.insert(
            address,
            Account {
                lamports: genesis.rent.minimum_balance(data.len()),
                data,
                owner: token_program,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        Ok(address.to_string())
    };
    let wallet_accounts = wallets
        .iter()
        .map(|wallet| create(wallet, 1_000_000_000_000))
        .collect::<Result<Vec<_>>>()?;
    let recipient_accounts = recipients
        .iter()
        .map(|wallet| create(wallet, 0))
        .collect::<Result<Vec<_>>>()?;
    Ok((Some(mint.to_string()), wallet_accounts, recipient_accounts))
}
fn application_state_data(
    state: &solana_runtime::pq_workload::State,
    data_bytes: usize,
    tag: u64,
) -> Vec<u8> {
    let mut data = state.encode(data_bytes);
    for (offset, byte) in data[solana_runtime::pq_workload::STATE_BYTES..]
        .iter_mut()
        .enumerate()
    {
        *byte = u8::try_from(
            (u64::try_from(offset).unwrap_or(0).wrapping_add(tag))
                .checked_rem(251)
                .unwrap_or(0),
        )
        .unwrap_or(0);
    }
    data
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex32(encoded: &str) -> Result<[u8; 32]> {
    ensure!(encoded.len() == 64, "32-byte hex value required");
    ensure!(encoded.is_ascii(), "hex value must be ASCII");
    let bytes = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII was checked"), 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    bytes.try_into().map_err(|_| anyhow!("hex length"))
}
fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn init(spec: InitSpec) -> Result<Value> {
    ensure!(
        spec.directory.is_absolute(),
        "initialization directory must be absolute"
    );
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    ensure!(
        !spec.directory.starts_with(repo),
        "private initialization directory must be outside the repository"
    );
    ensure!(
        (4..=256).contains(&spec.hosts.len()),
        "4..=256 validator hosts required"
    );
    ensure!(
        (1..=1024).contains(&spec.wallet_count),
        "wallet count bound"
    );
    ensure!(
        (1..=1024).contains(&spec.recipient_count),
        "recipient count bound"
    );
    ensure!(
        (4..=u64::from(agave_pq_crypto::ax::AX_MAX_SLOTS)).contains(&spec.slot_count)
            && spec.slot_count.is_multiple_of(4),
        "finite epoch needs4..=18000 slots in windows of4"
    );
    ensure!(
        spec.cutoff_slot <= spec.slot_count,
        "cutoff exceeds finite epoch"
    );
    ensure!(
        spec.legacy_wallet_count <= spec.wallet_count,
        "legacy wallet count exceeds wallet count"
    );
    ensure!(
        spec.legacy_wallet_count == 0 || spec.cutoff_slot > 0,
        "legacy wallet enrollment needs a future cutoff"
    );
    ensure!(
        spec.workload_state_count == 0
            || spec
                .workload_state_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(1))
                .is_some_and(|count| count <= spec.legacy_wallet_count),
        "legacy vault states need two actors each and a separate enrollment sponsor"
    );
    ensure!(
        (128..=1_048_576).contains(&spec.state_data_bytes)
            && spec.background_state_accounts <= 10_000,
        "application state size/count bounds"
    );
    ensure!(
        spec.background_state_accounts
            .checked_add(spec.workload_state_count)
            .and_then(|count| count.checked_mul(spec.state_data_bytes))
            .is_some_and(|size| size <= 64 * 1024 * 1024),
        "application state total bytes bound"
    );
    ensure!(
        (spec.workload_state_count == 0 && spec.background_state_accounts == 0)
            || spec.enable_workload,
        "application states require workload program"
    );
    ensure!(
        !spec.rich_seed_fixture || (spec.enable_workload && spec.public_seed_fixture.is_some()),
        "rich private-seed fixture needs workload and actual public proof fixture"
    );
    ensure!(
        (1..=10_000).contains(&spec.network_delay_ms),
        "network delay must be 1..=10000 milliseconds"
    );
    ensure!(
        (1..=32).contains(&spec.execution_threads),
        "execution threads must be 1..=32"
    );
    ensure!(
        spec.proposal_target_block_bytes
            .is_none_or(|limit| (64..=spec.target_block_bytes).contains(&limit))
            && spec
                .proposal_max_transactions
                .is_none_or(|limit| (1..=spec.max_transactions).contains(&limit)),
        "local proposal caps must fit immutable consensus bounds"
    );
    private_dir(&spec.directory)
        .context("create fresh private cluster directory; existing state is never overwritten")?;
    let fixture: Option<SeedFixture> = spec
        .public_seed_fixture
        .as_ref()
        .map(|path| read_json(path))
        .transpose()?;
    let chain = fixture
        .as_ref()
        .map(|fixture| fixture.chain)
        .unwrap_or_else(rand::random);
    let context = fixture
        .as_ref()
        .map(|fixture| fixture.context)
        .unwrap_or_else(rand::random);
    let native = RuntimeConfig {
        chain_id: chain,
        migration_context: context,
        cutoff_slot: spec.cutoff_slot,
    };
    let mut genesis = GenesisConfig {
        fee_rate_governor: FeeRateGovernor::new(5000, 0),
        rent: solana_rent::Rent::default(),
        ..GenesisConfig::default()
    };
    genesis.accounts.insert(
        pq::CONFIG_ADDRESS,
        native.account(genesis.rent.minimum_balance(80)),
    );
    private_dir(&spec.directory.join("recipients"))?;
    let mut recipient_wallets = Vec::new();
    let mut recipients = Vec::new();
    for index in 0..spec.recipient_count {
        let key = FalconKeypair::generate();
        let nonce: [u8; 32] = rand::random();
        let address = Pubkey::new_from_array(fresh_address(&chain, &key.public_key(), &nonce));
        let private_key = spec
            .directory
            .join("recipients")
            .join(format!("recipient-{index}.key"));
        key.save_private(&private_key)?;
        let data =
            AuthRecord::new(address.to_bytes(), key.public_key(), Origin::FreshIdentity).encode();
        genesis.accounts.insert(
            policy_address(&address),
            Account {
                lamports: genesis.rent.minimum_balance(data.len()),
                data,
                owner: pq::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        recipient_wallets.push(WalletManifest {
            index,
            address: address.to_string(),
            private_key,
            nonce: hex(&nonce),
            legacy_private_key: None,
        });
        recipients.push(address);
    }
    let recipient = recipients[0];
    for destination in &recipients {
        genesis.accounts.insert(
            *destination,
            Account {
                lamports: 1_000_000_000,
                owner: system_program::id(),
                ..Account::default()
            },
        );
    }
    if let Some(fixture) = &fixture {
        genesis.accounts.insert(
            Pubkey::new_from_array(fixture.authority),
            Account {
                lamports: 1_000_000_000_000,
                owner: system_program::id(),
                ..Account::default()
            },
        );
    }
    private_dir(&spec.directory.join("wallets"))?;
    let mut wallets = Vec::new();
    for index in 0..spec.wallet_count {
        let key = FalconKeypair::generate();
        let nonce: [u8; 32] = rand::random();
        let legacy = (index < spec.legacy_wallet_count).then(Keypair::new);
        let address = legacy.as_ref().map(Signer::pubkey).unwrap_or_else(|| {
            Pubkey::new_from_array(fresh_address(&chain, &key.public_key(), &nonce))
        });
        let legacy_private_key = legacy
            .as_ref()
            .map(|legacy| -> Result<_> {
                let path = spec
                    .directory
                    .join("wallets")
                    .join(format!("wallet-{index}-ed25519.json"));
                identity_file(&path, legacy)?;
                Ok(path)
            })
            .transpose()?;
        let path = spec
            .directory
            .join("wallets")
            .join(format!("wallet-{index}.key"));
        key.save_private(&path)?;
        let data =
            AuthRecord::new(address.to_bytes(), key.public_key(), Origin::FreshIdentity).encode();
        genesis.accounts.insert(
            address,
            Account {
                lamports: 1_000_000_000_000,
                owner: system_program::id(),
                ..Account::default()
            },
        );
        if legacy_private_key.is_none() {
            genesis.accounts.insert(
                policy_address(&address),
                Account {
                    lamports: genesis.rent.minimum_balance(data.len()),
                    data,
                    owner: pq::PROGRAM_ID,
                    executable: false,
                    rent_epoch: u64::MAX,
                },
            );
        }
        wallets.push(WalletManifest {
            index,
            address: address.to_string(),
            private_key: path,
            nonce: hex(&nonce),
            legacy_private_key,
        });
    }
    let (token_mint, wallet_token_accounts, recipient_token_accounts) = if spec.enable_spl_programs
    {
        install_spl_state(&mut genesis, &wallets, &recipient_wallets)?
    } else {
        (None, Vec::new(), Vec::new())
    };
    if spec.enable_workload {
        for (address, account) in solana_runtime::pq_workload::program_accounts(&genesis.rent) {
            genesis.accounts.insert(address, account);
        }
    }
    let mut workload_states = Vec::new();
    for index in 0..spec
        .workload_state_count
        .saturating_add(spec.background_state_accounts)
    {
        let aliased = index < spec.workload_state_count;
        let primary_wallet = if aliased {
            index.checked_mul(2).context("actor index overflow")?
        } else {
            0
        };
        let secondary_wallet = if aliased {
            primary_wallet
                .checked_add(1)
                .context("actor index overflow")?
        } else {
            1
        };
        let primary = Pubkey::from_str(
            &wallets
                .get(primary_wallet)
                .context("application primary wallet")?
                .address,
        )?;
        let secondary = Pubkey::from_str(
            &wallets
                .get(secondary_wallet)
                .context("application secondary wallet")?
                .address,
        )?;
        let state = if aliased {
            primary
        } else {
            Pubkey::new_unique()
        };
        let data = application_state_data(
            &solana_runtime::pq_workload::State::new(primary, secondary),
            spec.state_data_bytes,
            index as u64,
        );
        genesis.accounts.insert(
            state,
            Account {
                lamports: genesis.rent.minimum_balance(data.len()),
                data,
                owner: solana_runtime::pq_workload::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        workload_states.push(WorkloadStateManifest {
            state: state.to_string(),
            primary_wallet,
            secondary_wallet,
            escrow: solana_runtime::pq_workload::escrow_address(&state).to_string(),
            data_bytes: spec.state_data_bytes,
            authority_is_state_address: aliased,
        });
    }
    let mut seed_escrow = None;
    let mut seed_token_account = None;
    let mut seed_secondary_wallet = None;
    if spec.rich_seed_fixture {
        let authority =
            Pubkey::new_from_array(fixture.as_ref().context("private seed fixture")?.authority);
        let secondary = wallets
            .iter()
            .find(|wallet| wallet.legacy_private_key.is_none())
            .context("rich seed fixture needs a fresh Falcon secondary/sponsor")?;
        let mut state = solana_runtime::pq_workload::State::new(
            authority,
            Pubkey::from_str(&secondary.address)?,
        );
        state.initialized = true;
        state.deposited = 1_000_000;
        let data = application_state_data(&state, spec.state_data_bytes, 0x5eed);
        genesis.accounts.insert(
            authority,
            Account {
                lamports: genesis.rent.minimum_balance(data.len()),
                data,
                owner: solana_runtime::pq_workload::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        let escrow = solana_runtime::pq_workload::escrow_address(&authority);
        genesis.accounts.insert(
            escrow,
            Account {
                lamports: genesis
                    .rent
                    .minimum_balance(0)
                    .checked_add(1_000_000)
                    .context("fixture escrow balance overflow")?,
                owner: system_program::id(),
                ..Account::default()
            },
        );
        seed_escrow = Some(escrow.to_string());
        seed_secondary_wallet = Some(secondary.index);
        if let Some(mint) = &token_mint {
            use {
                solana_program_option::COption,
                solana_program_pack::Pack,
                spl_token_interface::state::{Account as TokenAccount, AccountState, Mint},
            };
            let mint = Pubkey::from_str(mint)?;
            let token_program = spl_generic_token::token::id();
            let address=spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(&authority,&mint,&token_program);
            let mut data = vec![0; TokenAccount::LEN];
            TokenAccount::pack(
                TokenAccount {
                    mint,
                    owner: authority,
                    amount: 1_000_000,
                    delegate: COption::None,
                    state: AccountState::Initialized,
                    is_native: COption::None,
                    delegated_amount: 0,
                    close_authority: COption::None,
                },
                &mut data,
            )?;
            genesis.accounts.insert(
                address,
                Account {
                    lamports: genesis.rent.minimum_balance(data.len()),
                    data,
                    owner: token_program,
                    executable: false,
                    rent_epoch: u64::MAX,
                },
            );
            let mint_account = genesis.accounts.get_mut(&mint).unwrap();
            let mut state = Mint::unpack(&mint_account.data)?;
            state.supply = state
                .supply
                .checked_add(1_000_000)
                .context("fixture token supply overflow")?;
            Mint::pack(state, &mut mint_account.data)?;
            seed_token_account = Some(address.to_string());
        }
    }
    let mut nodes = Vec::new();
    let mut peers = Vec::new();
    for (index, host) in spec.hosts.iter().enumerate() {
        let directory = spec.directory.join(format!("node-{index}"));
        private_dir(&directory)?;
        let keys = directory.join("keys");
        private_dir(&keys)?;
        let identity = Keypair::new();
        let identity_path = directory.join("identity.json");
        identity_file(&identity_path, &identity)?;
        let vote = Keypair::new();
        identity_file(&directory.join("vote.json"), &vote)?;
        let stake = Keypair::new();
        identity_file(&directory.join("stake.json"), &stake)?;
        let vote_account = solana_vote_program::vote_state::create_v4_account_with_authorized(
            &identity.pubkey(),
            &identity.pubkey(),
            [0; 48],
            &identity.pubkey(),
            0,
            &identity.pubkey(),
            10_000,
            &identity.pubkey(),
            1_000_000_000_000,
        );
        let stake_account = solana_runtime::stake_utils::create_stake_account(
            &identity.pubkey(),
            &vote.pubkey(),
            &vote_account,
            &genesis.rent,
            1_000_000_000u64
                .checked_add(
                    genesis
                        .rent
                        .minimum_balance(solana_stake_interface::state::StakeStateV2::size_of()),
                )
                .context("stake funding overflow")?,
        );
        genesis.accounts.insert(
            identity.pubkey(),
            Account::from(AccountSharedData::new(
                1_000_000_000,
                0,
                &system_program::id(),
            )),
        );
        genesis.accounts.insert(vote.pubkey(), vote_account.into());
        genesis
            .accounts
            .insert(stake.pubkey(), stake_account.into());
        let account_key = FalconKeypair::generate();
        account_key.save_private(keys.join("account.key"))?;
        let account_policy = AuthRecord::new(
            identity.pubkey().to_bytes(),
            account_key.public_key(),
            Origin::LegacySignature,
        )
        .encode();
        genesis.accounts.insert(
            policy_address(&identity.pubkey()),
            Account {
                lamports: genesis.rent.minimum_balance(account_policy.len()),
                data: account_policy,
                owner: pq::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        let network = FalconKeypair::generate();
        network.save_private(keys.join("network.key"))?;
        let leader = FalconKeypair::generate();
        leader.save_private(keys.join("leader.key"))?;
        let signer = DurableConsensusSigner::create(
            keys.join("ax.state"),
            AxEpoch {
                chain,
                validator: identity.pubkey().to_bytes(),
                epoch: 1,
                generation: 1,
                first_slot: 1,
                slots: spec.slot_count as u32,
            },
            &network,
            Arc::new(FileMonotonicStore::open(keys.join("monotonic.store"))?),
        )?;
        let pq_port = spec
            .pq_port
            .checked_add(u16::try_from(index)?)
            .context("PQ port overflow")?;
        let rpc_port = spec
            .rpc_port
            .checked_add(u16::try_from(
                index.checked_mul(4).context("RPC port overflow")?,
            )?)
            .context("RPC port overflow")?;
        let address = SocketAddr::new(*host, pq_port);
        peers.push(ExperimentalPqPeer {
            id: identity.pubkey().to_string(),
            address,
            network_key: hex(network.public_key().as_bytes()),
            leader_key: hex(leader.public_key().as_bytes()),
            consensus_key: hex(signer.public_key().as_bytes()),
            stake: 1_000_000_000,
            vote_account: Some(vote.pubkey().to_string()),
        });
        nodes.push(NodeManifest {
            index,
            host: *host,
            config: directory.join("pq-config.json"),
            identity: identity_path,
            id: identity.pubkey().to_string(),
            ledger: directory.join("ledger"),
            keys,
            rpc_port,
            rpc_url: format!("http://{}", SocketAddr::new(*host, rpc_port)),
            pq_address: address,
            vote_account: vote.pubkey().to_string(),
            stake_account: stake.pubkey().to_string(),
        });
    }
    let common = ExperimentalPqConfig {
        chain: hex(&chain),
        genesis_hash: Hash::default().to_string(),
        activation_state: hex(&[0; 48]),
        local_id: nodes[0].id.clone(),
        epoch: 1,
        first_slot: 1,
        slot_count: spec.slot_count,
        window_size: 4,
        network_delay_ms: spec.network_delay_ms,
        block_time_ms: spec.block_time_ms,
        target_block_bytes: spec.target_block_bytes,
        max_transactions: spec.max_transactions,
        execution_threads: spec.execution_threads,
        proposal_target_block_bytes: spec.proposal_target_block_bytes,
        proposal_max_transactions: spec.proposal_max_transactions,
        listen: nodes[0].pq_address,
        key_directory: nodes[0].keys.clone(),
        peers,
        start_unix_ms: spec.start_unix_ms,
        prewarm_seed_verifier: fixture.is_some(),
    };
    common.validate()?;
    let roles = genesis_role_registry_bytes(&common)?;
    genesis.accounts.insert(
        pq::ROLE_REGISTRY_ADDRESS,
        Account {
            lamports: genesis.rent.minimum_balance(roles.len()),
            data: roles,
            owner: pq::PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        },
    );
    let genesis_hash = genesis.hash().to_string();
    for node in &nodes {
        genesis.write(&node.ledger)?;
        fs::set_permissions(
            node.ledger.join("genesis.bin"),
            fs::Permissions::from_mode(0o600),
        )?;
    }
    // Compute the checkpoint from the serialized configuration validators load.
    // Genesis serialization omits the current fee-rate governor value, so an
    // in-memory Bank constructed before this round trip has different sysvars.
    let persisted_genesis = GenesisConfig::load(&nodes[0].ledger)?;
    let activation_accounts = spec.directory.join("activation-accounts");
    private_dir(&activation_accounts)?;
    let activation_bank = solana_runtime::bank::Bank::new_from_genesis(
        &persisted_genesis,
        Arc::default(),
        vec![activation_accounts],
        None,
        solana_accounts_db::accounts_db::AccountsDbConfig::default(),
        None,
        None,
        Arc::new(AtomicBool::new(false)),
        None,
        None,
    );
    activation_bank.freeze();
    let activation_state = hex(&activation_bank.pq_state_commitment());
    for node in &nodes {
        let mut config = common.clone();
        config.genesis_hash = genesis_hash.clone();
        config.activation_state = activation_state.clone();
        config.local_id = node.id.clone();
        config.listen = node.pq_address;
        config.key_directory = node.keys.clone();
        write_json(&node.config, &config)?;
    }
    let manifest = Manifest {
        format: "agave-native-pq-v1".into(),
        directory: spec.directory.clone(),
        genesis_hash: genesis_hash.clone(),
        chain: hex(&chain),
        migration_context: hex(&context),
        cutoff_slot: spec.cutoff_slot,
        recipient: recipient.to_string(),
        recipients: recipients.iter().map(ToString::to_string).collect(),
        recipient_wallets,
        nodes,
        wallets,
        token_mint,
        wallet_token_accounts,
        recipient_token_accounts,
        workload_program: spec
            .enable_workload
            .then(|| Pubkey::new_from_array([0x55; 32]).to_string()),
        workload_states,
        seed_escrow,
        seed_token_account,
        seed_secondary_wallet,
        public_seed_fixture: spec.public_seed_fixture,
        legacy_authority: fixture
            .map(|fixture| Pubkey::new_from_array(fixture.authority).to_string()),
    };
    write_json(&spec.directory.join("manifest.json"), &manifest)?;
    Ok(
        json!({"manifest":spec.directory.join("manifest.json"), "validators":manifest.nodes.len(),"wallets":manifest.wallets.len(),"genesis_hash":genesis_hash,"activation_state":activation_state,"recipient":manifest.recipient,"recipients":manifest.recipients,"actual_genesis_config":true,"actual_vote_and_stake_accounts":true}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadSpec {
    manifest: PathBuf,
    count: usize,
    #[serde(default)]
    start_index: u64,
    #[serde(default)]
    wallet_index: usize,
    #[serde(default)]
    wallet_indices: Option<Vec<usize>>,
    #[serde(default = "default_recipients")]
    recipient_count: usize,
    #[serde(default)]
    rpc_urls: Option<Vec<String>>,
    /// Absolute final recipient balance shared by coordinated load generators.
    #[serde(default)]
    expected_recipient_balance: Option<u64>,
    #[serde(default)]
    expected_recipient_balances: Option<Vec<u64>>,
    #[serde(default = "default_connections")]
    connections: usize,
    #[serde(default = "default_signing_threads")]
    signing_threads: usize,
    #[serde(default = "default_batch")]
    batch_size: usize,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    output: Option<PathBuf>,
}

fn transaction(
    config: &RuntimeConfig,
    authority: Pubkey,
    key: &FalconKeypair,
    hash: Hash,
    instructions: &[Instruction],
) -> Result<VersionedTransaction> {
    let mut all = vec![authenticate_instruction(&[authority])];
    all.extend_from_slice(instructions);
    sign_transaction(
        VersionedMessage::Legacy(Message::new_with_blockhash(&all, Some(&authority), &hash)),
        config,
        &[key],
    )
    .map_err(Into::into)
}
fn sponsored_transaction(
    config: &RuntimeConfig,
    payer: Pubkey,
    participants: &[(Pubkey, &FalconKeypair)],
    hash: Hash,
    instructions: &[Instruction],
) -> Result<VersionedTransaction> {
    let authorities: Vec<_> = participants.iter().map(|(address, _)| *address).collect();
    ensure!(
        authorities.iter().collect::<BTreeSet<_>>().len() == authorities.len(),
        "sponsored signer identities must be distinct"
    );
    let mut all = vec![authenticate_instruction(&authorities)];
    all.extend_from_slice(instructions);
    let message = Message::new_with_blockhash(&all, Some(&payer), &hash);
    let keys = participants.iter().map(|(_, key)| *key).collect::<Vec<_>>();
    sign_transaction(VersionedMessage::Legacy(message), config, &keys).map_err(Into::into)
}
fn native_config(manifest: &Manifest) -> Result<RuntimeConfig> {
    Ok(RuntimeConfig {
        chain_id: unhex32(&manifest.chain)?,
        migration_context: unhex32(&manifest.migration_context)?,
        cutoff_slot: manifest.cutoff_slot,
    })
}

fn recipient_amounts(start_index: u64, count: usize, recipient_count: usize) -> Result<Vec<u64>> {
    ensure!(
        (1..=1024).contains(&recipient_count),
        "load recipient count bound"
    );
    let mut amounts = vec![0u64; recipient_count];
    for index in 0..count {
        let global = start_index
            .checked_add(u64::try_from(index)?)
            .context("transfer index overflow")?;
        let recipient = usize::try_from(
            global
                .checked_rem(u64::try_from(recipient_count)?)
                .context("empty recipient distribution")?,
        )?;
        amounts[recipient] = amounts[recipient]
            .checked_add(global.checked_add(1).context("transfer amount overflow")?)
            .context("recipient sum overflow")?;
    }
    Ok(amounts)
}

fn load_recipients(manifest: &Manifest, count: usize) -> Result<Vec<String>> {
    ensure!((1..=1024).contains(&count), "load recipient count bound");
    let available = if manifest.recipients.is_empty() {
        std::slice::from_ref(&manifest.recipient)
    } else {
        ensure!(
            manifest.recipients[0] == manifest.recipient,
            "manifest primary recipient mismatch"
        );
        &manifest.recipients
    };
    ensure!(
        count <= available.len(),
        "load recipients must exist in genesis"
    );
    let selected = available[..count].to_vec();
    ensure!(
        selected.iter().collect::<BTreeSet<_>>().len() == count,
        "load recipients must be distinct"
    );
    Ok(selected)
}

fn load(spec: LoadSpec) -> Result<Value> {
    ensure!((1..=1_000_000).contains(&spec.count), "load count bound");
    ensure!(
        (1..=128).contains(&spec.connections)
            && (1..=128).contains(&spec.signing_threads)
            && (1..=16).contains(&spec.batch_size),
        "load worker/batch bounds"
    );
    let manifest: Manifest = read_json(&spec.manifest)?;
    let ids_path = spec
        .output
        .as_ref()
        .map(|path| path.with_extension("ids.json"))
        .unwrap_or_else(|| {
            manifest.directory.join(format!(
                "load-{}-{}.ids.json",
                wall_ms(),
                std::process::id()
            ))
        });
    let failure_path = ids_path.with_extension("failure.json");
    ensure!(
        !ids_path.exists() && !failure_path.exists(),
        "load diagnostic paths must be fresh"
    );
    let config = native_config(&manifest)?;
    let wallet_indices = spec
        .wallet_indices
        .clone()
        .unwrap_or_else(|| vec![spec.wallet_index]);
    ensure!(
        !wallet_indices.is_empty()
            && wallet_indices.len() <= 1024
            && wallet_indices.iter().collect::<BTreeSet<_>>().len() == wallet_indices.len(),
        "load wallet indices must be distinct and bounded"
    );
    let wallets = wallet_indices
        .iter()
        .map(|index| -> Result<_> {
            let wallet = manifest.wallets.get(*index).context("wallet index")?;
            Ok((
                Pubkey::from_str(&wallet.address)?,
                FalconKeypair::load_private(&wallet.private_key)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let recipients = load_recipients(&manifest, spec.recipient_count)?;
    let destination_keys = recipients
        .iter()
        .map(|address| Pubkey::from_str(address).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        spec.expected_recipient_balance.is_none() || spec.expected_recipient_balances.is_none(),
        "choose one coordinated balance field"
    );
    ensure!(
        spec.expected_recipient_balance.is_none() || recipients.len() == 1,
        "scalar coordinated balance requires one recipient"
    );
    let coordinated_balances = spec
        .expected_recipient_balances
        .clone()
        .or_else(|| spec.expected_recipient_balance.map(|balance| vec![balance]));
    if let Some(expected) = &coordinated_balances {
        ensure!(
            expected.len() == recipients.len(),
            "coordinated recipient balance count mismatch"
        );
    }
    let amounts = recipient_amounts(spec.start_index, spec.count, recipients.len())?;
    let urls = spec.rpc_urls.clone().unwrap_or_else(|| {
        manifest
            .nodes
            .iter()
            .map(|node| node.rpc_url.clone())
            .collect()
    });
    ensure!(!urls.is_empty(), "RPC URL list");
    let rpc = Rpc::new()?;
    let before = urls
        .par_iter()
        .map(|url| rpc.balances(url, &recipients))
        .collect::<Result<Vec<_>>>()?;
    if coordinated_balances.is_none() {
        ensure!(
            before.iter().all(|balances| *balances == before[0]),
            "recipient balance differs before load"
        );
    }
    let latest = Arc::new(RwLock::new(rpc.hash(&urls[0])?));
    let refreshing = Arc::new(AtomicBool::new(true));
    let refresher = {
        let rpc = rpc.clone();
        let url = urls[0].clone();
        let latest = Arc::clone(&latest);
        let refreshing = Arc::clone(&refreshing);
        thread::spawn(move || {
            while refreshing.load(Ordering::Acquire) {
                if let Ok(hash) = rpc.hash(&url) {
                    *latest.write().unwrap() = hash;
                }
                thread::sleep(Duration::from_millis(250));
            }
        })
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(spec.signing_threads)
        .build()?;
    let next = AtomicUsize::new(0);
    let accepted = Mutex::new(Vec::with_capacity(spec.count));
    let start = Instant::now();
    let started_ms = wall_ms();
    let ids_result: Result<()> = thread::scope(|scope| {
        let mut tasks = Vec::new();
        for worker in 0..spec.connections {
            let rpc = &rpc;
            let config = &config;
            let wallets = &wallets;
            let destination_keys = &destination_keys;
            let next = &next;
            let latest = &latest;
            let pool = &pool;
            let accepted = &accepted;
            let url = &urls[worker
                .checked_rem(urls.len())
                .context("empty RPC URL list")?];
            let spec = &spec;
            tasks.push(scope.spawn(move||->Result<()>{
                loop{
                    let position=next.fetch_add(spec.batch_size,Ordering::AcqRel);if position>=spec.count{break;}
                    let end=position.saturating_add(spec.batch_size).min(spec.count);let hash=*latest.read().unwrap();
                    let batch=pool.install(||(position..end).into_par_iter().map(|index|->Result<_>{
                        let global=spec.start_index.checked_add(index as u64).context("transfer index overflow")?;
                        let amount=global.checked_add(1).context("transfer amount overflow")?;
                        let payer=index.checked_rem(wallets.len()).context("empty payer distribution")?;
                        let (authority,key)=&wallets[payer];
                        let recipient=&destination_keys[usize::try_from(global.checked_rem(u64::try_from(destination_keys.len())?).context("empty recipient distribution")?)?];
                        transaction(config,*authority,key,hash,&[system_instruction::transfer(authority,recipient,amount)])
                    }).collect::<Result<Vec<_>>>())?;
                    let request:Vec<_>=batch.iter().enumerate().map(|(index,tx)|json!({"jsonrpc":"2.0","id":index,"method":"sendTransaction","params":[BASE64_STANDARD.encode(wincode::serialize(tx).unwrap()),{"encoding":"base64","skipPreflight":true}]})).collect();
                    let response:Value=rpc.client.post(url).json(&request).send()?.error_for_status()?.json()?;
                    let rows=response.as_array().context("RPC batch response")?;ensure!(rows.len()==batch.len(),"RPC batch count mismatch");
                    let mut seen=BTreeSet::new();
                    for row in rows{
                        let index=usize::try_from(row["id"].as_u64().context("RPC batch id")?)?;ensure!(index<batch.len()&&seen.insert(index),"RPC batch id mismatch");
                        if let Some(error)=row.get("error"){
                            if error["message"].as_str().is_some_and(|text|text.contains("ingress is full")){
                                let mut retried=None;for _ in 0..100{thread::sleep(Duration::from_millis(25));if let Ok(id)=rpc.submit(url,&batch[index]){retried=Some(id);break;}}
                                accepted.lock().unwrap().push(retried.context("RPC ingress remained full")?);continue;
                            }
                            bail!("RPC batch admission failed: {error}");
                        }
                        let id=row["result"].as_str().context("RPC accepted id")?;ensure!(id==batch[index].signatures[0].to_string(),"RPC returned wrong transaction id");accepted.lock().unwrap().push(id.to_owned());
                    }
                }Ok(())
            }));
        }
        let mut failure = None;
        for task in tasks {
            if let Err(error) = task
                .join()
                .map_err(|_| anyhow!("load worker panicked"))
                .and_then(|result| result)
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    });
    refreshing.store(false, Ordering::Release);
    let _ = refresher.join();
    let mut ids = accepted
        .into_inner()
        .map_err(|_| anyhow!("accepted ID collector poisoned"))?;
    ids.sort();
    write_json(&ids_path, &ids)?;
    let record_failure = |phase: &str, error: anyhow::Error| -> anyhow::Error {
        let report = json!({"phase":phase,"requested":spec.count,"accepted":ids.len(),"accepted_ids_file":ids_path,"error":error.to_string().chars().take(4096).collect::<String>(),"finalization":error.downcast_ref::<FinalizationFailure>().map(|failure|&failure.report),"started_unix_ms":started_ms,"failed_unix_ms":wall_ms()});
        if let Err(write_error) = write_json(&failure_path, &report) {
            eprintln!("Unable to save load failure diagnostic: {write_error}");
        }
        eprintln!(
            "Load {phase} failed after {} accepted transactions; IDs: {}; diagnostic: {}",
            ids.len(),
            ids_path.display(),
            failure_path.display()
        );
        error
    };
    ids_result.map_err(|error| record_failure("admission", error))?;
    ensure!(
        ids.len() == spec.count && ids.iter().collect::<BTreeSet<_>>().len() == spec.count,
        "accepted ids must be distinct"
    );
    let accepted_ms = wall_ms();
    let accepted_seconds = start.elapsed().as_secs_f64();
    rpc.wait(&urls[0], &ids, Duration::from_secs(spec.timeout_seconds))
        .map_err(|error| record_failure("finalization", error))?;
    let amount = amounts
        .iter()
        .try_fold(0u64, |sum, amount| sum.checked_add(*amount))
        .context("load sum overflow")?;
    let expected = match &coordinated_balances {
        Some(expected) => expected.clone(),
        None => before[0]
            .iter()
            .zip(&amounts)
            .map(|(balance, amount)| {
                balance
                    .checked_add(*amount)
                    .context("recipient balance overflow")
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let timeout = Instant::now();
    let after = loop {
        let balances = urls
            .par_iter()
            .map(|url| rpc.balances(url, &recipients))
            .collect::<Result<Vec<_>>>()?;
        if balances.iter().all(|balances| *balances == expected) {
            break balances;
        }
        ensure!(
            timeout.elapsed() < Duration::from_secs(spec.timeout_seconds),
            "all-validator recipient balance did not converge: {balances:?}"
        );
        thread::sleep(Duration::from_millis(100));
    };
    let elapsed = start.elapsed().as_secs_f64();
    let statuses = urls
        .par_iter()
        .map(|url| rpc.call(url, "getExperimentalPqStatus", json!([])))
        .collect::<Result<Vec<_>>>()?;
    let result = json!({"actual_agave_rpc":true,"actual_bank_svm":true,"requested":spec.count,"accepted":ids.len(),"node0_finalized_signature_statuses":ids.len(),"all_validator_balances_match":true,"started_unix_ms":started_ms,"accepted_unix_ms":accepted_ms,"completed_unix_ms":wall_ms(),"admission_seconds":accepted_seconds,"finalized_seconds":elapsed,"finalized_tps":spec.count as f64/elapsed,"transfer_lamports":amount,"recipient":manifest.recipient,"recipient_before":before.iter().map(|balances|balances[0]).collect::<Vec<_>>(),"recipient_after":after.iter().map(|balances|balances[0]).collect::<Vec<_>>(),"expected_recipient_balance":expected[0],"recipients":recipients,"wallet_indices":wallet_indices,"recipient_balances_before":before,"recipient_balances_after":after,"expected_recipient_balances":expected,"transfer_lamports_per_recipient":amounts,"coordinated_generators":coordinated_balances.is_some(),"falcon_backend":agave_pq_crypto::crypto::falcon_backend_name(),"nodes":statuses,"signing_threads":spec.signing_threads,"connections":spec.connections,"batch_size":spec.batch_size,"transaction_ids_file":ids_path});
    if let Some(output) = &spec.output {
        write_json(output, &result)?;
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofSpec {
    manifest: PathBuf,
    replacement_private_key: PathBuf,
    #[serde(default)]
    public_seed_fixture: Option<PathBuf>,
    #[serde(default)]
    sponsor_wallet: Option<usize>,
    #[serde(default)]
    rpc_url: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    output: Option<PathBuf>,
}

fn proof(spec: ProofSpec) -> Result<Value> {
    let manifest: Manifest = read_json(&spec.manifest)?;
    let fixture_path = spec
        .public_seed_fixture
        .as_ref()
        .or(manifest.public_seed_fixture.as_ref())
        .context("public complete seed fixture required")?;
    let fixture: SeedFixture = read_json(fixture_path)?;
    let native = native_config(&manifest)?;
    ensure!(
        native.chain_id == fixture.chain && native.migration_context == fixture.context,
        "fixture must match the native on-chain migration context"
    );
    let replacement = FalconKeypair::load_private(&spec.replacement_private_key)?;
    ensure!(
        replacement.public_key() == FalconPublicKey::from_bytes(&fixture.replacement_key)?,
        "replacement private key does not match proved intent"
    );
    let sponsor = manifest
        .wallets
        .get(spec.sponsor_wallet.unwrap_or_else(|| {
            manifest
                .wallets
                .iter()
                .find(|wallet| wallet.legacy_private_key.is_none())
                .map(|wallet| wallet.index)
                .unwrap_or(0)
        }))
        .context("sponsor wallet index")?;
    let sponsor_address = Pubkey::from_str(&sponsor.address)?;
    let sponsor_key = FalconKeypair::load_private(&sponsor.private_key)?;
    let authority = Pubkey::new_from_array(fixture.authority);
    let statement = SeedClaimStatement {
        intent: MigrationIntent {
            chain_id: fixture.chain,
            context: fixture.context,
            authority: fixture.authority,
            replacement_key: replacement.public_key(),
            expected_generation: 0,
            claim_nonce: fixture.nonce,
        },
        secret_intent_commitment: fixture
            .secret_commitment
            .try_into()
            .map_err(|_| anyhow!("secret commitment size"))?,
    };
    let encoded = statement.canonical_bytes();
    let mut payload = u16::try_from(encoded.len())?.to_le_bytes().to_vec();
    payload.extend_from_slice(&encoded);
    payload.extend_from_slice(&fixture.proof);
    ensure!(
        payload.len() <= pq::MAX_UPLOAD_BYTES,
        "proof upload size bound"
    );
    let nonce: [u8; 32] = rand::random();
    let upload = upload_address(&sponsor_address, &nonce);
    let url = spec
        .rpc_url
        .clone()
        .unwrap_or_else(|| manifest.nodes[0].rpc_url.clone());
    let rpc = Rpc::new()?;
    let authority_before = rpc.call(
        &url,
        "getAccountInfo",
        json!([authority.to_string(),{"encoding":"base64","commitment":"finalized"}]),
    )?["value"]
        .clone();
    let snapshot = |address: &str| -> Result<Value> {
        Ok(rpc.call(
            &url,
            "getAccountInfo",
            json!([address,{"encoding":"base64","commitment":"finalized"}]),
        )?["value"]
            .clone())
    };
    let escrow_before = manifest.seed_escrow.as_deref().map(snapshot).transpose()?;
    let mint_before = manifest
        .token_mint
        .as_deref()
        .filter(|_| manifest.seed_token_account.is_some())
        .map(snapshot)
        .transpose()?;
    let token_destination_before = manifest
        .seed_token_account
        .as_ref()
        .map(|_| snapshot(&manifest.recipient_token_accounts[0]))
        .transpose()?;
    let sponsor_before = rpc.balance(&url, &sponsor.address)?;
    let timeout = Duration::from_secs(spec.timeout_seconds);
    let started = Instant::now();
    let started_ms = wall_ms();
    let confirmed = |instructions: &[Instruction]| -> Result<String> {
        let tx = transaction(
            &native,
            sponsor_address,
            &sponsor_key,
            rpc.hash(&url)?,
            instructions,
        )?;
        let id = rpc.submit(&url, &tx)?;
        rpc.wait(&url, std::slice::from_ref(&id), timeout)?;
        Ok(id)
    };
    let create = confirmed(&[create_upload_instruction(
        &sponsor_address,
        &nonce,
        u32::try_from(payload.len())?,
    )])?;
    let mut writes = Vec::new();
    // One persistent HTTP client submits every offset in order. Writes are
    // pipelined into the actual validator's FIFO mempool, without simulating
    // against the earlier unadvanced upload account. Every RPC call still
    // authenticates the Falcon witness, and the SVM rechecks it under locks.
    for (index, chunk) in payload.chunks(pq::MAX_UPLOAD_CHUNK_BYTES).enumerate() {
        let offset = index
            .checked_mul(pq::MAX_UPLOAD_CHUNK_BYTES)
            .context("upload offset overflow")?;
        let tx = transaction(
            &native,
            sponsor_address,
            &sponsor_key,
            rpc.hash(&url)?,
            &[write_upload_instruction(
                &sponsor_address,
                &upload,
                u32::try_from(offset)?,
                chunk,
            )],
        )?;
        writes.push(rpc.submit(&url, &tx)?);
    }
    rpc.wait(&url, &writes, timeout)?;
    let seal = confirmed(&[seal_upload_instruction(&sponsor_address, &upload)])?;
    let verify_start = Instant::now();
    let verify = confirmed(&[
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        verify_seed_instruction(&sponsor_address, &upload),
    ])?;
    let verify_finality_seconds = verify_start.elapsed().as_secs_f64();
    let finalize = confirmed(&[finalize_seed_instruction(
        &sponsor_address,
        &authority,
        &upload,
    )])?;
    let before = rpc.balance(&url, &manifest.recipient)?;
    let authority_after_install = rpc.call(
        &url,
        "getAccountInfo",
        json!([authority.to_string(),{"encoding":"base64","commitment":"finalized"}]),
    )?["value"]
        .clone();
    ensure!(
        authority_before["owner"] == authority_after_install["owner"]
            && authority_before["data"] == authority_after_install["data"]
            && authority_before["lamports"] == authority_after_install["lamports"],
        "complete private-seed migration changed target owner/data/lamports"
    );
    let rich = manifest.seed_escrow.is_some();
    let secondary_key = manifest
        .seed_secondary_wallet
        .map(|index| -> Result<_> {
            let wallet = &manifest.wallets[index];
            Ok((
                Pubkey::from_str(&wallet.address)?,
                FalconKeypair::load_private(&wallet.private_key)?,
            ))
        })
        .transpose()?;
    let spend = if rich {
        let secondary = secondary_key
            .as_ref()
            .context("rich fixture secondary authority")?;
        let accounts = solana_runtime::pq_workload::Accounts {
            state: authority,
            primary: authority,
            secondary: secondary.0,
            sponsor: sponsor_address,
            recipient: Pubkey::from_str(&manifest.recipient)?,
        };
        let mut participants = vec![(sponsor_address, &sponsor_key), (authority, &replacement)];
        if secondary.0 != sponsor_address {
            participants.push((secondary.0, &secondary.1));
        }
        sponsored_transaction(
            &native,
            sponsor_address,
            &participants,
            rpc.hash(&url)?,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(20_000),
                accounts.withdraw(1, 1),
            ],
        )?
    } else {
        transaction(
            &native,
            authority,
            &replacement,
            rpc.hash(&url)?,
            &[system_instruction::transfer(
                &authority,
                &Pubkey::from_str(&manifest.recipient)?,
                1,
            )],
        )?
    };
    let spend_id = rpc.submit(&url, &spend)?;
    rpc.wait(&url, std::slice::from_ref(&spend_id), timeout)?;
    let token_spend = if let Some(source) = &manifest.seed_token_account {
        let instruction = spl_token_interface::instruction::transfer_checked(
            &spl_generic_token::token::id(),
            &Pubkey::from_str(source)?,
            &Pubkey::from_str(
                manifest
                    .token_mint
                    .as_deref()
                    .context("rich fixture mint")?,
            )?,
            &Pubkey::from_str(&manifest.recipient_token_accounts[0])?,
            &authority,
            &[],
            1,
            0,
        )?;
        let tx = sponsored_transaction(
            &native,
            sponsor_address,
            &[(sponsor_address, &sponsor_key), (authority, &replacement)],
            rpc.hash(&url)?,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(20_000),
                instruction,
            ],
        )?;
        let id = rpc.submit(&url, &tx)?;
        rpc.wait(&url, std::slice::from_ref(&id), timeout)?;
        Some(id)
    } else {
        None
    };
    let closed = confirmed(&[close_upload_instruction(&sponsor_address, &upload)])?;
    let mut sponsored_ids = vec![
        create.clone(),
        seal.clone(),
        verify.clone(),
        finalize.clone(),
        closed.clone(),
    ];
    sponsored_ids.extend(writes.iter().cloned());
    if rich {
        sponsored_ids.push(spend_id.clone());
    }
    if let Some(id) = &token_spend {
        sponsored_ids.push(id.clone());
    }
    let sponsor_fees=sponsored_ids.iter().try_fold(0u64,|sum,id|->Result<_>{let receipt=rpc.call(&url,"getTransaction",json!([id,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]))?;sum.checked_add(receipt["meta"]["fee"].as_u64().context("actual sponsor receipt fee")?).context("sponsor fee sum overflow")})?;
    let policy = policy_address(&authority).to_string();
    let mut states = Vec::new();
    let mut verification_receipts = Vec::new();
    for node in &manifest.nodes {
        let account = rpc.call(
            &node.rpc_url,
            "getAccountInfo",
            json!([policy,{"encoding":"base64","commitment":"finalized"}]),
        )?;
        let value = &account["value"];
        ensure!(
            value["owner"] == pq::PROGRAM_ID.to_string(),
            "installed policy owner mismatch"
        );
        if rich {
            let account = rpc.call(
                &node.rpc_url,
                "getAccountInfo",
                json!([authority.to_string(),{"encoding":"base64","commitment":"finalized"}]),
            )?["value"]
                .clone();
            ensure!(
                account["owner"] == authority_before["owner"]
                    && account["lamports"] == authority_before["lamports"],
                "post-seed application owner/rent changed"
            );
            let data = BASE64_STANDARD.decode(
                account["data"][0]
                    .as_str()
                    .context("rich seeded app account")?,
            )?;
            let state = solana_runtime::pq_workload::State::decode(&data)
                .context("rich seeded app layout")?;
            let old_data = BASE64_STANDARD.decode(
                authority_before["data"][0]
                    .as_str()
                    .context("original seeded app data")?,
            )?;
            ensure!(
                data.len() == old_data.len()
                    && data[..72] == old_data[..72]
                    && data[88..96] == old_data[88..96]
                    && data[104..] == old_data[104..],
                "seeded application authorities/padding changed unexpectedly"
            );
            ensure!(
                state.primary == authority && state.last_sequence == 1 && state.withdrawn == 1,
                "recovered Falcon authority did not execute real seeded PDA withdrawal"
            );
            if let Some(source) = &manifest.seed_token_account {
                let account = rpc.call(
                    &node.rpc_url,
                    "getAccountInfo",
                    json!([source,{"encoding":"base64","commitment":"finalized"}]),
                )?["value"]
                    .clone();
                use solana_program_pack::Pack;
                let data = BASE64_STANDARD
                    .decode(account["data"][0].as_str().context("seeded token data")?)?;
                let token = spl_token_interface::state::Account::unpack(&data)?;
                ensure!(
                    token.owner == authority && token.amount == 999_999,
                    "seeded token ownership/spend did not survive migration"
                );
                let destination=rpc.call(&node.rpc_url,"getAccountInfo",json!([manifest.recipient_token_accounts[0],{"encoding":"base64","commitment":"finalized"}]))?["value"].clone();
                let before = token_destination_before.as_ref().unwrap();
                let prior = spl_token_interface::state::Account::unpack(
                    &BASE64_STANDARD.decode(
                        before["data"][0]
                            .as_str()
                            .context("token destination before")?,
                    )?,
                )?;
                let current = spl_token_interface::state::Account::unpack(
                    &BASE64_STANDARD.decode(
                        destination["data"][0]
                            .as_str()
                            .context("token destination after")?,
                    )?,
                )?;
                ensure!(
                    current.amount
                        == prior
                            .amount
                            .checked_add(1)
                            .context("token destination overflow")?
                        && current.owner == prior.owner
                        && current.mint == prior.mint,
                    "seed-recovered token destination increment/ownership missing"
                );
                let mint=rpc.call(&node.rpc_url,"getAccountInfo",json!([manifest.token_mint.as_deref().unwrap(),{"encoding":"base64","commitment":"finalized"}]))?["value"].clone();
                ensure!(
                    Some(&mint) == mint_before.as_ref(),
                    "seed proof altered mint authority/supply/data"
                );
            }
            let escrow=rpc.call(&node.rpc_url,"getAccountInfo",json!([manifest.seed_escrow.as_deref().unwrap(),{"encoding":"base64","commitment":"finalized"}]))?["value"].clone();
            let old = escrow_before.as_ref().unwrap();
            ensure!(
                escrow["owner"] == old["owner"]
                    && escrow["data"] == old["data"]
                    && escrow["lamports"].as_u64()
                        == old["lamports"]
                            .as_u64()
                            .and_then(|value| value.checked_sub(1)),
                "seeded PDA escrow debit changed unrelated state"
            );
        }
        let data = BASE64_STANDARD.decode(
            value["data"][0]
                .as_str()
                .context("installed policy bytes")?,
        )?;
        let record = AuthRecord::decode(&data)?;
        let policy_rent = value["lamports"].as_u64().context("seed policy rent")?;
        let expected_sponsor = sponsor_before
            .checked_sub(sponsor_fees)
            .and_then(|balance| balance.checked_sub(policy_rent))
            .context("sponsor fee/rent accounting overflow")?;
        ensure!(
            rpc.balance(&node.rpc_url, &sponsor.address)? == expected_sponsor,
            "proof upload refund/sponsor fee debit mismatch"
        );
        ensure!(
            record.authority == authority.to_bytes()
                && record.public_key == replacement.public_key()
                && record.origin == Origin::OriginalSeed,
            "installed actual policy mismatch"
        );
        ensure!(
            rpc.balance(&node.rpc_url, &manifest.recipient)?
                == before.checked_add(1).context("balance overflow")?,
            "migrated spend must converge at every validator"
        );
        let upload_state = rpc.call(
            &node.rpc_url,
            "getAccountInfo",
            json!([upload.to_string(),{"encoding":"base64","commitment":"finalized"}]),
        )?;
        ensure!(
            upload_state["value"].is_null(),
            "closed upload account remains"
        );
        verification_receipts.push(match rpc.call(&node.rpc_url,"getTransaction",json!([verify,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}])) {
            Ok(receipt) if !receipt.is_null() => {
                let encoded = receipt["transaction"][0].as_str().context("native verification receipt transaction")?;
                ensure!(encoded.len() <= pq::MAX_TRANSACTION_BYTES.div_ceil(3).saturating_mul(4),"native receipt encoding bounds");
                let wire = BASE64_STANDARD.decode(encoded)?;
                ensure!(wire.len() <= pq::MAX_TRANSACTION_BYTES,"native receipt transaction bounds");
                let transaction: VersionedTransaction = wincode::deserialize(&wire)?;
                ensure!(wincode::serialize(&transaction)? == wire && transaction.signatures.first().is_some_and(|signature|signature.to_string() == verify),"native receipt transaction identity mismatch");
                let expected = verify_seed_instruction(&sponsor_address,&upload);
                let keys = transaction.message.static_account_keys();
                let exact_verify = transaction.message.instructions().iter().any(|instruction|keys.get(usize::from(instruction.program_id_index)) == Some(&expected.program_id) && instruction.data == expected.data && instruction.accounts.iter().map(|index|keys.get(usize::from(*index))).eq(expected.accounts.iter().map(|account|Some(&account.pubkey))));
                ensure!(exact_verify && receipt["meta"]["err"].is_null(),"native VerifySeed receipt mismatch or execution failure");
                ensure!(receipt["meta"]["computeUnitsConsumed"].as_u64().is_some_and(|units|units >= 1_000_000),"native VerifySeed CU receipt missing");
                json!({"rpc_url":node.rpc_url,"available":true,"signature":verify,"slot":receipt["slot"],"block_time":receipt["blockTime"],"err":receipt["meta"]["err"],"compute_units_consumed":receipt["meta"]["computeUnitsConsumed"],"cost_units":receipt["meta"]["costUnits"],"exact_native_verify_seed_instruction":true,"log_messages":receipt["meta"]["logMessages"]})
            },
            Ok(_) => json!({"rpc_url":node.rpc_url,"available":false,"reason":"finalized native transaction receipt unavailable"}),
            Err(error) => json!({"rpc_url":node.rpc_url,"available":false,"reason":error.to_string().chars().take(2048).collect::<String>()}),
        });
        states.push(rpc.call(&node.rpc_url, "getExperimentalPqStatus", json!([]))?);
    }
    let result = json!({"actual_bank_svm":true,"actual_accountsdb":true,"native_program_verification":true,"rich_program_owned_seed_target":rich,"owner_data_lamports_preserved_at_install":true,"post_migration_token_spend":token_spend,"proof_bytes":fixture.proof.len(),"upload_bytes":payload.len(),"upload_transactions":writes.len(),"authority":authority.to_string(),"policy":policy,"origin":"OriginalSeed","verify_transaction_finality_seconds":verify_finality_seconds,"verification_receipts":verification_receipts,"all_validator_receipts_available":verification_receipts.iter().all(|receipt|receipt["available"] == true),"total_seconds":started.elapsed().as_secs_f64(),"started_unix_ms":started_ms,"completed_unix_ms":wall_ms(),"transactions":{"create":create,"seal":seal,"verify":verify,"finalize":finalize,"post_migration_spend":spend_id,"close":closed},"all_validator_policies_and_spend_match":true,"nodes":states});
    if let Some(output) = &spec.output {
        write_json(output, &result)?;
    }
    Ok(result)
}

fn default_block_size() -> usize {
    250
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchSpec {
    directory: PathBuf,
    count: usize,
    #[serde(default = "default_wallets")]
    wallet_count: usize,
    #[serde(default = "default_signing_threads")]
    signing_threads: usize,
    #[serde(default = "default_block_size")]
    block_size: usize,
    #[serde(default)]
    output: Option<PathBuf>,
}

fn process_resources() -> Value {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage writes the complete structure to this valid output pointer.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return Value::Null;
    }
    // SAFETY: getrusage succeeded and initialized all fields.
    let usage = unsafe { usage.assume_init() };
    json!({"process_user_seconds":usage.ru_utime.tv_sec as f64+usage.ru_utime.tv_usec as f64/1e6,
        "process_system_seconds":usage.ru_stime.tv_sec as f64+usage.ru_stime.tv_usec as f64/1e6,
        "process_peak_rss_mib_cumulative":usage.ru_maxrss as f64/1024.0,
        "minor_page_faults":usage.ru_minflt,"major_page_faults":usage.ru_majflt,
        "block_input_operations":usage.ru_inblock,"block_output_operations":usage.ru_oublock})
}

fn process_cpu_seconds() -> f64 {
    let resources = process_resources();
    resources["process_user_seconds"].as_f64().unwrap_or(0.0)
        + resources["process_system_seconds"].as_f64().unwrap_or(0.0)
}

fn bench(spec: BenchSpec) -> Result<Value> {
    ensure!(
        (1..=100_000).contains(&spec.count) && (1..=128).contains(&spec.wallet_count),
        "benchmark count/wallet bounds"
    );
    ensure!(
        (1..=500).contains(&spec.block_size) && (1..=128).contains(&spec.signing_threads),
        "benchmark bounded block/worker configuration"
    );
    let initialized = Instant::now();
    init(InitSpec {
        directory: spec.directory.clone(),
        hosts: vec!["127.0.0.1".parse()?; 4],
        pq_port: 25000,
        rpc_port: 21899,
        start_unix_ms: 0,
        cutoff_slot: 0,
        slot_count: 128,
        block_time_ms: 1000,
        network_delay_ms: default_network_delay(),
        target_block_bytes: 2 * 1024 * 1024,
        max_transactions: 4096,
        execution_threads: 8,
        proposal_target_block_bytes: None,
        proposal_max_transactions: None,
        wallet_count: 1,
        legacy_wallet_count: 0,
        recipient_count: 1,
        enable_spl_programs: false,
        enable_workload: false,
        workload_state_count: 0,
        background_state_accounts: 0,
        state_data_bytes: default_state_bytes(),
        rich_seed_fixture: false,
        public_seed_fixture: None,
    })?;
    let manifest: Manifest = read_json(&spec.directory.join("manifest.json"))?;
    let mut base = GenesisConfig::load(&manifest.nodes[0].ledger)?;
    let runtime = native_config(&manifest)?;
    for wallet in &manifest.wallets {
        let id = Pubkey::from_str(&wallet.address)?;
        base.accounts.remove(&id);
        base.accounts.remove(&policy_address(&id));
    }
    base.accounts.remove(&pq::CONFIG_ADDRESS);
    base.accounts.remove(&pq::ROLE_REGISTRY_ADDRESS);
    for node in &manifest.nodes {
        base.accounts
            .remove(&policy_address(&Pubkey::from_str(&node.id)?));
    }
    let wallets: Vec<_> = (0..spec.wallet_count)
        .map(|_| (Keypair::new(), FalconKeypair::generate()))
        .collect();
    for (key, _) in &wallets {
        base.accounts.insert(
            key.pubkey(),
            Account {
                lamports: 1_000_000_000_000,
                owner: system_program::id(),
                ..Account::default()
            },
        );
    }
    let mut post_quantum = base.clone();
    post_quantum.accounts.insert(
        pq::CONFIG_ADDRESS,
        runtime.account(post_quantum.rent.minimum_balance(80)),
    );
    for (id, key) in &wallets {
        let data = AuthRecord::new(
            id.pubkey().to_bytes(),
            key.public_key(),
            Origin::LegacySignature,
        )
        .encode();
        post_quantum.accounts.insert(
            policy_address(&id.pubkey()),
            Account {
                lamports: post_quantum.rent.minimum_balance(data.len()),
                data,
                owner: pq::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
    }
    let recipient = Pubkey::from_str(&manifest.recipient)?;
    let leader = solana_runtime::bank::SlotLeader {
        id: Pubkey::from_str(&manifest.nodes[0].id)?,
        vote_address: Pubkey::from_str(&manifest.nodes[0].vote_account)?,
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(spec.signing_threads)
        .build()?;
    let initialization_seconds = initialized.elapsed().as_secs_f64();
    let mut results = Vec::new();
    for (name, genesis, pq_mode) in [
        ("default_ed25519", base, false),
        ("pq_falcon", post_quantum, true),
    ] {
        let directory = spec.directory.join(format!("{name}-accounts"));
        private_dir(&directory)?;
        let bank_initialization = Instant::now();
        let bank = solana_runtime::bank::Bank::new_from_genesis(
            &genesis,
            Arc::default(),
            vec![directory],
            None,
            solana_accounts_db::accounts_db::AccountsDbConfig::default(),
            None,
            None,
            Arc::new(AtomicBool::new(false)),
            None,
            None,
        );
        let forks = solana_runtime::bank_forks::BankForks::new_rw_arc(bank);
        let bank_initialization_seconds = bank_initialization.elapsed().as_secs_f64();
        let before = process_resources();
        let cache_before = agave_pq_crypto::crypto::falcon_verification_cache_stats();
        let mut generation_seconds = 0.0;
        let mut generation_cpu_seconds = 0.0;
        let mut authorization_seconds = 0.0;
        let mut authorization_cpu_seconds = 0.0;
        let mut execution_seconds = 0.0;
        let mut execution_cpu_seconds = 0.0;
        let mut freeze_seconds = 0.0;
        let mut freeze_cpu_seconds = 0.0;
        let mut state_commitment_seconds = 0.0;
        let mut state_commitment_cpu_seconds = 0.0;
        let mut final_state_commitment = None;
        let mut wire_bytes = 0usize;
        let mut block_count = 0u64;
        let started = Instant::now();
        for first in (0..spec.count).step_by(spec.block_size) {
            block_count = block_count
                .checked_add(1)
                .context("benchmark block count")?;
            let parent = forks.read().unwrap().root_bank();
            let child = solana_runtime::bank::Bank::new_from_parent(parent, leader, block_count);
            let child = forks
                .write()
                .unwrap()
                .insert(child)
                .clone_without_scheduler();
            let hash = child.last_blockhash();
            let end = first.saturating_add(spec.block_size).min(spec.count);
            let stage = Instant::now();
            let stage_cpu = process_cpu_seconds();
            let transactions = pool.install(|| {
                (first..end)
                    .into_par_iter()
                    .map(|index| -> Result<VersionedTransaction> {
                        let (classic, falcon) = &wallets[index
                            .checked_rem(wallets.len())
                            .context("empty wallet list")?];
                        let amount = u64::try_from(index)?
                            .checked_add(1)
                            .context("benchmark amount")?;
                        let instructions = [system_instruction::transfer(
                            &classic.pubkey(),
                            &recipient,
                            amount,
                        )];
                        if pq_mode {
                            transaction(&runtime, classic.pubkey(), falcon, hash, &instructions)
                        } else {
                            Ok(solana_transaction::Transaction::new_signed_with_payer(
                                &instructions,
                                Some(&classic.pubkey()),
                                &[classic],
                                hash,
                            )
                            .into())
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            generation_seconds += stage.elapsed().as_secs_f64();
            generation_cpu_seconds += process_cpu_seconds() - stage_cpu;
            for tx in &transactions {
                wire_bytes = wire_bytes
                    .checked_add(usize::try_from(wincode::serialized_size(tx)?)?)
                    .context("benchmark bytes")?;
            }
            let stage = Instant::now();
            let stage_cpu = process_cpu_seconds();
            for tx in &transactions {
                if pq_mode {
                    child.verify_pq_transaction_for_ingress(tx)?;
                } else {
                    tx.verify_and_hash_message()?;
                }
            }
            authorization_seconds += stage.elapsed().as_secs_f64();
            authorization_cpu_seconds += process_cpu_seconds() - stage_cpu;
            let stage = Instant::now();
            let stage_cpu = process_cpu_seconds();
            for tx in transactions {
                let result = child.process_transaction_with_metadata(tx)?;
                ensure!(
                    result.status.is_ok(),
                    "native benchmark SVM transaction failed: {:?}",
                    result.status
                );
            }
            execution_seconds += stage.elapsed().as_secs_f64();
            execution_cpu_seconds += process_cpu_seconds() - stage_cpu;
            let stage = Instant::now();
            let stage_cpu = process_cpu_seconds();
            while child.tick_height() < child.max_tick_height() {
                child.register_tick(&Hash::new_unique(),&solana_runtime::installed_scheduler_pool::BankWithScheduler::no_scheduler_available());
            }
            child.freeze();
            forks
                .write()
                .unwrap()
                .set_root(block_count, None, Some(block_count));
            freeze_seconds += stage.elapsed().as_secs_f64();
            freeze_cpu_seconds += process_cpu_seconds() - stage_cpu;
            if pq_mode {
                let stage = Instant::now();
                let stage_cpu = process_cpu_seconds();
                final_state_commitment = Some(hex(&child.pq_state_commitment()));
                state_commitment_seconds += stage.elapsed().as_secs_f64();
                state_commitment_cpu_seconds += process_cpu_seconds() - stage_cpu;
            }
        }
        let final_bank = forks.read().unwrap().root_bank();
        let amount = (0..spec.count)
            .try_fold(0u64, |sum, index| {
                sum.checked_add((index as u64).checked_add(1)?)
            })
            .context("benchmark total transfer")?;
        ensure!(
            final_bank.get_balance(&recipient)
                == 1_000_000_000u64
                    .checked_add(amount)
                    .context("benchmark balance")?,
            "benchmark final native balance mismatch"
        );
        let elapsed = started.elapsed().as_secs_f64();
        let after = process_resources();
        let cache_after = agave_pq_crypto::crypto::falcon_verification_cache_stats();
        let cpu_before = before["process_user_seconds"].as_f64().unwrap_or(0.0)
            + before["process_system_seconds"].as_f64().unwrap_or(0.0);
        let cpu_after = after["process_user_seconds"].as_f64().unwrap_or(0.0)
            + after["process_system_seconds"].as_f64().unwrap_or(0.0);
        results.push(json!({"mode":name,"transactions":spec.count,"blocks":block_count,"generation_seconds":generation_seconds,"generation_cpu_seconds":generation_cpu_seconds,
            "full_authorization_seconds":authorization_seconds,"full_authorization_cpu_seconds":authorization_cpu_seconds,
            "bank_svm_execution_seconds":execution_seconds,"bank_svm_execution_cpu_seconds":execution_cpu_seconds,
            "ticks_freeze_root_seconds":freeze_seconds,"ticks_freeze_root_cpu_seconds":freeze_cpu_seconds,
            "pq_cached_state_query_seconds":state_commitment_seconds,"pq_cached_state_query_cpu_seconds":state_commitment_cpu_seconds,"final_pq_state_commitment":final_state_commitment,
            "bank_initialization_seconds_excluded":bank_initialization_seconds,"wall_seconds":elapsed,"measured_workload_tps":spec.count as f64/elapsed,
            "mean_wire_bytes":wire_bytes as f64/spec.count as f64,"process_cpu_seconds":cpu_after-cpu_before,
            "process_cpu_us_per_transaction":(cpu_after-cpu_before)*1e6/spec.count as f64,
            "falcon_math_cache":{"hits":cache_after.hits.saturating_sub(cache_before.hits),"misses":cache_after.misses.saturating_sub(cache_before.misses),"entries_after":cache_after.entries,"maximum_entries":cache_after.maximum_entries},
            "resources_before":before,"resources_after":after,"recipient_balance":final_bank.get_balance(&recipient),
            "native_bank_transaction_count":final_bank.transaction_count(),"all_transfers_successful":true}));
    }
    let result = json!({"scope":"Actual Bank/AccountsDB/System Program microbenchmark; no network or consensus throughput claim",
        "falcon_backend":agave_pq_crypto::crypto::falcon_backend_name(),
        "machine":{"architecture":std::env::consts::ARCH,"logical_cpus":std::thread::available_parallelism().map(usize::from).unwrap_or(1),
            "cpu_model":fs::read_to_string("/proc/cpuinfo").ok().and_then(|text|text.lines().find_map(|line|line.strip_prefix("model name\t: ")).map(str::to_owned))},
        "full_default_ed25519_verification":true,"pq_ingress_and_locked_execution_authentication":true,"pq_state_commitment_each_block":true,"pq_state_hash_cpu_included_in_freeze_stage":true,"successful_signature_math_cache_only":true,
        "same_wallet_addresses_and_system_transfer_workload":true,"wallet_count":spec.wallet_count,"block_size":spec.block_size,
        "signing_threads":spec.signing_threads,"initialization_seconds_excluded":initialization_seconds,
        "rss_note":"getrusage peak RSS is cumulative for the process; modes run default then PQ",
        "results":results});
    if let Some(output) = &spec.output {
        write_json(output, &result)?;
    }
    Ok(result)
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    ensure!(
        arguments.len() == 3,
        "usage: agave-pq-tool <init|load|transfer|proof|bench|soak|soak-pipelined|soak-validate> \
         <request.json>"
    );
    let path = Path::new(&arguments[2]);
    let value = match arguments[1].as_str() {
        "init" => init(read_json(path)?)?,
        "load" | "transfer" => load(read_json(path)?)?,
        "proof" => proof(read_json(path)?)?,
        "bench" => bench(read_json(path)?)?,
        "soak" => soak::run(read_json(path)?)?,
        "soak-pipelined" => soak::run_pipelined(read_json(path)?)?,
        "soak-validate" => soak::validate(read_json(path)?)?,
        "migrate" => migrate::run(read_json(path)?)?,
        "resume-rich-migration" => migrate::resume_rich_migration(read_json(path)?)?,
        "probe-shared-authority" => migrate::probe_shared_authority(read_json(path)?)?,
        other => bail!("unsupported command {other}"),
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sponsored_falcon_preserves_auth_key_order_when_message_reorders_readonly_signers() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("reordered-native-signers");
        let spec: InitSpec = serde_json::from_value(json!({"directory":directory,"hosts":["127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1"],"pq_port":25000,"rpc_port":21899,"slot_count":4,"wallet_count":3})).unwrap();
        init(spec).unwrap();
        let manifest: Manifest = read_json(&directory.join("manifest.json")).unwrap();
        let genesis = GenesisConfig::load(&manifest.nodes[0].ledger).unwrap();
        let bank = solana_runtime::bank::Bank::new_for_tests(&genesis);
        let addresses = manifest
            .wallets
            .iter()
            .map(|wallet| Pubkey::from_str(&wallet.address).unwrap())
            .collect::<Vec<_>>();
        let keys = manifest
            .wallets
            .iter()
            .map(|wallet| FalconKeypair::load_private(&wallet.private_key).unwrap())
            .collect::<Vec<_>>();
        let (low, high) = if addresses[1] < addresses[2] {
            (1, 2)
        } else {
            (2, 1)
        };
        let participants = [
            (addresses[0], &keys[0]),
            (addresses[high], &keys[high]),
            (addresses[low], &keys[low]),
        ];
        let transfer = system_instruction::transfer(
            &addresses[0],
            &Pubkey::from_str(&manifest.recipient).unwrap(),
            42,
        );
        let config = native_config(&manifest).unwrap();
        let tx = sponsored_transaction(
            &config,
            addresses[0],
            &participants,
            bank.last_blockhash(),
            std::slice::from_ref(&transfer),
        )
        .unwrap();
        assert_eq!(tx.message.static_account_keys()[1], addresses[low]);
        assert_eq!(tx.message.static_account_keys()[2], addresses[high]);
        bank.verify_pq_transaction_for_ingress(&tx).unwrap();
        assert_eq!(
            bank.process_transaction_with_metadata(tx).unwrap().status,
            Ok(())
        );
        assert_eq!(
            bank.get_balance(&Pubkey::from_str(&manifest.recipient).unwrap()),
            1_000_000_042
        );

        let message = Message::new_with_blockhash(
            &[
                authenticate_instruction(&[addresses[0], addresses[high], addresses[low]]),
                transfer,
            ],
            Some(&addresses[0]),
            &bank.last_blockhash(),
        );
        let incorrectly_presorted = sign_transaction(
            VersionedMessage::Legacy(message),
            &config,
            &[&keys[0], &keys[low], &keys[high]],
        )
        .unwrap();
        assert_eq!(
            bank.verify_pq_transaction_for_ingress(&incorrectly_presorted),
            Err(solana_transaction::TransactionError::SignatureFailure)
        );
    }

    #[test]
    fn richer_genesis_has_real_legacy_custody_and_executes_sbf_and_spl_with_falcon() {
        use {
            solana_program_pack::Pack,
            spl_token_interface::state::{Account as TokenAccount, Mint},
        };
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("rich-native-genesis");
        init(InitSpec {
            directory: directory.clone(),
            hosts: vec!["127.0.0.1".parse().unwrap(); 4],
            pq_port: 25000,
            rpc_port: 21899,
            start_unix_ms: 0,
            cutoff_slot: 16,
            slot_count: 32,
            block_time_ms: 1000,
            network_delay_ms: 500,
            target_block_bytes: 2 * 1024 * 1024,
            max_transactions: 4096,
            execution_threads: 8,
            proposal_target_block_bytes: None,
            proposal_max_transactions: None,
            wallet_count: 6,
            legacy_wallet_count: 3,
            recipient_count: 2,
            enable_spl_programs: true,
            enable_workload: true,
            workload_state_count: 1,
            background_state_accounts: 3,
            state_data_bytes: 2048,
            rich_seed_fixture: false,
            public_seed_fixture: None,
        })
        .unwrap();
        let manifest: Manifest = read_json(&directory.join("manifest.json")).unwrap();
        let genesis = GenesisConfig::load(&manifest.nodes[0].ledger).unwrap();
        assert_eq!(manifest.cutoff_slot, 16);
        assert_eq!(manifest.workload_states.len(), 4);
        assert_eq!(manifest.recipient_wallets.len(), 2);
        for wallet in &manifest.wallets[..3] {
            assert!(wallet.legacy_private_key.as_ref().unwrap().is_file());
            assert!(
                !genesis
                    .accounts
                    .contains_key(&policy_address(&Pubkey::from_str(&wallet.address).unwrap()))
            );
        }
        let actor = &manifest.workload_states[0];
        let actor_address = Pubkey::from_str(&actor.state).unwrap();
        assert_eq!(actor.state, manifest.wallets[0].address);
        let data = &genesis.accounts[&actor_address].data;
        assert_eq!(data.len(), 2048);
        assert!(data[128..].iter().any(|byte| *byte != 0));
        assert_eq!(
            genesis.accounts[&actor_address].owner,
            solana_runtime::pq_workload::PROGRAM_ID
        );
        let mint = Pubkey::from_str(manifest.token_mint.as_deref().unwrap()).unwrap();
        assert_eq!(
            Mint::unpack(&genesis.accounts[&mint].data).unwrap().supply,
            6_000_000_000_000
        );
        for recipient in &manifest.recipient_wallets {
            assert!(genesis.accounts.contains_key(&policy_address(
                &Pubkey::from_str(&recipient.address).unwrap()
            )));
            assert!(recipient.private_key.is_file());
        }
        let forks = solana_runtime::bank_forks::BankForks::new_rw_arc(
            solana_runtime::bank::Bank::new_for_tests(&genesis),
        );
        let parent_bank = forks.read().unwrap().root_bank();
        parent_bank.freeze();
        let node = &manifest.nodes[0];
        let child = solana_runtime::bank::Bank::new_from_parent(
            parent_bank,
            solana_runtime::bank::SlotLeader {
                id: Pubkey::from_str(&node.id).unwrap(),
                vote_address: Pubkey::from_str(&node.vote_account).unwrap(),
            },
            1,
        );
        let child = forks
            .write()
            .unwrap()
            .insert(child)
            .clone_without_scheduler();
        let wallet = &manifest.wallets[3];
        let authority = Pubkey::from_str(&wallet.address).unwrap();
        let key = FalconKeypair::load_private(&wallet.private_key).unwrap();
        let source = Pubkey::from_str(&manifest.wallet_token_accounts[3]).unwrap();
        let destination = Pubkey::from_str(&manifest.recipient_token_accounts[0]).unwrap();
        let instruction = spl_token_interface::instruction::transfer_checked(
            &spl_generic_token::token::id(),
            &source,
            &mint,
            &destination,
            &authority,
            &[],
            7,
            0,
        )
        .unwrap();
        let tx = transaction(
            &native_config(&manifest).unwrap(),
            authority,
            &key,
            child.last_blockhash(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(20_000),
                solana_runtime::pq_workload::nonce_instruction(7, 1),
                instruction,
            ],
        )
        .unwrap();
        child.verify_pq_transaction_for_ingress(&tx).unwrap();
        let executed = child.process_transaction_with_metadata(tx).unwrap();
        assert_eq!(executed.status, Ok(()));
        assert!(executed.executed_units < 20_000);
        assert_eq!(
            TokenAccount::unpack(solana_account::ReadableAccount::data(
                &child.get_account(&source).unwrap()
            ))
            .unwrap()
            .amount,
            999_999_999_993
        );
        assert_eq!(
            TokenAccount::unpack(solana_account::ReadableAccount::data(
                &child.get_account(&destination).unwrap()
            ))
            .unwrap()
            .amount,
            7
        );
        assert_eq!(
            solana_account::ReadableAccount::data(&child.get_account(&actor_address).unwrap()),
            data
        );
    }

    #[test]
    fn distributed_amounts_match_global_workload_and_balance_batches_require_exact_ids() {
        let all = recipient_amounts(0, 50_000, 64).unwrap();
        let first = recipient_amounts(0, 25_000, 64).unwrap();
        let second = recipient_amounts(25_000, 25_000, 64).unwrap();
        assert_eq!(all.iter().sum::<u64>(), 1_250_025_000);
        assert_eq!(
            all,
            first
                .iter()
                .zip(second)
                .map(|(a, b)| a + b)
                .collect::<Vec<_>>()
        );
        assert_eq!(recipient_amounts(0, 3, 1).unwrap(), vec![6]);
        assert!(recipient_amounts(u64::MAX, 1, 64).is_err());
        let rows = json!([
            {"jsonrpc":"2.0","id":1,"result":{"value":22}},
            {"jsonrpc":"2.0","id":0,"result":{"value":11}}
        ]);
        assert_eq!(decode_balance_batch(&rows, 2).unwrap(), vec![11, 22]);
        assert!(
            decode_balance_batch(
                &json!([{"id":0,"result":{"value":11}},{"id":0,"result":{"value":22}}]),
                2
            )
            .is_err()
        );
        assert!(
            decode_balance_batch(&json!([{"id":0,"error":{"message":"unavailable"}}]), 1).is_err()
        );
        assert!(decode_balance_batch(&json!([{"id":0,"result":{"value":-1}}]), 1).is_err());
        assert!(decode_balance_batch(&rows, 3).is_err());
    }

    #[test]
    fn distributed_payers_execute_native_transfers_to_distinct_genesis_recipients() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("distributed-native-cluster");
        init(InitSpec {
            directory: directory.clone(),
            hosts: vec!["127.0.0.1".parse().unwrap(); 4],
            pq_port: 25000,
            rpc_port: 21899,
            start_unix_ms: 0,
            cutoff_slot: 0,
            slot_count: 4,
            block_time_ms: 1000,
            network_delay_ms: default_network_delay(),
            target_block_bytes: 2 * 1024 * 1024,
            max_transactions: 4096,
            execution_threads: 8,
            proposal_target_block_bytes: None,
            proposal_max_transactions: None,
            wallet_count: 4,
            legacy_wallet_count: 0,
            recipient_count: 8,
            enable_spl_programs: false,
            enable_workload: false,
            workload_state_count: 0,
            background_state_accounts: 0,
            state_data_bytes: default_state_bytes(),
            rich_seed_fixture: false,
            public_seed_fixture: None,
        })
        .unwrap();
        let manifest: Manifest = read_json(&directory.join("manifest.json")).unwrap();
        let recipients = load_recipients(&manifest, 8).unwrap();
        assert_eq!(recipients.len(), 8);
        let genesis = GenesisConfig::load(&manifest.nodes[0].ledger).unwrap();
        for destination in &recipients {
            let account = &genesis.accounts[&Pubkey::from_str(destination).unwrap()];
            assert_eq!(account.owner, system_program::id());
            assert_eq!(account.lamports, 1_000_000_000);
            assert!(account.data.is_empty());
        }
        let forks = solana_runtime::bank_forks::BankForks::new_rw_arc(
            solana_runtime::bank::Bank::new_for_tests(&genesis),
        );
        let parent_bank = forks.read().unwrap().root_bank();
        parent_bank.freeze();
        let node = &manifest.nodes[0];
        let child = solana_runtime::bank::Bank::new_from_parent(
            parent_bank,
            solana_runtime::bank::SlotLeader {
                id: Pubkey::from_str(&node.id).unwrap(),
                vote_address: Pubkey::from_str(&node.vote_account).unwrap(),
            },
            1,
        );
        let child = forks
            .write()
            .unwrap()
            .insert(child)
            .clone_without_scheduler();
        let wallets: Vec<_> = manifest
            .wallets
            .iter()
            .map(|wallet| {
                (
                    Pubkey::from_str(&wallet.address).unwrap(),
                    FalconKeypair::load_private(&wallet.private_key).unwrap(),
                )
            })
            .collect();
        let config = native_config(&manifest).unwrap();
        for index in 0..32usize {
            let global = 10 + index;
            let (authority, key) = &wallets[index % wallets.len()];
            let destination = Pubkey::from_str(&recipients[global % recipients.len()]).unwrap();
            let tx = transaction(
                &config,
                *authority,
                key,
                child.last_blockhash(),
                &[system_instruction::transfer(
                    authority,
                    &destination,
                    u64::try_from(global + 1).unwrap(),
                )],
            )
            .unwrap();
            child.verify_pq_transaction_for_ingress(&tx).unwrap();
            assert!(
                child
                    .process_transaction_with_metadata(tx)
                    .unwrap()
                    .status
                    .is_ok()
            );
        }
        child.freeze();
        for (destination, amount) in recipients.iter().zip(recipient_amounts(10, 32, 8).unwrap()) {
            assert_eq!(
                child.get_balance(&Pubkey::from_str(destination).unwrap()),
                1_000_000_000 + amount
            );
        }
        // Old manifests omit the vector and still select the original recipient.
        let mut old = serde_json::to_value(&manifest).unwrap();
        old.as_object_mut().unwrap().remove("recipients");
        let old: Manifest = serde_json::from_value(old).unwrap();
        assert_eq!(load_recipients(&old, 1).unwrap(), vec![manifest.recipient]);
        assert!(load_recipients(&old, 2).is_err());
    }

    #[test]
    fn finality_polling_observes_later_ids_when_first_batch_never_finalizes() {
        use std::{io::Read, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stopped = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stopped);
        let server = thread::spawn(move || {
            while !server_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("test RPC listener: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                let (body_start, length) = loop {
                    let read = stream.read(&mut chunk).unwrap();
                    assert!(read > 0 && request.len().saturating_add(read) <= 64 * 1024);
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let header = std::str::from_utf8(&request[..end]).unwrap();
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.split_once(':')
                                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end.saturating_add(4), length);
                    }
                };
                while request.len() < body_start.saturating_add(length) {
                    let read = stream.read(&mut chunk).unwrap();
                    assert!(read > 0 && request.len().saturating_add(read) <= 64 * 1024);
                    request.extend_from_slice(&chunk[..read]);
                }
                let query: Value =
                    serde_json::from_slice(&request[body_start..body_start.saturating_add(length)])
                        .unwrap();
                let ids = query["params"][0].as_array().unwrap();
                assert!(ids.len() <= 256);
                let statuses: Vec<_> = ids
                    .iter()
                    .map(|id| {
                        if id
                            .as_str()
                            .unwrap()
                            .strip_prefix("id-")
                            .unwrap()
                            .parse::<usize>()
                            .unwrap()
                            < 256
                        {
                            Value::Null
                        } else {
                            json!({"slot":1,"err":null,"confirmationStatus":"finalized"})
                        }
                    })
                    .collect();
                let body = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":query["id"],"result":{"value":statuses}}),
                )
                .unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                     {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let ids: Vec<_> = (0..600).map(|index| format!("id-{index}")).collect();
        let error = Rpc::new()
            .unwrap()
            .wait(&url, &ids, Duration::from_millis(300))
            .unwrap_err();
        stopped.store(true, Ordering::Release);
        server.join().unwrap();
        let report = &error.downcast_ref::<FinalizationFailure>().unwrap().report;
        assert_eq!(report["observed_finalized"], 344);
        assert_eq!(report["pending_count"], 256);
        assert_eq!(report["pending_examples"].as_array().unwrap().len(), 64);
    }

    #[test]
    fn actual_genesis_has_stake_and_pq_account_authority_and_refuses_reinitialization() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("native-cluster");
        let spec = || InitSpec {
            directory: directory.clone(),
            hosts: vec!["127.0.0.1".parse().unwrap(); 4],
            pq_port: 25000,
            rpc_port: 21899,
            start_unix_ms: 0,
            cutoff_slot: 0,
            slot_count: 4,
            block_time_ms: 1000,
            network_delay_ms: default_network_delay(),
            target_block_bytes: 2 * 1024 * 1024,
            max_transactions: 4096,
            execution_threads: 8,
            proposal_target_block_bytes: None,
            proposal_max_transactions: None,
            wallet_count: 1,
            legacy_wallet_count: 0,
            recipient_count: 1,
            enable_spl_programs: false,
            enable_workload: false,
            workload_state_count: 0,
            background_state_accounts: 0,
            state_data_bytes: default_state_bytes(),
            rich_seed_fixture: false,
            public_seed_fixture: None,
        };
        init(spec()).unwrap();
        assert!(init(spec()).is_err());
        let manifest: Manifest = read_json(&directory.join("manifest.json")).unwrap();
        let genesis = GenesisConfig::load(&manifest.nodes[0].ledger).unwrap();
        assert_eq!(genesis.hash().to_string(), manifest.genesis_hash);
        let bank_forks = solana_runtime::bank_forks::BankForks::new_rw_arc(
            solana_runtime::bank::Bank::new_for_tests(&genesis),
        );
        let parent_bank = bank_forks.read().unwrap().root_bank();
        parent_bank.freeze();
        for node in &manifest.nodes {
            let identity = Pubkey::from_str(&node.id).unwrap();
            let vote = Pubkey::from_str(&node.vote_account).unwrap();
            let policy = parent_bank.get_account(&policy_address(&identity)).unwrap();
            let record =
                AuthRecord::decode(solana_account::ReadableAccount::data(&policy)).unwrap();
            assert_eq!(record.origin, Origin::LegacySignature);
            assert_eq!(
                record.public_key,
                FalconKeypair::load_private(node.keys.join("account.key"))
                    .unwrap()
                    .public_key()
            );
            assert!(
                parent_bank
                    .epoch_stakes(parent_bank.epoch())
                    .unwrap()
                    .vote_account_stake(&vote)
                    > 0
            );
            let config = ExperimentalPqConfig::read(&node.config).unwrap();
            assert_eq!(config.network_delay_ms, default_network_delay());
            assert_eq!(
                config.activation_state,
                hex(&parent_bank.pq_state_commitment())
            );
            assert_eq!(
                genesis_role_registry_bytes(&config).unwrap(),
                genesis.accounts[&pq::ROLE_REGISTRY_ADDRESS].data
            );
        }
        let first = &manifest.nodes[0];
        let child = solana_runtime::bank::Bank::new_from_parent(
            parent_bank,
            solana_runtime::bank::SlotLeader {
                id: Pubkey::from_str(&first.id).unwrap(),
                vote_address: Pubkey::from_str(&first.vote_account).unwrap(),
            },
            1,
        );
        let child = bank_forks
            .write()
            .unwrap()
            .insert(child)
            .clone_without_scheduler();
        let wallet = &manifest.wallets[0];
        let authority = Pubkey::from_str(&wallet.address).unwrap();
        let key = FalconKeypair::load_private(&wallet.private_key).unwrap();
        let tx = transaction(
            &native_config(&manifest).unwrap(),
            authority,
            &key,
            child.last_blockhash(),
            &[system_instruction::transfer(
                &authority,
                &Pubkey::from_str(&manifest.recipient).unwrap(),
                42,
            )],
        )
        .unwrap();
        assert_eq!(
            child.process_transaction_with_metadata(tx).unwrap().status,
            Ok(())
        );
        child.freeze();
        assert_eq!(
            child.get_balance(&Pubkey::from_str(&manifest.recipient).unwrap()),
            1_000_000_042
        );
    }
}
