//! Bounded continuous traffic through actual native Agave RPC and the SVM.

#[path = "observer.rs"]
mod observer;

use {
    super::*,
    crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError, bounded},
    sha2::{Digest, Sha384},
    std::{collections::BTreeMap, io::BufWriter},
};

const MAX_OUTSTANDING: usize = 131_072;
const HASH_REFRESH_WORKERS: usize = 8;
const HASH_REFRESH_BUDGET: Duration = Duration::from_secs(2);
const HASH_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const HASH_REFRESH_UNAVAILABLE_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct FinalizedHash {
    hash: Hash,
    last_valid_block_height: u64,
    context_slot: u64,
    endpoint: usize,
    observed_at: Instant,
}

impl FinalizedHash {
    fn rank(&self) -> (u64, u64) {
        (self.last_valid_block_height, self.context_slot)
    }
}

fn finalized_hash_response(value: Value, endpoint: usize) -> Result<FinalizedHash> {
    ensure!(
        value["jsonrpc"] == "2.0" && value["id"].as_u64() == Some(1),
        "finalized blockhash RPC response ID/version mismatch"
    );
    ensure!(
        value.get("error").is_none(),
        "finalized blockhash RPC error: {}",
        value["error"]
    );
    let result = value
        .get("result")
        .context("finalized blockhash RPC result")?;
    let context_slot = result["context"]["slot"]
        .as_u64()
        .context("finalized blockhash context slot")?;
    let last_valid_block_height = result["value"]["lastValidBlockHeight"]
        .as_u64()
        .filter(|height| *height > 0)
        .context("finalized blockhash positive last-valid block height")?;
    let hash = Hash::from_str(
        result["value"]["blockhash"]
            .as_str()
            .context("finalized blockhash bytes")?,
    )?;
    Ok(FinalizedHash {
        hash,
        last_valid_block_height,
        context_slot,
        endpoint,
        observed_at: Instant::now(),
    })
}

fn finalized_hash_sweep(
    rpc: &Rpc,
    urls: &[String],
    pool: &rayon::ThreadPool,
    deadline: Instant,
    cancelled: Option<&AtomicBool>,
) -> Vec<Result<Option<FinalizedHash>>> {
    pool.install(|| {
        urls.par_iter()
            .enumerate()
            .map(|(endpoint, url)| {
                if Instant::now() >= deadline
                    || cancelled.is_some_and(|flag| flag.load(Ordering::Acquire))
                {
                    return Ok(None);
                }
                let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,
                "method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}))?;
                match rpc.post_json_retry_until(
                    url,
                    &body,
                    "freshest finalized blockhash",
                    cancelled,
                    deadline,
                ) {
                    Ok(value) => finalized_hash_response(value, endpoint).map(Some),
                    Err(error) if transport::is_transient(&error) => Ok(None),
                    Err(error) => Err(error),
                }
            })
            .collect()
    })
}

struct LatestFinalizedHash {
    selected: Option<FinalizedHash>,
    started: Instant,
    last_success: Option<Instant>,
    failure: Option<String>,
    sweeps: u64,
    successful_sweeps: u64,
    valid_sweeps: u64,
    valid_endpoint_results: u64,
    unavailable_endpoint_results: u64,
    malformed_sweeps: u64,
    selection_changes: u64,
    regressions_ignored: u64,
    requests_per_endpoint: Vec<u64>,
}

impl LatestFinalizedHash {
    fn new(endpoints: usize) -> Self {
        Self {
            selected: None,
            started: Instant::now(),
            last_success: None,
            failure: None,
            sweeps: 0,
            successful_sweeps: 0,
            valid_sweeps: 0,
            valid_endpoint_results: 0,
            unavailable_endpoint_results: 0,
            malformed_sweeps: 0,
            selection_changes: 0,
            regressions_ignored: 0,
            requests_per_endpoint: vec![0; endpoints],
        }
    }

    fn apply(&mut self, results: Vec<Result<Option<FinalizedHash>>>, now: Instant) {
        if self.failure.is_some() {
            return;
        }
        self.sweeps = self.sweeps.saturating_add(1);
        for count in &mut self.requests_per_endpoint {
            *count = count.saturating_add(1);
        }
        let mut best: Option<FinalizedHash> = None;
        let mut malformed = None;
        for result in results {
            match result {
                Ok(Some(candidate)) => {
                    self.valid_endpoint_results = self.valid_endpoint_results.saturating_add(1);
                    if best.as_ref().is_none_or(|old| {
                        candidate.rank() > old.rank()
                            || (candidate.rank() == old.rank() && candidate.endpoint < old.endpoint)
                    }) {
                        best = Some(candidate);
                    }
                }
                Ok(None) => {
                    self.unavailable_endpoint_results =
                        self.unavailable_endpoint_results.saturating_add(1)
                }
                Err(error) => {
                    malformed.get_or_insert_with(|| {
                        format!("finalized blockhash refresh failed closed: {error:#}")
                    });
                }
            }
        }
        if best.is_some() {
            self.valid_sweeps = self.valid_sweeps.saturating_add(1);
        }
        if let Some(failure) = malformed {
            self.malformed_sweeps = self.malformed_sweeps.saturating_add(1);
            self.failure = Some(failure);
            return;
        }
        if let Some(best) = best {
            if self
                .selected
                .as_ref()
                .is_some_and(|old| old.rank() > best.rank())
            {
                self.regressions_ignored = self.regressions_ignored.saturating_add(1);
            } else {
                self.successful_sweeps = self.successful_sweeps.saturating_add(1);
                self.last_success = Some(now);
                if self.selected.as_ref().is_none_or(|old| {
                    old.hash != best.hash
                        || old.rank() != best.rank()
                        || old.endpoint != best.endpoint
                }) {
                    self.selection_changes = self.selection_changes.saturating_add(1);
                }
                self.selected = Some(best);
            }
        }
    }

    fn available(&self, now: Instant) -> Result<Option<Hash>> {
        if let Some(failure) = &self.failure {
            bail!("{failure}");
        }
        ensure!(
            now.saturating_duration_since(self.last_success.unwrap_or(self.started))
                <= HASH_REFRESH_UNAVAILABLE_LIMIT,
            "no usable finalized blockhash refresh (matching or newer) for more than five seconds"
        );
        Ok(self.selected.as_ref().map(|selected| selected.hash))
    }

    fn metrics(&self) -> Value {
        let now = Instant::now();
        json!({"policy":"freshest_finalized_all_endpoints_v1","workers":HASH_REFRESH_WORKERS,
            "shared_sweep_budget_ms":HASH_REFRESH_BUDGET.as_millis(),
            "refresh_interval_ms":HASH_REFRESH_INTERVAL.as_millis(),
            "usable_refresh_limit_ms":HASH_REFRESH_UNAVAILABLE_LIMIT.as_millis(),
            "rank":"last_valid_block_height_then_context_slot_then_lowest_endpoint_index",
            "selected_endpoint":self.selected.as_ref().map(|selected|selected.endpoint),
            "selected_last_valid_block_height":self.selected.as_ref().map(|selected|selected.last_valid_block_height),
            "selected_context_slot":self.selected.as_ref().map(|selected|selected.context_slot),
            "selected_observation_age_ms":self.selected.as_ref().map(|selected|now.saturating_duration_since(selected.observed_at).as_millis()),
            "last_successful_sweep_age_ms":self.last_success.map(|last|now.saturating_duration_since(last).as_millis()),
            "sweeps":self.sweeps,"successful_sweeps":self.successful_sweeps,
            "valid_sweeps":self.valid_sweeps,"valid_endpoint_results":self.valid_endpoint_results,
            "unavailable_endpoint_results":self.unavailable_endpoint_results,"malformed_sweeps":self.malformed_sweeps,
            "selection_changes":self.selection_changes,"regressions_ignored":self.regressions_ignored,
            "endpoint_sweeps":self.requests_per_endpoint,"failure":self.failure})
    }
}

struct HashRefresher {
    latest: Arc<RwLock<LatestFinalizedHash>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl HashRefresher {
    fn new(rpc: Rpc, urls: Vec<String>) -> Result<Self> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(HASH_REFRESH_WORKERS)
            .build()?;
        let latest = Arc::new(RwLock::new(LatestFinalizedHash::new(urls.len())));
        let cancelled = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&latest);
        let stopped = Arc::clone(&cancelled);
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let deadline = Instant::now()
                    .checked_add(HASH_REFRESH_BUDGET)
                    .expect("bounded hash refresh deadline");
                let results = finalized_hash_sweep(&rpc, &urls, &pool, deadline, Some(&stopped));
                let mut state = shared.write().unwrap();
                state.apply(results, Instant::now());
                if state.failure.is_some() {
                    break;
                }
                drop(state);
                thread::sleep(HASH_REFRESH_INTERVAL);
            }
        });
        Ok(Self {
            latest,
            cancelled,
            worker: Some(worker),
        })
    }

    fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for HashRefresher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn default_duration() -> u64 {
    3600
}
fn default_pending() -> usize {
    4096
}
fn default_poll() -> u64 {
    100
}
fn default_stride() -> u64 {
    100
}
fn default_amount() -> u64 {
    1
}
fn default_compute_limit() -> u32 {
    20_000
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    SystemTransfer,
    TokenTransfer,
    NonceOnly,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    seconds: u64,
    target_tps: u64,
    kind: Kind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SoakSpec {
    manifest: PathBuf,
    source_id: u64,
    #[serde(default)]
    start_counter: u64,
    wallet_indices: Vec<usize>,
    recipient_count: usize,
    #[serde(default)]
    rpc_urls: Option<Vec<String>>,
    #[serde(default = "default_duration")]
    duration_seconds: u64,
    phases: Vec<Phase>,
    #[serde(default = "default_connections")]
    connections: usize,
    #[serde(default = "default_signing_threads")]
    signing_threads: usize,
    #[serde(default = "default_batch")]
    batch_size: usize,
    #[serde(default = "default_pending")]
    max_outstanding: usize,
    #[serde(default = "default_poll")]
    status_poll_ms: u64,
    #[serde(default = "default_timeout")]
    drain_timeout_seconds: u64,
    #[serde(default = "default_stride")]
    id_sample_stride: u64,
    #[serde(default = "default_amount")]
    amount: u64,
    #[serde(default = "default_compute_limit")]
    compute_unit_limit: u32,
    output: PathBuf,
}

struct Pending {
    id: String,
    started: Instant,
    admitted: bool,
    recipient: usize,
    kind: Kind,
}
struct Job {
    counters: Vec<u64>,
    transactions: Vec<VersionedTransaction>,
}
struct Submitted {
    counter: u64,
    result: std::result::Result<(), String>,
}

#[derive(Default, Serialize)]
struct Counts {
    generated: u64,
    admitted: u64,
    admission_errors: u64,
    finalized_success: u64,
    finalized_error: u64,
    latency_millis_total: u64,
    latency_millis_max: u64,
    latency_buckets: [u64; 32],
}
impl Counts {
    fn finalized(&mut self, milliseconds: u64, success: bool) {
        if success {
            self.finalized_success = self.finalized_success.saturating_add(1);
        } else {
            self.finalized_error = self.finalized_error.saturating_add(1);
        }
        self.latency_millis_total = self.latency_millis_total.saturating_add(milliseconds);
        self.latency_millis_max = self.latency_millis_max.max(milliseconds);
        let bucket = usize::try_from(u64::BITS.saturating_sub(milliseconds.leading_zeros()))
            .unwrap_or(31)
            .min(31);
        self.latency_buckets[bucket] = self.latency_buckets[bucket].saturating_add(1);
    }
}

#[derive(Clone, Debug)]
enum SubmissionFailure {
    IngressFull(String),
    AlreadyProcessed(String),
    Hard(String),
}
type SubmissionOutcome = std::result::Result<(), SubmissionFailure>;

fn decode_submission_batch(
    response: &Value,
    transactions: &[VersionedTransaction],
) -> Result<Vec<SubmissionOutcome>> {
    let rows = response.as_array().context("RPC submission batch")?;
    ensure!(
        rows.len() == transactions.len(),
        "RPC submission batch length mismatch"
    );
    let mut outcomes =
        vec![Err(SubmissionFailure::Hard("RPC batch response missing".into())); transactions.len()];
    let mut seen = BTreeSet::new();
    for row in rows {
        ensure!(
            row["jsonrpc"] == "2.0",
            "RPC submission JSONRPC version mismatch"
        );
        let index = usize::try_from(row["id"].as_u64().context("RPC submission ID")?)?;
        ensure!(
            index < transactions.len() && seen.insert(index),
            "RPC submission ID mismatch"
        );
        ensure!(
            row.get("error").is_some() != row.get("result").is_some(),
            "RPC submission requires exactly one result or error"
        );
        outcomes[index] = if let Some(error) = row.get("error") {
            let code = error["code"]
                .as_i64()
                .context("RPC submission error code")?;
            let message = error["message"]
                .as_str()
                .context("RPC submission error message")?;
            let text = error.to_string();
            Err(
                if code == -32050
                    && message
                        == "PQ transaction ingress is full; retry the same signed transaction"
                {
                    SubmissionFailure::IngressFull(text)
                } else if message.contains("AlreadyProcessed")
                    || message.contains("already processed")
                {
                    SubmissionFailure::AlreadyProcessed(text)
                } else {
                    SubmissionFailure::Hard(text)
                },
            )
        } else {
            let expected = transactions[index]
                .signatures
                .first()
                .context("RPC submission signature missing")?
                .to_string();
            ensure!(
                row["result"].as_str() == Some(expected.as_str()),
                "RPC returned wrong transaction identity"
            );
            Ok(())
        };
    }
    Ok(outcomes)
}

fn submission_body(transactions: &[VersionedTransaction], batch: bool) -> Result<Vec<u8>> {
    let requests = transactions.iter().enumerate().map(|(index, tx)| -> Result<Value> {
        Ok(json!({"jsonrpc":"2.0","id":index,"method":"sendTransaction","params":[BASE64_STANDARD.encode(wincode::serialize(tx)?),{"encoding":"base64","skipPreflight":true}]}))
    }).collect::<Result<Vec<_>>>()?;
    ensure!(!requests.is_empty(), "empty RPC submission");
    Ok(serde_json::to_vec(&if batch {
        Value::Array(requests)
    } else {
        ensure!(requests.len() == 1, "single RPC submission length");
        requests.into_iter().next().unwrap()
    })?)
}

fn batch_submit(rpc: &Rpc, url: &str, job: &Job, deadline: Instant) -> Vec<SubmissionOutcome> {
    let response = (|| -> Result<Vec<SubmissionOutcome>> {
        let body = submission_body(&job.transactions, true)?;
        let response =
            rpc.post_json_retry_until(url, &body, "sendTransaction batch", None, deadline)?;
        decode_submission_batch(&response, &job.transactions)
    })();
    match response {
        Ok(outcomes) => outcomes,
        // A protocol/identity failure never reaches semantic retry handling.
        Err(error) => {
            vec![Err(SubmissionFailure::Hard(format!("{error:#}"))); job.transactions.len()]
        }
    }
}

fn verify_processed_submission(
    rpc: &Rpc,
    url: &str,
    tx: &VersionedTransaction,
    deadline: Instant,
) -> Result<()> {
    let signature = tx
        .signatures
        .first()
        .context("processed submission signature missing")?
        .to_string();
    let body = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[[signature],{"searchTransactionHistory":true}]}),
    )?;
    let response = rpc.post_json_retry_until(
        url,
        &body,
        "exact processed submission status",
        None,
        deadline,
    )?;
    ensure!(
        response["jsonrpc"] == "2.0" && response["id"].as_u64() == Some(1),
        "processed submission response identity mismatch"
    );
    ensure!(
        response.get("error").is_none(),
        "processed submission status RPC error"
    );
    let rows = response["result"]["value"]
        .as_array()
        .context("processed submission status rows")?;
    ensure!(
        rows.len() == 1,
        "processed submission status length mismatch"
    );
    let row = &rows[0];
    ensure!(
        row["confirmationStatus"] == "finalized"
            && row["slot"].as_u64().is_some()
            && row.get("err").is_some(),
        "AlreadyProcessed without exact finalized archive status"
    );
    let error = &row["err"];
    ensure!(
        error.is_null() || error.is_object() || error.is_string(),
        "processed submission status error shape"
    );
    // Admission is proven here, not successful execution. The normal observer
    // still records the pinned ID's success or chargeable instruction failure.
    Ok(())
}

fn finish_submission(
    rpc: &Rpc,
    url: &str,
    tx: &VersionedTransaction,
    mut result: SubmissionOutcome,
    deadline: Instant,
) -> std::result::Result<(), String> {
    let body =
        submission_body(std::slice::from_ref(tx), false).map_err(|error| format!("{error:#}"))?;
    loop {
        match result {
            Ok(()) => return Ok(()),
            Err(SubmissionFailure::Hard(text)) => return Err(text),
            Err(SubmissionFailure::AlreadyProcessed(text)) => {
                return verify_processed_submission(rpc, url, tx, deadline)
                    .with_context(|| format!("unverified replay response: {text}"))
                    .map_err(|error| format!("{error:#}"));
            }
            Err(SubmissionFailure::IngressFull(text)) => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(text);
                };
                thread::sleep(Duration::from_millis(25).min(remaining));
                let response = rpc
                    .post_json_retry_until(
                        url,
                        &body,
                        "sendTransaction ingress retry",
                        None,
                        deadline,
                    )
                    .map_err(|error| format!("{error:#}"))?;
                let decoded = decode_submission_batch(
                    &Value::Array(vec![response]),
                    std::slice::from_ref(tx),
                )
                .map_err(|error| format!("{error:#}"))?;
                result = decoded.into_iter().next().unwrap();
            }
        }
    }
}

fn submission_worker(rpc: Rpc, url: String, jobs: Receiver<Job>, results: Sender<Submitted>) {
    while let Ok(job) = jobs.recv() {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(20))
            .unwrap_or_else(Instant::now);
        let outcomes = batch_submit(&rpc, &url, &job, deadline);
        for ((counter, tx), result) in job.counters.into_iter().zip(job.transactions).zip(outcomes)
        {
            let result = finish_submission(&rpc, &url, &tx, result, deadline);
            if results.send(Submitted { counter, result }).is_err() {
                return;
            }
        }
    }
}

fn phase_at(phases: &[Phase], elapsed: u64) -> &Phase {
    let mut boundary = 0u64;
    for phase in phases {
        boundary = boundary.saturating_add(phase.seconds);
        if elapsed < boundary {
            return phase;
        }
    }
    phases.last().unwrap()
}

fn token_balances(rpc: &Rpc, url: &str, addresses: &[String]) -> Result<Vec<u64>> {
    token_balances_checked(rpc, url, addresses, None)
}

fn token_balances_checked(
    rpc: &Rpc,
    url: &str,
    addresses: &[String],
    cancelled: Option<&AtomicBool>,
) -> Result<Vec<u64>> {
    let mut values = Vec::with_capacity(addresses.len());
    for chunk in addresses.chunks(100) {
        ensure!(
            !cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)),
            "minute token audit cancelled"
        );
        let result = rpc.call_cancellable(
            url,
            "getMultipleAccounts",
            json!([chunk,{"encoding":"base64","commitment":"finalized"}]),
            cancelled,
        )?;
        let rows = result["value"]
            .as_array()
            .context("token balance account response")?;
        ensure!(rows.len() == chunk.len(), "token balance account count");
        for row in rows {
            ensure!(
                row["owner"] == spl_generic_token::token::id().to_string(),
                "token balance account owner"
            );
            let data = BASE64_STANDARD
                .decode(row["data"][0].as_str().context("token account encoding")?)?;
            use solana_program_pack::Pack;
            values.push(spl_token_interface::state::Account::unpack(&data)?.amount);
        }
    }
    Ok(values)
}

fn balances(rpc: &Rpc, urls: &[String], recipients: &[String], tokens: &[String]) -> Result<Value> {
    let nodes=urls.par_iter().map(|url|->Result<_>{Ok(json!({"rpc_url":url,"system":rpc.balances(url,recipients)?,"token":if tokens.is_empty(){Vec::new()}else{token_balances(rpc,url,tokens)?},"status":rpc.call(url,"getExperimentalPqStatus",json!([]))?}))}).collect::<Result<Vec<_>>>()?;
    Ok(json!(nodes))
}

pub(super) fn run(spec: SoakSpec) -> Result<Value> {
    run_mode(spec, false)
}

pub(super) fn run_pipelined(spec: SoakSpec) -> Result<Value> {
    run_mode(spec, true)
}

/// Local preflight uses the same bounds, route limit and credential loading as
/// actual traffic. Credential loading includes its fixed internal consistency
/// challenge; this command never constructs a transaction, RPC client or worker.
pub(super) fn validate(spec: SoakSpec) -> Result<Value> {
    let prepared = prepare_soak(&spec)?;
    let manifest = &prepared.manifest;
    ensure!(
        manifest.format == "agave-native-pq-v1",
        "native soak manifest format"
    );
    ensure!(!manifest.nodes.is_empty(), "native genesis node required");
    let genesis_path = manifest.nodes[0]
        .ledger
        .join(solana_genesis_config::DEFAULT_GENESIS_FILE);
    ensure!(
        fs::metadata(&genesis_path)?.len() <= 64 * 1024 * 1024,
        "native genesis input bound"
    );
    let genesis = GenesisConfig::load(&manifest.nodes[0].ledger)?;
    ensure!(
        genesis.hash().to_string() == manifest.genesis_hash,
        "native genesis hash mismatch"
    );
    let config_account = genesis
        .accounts
        .get(&pq::CONFIG_ADDRESS)
        .context("native PQ config account")?;
    ensure!(
        config_account.owner == pq::PROGRAM_ID
            && !config_account.executable
            && config_account.lamports > 0,
        "native PQ config must be active with its expected owner"
    );
    let config = RuntimeConfig::decode(&config_account.data)?;
    ensure!(
        config == prepared.config,
        "native chain/context/cutoff mismatch"
    );
    for (address, expected) in solana_runtime::pq_workload::program_accounts(&genesis.rent) {
        ensure!(
            genesis.accounts.get(&address) == Some(&expected),
            "native exact SBF nonce fixture mismatch"
        );
    }
    ensure!(
        !spec.output.exists()
            && !spec.output.with_extension("events.jsonl").exists()
            && !spec.output.with_extension("minutes.jsonl").exists(),
        "source outputs must be unused"
    );
    ensure!(
        spec.output.parent().is_some_and(Path::is_dir),
        "source output directory must exist"
    );
    ensure!(
        (1..=86_400).contains(&spec.drain_timeout_seconds),
        "finite drain budget"
    );
    let offered = spec
        .phases
        .iter()
        .try_fold(0u64, |total, phase| {
            total.checked_add(phase.seconds.checked_mul(phase.target_tps)?)
        })
        .context("offered counter bound overflow")?;
    let burst = u64::try_from(
        spec.batch_size
            .checked_mul(spec.connections)
            .context("counter burst bound")?,
    )?
    .checked_mul(u64::try_from(spec.phases.len())?)
    .context("phase burst bound")?;
    let counter_end_bound = spec
        .start_counter
        .checked_add(offered)
        .and_then(|count| count.checked_add(burst))
        .context("source counter range exhausted")?;
    let allowed_urls = manifest
        .nodes
        .iter()
        .map(|node| node.rpc_url.as_str())
        .collect::<BTreeSet<_>>();
    for url in &prepared.urls {
        let parsed = reqwest::Url::parse(url)?;
        ensure!(
            matches!(parsed.scheme(), "http" | "https")
                && parsed.host().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none(),
            "native RPC URL format"
        );
        ensure!(
            allowed_urls.contains(url.as_str()),
            "source RPC route must belong to native manifest"
        );
    }
    let mut bindings = Vec::new();
    let mut authorities = BTreeSet::new();
    for (&index, (address, key)) in spec.wallet_indices.iter().zip(&prepared.wallets) {
        ensure!(
            manifest.wallets[index].index == index && authorities.insert(*address),
            "native wallet lane identity mismatch"
        );
        let account = genesis
            .accounts
            .get(address)
            .context("native fee payer account")?;
        ensure!(
            account.owner == system_program::id()
                && !account.executable
                && account.data.is_empty()
                && account.lamports > 0,
            "native fee payer must be funded controlled System account"
        );
        let policy_address = pq::policy_address(address);
        let policy = genesis
            .accounts
            .get(&policy_address)
            .context("native fresh payer AUTH account")?;
        ensure!(
            policy.lamports > 0,
            "native fresh payer AUTH must be active"
        );
        let record =
            AuthRecord::from_account(&policy_address.to_bytes(), &address.to_bytes(), policy)?;
        ensure!(
            record.origin == Origin::FreshIdentity
                && record.generation == 1
                && record.public_key == key.public_key(),
            "native source credential/AUTH mismatch"
        );
        let nonce = unhex32(&manifest.wallets[index].nonce)?;
        ensure!(
            fresh_address(&config.chain_id, &key.public_key(), &nonce) == address.to_bytes(),
            "native fresh address/key/nonce mismatch"
        );
        bindings.push(json!({"index":index,"authority":address.to_string(),"public_key_commitment":hex(&record.key_commitment)}));
    }
    if !prepared.token_recipients.is_empty() {
        use solana_program_pack::Pack;
        let mint = Pubkey::from_str(manifest.token_mint.as_deref().context("native SPL mint")?)?;
        let mint_account = genesis
            .accounts
            .get(&mint)
            .context("native SPL mint account")?;
        ensure!(
            mint_account.owner == spl_token_interface::id()
                && !mint_account.executable
                && mint_account.lamports > 0,
            "native SPL mint must be active with its expected owner"
        );
        ensure!(
            spl_token_interface::state::Mint::unpack(&mint_account.data)?.decimals == 0,
            "native workload SPL decimals"
        );
        for (&index, (address, _)) in spec.wallet_indices.iter().zip(&prepared.wallets) {
            let source = Pubkey::from_str(&manifest.wallet_token_accounts[index])?;
            let account = genesis
                .accounts
                .get(&source)
                .context("native SPL source account")?;
            ensure!(
                account.owner == spl_token_interface::id()
                    && !account.executable
                    && account.lamports > 0,
                "native SPL source must be active with its expected program owner"
            );
            let token = spl_token_interface::state::Account::unpack(&account.data)?;
            ensure!(
                token.owner == *address && token.mint == mint,
                "native SPL source authority/mint mismatch"
            );
        }
        for (destination, authority) in prepared.token_recipients.iter().zip(&prepared.destinations)
        {
            let account = genesis
                .accounts
                .get(&Pubkey::from_str(destination)?)
                .context("native SPL destination account")?;
            ensure!(
                account.owner == spl_token_interface::id()
                    && !account.executable
                    && account.lamports > 0,
                "native SPL destination must be active with its expected program owner"
            );
            let token = spl_token_interface::state::Account::unpack(&account.data)?;
            ensure!(
                token.owner == *authority && token.mint == mint,
                "native SPL destination authority/mint mismatch"
            );
        }
    }
    let profile = json!({"source_id":spec.source_id,"start_counter":spec.start_counter,
        "duration_seconds":spec.duration_seconds,"phases":spec.phases,"wallet_indices":spec.wallet_indices,
        "recipient_count":spec.recipient_count,"connections":spec.connections,"signing_threads":spec.signing_threads,
        "batch_size":spec.batch_size,"max_outstanding":spec.max_outstanding,"status_poll_ms":spec.status_poll_ms,
        "drain_timeout_seconds":spec.drain_timeout_seconds,"id_sample_stride":spec.id_sample_stride,
        "amount":spec.amount,"compute_unit_limit":spec.compute_unit_limit,
        "rpc_routes_sha384":hex(&Sha384::digest(serde_json::to_vec(&prepared.urls)?)),
        "output_path_sha384":hex(&Sha384::digest(spec.output.as_os_str().as_encoded_bytes()))});
    Ok(
        json!({"format":"agave-pq-soak-local-validation-v1","generator_version":7,"validated":true,
        "offline_internal_credential_challenge":true,"transaction_generation":false,"network_calls":false,
        "state_mutation":false,"filesystem_writes":false,"ax_allocations":false,
        "native_genesis_hash":manifest.genesis_hash,"manifest_sha384":hex(&Sha384::digest(fs::read(&spec.manifest)?)),
        "selected_credential_count":bindings.len(),"native_fresh_AUTH_and_key_nonce_binding":true,
        "native_exact_SBF_nonce_fixture":true,
        "selected_wallet_bindings_sha384":hex(&Sha384::digest(serde_json::to_vec(&bindings)?)),
        "supported_max_outstanding":MAX_OUTSTANDING,"status_route_limit":spec.max_outstanding,
        "finalized_blockhash_refresh":{"all_configured_endpoints":true,"maximum_workers":HASH_REFRESH_WORKERS,
            "shared_sweep_budget_ms":HASH_REFRESH_BUDGET.as_millis(),"refresh_interval_ms":HASH_REFRESH_INTERVAL.as_millis(),
            "usable_refresh_limit_ms":HASH_REFRESH_UNAVAILABLE_LIMIT.as_millis(),
            "rank":"last_valid_block_height_then_context_slot_then_lowest_endpoint_index"},
        "counter_end_exclusive_upper_bound":counter_end_bound,
        "profile_sha384":hex(&Sha384::digest(serde_json::to_vec(&profile)?)),"profile":profile}),
    )
}

fn prepare_soak(spec: &SoakSpec) -> Result<PreparedSoak> {
    ensure!(
        (1..=86_400).contains(&spec.duration_seconds),
        "soak duration bound"
    );
    ensure!(
        !spec.phases.is_empty()
            && spec.phases.len() <= 1440
            && spec
                .phases
                .iter()
                .all(|phase| phase.seconds > 0 && (1..=50_000).contains(&phase.target_tps)),
        "soak phase bounds"
    );
    ensure!(
        spec.phases
            .iter()
            .try_fold(0u64, |sum, phase| sum.checked_add(phase.seconds))
            .context("phase duration overflow")?
            == spec.duration_seconds,
        "phase durations must equal requested continuous duration"
    );
    ensure!(
        (1..=128).contains(&spec.connections)
            && (1..=128).contains(&spec.signing_threads)
            && (1..=16).contains(&spec.batch_size),
        "soak worker bounds"
    );
    ensure!(
        (256..=MAX_OUTSTANDING).contains(&spec.max_outstanding)
            && (10..=1000).contains(&spec.status_poll_ms)
            && spec.id_sample_stride > 0
            && spec.amount > 0
            && (10_000..=1_400_000).contains(&spec.compute_unit_limit),
        "soak budget bounds"
    );
    ensure!(spec.output.is_absolute(), "soak output must be absolute");
    let manifest: Manifest = read_json(&spec.manifest)?;
    ensure!(
        manifest.workload_program.as_deref()
            == Some(solana_runtime::pq_workload::PROGRAM_ID.to_string().as_str()),
        "soak nonce program must be installed in actual genesis"
    );
    ensure!(
        !spec.wallet_indices.is_empty()
            && spec.wallet_indices.iter().collect::<BTreeSet<_>>().len()
                == spec.wallet_indices.len(),
        "soak payer selection must be distinct"
    );
    let wallets = spec
        .wallet_indices
        .iter()
        .map(|index| -> Result<_> {
            let wallet = manifest.wallets.get(*index).context("soak wallet index")?;
            Ok((
                Pubkey::from_str(&wallet.address)?,
                FalconKeypair::load_private(&wallet.private_key)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let recipients = load_recipients(&manifest, spec.recipient_count)?;
    let destinations = recipients
        .iter()
        .map(|address| Pubkey::from_str(address).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    let uses_tokens = spec
        .phases
        .iter()
        .any(|phase| phase.kind == Kind::TokenTransfer);
    let token_recipients = if uses_tokens {
        ensure!(
            manifest.recipient_token_accounts.len() >= recipients.len()
                && manifest.wallet_token_accounts.len() == manifest.wallets.len(),
            "SPL state required for token phase"
        );
        manifest.recipient_token_accounts[..recipients.len()].to_vec()
    } else {
        Vec::new()
    };
    let urls = spec.rpc_urls.clone().unwrap_or_else(|| {
        manifest
            .nodes
            .iter()
            .map(|node| node.rpc_url.clone())
            .collect()
    });
    ensure!(!urls.is_empty(), "soak RPC URLs");
    observer::validate_route_limit(spec.max_outstanding)?;
    let config = native_config(&manifest)?;
    Ok(PreparedSoak {
        manifest,
        config,
        wallets,
        recipients,
        destinations,
        token_recipients,
        urls,
    })
}

struct PreparedSoak {
    manifest: Manifest,
    config: RuntimeConfig,
    wallets: Vec<(Pubkey, FalconKeypair)>,
    recipients: Vec<String>,
    destinations: Vec<Pubkey>,
    token_recipients: Vec<String>,
    urls: Vec<String>,
}

fn run_mode(spec: SoakSpec, pipelined: bool) -> Result<Value> {
    let PreparedSoak {
        manifest,
        config,
        wallets,
        recipients,
        destinations,
        token_recipients,
        urls,
    } = prepare_soak(&spec)?;
    let rpc = Rpc::new()?;
    let payer_addresses = spec
        .wallet_indices
        .iter()
        .map(|index| manifest.wallets[*index].address.clone())
        .collect::<Vec<_>>();
    for chunk in payer_addresses.chunks(100) {
        let response = rpc.call(
            &urls[0],
            "getMultipleAccounts",
            json!([chunk,{"encoding":"base64","commitment":"finalized"}]),
        )?;
        let rows = response["value"]
            .as_array()
            .context("payer ownership response")?;
        ensure!(rows.len() == chunk.len(), "payer ownership response length");
        for row in rows {
            let data = BASE64_STANDARD.decode(
                row["data"][0]
                    .as_str()
                    .context("payer canonical account data")?,
            )?;
            ensure!(
                row["owner"] == system_program::id().to_string()
                    && row["executable"] == false
                    && data.is_empty(),
                "soak fee payers must be controlled System accounts without data"
            );
        }
    }
    let before = balances(&rpc, &urls, &recipients, &token_recipients)?;
    let events_path = spec.output.with_extension("events.jsonl");
    let minute_path = spec.output.with_extension("minutes.jsonl");
    ensure!(!spec.output.exists(), "soak output must be fresh");
    let mut events = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&events_path)?,
    );
    let mut minutes = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&minute_path)?,
    );
    let mut refresher = HashRefresher::new(rpc.clone(), urls.clone())?;
    let queue_capacity = spec.connections.saturating_mul(2);
    let (jobs_tx, jobs_rx) = bounded::<Job>(queue_capacity);
    let (results_tx, results_rx) = bounded::<Submitted>(spec.max_outstanding);
    let mut workers = Vec::new();
    for worker in 0..spec.connections {
        let rpc = rpc.clone();
        let url = urls[worker.checked_rem(urls.len()).context("empty URL set")?].clone();
        let jobs = jobs_rx.clone();
        let results = results_tx.clone();
        workers.push(thread::spawn(move || {
            submission_worker(rpc, url, jobs, results)
        }));
    }
    drop(jobs_rx);
    drop(results_tx);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(spec.signing_threads)
        .build()?;
    let mut status_pool = pipelined
        .then(|| observer::StatusPool::new(rpc.clone(), urls.clone(), spec.max_outstanding))
        .transpose()?;
    let mut audit_pool = if pipelined {
        let rpc = rpc.clone();
        let urls = urls.clone();
        let recipients = recipients.clone();
        let tokens = token_recipients.clone();
        Some(observer::AuditPool::new(move |cancelled| {
            let rows=urls.par_iter().map(|url|->Result<_>{
                ensure!(!cancelled.load(Ordering::Acquire),"minute validator audit cancelled");
                let system=rpc.balances_cancellable(url,&recipients,Some(cancelled))?;
                let token=token_balances_checked(&rpc,url,&tokens,Some(cancelled))?;
                ensure!(!cancelled.load(Ordering::Acquire),"minute status audit cancelled");
                Ok(json!({"rpc_url":url,"system":system,"token":token,"status":rpc.call_cancellable(url,"getExperimentalPqStatus",json!([]),Some(cancelled))?}))
            }).collect::<Result<Vec<_>>>()?;
            Ok(json!(rows))
        }))
    } else {
        None
    };
    let started_ms = wall_ms();
    let started = Instant::now();
    let mut totals = Counts::default();
    let mut minute = Counts::default();
    let mut pending = BTreeMap::<u64, Pending>::new();
    let mut next_counter = spec.start_counter;
    let mut cursor = spec.start_counter;
    let mut fair_cursor = observer::FairStatusCursor::default();
    let mut last_poll = Instant::now();
    let mut last_minute = Instant::now();
    let mut minute_number = 0u64;
    let mut credit = 0f64;
    let mut last_credit = Instant::now();
    let mut last_hash = Sha384::new();
    let mut system_delta = vec![0u64; recipients.len()];
    let mut token_delta = system_delta.clone();
    let mut max_pending = 0usize;
    let mut minute_summaries = Vec::new();
    let mut last_admitted_ms = None;
    let mut first_admitted_ms = None;
    let mut first_admitted_elapsed = None;
    let mut last_admitted_elapsed = 0.0f64;
    let mut largest_admission_gap_ms = 0u64;
    let mut refresh_failure = None;
    let mut refresh_failed_at: Option<Instant> = None;
    let operation = (|| -> Result<()> {
        loop {
            if let Err(error) = refresher.latest.read().unwrap().available(Instant::now()) {
                let reason = format!("{error:#}");
                refresh_failure.get_or_insert_with(|| reason.clone());
                refresh_failed_at.get_or_insert_with(Instant::now);
                refresher.cancelled.store(true, Ordering::Release);
            }
            loop {
                match results_rx.try_recv() {
                    Ok(result) => {
                        let item = pending
                            .get_mut(&result.counter)
                            .context("submission result without reserved transaction")?;
                        match result.result {
                            Ok(()) => {
                                item.admitted = true;
                                totals.admitted = totals.admitted.saturating_add(1);
                                minute.admitted = minute.admitted.saturating_add(1);
                                let now = wall_ms();
                                first_admitted_ms.get_or_insert(now);
                                first_admitted_elapsed
                                    .get_or_insert_with(|| started.elapsed().as_secs_f64());
                                last_admitted_elapsed = started.elapsed().as_secs_f64();
                                if let Some(last) = last_admitted_ms {
                                    largest_admission_gap_ms =
                                        largest_admission_gap_ms.max(now.saturating_sub(last));
                                }
                                last_admitted_ms = Some(now);
                            }
                            Err(error) => {
                                totals.admission_errors = totals.admission_errors.saturating_add(1);
                                minute.admission_errors = minute.admission_errors.saturating_add(1);
                                writeln!(
                                    events,
                                    "{}",
                                    json!({"event":"admission_error","counter":result.counter,"id":item.id,"error":error.chars().take(1024).collect::<String>(),"wall_ms":wall_ms()})
                                )?;
                                pending.remove(&result.counter);
                            }
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        ensure!(
                            pending.is_empty(),
                            "submission workers disconnected with pending transactions"
                        );
                        break;
                    }
                }
            }
            let mut observations = Vec::new();
            if let Some(observer) = &mut status_pool {
                observations = observer.drain()?;
            }
            // Completed batches release their worker reservations before the
            // central loop applies terminal rows. Keep them out of the next
            // polling batch until that reconciliation has finished.
            let completing = observations
                .iter()
                .flat_map(|batch| batch.entries.iter().map(|entry| entry.counter))
                .collect::<BTreeSet<_>>();
            if last_poll.elapsed() >= Duration::from_millis(spec.status_poll_ms)
                && !pending.is_empty()
            {
                loop {
                    if status_pool
                        .as_ref()
                        .is_some_and(|observer| !observer.has_capacity())
                    {
                        break;
                    }
                    let eligible = |counter: &u64, item: &Pending| {
                        item.admitted
                            && !completing.contains(counter)
                            && !status_pool
                                .as_ref()
                                .is_some_and(|observer| observer.is_busy(*counter))
                    };
                    let fair_batch = pipelined.then(|| fair_cursor.select(&pending, eligible));
                    let positions = if let Some(batch) = &fair_batch {
                        batch.counters.clone()
                    } else {
                        let mut positions = pending
                            .range(cursor..)
                            .filter(|(counter, item)| eligible(counter, item))
                            .take(256)
                            .map(|(counter, _)| *counter)
                            .collect::<Vec<_>>();
                        if positions.len() < 256 {
                            positions.extend(
                                pending
                                    .range(..cursor)
                                    .filter(|(counter, item)| eligible(counter, item))
                                    .take(256usize.saturating_sub(positions.len()))
                                    .map(|(counter, _)| *counter),
                            );
                        }
                        positions
                    };
                    if positions.is_empty() {
                        break;
                    }
                    let entries = positions
                        .iter()
                        .map(|counter| observer::StatusEntry {
                            counter: *counter,
                            signature: pending[counter].id.clone(),
                        })
                        .collect::<Vec<_>>();
                    if let Some(observer) = &mut status_pool {
                        if !observer.schedule(entries)? {
                            break;
                        }
                    } else {
                        let ids = entries
                            .iter()
                            .map(|entry| &entry.signature)
                            .collect::<Vec<_>>();
                        let response = rpc.call(
                            &urls[0],
                            "getSignatureStatuses",
                            json!([ids,{"searchTransactionHistory":true}]),
                        )?;
                        let rows = response["value"]
                            .as_array()
                            .context("soak exact status response")?;
                        ensure!(rows.len() == positions.len(), "soak exact status count");
                        observations.push(observer::StatusObservation {
                            entries,
                            rows: rows.clone(),
                        });
                    }
                    if let Some(batch) = &fair_batch {
                        fair_cursor.dispatched(batch)?;
                    } else {
                        cursor = positions
                            .last()
                            .unwrap()
                            .checked_add(1)
                            .context("poll cursor overflow")?;
                    }
                    if !pipelined {
                        break;
                    }
                }
                last_poll = Instant::now();
            }
            for batch in observations {
                batch.validate_pending(&pending)?;
                for (entry, row) in batch.entries.iter().zip(&batch.rows) {
                    let counter = &entry.counter;
                    let current = pending
                        .get(counter)
                        .context("status response references absent pending identity")?;
                    ensure!(
                        current.admitted && current.id == entry.signature,
                        "status response references stale or unadmitted transaction identity"
                    );
                    if row.is_null() || row["confirmationStatus"] != "finalized" {
                        continue;
                    }
                    if let Some(observer) = &mut status_pool {
                        observer.retire_finalized(entry, row, &pending)?;
                    }
                    let item = pending
                        .remove(counter)
                        .context("finalized pending item missing")?;
                    let success = row["err"].is_null();
                    let latency =
                        u64::try_from(item.started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    totals.finalized(latency, success);
                    minute.finalized(latency, success);
                    last_hash.update(counter.to_le_bytes());
                    last_hash.update(u64::try_from(item.id.len())?.to_le_bytes());
                    last_hash.update(item.id.as_bytes());
                    last_hash.update([u8::from(success)]);
                    if success {
                        let delta = match item.kind {
                            Kind::SystemTransfer => Some(&mut system_delta),
                            Kind::TokenTransfer => Some(&mut token_delta),
                            Kind::NonceOnly => None,
                        };
                        if let Some(delta) = delta {
                            delta[item.recipient] = delta[item.recipient]
                                .checked_add(spec.amount)
                                .context("finalized recipient delta overflow")?;
                        }
                    }
                    if !success || counter.checked_rem(spec.id_sample_stride) == Some(0) {
                        writeln!(
                            events,
                            "{}",
                            json!({"event":"finalized","counter":counter,"id":item.id,"success":success,"error":row["err"],"slot":row["slot"],"latency_ms":latency,"kind":item.kind,"recipient_index":item.recipient,"wall_ms":wall_ms()})
                        )?;
                    }
                }
            }
            if let Some(auditor) = &mut audit_pool {
                for report in auditor.drain()? {
                    writeln!(minutes, "{report}")?;
                    minutes.flush()?;
                    events.flush()?;
                    minute_summaries.push(report);
                }
            }
            if last_minute.elapsed() >= Duration::from_secs(60) {
                let elapsed = last_minute.elapsed().as_secs_f64();
                minute_number = minute_number.saturating_add(1);
                let mut report = json!({"minute":minute_number,"wall_ms":wall_ms(),"observed_seconds":elapsed,"counts":minute,"onchain_success_tps":minute.finalized_success as f64/elapsed,"pending":pending.len(),"phase":phase_at(&spec.phases,started.elapsed().as_secs()),"latest_blockhash_selection":refresher.latest.read().unwrap().metrics(),"blockhash_refresh_failure":refresh_failure});
                if let Some(auditor) = &mut audit_pool {
                    auditor.schedule(report)?;
                } else {
                    report["validators"] = balances(&rpc, &urls, &recipients, &token_recipients)?;
                    writeln!(minutes, "{report}")?;
                    minutes.flush()?;
                    events.flush()?;
                    minute_summaries.push(report);
                }
                minute = Counts::default();
                last_minute = Instant::now();
            }
            let elapsed = started.elapsed();
            if let Some(failed_at) = refresh_failed_at {
                // Stop new signing on a permanent or prolonged refresh failure,
                // but reconcile outstanding submission ACKs and exact receipts
                // for the existing finite drain. No acknowledged ID is replaced.
                if pending.is_empty()
                    && audit_pool
                        .as_ref()
                        .is_none_or(observer::AuditPool::is_empty)
                {
                    break;
                }
                ensure!(
                    failed_at.elapsed() < Duration::from_secs(spec.drain_timeout_seconds),
                    "finalized blockhash refresh failure with {} outstanding exact IDs: {}",
                    pending.len(),
                    refresh_failure.as_deref().unwrap()
                );
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            if elapsed >= Duration::from_secs(spec.duration_seconds) {
                if pending.is_empty()
                    && audit_pool
                        .as_ref()
                        .is_none_or(observer::AuditPool::is_empty)
                {
                    break;
                }
                ensure!(
                    elapsed
                        < Duration::from_secs(
                            spec.duration_seconds
                                .saturating_add(spec.drain_timeout_seconds)
                        ),
                    "continuous soak failed to drain {} outstanding exact transaction IDs",
                    pending.len()
                );
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            let phase = phase_at(&spec.phases, elapsed.as_secs());
            credit = (credit + last_credit.elapsed().as_secs_f64() * phase.target_tps as f64)
                .min((spec.batch_size.saturating_mul(spec.connections)) as f64);
            last_credit = Instant::now();
            let count = spec
                .batch_size
                .min(spec.max_outstanding.saturating_sub(pending.len()))
                .min(credit.floor() as usize);
            if count == 0 || jobs_tx.is_full() {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            // Status reconciliation can take time. Re-read the selection at
            // the signing boundary instead of retaining the turn's old hash.
            let hash = match refresher.latest.read().unwrap().available(Instant::now()) {
                Ok(Some(hash)) => hash,
                Ok(None) => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => continue,
            };
            let first = next_counter;
            let end = first
                .checked_add(u64::try_from(count)?)
                .context("soak counter exhausted")?;
            let transactions = pool.install(|| {
                (first..end)
                    .into_par_iter()
                    .map(|counter| -> Result<_> {
                        let payer = usize::try_from(
                            counter
                                .checked_rem(u64::try_from(wallets.len())?)
                                .context("empty payer set")?,
                        )?;
                        let recipient = usize::try_from(
                            counter
                                .checked_rem(u64::try_from(destinations.len())?)
                                .context("empty recipient set")?,
                        )?;
                        let (authority, key) = &wallets[payer];
                        let mut instructions = vec![
                            ComputeBudgetInstruction::set_compute_unit_limit(
                                spec.compute_unit_limit,
                            ),
                            solana_runtime::pq_workload::nonce_instruction(spec.source_id, counter),
                        ];
                        match phase.kind {
                            Kind::SystemTransfer => {
                                instructions.push(system_instruction::transfer(
                                    authority,
                                    &destinations[recipient],
                                    spec.amount,
                                ))
                            }
                            Kind::TokenTransfer => instructions.push(
                                spl_token_interface::instruction::transfer_checked(
                                    &spl_generic_token::token::id(),
                                    &Pubkey::from_str(
                                        &manifest.wallet_token_accounts[spec.wallet_indices[payer]],
                                    )?,
                                    &Pubkey::from_str(
                                        manifest
                                            .token_mint
                                            .as_deref()
                                            .context("token mint missing")?,
                                    )?,
                                    &Pubkey::from_str(&token_recipients[recipient])?,
                                    authority,
                                    &[],
                                    spec.amount,
                                    0,
                                )?,
                            ),
                            Kind::NonceOnly => {}
                        }
                        transaction(&config, *authority, key, hash, &instructions)
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            let counters: Vec<_> = (first..end).collect();
            for (counter, tx) in counters.iter().zip(&transactions) {
                let recipient = usize::try_from(
                    counter
                        .checked_rem(u64::try_from(destinations.len())?)
                        .context("empty recipient set")?,
                )?;
                pending.insert(
                    *counter,
                    Pending {
                        id: tx.signatures[0].to_string(),
                        started: Instant::now(),
                        admitted: false,
                        recipient,
                        kind: phase.kind,
                    },
                );
            }
            match jobs_tx.try_send(Job {
                counters,
                transactions,
            }) {
                Ok(()) => {
                    next_counter = end;
                    credit -= count as f64;
                    totals.generated = totals.generated.saturating_add(u64::try_from(count)?);
                    minute.generated = minute.generated.saturating_add(u64::try_from(count)?);
                    max_pending = max_pending.max(pending.len());
                }
                Err(TrySendError::Full(job)) => {
                    for counter in job.counters {
                        pending.remove(&counter);
                    }
                }
                Err(TrySendError::Disconnected(_)) => bail!("submission queue disconnected"),
            }
        }
        if let Some(failure) = &refresh_failure {
            bail!("{failure}");
        }
        Ok(())
    })();
    drop(jobs_tx);
    drop(results_rx);
    for worker in workers {
        let _ = worker.join();
    }
    if let Some(observer) = &mut status_pool {
        observer.stop();
    }
    if let Some(auditor) = &mut audit_pool {
        auditor.stop();
    }
    refresher.stop();
    for (counter, item) in &pending {
        writeln!(
            events,
            "{}",
            json!({"event":"pending_at_exit","counter":counter,"id":item.id,"admitted":item.admitted,"kind":item.kind,"recipient_index":item.recipient})
        )?;
    }
    events.flush()?;
    minutes.flush()?;
    let convergence_started = Instant::now();
    let after = loop {
        let sample = balances(&rpc, &urls, &recipients, &token_recipients)?;
        let rows = sample.as_array().unwrap();
        if rows
            .iter()
            .all(|row| row["system"] == rows[0]["system"] && row["token"] == rows[0]["token"])
        {
            break sample;
        }
        if convergence_started.elapsed() >= Duration::from_secs(spec.drain_timeout_seconds) {
            break sample;
        }
        thread::sleep(Duration::from_millis(100));
    };
    let rows = after.as_array().unwrap();
    let all_balances_match = rows
        .iter()
        .all(|row| row["system"] == rows[0]["system"] && row["token"] == rows[0]["token"]);
    let elapsed = started.elapsed().as_secs_f64();
    let failure = operation.as_ref().err().map(ToString::to_string);
    let result = json!({"actual_agave_rpc":true,"actual_bank_svm":true,"source_id":spec.source_id,"requested_continuous_seconds":spec.duration_seconds,"elapsed_including_drain_seconds":elapsed,"started_unix_ms":started_ms,"completed_unix_ms":wall_ms(),"counts":totals,"onchain_success_tps_including_drain":totals.finalized_success as f64/elapsed,"pending":pending.len(),"outstanding_bound":spec.max_outstanding,"maximum_outstanding_observed":max_pending,"last_counter_exclusive":next_counter,"first_admission_unix_ms":first_admitted_ms,"last_admission_unix_ms":last_admitted_ms,"admission_span_seconds_monotonic":first_admitted_elapsed.map(|first|last_admitted_elapsed-first),"largest_admission_gap_ms":largest_admission_gap_ms,"system_recipient_deltas":system_delta,"token_recipient_deltas":token_delta,"balances_before":before,"balances_after":after,"all_validator_recipient_balances_match":all_balances_match,"finalized_observation_sha384":hex(&last_hash.finalize()),"id_sample_stride":spec.id_sample_stride,"events_file":events_path,"minutes_file":minute_path,"minute_summaries":minute_summaries,"failure":failure,"wallet_indices":spec.wallet_indices,"recipients":recipients,"token_recipients":token_recipients,"phases":spec.phases});
    let mut result = result;
    result["generator_version"] = json!(7);
    result["latest_blockhash_selection"] = refresher.latest.read().unwrap().metrics();
    result["blockhash_refresh_failure"] = json!(refresh_failure);
    result["rpc_transport_retry_metrics"] = rpc.retry_statistics();
    if let Some(observer) = &status_pool {
        result["pipelined_status_observation"] = json!({"workers":observer::STATUS_WORKERS,"maximum_jobs":observer::STATUS_JOB_BOUND,"maximum_ids_per_job":256,"metrics":observer.metrics,"asynchronous_minute_audits":true,"fair_fixed_high_water_cycles":true});
    }
    write_json(&spec.output, &result)?;
    operation?;
    ensure!(
        pending.is_empty() && all_balances_match,
        "soak final recipient balances did not converge"
    );
    ensure!(
        totals.admission_errors == 0 && totals.finalized_error == 0,
        "soak observed admission/execution errors; see persisted result"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    type HashSweepFixture = (Vec<Result<Option<FinalizedHash>>>, Vec<Vec<Vec<u8>>>);

    fn hash_reply(height: u64, slot: u64, hash: Hash) -> Value {
        json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":slot},
            "value":{"blockhash":hash.to_string(),"lastValidBlockHeight":height}}})
    }

    fn eight_hash_sweep(replies: Vec<Value>) -> HashSweepFixture {
        assert_eq!(replies.len(), 8);
        let mocks = replies
            .into_iter()
            .map(|reply| transport::testing::mock(vec![transport::testing::json_reply(200, reply)]))
            .collect::<Vec<_>>();
        let urls = mocks
            .iter()
            .map(|mock| mock.url.clone())
            .collect::<Vec<_>>();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(HASH_REFRESH_WORKERS)
            .build()
            .unwrap();
        let results = finalized_hash_sweep(
            &Rpc::new().unwrap(),
            &urls,
            &pool,
            Instant::now().checked_add(HASH_REFRESH_BUDGET).unwrap(),
            None,
        );
        let requests = mocks
            .iter()
            .map(|mock| mock.requests.lock().unwrap().clone())
            .collect();
        (results, requests)
    }

    #[test]
    fn finalized_hash_sweep_uses_all_eight_and_escapes_lagging_node_zero() {
        let expected = Hash::new_unique();
        let mut replies = (0..8)
            .map(|_| hash_reply(300, 400, Hash::new_unique()))
            .collect::<Vec<_>>();
        replies[0] = hash_reply(100, 200, Hash::new_unique());
        replies[5] = hash_reply(301, 401, expected);
        let (results, requests) = eight_hash_sweep(replies);
        let mut latest = LatestFinalizedHash::new(8);
        latest.apply(results, Instant::now());
        assert_eq!(latest.available(Instant::now()).unwrap(), Some(expected));
        assert_eq!(latest.selected.as_ref().unwrap().endpoint, 5);
        assert_eq!(requests.len(), 8);
        for requests in requests {
            assert_eq!(requests.len(), 1);
            let body: Value = serde_json::from_slice(&requests[0]).unwrap();
            assert_eq!(
                body,
                json!({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash",
                "params":[{"commitment":"finalized"}]})
            );
        }
    }

    #[test]
    fn finalized_hash_height_outranks_missed_slots_and_ties_are_deterministic() {
        let expected = Hash::new_unique();
        let mut replies = (0..8)
            .map(|_| hash_reply(400, 900, Hash::new_unique()))
            .collect::<Vec<_>>();
        replies[0] = hash_reply(399, 10_000, Hash::new_unique());
        replies[2] = hash_reply(400, 901, expected);
        replies[6] = hash_reply(400, 901, Hash::new_unique());
        let (results, _) = eight_hash_sweep(replies);
        let mut latest = LatestFinalizedHash::new(8);
        latest.apply(results, Instant::now());
        assert_eq!(latest.available(Instant::now()).unwrap(), Some(expected));
        assert_eq!(latest.selected.as_ref().unwrap().endpoint, 2);
        assert_eq!(latest.selected.as_ref().unwrap().rank(), (400, 901));
    }

    #[test]
    fn finalized_hash_one_unreachable_endpoint_keeps_exact_last_good_without_regressing() {
        let highest = Hash::new_unique();
        let (results, _) =
            eight_hash_sweep((0..8).map(|_| hash_reply(500, 700, highest)).collect());
        let mut latest = LatestFinalizedHash::new(8);
        latest.apply(results, Instant::now());
        let mocks = (0..7)
            .map(|_| {
                transport::testing::mock(vec![transport::testing::json_reply(
                    200,
                    hash_reply(499, 699, Hash::new_unique()),
                )])
            })
            .collect::<Vec<_>>();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut urls = vec![format!("http://{}", closed.local_addr().unwrap())];
        drop(closed);
        urls.extend(mocks.iter().map(|mock| mock.url.clone()));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(HASH_REFRESH_WORKERS)
            .build()
            .unwrap();
        let mut rpc = transport::testing::rpc(Duration::from_millis(100), HASH_REFRESH_BUDGET);
        rpc.retry_policy.attempts = 1;
        let results = finalized_hash_sweep(
            &rpc,
            &urls,
            &pool,
            Instant::now().checked_add(HASH_REFRESH_BUDGET).unwrap(),
            None,
        );
        assert!(matches!(results[0], Ok(None)));
        latest.apply(results, Instant::now());
        assert_eq!(latest.available(Instant::now()).unwrap(), Some(highest));
        assert_eq!(latest.regressions_ignored, 1);
        assert_eq!(latest.unavailable_endpoint_results, 1);
        assert_eq!(latest.successful_sweeps, 1);
        assert_eq!(latest.valid_sweeps, 2);
    }

    #[test]
    fn finalized_hash_eight_slow_endpoints_share_one_parallel_deadline() {
        let mocks = (0..8)
            .map(|_| {
                transport::testing::mock(vec![transport::testing::Reply::Http {
                    code: 200,
                    body: serde_json::to_vec(&hash_reply(500, 700, Hash::new_unique())).unwrap(),
                    delay: Duration::from_millis(250),
                }])
            })
            .collect::<Vec<_>>();
        let urls = mocks
            .iter()
            .map(|mock| mock.url.clone())
            .collect::<Vec<_>>();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(HASH_REFRESH_WORKERS)
            .build()
            .unwrap();
        let mut rpc = transport::testing::rpc(Duration::from_secs(1), HASH_REFRESH_BUDGET);
        rpc.retry_policy.attempts = 1;
        let started = Instant::now();
        let results = finalized_hash_sweep(
            &rpc,
            &urls,
            &pool,
            started.checked_add(Duration::from_millis(100)).unwrap(),
            None,
        );
        assert!(started.elapsed() < Duration::from_millis(700));
        assert!(results.into_iter().all(|result| matches!(result, Ok(None))));
        assert!(
            mocks
                .iter()
                .all(|mock| mock.requests.lock().unwrap().len() == 1)
        );
    }

    #[test]
    fn finalized_hash_transient_http503_recovers_identical_read_without_losing_best_peer() {
        let expected = Hash::new_unique();
        let mut mocks = (0..7)
            .map(|_| {
                transport::testing::mock(vec![transport::testing::json_reply(
                    200,
                    hash_reply(500, 700, Hash::new_unique()),
                )])
            })
            .collect::<Vec<_>>();
        mocks.push(transport::testing::mock(vec![
            transport::testing::json_reply(503, json!({"temporarily_unavailable":true})),
            transport::testing::json_reply(200, hash_reply(501, 701, expected)),
        ]));
        let urls = mocks
            .iter()
            .map(|mock| mock.url.clone())
            .collect::<Vec<_>>();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(HASH_REFRESH_WORKERS)
            .build()
            .unwrap();
        let rpc = transport::testing::rpc(Duration::from_millis(200), HASH_REFRESH_BUDGET);
        let results = finalized_hash_sweep(
            &rpc,
            &urls,
            &pool,
            Instant::now().checked_add(HASH_REFRESH_BUDGET).unwrap(),
            None,
        );
        let mut latest = LatestFinalizedHash::new(8);
        latest.apply(results, Instant::now());
        assert_eq!(latest.available(Instant::now()).unwrap(), Some(expected));
        let retried = mocks[7].requests.lock().unwrap();
        assert_eq!(retried.len(), 2);
        assert_eq!(retried[0], retried[1]);
        assert_eq!(latest.unavailable_endpoint_results, 0);
    }

    #[test]
    fn finalized_hash_malformed_endpoint_fails_closed_despite_seven_valid_peers() {
        let valid = hash_reply(500, 700, Hash::new_unique());
        let malformed = [
            json!({"jsonrpc":"2.0","id":9,"result":valid["result"]}),
            json!({"jsonrpc":"1.0","id":1,"result":valid["result"]}),
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}),
            json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"bad","lastValidBlockHeight":500}}}),
            json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":Hash::new_unique().to_string(),"lastValidBlockHeight":0}}}),
            json!({"jsonrpc":"2.0","id":1,"result":{"context":{"slot":-1},"value":{"blockhash":Hash::new_unique().to_string(),"lastValidBlockHeight":500}}}),
        ];
        for bad in malformed {
            let mut replies = vec![valid.clone(); 8];
            replies[3] = bad;
            let (results, _) = eight_hash_sweep(replies);
            let mut latest = LatestFinalizedHash::new(8);
            latest.apply(results, Instant::now());
            assert!(latest.available(Instant::now()).is_err());
            assert!(latest.selected.is_none());
            assert_eq!(latest.malformed_sweeps, 1);
            // A later success must not revive signing after a permanent failure.
            let (results, _) = eight_hash_sweep(vec![valid.clone(); 8]);
            latest.apply(results, Instant::now());
            assert!(latest.available(Instant::now()).is_err());
        }
    }

    #[test]
    fn finalized_hash_total_unavailability_has_five_second_bound() {
        let mut latest = LatestFinalizedHash::new(8);
        let first = latest.started;
        let hash = Hash::new_unique();
        latest.apply(
            vec![Ok(Some(
                finalized_hash_response(hash_reply(500, 700, hash), 0).unwrap(),
            ))],
            first,
        );
        latest.apply(
            (0..8).map(|_| Ok(None)).collect(),
            first.checked_add(Duration::from_secs(4)).unwrap(),
        );
        assert_eq!(
            latest
                .available(first.checked_add(Duration::from_secs(5)).unwrap())
                .unwrap(),
            Some(hash)
        );
        assert!(
            latest
                .available(first.checked_add(Duration::from_millis(5001)).unwrap())
                .is_err()
        );
    }

    #[test]
    fn finalized_hash_all_eight_regressed_responses_do_not_extend_usable_freshness() {
        let selected = Hash::new_unique();
        let mut latest = LatestFinalizedHash::new(8);
        let first = latest.started;
        let (results, _) = eight_hash_sweep(vec![hash_reply(500, 700, selected); 8]);
        latest.apply(results, first);
        for second in [1, 2, 3, 4, 5, 6] {
            let (results, _) = eight_hash_sweep(vec![hash_reply(499, 699, Hash::new_unique()); 8]);
            let now = first.checked_add(Duration::from_secs(second)).unwrap();
            latest.apply(results, now);
            assert_eq!(latest.selected.as_ref().unwrap().hash, selected);
            assert_eq!(latest.last_success, Some(first));
            if second <= 5 {
                assert_eq!(latest.available(now).unwrap(), Some(selected));
            } else {
                assert!(latest.available(now).is_err());
            }
        }
        assert_eq!(latest.successful_sweeps, 1);
        assert_eq!(latest.regressions_ignored, 6);
        assert_eq!(latest.valid_endpoint_results, 56);
        assert_eq!(latest.valid_sweeps, 7);
        // A matching response refreshes usability without changing its ID/hash.
        let (results, _) = eight_hash_sweep(vec![hash_reply(500, 700, selected); 8]);
        let now = first.checked_add(Duration::from_secs(7)).unwrap();
        latest.apply(results, now);
        assert_eq!(latest.available(now).unwrap(), Some(selected));
    }

    struct SourceHashMock {
        url: String,
        submitted_ids: Arc<Mutex<Vec<String>>>,
        stopping: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl Drop for SourceHashMock {
        fn drop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            self.worker.take().unwrap().join().unwrap();
        }
    }

    fn source_hash_mock(hash: Hash) -> SourceHashMock {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let submitted_ids = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let ids = Arc::clone(&submitted_ids);
        let stop = Arc::clone(&stopping);
        let worker = thread::spawn(move || {
            let mut hash_reads = 0u64;
            while !stop.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(socket) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("source hash mock accept: {error}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    header.extend(byte);
                }
                let length = std::str::from_utf8(&header)
                    .unwrap()
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                let mut reply = |request: &Value| {
                    let result = match request["method"].as_str().unwrap() {
                        "getMultipleAccounts" => {
                            json!({"context":{"slot":700},"value":request["params"][0].as_array().unwrap().iter().map(|_|json!({"lamports":1_000_000,"owner":system_program::id().to_string(),"executable":false,"data":["","base64"]})).collect::<Vec<_>>()})
                        }
                        "getBalance" => json!({"context":{"slot":700},"value":1_000_000}),
                        "getExperimentalPqStatus" => json!({"slot":700}),
                        "getLatestBlockhash" => {
                            hash_reads = hash_reads.saturating_add(1);
                            if hash_reads > 1 {
                                return json!({"jsonrpc":"2.0","id":999,"result":hash_reply(500,700,hash)["result"]});
                            }
                            hash_reply(500, 700, hash)["result"].clone()
                        }
                        "sendTransaction" => {
                            let wire = BASE64_STANDARD
                                .decode(request["params"][0].as_str().unwrap())
                                .unwrap();
                            let transaction: VersionedTransaction =
                                wincode::deserialize(&wire).unwrap();
                            let id = transaction.signatures[0].to_string();
                            ids.lock().unwrap().push(id.clone());
                            json!(id)
                        }
                        "getSignatureStatuses" => {
                            json!({"context":{"slot":700},"value":vec![Value::Null;request["params"][0].as_array().unwrap().len()]})
                        }
                        method => panic!("unexpected actual soak method: {method}"),
                    };
                    json!({"jsonrpc":"2.0","id":request["id"],"result":result})
                };
                let response = match request.as_array() {
                    Some(batch) => Value::Array(batch.iter().map(&mut reply).collect()),
                    None => reply(&request),
                };
                let bytes = serde_json::to_vec(&response).unwrap();
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                     {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .unwrap();
                socket.write_all(&bytes).unwrap();
            }
        });
        SourceHashMock {
            url,
            submitted_ids,
            stopping,
            worker: Some(worker),
        }
    }

    #[test]
    fn actual_soak_refresh_failure_preserves_every_acknowledged_exact_id_without_resigning() {
        let (parent, mut request) = validation_fixture(24001);
        let hash = Hash::new_unique();
        let mocks = (0..8).map(|_| source_hash_mock(hash)).collect::<Vec<_>>();
        request["rpc_urls"] = json!(
            mocks
                .iter()
                .map(|mock| mock.url.clone())
                .collect::<Vec<_>>()
        );
        request["duration_seconds"] = json!(1);
        request["phases"] = json!([{"seconds":1,"target_tps":10000,"kind":"system_transfer"}]);
        request["connections"] = json!(2);
        request["signing_threads"] = json!(2);
        request["batch_size"] = json!(16);
        request["max_outstanding"] = json!(256);
        request["drain_timeout_seconds"] = json!(1);
        let error = run_pipelined(serde_json::from_value(request.clone()).unwrap()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("finalized blockhash refresh failure"),
            "{error:#}"
        );
        let output = PathBuf::from(request["output"].as_str().unwrap());
        let result: Value = read_json(&output).unwrap();
        assert_eq!(result["counts"]["generated"], 256);
        assert_eq!(result["counts"]["admitted"], 256);
        assert_eq!(result["counts"]["finalized_success"], 0);
        assert_eq!(result["counts"]["finalized_error"], 0);
        assert_eq!(result["pending"], 256);
        assert!(
            result["blockhash_refresh_failure"]
                .as_str()
                .unwrap()
                .contains("ID/version mismatch")
        );
        assert_eq!(result["generator_version"], 7);
        let submitted = mocks
            .iter()
            .flat_map(|mock| mock.submitted_ids.lock().unwrap().clone())
            .collect::<Vec<_>>();
        let unique = submitted.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            submitted.len(),
            256,
            "existing admitted logical counters must never be resigned/replaced"
        );
        assert_eq!(unique.len(), 256);
        let events = fs::read_to_string(output.with_extension("events.jsonl")).unwrap();
        let pending = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["event"] == "pending_at_exit")
            .collect::<Vec<_>>();
        assert_eq!(pending.len(), 256);
        assert!(pending.iter().all(|event| event["admitted"] == true));
        assert_eq!(
            pending
                .iter()
                .map(|event| event["id"].as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>(),
            unique
        );
        assert!(parent.path().exists());
    }

    fn validation_fixture(rpc_port: u16) -> (tempfile::TempDir, Value) {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("fresh-native-validation");
        let spec: InitSpec = serde_json::from_value(json!({"directory":directory,
            "hosts":["127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1"],
            "pq_port":25000,"rpc_port":rpc_port,"slot_count":4,"wallet_count":2,
            "recipient_count":2,"enable_workload":true,"enable_spl_programs":true}))
        .unwrap();
        init(spec).unwrap();
        let request = json!({"manifest":directory.join("manifest.json"),"source_id":2131,
            "wallet_indices":[0,1],"recipient_count":2,"duration_seconds":120,
            "phases":[{"seconds":120,"target_tps":16000,"kind":"token_transfer"}],
            "connections":32,"signing_threads":64,"batch_size":16,"max_outstanding":131072,
            "status_poll_ms":100,"drain_timeout_seconds":180,"id_sample_stride":100,
            "amount":1,"compute_unit_limit":20000,"output":parent.path().join("unused-output.json")});
        (parent, request)
    }

    fn input_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut result = BTreeMap::new();
        for row in fs::read_dir(root).unwrap() {
            let path = row.unwrap().path();
            if path.is_dir() {
                result.extend(input_tree(&path));
            } else {
                let digest = Sha384::digest(fs::read(&path).unwrap()).to_vec();
                result.insert(path, digest);
            }
        }
        result
    }

    #[test]
    fn local_validation_accepts_both_profile_caps_without_network_or_filesystem_mutation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (parent, mut request) = validation_fixture(listener.local_addr().unwrap().port());
        let before = input_tree(parent.path());
        for limit in [32768, 131072] {
            request["max_outstanding"] = json!(limit);
            let result = validate(serde_json::from_value(request.clone()).unwrap()).unwrap();
            assert_eq!(result["validated"], true);
            assert_eq!(result["offline_internal_credential_challenge"], true);
            assert_eq!(result["transaction_generation"], false);
            assert_eq!(result["network_calls"], false);
            assert_eq!(result["filesystem_writes"], false);
            assert_eq!(result["state_mutation"], false);
            assert_eq!(result["native_fresh_AUTH_and_key_nonce_binding"], true);
            assert_eq!(result["native_exact_SBF_nonce_fixture"], true);
            assert_eq!(result["selected_credential_count"], 2);
            assert_eq!(result["status_route_limit"], limit);
            assert_eq!(result["profile_sha384"].as_str().unwrap().len(), 96);
        }
        assert_eq!(input_tree(parent.path()), before);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn local_validation_refuses_out_of_range_and_mismatched_native_inputs() {
        let (_parent, request) = validation_fixture(21899);
        for (field, value) in [
            ("max_outstanding", json!(131073)),
            ("max_outstanding", json!(255)),
            ("connections", json!(129)),
            ("start_counter", json!(u64::MAX)),
            ("duration_seconds", json!(121)),
            ("wallet_indices", json!([0, 0])),
            ("rpc_urls", json!(["http://127.0.0.1:1"])),
        ] {
            let mut invalid = request.clone();
            invalid[field] = value;
            assert!(
                validate(serde_json::from_value(invalid).unwrap()).is_err(),
                "invalid {field}"
            );
        }
        let path = PathBuf::from(request["manifest"].as_str().unwrap());
        let original: Manifest = read_json(&path).unwrap();
        for mismatch in 0..4 {
            let mut manifest = original.clone();
            match mismatch {
                0 => manifest.wallets[0].private_key = manifest.wallets[1].private_key.clone(),
                1 => manifest.wallets[0].nonce = "00".repeat(32),
                2 => manifest.genesis_hash = Hash::new_unique().to_string(),
                3 => manifest.wallets[0].index = 1,
                _ => unreachable!(),
            }
            let invalid_path = path.with_file_name(format!("invalid-{mismatch}.json"));
            write_json(&invalid_path, &manifest).unwrap();
            let mut invalid = request.clone();
            invalid["manifest"] = json!(invalid_path);
            assert!(
                validate(serde_json::from_value(invalid).unwrap()).is_err(),
                "mismatch {mismatch}"
            );
        }
        let output =
            PathBuf::from(request["output"].as_str().unwrap()).with_extension("events.jsonl");
        fs::write(output, b"retained source evidence").unwrap();
        assert!(validate(serde_json::from_value(request).unwrap()).is_err());
    }

    #[test]
    fn local_validation_rejects_genesis_tombstones_even_with_matching_genesis_hash() {
        let (_parent, request) = validation_fixture(21899);
        let path = PathBuf::from(request["manifest"].as_str().unwrap());
        let original: Manifest = read_json(&path).unwrap();
        let ledger = &original.nodes[0].ledger;
        let genesis_path = ledger.join(solana_genesis_config::DEFAULT_GENESIS_FILE);
        let original_bytes = fs::read(&genesis_path).unwrap();
        let payer = Pubkey::from_str(&original.wallets[0].address).unwrap();
        let accounts = [
            (pq::CONFIG_ADDRESS, "native PQ config must be active"),
            (payer, "native fee payer must be funded"),
            (
                pq::policy_address(&payer),
                "native fresh payer AUTH must be active",
            ),
            (
                Pubkey::from_str(original.token_mint.as_ref().unwrap()).unwrap(),
                "native SPL mint must be active",
            ),
            (
                Pubkey::from_str(&original.wallet_token_accounts[0]).unwrap(),
                "native SPL source must be active",
            ),
            (
                Pubkey::from_str(&original.recipient_token_accounts[0]).unwrap(),
                "native SPL destination must be active",
            ),
        ];
        for (address, expected_error) in accounts {
            let mut genesis = GenesisConfig::load(ledger).unwrap();
            assert!(genesis.accounts[&address].lamports > 0);
            genesis.accounts.get_mut(&address).unwrap().lamports = 0;
            genesis.write(ledger).unwrap();
            let mut manifest = original.clone();
            manifest.genesis_hash = genesis.hash().to_string();
            fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            // Hash/owner/data are still genuine. A native Bank removes this
            // tombstone, so offline validation must reject its active binding.
            let error = validate(serde_json::from_value(request.clone()).unwrap())
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected_error), "{address}: {error}");
            fs::write(&genesis_path, &original_bytes).unwrap();
            fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        }
        assert!(validate(serde_json::from_value(request).unwrap()).is_ok());
    }

    #[test]
    fn actual_status_pool_uses_the_same_bounded_pressure_cap() {
        for limit in [32768, 131072] {
            let pool = observer::StatusPool::new(
                Rpc::new().unwrap(),
                vec!["http://127.0.0.1:1".into()],
                limit,
            )
            .unwrap();
            drop(pool);
        }
        for limit in [0, 131073, usize::MAX] {
            assert!(
                observer::StatusPool::new(
                    Rpc::new().unwrap(),
                    vec!["http://127.0.0.1:1".into()],
                    limit
                )
                .is_err()
            );
        }
    }

    fn submission_tx() -> VersionedTransaction {
        let signer = Keypair::new();
        VersionedTransaction::try_new(
            VersionedMessage::Legacy(Message::new(&[], Some(&signer.pubkey()))),
            &[&signer],
        )
        .unwrap()
    }

    fn submission_server(
        responses: Vec<Option<(u16, Value)>>,
    ) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        use std::{io::Read, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                }
                let length = String::from_utf8(headers)
                    .unwrap()
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                requests.push(body);
                // None models a request accepted at the transport boundary
                // followed by EOF before its response: retry must be identical.
                if let Some((code, response)) = response {
                    let body = serde_json::to_vec(&response).unwrap();
                    write!(
                        stream,
                        "HTTP/1.1 {code} Test\r\nContent-Length: {}\r\nContent-Type: \
                         application/json\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
            requests
        });
        (url, worker)
    }

    #[test]
    fn ambiguous_batch_transport_retry_preserves_signed_wire_and_exact_ids() {
        let tx = submission_tx();
        let response = json!([{"jsonrpc":"2.0","id":0,"result":tx.signatures[0].to_string()}]);
        let (url, server) = submission_server(vec![None, Some((200, response))]);
        let job = Job {
            counters: vec![7],
            transactions: vec![tx.clone()],
        };
        let outcomes = batch_submit(
            &Rpc::new().unwrap(),
            &url,
            &job,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(outcomes[0].is_ok());
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        let body: Value = serde_json::from_slice(&requests[0]).unwrap();
        assert_eq!(
            BASE64_STANDARD
                .decode(body[0]["params"][0].as_str().unwrap())
                .unwrap(),
            wincode::serialize(&tx).unwrap()
        );
    }

    #[test]
    fn submission_protocol_and_signature_errors_never_escape_through_outer_retry() {
        let tx = submission_tx();
        let sig = tx.signatures[0].to_string();
        let responses = [
            json!([{"jsonrpc":"1.0","id":0,"result":sig}]),
            json!([{"jsonrpc":"2.0","id":1,"result":sig}]),
            json!([{"jsonrpc":"2.0","id":0,"result":"wrong identity"}]),
            json!([{"jsonrpc":"2.0","id":0,"result":sig,"error":{"code":-1,"message":"failed"}}]),
            json!([{"jsonrpc":"2.0","id":0,"error":{"code":-32050,"message":"SignatureFailure: ingress is full"}}]),
        ];
        let rpc = Rpc::new().unwrap();
        for response in responses {
            let result = match decode_submission_batch(&response, std::slice::from_ref(&tx)) {
                Ok(mut outcomes) => outcomes.remove(0),
                Err(error) => Err(SubmissionFailure::Hard(format!("{error:#}"))),
            };
            assert!(matches!(result, Err(SubmissionFailure::Hard(_))));
            // A hard result must not connect or retry against any endpoint.
            assert!(
                finish_submission(
                    &rpc,
                    "http://127.0.0.1:9",
                    &tx,
                    result,
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ingress_retry_uses_identical_transaction_and_one_original_deadline() {
        let tx = submission_tx();
        let error = json!([{"jsonrpc":"2.0","id":0,"error":{"code":-32050,"message":"PQ transaction ingress is full; retry the same signed transaction"}}]);
        let accepted = json!({"jsonrpc":"2.0","id":0,"result":tx.signatures[0].to_string()});
        let (url, server) = submission_server(vec![Some((200, error)), Some((200, accepted))]);
        let rpc = Rpc::new().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let job = Job {
            counters: vec![8],
            transactions: vec![tx.clone()],
        };
        let result = batch_submit(&rpc, &url, &job, deadline).remove(0);
        assert!(finish_submission(&rpc, &url, &tx, result, deadline).is_ok());
        let requests = server.join().unwrap();
        let batch: Value = serde_json::from_slice(&requests[0]).unwrap();
        let single: Value = serde_json::from_slice(&requests[1]).unwrap();
        assert_eq!(batch[0]["params"], single["params"]);
        assert!(
            finish_submission(
                &rpc,
                "http://127.0.0.1:9",
                &tx,
                Err(SubmissionFailure::IngressFull("full".into())),
                Instant::now() - Duration::from_millis(1)
            )
            .is_err()
        );
    }

    #[test]
    fn already_processed_requires_exact_finalized_archive_status_not_null_or_wrong_rpc_id() {
        let tx = submission_tx();
        for (row, response_id, accepted) in [
            (Value::Null, 1, false),
            (
                json!({"slot":9,"confirmationStatus":"confirmed","err":null}),
                1,
                false,
            ),
            (
                json!({"slot":9,"confirmationStatus":"finalized","err":null}),
                999,
                false,
            ),
            (
                json!({"slot":9,"confirmationStatus":"finalized","err":false}),
                1,
                false,
            ),
            (
                json!({"slot":9,"confirmationStatus":"finalized","err":[]}),
                1,
                false,
            ),
            (
                json!({"slot":9,"confirmationStatus":"finalized","err":null}),
                1,
                true,
            ),
            (
                json!({"slot":9,"confirmationStatus":"finalized","err":{"InstructionError":[0,"Custom"]}}),
                1,
                true,
            ),
        ] {
            let response = json!({"jsonrpc":"2.0","id":response_id,"result":{"value":[row]}});
            let (url, server) = submission_server(vec![Some((200, response))]);
            let result = finish_submission(
                &Rpc::new().unwrap(),
                &url,
                &tx,
                Err(SubmissionFailure::AlreadyProcessed(
                    "AlreadyProcessed".into(),
                )),
                Instant::now() + Duration::from_secs(2),
            );
            assert_eq!(result.is_ok(), accepted);
            let body: Value = serde_json::from_slice(&server.join().unwrap()[0]).unwrap();
            assert_eq!(body["method"], "getSignatureStatuses");
            assert_eq!(body["params"][0][0], tx.signatures[0].to_string());
        }
    }

    #[test]
    fn paced_phases_and_actual_finality_metrics_keep_success_and_errors_distinct() {
        let phases = vec![
            Phase {
                seconds: 60,
                target_tps: 1000,
                kind: Kind::SystemTransfer,
            },
            Phase {
                seconds: 60,
                target_tps: 2000,
                kind: Kind::TokenTransfer,
            },
        ];
        assert_eq!(phase_at(&phases, 59).kind, Kind::SystemTransfer);
        assert_eq!(phase_at(&phases, 60).kind, Kind::TokenTransfer);
        let mut counts = Counts::default();
        counts.finalized(1, true);
        counts.finalized(2048, true);
        counts.finalized(8, false);
        assert_eq!(counts.finalized_success, 2);
        assert_eq!(counts.finalized_error, 1);
        assert_eq!(counts.latency_buckets.iter().sum::<u64>(), 3);
        assert_eq!(counts.latency_millis_max, 2048);
        assert_eq!(counts.latency_millis_total, 2057);
    }
}
