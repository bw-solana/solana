//! Bounded observers used only by the opt-in pipelined traffic generator.
use super::*;

pub(super) const STATUS_WORKERS: usize = 4;
pub(super) const STATUS_JOB_BOUND: usize = 8;

/// Freeze the upper bound of each polling pass so continuous new arrivals
/// cannot prevent older, previously-null identities from being revisited.
#[derive(Default)]
pub(super) struct FairStatusCursor {
    next: u64,
    ceiling: Option<u64>,
}

pub(super) struct FairStatusBatch {
    pub counters: Vec<u64>,
    finishes_cycle: bool,
}

impl FairStatusCursor {
    pub fn select(
        &mut self,
        pending: &BTreeMap<u64, Pending>,
        eligible: impl Fn(&u64, &Pending) -> bool,
    ) -> FairStatusBatch {
        // At most one wrap: an empty pass must not spin when every identity
        // already has an in-flight request or awaits central reconciliation.
        for _ in 0..2 {
            let ceiling = match self.ceiling {
                Some(ceiling) => ceiling,
                None => {
                    let Some((last, _)) = pending.last_key_value() else {
                        break;
                    };
                    self.next = 0;
                    self.ceiling = Some(*last);
                    *last
                }
            };
            let counters = pending
                .range(self.next..=ceiling)
                .filter(|(counter, item)| eligible(counter, item))
                .take(256)
                .map(|(counter, _)| *counter)
                .collect::<Vec<_>>();
            if let Some(last) = counters.last() {
                let finishes_cycle = counters.len() < 256 || *last == ceiling;
                return FairStatusBatch {
                    counters,
                    finishes_cycle,
                };
            }
            self.ceiling = None;
        }
        FairStatusBatch {
            counters: Vec::new(),
            finishes_cycle: true,
        }
    }

    pub fn dispatched(&mut self, batch: &FairStatusBatch) -> Result<()> {
        ensure!(!batch.counters.is_empty(), "empty fair status dispatch");
        if batch.finishes_cycle {
            self.ceiling = None;
        } else {
            self.next = batch
                .counters
                .last()
                .unwrap()
                .checked_add(1)
                .context("fair status cursor overflow")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StatusEntry {
    pub counter: u64,
    pub signature: String,
}

struct StatusJob {
    request_id: u64,
    endpoint: usize,
    entries: Vec<StatusEntry>,
}

struct StatusRoute {
    signature: String,
    endpoint: usize,
}

struct StatusReady {
    request_id: u64,
    endpoint: usize,
    requests_per_endpoint: Vec<u64>,
    transient_errors: u64,
    entries: Vec<StatusEntry>,
    result: std::result::Result<Vec<Value>, String>,
    milliseconds: u64,
}

pub(super) struct StatusObservation {
    pub entries: Vec<StatusEntry>,
    pub rows: Vec<Value>,
}

impl StatusObservation {
    pub fn validate_pending(&self, pending: &BTreeMap<u64, Pending>) -> Result<()> {
        ensure!(
            self.entries.len() == self.rows.len(),
            "status observation row count mismatch"
        );
        for entry in &self.entries {
            let item = pending
                .get(&entry.counter)
                .context("status response references absent pending identity")?;
            ensure!(
                item.admitted && item.id == entry.signature,
                "status response references stale or unadmitted transaction identity"
            );
        }
        Ok(())
    }
}

#[derive(Default, Serialize)]
pub(super) struct StatusMetrics {
    requests_per_endpoint: Vec<u64>,
    started: u64,
    completed: u64,
    rpc_milliseconds_total: u64,
    rpc_milliseconds_max: u64,
    maximum_inflight_jobs: usize,
    maximum_inflight_ids: usize,
    requested_ids: u64,
    minimum_batch_ids: Option<usize>,
    maximum_batch_ids: usize,
    null_rows: u64,
    finalized_rows: u64,
    transport_retry_errors: u64,
    transport_recovered_jobs: u64,
    failed_jobs: u64,
}

pub(super) struct StatusPool {
    jobs: Option<Sender<StatusJob>>,
    results: Receiver<StatusReady>,
    workers: Vec<thread::JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    active: BTreeMap<u64, Vec<StatusEntry>>,
    busy: BTreeSet<u64>,
    routes: BTreeMap<u64, StatusRoute>,
    route_limit: usize,
    next_request_id: u64,
    pub metrics: StatusMetrics,
}

fn decode_status(response: &Value, job: &StatusJob) -> Result<Vec<Value>> {
    ensure!(
        response["jsonrpc"] == "2.0" && response["id"].as_u64() == Some(job.request_id),
        "pipelined status response ID/version mismatch"
    );
    if let Some(error) = response.get("error") {
        bail!("pipelined exact status RPC error: {error}");
    }
    let rows = response["result"]["value"]
        .as_array()
        .context("pipelined status response rows")?;
    ensure!(
        rows.len() == job.entries.len(),
        "pipelined status response length mismatch"
    );
    for row in rows {
        if row.is_null() {
            continue;
        }
        ensure!(
            row["slot"].as_u64().is_some() && row.get("err").is_some(),
            "pipelined status row missing slot/error"
        );
        let error = &row["err"];
        ensure!(
            error.is_null() || error.is_object() || error.is_string(),
            "pipelined status malformed transaction error"
        );
        ensure!(
            row["confirmationStatus"].is_null()
                || matches!(
                    row["confirmationStatus"].as_str(),
                    Some("processed" | "confirmed" | "finalized")
                ),
            "pipelined status malformed confirmation state"
        );
    }
    Ok(rows.clone())
}

pub(super) fn validate_route_limit(route_limit: usize) -> Result<()> {
    ensure!(
        (1..=super::MAX_OUTSTANDING).contains(&route_limit),
        "bounded pending status routing identities"
    );
    Ok(())
}

impl StatusPool {
    pub fn new(rpc: Rpc, urls: Vec<String>, route_limit: usize) -> Result<Self> {
        ensure!(!urls.is_empty(), "status pool requires validator endpoints");
        validate_route_limit(route_limit)?;
        let endpoint_count = urls.len();
        let urls = Arc::new(urls);
        let (jobs_tx, jobs_rx) = bounded::<StatusJob>(STATUS_JOB_BOUND);
        let (results_tx, results_rx) = bounded::<StatusReady>(STATUS_JOB_BOUND);
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::new();
        for _ in 0..STATUS_WORKERS {
            let rpc = rpc.clone();
            let urls = Arc::clone(&urls);
            let jobs = jobs_rx.clone();
            let results = results_tx.clone();
            let stopping = Arc::clone(&cancelled);
            workers.push(thread::spawn(move || {
                while let Ok(job) = jobs.recv() {
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let started = Instant::now();
                    let ids = job.entries.iter().map(|entry| &entry.signature).collect::<Vec<_>>();
                    let request = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":job.request_id,"method":"getSignatureStatuses","params":[ids,{"searchTransactionHistory":true}]}))
                        .expect("status request consists only of JSON identities");
                    let outcome = rpc.post_json_on_endpoints(
                        &urls, job.endpoint, &request, "getSignatureStatuses", Some(&stopping),
                    );
                    let result = outcome.value
                        .and_then(|response| decode_status(&response, &job))
                        .map_err(|error| format!("{error:#}"));
                    let milliseconds =
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    if results
                        .send(StatusReady {
                            request_id: job.request_id,
                            endpoint: outcome.last_endpoint,
                            requests_per_endpoint: outcome.requests_per_endpoint,
                            transient_errors: outcome.transient_errors,
                            entries: job.entries,
                            result,
                            milliseconds,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        Ok(Self {
            jobs: Some(jobs_tx),
            results: results_rx,
            workers,
            cancelled,
            active: BTreeMap::new(),
            busy: BTreeSet::new(),
            routes: BTreeMap::new(),
            route_limit,
            next_request_id: 1,
            metrics: StatusMetrics {
                requests_per_endpoint: vec![0; endpoint_count],
                ..StatusMetrics::default()
            },
        })
    }
    pub fn is_busy(&self, counter: u64) -> bool {
        self.busy.contains(&counter)
    }
    pub fn has_capacity(&self) -> bool {
        self.active.len() < STATUS_JOB_BOUND
    }
    pub fn schedule(&mut self, entries: Vec<StatusEntry>) -> Result<bool> {
        ensure!(
            !entries.is_empty() && entries.len() <= 256,
            "bounded pipelined status batch"
        );
        let mut unique = BTreeSet::new();
        ensure!(
            entries
                .iter()
                .all(|entry| !self.busy.contains(&entry.counter) && unique.insert(entry.counter)),
            "pipelined status counter already in flight or duplicated"
        );
        let mut new_routes = 0usize;
        for entry in &entries {
            if let Some(route) = self.routes.get(&entry.counter) {
                ensure!(
                    route.signature == entry.signature,
                    "status reroute changed counter/signature identity"
                );
            } else {
                new_routes = new_routes
                    .checked_add(1)
                    .context("status route count overflow")?;
            }
        }
        ensure!(
            new_routes <= self.route_limit.saturating_sub(self.routes.len()),
            "pending status routing identity bound exhausted"
        );
        if !self.has_capacity() {
            return Ok(false);
        }
        let request_id = self.next_request_id;
        let next = request_id
            .checked_add(1)
            .context("status request ID exhausted")?;
        let endpoint_count = self.metrics.requests_per_endpoint.len();
        // Rotate this batch relative to its first pending identity, not the
        // global request number: a polling pass can contain exactly as many
        // batches as endpoints. Record the route for every member so later
        // changes to batch membership still use that identity's actual route.
        let endpoint = match self.routes.get(&entries[0].counter) {
            Some(route) => route
                .endpoint
                .checked_add(1)
                .and_then(|next| next.checked_rem(endpoint_count))
                .context("status route endpoints disappeared")?,
            None => request_id
                .saturating_sub(1)
                .checked_rem(endpoint_count as u64)
                .context("status endpoints disappeared")? as usize,
        };
        match self
            .jobs
            .as_ref()
            .context("status pool stopped")?
            .try_send(StatusJob {
                request_id,
                endpoint,
                entries: entries.clone(),
            }) {
            Ok(()) => {
                self.next_request_id = next;
                for entry in &entries {
                    self.routes.insert(
                        entry.counter,
                        StatusRoute {
                            signature: entry.signature.clone(),
                            endpoint,
                        },
                    );
                }
                self.busy.extend(entries.iter().map(|entry| entry.counter));
                self.active.insert(request_id, entries);
                self.metrics.started = self.metrics.started.saturating_add(1);
                self.metrics.requested_ids = self
                    .metrics
                    .requested_ids
                    .saturating_add(u64::try_from(unique.len()).expect("bounded status batch"));
                self.metrics.minimum_batch_ids = Some(
                    self.metrics
                        .minimum_batch_ids
                        .map_or(unique.len(), |previous| previous.min(unique.len())),
                );
                self.metrics.maximum_batch_ids = self.metrics.maximum_batch_ids.max(unique.len());
                self.metrics.maximum_inflight_jobs =
                    self.metrics.maximum_inflight_jobs.max(self.active.len());
                self.metrics.maximum_inflight_ids =
                    self.metrics.maximum_inflight_ids.max(self.busy.len());
                Ok(true)
            }
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Disconnected(_)) => bail!("pipelined status workers disconnected"),
        }
    }
    /// Release only a finalized identity after central pending reconciliation.
    /// Null and merely confirmed responses retain their last endpoint for retry.
    pub fn retire_finalized(
        &mut self,
        entry: &StatusEntry,
        row: &Value,
        pending: &BTreeMap<u64, Pending>,
    ) -> Result<()> {
        let item = pending
            .get(&entry.counter)
            .context("finalized status route references absent pending identity")?;
        ensure!(
            item.admitted && item.id == entry.signature,
            "finalized status route references stale or unadmitted identity"
        );
        ensure!(
            row["confirmationStatus"] == "finalized"
                && row["slot"].as_u64().is_some()
                && row.get("err").is_some(),
            "status route cannot retire before finalization"
        );
        ensure!(
            !self.busy.contains(&entry.counter),
            "finalized status route still in flight"
        );
        let route = self
            .routes
            .get(&entry.counter)
            .context("finalized status route not tracked")?;
        ensure!(
            route.signature == entry.signature,
            "finalized status route changed counter/signature identity"
        );
        self.routes.remove(&entry.counter);
        Ok(())
    }
    pub fn drain(&mut self) -> Result<Vec<StatusObservation>> {
        let mut ready = Vec::new();
        loop {
            match self.results.try_recv() {
                Ok(result) => {
                    let entries = self
                        .active
                        .get(&result.request_id)
                        .context("unrequested/stale status batch response")?;
                    ensure!(
                        *entries == result.entries,
                        "status batch changed counter/signature identities"
                    );
                    ensure!(
                        result.endpoint < self.metrics.requests_per_endpoint.len()
                            && result.requests_per_endpoint.len()
                                == self.metrics.requests_per_endpoint.len(),
                        "status response changed endpoint route bounds"
                    );
                    for (total, attempts) in self
                        .metrics
                        .requests_per_endpoint
                        .iter_mut()
                        .zip(&result.requests_per_endpoint)
                    {
                        *total = total.saturating_add(*attempts);
                    }
                    self.metrics.transport_retry_errors = self
                        .metrics
                        .transport_retry_errors
                        .saturating_add(result.transient_errors);
                    for entry in entries {
                        let route = self
                            .routes
                            .get_mut(&entry.counter)
                            .context("status response route identity absent")?;
                        ensure!(
                            route.signature == entry.signature,
                            "status response changed route signature"
                        );
                        route.endpoint = result.endpoint;
                    }
                    let rows = match result.result {
                        Ok(rows) => rows,
                        Err(error) => {
                            // Keep exact pending/route/busy ownership on a
                            // terminal failure; callers fail closed and stop.
                            self.metrics.failed_jobs = self.metrics.failed_jobs.saturating_add(1);
                            bail!("status job {} failed: {error}", result.request_id);
                        }
                    };
                    if result.transient_errors > 0 {
                        self.metrics.transport_recovered_jobs =
                            self.metrics.transport_recovered_jobs.saturating_add(1);
                    }
                    let entries = self.active.remove(&result.request_id).unwrap();
                    for entry in &entries {
                        ensure!(
                            self.busy.remove(&entry.counter),
                            "status counter not reserved"
                        );
                    }
                    for row in &rows {
                        if row.is_null() {
                            self.metrics.null_rows = self.metrics.null_rows.saturating_add(1);
                        } else if row["confirmationStatus"] == "finalized" {
                            self.metrics.finalized_rows =
                                self.metrics.finalized_rows.saturating_add(1);
                        }
                    }
                    self.metrics.completed = self.metrics.completed.saturating_add(1);
                    self.metrics.rpc_milliseconds_total = self
                        .metrics
                        .rpc_milliseconds_total
                        .saturating_add(result.milliseconds);
                    self.metrics.rpc_milliseconds_max =
                        self.metrics.rpc_milliseconds_max.max(result.milliseconds);
                    ready.push(StatusObservation { entries, rows });
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    ensure!(
                        self.active.is_empty(),
                        "status workers disconnected with active batches"
                    );
                    break;
                }
            }
        }
        Ok(ready)
    }
    pub fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.jobs.take();
        let (_, closed) = bounded(0);
        self.results = closed;
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
impl Drop for StatusPool {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) struct AuditPool {
    jobs: Option<Sender<Value>>,
    results: Receiver<std::result::Result<Value, String>>,
    worker: Option<thread::JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    outstanding: usize,
}
impl AuditPool {
    pub fn new(snapshot: impl Fn(&AtomicBool) -> Result<Value> + Send + 'static) -> Self {
        let (jobs_tx, jobs_rx) = bounded::<Value>(1);
        let (results_tx, results_rx) = bounded(2);
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&cancelled);
        let worker = thread::spawn(move || {
            while let Ok(mut report) = jobs_rx.recv() {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let started = Instant::now();
                let result = snapshot(&stopping)
                    .map(|values| {
                        report["validators"] = values;
                        report["audit_completed_unix_ms"] = json!(wall_ms());
                        report["audit_seconds"] = json!(started.elapsed().as_secs_f64());
                        report
                    })
                    .map_err(|error| error.to_string());
                if results_tx.send(result).is_err() {
                    break;
                }
            }
        });
        Self {
            jobs: Some(jobs_tx),
            results: results_rx,
            worker: Some(worker),
            cancelled,
            outstanding: 0,
        }
    }
    pub fn schedule(&mut self, report: Value) -> Result<()> {
        ensure!(
            self.outstanding < 2,
            "bounded minute audit outstanding count"
        );
        self.jobs
            .as_ref()
            .context("audit pool stopped")?
            .try_send(report)
            .map_err(|error| anyhow!("bounded minute audit queue unavailable: {error}"))?;
        self.outstanding = self
            .outstanding
            .checked_add(1)
            .context("audit count overflow")?;
        ensure!(
            self.outstanding <= 2,
            "bounded minute audit outstanding count"
        );
        Ok(())
    }
    pub fn drain(&mut self) -> Result<Vec<Value>> {
        let mut ready = Vec::new();
        loop {
            match self.results.try_recv() {
                Ok(result) => {
                    self.outstanding = self
                        .outstanding
                        .checked_sub(1)
                        .context("unrequested minute audit")?;
                    ready.push(result.map_err(|error| anyhow!(error))?);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    ensure!(
                        self.outstanding == 0,
                        "minute auditor disconnected with pending observations"
                    );
                    break;
                }
            }
        }
        Ok(ready)
    }
    pub fn is_empty(&self) -> bool {
        self.outstanding == 0
    }
    pub fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.jobs.take();
        let (_, closed) = bounded(0);
        self.results = closed;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for AuditPool {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{
            io::{Read, Write},
            net::TcpListener,
        },
    };

    fn mock_status_server(
        count: usize,
        respond: impl Fn(Value) -> (Duration, Value) + Send + Sync + 'static,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let respond = Arc::new(respond);
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..count {
                let (mut socket, _) = listener.accept().unwrap();
                let respond = Arc::clone(&respond);
                requests.push(thread::spawn(move || {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let header_end = loop {
                        let mut b = [0u8; 1];
                        socket.read_exact(&mut b).unwrap();
                        bytes.extend_from_slice(&b);
                        if bytes.ends_with(b"\r\n\r\n") {
                            break bytes.len();
                        }
                    };
                    let headers = std::str::from_utf8(&bytes).unwrap();
                    let len = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|n| n.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    bytes.resize(header_end.checked_add(len).unwrap(), 0);
                    socket.read_exact(&mut bytes[header_end..]).unwrap();
                    let request = serde_json::from_slice(&bytes[header_end..]).unwrap();
                    let (delay, response) = respond(request);
                    thread::sleep(delay);
                    let body = response.to_string();
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                         {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                    socket.flush().unwrap();
                }));
            }
            for request in requests {
                request.join().unwrap();
            }
        });
        (url, handle)
    }

    fn entry(counter: u64) -> StatusEntry {
        StatusEntry {
            counter,
            signature: format!("exact-signature-{counter}"),
        }
    }
    fn finalized(error: Value) -> Value {
        json!({"slot":7,"err":error,"confirmationStatus":"finalized"})
    }

    #[test]
    fn delayed_status_batches_allow_progress_and_out_of_order_completion_preserves_ids() {
        let (url, server) = mock_status_server(2, |request| {
            let first = request["params"][0][0] == "exact-signature-0";
            (
                Duration::from_millis(if first { 160 } else { 5 }),
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"value":[finalized(if first {Value::Null}else {json!({"InstructionError":[1,{"Custom":7005}]})})]}}),
            )
        });
        let mut pool = StatusPool::new(Rpc::new().unwrap(), vec![url], 2).unwrap();
        assert!(pool.schedule(vec![entry(0)]).unwrap());
        assert!(pool.schedule(vec![entry(1)]).unwrap());
        assert!(pool.schedule(vec![entry(0)]).is_err());
        let started = Instant::now();
        let mut ticks = 0;
        let mut observations = Vec::new();
        while observations.len() < 2 {
            ticks += 1;
            observations.extend(pool.drain().unwrap());
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(1));
        }
        assert!(ticks > 40, "main-loop progress stopped while RPC awaited");
        assert_eq!(observations[0].entries, vec![entry(1)]);
        assert_eq!(observations[1].entries, vec![entry(0)]);
        assert_eq!(
            observations[0].rows[0]["err"],
            json!({"InstructionError":[1,{"Custom":7005}]})
        );
        assert!(observations[1].rows[0]["err"].is_null());
        assert_eq!(pool.metrics.completed, 2);
        assert_eq!(pool.metrics.maximum_inflight_jobs, 2);
        assert!(!pool.is_busy(0));
        pool.stop();
        assert!(pool.workers.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn malformed_status_ids_lengths_fields_and_rpc_errors_fail_closed() {
        for case in 0..4 {
            let (url, server) = mock_status_server(1, move |request| {
                let response = match case {
                    0 => {
                        json!({"jsonrpc":"2.0","id":999,"result":{"value":[finalized(Value::Null)]}})
                    }
                    1 => json!({"jsonrpc":"2.0","id":request["id"],"result":{"value":[]}}),
                    2 => {
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{"value":[{"slot":7,"confirmationStatus":"finalized"}]}})
                    }
                    _ => {
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-1,"message":"failed native lookup"}})
                    }
                };
                (Duration::ZERO, response)
            });
            let mut pool = StatusPool::new(Rpc::new().unwrap(), vec![url], 1).unwrap();
            pool.schedule(vec![entry(0)]).unwrap();
            let started = Instant::now();
            loop {
                match pool.drain() {
                    Ok(rows) => assert!(rows.is_empty()),
                    Err(_) => break,
                };
                assert!(started.elapsed() < Duration::from_secs(2));
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(pool.metrics.completed, 0);
            assert!(pool.is_busy(0), "hard failure lost pending reservation");
            assert_eq!(pool.routes.len(), 1);
            pool.stop();
            assert!(pool.workers.is_empty());
            server.join().unwrap();
        }
    }

    #[test]
    fn transient_timeout_and_http503_reroute_same_status_job_without_losing_pending() {
        use transport::testing::{Reply, json_reply, mock, rpc};
        let servers = [
            mock(vec![Reply::Http {
                code: 200,
                body: serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":1,"result":{"value":[finalized(Value::Null)]}}),
                )
                .unwrap(),
                delay: Duration::from_millis(100),
            }]),
            mock(vec![json_reply(503, json!({}))]),
            mock(vec![json_reply(
                200,
                json!({"jsonrpc":"2.0","id":1,"result":{"value":[finalized(json!({"InstructionError":[0,{"Custom":7005}]}))]}}),
            )]),
        ];
        let urls = servers.iter().map(|server| server.url.clone()).collect();
        let mut pool = StatusPool::new(
            rpc(Duration::from_millis(30), Duration::from_millis(200)),
            urls,
            1,
        )
        .unwrap();
        let pending = BTreeMap::from([(
            0,
            Pending {
                id: entry(0).signature,
                started: Instant::now(),
                admitted: true,
                recipient: 0,
                kind: Kind::NonceOnly,
            },
        )]);
        assert!(pool.schedule(vec![entry(0)]).unwrap());
        let started = Instant::now();
        let observation = loop {
            assert!(pool.is_busy(0));
            assert!(pool.schedule(vec![entry(0)]).is_err());
            let mut rows = pool.drain().unwrap();
            if let Some(row) = rows.pop() {
                break row;
            }
            assert!(started.elapsed() < Duration::from_secs(1));
            thread::sleep(Duration::from_millis(1));
        };
        observation.validate_pending(&pending).unwrap();
        assert_eq!(observation.entries, vec![entry(0)]);
        assert_eq!(
            observation.rows[0]["err"],
            json!({"InstructionError":[0,{"Custom":7005}]})
        );
        assert!(!pool.is_busy(0));
        assert_eq!(pool.routes[&0].endpoint, 2);
        assert_eq!(pool.metrics.requests_per_endpoint, [1, 1, 1]);
        assert_eq!(pool.metrics.transport_retry_errors, 2);
        assert_eq!(pool.metrics.transport_recovered_jobs, 1);
        assert_eq!(pool.metrics.completed, 1);
        let bodies = servers
            .iter()
            .map(|server| server.requests.lock().unwrap()[0].clone())
            .collect::<Vec<_>>();
        assert!(bodies.iter().all(|body| body == &bodies[0]));
        pool.retire_finalized(&entry(0), &observation.rows[0], &pending)
            .unwrap();
        assert!(pool.routes.is_empty());
        pool.stop();

        let server = mock(vec![json_reply(503, json!({}))]);
        let mut client = rpc(Duration::from_millis(30), Duration::from_secs(1));
        client.retry_policy.backoff = Duration::from_millis(300);
        let mut stopping = StatusPool::new(client, vec![server.url.clone()], 1).unwrap();
        assert!(stopping.schedule(vec![entry(0)]).unwrap());
        let waiting = Instant::now();
        while server.requests.lock().unwrap().is_empty() {
            assert!(waiting.elapsed() < Duration::from_secs(1));
            thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        stopping.stop();
        assert!(started.elapsed() < Duration::from_millis(150));
        assert!(stopping.workers.is_empty());
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn lagging_validator_null_retries_another_endpoint_with_exact_pending_identity() {
        let servers = [false, true].map(|rooted| {
            mock_status_server(1, move |request| {
                assert_eq!(request["params"][0][0], "exact-signature-0");
                (
                    Duration::ZERO,
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"value":[
                        if rooted { finalized(Value::Null) } else { Value::Null }
                    ]}}),
                )
            })
        });
        let urls = servers.iter().map(|(url, _)| url.clone()).collect();
        let mut pool = StatusPool::new(Rpc::new().unwrap(), urls, 1).unwrap();
        let mut pending = BTreeMap::from([(
            0,
            Pending {
                id: entry(0).signature,
                started: Instant::now(),
                admitted: true,
                recipient: 0,
                kind: Kind::NonceOnly,
            },
        )]);
        for rooted in [false, true] {
            assert!(pool.schedule(vec![entry(0)]).unwrap());
            let started = Instant::now();
            let observation = loop {
                let mut rows = pool.drain().unwrap();
                if let Some(row) = rows.pop() {
                    assert!(rows.is_empty());
                    break row;
                }
                assert!(started.elapsed() < Duration::from_secs(2));
                thread::sleep(Duration::from_millis(1));
            };
            observation.validate_pending(&pending).unwrap();
            assert_eq!(observation.entries, vec![entry(0)]);
            assert_eq!(observation.rows[0].is_null(), !rooted);
            assert!(!pool.is_busy(0));
            assert_eq!(pool.routes.len(), 1);
            if rooted {
                assert_eq!(observation.rows[0]["confirmationStatus"], "finalized");
                pending.get_mut(&0).unwrap().id = "reused-counter-different-intent".into();
                assert!(observation.validate_pending(&pending).is_err());
                assert!(
                    pool.retire_finalized(&entry(0), &observation.rows[0], &pending)
                        .is_err()
                );
                pending.get_mut(&0).unwrap().id = entry(0).signature;
                pool.retire_finalized(&entry(0), &observation.rows[0], &pending)
                    .unwrap();
                assert!(pool.routes.is_empty());
            } else {
                assert!(pool.schedule(vec![entry(1)]).is_err());
                assert!(
                    pool.schedule(vec![StatusEntry {
                        counter: 0,
                        signature: "counter-reused-before-finalization".into(),
                    }])
                    .is_err()
                );
                assert!(
                    pool.retire_finalized(&entry(0), &Value::Null, &pending)
                        .is_err()
                );
                assert!(
                    pool.retire_finalized(
                        &entry(0),
                        &json!({"slot":7,"err":null,"confirmationStatus":"confirmed"}),
                        &pending,
                    )
                    .is_err()
                );
                assert_eq!(pool.routes[&0].endpoint, 0);
            }
        }
        assert_eq!(pool.metrics.requests_per_endpoint, [1, 1]);
        pool.stop();
        for (_, server) in servers {
            server.join().unwrap();
        }
        assert!(StatusPool::new(Rpc::new().unwrap(), Vec::new(), 1).is_err());
        for limit in [0, soak::MAX_OUTSTANDING + 1] {
            assert!(StatusPool::new(Rpc::new().unwrap(), vec!["unused".into()], limit).is_err());
        }
    }

    #[test]
    fn eight_full_null_batches_cycle_each_identity_across_all_eight_endpoints() {
        const ENDPOINTS: usize = 8;
        const IDS: usize = ENDPOINTS * 256;
        // Nine passes: eight null responses visit every endpoint; the last
        // finalizes successes and charged failures, releasing all route state.
        let routes = Arc::new(Mutex::new(BTreeMap::<String, Vec<usize>>::new()));
        let servers = (0..ENDPOINTS)
            .map(|endpoint| {
                let routes = Arc::clone(&routes);
                mock_status_server(ENDPOINTS + 1, move |request| {
                    let ids = request["params"][0].as_array().unwrap();
                    assert_eq!(ids.len(), 256);
                    let mut routes = routes.lock().unwrap();
                    let rows = ids
                        .iter()
                        .map(|id| {
                            let id = id.as_str().unwrap();
                            let history = routes.entry(id.into()).or_default();
                            history.push(endpoint);
                            if history.len() <= ENDPOINTS {
                                Value::Null
                            } else {
                                finalized(if id.ends_with("-0") {
                                    json!({"InstructionError":[0,{"Custom":7005}]})
                                } else {
                                    Value::Null
                                })
                            }
                        })
                        .collect::<Vec<_>>();
                    (
                        Duration::ZERO,
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{"value":rows}}),
                    )
                })
            })
            .collect::<Vec<_>>();
        let urls = servers.iter().map(|(url, _)| url.clone()).collect();
        let mut pool = StatusPool::new(Rpc::new().unwrap(), urls, IDS).unwrap();
        let mut pending = (0..IDS as u64)
            .map(|counter| {
                (
                    counter,
                    Pending {
                        id: entry(counter).signature,
                        started: Instant::now(),
                        admitted: true,
                        recipient: 0,
                        kind: Kind::NonceOnly,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for pass in 0..=ENDPOINTS {
            for batch in 0..ENDPOINTS as u64 {
                let start = batch * 256;
                assert!(
                    pool.schedule((start..start + 256).map(entry).collect())
                        .unwrap()
                );
            }
            let started = Instant::now();
            let mut observed = 0;
            while observed < IDS {
                for observation in pool.drain().unwrap() {
                    observation.validate_pending(&pending).unwrap();
                    observed += observation.entries.len();
                    for (entry, row) in observation.entries.iter().zip(&observation.rows) {
                        if pass < ENDPOINTS {
                            assert!(row.is_null());
                        } else {
                            assert_eq!(row["confirmationStatus"], "finalized");
                            pool.retire_finalized(entry, row, &pending).unwrap();
                            pending.remove(&entry.counter).unwrap();
                        }
                    }
                }
                assert!(started.elapsed() < Duration::from_secs(5));
                thread::sleep(Duration::from_millis(1));
            }
            assert!(pool.active.is_empty());
            assert!(pool.busy.is_empty());
            assert_eq!(pool.routes.len(), if pass < ENDPOINTS { IDS } else { 0 });
        }
        assert!(pending.is_empty());
        assert_eq!(pool.metrics.requests_per_endpoint, vec![9; ENDPOINTS]);
        let routes = routes.lock().unwrap();
        assert_eq!(routes.len(), IDS);
        for history in routes.values() {
            assert_eq!(history.len(), ENDPOINTS + 1);
            assert_eq!(
                history[..ENDPOINTS]
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                (0..ENDPOINTS).collect::<BTreeSet<_>>()
            );
            assert!(history.windows(2).all(|pair| pair[0] != pair[1]));
        }
        pool.stop();
        for (_, server) in servers {
            server.join().unwrap();
        }
    }

    #[test]
    fn fixed_poll_cycles_revisit_old_null_statuses_despite_continuous_new_arrivals() {
        let item = |counter| Pending {
            id: entry(counter).signature,
            started: Instant::now(),
            admitted: counter != 2,
            recipient: 0,
            kind: Kind::NonceOnly,
        };
        let mut pending = (0..512)
            .map(|counter| (counter, item(counter)))
            .collect::<BTreeMap<_, _>>();
        let mut legacy_pending = (0..512).collect::<BTreeSet<u64>>();
        let mut legacy_cursor = 0;
        let mut fair = FairStatusCursor::default();
        let mut next = 512;
        let mut root_observed = BTreeMap::new();
        let mut old_null_polls = 0;
        for turn in 0..40 {
            // At least one whole batch arrives before every scan; a cursor
            // that only wraps after exhausting the moving tail never returns.
            for counter in next..next + 256 {
                pending.insert(counter, item(counter));
                legacy_pending.insert(counter);
            }
            next += 256;
            if turn == 5 {
                pending.get_mut(&2).unwrap().admitted = true;
            }
            let legacy = legacy_pending
                .range(legacy_cursor..)
                .take(256)
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(legacy.len(), 256);
            legacy_cursor = legacy.last().unwrap() + 1;
            for counter in legacy {
                if counter != 0 {
                    legacy_pending.remove(&counter);
                }
            }
            let batch = fair.select(&pending, |counter, row| {
                row.admitted && (*counter != 1 || turn >= 6)
            });
            assert!(!batch.counters.is_empty());
            assert!(batch.counters.len() <= 256);
            assert!(
                !batch.counters.contains(&1) || turn >= 6,
                "identity with an active request was scheduled twice"
            );
            fair.dispatched(&batch).unwrap();
            for counter in batch.counters {
                if counter == 0 && turn < 3 {
                    old_null_polls += 1;
                    continue;
                }
                if counter <= 2 {
                    root_observed.insert(counter, turn);
                }
                pending.remove(&counter);
            }
            assert!(pending.len() < 16_384);
        }
        assert!(old_null_polls > 0);
        assert!(root_observed[&0] <= 6, "old rooted identity was starved");
        assert!(
            root_observed[&1] <= 12,
            "formerly busy identity was starved"
        );
        assert!(
            root_observed[&2] <= 12,
            "newly admitted identity was starved"
        );
        assert!(
            legacy_pending.contains(&0),
            "legacy control did not reproduce starvation"
        );
    }

    #[test]
    fn stale_reused_counter_and_unadmitted_identity_never_reconcile() {
        let mut pending = BTreeMap::from([(
            0,
            Pending {
                id: "new-signature".into(),
                started: Instant::now(),
                admitted: true,
                recipient: 0,
                kind: Kind::NonceOnly,
            },
        )]);
        let old = StatusObservation {
            entries: vec![entry(0)],
            rows: vec![finalized(Value::Null)],
        };
        assert!(old.validate_pending(&pending).is_err());
        let item = pending.get_mut(&0).unwrap();
        item.id = entry(0).signature;
        item.admitted = false;
        assert!(old.validate_pending(&pending).is_err());
        pending.get_mut(&0).unwrap().admitted = true;
        assert!(old.validate_pending(&pending).is_ok());
        pending.clear();
        assert!(old.validate_pending(&pending).is_err());
    }

    #[test]
    fn bounded_minute_audit_does_not_pause_progress_and_joins_on_failure() {
        let mut pool = AuditPool::new(|_| {
            thread::sleep(Duration::from_millis(100));
            bail!("mock failed all-node account audit")
        });
        pool.schedule(json!({"minute":1})).unwrap();
        let started = Instant::now();
        let mut ticks = 0;
        loop {
            ticks += 1;
            match pool.drain() {
                Ok(rows) => assert!(rows.is_empty()),
                Err(error) => {
                    assert!(error.to_string().contains("mock failed"));
                    break;
                }
            };
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(1));
        }
        assert!(ticks > 40);
        pool.stop();
        assert!(pool.worker.is_none());
    }
}
