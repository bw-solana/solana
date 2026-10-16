//! Finite transport retries for immutable benchmark RPC request bytes.
use {super::*, std::sync::atomic::AtomicU64};

#[derive(Clone)]
pub(super) struct RetryPolicy {
    pub attempt_timeout: Duration,
    pub budget: Duration,
    pub attempts: usize,
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(5),
            budget: Duration::from_secs(20),
            attempts: 8,
            backoff: Duration::from_millis(50),
        }
    }
}

#[derive(Default)]
pub(super) struct RetryMetrics {
    requests: AtomicU64,
    attempts: AtomicU64,
    transient_errors: AtomicU64,
    recovered_requests: AtomicU64,
    failed_requests: AtomicU64,
}

pub(super) struct HttpOutcome {
    pub value: Result<Value>,
    pub requests_per_endpoint: Vec<u64>,
    pub transient_errors: u64,
    pub last_endpoint: usize,
}

pub(super) fn is_transient(error: &anyhow::Error) -> bool {
    let Some(error) = error.downcast_ref::<reqwest::Error>() else {
        return false;
    };
    if let Some(status) = error.status() {
        return matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504);
    }
    if error.is_builder() || error.is_decode() || error.is_redirect() {
        return false;
    }
    // Sending/receiving valid HTTP bytes can fail after the server accepts a
    // request. Certificate and malformed HTTP protocol errors are permanent.
    let details = format!("{error:?}").to_ascii_lowercase();
    if [
        "certificate",
        "unknownissuer",
        "invalidheader",
        "invaliduri",
        "invalidurl",
        "parseerror",
    ]
    .iter()
    .any(|permanent| details.contains(permanent))
    {
        return false;
    }
    error.is_timeout() || error.is_connect() || error.is_body() || error.is_request()
}

fn retry_pause(
    duration: Duration,
    started: Instant,
    budget: Duration,
    cancelled: Option<&AtomicBool>,
) {
    let pause_started = Instant::now();
    while pause_started.elapsed() < duration && started.elapsed() < budget {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            break;
        }
        let remaining = duration
            .saturating_sub(pause_started.elapsed())
            .min(budget.saturating_sub(started.elapsed()));
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

impl Rpc {
    pub(super) fn post_json_retry(
        &self,
        url: &str,
        body: &[u8],
        label: &str,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Value> {
        self.post_json_on_endpoints(&[url.to_owned()], 0, body, label, cancelled)
            .value
    }

    pub(super) fn post_json_retry_until(
        &self,
        url: &str,
        body: &[u8],
        label: &str,
        cancelled: Option<&AtomicBool>,
        deadline: Instant,
    ) -> Result<Value> {
        self.post_json_on_endpoints_until(&[url.to_owned()], 0, body, label, cancelled, deadline)
            .value
    }

    pub(super) fn post_json_on_endpoints(
        &self,
        urls: &[String],
        first_endpoint: usize,
        body: &[u8],
        label: &str,
        cancelled: Option<&AtomicBool>,
    ) -> HttpOutcome {
        let deadline = Instant::now()
            .checked_add(self.retry_policy.budget)
            .expect("bounded trusted RPC retry budget");
        self.post_json_on_endpoints_until(urls, first_endpoint, body, label, cancelled, deadline)
    }

    fn post_json_on_endpoints_until(
        &self,
        urls: &[String],
        first_endpoint: usize,
        body: &[u8],
        label: &str,
        cancelled: Option<&AtomicBool>,
        deadline: Instant,
    ) -> HttpOutcome {
        let mut outcome = HttpOutcome {
            value: Err(anyhow!("{label}: RPC retry attempts exhausted")),
            requests_per_endpoint: vec![0; urls.len()],
            transient_errors: 0,
            last_endpoint: first_endpoint,
        };
        self.retry_metrics.requests.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let budget = self
            .retry_policy
            .budget
            .min(deadline.saturating_duration_since(started));
        for attempt in 0..self.retry_policy.attempts {
            if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                outcome.value = Err(anyhow!("{label}: RPC observer cancelled"));
                break;
            }
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let Some(endpoint) = first_endpoint
                .checked_add(attempt)
                .and_then(|index| index.checked_rem(urls.len()))
            else {
                outcome.value = Err(anyhow!("{label}: RPC endpoint bounds"));
                break;
            };
            outcome.last_endpoint = endpoint;
            outcome.requests_per_endpoint[endpoint] =
                outcome.requests_per_endpoint[endpoint].saturating_add(1);
            self.retry_metrics.attempts.fetch_add(1, Ordering::Relaxed);
            let request = (|| -> Result<Value> {
                let parsed_url = reqwest::Url::parse(&urls[endpoint])?;
                ensure!(
                    matches!(parsed_url.scheme(), "http" | "https"),
                    "{label}: unsupported RPC URL scheme"
                );
                let mut request = self
                    .client
                    .post(parsed_url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.to_vec())
                    .timeout(self.retry_policy.attempt_timeout.min(remaining));
                if attempt > 0 {
                    request = request.header(reqwest::header::CONNECTION, "close");
                }
                // Read the body before decoding so incomplete HTTP transport
                // is retryable, while syntactically invalid JSON is permanent.
                let bytes = request.send()?.error_for_status()?.bytes()?;
                Ok(serde_json::from_slice(&bytes)?)
            })();
            match request {
                Ok(value) => {
                    if outcome.transient_errors > 0 {
                        self.retry_metrics
                            .recovered_requests
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    outcome.value = Ok(value);
                    return outcome;
                }
                Err(error) => {
                    let retryable = is_transient(&error);
                    outcome.value = Err(error.context(format!(
                        "{label}: endpoint {} attempt {} transport request failed",
                        urls[endpoint],
                        attempt.saturating_add(1)
                    )));
                    if !retryable {
                        break;
                    }
                    outcome.transient_errors = outcome.transient_errors.saturating_add(1);
                    self.retry_metrics
                        .transient_errors
                        .fetch_add(1, Ordering::Relaxed);
                    if attempt.saturating_add(1) < self.retry_policy.attempts {
                        retry_pause(self.retry_policy.backoff, started, budget, cancelled);
                    }
                }
            }
        }
        self.retry_metrics
            .failed_requests
            .fetch_add(1, Ordering::Relaxed);
        let attempts = outcome.requests_per_endpoint.iter().copied().sum::<u64>();
        outcome.value = outcome.value.map_err(|error| {
            let reason = format!("{error:#}");
            error.context(format!(
                "{label}: RPC failed after {attempts} attempts in {:.3}s: {reason}",
                started.elapsed().as_secs_f64()
            ))
        });
        outcome
    }

    pub(super) fn retry_statistics(&self) -> Value {
        json!({
            "requests":self.retry_metrics.requests.load(Ordering::Relaxed),
            "attempts":self.retry_metrics.attempts.load(Ordering::Relaxed),
            "transient_errors":self.retry_metrics.transient_errors.load(Ordering::Relaxed),
            "recovered_requests":self.retry_metrics.recovered_requests.load(Ordering::Relaxed),
            "failed_requests":self.retry_metrics.failed_requests.load(Ordering::Relaxed),
            "maximum_attempts":self.retry_policy.attempts,
            "total_budget_ms":self.retry_policy.budget.as_millis(),
            "attempt_timeout_ms":self.retry_policy.attempt_timeout.as_millis(),
            "backoff_ms":self.retry_policy.backoff.as_millis(),
        })
    }
}

#[cfg(test)]
pub(super) mod testing {
    use {
        super::*,
        std::{
            io::{Read, Write},
            net::TcpListener,
        },
    };

    pub enum Reply {
        Disconnect,
        Http {
            code: u16,
            body: Vec<u8>,
            delay: Duration,
        },
    }

    pub fn json_reply(code: u16, value: Value) -> Reply {
        Reply::Http {
            code,
            body: serde_json::to_vec(&value).unwrap(),
            delay: Duration::ZERO,
        }
    }

    pub struct Mock {
        pub url: String,
        pub requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.worker.take().unwrap().join().unwrap();
        }
    }

    pub fn mock(replies: Vec<Reply>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
            for reply in replies {
                let (mut socket, _) = loop {
                    if stopping.load(Ordering::Acquire) {
                        for worker in workers {
                            worker.join().unwrap();
                        }
                        return;
                    }
                    match listener.accept() {
                        Ok(socket) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                started.elapsed() < Duration::from_secs(3),
                                "RPC test mock never received expected request"
                            );
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("RPC test listener: {error}"),
                    }
                };
                let recorded = Arc::clone(&recorded);
                workers.push(thread::spawn(move || {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    while !bytes.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        socket.read_exact(&mut byte).unwrap();
                        bytes.extend(byte);
                    }
                    let header = std::str::from_utf8(&bytes).unwrap();
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).unwrap();
                    recorded.lock().unwrap().push(body);
                    if let Reply::Http { code, body, delay } = reply {
                        thread::sleep(delay);
                        let _ = write!(
                            socket,
                            "HTTP/1.1 {code} Test\r\nContent-Type: \
                             application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(&body);
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Mock {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    pub fn rpc(timeout: Duration, budget: Duration) -> Rpc {
        let mut rpc = Rpc::new().unwrap();
        rpc.retry_policy = RetryPolicy {
            attempt_timeout: timeout,
            budget,
            attempts: 8,
            backoff: Duration::from_millis(1),
        };
        rpc
    }
}

#[cfg(test)]
mod tests {
    use {super::*, testing::*};

    #[test]
    fn disconnected_and_http503_read_retries_preserve_exact_serialized_request() {
        let server = mock(vec![
            Reply::Disconnect,
            json_reply(503, json!({})),
            json_reply(200, json!({"jsonrpc":"2.0","id":1,"result":{"slot":7}})),
        ]);
        let rpc = rpc(Duration::from_millis(100), Duration::from_secs(1));
        assert_eq!(
            rpc.call(&server.url, "getExperimentalPqStatus", json!([]))
                .unwrap(),
            json!({"slot":7})
        );
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|request| request == &requests[0]));
        assert_eq!(rpc.retry_statistics()["transient_errors"], 2);
        assert_eq!(rpc.retry_statistics()["recovered_requests"], 1);
    }

    #[test]
    fn timeout_retries_share_one_deadline_and_keep_same_body() {
        let server = mock(
            (0..8)
                .map(|_| Reply::Http {
                    code: 200,
                    body: b"{}".to_vec(),
                    delay: Duration::from_millis(120),
                })
                .collect(),
        );
        let rpc = rpc(Duration::from_millis(30), Duration::from_millis(75));
        let started = Instant::now();
        let error = rpc
            .call(&server.url, "getLatestBlockhash", json!([]))
            .unwrap_err();
        assert!(is_transient(&error));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(
            error
                .to_string()
                .contains("getLatestBlockhash: RPC failed after")
        );
        let requests = server.requests.lock().unwrap();
        assert!((1..=3).contains(&requests.len()));
        assert!(requests.iter().all(|request| request == &requests[0]));
        assert_eq!(rpc.retry_statistics()["recovered_requests"], 0);
    }

    #[test]
    fn malformed_identity_protocol_and_semantic_failures_are_never_retried() {
        let replies = [
            json_reply(200, json!({"jsonrpc":"2.0","id":2,"result":7})),
            json_reply(200, json!({"jsonrpc":"1.0","id":1,"result":7})),
            json_reply(
                200,
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"wrong chain or signature"}}),
            ),
            Reply::Http {
                code: 200,
                body: b"invalid json".to_vec(),
                delay: Duration::ZERO,
            },
            json_reply(400, json!({"error":"permanent invalid request"})),
        ];
        for reply in replies {
            let server = mock(vec![reply]);
            let rpc = rpc(Duration::from_millis(100), Duration::from_millis(300));
            let error = rpc
                .call(&server.url, "getExperimentalPqStatus", json!([]))
                .unwrap_err();
            assert!(!is_transient(&error));
            assert_eq!(server.requests.lock().unwrap().len(), 1);
            assert_eq!(rpc.retry_statistics()["attempts"], 1);
        }
        let rpc = rpc(Duration::from_millis(100), Duration::from_millis(300));
        assert!(
            rpc.call("not-a-valid-url", "getExperimentalPqStatus", json!([]))
                .is_err()
        );
        assert_eq!(rpc.retry_statistics()["attempts"], 1);
    }

    #[test]
    fn retry_cancellation_interrupts_backoff_and_does_not_accept_a_response() {
        let server = mock(vec![json_reply(503, json!({}))]);
        let mut rpc = rpc(Duration::from_millis(30), Duration::from_secs(1));
        rpc.retry_policy.backoff = Duration::from_millis(300);
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&cancelled);
        let cancel = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            cancellation.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let result = rpc.post_json_retry(&server.url, b"{}", "test cancellation", Some(&cancelled));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(150));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
        cancel.join().unwrap();
    }
}
