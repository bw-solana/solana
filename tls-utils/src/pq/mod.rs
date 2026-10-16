//! Native post-quantum QUIC transport used by the experimental Agave validator.
//!
//! These endpoints run Quinn/rustls over UDP. TLS CertificateVerify uses Falcon,
//! key exchange uses ML-KEM-768, and authenticated traffic uses AES-256-GCM and
//! HKDF-SHA384. RFC 9001's publicly derivable Initial packet protection remains
//! AES-128-GCM/SHA256; Initial packets never establish peer authority.

mod tls;
mod trace;

pub use trace::{PqBlockTrace, PqTraceConfig, PqTraceLandmark};
use {
    self::trace::{BlockTracer, FrameTrace, Stage},
    agave_pq_crypto::crypto::{FalconKeypair, FalconPublicKey},
    crossbeam_channel::{Receiver, RecvError, RecvTimeoutError, TryRecvError},
    quinn::{
        ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt,
        crypto::rustls::{QuicClientConfig, QuicServerConfig},
    },
    rustls::pki_types::CertificateDer,
    solana_pubkey::Pubkey,
    std::{
        collections::{BTreeMap, BTreeSet},
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    },
    tokio::{io::AsyncReadExt, sync::mpsc},
};

pub const MAX_PQ_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PQ_QUEUE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PQ_QUEUE_RECORDS: usize = 4096;
const RESERVED_CONTROL_RECORDS: usize = 128;
// Preserve control priority while guaranteeing progress for authenticated bodies.
const MAX_INCOMING_CONTROL_BURST: usize = 8;
const RESERVED_CONTROL_BYTES: usize = 512 * 1024;
const STREAM_PREFACE: &[u8; 8] = b"PQSTRM02";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
enum TrafficClass {
    Bulk = 0,
    Control = 1,
}

#[derive(Default)]
struct QueueBudget {
    bytes: AtomicUsize,
    records: AtomicUsize,
}

impl QueueBudget {
    fn reserve(&self, bytes: usize, class: TrafficClass) -> bool {
        let (byte_limit, record_limit) = match class {
            TrafficClass::Bulk => (
                MAX_PQ_QUEUE_BYTES - RESERVED_CONTROL_BYTES,
                MAX_PQ_QUEUE_RECORDS - RESERVED_CONTROL_RECORDS,
            ),
            TrafficClass::Control => (MAX_PQ_QUEUE_BYTES, MAX_PQ_QUEUE_RECORDS),
        };
        if !reserve_limit(&self.bytes, bytes, byte_limit) {
            return false;
        }
        if !reserve_limit(&self.records, 1, record_limit) {
            self.bytes.fetch_sub(bytes, Ordering::AcqRel);
            return false;
        }
        true
    }
}

pub struct PqQuicConfig {
    /// The trusted PQ signature domain from the genesis accounts. The actual
    /// Agave genesis hash is pinned separately at validator startup.
    pub chain: [u8; 32],
    pub identity: Pubkey,
    pub signer: Arc<FalconKeypair>,
    /// Independently trusted identity-to-PQ-key bindings; never learned from TLS.
    pub registry: BTreeMap<Pubkey, FalconPublicKey>,
    pub peers: BTreeMap<Pubkey, SocketAddr>,
    pub listen: SocketAddr,
}

impl PqQuicConfig {
    /// Build an actual Quinn server configuration with mutual Falcon TLS
    /// authentication. Useful when another Agave service owns the endpoint.
    pub fn server_config(&self) -> Result<ServerConfig, PqQuicError> {
        self.validate()?;
        native_server_config(self)
    }

    /// The expected server identity is pinned separately for every destination.
    pub fn client_config(&self, expected: Pubkey) -> Result<ClientConfig, PqQuicError> {
        self.validate()?;
        if !self.registry.contains_key(&expected) {
            return Err(PqQuicError::UnknownPeer(expected));
        }
        client_config(self, expected)
    }

    fn validate(&self) -> Result<(), PqQuicError> {
        if self.registry.get(&self.identity) != Some(&self.signer.public_key()) {
            return Err(PqQuicError::Configuration(
                "local Falcon credential does not match trusted registry".into(),
            ));
        }
        if self.peers.len() > 256 || self.registry.len() > 4096 {
            return Err(PqQuicError::Configuration(
                "peer/credential registry exceeds experimental limits".into(),
            ));
        }
        if self
            .peers
            .keys()
            .any(|peer| *peer == self.identity || !self.registry.contains_key(peer))
        {
            return Err(PqQuicError::Configuration(
                "outbound peers must be distinct registered identities".into(),
            ));
        }
        let mut public_keys = BTreeSet::new();
        if self
            .registry
            .values()
            .any(|key| !public_keys.insert(key.as_bytes()))
        {
            return Err(PqQuicError::Configuration(
                "each registered identity must use a distinct Falcon credential".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PqQuicError {
    #[error("invalid PQ transport configuration: {0}")]
    Configuration(String),
    #[error("PQ QUIC transport failed: {0}")]
    Transport(String),
    #[error("PQ QUIC frame length must be 1..={MAX_PQ_FRAME_BYTES}")]
    FrameSize,
    #[error("PQ QUIC peer is not configured: {0}")]
    UnknownPeer(Pubkey),
    #[error("PQ QUIC queue is full for {0}; caller must retain and retry the frame")]
    QueueFull(Pubkey),
    #[error("PQ QUIC transport is closed")]
    Closed,
}

#[derive(Default)]
pub struct PqQuicStats {
    pub sent_frames: AtomicU64,
    pub received_frames: AtomicU64,
    pub sent_bytes: AtomicU64,
    pub received_bytes: AtomicU64,
    pub rejected_handshakes: AtomicU64,
    pub reconnects: AtomicU64,
    pub queue_full: AtomicU64,
    pub sent_control_frames: AtomicU64,
    pub sent_bulk_frames: AtomicU64,
    pub control_queue_wait_us: AtomicU64,
    pub maximum_control_queue_wait_us: AtomicU64,
    pub inbound_budget_wait_frames: AtomicU64,
    pub inbound_budget_wait_us: AtomicU64,
    pub inbound_budget_wait_max_us: AtomicU64,
    pub inbound_channel_wait_frames: AtomicU64,
    pub inbound_channel_wait_us: AtomicU64,
    pub inbound_channel_wait_max_us: AtomicU64,
    block_traces: Arc<BlockTracer>,
}

impl PqQuicStats {
    pub fn block_trace_evictions(&self) -> u64 {
        self.block_traces.evictions.load(Ordering::Relaxed)
    }
}

struct QueuedFrame {
    bytes: Vec<u8>,
    budget: Arc<QueueBudget>,
    enqueued: std::time::Instant,
    reserved: bool,
    trace: Option<FrameTrace>,
}

impl Drop for QueuedFrame {
    fn drop(&mut self) {
        if self.reserved {
            self.budget
                .bytes
                .fetch_sub(self.bytes.len(), Ordering::AcqRel);
            self.budget.records.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Records one blocked frame, including a wait interrupted by shutdown.
struct InboundWait<'a> {
    frames: &'a AtomicU64,
    total_us: &'a AtomicU64,
    max_us: &'a AtomicU64,
    started: Option<std::time::Instant>,
}

impl<'a> InboundWait<'a> {
    fn new(frames: &'a AtomicU64, total_us: &'a AtomicU64, max_us: &'a AtomicU64) -> Self {
        Self {
            frames,
            total_us,
            max_us,
            started: None,
        }
    }

    fn blocked(&mut self) {
        if self.started.is_none() {
            self.started = Some(std::time::Instant::now());
            self.frames.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for InboundWait<'_> {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            self.total_us.fetch_add(elapsed, Ordering::Relaxed);
            self.max_us.fetch_max(elapsed, Ordering::Relaxed);
        }
    }
}

struct IncomingFrame {
    peer: Pubkey,
    frame: QueuedFrame,
}

/// Dequeueing releases the transport's inbound byte reservation. The consumer
/// owns the returned buffer and is responsible for its own bounded work queues.
pub struct PqReceiver {
    control: Receiver<IncomingFrame>,
    bulk: Receiver<IncomingFrame>,
    control_streak: AtomicUsize,
}

#[derive(Clone)]
struct IncomingSenders {
    control: crossbeam_channel::Sender<IncomingFrame>,
    bulk: crossbeam_channel::Sender<IncomingFrame>,
}

impl PqReceiver {
    fn ordered<'a>(
        &self,
        control: &'a Receiver<IncomingFrame>,
        bulk: &'a Receiver<IncomingFrame>,
    ) -> (
        &'a Receiver<IncomingFrame>,
        &'a Receiver<IncomingFrame>,
        bool,
    ) {
        if self.control_streak.load(Ordering::Relaxed) >= MAX_INCOMING_CONTROL_BURST {
            (bulk, control, false)
        } else {
            (control, bulk, true)
        }
    }

    pub fn recv(&self) -> Result<(Pubkey, Vec<u8>), RecvError> {
        let never = crossbeam_channel::never();
        let mut control = &self.control;
        let mut bulk = &self.bulk;
        loop {
            let (first, second, first_control) = self.ordered(control, bulk);
            crossbeam_channel::select_biased! {
                recv(first) -> frame => match frame {
                    Ok(frame) => return Ok(self.take(frame, first_control)),
                    Err(_) if first_control => control = &never,
                    Err(_) => bulk = &never,
                },
                recv(second) -> frame => match frame {
                    Ok(frame) => return Ok(self.take(frame, !first_control)),
                    Err(_) if first_control => bulk = &never,
                    Err(_) => control = &never,
                },
            }
            if std::ptr::eq(control, &never) && std::ptr::eq(bulk, &never) {
                return Err(RecvError);
            }
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<(Pubkey, Vec<u8>), RecvTimeoutError> {
        let started = std::time::Instant::now();
        let never = crossbeam_channel::never();
        let mut control = &self.control;
        let mut bulk = &self.bulk;
        loop {
            let (first, second, first_control) = self.ordered(control, bulk);
            crossbeam_channel::select_biased! {
                recv(first) -> frame => match frame {
                    Ok(frame) => return Ok(self.take(frame, first_control)),
                    Err(_) if first_control => control = &never,
                    Err(_) => bulk = &never,
                },
                recv(second) -> frame => match frame {
                    Ok(frame) => return Ok(self.take(frame, !first_control)),
                    Err(_) if first_control => bulk = &never,
                    Err(_) => control = &never,
                },
                default(timeout.saturating_sub(started.elapsed())) => return Err(RecvTimeoutError::Timeout),
            }
            if std::ptr::eq(control, &never) && std::ptr::eq(bulk, &never) {
                return Err(RecvTimeoutError::Disconnected);
            }
        }
    }

    pub fn try_recv(&self) -> Result<(Pubkey, Vec<u8>), TryRecvError> {
        let (first, second, first_control) = self.ordered(&self.control, &self.bulk);
        match first.try_recv() {
            Ok(frame) => Ok(self.take(frame, first_control)),
            Err(first) => match second.try_recv() {
                Ok(frame) => Ok(self.take(frame, !first_control)),
                Err(TryRecvError::Disconnected) if first == TryRecvError::Disconnected => {
                    Err(TryRecvError::Disconnected)
                }
                Err(_) => Err(TryRecvError::Empty),
            },
        }
    }

    fn take(&self, mut incoming: IncomingFrame, control: bool) -> (Pubkey, Vec<u8>) {
        if let Some(trace) = &incoming.frame.trace {
            trace.observe(Stage::Dequeue, incoming.frame.bytes.len());
        }
        if control {
            // Fairness metadata never authorizes a frame or changes its reservation.
            let _ =
                self.control_streak
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |streak| {
                        Some(streak.saturating_add(1).min(MAX_INCOMING_CONTROL_BURST))
                    });
        } else {
            self.control_streak.store(0, Ordering::Relaxed);
        }
        let bytes = std::mem::take(&mut incoming.frame.bytes);
        incoming
            .frame
            .budget
            .bytes
            .fetch_sub(bytes.len(), Ordering::AcqRel);
        incoming.frame.budget.records.fetch_sub(1, Ordering::AcqRel);
        incoming.frame.reserved = false;
        (incoming.peer, bytes)
    }
}

impl Drop for PqReceiver {
    fn drop(&mut self) {
        // Transport teardown first joins/cancels its producers. Crossbeam
        // otherwise keeps unread messages while any sender survives, so
        // explicitly release the bounded queued reservations on consumer drop.
        // A fixed upper bound also prevents a racing producer from extending
        // teardown indefinitely.
        for receiver in [&self.control, &self.bulk] {
            for _ in 0..MAX_PQ_QUEUE_RECORDS {
                let Ok(frame) = receiver.try_recv() else {
                    break;
                };
                drop(frame);
            }
        }
    }
}

struct PeerSender {
    control: mpsc::Sender<QueuedFrame>,
    bulk: mpsc::Sender<QueuedFrame>,
    budget: Arc<QueueBudget>,
}

pub struct PqQuicTransport {
    pub receiver: PqReceiver,
    pub stats: Arc<PqQuicStats>,
    pub local_addr: SocketAddr,
    peers: BTreeMap<Pubkey, PeerSender>,
    exit: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PqQuicTransport {
    pub fn spawn(config: PqQuicConfig, exit: Arc<AtomicBool>) -> Result<Self, PqQuicError> {
        config.validate()?;
        let config = Arc::new(config);
        let (control_sender, control_receiver) =
            crossbeam_channel::bounded(RESERVED_CONTROL_RECORDS);
        let (bulk_sender, bulk_receiver) =
            crossbeam_channel::bounded(MAX_PQ_QUEUE_RECORDS - RESERVED_CONTROL_RECORDS);
        let incoming_sender = IncomingSenders {
            control: control_sender,
            bulk: bulk_sender,
        };
        let inbound_budget = Arc::new(QueueBudget::default());
        let stats = Arc::new(PqQuicStats {
            block_traces: Arc::new(BlockTracer::new(config.registry.keys().copied())),
            ..PqQuicStats::default()
        });
        let mut peers = BTreeMap::new();
        let mut receivers = Vec::new();
        for (peer, address) in &config.peers {
            let (control, control_receiver) = mpsc::channel(RESERVED_CONTROL_RECORDS);
            let (bulk, bulk_receiver) =
                mpsc::channel(MAX_PQ_QUEUE_RECORDS - RESERVED_CONTROL_RECORDS);
            let budget = Arc::new(QueueBudget::default());
            peers.insert(
                *peer,
                PeerSender {
                    control,
                    bulk,
                    budget,
                },
            );
            receivers.push((*peer, *address, TrafficClass::Control, control_receiver));
            receivers.push((*peer, *address, TrafficClass::Bulk, bulk_receiver));
        }
        let (ready_sender, ready_receiver) = crossbeam_channel::bounded(1);
        let thread_exit = Arc::clone(&exit);
        let thread_stats = Arc::clone(&stats);
        let thread = thread::Builder::new()
            .name("agave-pq-quic".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(4)
                    .thread_name("agave-pq-quic-io")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_sender.send(Err(PqQuicError::Transport(error.to_string())));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let endpoint = match server_endpoint(&config) {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            let _ = ready_sender.send(Err(error));
                            return;
                        }
                    };
                    let address = match endpoint.local_addr() {
                        Ok(address) => address,
                        Err(error) => {
                            let _ =
                                ready_sender.send(Err(PqQuicError::Transport(error.to_string())));
                            return;
                        }
                    };
                    let _ = ready_sender.send(Ok(address));
                    let incoming_task = tokio::spawn(accept_connections(
                        endpoint.clone(),
                        Arc::clone(&config),
                        incoming_sender,
                        inbound_budget,
                        Arc::clone(&thread_stats),
                        Arc::clone(&thread_exit),
                    ));
                    let mut outgoing_tasks = Vec::new();
                    for (peer, address, class, receiver) in receivers {
                        outgoing_tasks.push(tokio::spawn(send_frames(
                            endpoint.clone(),
                            Arc::clone(&config),
                            peer,
                            address,
                            class,
                            receiver,
                            Arc::clone(&thread_stats),
                            Arc::clone(&thread_exit),
                        )));
                    }
                    while !thread_exit.load(Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    endpoint.close(VarInt::from_u32(0), b"validator shutdown");
                    incoming_task.abort();
                    for task in outgoing_tasks {
                        task.abort();
                    }
                    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, endpoint.wait_idle()).await;
                });
            })
            .map_err(|error| PqQuicError::Transport(error.to_string()))?;
        match ready_receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(local_addr)) => Ok(Self {
                receiver: PqReceiver {
                    control: control_receiver,
                    bulk: bulk_receiver,
                    control_streak: AtomicUsize::new(0),
                },
                stats,
                local_addr,
                peers,
                exit,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(error) => {
                exit.store(true, Ordering::Release);
                let _ = thread.join();
                Err(PqQuicError::Transport(error.to_string()))
            }
        }
    }

    pub fn send(&self, peer: Pubkey, bytes: &[u8]) -> Result<(), PqQuicError> {
        self.send_class(peer, bytes, TrafficClass::Bulk)
    }

    /// Diagnostic-only, all first/last slots of leader windows. Peer indices
    /// follow the sorted trusted registry. No transaction or frame is accepted
    /// based on these unverified public metadata prefixes.
    pub fn configure_block_tracing(&self, config: PqTraceConfig) -> Result<(), PqQuicError> {
        self.stats.block_traces.configure(config)
    }

    /// At most 256 cumulative dirty snapshots per second. A new generation
    /// after bounded retention eviction is a partial observation, never proof
    /// of complete delivery. Quinn write completion is not remote receipt.
    pub fn drain_block_traces(&self) -> Vec<PqBlockTrace> {
        self.stats.block_traces.drain()
    }

    /// Independent authenticated stream/connection, with reserved queue space.
    /// This avoids placing consensus evidence behind already queued bulk bytes.
    pub fn send_control(&self, peer: Pubkey, bytes: &[u8]) -> Result<(), PqQuicError> {
        self.send_class(peer, bytes, TrafficClass::Control)
    }

    fn send_class(
        &self,
        peer: Pubkey,
        bytes: &[u8],
        class: TrafficClass,
    ) -> Result<(), PqQuicError> {
        if bytes.is_empty() || bytes.len() > MAX_PQ_FRAME_BYTES {
            return Err(PqQuicError::FrameSize);
        }
        if self.exit.load(Ordering::Acquire) {
            return Err(PqQuicError::Closed);
        }
        let sender = self
            .peers
            .get(&peer)
            .ok_or(PqQuicError::UnknownPeer(peer))?;
        if !sender.budget.reserve(bytes.len(), class) {
            self.stats.queue_full.fetch_add(1, Ordering::Relaxed);
            return Err(PqQuicError::QueueFull(peer));
        }
        let trace = self.stats.block_traces.tag(peer, bytes, true);
        let frame = QueuedFrame {
            bytes: bytes.to_vec(),
            budget: Arc::clone(&sender.budget),
            enqueued: std::time::Instant::now(),
            reserved: true,
            trace: trace.clone(),
        };
        let queue = match class {
            TrafficClass::Bulk => &sender.bulk,
            TrafficClass::Control => &sender.control,
        };
        let enqueued_us = trace.as_ref().map(|_| self.stats.block_traces.now_us());
        queue.try_send(frame).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                self.stats.queue_full.fetch_add(1, Ordering::Relaxed);
                PqQuicError::QueueFull(peer)
            }
            mpsc::error::TrySendError::Closed(_) => PqQuicError::Closed,
        })?;
        if let Some(trace) = trace {
            trace.observe_at(Stage::Enqueue, bytes.len(), enqueued_us.unwrap());
        }
        Ok(())
    }

    /// Some peers may already have accepted the frame when this returns a queue
    /// error. A retry can duplicate delivery; consensus frames must be idempotent.
    pub fn broadcast(&self, bytes: &[u8]) -> Result<(), PqQuicError> {
        for peer in self.peers.keys() {
            self.send(*peer, bytes)?;
        }
        Ok(())
    }

    pub fn join(mut self) -> Result<(), PqQuicError> {
        self.exit.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| PqQuicError::Transport("QUIC runtime thread panicked".into()))?;
        }
        Ok(())
    }
}

impl Drop for PqQuicTransport {
    fn drop(&mut self) {
        self.exit.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn reserve_limit(budget: &AtomicUsize, bytes: usize, limit: usize) -> bool {
    budget
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            used.checked_add(bytes).filter(|next| *next <= limit)
        })
        .is_ok()
}

fn initial_suite() -> rustls::quic::Suite {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("ring QUIC Initial suite is TLS 1.3");
    rustls::quic::Suite {
        suite,
        quic: suite.quic.expect("ring Initial suite supports QUIC"),
    }
}

fn transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(1u32.into());
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.stream_receive_window(VarInt::from_u32(MAX_PQ_QUEUE_BYTES as u32));
    transport.receive_window(VarInt::from_u32(MAX_PQ_QUEUE_BYTES as u32));
    transport.send_window(MAX_PQ_QUEUE_BYTES as u64);
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport.datagram_receive_buffer_size(None);
    Arc::new(transport)
}

fn server_endpoint(config: &PqQuicConfig) -> Result<Endpoint, PqQuicError> {
    Endpoint::server(native_server_config(config)?, config.listen)
        .map_err(|error| PqQuicError::Transport(error.to_string()))
}

fn native_server_config(config: &PqQuicConfig) -> Result<ServerConfig, PqQuicError> {
    let tls = tls::server_config(
        config.chain,
        config.identity,
        Arc::clone(&config.signer),
        &config.registry,
    )
    .map_err(|error| PqQuicError::Transport(error.to_string()))?;
    let quic = QuicServerConfig::with_initial(Arc::new(tls), initial_suite())
        .map_err(|error| PqQuicError::Transport(error.to_string()))?;
    let mut server = ServerConfig::with_crypto(Arc::new(quic));
    server.migration(false);
    server.max_incoming(128);
    server.transport_config(transport_config());
    Ok(server)
}

fn client_config(config: &PqQuicConfig, peer: Pubkey) -> Result<ClientConfig, PqQuicError> {
    let tls = tls::client_config(
        config.chain,
        config.identity,
        Arc::clone(&config.signer),
        &config.registry,
        peer,
    )
    .map_err(|error| PqQuicError::Transport(error.to_string()))?;
    let quic = QuicClientConfig::with_initial(Arc::new(tls), initial_suite())
        .map_err(|error| PqQuicError::Transport(error.to_string()))?;
    let mut client = ClientConfig::new(Arc::new(quic));
    client.transport_config(transport_config());
    Ok(client)
}

async fn accept_connections(
    endpoint: Endpoint,
    config: Arc<PqQuicConfig>,
    sender: IncomingSenders,
    budget: Arc<QueueBudget>,
    stats: Arc<PqQuicStats>,
    exit: Arc<AtomicBool>,
) {
    let pins = Arc::new(tls::PinnedCredentials::new(
        config.chain,
        &config.registry,
        None,
    ));
    let limit = Arc::new(tokio::sync::Semaphore::new(128));
    while let Some(incoming) = endpoint.accept().await {
        if exit.load(Ordering::Acquire) {
            return;
        }
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            incoming.refuse();
            stats.rejected_handshakes.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let pins = Arc::clone(&pins);
        let sender = sender.clone();
        let budget = Arc::clone(&budget);
        let stats = Arc::clone(&stats);
        let exit = Arc::clone(&exit);
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await else {
                stats.rejected_handshakes.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let Some(peer) = peer_identity(&connection, &pins) else {
                connection.close(VarInt::from_u32(1), b"PQ credential attribution failed");
                stats.rejected_handshakes.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if let Ok(stream) = connection.accept_uni().await {
                receive_frames(stream, peer, sender, budget, stats, exit).await;
            }
            connection.close(VarInt::from_u32(0), b"PQ frame stream closed");
        });
    }
}

fn peer_identity(connection: &Connection, pins: &tls::PinnedCredentials) -> Option<Pubkey> {
    let identity = connection
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    if identity.len() != 1 {
        return None;
    }
    pins.identity(&identity[0]).ok()
}

async fn receive_frames(
    mut stream: quinn::RecvStream,
    peer: Pubkey,
    senders: IncomingSenders,
    budget: Arc<QueueBudget>,
    stats: Arc<PqQuicStats>,
    exit: Arc<AtomicBool>,
) {
    let mut preface = [0; 9];
    if !matches!(
        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut preface)).await,
        Ok(Ok(()))
    ) || &preface[..8] != STREAM_PREFACE
    {
        let _ = stream.stop(VarInt::from_u32(5));
        return;
    }
    let (class, sender) = match preface[8] {
        0 => (TrafficClass::Bulk, senders.bulk),
        1 => (TrafficClass::Control, senders.control),
        _ => {
            let _ = stream.stop(VarInt::from_u32(5));
            return;
        }
    };
    loop {
        let Ok(length) = stream.read_u32().await else {
            return;
        };
        let length = length as usize;
        if length == 0 || length > MAX_PQ_FRAME_BYTES {
            let _ = stream.stop(VarInt::from_u32(2));
            return;
        }
        let mut budget_wait = InboundWait::new(
            &stats.inbound_budget_wait_frames,
            &stats.inbound_budget_wait_us,
            &stats.inbound_budget_wait_max_us,
        );
        while !budget.reserve(length, class) {
            budget_wait.blocked();
            if exit.load(Ordering::Acquire) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        drop(budget_wait);
        let mut frame = QueuedFrame {
            bytes: vec![0; length],
            budget: Arc::clone(&budget),
            enqueued: std::time::Instant::now(),
            reserved: true,
            trace: None,
        };
        if !matches!(
            tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut frame.bytes)).await,
            Ok(Ok(()))
        ) {
            let _ = stream.stop(VarInt::from_u32(4));
            return;
        }
        frame.trace = stats.block_traces.tag(peer, &frame.bytes, false);
        if let Some(trace) = &frame.trace {
            trace.observe(Stage::Read, frame.bytes.len());
        }
        let mut incoming = IncomingFrame { peer, frame };
        let trace = incoming.frame.trace.clone();
        let mut channel_wait = InboundWait::new(
            &stats.inbound_channel_wait_frames,
            &stats.inbound_channel_wait_us,
            &stats.inbound_channel_wait_max_us,
        );
        let enqueued_us = loop {
            let enqueued_us = trace.as_ref().map(|_| stats.block_traces.now_us());
            match sender.try_send(incoming) {
                Ok(()) => break enqueued_us,
                Err(crossbeam_channel::TrySendError::Full(returned)) => {
                    channel_wait.blocked();
                    incoming = returned;
                    if exit.load(Ordering::Acquire) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => return,
            }
        };
        drop(channel_wait);
        if let Some(trace) = trace {
            trace.observe_at(Stage::Enqueue, length, enqueued_us.unwrap());
        }
        stats.received_frames.fetch_add(1, Ordering::Relaxed);
        stats
            .received_bytes
            .fetch_add(length as u64, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_frames(
    endpoint: Endpoint,
    config: Arc<PqQuicConfig>,
    peer: Pubkey,
    address: SocketAddr,
    class: TrafficClass,
    mut receiver: mpsc::Receiver<QueuedFrame>,
    stats: Arc<PqQuicStats>,
    exit: Arc<AtomicBool>,
) {
    let Ok(client_config) = client_config(&config, peer) else {
        return;
    };
    let pins = tls::PinnedCredentials::new(config.chain, &config.registry, Some(peer));
    let mut active: Option<(Connection, quinn::SendStream)> = None;
    while let Some(frame) = receiver.recv().await {
        loop {
            if exit.load(Ordering::Acquire) {
                return;
            }
            if active.is_none() {
                let Ok(connecting) =
                    endpoint.connect_with(client_config.clone(), address, "agave-pq.invalid")
                else {
                    stats.reconnects.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
                    Ok(Ok(connection)) if peer_identity(&connection, &pins) == Some(peer) => {
                        connection
                    }
                    _ => {
                        stats.rejected_handshakes.fetch_add(1, Ordering::Relaxed);
                        stats.reconnects.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                match connection.open_uni().await {
                    Ok(mut stream) => {
                        let mut preface = STREAM_PREFACE.to_vec();
                        preface.push(class as u8);
                        if stream.write_all(&preface).await.is_err() {
                            connection.close(VarInt::from_u32(5), b"PQ stream preface failed");
                            continue;
                        }
                        active = Some((connection, stream));
                    }
                    Err(_) => continue,
                }
            }
            let Some((connection, stream)) = active.as_mut() else {
                continue;
            };
            let length = (frame.bytes.len() as u32).to_be_bytes();
            if stream.write_all(&length).await.is_ok()
                && stream.write_all(&frame.bytes).await.is_ok()
            {
                if let Some(trace) = &frame.trace {
                    trace.observe(Stage::Write, frame.bytes.len());
                }
                stats.sent_frames.fetch_add(1, Ordering::Relaxed);
                stats
                    .sent_bytes
                    .fetch_add(frame.bytes.len() as u64, Ordering::Relaxed);
                match class {
                    TrafficClass::Bulk => {
                        stats.sent_bulk_frames.fetch_add(1, Ordering::Relaxed);
                    }
                    TrafficClass::Control => {
                        stats.sent_control_frames.fetch_add(1, Ordering::Relaxed);
                        let wait =
                            frame.enqueued.elapsed().as_micros().min(u64::MAX as u128) as u64;
                        stats
                            .control_queue_wait_us
                            .fetch_add(wait, Ordering::Relaxed);
                        stats
                            .maximum_control_queue_wait_us
                            .fetch_max(wait, Ordering::Relaxed);
                    }
                }
                break;
            }
            connection.close(VarInt::from_u32(3), b"PQ frame send failed");
            active = None;
            stats.reconnects.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_configs() -> (PqQuicConfig, PqQuicConfig) {
        let left_id = Pubkey::new_unique();
        let right_id = Pubkey::new_unique();
        let left_key = Arc::new(FalconKeypair::generate());
        let right_key = Arc::new(FalconKeypair::generate());
        let registry = BTreeMap::from([
            (left_id, left_key.public_key()),
            (right_id, right_key.public_key()),
        ]);
        (
            PqQuicConfig {
                chain: [0x37; 32],
                identity: left_id,
                signer: left_key,
                registry: registry.clone(),
                peers: BTreeMap::new(),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            PqQuicConfig {
                chain: [0x37; 32],
                identity: right_id,
                signer: right_key,
                registry,
                peers: BTreeMap::new(),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
        )
    }

    fn wait_until(condition: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "condition timed out"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn queued(budget: &Arc<QueueBudget>, class: TrafficClass, bytes: Vec<u8>) -> QueuedFrame {
        assert!(budget.reserve(bytes.len(), class));
        QueuedFrame {
            bytes,
            budget: Arc::clone(budget),
            enqueued: std::time::Instant::now(),
            reserved: true,
            trace: None,
        }
    }

    #[test]
    fn receiver_services_bulk_during_continuously_refilled_control() {
        for mode in 0..3 {
            let (control, control_receiver) = crossbeam_channel::bounded(1);
            let (bulk, bulk_receiver) = crossbeam_channel::bounded(1);
            let receiver = PqReceiver {
                control: control_receiver,
                bulk: bulk_receiver,
                control_streak: AtomicUsize::new(0),
            };
            let budget = Arc::new(QueueBudget::default());
            let peer = Pubkey::new_unique();
            bulk.send(IncomingFrame {
                peer,
                frame: queued(&budget, TrafficClass::Bulk, vec![1]),
            })
            .unwrap();
            for turn in 0..9 {
                control
                    .send(IncomingFrame {
                        peer,
                        frame: queued(&budget, TrafficClass::Control, vec![3]),
                    })
                    .unwrap();
                let actual = match mode {
                    0 => receiver.recv().unwrap(),
                    1 => receiver.recv_timeout(Duration::ZERO).unwrap(),
                    _ => receiver.try_recv().unwrap(),
                };
                assert_eq!(actual, (peer, vec![if turn < 8 { 3 } else { 1 }]));
            }
            assert_eq!(budget.bytes.load(Ordering::Acquire), 1);
            assert_eq!(budget.records.load(Ordering::Acquire), 1);
            // The queued control frame keeps its reservation until received.
            assert_eq!(receiver.try_recv().unwrap(), (peer, vec![3]));
            assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
            assert_eq!(budget.records.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn receiver_preserves_single_class_progress_after_control_burst() {
        for mode in 0..3 {
            let (control, control_receiver) = crossbeam_channel::bounded(1);
            let (bulk, bulk_receiver) = crossbeam_channel::bounded(1);
            let receiver = PqReceiver {
                control: control_receiver,
                bulk: bulk_receiver,
                control_streak: AtomicUsize::new(MAX_INCOMING_CONTROL_BURST),
            };
            let budget = Arc::new(QueueBudget::default());
            let peer = Pubkey::new_unique();
            for index in 0u8..16 {
                control
                    .send(IncomingFrame {
                        peer,
                        frame: queued(&budget, TrafficClass::Control, vec![index]),
                    })
                    .unwrap();
                let actual = match mode {
                    0 => receiver.recv().unwrap(),
                    1 => receiver.recv_timeout(Duration::ZERO).unwrap(),
                    _ => receiver.try_recv().unwrap(),
                };
                assert_eq!(actual, (peer, vec![index]));
            }
            drop(control);
            bulk.send(IncomingFrame {
                peer,
                frame: queued(&budget, TrafficClass::Bulk, vec![1]),
            })
            .unwrap();
            assert_eq!(receiver.try_recv().unwrap(), (peer, vec![1]));
            assert_eq!(receiver.control_streak.load(Ordering::Relaxed), 0);
            assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
            assert_eq!(budget.records.load(Ordering::Acquire), 0);
            drop(bulk);
            assert!(matches!(receiver.recv(), Err(RecvError)));
            assert!(matches!(
                receiver.recv_timeout(Duration::ZERO),
                Err(RecvTimeoutError::Disconnected)
            ));
            assert!(matches!(
                receiver.try_recv(),
                Err(TryRecvError::Disconnected)
            ));
        }
    }

    #[test]
    fn receiver_drains_both_classes_and_releases_reservations_after_one_disconnects() {
        for mode in 0..3 {
            let (control, control_receiver) = crossbeam_channel::bounded(2);
            let (bulk, bulk_receiver) = crossbeam_channel::bounded(2);
            let receiver = PqReceiver {
                control: control_receiver,
                bulk: bulk_receiver,
                control_streak: AtomicUsize::new(0),
            };
            let budget = Arc::new(QueueBudget::default());
            let peer = Pubkey::new_unique();
            bulk.send(IncomingFrame {
                peer,
                frame: queued(&budget, TrafficClass::Bulk, vec![3]),
            })
            .unwrap();
            drop(control);
            let frame = match mode {
                0 => receiver.recv().unwrap(),
                1 => receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                _ => receiver.try_recv().unwrap(),
            };
            assert_eq!(frame, (peer, vec![3]));
            assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
            assert_eq!(budget.records.load(Ordering::Acquire), 0);
            assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            assert!(matches!(
                receiver.recv_timeout(Duration::ZERO),
                Err(RecvTimeoutError::Timeout)
            ));
            drop(bulk);
            assert!(matches!(receiver.recv(), Err(RecvError)));
            assert!(matches!(
                receiver.try_recv(),
                Err(TryRecvError::Disconnected)
            ));
            assert!(matches!(
                receiver.recv_timeout(Duration::from_secs(1)),
                Err(RecvTimeoutError::Disconnected)
            ));
        }
        let (control, control_receiver) = crossbeam_channel::bounded(2);
        let (bulk, bulk_receiver) = crossbeam_channel::bounded(2);
        let receiver = PqReceiver {
            control: control_receiver,
            bulk: bulk_receiver,
            control_streak: AtomicUsize::new(0),
        };
        let budget = Arc::new(QueueBudget::default());
        drop(bulk);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(
            receiver.recv_timeout(Duration::ZERO),
            Err(RecvTimeoutError::Timeout)
        ));
        control
            .send(IncomingFrame {
                peer: Pubkey::new_unique(),
                frame: queued(&budget, TrafficClass::Control, vec![4; 17]),
            })
            .unwrap();
        assert_eq!(budget.bytes.load(Ordering::Acquire), 17);
        drop(receiver);
        assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.records.load(Ordering::Acquire), 0);
    }

    #[test]
    fn failed_or_full_channel_send_releases_its_shared_reservation() {
        let peer = Pubkey::new_unique();
        let budget = Arc::new(QueueBudget::default());
        let (control, mut control_receiver) = mpsc::channel(1);
        let (bulk, bulk_receiver) = mpsc::channel(1);
        drop(bulk_receiver);
        let (_, control_in) = crossbeam_channel::bounded(1);
        let (_, bulk_in) = crossbeam_channel::bounded(1);
        let transport = PqQuicTransport {
            receiver: PqReceiver {
                control: control_in,
                bulk: bulk_in,
                control_streak: AtomicUsize::new(0),
            },
            stats: Arc::default(),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peers: BTreeMap::from([(
                peer,
                PeerSender {
                    control,
                    bulk,
                    budget: Arc::clone(&budget),
                },
            )]),
            exit: Arc::new(AtomicBool::new(false)),
            thread: None,
        };
        assert!(matches!(
            transport.send(peer, &[1; 12]),
            Err(PqQuicError::Closed)
        ));
        assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.records.load(Ordering::Acquire), 0);
        transport.send_control(peer, &[2; 17]).unwrap();
        assert!(matches!(
            transport.send_control(peer, &[3; 23]),
            Err(PqQuicError::QueueFull(_))
        ));
        assert_eq!(budget.bytes.load(Ordering::Acquire), 17);
        assert_eq!(budget.records.load(Ordering::Acquire), 1);
        drop(control_receiver.try_recv().unwrap());
        assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.records.load(Ordering::Acquire), 0);
    }

    #[test]
    fn disconnected_real_quic_queues_share_fixed_byte_and_record_limits_and_stop_promptly() {
        for records in [false, true] {
            let (mut left_config, right_config) = test_configs();
            let silent_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let context = silent_runtime.enter();
            let silent_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            drop(context);
            left_config
                .peers
                .insert(right_config.identity, silent_endpoint.local_addr().unwrap());
            let peer = right_config.identity;
            let left =
                PqQuicTransport::spawn(left_config, Arc::new(AtomicBool::new(false))).unwrap();
            let budget = Arc::clone(&left.peers[&peer].budget);
            if records {
                for _ in 0..MAX_PQ_QUEUE_RECORDS - RESERVED_CONTROL_RECORDS {
                    left.send(peer, &[0]).unwrap();
                }
                assert!(matches!(
                    left.send(peer, &[1]),
                    Err(PqQuicError::QueueFull(_))
                ));
                for _ in 0..RESERVED_CONTROL_RECORDS {
                    left.send_control(peer, &[2]).unwrap();
                }
                assert_eq!(budget.records.load(Ordering::Acquire), MAX_PQ_QUEUE_RECORDS);
                assert!(matches!(
                    left.send_control(peer, &[3]),
                    Err(PqQuicError::QueueFull(_))
                ));
            } else {
                let payload = vec![4; MAX_PQ_FRAME_BYTES];
                for _ in 0..3 {
                    left.send(peer, &payload).unwrap();
                }
                left.send(
                    peer,
                    &payload[..MAX_PQ_FRAME_BYTES - RESERVED_CONTROL_BYTES],
                )
                .unwrap();
                assert!(matches!(
                    left.send(peer, &[5]),
                    Err(PqQuicError::QueueFull(_))
                ));
                left.send_control(peer, &payload[..RESERVED_CONTROL_BYTES])
                    .unwrap();
                assert_eq!(budget.bytes.load(Ordering::Acquire), MAX_PQ_QUEUE_BYTES);
                assert!(matches!(
                    left.send_control(peer, &[6]),
                    Err(PqQuicError::QueueFull(_))
                ));
            }
            let shutdown = std::time::Instant::now();
            left.join().unwrap();
            assert!(shutdown.elapsed() < Duration::from_secs(3));
            assert_eq!(budget.records.load(Ordering::Acquire), 0);
            assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
            drop(silent_endpoint);
            drop(silent_runtime);
        }
    }

    #[test]
    fn authenticated_control_progresses_past_full_bulk_and_both_classes_remain_ordered() {
        let (mut left_config, right_config) = test_configs();
        let left_id = left_config.identity;
        let right_id = right_config.identity;
        let right = PqQuicTransport::spawn(right_config, Arc::new(AtomicBool::new(false))).unwrap();
        left_config.peers.insert(right_id, right.local_addr);
        let left = PqQuicTransport::spawn(left_config, Arc::new(AtomicBool::new(false))).unwrap();
        for index in 0u32..4 {
            let length = if index == 3 {
                MAX_PQ_FRAME_BYTES - RESERVED_CONTROL_BYTES
            } else {
                MAX_PQ_FRAME_BYTES
            };
            let mut bytes = vec![0; length];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            left.send(right_id, &bytes).unwrap();
        }
        wait_until(|| right.receiver.bulk.len() == 4);
        left.send(right_id, &4u32.to_be_bytes()).unwrap();
        wait_until(|| {
            right
                .stats
                .inbound_budget_wait_frames
                .load(Ordering::Acquire)
                > 0
        });
        for index in 0u32..64 {
            let mut bytes = vec![0xc1];
            bytes.extend(index.to_be_bytes());
            left.send_control(right_id, &bytes).unwrap();
        }
        wait_until(|| right.receiver.control.len() == 64);
        assert_eq!(
            right.receiver.bulk.len(),
            4,
            "bulk remains blocked on its application budget"
        );
        let mut next_control = 0u32;
        let mut next_bulk = 0u32;
        let mut first_bulk = None;
        for ordinal in 0..69 {
            let (peer, bytes) = right
                .receiver
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            assert_eq!(peer, left_id);
            if bytes[0] == 0xc1 {
                assert_eq!(&bytes[1..], &next_control.to_be_bytes());
                next_control += 1;
            } else {
                first_bulk.get_or_insert(ordinal);
                assert_eq!(&bytes[..4], &next_bulk.to_be_bytes());
                next_bulk += 1;
            }
        }
        assert_eq!(first_bulk, Some(MAX_INCOMING_CONTROL_BURST));
        assert_eq!(next_control, 64);
        assert_eq!(next_bulk, 5);
        assert_eq!(left.stats.sent_control_frames.load(Ordering::Acquire), 64);
        assert_eq!(left.stats.sent_bulk_frames.load(Ordering::Acquire), 5);
        assert!(right.stats.inbound_budget_wait_us.load(Ordering::Acquire) > 0);
        assert!(
            right
                .stats
                .inbound_budget_wait_max_us
                .load(Ordering::Acquire)
                > 0
        );
        left.join().unwrap();
        right.join().unwrap();
    }

    #[test]
    fn real_quic_block_landmarks_include_control_backpressure_and_exact_dequeue() {
        let (mut left_config, right_config) = test_configs();
        let left_id = left_config.identity;
        let right_id = right_config.identity;
        let (data, terminal) = trace::tests::signed_frames(&left_config.signer, 4);
        let right = PqQuicTransport::spawn(right_config, Arc::new(AtomicBool::new(false))).unwrap();
        left_config.peers.insert(right_id, right.local_addr);
        let left = PqQuicTransport::spawn(left_config, Arc::new(AtomicBool::new(false))).unwrap();
        let config = PqTraceConfig {
            first_slot: 1,
            slot_count: 8,
            window_size: 4,
        };
        left.configure_block_tracing(config).unwrap();
        right.configure_block_tracing(config).unwrap();
        for frame in &data {
            left.send(right_id, frame).unwrap();
        }
        for _ in 0..RESERVED_CONTROL_RECORDS {
            left.send_control(right_id, &[3]).unwrap();
        }
        wait_until(|| right.receiver.control.len() == RESERVED_CONTROL_RECORDS);
        left.send_control(right_id, &terminal).unwrap();
        wait_until(|| {
            right
                .stats
                .inbound_channel_wait_frames
                .load(Ordering::Acquire)
                > 0
        });
        let mut data_frames = 0;
        let mut terminal_frames = 0;
        for _ in 0..RESERVED_CONTROL_RECORDS + data.len() + 1 {
            let (peer, frame) = right
                .receiver
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            assert_eq!(peer, left_id);
            if frame == terminal {
                terminal_frames += 1;
            } else if frame != [3] {
                assert_eq!(frame, data[data_frames]);
                data_frames += 1;
            }
        }
        assert_eq!(data_frames, data.len());
        assert_eq!(terminal_frames, 1);
        wait_until(|| right.stats.inbound_channel_wait_us.load(Ordering::Acquire) > 0);
        let outbound = std::sync::Mutex::new(Vec::new());
        let inbound = std::sync::Mutex::new(Vec::new());
        wait_until(|| {
            let rows = left.drain_block_traces();
            if rows.is_empty() {
                return false;
            }
            *outbound.lock().unwrap() = rows;
            true
        });
        wait_until(|| {
            let rows = right.drain_block_traces();
            if rows.is_empty() {
                return false;
            }
            *inbound.lock().unwrap() = rows;
            true
        });
        let sent = outbound.into_inner().unwrap();
        let received = inbound.into_inner().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(received.len(), 1);
        assert!(sent[0].outbound && !received[0].outbound);
        assert_eq!(sent[0].candidate, received[0].candidate);
        assert_eq!(sent[0].slot, 4);
        assert_eq!(sent[0].data[0].frames, data.len() as u64);
        assert_eq!(sent[0].data[1].frames, data.len() as u64);
        assert_eq!(received[0].data[2].frames, data.len() as u64);
        assert_eq!(received[0].data[3].frames, data.len() as u64);
        assert_eq!(sent[0].terminal[0].frames, 1);
        assert_eq!(sent[0].terminal[1].frames, 1);
        assert_eq!(received[0].terminal[2].frames, 1);
        assert_eq!(received[0].terminal[3].frames, 1);
        assert!(received[0].terminal[3].last_unix_us >= received[0].terminal[2].last_unix_us);
        assert!(received[0].terminal[0].last_unix_us >= received[0].terminal[2].last_unix_us);
        assert!(
            right
                .stats
                .inbound_channel_wait_max_us
                .load(Ordering::Acquire)
                > 0
        );
        assert!(left.drain_block_traces().is_empty());
        left.join().unwrap();
        right.join().unwrap();
    }

    #[test]
    fn authenticated_quic_rejects_bad_stream_prefaces_and_accepts_current_control_class() {
        let (left_config, right_config) = test_configs();
        let right_id = right_config.identity;
        let right = PqQuicTransport::spawn(right_config, Arc::new(AtomicBool::new(false))).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let client = left_config.client_config(right_id).unwrap();
            for preface in [
                b"PQSTRM01\0".as_slice(),
                b"PQSTRM02\x02".as_slice(),
                b"PQSTRM02".as_slice(),
            ] {
                let connection = endpoint
                    .connect_with(client.clone(), right.local_addr, "agave-pq.invalid")
                    .unwrap()
                    .await
                    .unwrap();
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(preface).await.unwrap();
                stream.finish().unwrap();
                tokio::time::timeout(Duration::from_secs(2), connection.closed())
                    .await
                    .unwrap();
            }
            assert_eq!(right.stats.received_frames.load(Ordering::Acquire), 0);
            assert!(matches!(
                right.receiver.try_recv(),
                Err(TryRecvError::Empty)
            ));
            let connection = endpoint
                .connect_with(client, right.local_addr, "agave-pq.invalid")
                .unwrap()
                .await
                .unwrap();
            let mut stream = connection.open_uni().await.unwrap();
            let mut bytes = STREAM_PREFACE.to_vec();
            bytes.push(TrafficClass::Control as u8);
            bytes.extend(7u32.to_be_bytes());
            bytes.extend(b"current");
            stream.write_all(&bytes).await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while right.receiver.control.is_empty() {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                right.receiver.try_recv().unwrap(),
                (left_config.identity, b"current".to_vec())
            );
            endpoint.close(VarInt::from_u32(0), b"test complete");
            tokio::time::timeout(SHUTDOWN_TIMEOUT, endpoint.wait_idle())
                .await
                .unwrap();
        });
        right.join().unwrap();
    }

    #[test]
    fn interrupted_authenticated_bulk_write_keeps_reservation_and_replays_whole_frame() {
        let (mut left_config, right_config) = test_configs();
        let left_id = left_config.identity;
        let right_id = right_config.identity;
        let (ready, address) = crossbeam_channel::bounded(1);
        let (interrupted, observed) = crossbeam_channel::bounded(1);
        let (proceed, gate) = crossbeam_channel::bounded(1);
        let (completed, received) = crossbeam_channel::bounded(1);
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let mut config = right_config.server_config().unwrap();
                let mut transport = TransportConfig::default();
                transport.max_concurrent_uni_streams(1u32.into());
                transport.max_concurrent_bidi_streams(0u32.into());
                // Force the large first frame to remain partially written so
                // reconnect exercises a retained in-flight reservation.
                transport.stream_receive_window(VarInt::from_u32(4096));
                transport.receive_window(VarInt::from_u32(4096));
                config.transport_config(Arc::new(transport));
                let endpoint = Endpoint::server(config, right_config.listen).unwrap();
                ready.send(endpoint.local_addr().unwrap()).unwrap();
                let pins = tls::PinnedCredentials::new(
                    right_config.chain,
                    &right_config.registry,
                    Some(left_id),
                );
                let first = endpoint.accept().await.unwrap().await.unwrap();
                assert_eq!(peer_identity(&first, &pins), Some(left_id));
                let mut stream = first.accept_uni().await.unwrap();
                let mut preface = [0; 9];
                stream.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface[..8], STREAM_PREFACE);
                assert_eq!(preface[8], TrafficClass::Bulk as u8);
                assert_eq!(stream.read_u32().await.unwrap(), 1024 * 1024);
                let mut prefix = [0; 32];
                stream.read_exact(&mut prefix).await.unwrap();
                assert_eq!(prefix, [0x71; 32]);
                interrupted.send(()).unwrap();
                gate.recv_timeout(Duration::from_secs(10)).unwrap();
                first.close(VarInt::from_u32(6), b"test interrupts partial frame");

                let second = tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
                    .await
                    .unwrap()
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(peer_identity(&second, &pins), Some(left_id));
                let mut stream = second.accept_uni().await.unwrap();
                stream.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface[..8], STREAM_PREFACE);
                assert_eq!(preface[8], TrafficClass::Bulk as u8);
                let mut frames = Vec::new();
                for expected in [1024 * 1024, 23] {
                    assert_eq!(stream.read_u32().await.unwrap(), expected);
                    let mut bytes = vec![0; expected as usize];
                    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                    frames.push(bytes);
                }
                completed.send(frames).unwrap();
                endpoint.close(VarInt::from_u32(0), b"test complete");
                let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, endpoint.wait_idle()).await;
            });
        });
        left_config.peers.insert(
            right_id,
            address.recv_timeout(Duration::from_secs(10)).unwrap(),
        );
        let left = PqQuicTransport::spawn(left_config, Arc::new(AtomicBool::new(false))).unwrap();
        let budget = Arc::clone(&left.peers[&right_id].budget);
        left.send(right_id, &vec![0x71; 1024 * 1024]).unwrap();
        observed.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(budget.bytes.load(Ordering::Acquire), 1024 * 1024);
        assert_eq!(budget.records.load(Ordering::Acquire), 1);
        left.send(right_id, &[0x72; 23]).unwrap();
        assert_eq!(budget.bytes.load(Ordering::Acquire), 1024 * 1024 + 23);
        assert_eq!(budget.records.load(Ordering::Acquire), 2);
        proceed.send(()).unwrap();
        let frames = received.recv_timeout(Duration::from_secs(15)).unwrap();
        assert_eq!(frames, vec![vec![0x71; 1024 * 1024], vec![0x72; 23]]);
        wait_until(|| budget.records.load(Ordering::Acquire) == 0);
        assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
        assert!(left.stats.reconnects.load(Ordering::Acquire) >= 1);
        left.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn native_quic_mutual_pq_authentication_and_ordered_frames() {
        let left_id = Pubkey::new_unique();
        let right_id = Pubkey::new_unique();
        let left_key = Arc::new(FalconKeypair::generate());
        let right_key = Arc::new(FalconKeypair::generate());
        let registry = BTreeMap::from([
            (left_id, left_key.public_key()),
            (right_id, right_key.public_key()),
        ]);
        let right_exit = Arc::new(AtomicBool::new(false));
        let right = PqQuicTransport::spawn(
            PqQuicConfig {
                chain: [9; 32],
                identity: right_id,
                signer: right_key,
                registry: registry.clone(),
                peers: BTreeMap::new(),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            Arc::clone(&right_exit),
        )
        .unwrap();
        let left_exit = Arc::new(AtomicBool::new(false));
        let left = PqQuicTransport::spawn(
            PqQuicConfig {
                chain: [9; 32],
                identity: left_id,
                signer: left_key,
                registry,
                peers: BTreeMap::from([(right_id, right.local_addr)]),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            Arc::clone(&left_exit),
        )
        .unwrap();
        for n in 0u32..64 {
            left.send(right_id, &n.to_be_bytes()).unwrap();
        }
        for n in 0u32..64 {
            let (peer, frame) = right
                .receiver
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            assert_eq!(peer, left_id);
            assert_eq!(frame, n.to_be_bytes());
        }
        assert_eq!(right.stats.received_frames.load(Ordering::Relaxed), 64);
        left.join().unwrap();
        right.join().unwrap();
    }

    #[test]
    fn bounded_queues_and_mismatched_local_credential() {
        let budget = QueueBudget::default();
        assert!(budget.reserve(MAX_PQ_QUEUE_BYTES, TrafficClass::Control));
        assert!(!budget.reserve(1, TrafficClass::Control));
        let identity = Pubkey::new_unique();
        let config = PqQuicConfig {
            chain: [0; 32],
            identity,
            signer: Arc::new(FalconKeypair::generate()),
            registry: BTreeMap::from([(identity, FalconKeypair::generate().public_key())]),
            peers: BTreeMap::new(),
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        assert!(matches!(
            PqQuicTransport::spawn(config, Arc::new(AtomicBool::new(false))),
            Err(PqQuicError::Configuration(_))
        ));
    }

    #[test]
    fn native_quic_wrong_signature_domain_never_delivers_a_frame() {
        let left_id = Pubkey::new_unique();
        let right_id = Pubkey::new_unique();
        let left_key = Arc::new(FalconKeypair::generate());
        let right_key = Arc::new(FalconKeypair::generate());
        let registry = BTreeMap::from([
            (left_id, left_key.public_key()),
            (right_id, right_key.public_key()),
        ]);
        let right = PqQuicTransport::spawn(
            PqQuicConfig {
                chain: [1; 32],
                identity: right_id,
                signer: right_key,
                registry: registry.clone(),
                peers: BTreeMap::new(),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let left = PqQuicTransport::spawn(
            PqQuicConfig {
                chain: [2; 32],
                identity: left_id,
                signer: left_key,
                registry,
                peers: BTreeMap::from([(right_id, right.local_addr)]),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        left.send(right_id, b"must not be admitted").unwrap();
        assert!(matches!(
            right.receiver.recv_timeout(Duration::from_millis(500)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert_eq!(right.stats.received_frames.load(Ordering::Relaxed), 0);
        assert!(left.stats.rejected_handshakes.load(Ordering::Relaxed) > 0);
        left.join().unwrap();
        right.join().unwrap();
    }

    #[test]
    fn native_quic_classical_client_has_no_downgrade_path() {
        let identity = Pubkey::new_unique();
        let signer = Arc::new(FalconKeypair::generate());
        let server = PqQuicTransport::spawn(
            PqQuicConfig {
                chain: [1; 32],
                identity,
                registry: BTreeMap::from([(identity, signer.public_key())]),
                signer,
                peers: BTreeMap::new(),
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (cert, key) = crate::new_dummy_x509_certificate(&solana_keypair::Keypair::new());
            let mut legacy = crate::tls_client_config_builder()
                .with_client_auth_cert(vec![cert], key)
                .unwrap();
            legacy.alpn_protocols = vec![tls::PQ_ALPN.to_vec()];
            let config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(legacy).unwrap()));
            let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(config);
            let connect = client.connect(server.local_addr, "localhost").unwrap();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), connect).await,
                Ok(Err(_))
            ));
            client.close(VarInt::from_u32(0), b"test completed");
            client.wait_idle().await;
        });
        assert_eq!(server.stats.received_frames.load(Ordering::Relaxed), 0);
        server.join().unwrap();
    }
}
