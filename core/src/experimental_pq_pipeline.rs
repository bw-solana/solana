//! Bounded work services for the experimental native PQ coordinator.
//! No worker owns Quantumglow or the durable consensus signer. Execution is
//! isolated; ordered promotion adopts the exact frozen Arc without another SVM.
use {
    super::*,
    crossbeam_channel::{RecvTimeoutError, SendTimeoutError, TryRecvError, TrySendError},
};

pub(super) const MAX_PENDING_NATIVE_CANDIDATES: usize = 4;
pub(super) const MAX_STREAMING_CANDIDATES: usize = 4;
pub(super) const MAX_STREAM_EVENTS: usize = MAX_BLOCK_BYTES.div_ceil(128 * 1024) + 1;
pub(super) const MAX_STREAM_FRAMES: usize = MAX_BLOCK_BYTES.div_ceil(2048) + 1;

pub(super) struct Worker<J, O> {
    requests: Option<Sender<J>>,
    results: Receiver<Result<O>>,
    thread: Option<JoinHandle<()>>,
    pub busy: bool,
}
impl<J: Send + 'static, O: Send + 'static> Worker<J, O> {
    fn new(name: &str, execute: impl Fn(J) -> Result<O> + Send + 'static) -> Result<Self> {
        let (requests, incoming) = bounded(1);
        let (outgoing, results) = bounded(1);
        let thread = thread::Builder::new().name(name.into()).spawn(move || {
            while let Ok(job) = incoming.recv() {
                if outgoing.send(execute(job)).is_err() {
                    break;
                }
            }
        })?;
        Ok(Self {
            requests: Some(requests),
            results,
            thread: Some(thread),
            busy: false,
        })
    }
    pub fn submit(&mut self, job: J) -> Result<()> {
        if self.busy {
            bail!(InternalPqError("PQ worker already occupied"));
        }
        match self.requests.as_ref().unwrap().try_send(job) {
            Ok(()) => {
                self.busy = true;
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                bail!(InternalPqError("PQ bounded worker queue unexpectedly full"))
            }
            Err(TrySendError::Disconnected(_)) => bail!(InternalPqError("PQ worker stopped")),
        }
    }
    pub fn poll(&mut self) -> Result<Option<O>> {
        match self.results.try_recv() {
            Ok(result) => {
                self.busy = false;
                result.map(Some)
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                bail!(InternalPqError("PQ worker disconnected or panicked"))
            }
        }
    }
    pub fn wait(&mut self, timeout: Duration) -> Result<Option<O>> {
        match self.results.recv_timeout(timeout) {
            Ok(result) => {
                self.busy = false;
                result.map(Some)
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                bail!(InternalPqError("PQ worker disconnected or panicked"))
            }
        }
    }
}
#[cfg(test)]
impl<J, O> Worker<J, O> {
    pub fn result_ready(&self) -> bool {
        !self.results.is_empty()
    }
    pub fn result_observer(&self) -> Receiver<Result<O>> {
        self.results.clone()
    }
}

impl<J, O> Drop for Worker<J, O> {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(thread) = self.thread.take() {
            // One dispatched job and one result slot ensure shutdown cannot
            // block behind an undrained stream of additional jobs.
            let _ = thread.join();
        }
    }
}

pub(super) struct PqPipeline {
    pub producer: Worker<ProducerJob, ProducerOutput>,
    // Reserved at dispatch, before any asynchronous signing intent can escape.
    // ParentReady cannot retarget this slot while its result is outstanding.
    pub producer_reservation: Option<Production>,
    pub producer_parent_sender: Sender<PrivateProducerParent>,
    pub producer_parent_receiver: Receiver<PrivateProducerParent>,
    // One extra reference to the existing producer reservation, not another Bank.
    pub private_producer_parent: Option<PrivateProducerParent>,
    pub unsigned_preparation: Worker<PreparationJob, PreparedProposal>,
    pub unsigned_reservation: Option<Production>,
    pub unsigned_ready: Option<PreparedProposal>,
    pub unsigned_attempted: Option<u64>,
    pub candidate: Worker<CandidateJob, CandidateOutput>,
    pub native_parent_sender: Sender<PrivateNativeParent>,
    pub native_parent_receiver: Receiver<PrivateNativeParent>,
    // Compute-only, never visible to consensus, signing, RPC or promotion.
    // Validated, unaccepted native results are bounded separately from the
    // shared Bank limit; their independent body writer cannot stall replay.
    pub private_parents: BTreeMap<Commitment, PrivateNativeParent>,
    pub pending_candidates: VecDeque<CandidateOutput>,
    pub candidate_body: Worker<CandidateBodyJob, CandidateBodyOutput>,
    pub reconstruction: Worker<ReconstructionJob, VerifiedCandidate>,
    pub archive: Worker<FinalizationJob, FinalizationOutput>,
    pub publisher: Worker<PublicationJob, PublicationOutput>,
    pub journal: Worker<JournalJob, JournalAck>,
    pub journal_barrier: Option<JournalBarrier>,
    pub journal_sequence: u64,
    pub journal_failed: bool,
    pub executing: BTreeMap<Commitment, (u64, Commitment)>,
    pub reconstructing: Option<(u64, Commitment)>,
    pub publishing: BTreeSet<Commitment>,
    pub pending_publications: VecDeque<PublicationJob>,
    pub stream_sender: Sender<StreamBatch>,
    pub stream_receiver: Option<Receiver<StreamBatch>>,
    pub stop: Arc<AtomicBool>,
    #[cfg(test)]
    pub archive_gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub candidate_body_gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub candidate_observe_gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub producer_intent_gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub after_stream_drain_gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub journal_gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub journal_bad_ack: bool,
    #[cfg(test)]
    pub journal_service_error: Option<Sender<String>>,
    #[cfg(test)]
    pub native_bank_capacity: usize,
}
impl PqPipeline {
    pub fn new() -> Result<Self> {
        // A producer must be able to finish one bounded proposal even while
        // the coordinator services consensus/WAL work. Each event contains at
        // most 128 KiB of data in 64 authenticated 2 KiB shards. The immutable
        // 8 MiB proposal limit therefore bounds this queue to 64 such events.
        let (stream_sender, stream_receiver) = bounded(MAX_STREAM_EVENTS);
        let (native_parent_sender, native_parent_receiver) = bounded(1);
        let (producer_parent_sender, producer_parent_receiver) = bounded(1);
        Ok(Self {
            producer: Worker::new("agavePqProduce", ProducerJob::execute)?,
            producer_reservation: None,
            producer_parent_sender,
            producer_parent_receiver,
            private_producer_parent: None,
            unsigned_preparation: Worker::new("agavePqUnsigned", PreparationJob::execute)?,
            unsigned_reservation: None,
            unsigned_ready: None,
            unsigned_attempted: None,
            candidate: Worker::new("agavePqExecute", CandidateJob::execute)?,
            native_parent_sender,
            native_parent_receiver,
            private_parents: BTreeMap::new(),
            pending_candidates: VecDeque::new(),
            candidate_body: Worker::new("agavePqBodyWal", CandidateBodyJob::execute)?,
            reconstruction: Worker::new("agavePqRecover", |job: ReconstructionJob| {
                let started = Instant::now();
                let candidate = job
                    .authentication_pool
                    .install(|| job.assembler.finish_verified(job.marker))?;
                info!(
                    "PQ pipeline stage=reconstruction_ready slot={} reconstruction_us={} \
                     payload_candidate={} block_commitment={}",
                    candidate.marker().slot,
                    elapsed_us(started),
                    encode_hex(&candidate.marker().candidate),
                    encode_hex(&candidate.marker().block_commitment)
                );
                Ok(candidate)
            })?,
            archive: Worker::new("agavePqArchive", FinalizationJob::execute)?,
            publisher: Worker::new("agavePqPublish", PublicationJob::execute)?,
            journal: Worker::new("agavePqJournal", JournalJob::execute)?,
            journal_barrier: None,
            journal_sequence: 0,
            journal_failed: false,
            executing: BTreeMap::new(),
            reconstructing: None,
            publishing: BTreeSet::new(),
            pending_publications: VecDeque::new(),
            stream_sender,
            stream_receiver: Some(stream_receiver),
            stop: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            archive_gate: None,
            #[cfg(test)]
            candidate_body_gate: None,
            #[cfg(test)]
            candidate_observe_gate: None,
            #[cfg(test)]
            producer_intent_gate: None,
            #[cfg(test)]
            after_stream_drain_gate: None,
            #[cfg(test)]
            journal_gate: None,
            #[cfg(test)]
            journal_bad_ack: false,
            #[cfg(test)]
            journal_service_error: None,
            #[cfg(test)]
            native_bank_capacity: MAX_NATIVE_CANDIDATE_BANKS,
        })
    }

    pub fn unsigned_bank_reservation(&self) -> usize {
        usize::from(self.unsigned_preparation.busy || self.unsigned_ready.is_some())
    }

    pub fn candidate_bank_reservations(&self, banks: &BTreeMap<Commitment, Arc<Bank>>) -> usize {
        self.private_parents
            .keys()
            .filter(|hash| !banks.contains_key(*hash))
            .count()
            + self
                .executing
                .keys()
                .filter(|hash| {
                    !banks.contains_key(*hash) && !self.private_parents.contains_key(*hash)
                })
                .count()
    }

    #[cfg(test)]
    pub fn gate_unsigned_before_execution(
        &mut self,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        self.unsigned_preparation =
            Worker::new("agavePqUnsignedBeforeTest", move |job: PreparationJob| {
                entered.send(())?;
                release
                    .recv_timeout(Duration::from_secs(10))
                    .context("test before unsigned execution barrier")?;
                job.execute()
            })?;
        Ok(())
    }
    #[cfg(test)]
    pub fn disconnect_unsigned_requests(&mut self) {
        let (sender, receiver) = bounded(1);
        drop(receiver);
        self.unsigned_preparation.requests = Some(sender);
    }

    #[cfg(test)]
    pub fn disconnect_journal_requests(&mut self) {
        let (sender, receiver) = bounded(1);
        drop(receiver);
        self.journal.requests = Some(sender);
    }

    #[cfg(test)]
    pub fn gate_candidate_before_execution(
        &mut self,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        self.candidate = Worker::new(
            "agavePqNativeBeforeJournalTest",
            move |job: CandidateJob| {
                entered.send(())?;
                release
                    .recv_timeout(Duration::from_secs(10))
                    .context("test native work before journal barrier")?;
                job.execute()
            },
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn gate_first_unsigned_preparation(
        &mut self,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        let first = AtomicBool::new(true);
        self.unsigned_preparation =
            Worker::new("agavePqUnsignedTest", move |job: PreparationJob| {
                let output = job.execute()?;
                if first.swap(false, Ordering::AcqRel) {
                    entered.send(())?;
                    release
                        .recv_timeout(Duration::from_secs(10))
                        .context("test unsigned preparation barrier")?;
                }
                Ok(output)
            })?;
        Ok(())
    }

    #[cfg(test)]
    pub fn gate_first_publication(
        &mut self,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        let first = AtomicBool::new(true);
        self.publisher = Worker::new("agavePqPublishTest", move |job: PublicationJob| {
            if first.swap(false, Ordering::AcqRel) {
                entered.send(())?;
                release
                    .recv_timeout(Duration::from_secs(10))
                    .context("test publication barrier")?;
            }
            job.execute()
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub fn disconnect_reconstruction_requests(&mut self) {
        let (sender, receiver) = bounded(1);
        drop(receiver);
        self.reconstruction.requests = Some(sender);
    }

    #[cfg(test)]
    pub fn gate_first_finalization(
        &mut self,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        let first = AtomicBool::new(true);
        self.archive = Worker::new("agavePqArchiveBeforeTest", move |job: FinalizationJob| {
            if first.swap(false, Ordering::AcqRel) {
                entered.send(())?;
                release
                    .recv_timeout(Duration::from_secs(10))
                    .context("test pre-promotion barrier")?;
            }
            job.execute()
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub fn gate_first_production(
        &mut self,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        let first = AtomicBool::new(true);
        self.producer = Worker::new("agavePqProducerTest", move |job: ProducerJob| {
            let output = job.execute()?;
            if first.swap(false, Ordering::AcqRel) {
                entered.send(())?;
                release
                    .recv_timeout(Duration::from_secs(10))
                    .context("test producer result barrier")?;
            }
            Ok(output)
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub fn gate_production_slot(
        &mut self,
        slot: u64,
        entered: Sender<()>,
        release: Receiver<()>,
    ) -> Result<()> {
        self.producer = Worker::new("agavePqProducerDescendantTest", move |job: ProducerJob| {
            let output = job.execute()?;
            if output.production.next == slot {
                entered.send(())?;
                release
                    .recv_timeout(Duration::from_secs(10))
                    .context("test private descendant result barrier")?;
            }
            Ok(output)
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct ArchiveGate {
    pub entered: Sender<()>,
    pub release: Receiver<()>,
    pub fail: bool,
}

pub(super) struct ReconstructionJob {
    pub assembler: CandidateAssembler,
    pub marker: FinalMarker,
    pub authentication_pool: Arc<rayon::ThreadPool>,
}

/// Identifies the single immutable suffix owned by the append worker. The
/// private channel and moved bytes bind this ACK to the exact dispatched job;
/// no signer, Bank, QG state or continuation is accessible to that worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct JournalBarrier {
    pub sequence: u64,
    pub header: [u8; 53],
    pub previous_records: u32,
    pub target_records: u32,
    pub body_bytes: usize,
}
pub(super) struct JournalJob {
    pub barrier: JournalBarrier,
    pub body: Vec<u8>,
    pub finalized: Vec<(u64, Commitment)>,
    pub blockstore: Arc<Blockstore>,
    pub queued: Instant,
    #[cfg(test)]
    pub gate: Option<ArchiveGate>,
    #[cfg(test)]
    pub bad_ack: bool,
}
pub(super) struct JournalAck {
    pub barrier: JournalBarrier,
    pub append_us: u64,
    pub queue_us: u64,
}
impl JournalJob {
    fn execute(self) -> Result<JournalAck> {
        let queue_us = elapsed_us(self.queued);
        #[cfg(test)]
        if let Some(gate) = self.gate {
            gate.entered.send(())?;
            gate.release
                .recv_timeout(Duration::from_secs(10))
                .context("test journal append barrier")?;
            ensure!(!gate.fail, "test journal append failure");
        }
        ensure!(
            self.body.len() == self.barrier.body_bytes,
            InternalPqError("PQ journal immutable suffix differs")
        );
        let started = Instant::now();
        self.blockstore.append_experimental_pq_checkpoint(
            &self.barrier.header,
            self.barrier.previous_records,
            &self.body,
            &self.finalized,
        )?;
        let barrier = self.barrier;
        #[cfg(test)]
        let barrier = if self.bad_ack {
            JournalBarrier {
                target_records: barrier.target_records ^ 1,
                ..barrier
            }
        } else {
            barrier
        };
        Ok(JournalAck {
            barrier,
            append_us: elapsed_us(started),
            queue_us,
        })
    }
}
impl Drop for PqPipeline {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.stream_receiver.take();
    }
}

pub(super) struct StreamBatch {
    pub slot: u64,
    pub candidate: Commitment,
    pub frames: Vec<Arc<Vec<u8>>>,
}

fn send_stream_batch(
    sender: &Sender<StreamBatch>,
    stop: &AtomicBool,
    mut event: StreamBatch,
) -> Result<u64> {
    let started = Instant::now();
    loop {
        ensure!(
            !stop.load(Ordering::Acquire),
            "PQ producer stream cancelled on shutdown"
        );
        match sender.send_timeout(event, Duration::from_millis(10)) {
            Ok(()) => return Ok(elapsed_us(started)),
            Err(SendTimeoutError::Timeout(returned)) => event = returned,
            Err(SendTimeoutError::Disconnected(_)) => {
                bail!("PQ coordinator stream receiver stopped")
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct PrivateNativeParent {
    pub block: BlockRef,
    pub payload_candidate: Commitment,
    pub parent: Commitment,
    pub bank: Arc<Bank>,
    pub state: Commitment,
    pub executed: ExecutedCandidate,
}
// Pure, local construction metadata. It cannot authenticate a received block
// or enter runtime/QG; the signed ProducerOutput must match it before reuse.
pub(super) struct PrivateProducerParent {
    pub production: Production,
    pub block: BlockRef,
    pub bank: Arc<Bank>,
    pub parent: Arc<Bank>,
    pub executed: ExecutedCandidate,
    pub candidate: Commitment,
    pub profile: Commitment,
    pub selected_ids: BTreeSet<Commitment>,
    pub rejected_ids: BTreeSet<Commitment>,
}
pub(super) struct PublicationJob {
    pub verified: VerifiedCandidate,
    pub witness: BlockWitness,
    pub blockstore: Arc<Blockstore>,
}
pub(super) struct PublicationOutput {
    pub verified: VerifiedCandidate,
    pub witness: BlockWitness,
    pub block_wal_us: u64,
}
impl PublicationJob {
    fn execute(self) -> Result<PublicationOutput> {
        let started = Instant::now();
        let bytes = self.witness.encode()?;
        let encode_us = elapsed_us(started);
        let body_started = Instant::now();
        self.blockstore.put_experimental_pq_local_block(
            self.witness.marker.slot,
            self.witness.marker.block_commitment,
            &bytes,
        )?;
        info!(
            "PQ phases stage=publisher slot={} encode_us={} slot_intent_wal_us=0 body_wal_us={} \
             atomic_local_wal=true atomic_wal_us={} total_us={}",
            self.witness.marker.slot,
            encode_us,
            elapsed_us(body_started),
            elapsed_us(body_started),
            elapsed_us(started)
        );
        Ok(PublicationOutput {
            verified: self.verified,
            witness: self.witness,
            block_wal_us: elapsed_us(started),
        })
    }
}

pub(super) struct ProducerJob {
    pub production: Production,
    pub parent: Arc<Bank>,
    pub rooted: Arc<Bank>,
    pub slot_leader: SlotLeader,
    pub chain: [u8; 32],
    pub public: ExperimentalPqConfig,
    pub entries: Vec<(Commitment, Arc<MempoolEntry>)>,
    pub executor: Arc<PqExecutor>,
    pub authentication_pool: Arc<rayon::ThreadPool>,
    pub leader: Arc<FalconKeypair>,
    pub blockstore: Arc<Blockstore>,
    pub stream_sender: Sender<StreamBatch>,
    pub producer_parent_sender: Sender<PrivateProducerParent>,
    pub stop: Arc<AtomicBool>,
    pub fixed_payload: Option<Vec<u8>>,
    pub queued_at: Instant,
    pub prepared: Option<PreparedProposal>,
    #[cfg(test)]
    pub intent_gate: Option<ArchiveGate>,
}
pub(super) struct ProducerOutput {
    pub production: Production,
    pub bank: Arc<Bank>,
    pub executed: ExecutedCandidate,
    pub archive: Arc<Vec<ExperimentalPqTransaction>>,
    pub verified: VerifiedCandidate,
    pub witness: BlockWitness,
    pub rejected: Vec<Commitment>,
    pub selected_ids: BTreeSet<Commitment>,
}
// This worker receives no signing key, Blockstore, stream sender or consensus
// machine. Its only writes are to its isolated private native Bank.
pub(super) struct PreparationJob {
    pub production: Production,
    pub parent: Arc<Bank>,
    pub rooted: Arc<Bank>,
    pub slot_leader: SlotLeader,
    pub chain: [u8; 32],
    pub public: ExperimentalPqConfig,
    pub entries: Vec<(Commitment, Arc<MempoolEntry>)>,
    pub executor: Arc<PqExecutor>,
    pub authentication_pool: Arc<rayon::ThreadPool>,
    pub stop: Arc<AtomicBool>,
    pub fixed_payload: Option<Vec<u8>>,
    pub queued_at: Instant,
    pub unsigned: bool,
}

struct PreparationExecutionSummary {
    timings: crate::experimental_pq_execution::PqExecutionTimings,
    waves: usize,
    max_parallel_transactions: usize,
    peak_active_batches: usize,
}

pub(super) struct PreparedProposal {
    pub production: Production,
    pub parent: Arc<Bank>,
    pub bank: Arc<Bank>,
    executed: ExecutedCandidate,
    payload: Vec<u8>,
    candidate: Commitment,
    prepared: Vec<PreparedBatch>,
    archive: Vec<ExperimentalPqTransaction>,
    rejected: Vec<Commitment>,
    selected_ids: BTreeSet<Commitment>,
    profile: Commitment,
    chain: [u8; 32],
    execution: PreparationExecutionSummary,
    private_child_us: u64,
    select_us: u64,
    encode_us: u64,
    payload_bind_us: u64,
    freeze_us: u64,
    prepare_us: u64,
    freeze_prepare_us: u64,
    producer_phase_overlap_us: u64,
    preparation_capability_us: u64,
    deferred_replays: usize,
    deferred_blockhashes: usize,
    rejection_reasons: BTreeMap<String, usize>,
    preparation_us: u64,
    unsigned: bool,
    ready_at: Instant,
}

pub(super) fn local_preparation_profile(public: &ExperimentalPqConfig) -> Result<Commitment> {
    Ok(hash_commitment(
        b"agave-pq-local-unsigned-profile-v1",
        &[&serde_json::to_vec(public)?],
    ))
}

impl PreparedProposal {
    #[cfg(test)]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    #[cfg(test)]
    pub fn records(&self) -> &[ExperimentalPqTransaction] {
        &self.archive
    }
    fn check_sealing_context(&self, job: &ProducerJob) -> Result<()> {
        ensure!(
            self.chain == job.chain && self.profile == local_preparation_profile(&job.public)?,
            "PQ prepared local execution profile differs"
        );
        ensure!(
            self.production.first == job.production.first
                && self.production.next == job.production.next
                && self.production.parent == job.production.parent
                && Arc::ptr_eq(&self.parent, &job.parent),
            "PQ prepared local parent/window differs"
        );
        ensure!(
            self.bank.is_frozen()
                && self.parent.is_frozen()
                && self.bank.slot() == job.production.next
                && self.bank.leader().id == job.slot_leader.id
                && self.bank.leader().vote_address == job.slot_leader.vote_address,
            "PQ prepared native Bank context differs"
        );
        ensure!(
            self.executed.chain == job.chain
                && self.executed.slot == job.production.next
                && self.executed.parent == job.production.parent
                && self.executed.parent_state == bank_state(&job.parent)
                && self.executed.state == bank_state(&self.bank)
                && self.executed.payload
                    == hash_commitment(
                        b"agave-pq-executed-payload-v1",
                        &[&job.chain, &self.payload]
                    ),
            "PQ prepared native full-state/payload capability differs"
        );
        ensure!(
            self.candidate
                == hash_commitment(
                    b"agave-pq-candidate-v1",
                    &[
                        &job.chain,
                        &job.production.next.to_le_bytes(),
                        &job.production.parent,
                        &self.payload
                    ]
                ),
            "PQ prepared local candidate identity differs"
        );
        if let Some(fixed) = &job.fixed_payload {
            ensure!(
                &self.payload == fixed,
                "PQ prepared local payload differs from immutable recovery intent"
            );
        }
        Ok(())
    }
}

impl PreparationJob {
    pub fn execute(self) -> Result<PreparedProposal> {
        let production = self.production;
        let parent = self.parent.clone();
        let slot_leader = self.slot_leader;
        ensure!(
            !self.stop.load(Ordering::Acquire),
            "PQ preparation cancelled on shutdown"
        );
        let preparation_started = Instant::now();
        info!(
            "PQ pipeline stage=preparation_started slot={} queue_wait_us={}",
            production.next,
            elapsed_us(self.queued_at)
        );
        let private_started = Instant::now();
        let bank = Arc::new(Bank::new_isolated_pq_child(
            parent.clone(),
            slot_leader,
            production.next,
        )?);
        let private_child_us = elapsed_us(private_started);
        let selection_started = Instant::now();
        let mut selected = Vec::new();
        let mut selected_ids = BTreeSet::new();
        let mut archive = Vec::new();
        let mut rejected = Vec::new();
        let mut rejection_reasons = BTreeMap::<String, usize>::new();
        let mut deferred_replays = 0usize;
        let mut deferred_blockhashes = 0usize;
        let rooted = self.rooted.clone();
        let proposal_count = self
            .public
            .proposal_max_transactions
            .unwrap_or(self.public.max_transactions);
        let proposal_bytes = self
            .public
            .proposal_target_block_bytes
            .unwrap_or(self.public.target_block_bytes);
        let mut candidates = Vec::new();
        let mut bytes = 12;
        for (id, raw) in self.entries {
            if candidates.len() >= proposal_count || bytes + raw.len() + 4 > proposal_bytes {
                break;
            }
            let rooted_processed = raw.processed(&rooted)?;
            if raw.processed(&bank)? {
                if rooted_processed {
                    rejected.push(id);
                } else {
                    deferred_replays += 1;
                }
                continue;
            }
            bytes += raw.len() + 4;
            candidates.push((id, raw, rooted_processed));
        }
        let transactions = candidates
            .iter()
            .map(|(_, raw, _)| raw.transaction.clone())
            .collect::<Vec<_>>();
        let executor = self.executor;
        let execution = executor
            .execute(&bank, &transactions)
            .context("abort entire PQ candidate after parallel native execution failure")?;
        for ((id, raw, rooted_processed), record) in candidates.into_iter().zip(execution.records) {
            match record {
                Ok(record) => {
                    selected_ids.insert(id);
                    selected.push(raw.raw.clone());
                    archive.push(record);
                }
                Err(TransactionError::AlreadyProcessed) if !rooted_processed => {
                    // Preserve a valid transaction seen only by a speculative branch.
                    deferred_replays += 1;
                }
                Err(TransactionError::BlockhashNotFound) => {
                    // An exact speculative parent may not yet contain a hash
                    // observed at another finalized RPC endpoint. This result
                    // cannot retire the admitted wire from the bounded pool.
                    deferred_blockhashes += 1;
                }
                Err(error) => {
                    *rejection_reasons.entry(error.to_string()).or_default() += 1;
                    rejected.push(id);
                }
            }
        }
        let select_us = elapsed_us(selection_started)
            .saturating_sub(execution.timings.native_us)
            .saturating_sub(execution.timings.bridge_us);
        let encode_started = Instant::now();
        let payload = encode_block(&selected)?;
        if let Some(fixed) = &self.fixed_payload {
            ensure!(
                &payload == fixed,
                "PQ recovered proposal execution differs from immutable payload intent"
            );
        }
        let encode_us = elapsed_us(encode_started);
        let payload_bind_started = Instant::now();
        let candidate = hash_commitment(
            b"agave-pq-candidate-v1",
            &[
                &self.chain,
                &production.next.to_le_bytes(),
                &production.parent,
                &payload,
            ],
        );
        let payload_bind_us = elapsed_us(payload_bind_started);
        let freeze_prepare_started = Instant::now();
        // Native execution fixed the complete payload. Native freeze/state
        // commitment and RS/Merkle construction now read independent immutable
        // inputs, so they overlap without changing either wire commitments or
        // native execution. Both finish before the frozen parent is exposed.
        let (prepared, freeze_us, prepare_us) = thread::scope(|scope| -> Result<_> {
            let freeze = scope.spawn(|| {
                let started = Instant::now();
                complete_bank(&bank, &self.chain, &production.parent, &payload);
                elapsed_us(started)
            });
            let started = Instant::now();
            let prepared = self.authentication_pool.install(|| {
                payload
                    .par_chunks(128 * 1024)
                    .map(|bytes| {
                        let data = bytes.len().div_ceil(2048).max(1) as u16;
                        PreparedBatch::prepare(bytes, data, data)
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()
            })?;
            let prepare_us = elapsed_us(started);
            let freeze_us = freeze
                .join()
                .map_err(|_| anyhow!("PQ native freeze worker panicked"))?;
            Ok((prepared, freeze_us, prepare_us))
        })?;
        let freeze_prepare_us = elapsed_us(freeze_prepare_started);
        let producer_phase_overlap_us = freeze_us
            .saturating_add(prepare_us)
            .saturating_sub(freeze_prepare_us);
        let capability_started = Instant::now();
        let executed =
            ExecutedCandidate::new(self.chain, production.parent, &parent, &bank, &payload)?;
        bank.detach_isolated_pq_parent()?;
        let preparation_capability_us = elapsed_us(capability_started);
        let profile = local_preparation_profile(&self.public)?;
        let preparation_us = elapsed_us(preparation_started);
        info!(
            "PQ pipeline stage=preparation_ready slot={} parent={} unsigned={} elapsed_us={} \
             native_execute_us={} bridge_us={}",
            production.next,
            encode_hex(&production.parent),
            usize::from(self.unsigned),
            preparation_us,
            execution.timings.native_us,
            execution.timings.bridge_us
        );
        ensure!(
            !self.stop.load(Ordering::Acquire),
            "PQ preparation cancelled on shutdown"
        );
        Ok(PreparedProposal {
            production,
            parent,
            bank,
            executed,
            payload,
            candidate,
            prepared,
            archive,
            rejected,
            selected_ids,
            profile,
            chain: self.chain,
            execution: PreparationExecutionSummary {
                timings: execution.timings,
                waves: execution.waves,
                max_parallel_transactions: execution.max_parallel_transactions,
                peak_active_batches: execution.peak_active_batches,
            },
            private_child_us,
            select_us,
            encode_us,
            payload_bind_us,
            freeze_us,
            prepare_us,
            freeze_prepare_us,
            producer_phase_overlap_us,
            preparation_capability_us,
            deferred_replays,
            deferred_blockhashes,
            rejection_reasons,
            preparation_us,
            unsigned: self.unsigned,
            ready_at: Instant::now(),
        })
    }
}

impl ProducerJob {
    fn execute(mut self) -> Result<ProducerOutput> {
        let production = self.production;
        info!(
            "PQ pipeline stage=producer_started slot={} queue_wait_us={}",
            production.next,
            elapsed_us(self.queued_at)
        );
        let proposal = match self.prepared.take() {
            Some(proposal) => proposal,
            None => PreparationJob {
                production,
                parent: self.parent.clone(),
                rooted: self.rooted.clone(),
                slot_leader: self.slot_leader,
                chain: self.chain,
                public: self.public.clone(),
                entries: std::mem::take(&mut self.entries),
                executor: self.executor.clone(),
                authentication_pool: self.authentication_pool.clone(),
                stop: self.stop.clone(),
                fixed_payload: self.fixed_payload.clone(),
                queued_at: self.queued_at,
                unsigned: false,
            }
            .execute()?,
        };
        proposal.check_sealing_context(&self)?;
        let predicted = if production.next + 1 < production.first + self.public.window_size {
            Some(prepared_block_commitment(
                BatchContext {
                    leader_epoch: self.public.epoch,
                    slot: production.next,
                    candidate: proposal.candidate,
                    parent: production.parent,
                    batch_index: 0,
                    previous: [0; 48],
                },
                &proposal.prepared,
                &proposal.payload,
            )?)
        } else {
            None
        };
        if let Some(predicted) = predicted {
            self.producer_parent_sender
                .try_send(PrivateProducerParent {
                    production,
                    block: BlockRef {
                        slot: production.next,
                        hash: predicted,
                    },
                    bank: proposal.bank.clone(),
                    parent: proposal.parent.clone(),
                    executed: proposal.executed.clone(),
                    candidate: proposal.candidate,
                    profile: proposal.profile,
                    selected_ids: proposal.selected_ids.clone(),
                    rejected_ids: proposal.rejected.iter().copied().collect(),
                })
                .map_err(|_| {
                    InternalPqError("PQ bounded private producer capability unavailable")
                })?;
            info!(
                "PQ pipeline stage=producer_parent_ready slot={} block_commitment={} \
                 payload_candidate={} parent={} durable=0",
                production.next,
                encode_hex(&predicted),
                encode_hex(&proposal.candidate),
                encode_hex(&production.parent)
            );
        }
        let prepared_wait_us = elapsed_us(proposal.ready_at);
        let PreparedProposal {
            production: _,
            parent: _,
            bank,
            executed,
            payload,
            candidate,
            prepared,
            archive,
            rejected,
            selected_ids,
            profile: _,
            chain: _,
            execution,
            private_child_us,
            select_us,
            encode_us,
            payload_bind_us,
            freeze_us,
            prepare_us,
            freeze_prepare_us,
            producer_phase_overlap_us,
            preparation_capability_us,
            deferred_replays,
            deferred_blockhashes,
            rejection_reasons,
            preparation_us,
            unsigned,
            ready_at: _,
        } = proposal;
        let selected_count = archive.len();
        let sealing_started = Instant::now();
        ensure!(
            !self.stop.load(Ordering::Acquire),
            "PQ sealing cancelled before durable intent"
        );
        let intent_started = Instant::now();
        #[cfg(test)]
        if let Some(gate) = &self.intent_gate {
            gate.entered.send(())?;
            gate.release
                .recv_timeout(Duration::from_secs(10))
                .context("test producer intent WAL barrier")?;
            ensure!(!gate.fail, "injected producer intent WAL failure");
        }
        self.blockstore.put_experimental_pq_proposal_intent(
            &solana_ledger::blockstore::ExperimentalPqProposalIntent {
                chain: self.chain,
                epoch: self.public.epoch,
                slot: production.next,
                parent: production.parent,
                candidate,
                payload: payload.clone(),
            },
        )?;
        let intent_wal_us = elapsed_us(intent_started);
        let seal_started = Instant::now();
        let mut seal_sign_us = 0u64;
        let mut frame_encode_us = 0u64;
        let mut stream_queue_wait_us = 0u64;
        let mut batches = Vec::new();
        let mut previous = [0; 48];
        for (index, prepared) in prepared.into_iter().enumerate() {
            let sign_started = Instant::now();
            let batch = prepared.seal_local(
                &self.chain,
                &self.leader,
                BatchContext {
                    leader_epoch: self.public.epoch,
                    slot: production.next,
                    candidate,
                    parent: production.parent,
                    batch_index: index as u32,
                    previous,
                },
            )?;
            seal_sign_us = seal_sign_us.saturating_add(elapsed_us(sign_started));
            previous = batch.commitment();
            let encode_started = Instant::now();
            let frames = batch
                .data_shreds()
                .iter()
                .map(|shred| {
                    let mut frame = vec![1];
                    frame.extend(shred.encode()?);
                    Ok(Arc::new(frame))
                })
                .collect::<Result<Vec<_>>>()?;
            frame_encode_us = frame_encode_us.saturating_add(elapsed_us(encode_started));
            let event = StreamBatch {
                slot: production.next,
                candidate,
                frames,
            };
            stream_queue_wait_us = stream_queue_wait_us.saturating_add(send_stream_batch(
                &self.stream_sender,
                &self.stop,
                event,
            )?);
            batches.push(batch);
        }
        let seal_us = elapsed_us(seal_started);
        let terminal_started = Instant::now();
        let verified =
            FinalMarker::build_local_verified(&self.chain, &self.leader, batches, payload)?;
        let payload = verified.payload();
        let terminal_us = elapsed_us(terminal_started);
        let capability_started = Instant::now();
        let marker = verified.marker().clone();
        if let Some(predicted) = predicted {
            ensure!(
                marker.block_commitment == predicted,
                "PQ sealed block differs from predicted private parent"
            );
        }
        // The exact complete payload intent is already synced before any
        // signing. Its signed terminal can follow the DATA immediately; the
        // redundant body publisher/journal only gate local observation/votes.
        let mut terminal = vec![2];
        terminal.extend(marker.encode());
        stream_queue_wait_us = stream_queue_wait_us.saturating_add(send_stream_batch(
            &self.stream_sender,
            &self.stop,
            StreamBatch {
                slot: production.next,
                candidate,
                frames: vec![Arc::new(terminal)],
            },
        )?);
        let witness = BlockWitness {
            marker: marker.clone(),
            shreds: verified.shreds().to_vec(),
        };
        info!(
            "PQ pipeline stage=terminal_stream_enqueued slot={} payload_candidate={} \
             block_commitment={}",
            production.next,
            encode_hex(&marker.candidate),
            encode_hex(&marker.block_commitment)
        );
        let capability_us =
            preparation_capability_us.saturating_add(elapsed_us(capability_started));
        info!(
            "PQ pipeline stage=sealing_complete slot={} reused_unsigned={} preparation_us={} \
             prepared_wait_us={} sealing_us={}",
            production.next,
            usize::from(unsigned),
            preparation_us,
            prepared_wait_us,
            elapsed_us(sealing_started)
        );
        info!(
            "PQ phases stage=producer slot={} transactions={} bytes={} private_child_us={} \
             native_execute_us={} bridge_us={} select_us={} encode_us={} freeze_us={} \
             payload_bind_us={} prepare_us={} seal_us={} terminal_us={} capability_us={} \
             persist_publish_us={} native_worker_us={} parallel_waves={} \
             max_parallel_transactions={} peak_active_batches={} freeze_prepare_us={} \
             producer_phase_overlap_us={} seal_sign_us={} frame_encode_us={} \
             stream_queue_wait_us={} native_prepare_us={} native_access_discovery_us={} \
             native_cost_reserve_us={} native_pool_dispatch_join_us={} native_reconcile_us={} \
             native_pool_overhead_us={} native_bridge_residual_us={} total_us={}",
            production.next,
            selected_count,
            payload.len(),
            private_child_us,
            execution.timings.native_us,
            execution.timings.bridge_us,
            select_us,
            encode_us,
            freeze_us,
            payload_bind_us,
            prepare_us,
            seal_us,
            terminal_us,
            capability_us,
            intent_wal_us,
            execution.timings.native_worker_us,
            execution.waves,
            execution.max_parallel_transactions,
            execution.peak_active_batches,
            freeze_prepare_us,
            producer_phase_overlap_us,
            seal_sign_us,
            frame_encode_us,
            stream_queue_wait_us,
            execution.timings.prepare_us,
            execution.timings.access_discovery_us,
            execution.timings.cost_reserve_us,
            execution.timings.pool_dispatch_join_us,
            execution.timings.reconcile_us,
            execution.timings.pool_overhead_us,
            execution.timings.bridge_residual_us,
            preparation_us.saturating_add(elapsed_us(sealing_started))
        );
        info!(
            "PQ proposed slot={} transactions={} bytes={} elapsed_ms={} deferred_replays={} \
             deferred_blockhashes={}",
            production.next,
            selected_count,
            payload.len(),
            u128::from(preparation_us.saturating_add(elapsed_us(sealing_started))) / 1000,
            deferred_replays,
            deferred_blockhashes
        );
        if !rejection_reasons.is_empty() {
            warn!(
                "PQ noncommitted proposal rejections at slot {}: {:?}",
                production.next, rejection_reasons
            );
        }
        info!(
            "PQ pipeline stage=producer_ready slot={} elapsed_us={}",
            production.next,
            preparation_us.saturating_add(elapsed_us(sealing_started))
        );
        Ok(ProducerOutput {
            production,
            bank,
            executed,
            archive: Arc::new(archive),
            verified,
            witness,
            rejected,
            selected_ids,
        })
    }
}

pub(super) struct CandidateJob {
    pub witness: BlockWitness,
    pub candidate: VerifiedCandidate,
    pub parent: Arc<Bank>,
    pub parent_state: Commitment,
    pub chain: [u8; 32],
    pub leaders: Vec<SlotLeader>,
    pub first_slot: u64,
    pub max_block_bytes: usize,
    pub max_transactions: usize,
    pub executor: Arc<PqExecutor>,
    pub native_parent_sender: Sender<PrivateNativeParent>,
    pub stop: Arc<AtomicBool>,
}
pub(super) struct CandidateOutput {
    pub witness: BlockWitness,
    pub candidate: VerifiedCandidate,
    pub bank: Arc<Bank>,
    pub parent: Arc<Bank>,
    pub state: Commitment,
    pub executed: ExecutedCandidate,
    pub archive: Arc<Vec<ExperimentalPqTransaction>>,
    pub started: Instant,
    pub block_wal_us: u64,
    pub encoded_witness: Option<Vec<u8>>,
    pub body_durable: bool,
}
impl CandidateJob {
    fn execute(self) -> Result<CandidateOutput> {
        let started = Instant::now();
        let hash = self.witness.marker.block_commitment;
        let parent_hash = self.witness.marker.parent;
        let parent = self.parent.clone();
        let mut runtime = RuntimeForks {
            banks: BTreeMap::from([(parent_hash, self.parent)]),
            states: BTreeMap::from([(parent_hash, self.parent_state)]),
            executions: BTreeMap::new(),
            archives: BTreeMap::new(),
            leaders: self.leaders,
            first_slot: self.first_slot,
            chain: self.chain,
            max_block_bytes: self.max_block_bytes,
            max_transactions: self.max_transactions,
            executor: self.executor,
        };
        // Encoding immutable, authenticated bytes can overlap native replay.
        // Invalid native execution still cannot write a normal durable body.
        let bytes = thread::scope(|scope| -> Result<Vec<u8>> {
            let encoded = scope.spawn(|| self.witness.encode());
            let validation = runtime.validate_checked(&ExecutionCandidate {
                reference: BlockRef {
                    slot: self.witness.marker.slot,
                    hash,
                },
                parent: parent_hash,
                payload: self.candidate.payload(),
            });
            let bytes = encoded
                .join()
                .map_err(|_| InternalPqError("PQ candidate encoding worker panicked"))??;
            validation?;
            Ok(bytes)
        })?;
        ensure!(
            !self.stop.load(Ordering::Acquire),
            "PQ native candidate cancelled before private capability"
        );
        self.native_parent_sender
            .try_send(PrivateNativeParent {
                block: BlockRef {
                    slot: self.witness.marker.slot,
                    hash,
                },
                parent: parent_hash,
                payload_candidate: self.witness.marker.candidate,
                bank: runtime.banks[&hash].clone(),
                state: runtime.states[&hash],
                executed: runtime.executions[&hash].clone(),
            })
            .map_err(|_| InternalPqError("PQ private native capability channel unavailable"))?;
        Ok(CandidateOutput {
            witness: self.witness,
            candidate: self.candidate,
            bank: runtime.banks.remove(&hash).unwrap(),
            parent,
            state: runtime.states[&hash],
            executed: runtime.executions.remove(&hash).unwrap(),
            archive: runtime.archives.remove(&hash).unwrap(),
            started,
            block_wal_us: 0,
            encoded_witness: Some(bytes),
            body_durable: false,
        })
    }
}

pub(super) struct CandidateBodyJob {
    pub block: BlockRef,
    pub payload_candidate: Commitment,
    pub bytes: Vec<u8>,
    pub blockstore: Arc<Blockstore>,
    pub stop: Arc<AtomicBool>,
    #[cfg(test)]
    pub gate: Option<ArchiveGate>,
}
pub(super) struct CandidateBodyOutput {
    pub block: BlockRef,
    pub block_wal_us: u64,
}
impl CandidateBodyJob {
    fn execute(self) -> Result<CandidateBodyOutput> {
        #[cfg(test)]
        if let Some(gate) = self.gate {
            gate.entered.send(())?;
            gate.release
                .recv_timeout(Duration::from_secs(10))
                .context("test candidate body durability barrier")?;
        }
        ensure!(
            !self.stop.load(Ordering::Acquire),
            "PQ native candidate cancelled before body WAL"
        );
        let started = Instant::now();
        self.blockstore
            .put_experimental_pq_block(self.block.slot, self.block.hash, &self.bytes)?;
        let block_wal_us = elapsed_us(started);
        info!(
            "PQ pipeline stage=candidate_body_durable slot={} payload_candidate={} \
             block_commitment={} body_wal_us={}",
            self.block.slot,
            encode_hex(&self.payload_candidate),
            encode_hex(&self.block.hash),
            block_wal_us
        );
        Ok(CandidateBodyOutput {
            block: self.block,
            block_wal_us,
        })
    }
}

pub(super) struct FinalizationJob {
    pub block: BlockRef,
    pub candidate: Arc<Bank>,
    pub parent: Arc<Bank>,
    pub parent_commitment: Commitment,
    pub parent_state: Commitment,
    pub chain: [u8; 32],
    pub payload: Vec<u8>,
    pub executed: ExecutedCandidate,
    pub records: Arc<Vec<ExperimentalPqTransaction>>,
    pub bank_forks: Arc<RwLock<BankForks>>,
    pub blockstore: Arc<Blockstore>,
    #[cfg(test)]
    pub archive_gate: Option<ArchiveGate>,
}
pub(super) struct FinalizationOutput {
    pub block: BlockRef,
    pub bank: Arc<Bank>,
    pub records: Arc<Vec<ExperimentalPqTransaction>>,
    pub promotion_us: u64,
    pub archive_wal_us: u64,
    pub started: Instant,
}
impl FinalizationJob {
    fn execute(self) -> Result<FinalizationOutput> {
        let started = Instant::now();
        info!(
            "PQ pipeline stage=finalize_started slot={}",
            self.block.slot
        );
        let parent_state = self.parent.pq_state_commitment();
        ensure!(
            parent_state == self.parent_state,
            "PQ native root differs from certified replay parent"
        );
        ensure!(
            self.executed.matches(
                &self.chain,
                &ExecutionCandidate {
                    reference: self.block,
                    parent: self.parent_commitment,
                    payload: &self.payload,
                },
                &parent_state,
                &self.candidate.pq_state_commitment()
            ),
            "PQ finalized payload, parent, Bank or execution state differs from certificate"
        );
        ensure!(
            self.candidate
                .transaction_count()
                .checked_sub(self.parent.transaction_count())
                == Some(self.records.len() as u64),
            "PQ finalized native transaction count differs"
        );
        let (bank, promotion_us, archive_wal_us) = promote_and_archive_with_hook(
            &self.bank_forks,
            &self.blockstore,
            self.block,
            self.candidate,
            parent_state,
            self.parent.last_blockhash(),
            &self.records,
            || {
                #[cfg(test)]
                if let Some(gate) = self.archive_gate {
                    gate.entered.send(())?;
                    gate.release
                        .recv_timeout(Duration::from_secs(10))
                        .context("test post-promotion archive barrier")?;
                    ensure!(
                        !gate.fail,
                        "test archive WAL failure after native promotion"
                    );
                }
                Ok(())
            },
        )?;
        Ok(FinalizationOutput {
            block: self.block,
            bank,
            records: self.records,
            promotion_us,
            archive_wal_us,
            started,
        })
    }
}
