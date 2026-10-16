//! Service to clean up dead slots in accounts_db
//!
//! This can be expensive since we have to walk the append vecs being cleaned up.

mod pending_snapshot_packages;
mod stats;
pub use pending_snapshot_packages::PendingSnapshotPackages;
#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    crate::{
        bank::{Bank, BankId, BankSlotDelta, DropCallback},
        bank_forks::BankForks,
        snapshot_controller::SnapshotController,
        snapshot_package::SnapshotPackage,
    },
    agave_snapshots::{SnapshotArchiveKind, SnapshotKind, error::SnapshotError},
    crossbeam_channel::{Receiver, SendError, Sender},
    log::*,
    solana_clock::Slot,
    solana_measure::{measure::Measure, measure_us},
    stats::StatsManager,
    std::{
        boxed::Box,
        cmp,
        fmt::{self, Debug, Formatter},
        sync::{
            Arc, LazyLock, Mutex, RwLock,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread::{self, Builder, JoinHandle, sleep},
        time::{Duration, Instant},
    },
};

/// Limit the maximum frequency that the ABS main loop can run.
/// If the loop ran for less than this duration, sleep the remainder.
/// E.g. with a min interval of 100 millis, the loop will run a maximum
/// of 10 times per second.  Lower frequency is allowed, and occurs
/// when longer-running tasks are triggered.
const MIN_LOOP_INTERVAL: Duration = Duration::from_millis(100);
// Set the clean interval duration to be approximately how long before the next incremental
// snapshot request is received, plus some buffer.  The default incremental snapshot interval is
// 200 slots, which ends up being 50 seconds plus buffer.
const CLEAN_INTERVAL: Duration = Duration::from_secs(60);
const SHRINK_INTERVAL: Duration = Duration::from_secs(1);

// The caller supplies the actual canonical root and preserves the snapshot
// clean barrier. Speculative Bank drop/scan operations must use their local DB.
fn maintain_root_accounts(
    bank: &Bank,
    max_clean_slot_inclusive: Slot,
    should_clean: bool,
    should_shrink: bool,
) {
    let accounts_db = bank.rc.accounts.accounts_db.pq_storage_db();
    accounts_db.flush_accounts_cache(should_clean, Some(max_clean_slot_inclusive));
    if should_clean {
        accounts_db.clean_accounts(max_clean_slot_inclusive);
    }
    if should_shrink || should_clean {
        if should_clean {
            bank.shrink_ancient_slots();
        }
        bank.shrink_candidate_slots();
    }
}

pub type SnapshotRequestSender = Sender<SnapshotRequest>;
pub type SnapshotRequestReceiver = Receiver<SnapshotRequest>;
pub type DroppedSlotsSender = Sender<(Slot, BankId)>;
pub type DroppedSlotsReceiver = Receiver<(Slot, BankId)>;

/// interval to report bank_drop queue events: 60s
const BANK_DROP_SIGNAL_CHANNEL_REPORT_INTERVAL: u64 = 60_000;
/// maximum drop bank signal queue length
const MAX_DROP_BANK_SIGNAL_QUEUE_SIZE: usize = 10_000;

#[derive(Debug, Default)]
struct PrunedBankQueueLenReporter {
    last_report_time: AtomicU64,
}

impl PrunedBankQueueLenReporter {
    fn report(&self, q_len: usize) {
        let now = solana_time_utils::timestamp();
        let last_report_time = self.last_report_time.load(Ordering::Acquire);
        if q_len > MAX_DROP_BANK_SIGNAL_QUEUE_SIZE
            && now.saturating_sub(last_report_time) > BANK_DROP_SIGNAL_CHANNEL_REPORT_INTERVAL
        {
            datapoint_warn!("excessive_pruned_bank_channel_len", ("len", q_len, i64));
            self.last_report_time.store(now, Ordering::Release);
        }
    }
}

static BANK_DROP_QUEUE_REPORTER: LazyLock<PrunedBankQueueLenReporter> =
    LazyLock::new(PrunedBankQueueLenReporter::default);

#[derive(Clone)]
pub struct SendDroppedBankCallback {
    sender: DroppedSlotsSender,
}

impl DropCallback for SendDroppedBankCallback {
    fn callback(&self, bank: &Bank) {
        BANK_DROP_QUEUE_REPORTER.report(self.sender.len());
        if let Err(SendError(_)) = self.sender.send((bank.slot(), bank.bank_id())) {
            info!("bank DropCallback signal queue disconnected.");
        }
    }

    fn clone_box(&self) -> Box<dyn DropCallback + Send + Sync> {
        Box::new(self.clone())
    }
}

impl Debug for SendDroppedBankCallback {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "SendDroppedBankCallback({self:p})")
    }
}

impl SendDroppedBankCallback {
    pub fn new(sender: DroppedSlotsSender) -> Self {
        Self { sender }
    }
}

pub struct SnapshotRequest {
    pub snapshot_root_bank: Arc<Bank>,
    pub status_cache_slot_deltas: Vec<BankSlotDelta>,
    pub request_kind: SnapshotRequestKind,

    /// The instant this request was send to the queue.
    /// Used to track how long requests wait before processing.
    pub enqueued: Instant,
}

impl Debug for SnapshotRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotRequest")
            .field("request kind", &self.request_kind)
            .field("bank slot", &self.snapshot_root_bank.slot())
            .field("block height", &self.snapshot_root_bank.block_height())
            .finish_non_exhaustive()
    }
}

/// What kind of request is this?
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SnapshotRequestKind {
    FullSnapshot,
    IncrementalSnapshot,
    FastbootSnapshot,
}

pub struct SnapshotRequestHandler {
    pub snapshot_controller: Arc<SnapshotController>,
    pub snapshot_request_receiver: SnapshotRequestReceiver,
    pub pending_snapshot_packages: Arc<Mutex<PendingSnapshotPackages>>,
}

impl SnapshotRequestHandler {
    // Returns the latest requested snapshot slot and storages
    pub fn handle_snapshot_requests(
        &self,
        non_snapshot_time_us: u128,
    ) -> Option<Result<Slot, SnapshotError>> {
        let (snapshot_request, num_outstanding_requests, num_re_enqueued_requests) =
            self.get_next_snapshot_request()?;

        datapoint_info!(
            "handle_snapshot_requests",
            ("num_outstanding_requests", num_outstanding_requests, i64),
            ("num_re_enqueued_requests", num_re_enqueued_requests, i64),
            (
                "enqueued_time_us",
                snapshot_request.enqueued.elapsed().as_micros(),
                i64
            ),
        );

        let snapshot_kind = new_snapshot_kind(&snapshot_request)?;
        Some(self.handle_snapshot_request(non_snapshot_time_us, snapshot_request, snapshot_kind))
    }

    /// Get the next snapshot request to handle
    ///
    /// Look through the snapshot request channel to find the highest priority one to handle next.
    /// If there are no snapshot requests in the channel, return None.  Otherwise return the
    /// highest priority one.  Unhandled snapshot requests with slots GREATER-THAN the handled one
    /// will be re-enqueued.  The remaining will be dropped.
    ///
    /// Also return the number of snapshot requests initially in the channel, and the number of
    /// ones re-enqueued.
    fn get_next_snapshot_request(
        &self,
    ) -> Option<(
        SnapshotRequest,
        /*num outstanding snapshot requests*/ usize,
        /*num re-enqueued snapshot requests*/ usize,
    )> {
        let mut requests: Vec<_> = self.snapshot_request_receiver.try_iter().collect();
        let requests_len = requests.len();
        debug!("outstanding snapshot requests ({requests_len}): {requests:?}");

        match requests_len {
            0 => None,
            1 => {
                // SAFETY: We know the len is 1, so `pop` will return `Some`
                let snapshot_request = requests.pop().unwrap();
                Some((snapshot_request, 1, 0))
            }
            _ => {
                let max_idx = requests
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| cmp_requests_by_priority(a, b))
                    .map(|(idx, _)| idx)
                    .unwrap(); // SAFETY: We know len > 1
                let snapshot_request = requests.swap_remove(max_idx);
                let handled_request_slot = snapshot_request.snapshot_root_bank.slot();
                // re-enqueue any remaining requests for slots GREATER-THAN the one that will be handled
                let num_re_enqueued_requests = requests
                    .into_iter()
                    .filter(|snapshot_request| {
                        snapshot_request.snapshot_root_bank.slot() > handled_request_slot
                    })
                    .map(|snapshot_request| {
                        self.snapshot_controller
                            .request_sender()
                            .try_send(snapshot_request)
                            .expect("re-enqueue snapshot request");
                    })
                    .count();

                Some((snapshot_request, requests_len, num_re_enqueued_requests))
            }
        }
    }

    fn handle_snapshot_request(
        &self,
        non_snapshot_time_us: u128,
        snapshot_request: SnapshotRequest,
        snapshot_kind: SnapshotKind,
    ) -> Result<Slot, SnapshotError> {
        info!("handling snapshot request: {snapshot_request:?}, {snapshot_kind:?}");
        let mut total_time = Measure::start("snapshot_request_receiver_total_time");
        let SnapshotRequest {
            snapshot_root_bank,
            status_cache_slot_deltas,
            request_kind: _,
            enqueued: _,
        } = snapshot_request;
        let accounts_db = snapshot_root_bank.rc.accounts.accounts_db.pq_storage_db();

        if snapshot_kind.is_full_snapshot() {
            // The latest full snapshot slot is what accounts-db uses to properly handle
            // zero lamport accounts.  We are handling a full snapshot request here, and
            // since taking a snapshot is not allowed to fail, we can update accounts-db now.
            accounts_db.set_latest_full_snapshot_slot(snapshot_root_bank.slot());
        }

        let mut flush_accounts_cache_time = Measure::start("flush_accounts_cache_time");
        // Forced cache flushing MUST flush all roots <= snapshot_root_bank.slot().
        // That's because `snapshot_root_bank.slot()` must be root at this point,
        // and contains relevant updates because each bank has at least 1 account update due
        // to sysvar maintenance. Otherwise, this would cause missing storages in the snapshot
        snapshot_root_bank.force_flush_accounts_cache();
        // Ensure all roots <= `self.slot()` have been flushed.
        // Note `max_flush_root` could be larger than self.slot() if there are
        // `> MAX_CACHE_SLOT` cached and rooted slots which triggered earlier flushes.
        assert!(
            snapshot_root_bank.slot()
                <= accounts_db
                    .accounts_cache
                    .fetch_max_flush_root()
                    .expect("Roots have been flushed")
        );
        flush_accounts_cache_time.stop();

        let mut clean_time = Measure::start("clean_time");
        snapshot_root_bank.clean_accounts();
        clean_time.stop();

        let (_, shrink_ancient_time_us) =
            measure_us!(accounts_db.shrink_ancient_slots(snapshot_root_bank.epoch_schedule()));

        let mut shrink_time = Measure::start("shrink_time");
        snapshot_root_bank.shrink_candidate_slots();
        shrink_time.stop();

        // Snapshot the bank and send over a snapshot package
        let mut snapshot_time = Measure::start("snapshot_time");
        let snapshot_package = SnapshotPackage::new(
            snapshot_kind,
            &snapshot_root_bank,
            snapshot_root_bank.get_snapshot_storages(None),
            status_cache_slot_deltas,
        );
        self.pending_snapshot_packages
            .lock()
            .unwrap()
            .push(snapshot_package);
        snapshot_time.stop();
        info!(
            "Handled snapshot request. snapshot kind: {:?}, slot: {}, bank hash: {}",
            snapshot_kind,
            snapshot_root_bank.slot(),
            snapshot_root_bank.hash(),
        );

        total_time.stop();

        datapoint_info!(
            "handle_snapshot_requests-timing",
            (
                "flush_accounts_cache_time",
                flush_accounts_cache_time.as_us(),
                i64
            ),
            ("shrink_time", shrink_time.as_us(), i64),
            ("clean_time", clean_time.as_us(), i64),
            ("snapshot_time", snapshot_time.as_us(), i64),
            ("total_us", total_time.as_us(), i64),
            ("non_snapshot_time_us", non_snapshot_time_us, i64),
            ("shrink_ancient_time_us", shrink_ancient_time_us, i64),
        );
        Ok(snapshot_root_bank.slot())
    }

    /// Returns the slot of the next snapshot request to be handled
    fn peek_next_snapshot_request_slot(&self) -> Option<Slot> {
        // We reuse `get_next_snapshot_request()` here, since it already implements all the logic
        // for getting the highest priority request, *AND* we leverage its test coverage.
        // Additionally, since `get_next_snapshot_request()` drops old requests, we might get to
        // proactively clean up old banks earlier as well!
        let (next_request, _, _) = self.get_next_snapshot_request()?;
        let next_slot = next_request.snapshot_root_bank.slot();

        // make sure to re-enqueue the request, otherwise we'd lose it!
        self.snapshot_controller
            .request_sender()
            .try_send(next_request)
            .expect("re-enqueue snapshot request");

        Some(next_slot)
    }
}

#[derive(Debug)]
pub struct PrunedBanksRequestHandler {
    pub pruned_banks_receiver: DroppedSlotsReceiver,
}

impl PrunedBanksRequestHandler {
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn handle_request(&self, bank: &Bank) -> usize {
        let mut banks_to_purge: Vec<_> = self.pruned_banks_receiver.try_iter().collect();
        // We need a stable sort to ensure we purge banks—with the same slot—in the same order
        // they were sent into the channel.
        banks_to_purge.sort_by_key(|(slot, _id)| *slot);
        let num_banks_to_purge = banks_to_purge.len();

        // Group the banks into slices with the same slot
        let grouped_banks_to_purge: Vec<_> = banks_to_purge.chunk_by(|a, b| a.0 == b.0).collect();

        // Log whenever we need to handle banks with the same slot.  Purposely do this *before* we
        // call `purge_slot()` to ensure we get the datapoint (in case there's an assert/panic).
        let num_banks_with_same_slot =
            num_banks_to_purge.saturating_sub(grouped_banks_to_purge.len());
        if num_banks_with_same_slot > 0 {
            datapoint_info!(
                "pruned_banks_request_handler",
                ("num_pruned_banks", num_banks_to_purge, i64),
                ("num_banks_with_same_slot", num_banks_with_same_slot, i64),
            );
        }

        // Banks for the same slot are purged sequentially
        // This queue contains native startup Bank callbacks. Private PQ
        // candidates install their own local callback and never enter it.
        let accounts_db = bank.rc.accounts.accounts_db.pq_storage_db();
        grouped_banks_to_purge.into_iter().for_each(|group| {
            group.iter().for_each(|(slot, bank_id)| {
                accounts_db.purge_slot(*slot, *bank_id, true);
            })
        });
        num_banks_to_purge
    }

    fn remove_dead_slots(
        &self,
        bank: &Bank,
        removed_slots_count: &mut usize,
        total_remove_slots_time: &mut u64,
    ) {
        let mut remove_slots_time = Measure::start("remove_slots_time");
        *removed_slots_count += self.handle_request(bank);
        remove_slots_time.stop();
        *total_remove_slots_time += remove_slots_time.as_us();

        if *removed_slots_count >= 100 {
            datapoint_info!(
                "remove_slots_timing",
                ("remove_slots_time", *total_remove_slots_time, i64),
                ("removed_slots_count", *removed_slots_count, i64),
            );
            *total_remove_slots_time = 0;
            *removed_slots_count = 0;
        }
    }
}

pub struct AbsRequestHandlers {
    pub snapshot_request_handler: SnapshotRequestHandler,
    pub pruned_banks_request_handler: PrunedBanksRequestHandler,
}

impl AbsRequestHandlers {
    // Returns the latest requested snapshot slot, if one exists
    pub fn handle_snapshot_requests(
        &self,
        non_snapshot_time_us: u128,
    ) -> Option<Result<Slot, SnapshotError>> {
        self.snapshot_request_handler
            .handle_snapshot_requests(non_snapshot_time_us)
    }
}

pub struct AccountsBackgroundService {
    t_background: JoinHandle<()>,
    status: AbsStatus,
}

impl AccountsBackgroundService {
    pub fn new(
        bank_forks: Arc<RwLock<BankForks>>,
        exit: Arc<AtomicBool>,
        request_handlers: AbsRequestHandlers,
    ) -> Self {
        let is_running = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let mut last_cleaned_slot = 0;
        let mut removed_slots_count = 0;
        let mut total_remove_slots_time = 0;
        let t_background = Builder::new()
            .name("solAcctsBgSvc".to_string())
            .spawn({
                let is_running = is_running.clone();
                let stop = stop.clone();

                move || {
                    info!("AccountsBackgroundService has started");
                    let mut stats = StatsManager::new();
                    let mut last_snapshot_end_time = None;
                    let mut previous_clean_time = Instant::now();
                    let mut previous_shrink_time = Instant::now();

                    let bank = bank_forks.read().unwrap().root_bank();
                    bank.rc
                        .accounts
                        .accounts_db
                        .pq_storage_db()
                        .finish_startup();

                    loop {
                        if exit.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let start_time = Instant::now();

                        // Grab the current root bank
                        let bank = bank_forks.read().unwrap().root_bank();

                        // Purge accounts of any dead slots
                        request_handlers
                            .pruned_banks_request_handler
                            .remove_dead_slots(
                                &bank,
                                &mut removed_slots_count,
                                &mut total_remove_slots_time,
                            );

                        let non_snapshot_time = last_snapshot_end_time
                            .map(|last_snapshot_end_time: Instant| {
                                last_snapshot_end_time.elapsed().as_micros()
                            })
                            .unwrap_or_default();

                        // Check to see if there were any requests for snapshotting banks
                        // < the current root bank `bank` above.
                        //
                        // Claim: Any snapshot request for slot `N` found here implies that the
                        // last cleanup slot `M` satisfies `M < N`
                        //
                        // Proof: Assume for contradiction that we find a snapshot request for slot
                        // `N` here, but cleanup has already happened on some slot `M >= N`.
                        // Because the call to `bank.clean_accounts(true)` (in the code below)
                        // implies we only clean slots `<= bank - 1`, then that means in some
                        // *previous* iteration of this loop, we must have gotten a root bank for
                        // slot some slot `R` where `R > N`, but did not see the snapshot for `N`
                        // in the snapshot request channel.
                        //
                        // However, this is impossible because BankForks.set_root() will always
                        // flush the snapshot request for `N` to the snapshot request channel
                        // before setting a root `R > N`, and
                        // snapshot_request_handler.handle_requests() will always look for the
                        // latest available snapshot in the channel.
                        let snapshot_handle_result =
                            request_handlers.handle_snapshot_requests(non_snapshot_time);

                        if let Some(snapshot_handle_result) = snapshot_handle_result {
                            // Safe, see proof above

                            last_snapshot_end_time = Some(Instant::now());
                            match snapshot_handle_result {
                                Ok(snapshot_slot) => {
                                    assert!(
                                        last_cleaned_slot <= snapshot_slot,
                                        "last cleaned slot: {last_cleaned_slot}, snapshot request \
                                         slot: {snapshot_slot}, enqueued snapshot requests: {:?}",
                                        request_handlers
                                            .snapshot_request_handler
                                            .snapshot_request_receiver
                                            .try_iter()
                                            .collect::<Vec<_>>(),
                                    );
                                    last_cleaned_slot = snapshot_slot;
                                    previous_clean_time = Instant::now();
                                    previous_shrink_time = Instant::now();
                                }
                                Err(err) => {
                                    error!(
                                        "Stopping AccountsBackgroundService! Fatal error while \
                                         handling snapshot requests: {err}",
                                    );
                                    exit.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                        } else {
                            // we didn't handle a snapshot request, so do flush/clean/shrink

                            let next_snapshot_request_slot = request_handlers
                                .snapshot_request_handler
                                .peek_next_snapshot_request_slot();

                            // We cannot clean past the next snapshot request slot because it may
                            // have zero-lamport accounts.  See the comments in
                            // Bank::clean_accounts() for more information.
                            let max_clean_slot_inclusive = cmp::min(
                                next_snapshot_request_slot.unwrap_or(Slot::MAX),
                                bank.slot(),
                            )
                            .saturating_sub(1);

                            let duration_since_previous_clean = previous_clean_time.elapsed();
                            let should_clean = duration_since_previous_clean > CLEAN_INTERVAL;

                            let duration_since_previous_shrink = previous_shrink_time.elapsed();
                            let should_shrink = duration_since_previous_shrink > SHRINK_INTERVAL;
                            maintain_root_accounts(
                                &bank,
                                max_clean_slot_inclusive,
                                should_clean,
                                should_shrink,
                            );
                            if should_clean {
                                last_cleaned_slot = max_clean_slot_inclusive;
                                previous_clean_time = Instant::now();
                            }
                            if should_shrink || should_clean {
                                previous_shrink_time = Instant::now();
                            }
                        }

                        let loop_dur = start_time.elapsed();
                        stats.record_and_maybe_submit(loop_dur);
                        if let Some(sleep_dur) = MIN_LOOP_INTERVAL.checked_sub(loop_dur) {
                            sleep(sleep_dur);
                        }
                    }
                    info!("AccountsBackgroundService has stopped");
                    is_running.store(false, Ordering::Relaxed);
                }
            })
            .unwrap();

        Self {
            t_background,
            status: AbsStatus { is_running, stop },
        }
    }

    /// Should be called immediately after bank_fork_utils::load_bank_forks(), and as such, there
    /// should only be one bank, the root bank, in `bank_forks`
    /// All banks added to `bank_forks` will be descended from the root bank, and thus will inherit
    /// the bank drop callback.
    pub fn setup_bank_drop_callback(bank_forks: Arc<RwLock<BankForks>>) -> DroppedSlotsReceiver {
        assert_eq!(bank_forks.read().unwrap().banks().len(), 1);

        let (pruned_banks_sender, pruned_banks_receiver) = crossbeam_channel::unbounded();
        {
            let root_bank = bank_forks.read().unwrap().root_bank();

            root_bank
                .rc
                .accounts
                .accounts_db
                .pq_storage_db()
                .enable_bank_drop_callback();
            root_bank.set_callback(Some(Box::new(SendDroppedBankCallback::new(
                pruned_banks_sender,
            ))));
        }
        pruned_banks_receiver
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_background.join()
    }

    /// Returns an object to query/manage the status of ABS
    pub fn status(&self) -> &AbsStatus {
        &self.status
    }
}

/// Query and manage the status of AccountsBackgroundService
#[derive(Debug, Clone)]
pub struct AbsStatus {
    /// Flag to query if ABS is running
    is_running: Arc<AtomicBool>,
    /// Flag to set to stop ABS
    stop: Arc<AtomicBool>,
}

impl AbsStatus {
    /// Returns if ABS is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Raises the flag for ABS to stop
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed)
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn new_for_tests() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Get the SnapshotKind from a given SnapshotRequest
#[must_use]
fn new_snapshot_kind(snapshot_request: &SnapshotRequest) -> Option<SnapshotKind> {
    match snapshot_request.request_kind {
        SnapshotRequestKind::FullSnapshot => Some(SnapshotKind::Archive(SnapshotArchiveKind::Full)),
        SnapshotRequestKind::IncrementalSnapshot => {
            if let Some(latest_full_snapshot_slot) = snapshot_request
                .snapshot_root_bank
                .rc
                .accounts
                .accounts_db
                .pq_storage_db()
                .latest_full_snapshot_slot()
            {
                Some(SnapshotKind::Archive(SnapshotArchiveKind::Incremental(
                    latest_full_snapshot_slot,
                )))
            } else {
                warn!(
                    "Ignoring IncrementalSnapshot request for slot {} because there is no latest \
                     full snapshot",
                    snapshot_request.snapshot_root_bank.slot()
                );
                None
            }
        }
        SnapshotRequestKind::FastbootSnapshot => Some(SnapshotKind::Fastboot),
    }
}

/// Compare snapshot requests; used to pick the highest priority request to handle.
///
/// Priority, from highest to lowest:
/// - Epoch Accounts Hash
/// - Full Snapshot
/// - Incremental Snapshot
///
/// If two requests of the same kind are being compared, their bank slots are the tiebreaker.
#[must_use]
fn cmp_requests_by_priority(a: &SnapshotRequest, b: &SnapshotRequest) -> cmp::Ordering {
    let slot_a = a.snapshot_root_bank.slot();
    let slot_b = b.snapshot_root_bank.slot();
    cmp_snapshot_request_kinds_by_priority(&a.request_kind, &b.request_kind)
        .then(slot_a.cmp(&slot_b))
}

/// Compare snapshot request kinds by priority
///
/// Priority, from highest to lowest:
/// - Full Snapshot
/// - Incremental Snapshot
/// - Fastboot Snapshot
#[must_use]
fn cmp_snapshot_request_kinds_by_priority(
    a: &SnapshotRequestKind,
    b: &SnapshotRequestKind,
) -> cmp::Ordering {
    use {
        SnapshotRequestKind as Kind,
        cmp::Ordering::{Equal, Greater, Less},
    };
    match (a, b) {
        (Kind::FullSnapshot, Kind::FullSnapshot) => Equal,
        (Kind::FullSnapshot, Kind::IncrementalSnapshot) => Greater,
        (Kind::FullSnapshot, Kind::FastbootSnapshot) => Greater,
        (Kind::IncrementalSnapshot, Kind::FullSnapshot) => Less,
        (Kind::IncrementalSnapshot, Kind::IncrementalSnapshot) => Equal,
        (Kind::IncrementalSnapshot, Kind::FastbootSnapshot) => Greater,
        (Kind::FastbootSnapshot, Kind::FullSnapshot) => Less,
        (Kind::FastbootSnapshot, Kind::IncrementalSnapshot) => Less,
        (Kind::FastbootSnapshot, Kind::FastbootSnapshot) => Equal,
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::genesis_utils::{create_genesis_config, create_genesis_config_with_leader},
        agave_pq_crypto::{
            auth::{AuthRecord, Origin},
            crypto::FalconKeypair,
        },
        agave_snapshots::snapshot_config::SnapshotConfig,
        crossbeam_channel::bounded,
        solana_account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        solana_epoch_schedule::EpochSchedule,
        solana_fee_calculator::FeeRateGovernor,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_leader_schedule::SlotLeader,
        solana_message::{Message, VersionedMessage},
        solana_pubkey::Pubkey,
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::versioned::VersionedTransaction,
        solana_transaction_error::TransactionError,
    };

    type MaintenanceFixture = (
        Arc<Bank>,
        Arc<RwLock<BankForks>>,
        Keypair,
        FalconKeypair,
        crate::pq::Config,
    );

    fn pq_maintenance_bank() -> MaintenanceFixture {
        let mut genesis =
            create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000_000);
        genesis.genesis_config.rent = solana_rent::Rent::default();
        genesis.genesis_config.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        let config = crate::pq::Config {
            chain_id: [0x53; 32],
            migration_context: [0x57; 32],
            cutoff_slot: 0,
        };
        genesis.genesis_config.accounts.insert(
            crate::pq::CONFIG_ADDRESS,
            config.account(genesis.genesis_config.rent.minimum_balance(80)),
        );
        let key = FalconKeypair::generate();
        let policy = AuthRecord::new(
            genesis.mint_keypair.pubkey().to_bytes(),
            key.public_key(),
            Origin::FreshIdentity,
        )
        .encode();
        genesis.genesis_config.accounts.insert(
            crate::pq::policy_address(&genesis.mint_keypair.pubkey()),
            Account {
                lamports: genesis.genesis_config.rent.minimum_balance(policy.len()),
                data: policy,
                owner: crate::pq::PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        );
        let (bank, forks) =
            Bank::new_for_tests(&genesis.genesis_config).wrap_with_bank_forks_for_tests();
        (bank, forks, genesis.mint_keypair, key, config)
    }

    fn pq_maintenance_transfer(
        bank: &Bank,
        authority: Pubkey,
        key: &FalconKeypair,
        config: &crate::pq::Config,
        recipient: Pubkey,
        amount: u64,
    ) -> VersionedTransaction {
        crate::pq::sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    crate::pq::authenticate_instruction(&[authority]),
                    system_instruction::transfer(&authority, &recipient, amount),
                ],
                Some(&authority),
                &bank.last_blockhash(),
            )),
            config,
            &[key],
        )
        .unwrap()
    }

    fn recompute_pq_accounts(bank: &Bank) -> [u8; 48] {
        let mut leaves = Vec::new();
        bank.rc
            .accounts
            .scan_all(&bank.ancestors, bank.bank_id(), |entry| {
                if let Some((address, account, _)) = entry
                    && account.lamports() != 0
                {
                    leaves.push((*address, crate::pq::account_leaf(address, &account)));
                }
            })
            .unwrap();
        crate::pq::accounts_merkle_root(leaves)
    }

    #[test]
    fn test_pq_root_background_maintenance_bounds_original_cache_and_keeps_snapshots() {
        let (initial, forks, authority, key, config) = pq_maintenance_bank();
        let recipient = Pubkey::new_unique();
        initial.store_account(
            &recipient,
            &AccountSharedData::new(1_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        let changed = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let inherited = Pubkey::new_unique();
        let inherited_account = AccountSharedData::from(Account {
            lamports: 1_000_000_000,
            data: vec![0x91; 2048],
            owner,
            executable: false,
            rent_epoch: 79,
        });
        initial.store_account(&inherited, &inherited_account);
        initial.store_account(
            &changed,
            &AccountSharedData::from(Account {
                lamports: 1_000_000_000,
                data: vec![0; 65536],
                owner,
                executable: false,
                rent_epoch: 31,
            }),
        );
        initial.freeze();
        initial.squash();
        initial.force_flush_accounts_cache();
        let storage = initial.rc.accounts.accounts_db.pq_storage_db();
        assert_eq!(storage.accounts_cache.num_slots(), 0);
        let leader = *initial.leader();
        let initial_authority_balance = initial.get_balance(&authority.pubkey());
        let mut successful = Vec::new();
        let mut charged_failure = None;
        let mut sibling = None;
        let mut frozen_descendant = None;
        let mut peaks = Vec::new();
        for slot in 1u64..=16 {
            let parent = forks.read().unwrap().root_bank();
            let child =
                Arc::new(Bank::new_isolated_pq_child(Arc::clone(&parent), leader, slot).unwrap());
            let wire =
                pq_maintenance_transfer(&child, authority.pubkey(), &key, &config, recipient, slot);
            let identity = crate::pq::transaction_intent_identity(&wire, &config.chain_id).unwrap();
            assert_eq!(
                child
                    .process_transaction_with_metadata(wire.clone())
                    .unwrap()
                    .status,
                Ok(())
            );
            successful.push((identity, wire));
            if slot == 5 {
                let failed = pq_maintenance_transfer(
                    &child,
                    authority.pubkey(),
                    &key,
                    &config,
                    recipient,
                    u64::MAX,
                );
                let failed_identity =
                    crate::pq::transaction_intent_identity(&failed, &config.chain_id).unwrap();
                let before = child.get_balance(&authority.pubkey());
                assert!(
                    child
                        .process_transaction_with_metadata(failed.clone())
                        .unwrap()
                        .status
                        .is_err()
                );
                assert_eq!(child.get_balance(&authority.pubkey()), before - 5_000);
                charged_failure = Some((failed_identity, failed));
            }
            let mut account = child.get_account(&changed).unwrap();
            account.set_data_from_slice(&vec![slot as u8; 65536]);
            account.set_rent_epoch(slot + 31);
            child.store_account(&changed, &account);
            if slot == 3 {
                let alternative = Arc::new(
                    Bank::new_isolated_pq_child(Arc::clone(&parent), leader, slot).unwrap(),
                );
                let wire = pq_maintenance_transfer(
                    &alternative,
                    authority.pubkey(),
                    &key,
                    &config,
                    recipient,
                    999,
                );
                let identity =
                    crate::pq::transaction_intent_identity(&wire, &config.chain_id).unwrap();
                assert_eq!(
                    alternative
                        .process_transaction_with_metadata(wire)
                        .unwrap()
                        .status,
                    Ok(())
                );
                alternative.freeze();
                alternative.detach_isolated_pq_parent().unwrap();
                sibling = Some((
                    Arc::clone(&alternative),
                    alternative.pq_state_commitment(),
                    identity,
                ));
            }
            let mut hash = [0x84; 32];
            hash[..8].copy_from_slice(&slot.to_le_bytes());
            child.register_recent_blockhash_for_test(&Hash::new_from_array(hash), None);
            child.freeze();
            child.detach_isolated_pq_parent().unwrap();
            if slot == 3 {
                // This descendant executes before its own parent is certified.
                // Later canonical flush/clean must preserve its private view.
                let descendant =
                    Arc::new(Bank::new_isolated_pq_child(Arc::clone(&child), leader, 4).unwrap());
                let wire = pq_maintenance_transfer(
                    &descendant,
                    authority.pubkey(),
                    &key,
                    &config,
                    recipient,
                    777,
                );
                let identity =
                    crate::pq::transaction_intent_identity(&wire, &config.chain_id).unwrap();
                assert_eq!(
                    descendant
                        .process_transaction_with_metadata(wire)
                        .unwrap()
                        .status,
                    Ok(())
                );
                descendant.freeze();
                descendant.detach_isolated_pq_parent().unwrap();
                let state = descendant.pq_state_commitment();
                frozen_descendant = Some((descendant, state, identity, account.clone()));
            }
            let state = child.pq_state_commitment();
            let accounts_root = recompute_pq_accounts(&child);
            let promoted = forks
                .write()
                .unwrap()
                .promote_pq_candidate(Arc::clone(&child), parent.pq_state_commitment())
                .unwrap();
            assert!(Arc::ptr_eq(&promoted, &child));
            let before = (
                storage.accounts_cache.num_slots(),
                storage.accounts_cache.num_unflushed_roots(),
                storage.accounts_cache.size(),
            );
            let observed = promoted.pq_persisted_accounts_cache_stats();
            assert_eq!(
                (
                    observed.slots,
                    observed.unflushed_roots,
                    observed.data_bytes
                ),
                before
            );
            maintain_root_accounts(&promoted, slot - 1, true, true);
            let after = (
                storage.accounts_cache.num_slots(),
                storage.accounts_cache.num_unflushed_roots(),
                storage.accounts_cache.size(),
            );
            eprintln!(
                "PQ root maintenance slot={slot} original_cache_before={before:?} \
                 original_cache_after={after:?}"
            );
            peaks.push(after);
            assert_eq!(promoted.pq_state_commitment(), state);
            assert_eq!(promoted.pq_accounts_commitment(), accounts_root);
            assert_eq!(recompute_pq_accounts(&promoted), accounts_root);
            assert_eq!(promoted.get_account(&inherited).unwrap(), inherited_account);
            assert_eq!(promoted.get_account(&changed).unwrap(), account);
            for (identity, _) in &successful {
                assert!(promoted.pq_intent_processed(identity).unwrap());
            }
            if let Some((identity, _)) = &charged_failure {
                assert!(promoted.pq_intent_processed(identity).unwrap());
            }
            if let Some((alternative, state, identity)) = &sibling {
                assert_eq!(alternative.pq_state_commitment(), *state);
                assert_eq!(
                    alternative.pq_accounts_commitment(),
                    recompute_pq_accounts(alternative)
                );
                assert!(alternative.pq_intent_processed(identity).unwrap());
                assert!(!promoted.pq_intent_processed(identity).unwrap());
                assert_eq!(
                    alternative.get_account(&inherited).unwrap(),
                    inherited_account
                );
            }
            if let Some((descendant, state, identity, account)) = &frozen_descendant {
                assert_eq!(descendant.pq_state_commitment(), *state);
                assert_eq!(
                    descendant.pq_accounts_commitment(),
                    recompute_pq_accounts(descendant)
                );
                assert_eq!(descendant.get_account(&changed).unwrap(), *account);
                assert_eq!(
                    descendant.get_account(&inherited).unwrap(),
                    inherited_account
                );
                assert_eq!(descendant.get_balance(&recipient), 1_000_000 + 6 + 777);
                assert!(descendant.pq_intent_processed(identity).unwrap());
                assert!(!promoted.pq_intent_processed(identity).unwrap());
            }
        }
        let root = forks.read().unwrap().root_bank();
        assert_eq!(
            root.get_balance(&recipient),
            1_000_000 + (1..=16u64).sum::<u64>()
        );
        assert_eq!(
            root.get_balance(&authority.pubkey()),
            initial_authority_balance - (1..=16u64).sum::<u64>() - 17 * 5_000
        );
        assert_eq!(root.transaction_count(), initial.transaction_count() + 17);
        let probe = Bank::new_isolated_pq_child(Arc::clone(&root), leader, 17).unwrap();
        for (_, wire) in successful.iter().take(1).chain(charged_failure.iter()) {
            assert_eq!(
                probe
                    .process_transaction_with_metadata(wire.clone())
                    .unwrap_err(),
                TransactionError::AlreadyProcessed
            );
        }
        let (alternative, state, _) = sibling.unwrap();
        assert!(
            forks
                .write()
                .unwrap()
                .promote_pq_candidate(Arc::clone(&alternative), root.pq_state_commitment())
                .is_err()
        );
        drop(alternative);
        assert_eq!(root.pq_accounts_commitment(), recompute_pq_accounts(&root));
        assert!(state != root.pq_state_commitment());
        assert!(
            peaks
                .iter()
                .all(|(slots, roots, _)| *slots <= 1 && *roots <= 1),
            "rooted original versions must be drained by actual ABS maintenance: {peaks:?}"
        );
    }

    #[test]
    fn test_pq_background_original_dead_slots_and_private_sibling_drops_stay_separate() {
        let (initial, forks, authority, key, config) = pq_maintenance_bank();
        let receiver = AccountsBackgroundService::setup_bank_drop_callback(Arc::clone(&forks));
        initial.freeze();
        initial.squash();
        let storage = initial.rc.accounts.accounts_db.pq_storage_db();
        let dead = Bank::new_from_parent(Arc::clone(&initial), *initial.leader(), 1);
        let dead_address = Pubkey::new_unique();
        dead.store_account(
            &dead_address,
            &AccountSharedData::new(1_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        assert!(storage.accounts_cache.slot_cache(1).is_some());
        drop(dead);
        assert_eq!(receiver.len(), 1);
        let canonical = Arc::new(
            Bank::new_isolated_pq_child(Arc::clone(&initial), *initial.leader(), 2).unwrap(),
        );
        let recipient = Pubkey::new_unique();
        let wire = pq_maintenance_transfer(
            &canonical,
            authority.pubkey(),
            &key,
            &config,
            recipient,
            1_000_000,
        );
        assert_eq!(
            canonical
                .process_transaction_with_metadata(wire)
                .unwrap()
                .status,
            Ok(())
        );
        canonical.freeze();
        canonical.detach_isolated_pq_parent().unwrap();
        let private = Arc::new(
            Bank::new_isolated_pq_child(Arc::clone(&initial), *initial.leader(), 2).unwrap(),
        );
        let wire = pq_maintenance_transfer(
            &private,
            authority.pubkey(),
            &key,
            &config,
            Pubkey::new_unique(),
            1_000_000,
        );
        assert_eq!(
            private
                .process_transaction_with_metadata(wire)
                .unwrap()
                .status,
            Ok(())
        );
        private.freeze();
        private.detach_isolated_pq_parent().unwrap();
        let private_db = Arc::clone(&private.rc.accounts.accounts_db);
        let state = canonical.pq_state_commitment();
        forks
            .write()
            .unwrap()
            .promote_pq_candidate(Arc::clone(&canonical), initial.pq_state_commitment())
            .unwrap();
        drop(private);
        assert_eq!(
            receiver.len(),
            1,
            "private speculative drop must not enter original ABS queue"
        );
        assert!(private_db.accounts_cache.slot_cache(2).is_none());
        assert!(storage.accounts_cache.slot_cache(2).is_some());
        let handler = PrunedBanksRequestHandler {
            pruned_banks_receiver: receiver,
        };
        handler.remove_dead_slots(&canonical, &mut 0, &mut 0);
        assert!(
            storage.accounts_cache.slot_cache(1).is_none(),
            "original startup-bank drop must purge original storage"
        );
        assert!(storage.accounts_cache.slot_cache(2).is_some());
        assert_eq!(canonical.pq_state_commitment(), state);
        assert_eq!(
            canonical.pq_accounts_commitment(),
            recompute_pq_accounts(&canonical)
        );
        assert_eq!(canonical.get_balance(&recipient), 1_000_000);
    }

    #[test]
    fn test_native_root_background_maintenance_retains_original_non_pq_behavior() {
        let mut genesis =
            create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000_000);
        genesis.genesis_config.rent = solana_rent::Rent::default();
        genesis.genesis_config.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        let (initial, forks) =
            Bank::new_for_tests(&genesis.genesis_config).wrap_with_bank_forks_for_tests();
        initial.freeze();
        initial.squash();
        initial.force_flush_accounts_cache();
        let storage = Arc::clone(&initial.rc.accounts.accounts_db);
        let recipient = Pubkey::new_unique();
        for slot in 1..=4 {
            let parent = forks.read().unwrap().root_bank();
            let child = Bank::new_from_parent(Arc::clone(&parent), *parent.leader(), slot);
            assert!(Arc::ptr_eq(
                &storage,
                &child.rc.accounts.accounts_db.pq_storage_db()
            ));
            let tx = solana_system_transaction::transfer(
                &genesis.mint_keypair,
                &recipient,
                slot * 1_000_000,
                child.last_blockhash(),
            );
            assert!(tx.verify().is_ok());
            assert!(child.process_transaction(&tx).is_ok());
            child.freeze();
            let hash = child.hash();
            forks.write().unwrap().insert(child);
            forks.write().unwrap().set_root(slot, None, Some(slot));
            let root = forks.read().unwrap().root_bank();
            maintain_root_accounts(&root, slot - 1, true, true);
            assert_eq!(storage.accounts_cache.num_slots(), 1);
            assert_eq!(storage.accounts_cache.num_unflushed_roots(), 1);
            assert_eq!(root.hash(), hash);
            assert_eq!(
                root.get_balance(&recipient),
                (1..=slot).sum::<u64>() * 1_000_000
            );
            assert_eq!(root.pq_config().unwrap(), None);
        }
    }

    #[test]
    fn test_pq_root_snapshot_maintenance_uses_original_full_and_incremental_metadata() {
        let (initial, forks, authority, key, config) = pq_maintenance_bank();
        initial.freeze();
        initial.squash();
        let storage = initial.rc.accounts.accounts_db.pq_storage_db();
        let (sender, receiver) = bounded(16);
        let packages = Arc::new(Mutex::new(PendingSnapshotPackages::default()));
        let handler = SnapshotRequestHandler {
            snapshot_controller: Arc::new(SnapshotController::new(
                sender,
                SnapshotConfig::default(),
                0,
            )),
            snapshot_request_receiver: receiver,
            pending_snapshot_packages: Arc::clone(&packages),
        };
        let recipient = Pubkey::new_unique();
        let mut snapshot_roots = Vec::new();
        for slot in 1..=2 {
            let parent = forks.read().unwrap().root_bank();
            let child = Arc::new(
                Bank::new_isolated_pq_child(Arc::clone(&parent), *parent.leader(), slot).unwrap(),
            );
            let wire = pq_maintenance_transfer(
                &child,
                authority.pubkey(),
                &key,
                &config,
                recipient,
                slot * 1_000_000,
            );
            assert_eq!(
                child
                    .process_transaction_with_metadata(wire)
                    .unwrap()
                    .status,
                Ok(())
            );
            child.freeze();
            child.detach_isolated_pq_parent().unwrap();
            let state = child.pq_state_commitment();
            // Supply native package metadata in this fixture only; PQ recovery
            // still requires its separate full-width authenticated checkpoint.
            child.set_block_id(Some(child.hash()));
            forks
                .write()
                .unwrap()
                .promote_pq_candidate(Arc::clone(&child), parent.pq_state_commitment())
                .unwrap();
            let request = SnapshotRequest {
                snapshot_root_bank: Arc::clone(&child),
                status_cache_slot_deltas: child.status_cache.read().unwrap().root_slot_deltas(),
                request_kind: if slot == 1 {
                    SnapshotRequestKind::FullSnapshot
                } else {
                    SnapshotRequestKind::IncrementalSnapshot
                },
                enqueued: Instant::now(),
            };
            let expected_kind = if slot == 1 {
                SnapshotKind::Archive(SnapshotArchiveKind::Full)
            } else {
                SnapshotKind::Archive(SnapshotArchiveKind::Incremental(1))
            };
            assert_eq!(new_snapshot_kind(&request), Some(expected_kind));
            assert_eq!(
                handler
                    .handle_snapshot_request(0, request, expected_kind)
                    .unwrap(),
                slot
            );
            assert_eq!(storage.accounts_cache.num_slots(), 0);
            assert_eq!(storage.accounts_cache.num_unflushed_roots(), 0);
            assert!(storage.accounts_cache.fetch_max_flush_root().unwrap() >= slot);
            assert_eq!(storage.latest_full_snapshot_slot(), Some(1));
            assert_eq!(
                child.rc.accounts.accounts_db.latest_full_snapshot_slot(),
                None
            );
            assert_eq!(child.pq_state_commitment(), state);
            assert_eq!(
                child.pq_accounts_commitment(),
                recompute_pq_accounts(&child)
            );
            snapshot_roots.push((child, state));
        }
        assert!(!packages.lock().unwrap().is_empty());
        for (bank, state) in snapshot_roots {
            assert_eq!(bank.pq_state_commitment(), state);
            assert_eq!(bank.pq_accounts_commitment(), recompute_pq_accounts(&bank));
        }
        // This checks physical maintenance/package construction only. Native
        // snapshots still do not carry the full-width PQ recovery checkpoint.
    }

    #[test]
    fn test_accounts_background_service_remove_dead_slots() {
        let genesis = create_genesis_config(10);
        let bank0 = Arc::new(Bank::new_for_tests(&genesis.genesis_config));
        let (pruned_banks_sender, pruned_banks_receiver) = bounded(1024);
        let pruned_banks_request_handler = PrunedBanksRequestHandler {
            pruned_banks_receiver,
        };

        // Store an account in slot 0
        let account_key = Pubkey::new_unique();
        bank0.store_account(
            &account_key,
            &AccountSharedData::new(264, 0, &Pubkey::default()),
        );
        assert!(bank0.get_account(&account_key).is_some());
        pruned_banks_sender.send((0, BankId::new(0))).unwrap();

        assert!(!bank0.rc.accounts.scan_slot(0, |_| Some(())).is_empty());

        pruned_banks_request_handler.remove_dead_slots(&bank0, &mut 0, &mut 0);

        assert!(bank0.rc.accounts.scan_slot(0, |_| Some(())).is_empty());
    }

    /// Ensure that unhandled snapshot requests are properly re-enqueued or dropped
    ///
    /// The snapshot request handler should be flexible and handle re-queueing unhandled snapshot
    /// requests, if those unhandled requests are for slots GREATER-THAN the last request handled.
    #[test]
    fn test_get_next_snapshot_request() {
        // These constants were picked to ensure the desired snapshot requests were sent to the
        // channel.  Ensure there are multiple requests of each kind.
        const SLOTS_PER_EPOCH: Slot = 400;
        const FULL_SNAPSHOT_INTERVAL: Slot = 80;
        const INCREMENTAL_SNAPSHOT_INTERVAL: Slot = 30;
        const FASTBOOT_SNAPSHOT_INTERVAL: Slot = 45;

        // This would typically configure the snapshot controller, but since `set_root` is never
        // called, the snapshot controller is never invoked. The default configuration suffices
        // as it does not affect the test behavior.
        let snapshot_config = SnapshotConfig::default();

        let pending_snapshot_packages = Arc::new(Mutex::new(PendingSnapshotPackages::default()));
        let (snapshot_request_sender, snapshot_request_receiver) = bounded(1024);
        let snapshot_controller = Arc::new(SnapshotController::new(
            snapshot_request_sender.clone(),
            snapshot_config,
            0,
        ));
        let snapshot_request_handler = SnapshotRequestHandler {
            snapshot_controller,
            snapshot_request_receiver,
            pending_snapshot_packages,
        };

        let send_snapshot_request = |snapshot_root_bank, request_kind| {
            let snapshot_request = SnapshotRequest {
                snapshot_root_bank,
                status_cache_slot_deltas: Vec::default(),
                request_kind,
                enqueued: Instant::now(),
            };
            snapshot_request_sender.send(snapshot_request).unwrap();
        };

        let mut genesis_config_info = create_genesis_config(10);
        genesis_config_info.genesis_config.epoch_schedule =
            EpochSchedule::custom(SLOTS_PER_EPOCH, SLOTS_PER_EPOCH, false);
        let (mut bank, _bank_forks) = Bank::new_for_tests(&genesis_config_info.genesis_config)
            .wrap_with_bank_forks_for_tests();

        // We need to get and set accounts-db's latest full snapshot slot to test
        // get_next_snapshot_request().  To workaround potential borrowing issues
        // caused by make_banks() below, Arc::clone bank0 and add helper functions.
        let bank0 = bank.clone();
        fn latest_full_snapshot_slot(bank: &Bank) -> Option<Slot> {
            bank.rc.accounts.accounts_db.latest_full_snapshot_slot()
        }
        fn set_latest_full_snapshot_slot(bank: &Bank, slot: Slot) {
            bank.rc
                .accounts
                .accounts_db
                .set_latest_full_snapshot_slot(slot);
        }

        // Create new banks and send snapshot requests so that the following requests will be in
        // the channel before handling the requests:
        //
        // full          80
        // incremental   90
        // incremental  120
        // fastboot     135
        // incremental  150
        // full         160
        // incremental  180
        // incremental  210
        // fastboot     225
        // full         240 <-- handled 1st
        // incremental  270
        // incremental  300 <-- handled 2nd
        // fastboot     315 <-- handled last
        // Also, incremental snapshots before slot 240 (the first full snapshot handled), will
        // actually be skipped since the latest full snapshot slot will be `None`.
        let mut make_banks = |num_banks| {
            for _ in 0..num_banks {
                let slot = bank.slot() + 1;
                bank = Arc::new(Bank::new_from_parent(
                    bank.clone(),
                    SlotLeader::new_unique(),
                    slot,
                ));

                // Since we're not using `BankForks::set_root()`, we have to handle sending the
                // correct snapshot requests ourself.
                if bank.block_height().is_multiple_of(FULL_SNAPSHOT_INTERVAL) {
                    send_snapshot_request(Arc::clone(&bank), SnapshotRequestKind::FullSnapshot);
                } else if bank
                    .block_height()
                    .is_multiple_of(INCREMENTAL_SNAPSHOT_INTERVAL)
                {
                    send_snapshot_request(
                        Arc::clone(&bank),
                        SnapshotRequestKind::IncrementalSnapshot,
                    );
                } else if bank
                    .block_height()
                    .is_multiple_of(FASTBOOT_SNAPSHOT_INTERVAL)
                {
                    send_snapshot_request(Arc::clone(&bank), SnapshotRequestKind::FastbootSnapshot);
                }
            }
        };
        make_banks(318);

        // Ensure the full snapshot from slot 240 is handled 1st
        // (the older full snapshots are skipped and dropped)
        assert_eq!(latest_full_snapshot_slot(&bank0), None);
        let (snapshot_request, ..) = snapshot_request_handler
            .get_next_snapshot_request()
            .unwrap();
        assert_eq!(
            snapshot_request.request_kind,
            SnapshotRequestKind::FullSnapshot
        );
        assert_eq!(snapshot_request.snapshot_root_bank.slot(), 240);
        set_latest_full_snapshot_slot(&bank0, 240);

        // Ensure the incremental snapshot from slot 300 is handled 2nd
        // (the older incremental snapshots are skipped and dropped)
        assert_eq!(latest_full_snapshot_slot(&bank0), Some(240));
        let (snapshot_request, ..) = snapshot_request_handler
            .get_next_snapshot_request()
            .unwrap();
        assert_eq!(
            snapshot_request.request_kind,
            SnapshotRequestKind::IncrementalSnapshot
        );
        assert_eq!(snapshot_request.snapshot_root_bank.slot(), 300);

        // Ensure the fastboot snapshot from slot 315 is handled last
        // (the older fastboot snapshots are skipped and dropped)
        assert_eq!(latest_full_snapshot_slot(&bank0), Some(240));
        let (snapshot_request, ..) = snapshot_request_handler
            .get_next_snapshot_request()
            .unwrap();
        assert_eq!(
            snapshot_request.request_kind,
            SnapshotRequestKind::FastbootSnapshot
        );
        assert_eq!(snapshot_request.snapshot_root_bank.slot(), 315);

        // And now ensure the snapshot request channel is empty!
        assert_eq!(latest_full_snapshot_slot(&bank0), Some(240));
        assert!(
            snapshot_request_handler
                .get_next_snapshot_request()
                .is_none()
        );
    }

    /// Ensure that we can prune banks with the same slot (if they were on different forks)
    #[test]
    fn test_pruned_banks_request_handler_handle_request() {
        let (pruned_banks_sender, pruned_banks_receiver) = bounded(1024);
        let pruned_banks_request_handler = PrunedBanksRequestHandler {
            pruned_banks_receiver,
        };
        let genesis_config_info = create_genesis_config(10);
        let bank = Bank::new_for_tests(&genesis_config_info.genesis_config);
        bank.rc.accounts.accounts_db.enable_bank_drop_callback();
        bank.set_callback(Some(Box::new(SendDroppedBankCallback::new(
            pruned_banks_sender,
        ))));

        let (fork0_bank0, bank_forks) = bank.wrap_with_bank_forks_for_tests();
        let fork0_bank1 = Arc::new(Bank::new_from_parent(
            fork0_bank0.clone(),
            SlotLeader::new_unique(),
            fork0_bank0.slot() + 1,
        ));
        let fork1_bank1 = Arc::new(Bank::new_from_parent(
            fork0_bank0.clone(),
            SlotLeader::new_unique(),
            fork0_bank0.slot() + 1,
        ));
        let fork2_bank1 = Arc::new(Bank::new_from_parent(
            fork0_bank0.clone(),
            SlotLeader::new_unique(),
            fork0_bank0.slot() + 1,
        ));
        let fork0_bank2 = Arc::new(Bank::new_from_parent(
            fork0_bank1.clone(),
            SlotLeader::new_unique(),
            fork0_bank1.slot() + 1,
        ));
        let fork1_bank2 = Arc::new(Bank::new_from_parent(
            fork1_bank1.clone(),
            SlotLeader::new_unique(),
            fork1_bank1.slot() + 1,
        ));
        let fork0_bank3 = Arc::new(Bank::new_from_parent(
            fork0_bank2.clone(),
            SlotLeader::new_unique(),
            fork0_bank2.slot() + 1,
        ));
        let fork3_bank3 = Arc::new(Bank::new_from_parent(
            fork0_bank2.clone(),
            SlotLeader::new_unique(),
            fork0_bank2.slot() + 1,
        ));
        fork0_bank3.squash();

        drop(fork3_bank3);
        drop(fork1_bank2);
        drop(fork0_bank2);
        drop(fork1_bank1);
        drop(fork2_bank1);
        drop(fork0_bank1);
        drop(fork0_bank0);
        drop(bank_forks);
        let num_banks_purged = pruned_banks_request_handler.handle_request(&fork0_bank3);
        assert_eq!(num_banks_purged, 7);
    }

    #[test]
    fn test_cmp_snapshot_request_kinds_by_priority() {
        use cmp::Ordering::{Equal, Greater, Less};
        for (snapshot_request_kind_a, snapshot_request_kind_b, expected_result) in [
            (
                SnapshotRequestKind::FullSnapshot,
                SnapshotRequestKind::FullSnapshot,
                Equal,
            ),
            (
                SnapshotRequestKind::FullSnapshot,
                SnapshotRequestKind::IncrementalSnapshot,
                Greater,
            ),
            (
                SnapshotRequestKind::FullSnapshot,
                SnapshotRequestKind::FastbootSnapshot,
                Greater,
            ),
            (
                SnapshotRequestKind::IncrementalSnapshot,
                SnapshotRequestKind::FullSnapshot,
                Less,
            ),
            (
                SnapshotRequestKind::IncrementalSnapshot,
                SnapshotRequestKind::IncrementalSnapshot,
                Equal,
            ),
            (
                SnapshotRequestKind::IncrementalSnapshot,
                SnapshotRequestKind::FastbootSnapshot,
                Greater,
            ),
            (
                SnapshotRequestKind::FastbootSnapshot,
                SnapshotRequestKind::FullSnapshot,
                Less,
            ),
            (
                SnapshotRequestKind::FastbootSnapshot,
                SnapshotRequestKind::IncrementalSnapshot,
                Less,
            ),
            (
                SnapshotRequestKind::FastbootSnapshot,
                SnapshotRequestKind::FastbootSnapshot,
                Equal,
            ),
        ] {
            let actual_result = cmp_snapshot_request_kinds_by_priority(
                &snapshot_request_kind_a,
                &snapshot_request_kind_b,
            );
            assert_eq!(expected_result, actual_result);
        }
    }
}
