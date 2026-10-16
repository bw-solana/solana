//! Quantumglow's Votor event loop (Alpenglow v1.2, Algorithms 1/2;
//! Definitions 10, 12, 14--18 and 59--65).
//!
//! Only authenticated pool evidence can authorize votes. Block data is checked
//! by the existing Falcon/Merkle/erasure decoder with the finalized scheduled
//! leader's key. Output Broadcast actions must be durably journaled before an
//! Ax signer publishes them. Finalization waits for the complete parent chain.
use {
    crate::{
        consensus::{
            CertificateKind, Commitment, ConsensusError, ConsensusEvent, ConsensusMessage,
            ConsensusPool, EvidenceAuthentication, EvidenceVerifier, MAX_EPOCH_SLOTS,
            MAX_SLOT_WINDOW, MessageKind, PreparedEvidence, SignedEvidence, Validator,
        },
        crypto::{FalconPublicKey, hash_commitment},
        network::{AuthenticatedShred, CandidateAssembler, FinalMarker, VerifiedCandidate},
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    },
};

const MAX_BLOCKS_PER_SLOT: usize = 5; // first block plus four notar-fallback blocks (Lemma 48)
// Live history and staged journal bytes are bounded independently of the
// finite epoch length. Native callers sync and discard journal buffers and
// compact only after replaying the certified chain into the actual runtime.
const MAX_STORED_BLOCK_BYTES: usize = 256 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 512 * 1024 * 1024;
const MAX_JOURNAL_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockRef {
    pub slot: u64,
    pub hash: Commitment,
}

pub struct ExecutionCandidate<'a> {
    pub reference: BlockRef,
    pub parent: Commitment,
    pub payload: &'a [u8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionState {
    pub parent_state_root: Commitment,
    pub state_root: Commitment,
}
/// A trusted local runtime hook: execute/sanitize the exact authenticated candidate
/// against its exact parent state. Peers never supply this callback or its result.
pub type ExecutionValidator =
    Arc<dyn Fn(&ExecutionCandidate<'_>) -> Option<ExecutionState> + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    pub chain: [u8; 32],
    pub epoch: u64,
    pub first_slot: u64,
    pub slot_count: u64,
    pub window_size: u64,
    /// Conservative synchronous delay bound. Quantumglow uses 4 * delta.
    pub network_delay_ms: u64,
    pub block_time_ms: u64,
    /// One validator ID per slot, identical throughout each leader window.
    pub leaders: Vec<[u8; 32]>,
    pub leader_keys: BTreeMap<[u8; 32], FalconPublicKey>,
    /// Must come from independently authenticated finalized state/checkpoint.
    pub finalized_anchor: BlockRef,
    pub finalized_state_root: Commitment,
    /// Identifies the execution rules and is bound into epoch and recovery state.
    pub execution_rules: Commitment,
    pub validate_execution: ExecutionValidator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Broadcast(ConsensusMessage),
    ParentReady {
        slot: u64,
        parent: Commitment,
    },
    /// An untrusted response must pass observe_block's scheduled-key validation.
    Repair {
        slot: Option<u64>,
        block: Commitment,
    },
    Finalized(BlockRef),
    Equivocation {
        validator: [u8; 32],
        slot: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Consensus(ConsensusError),
    Config,
    Clock,
    BlockAuthentication,
    InvalidExecution,
    Bounds,
    /// Internal staged recovery journal capacity, distinct from peer candidate
    /// admission pressure. Native callers must retain fail-stop behavior.
    JournalBounds,
    InvalidAncestry,
    SafetyViolation,
    Journal,
    EpochTransition,
}
impl From<ConsensusError> for Error {
    fn from(e: ConsensusError) -> Self {
        Self::Consensus(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Default)]
struct SlotState {
    parent_ready: BTreeSet<Commitment>,
    initial: Option<Option<Commitment>>, // None=unvoted, Some(None)=skip
    notarized: BTreeSet<Commitment>,
    its_over: bool,
    bad_window: bool,
    pending: Option<Commitment>,
    safe_notar: BTreeSet<Commitment>,
    safe_skip: bool,
    approvals: BTreeSet<(MessageKind, Option<Commitment>)>,
}
#[derive(Clone)]
struct Block {
    reference: BlockRef,
    parent: Commitment,
    payload: Vec<u8>,
    execution: ExecutionState,
}
#[derive(Clone)]
enum Input {
    Evidence(SignedEvidence, u64),
    Block(Box<FinalMarker>, Vec<AuthenticatedShred>, u64),
    Tick(u64),
}

/// Local recovery log, bound to chain, membership, configuration and local ID.
/// Its provenance is a local operator trust boundary; Ax's independent durable
/// allocation store must reject rolled-back signing choices, even if a stale
/// valid recovery log is restored.
#[derive(Clone)]
pub struct RecoveryJournal {
    binding: Commitment,
    records: Vec<Input>,
    bytes: usize,
    base_records: u32,
}

/// Canonical additions to an existing recovery journal. The header and record
/// encodings are identical to `RecoveryJournal::encode`; callers must durably
/// append this update before publishing any actions it authorizes.
pub struct RecoveryUpdate {
    pub header: [u8; 53],
    pub previous_records: u32,
    pub body: Vec<u8>,
}

type AuthorizedKey = (u64, MessageKind, Option<Commitment>);
pub struct Quantumglow {
    config: Config,
    local: [u8; 32],
    pool: ConsensusPool,
    states: BTreeMap<u64, SlotState>,
    blocks: BTreeMap<Commitment, Block>,
    first_blocks: BTreeMap<u64, Commitment>,
    deadlines: BTreeMap<u64, u64>,
    started_windows: BTreeSet<u64>,
    repairs: BTreeSet<Commitment>,
    finalized: Vec<BlockRef>,
    // Exact membership mirror of the retained ordered finalized history.
    // It changes no ancestry, authority, journal or compaction lifetime.
    finalized_hashes: BTreeSet<Commitment>,
    last_now: u64,
    stored_bytes: usize,
    journal: RecoveryJournal,
    authorized: BTreeMap<AuthorizedKey, ConsensusMessage>,
    active_anchor: BlockRef,
    active_anchor_state: Commitment,
    #[cfg(test)]
    known_slot_scan_work: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    eager_repair_slot_lookup: bool,
    #[cfg(test)]
    applied_block_buffers: Option<(usize, usize)>,
    #[cfg(test)]
    linear_finalized_lookup: bool,
    #[cfg(test)]
    finalized_linear_comparisons: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    finalized_index_queries: std::sync::atomic::AtomicUsize,
}

impl Quantumglow {
    pub fn new(config: Config, local: [u8; 32], validators: Vec<Validator>) -> Result<Self, Error> {
        let end = config
            .first_slot
            .checked_add(config.slot_count)
            .ok_or(Error::Config)?;
        if config.first_slot == 0
            || config.window_size == 0
            || config.window_size > MAX_SLOT_WINDOW
            || config.slot_count == 0
            || config.slot_count > MAX_EPOCH_SLOTS
            || !config.slot_count.is_multiple_of(config.window_size)
            || config.leaders.len() != config.slot_count as usize
            || config.network_delay_ms == 0
            || config.block_time_ms == 0
            || config.finalized_anchor.slot >= config.first_slot
            || config.execution_rules == [0; 48]
            || !validators.iter().any(|v| v.id == local)
        {
            return Err(Error::Config);
        }
        for window in config.leaders.chunks(config.window_size as usize) {
            if window.iter().any(|id| *id != window[0])
                || !validators.iter().any(|v| v.id == window[0])
                || !config.leader_keys.contains_key(&window[0])
            {
                return Err(Error::Config);
            }
        }
        // Check all timeout arithmetic before accepting any network input.
        config
            .network_delay_ms
            .checked_mul(4)
            .and_then(|x| {
                config
                    .block_time_ms
                    .checked_mul(config.window_size)
                    .and_then(|y| x.checked_add(y))
            })
            .ok_or(Error::Config)?;
        let pool = ConsensusPool::new(
            config.chain,
            config.epoch,
            validators,
            config.first_slot,
            end - config.first_slot,
        )?;
        let binding = config_binding(&config, &local, &pool.validator_set_commitment());
        let anchor = config.finalized_anchor;
        let active_anchor_state = config.finalized_state_root;
        let mut machine = Self {
            config,
            local,
            pool,
            states: BTreeMap::new(),
            blocks: BTreeMap::new(),
            first_blocks: BTreeMap::new(),
            deadlines: BTreeMap::new(),
            started_windows: BTreeSet::new(),
            repairs: BTreeSet::new(),
            finalized: vec![anchor],
            finalized_hashes: BTreeSet::from([anchor.hash]),
            last_now: 0,
            stored_bytes: 0,
            journal: RecoveryJournal {
                binding,
                records: vec![],
                bytes: 0,
                base_records: 0,
            },
            authorized: BTreeMap::new(),
            active_anchor: anchor,
            active_anchor_state,
            #[cfg(test)]
            known_slot_scan_work: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            eager_repair_slot_lookup: false,
            #[cfg(test)]
            applied_block_buffers: None,
            #[cfg(test)]
            linear_finalized_lookup: false,
            #[cfg(test)]
            finalized_linear_comparisons: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            finalized_index_queries: std::sync::atomic::AtomicUsize::new(0),
        };
        machine
            .states
            .entry(machine.config.first_slot)
            .or_default()
            .parent_ready
            .insert(anchor.hash);
        Ok(machine)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn local_validator(&self) -> [u8; 32] {
        self.local
    }
    pub fn clock(&self) -> u64 {
        self.last_now
    }
    pub fn pool(&self) -> &ConsensusPool {
        &self.pool
    }
    pub fn finalized_chain(&self) -> &[BlockRef] {
        &self.finalized
    }
    pub fn payload(&self, hash: &Commitment) -> Option<&[u8]> {
        self.blocks.get(hash).map(|b| b.payload.as_slice())
    }
    pub fn recovery_journal(&self) -> RecoveryJournal {
        self.journal.clone()
    }
    pub fn recovery_record_count(&self) -> u32 {
        self.journal.base_records + self.journal.records.len() as u32
    }
    /// The caller must have synced all records before releasing their buffers.
    /// Complete raw authentication remains on disk; this is not a snapshot.
    pub fn discard_durable_records(&mut self, through: u32) -> Result<(), Error> {
        if through != self.recovery_record_count() {
            return Err(Error::Journal);
        }
        self.journal.base_records = through;
        self.journal.records.clear();
        self.journal.bytes = 0;
        Ok(())
    }
    pub fn journal_binding(&self) -> Commitment {
        self.journal.binding
    }
    /// Replay one canonical durable record; signatures and native execution
    /// are checked normally, and callers apply finalization before the next.
    pub fn replay_record(
        &mut self,
        bytes: &[u8],
    ) -> Result<(usize, Vec<Action>, Option<BlockRef>), Error> {
        let mut reader = Reader { bytes, pos: 0 };
        let input = read_input(&mut reader)?;
        let block = match &input {
            Input::Block(marker, _, _) => Some(BlockRef {
                slot: marker.slot,
                hash: marker.block_commitment,
            }),
            _ => None,
        };
        let actions = self.accept(input)?;
        Ok((reader.pos, actions, block))
    }
    /// Compact only after the actual runtime has rooted the certified chain.
    /// Retain recent certificates and complete windows for delayed fallback.
    pub fn compact_finalized(
        &mut self,
        actual: BlockRef,
        actual_state: Commitment,
    ) -> Result<BlockRef, Error> {
        if self.finalized.last() != Some(&actual)
            || self.parent_state(&actual.hash) != Some(actual_state)
        {
            return Err(Error::InvalidExecution);
        }
        let floor = self
            .window_start(actual.slot.max(self.config.first_slot))
            .saturating_sub(self.config.window_size * 4);
        let anchor = self
            .finalized
            .iter()
            .rev()
            .copied()
            .find(|block| block.slot < floor)
            .unwrap_or(self.active_anchor);
        if anchor.slot <= self.active_anchor.slot {
            return Ok(self.active_anchor);
        }
        let state = self
            .parent_state(&anchor.hash)
            .ok_or(Error::InvalidExecution)?;
        self.active_anchor = anchor;
        self.active_anchor_state = state;
        self.blocks
            .retain(|_, block| block.reference.slot > anchor.slot);
        self.stored_bytes = self.blocks.values().map(|block| block.payload.len()).sum();
        self.states.retain(|slot, _| *slot > anchor.slot);
        self.first_blocks.retain(|slot, _| *slot > anchor.slot);
        self.deadlines.retain(|slot, _| *slot > anchor.slot);
        self.started_windows
            .retain(|slot| *slot + self.config.window_size > anchor.slot);
        self.authorized
            .retain(|(slot, _, _), _| *slot > anchor.slot);
        self.repairs.retain(|hash| self.blocks.contains_key(hash));
        self.pool.prune_through(anchor.slot)?;
        Ok(anchor)
    }
    /// Encode only records not yet durable, without cloning historic blocks,
    /// shreds or evidence. A stale cursor cannot alter the prior record prefix.
    pub fn recovery_update_since(&self, previous_records: u32) -> Result<RecoveryUpdate, Error> {
        self.journal.update_since(previous_records)
    }
    /// Recover publication after a crash between persisting Votor's decision
    /// and publishing its signature. The durable Ax signer returns a previously
    /// released witness unchanged, or safely signs the still-unused reservation.
    /// A crash-burned key without a released witness remains unavailable.
    pub fn retransmission_intents(&self) -> Vec<ConsensusMessage> {
        self.authorized.values().cloned().collect()
    }
    pub fn ready_parents(&self, slot: u64) -> Vec<Commitment> {
        self.states
            .get(&slot)
            .map(|s| s.parent_ready.iter().copied().collect())
            .unwrap_or_default()
    }
    pub fn restore(
        config: Config,
        local: [u8; 32],
        validators: Vec<Validator>,
        journal: RecoveryJournal,
    ) -> Result<Self, Error> {
        let mut restored = Self::new(config, local, validators)?;
        if restored.journal.binding != journal.binding {
            return Err(Error::Journal);
        }
        for input in &journal.records {
            restored.apply(input, None)?;
        }
        restored.journal = journal;
        Ok(restored)
    }
    /// Persist the returned recovery journal before signing/broadcasting actions.
    pub fn receive(&mut self, evidence: SignedEvidence, now_ms: u64) -> Result<Vec<Action>, Error> {
        self.accept(Input::Evidence(evidence, now_ms))
    }
    pub fn evidence_verifier(&self) -> EvidenceVerifier {
        self.pool.evidence_verifier()
    }
    /// Live-only authentication outcome; the journal still owns the unchanged
    /// raw witness and replay never receives or trusts this transient receipt.
    pub fn receive_prepared(
        &mut self,
        prepared: PreparedEvidence,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        let (evidence, authentication) = prepared.into_parts();
        self.accept_authenticated(
            Input::Evidence(evidence, now_ms),
            None,
            Some(authentication),
        )
    }
    pub fn observe_block(
        &mut self,
        marker: FinalMarker,
        shreds: Vec<AuthenticatedShred>,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        self.accept(Input::Block(Box::new(marker), shreds, now_ms))
    }
    /// Consume live authentication bound to this exact finalized leader role.
    /// Only raw witnesses enter the journal; restore always authenticates anew.
    pub fn observe_verified(
        &mut self,
        candidate: VerifiedCandidate,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        let marker = candidate.marker();
        if marker.leader_epoch != self.config.epoch || !self.in_range(marker.slot) {
            return Err(Error::BlockAuthentication);
        }
        let leader = self.config.leaders[(marker.slot - self.config.first_slot) as usize];
        let key = self.config.leader_keys.get(&leader).ok_or(Error::Config)?;
        let (marker, shreds, payload) = candidate
            .into_parts(&self.config.chain, key)
            .map_err(|_| Error::BlockAuthentication)?;
        self.accept_verified(
            Input::Block(Box::new(marker), shreds, now_ms),
            Some(payload),
        )
    }
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action>, Error> {
        self.accept(Input::Tick(now_ms))
    }
    fn accept(&mut self, input: Input) -> Result<Vec<Action>, Error> {
        self.accept_verified(input, None)
    }
    fn accept_verified(
        &mut self,
        input: Input,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<Action>, Error> {
        self.accept_authenticated(input, payload, None)
    }
    fn accept_authenticated(
        &mut self,
        input: Input,
        payload: Option<Vec<u8>>,
        authentication: Option<EvidenceAuthentication>,
    ) -> Result<Vec<Action>, Error> {
        let size = input_bytes(&input)?;
        if self.journal.bytes.saturating_add(size) > MAX_JOURNAL_BYTES
            || self.recovery_record_count() as usize >= MAX_JOURNAL_RECORDS
        {
            return Err(Error::JournalBounds);
        }
        let actions = self.apply_authenticated(&input, payload, authentication)?;
        self.journal.records.push(input);
        self.journal.bytes += size;
        Ok(actions)
    }
    fn apply(&mut self, input: &Input, payload: Option<Vec<u8>>) -> Result<Vec<Action>, Error> {
        self.apply_authenticated(input, payload, None)
    }
    fn apply_authenticated(
        &mut self,
        input: &Input,
        payload: Option<Vec<u8>>,
        authentication: Option<EvidenceAuthentication>,
    ) -> Result<Vec<Action>, Error> {
        let now = match input {
            Input::Evidence(_, t) | Input::Block(_, _, t) | Input::Tick(t) => *t,
        };
        if now < self.last_now {
            return Err(Error::Clock);
        }
        let mut actions = vec![];
        match input {
            Input::Evidence(evidence, _) => {
                let validator = evidence.validator;
                let slot = evidence.message.slot;
                match self
                    .pool
                    .insert_authenticated(evidence.clone(), authentication)
                {
                    Ok(events) => self.process_events(events, &mut actions),
                    Err(ConsensusError::Equivocation) => {
                        actions.push(Action::Equivocation { validator, slot })
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Input::Block(marker, shreds, _) => {
                self.insert_block(marker, shreds, payload, &mut actions)?
            }
            Input::Tick(_) => {}
        }
        self.last_now = now;
        self.parent_ready(now, &mut actions)?;
        // Check pending blocks before timers at the same instant: the block event
        // won the serialized event race. A later arrival cannot undo a skip.
        self.check_pending(&mut actions);
        let expired: Vec<_> = self
            .deadlines
            .iter()
            .filter_map(|(s, t)| (*t <= now).then_some(*s))
            .collect();
        for slot in expired {
            self.deadlines.remove(&slot);
            if self.states.get(&slot).and_then(|s| s.initial).is_none() {
                self.skip_window(slot, &mut actions);
            }
        }
        self.fallbacks(&mut actions);
        self.finalize(&mut actions)?;
        Ok(actions)
    }
    fn in_range(&self, slot: u64) -> bool {
        slot >= self.config.first_slot && slot < self.config.first_slot + self.config.slot_count
    }
    fn window_start(&self, slot: u64) -> u64 {
        self.config.first_slot
            + (slot - self.config.first_slot) / self.config.window_size * self.config.window_size
    }
    fn broadcast(
        &mut self,
        slot: u64,
        kind: MessageKind,
        block: Option<Commitment>,
        actions: &mut Vec<Action>,
    ) {
        let message = ConsensusMessage {
            epoch: self.config.epoch,
            slot,
            kind,
            block,
        };
        self.authorized.insert((slot, kind, block), message.clone());
        actions.push(Action::Broadcast(message));
    }
    fn process_events(&mut self, events: Vec<ConsensusEvent>, actions: &mut Vec<Action>) {
        for event in events {
            match event {
                ConsensusEvent::WeakCertificate {
                    slot,
                    kind: CertificateKind::Notar,
                    block: Some(block),
                } => {
                    self.states.entry(slot).or_default().notarized.insert(block);
                    self.try_final(slot, block, actions);
                    if !self.blocks.contains_key(&block) {
                        self.repair(Some(slot), block, actions);
                    }
                }
                ConsensusEvent::WeakCertificate {
                    slot,
                    kind: CertificateKind::NotarFallback,
                    block: Some(block),
                } if !self.blocks.contains_key(&block) => self.repair(Some(slot), block, actions),
                ConsensusEvent::BroadcastApproval { slot, kind, block }
                    if self
                        .states
                        .entry(slot)
                        .or_default()
                        .approvals
                        .insert((kind, block)) =>
                {
                    self.broadcast(slot, kind, block, actions);
                }
                _ => {}
            }
        }
    }
    fn insert_block(
        &mut self,
        marker: &FinalMarker,
        shreds: &[AuthenticatedShred],
        verified_payload: Option<Vec<u8>>,
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        #[cfg(test)]
        {
            self.applied_block_buffers = Some((
                shreds.as_ptr() as usize,
                shreds
                    .first()
                    .map_or(0, |shred| shred.payload.as_ptr() as usize),
            ));
        }
        if marker.leader_epoch != self.config.epoch || !self.in_range(marker.slot) {
            return Err(Error::BlockAuthentication);
        }
        let leader = self.config.leaders[(marker.slot - self.config.first_slot) as usize];
        let key = self
            .config
            .leader_keys
            .get(&leader)
            .ok_or(Error::Config)?
            .clone();
        let payload = if let Some(payload) = verified_payload {
            payload
        } else {
            let mut assembler = CandidateAssembler::new(
                self.config.chain,
                key,
                self.config.epoch,
                marker.slot,
                marker.candidate,
                marker.parent,
            );
            // Raw/recovery inputs still reconstruct and authenticate every
            // witness. Live verified payloads do not need this owned copy.
            for shred in shreds.iter().cloned() {
                assembler
                    .insert(shred)
                    .map_err(|_| Error::BlockAuthentication)?;
            }
            assembler
                .finish(marker)
                .map_err(|_| Error::BlockAuthentication)?
        };
        if marker.slot <= self.active_anchor.slot {
            return Ok(());
        }
        let execution = (self.config.validate_execution)(&ExecutionCandidate {
            reference: BlockRef {
                slot: marker.slot,
                hash: marker.block_commitment,
            },
            parent: marker.parent,
            payload: &payload,
        })
        .ok_or(Error::InvalidExecution)?;
        let expected_parent_state = self.parent_state(&marker.parent);
        if expected_parent_state.is_some_and(|root| root != execution.parent_state_root) {
            return Err(Error::InvalidExecution);
        }
        if self.blocks.contains_key(&marker.block_commitment) {
            return Ok(());
        }
        if self
            .blocks
            .values()
            .filter(|b| b.reference.slot == marker.slot)
            .count()
            >= MAX_BLOCKS_PER_SLOT
            || self.stored_bytes.saturating_add(payload.len()) > MAX_STORED_BLOCK_BYTES
        {
            return Err(Error::Bounds);
        }
        if marker.parent == marker.block_commitment
            || self
                .blocks
                .get(&marker.parent)
                .is_some_and(|p| p.reference.slot >= marker.slot)
            || marker.parent == self.active_anchor.hash && self.active_anchor.slot >= marker.slot
        {
            return Err(Error::InvalidAncestry);
        }
        let slot = marker.slot;
        let hash = marker.block_commitment;
        self.stored_bytes += payload.len();
        self.blocks.insert(
            hash,
            Block {
                reference: BlockRef { slot, hash },
                parent: marker.parent,
                payload,
                execution,
            },
        );
        self.repairs.remove(&hash);
        // Definition 10 emits Block only for the first completely received block.
        // Additional repaired alternatives can authorize fallback but no new initial vote.
        if let std::collections::btree_map::Entry::Vacant(entry) = self.first_blocks.entry(slot) {
            entry.insert(hash);
            if !self.try_notar(slot, hash, actions)
                && self.states.entry(slot).or_default().initial.is_none()
            {
                self.states.entry(slot).or_default().pending = Some(hash);
            }
        }
        Ok(())
    }
    fn try_notar(&mut self, slot: u64, hash: Commitment, actions: &mut Vec<Action>) -> bool {
        if self.states.entry(slot).or_default().initial.is_some() {
            return false;
        }
        let Some(block) = self.blocks.get(&hash) else {
            return false;
        };
        let parent = block.parent;
        let claimed_parent_state = block.execution.parent_state_root;
        let Some(parent_state) = self.parent_state(&parent) else {
            self.repair_unknown_slot(parent, actions);
            return false;
        };
        if parent_state != claimed_parent_state {
            return false;
        }
        let legal = if self.window_start(slot) == slot {
            self.states[&slot].parent_ready.contains(&block.parent)
        } else {
            self.states.get(&(slot - 1)).and_then(|s| s.initial) == Some(Some(block.parent))
        };
        if !legal {
            return false;
        }
        let state = self.states.entry(slot).or_default();
        state.initial = Some(Some(hash));
        state.pending = None;
        self.broadcast(slot, MessageKind::NotarVote, Some(hash), actions);
        self.try_final(slot, hash, actions);
        true
    }
    fn try_final(&mut self, slot: u64, hash: Commitment, actions: &mut Vec<Action>) {
        let state = self.states.entry(slot).or_default();
        if state.notarized.contains(&hash)
            && state.initial == Some(Some(hash))
            && !state.bad_window
            && !state.its_over
        {
            state.its_over = true;
            self.broadcast(slot, MessageKind::FinalVote, None, actions);
        }
    }
    fn skip_window(&mut self, slot: u64, actions: &mut Vec<Action>) {
        let start = self.window_start(slot);
        for s in start.max(self.active_anchor.slot + 1)..start + self.config.window_size {
            let state = self.states.entry(s).or_default();
            if state.initial.is_none() {
                state.initial = Some(None);
                state.bad_window = true;
                state.pending = None;
                self.broadcast(s, MessageKind::SkipVote, None, actions);
            }
        }
    }
    fn check_pending(&mut self, actions: &mut Vec<Action>) {
        let pending: Vec<_> = self
            .states
            .iter()
            .filter_map(|(s, state)| state.pending.map(|h| (*s, h)))
            .collect();
        for (slot, hash) in pending {
            self.try_notar(slot, hash, actions);
        }
    }
    fn repair(&mut self, slot: Option<u64>, block: Commitment, actions: &mut Vec<Action>) {
        if self.repairs.insert(block) {
            actions.push(Action::Repair { slot, block });
        }
    }
    fn repair_unknown_slot(&mut self, block: Commitment, actions: &mut Vec<Action>) {
        // The exact pending hash already suppresses this action. In a missing
        // body backlog, do not scan every certificate again just to discard
        // the resulting hint. This changes neither the first request nor its
        // lifetime: block observation and compaction still clear repairs.
        #[cfg(test)]
        if self.eager_repair_slot_lookup {
            // Reference the former eager ordering for byte/action/work oracles.
            self.repair(self.known_slot(&block), block, actions);
            return;
        }
        if !self.repairs.contains(&block) {
            self.repair(self.known_slot(&block), block, actions);
        }
    }
    fn parent_ready(&mut self, now: u64, actions: &mut Vec<Action>) -> Result<(), Error> {
        let mut parents = vec![self.active_anchor];
        for slot in self.pool.active_slots() {
            parents.extend(
                self.pool
                    .certificate_blocks(slot, true)
                    .into_iter()
                    .map(|hash| BlockRef { slot, hash }),
            );
        }
        let end = self.config.first_slot + self.config.slot_count;
        for parent in parents {
            let relative = parent
                .slot
                .saturating_add(1)
                .saturating_sub(self.config.first_slot);
            let mut start = self.config.first_slot
                + relative.div_ceil(self.config.window_size) * self.config.window_size;
            while start < end {
                if !(self.config.first_slot.max(parent.slot + 1)..start).all(|slot| {
                    self.pool
                        .has_certificate(slot, CertificateKind::Skip, None, true)
                }) {
                    break;
                }
                let state = self.states.entry(start).or_default();
                let new = state.parent_ready.insert(parent.hash);
                let first = self.started_windows.insert(start);
                if first {
                    for slot in start..start + self.config.window_size {
                        let duration = self.config.network_delay_ms * 4
                            + (slot - start + 1) * self.config.block_time_ms;
                        self.deadlines
                            .entry(slot)
                            .or_insert(now.checked_add(duration).ok_or(Error::Clock)?);
                    }
                }
                if new || first {
                    actions.push(Action::ParentReady {
                        slot: start,
                        parent: parent.hash,
                    });
                }
                start += self.config.window_size;
            }
        }
        Ok(())
    }
    fn fallbacks(&mut self, actions: &mut Vec<Action>) {
        let total = self.pool.total_stake();
        for slot in self.states.keys().copied().collect::<Vec<_>>() {
            let Some(initial) = self.states.get(&slot).and_then(|s| s.initial) else {
                continue;
            };
            let (skip, notar) = self.pool.initial_stakes(slot);
            for (hash, stake) in &notar {
                if initial == Some(*hash) || self.states[&slot].safe_notar.contains(hash) {
                    continue;
                }
                if !at_least(*stake, total, 40)
                    && !(at_least(skip + stake, total, 60) && at_least(*stake, total, 20))
                {
                    continue;
                }
                let Some(block) = self.blocks.get(hash) else {
                    self.repair(Some(slot), *hash, actions);
                    continue;
                };
                let parent = block.parent;
                let claimed_parent_state = block.execution.parent_state_root;
                let Some(parent_state) = self.parent_state(&parent) else {
                    self.repair_unknown_slot(parent, actions);
                    continue;
                };
                if parent_state != claimed_parent_state {
                    continue;
                }
                if self.window_start(slot) != slot {
                    let parent_cert = self.pool.active_slots().filter(|p| *p < slot).any(|p| {
                        self.pool.has_certificate(
                            p,
                            CertificateKind::NotarFallback,
                            Some(block.parent),
                            false,
                        )
                    });
                    if !parent_cert {
                        continue;
                    }
                }
                self.states
                    .entry(slot)
                    .or_default()
                    .safe_notar
                    .insert(*hash);
                self.skip_window(slot, actions);
                if !self.states[&slot].its_over {
                    self.states.entry(slot).or_default().bad_window = true;
                    self.broadcast(slot, MessageKind::NotarFallbackVote, Some(*hash), actions);
                }
            }
            let sum: u64 = notar.values().sum();
            let max = notar.values().copied().max().unwrap_or(0);
            if initial.is_some()
                && !self.states[&slot].safe_skip
                && at_least(skip + sum - max, total, 40)
            {
                self.states.entry(slot).or_default().safe_skip = true;
                self.skip_window(slot, actions);
                if !self.states[&slot].its_over {
                    self.states.entry(slot).or_default().bad_window = true;
                    self.broadcast(slot, MessageKind::SkipFallbackVote, None, actions);
                }
            }
        }
    }
    fn parent_state(&self, hash: &Commitment) -> Option<Commitment> {
        if *hash == self.active_anchor.hash {
            Some(self.active_anchor_state)
        } else {
            self.blocks.get(hash).map(|p| p.execution.state_root)
        }
    }
    fn known_slot(&self, hash: &Commitment) -> Option<u64> {
        if *hash == self.active_anchor.hash {
            return Some(self.active_anchor.slot);
        }
        if let Some(b) = self.blocks.get(hash) {
            return Some(b.reference.slot);
        }
        self.pool.active_slots().find(|s| {
            #[cfg(test)]
            self.known_slot_scan_work
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.pool.certificate_blocks(*s, false).contains(hash)
        })
    }
    fn contains_finalized(&self, hash: &Commitment) -> bool {
        #[cfg(test)]
        if self.linear_finalized_lookup {
            // Exact former full48 membership operation, retained as a work
            // and ordered-action oracle without hardware timing assertions.
            return self.finalized.iter().rev().any(|block| {
                self.finalized_linear_comparisons
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                block.hash == *hash
            });
        }
        #[cfg(test)]
        self.finalized_index_queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.finalized_hashes.contains(hash)
    }
    fn finalize(&mut self, actions: &mut Vec<Action>) -> Result<(), Error> {
        for slot in self.pool.active_slots().collect::<Vec<_>>() {
            let Some(hash) = self.pool.finalized(slot) else {
                continue;
            };
            if self.contains_finalized(&hash) {
                continue;
            }
            if slot <= self.finalized.last().unwrap().slot {
                return Err(Error::SafetyViolation);
            }
            let mut chain = vec![];
            let mut next = hash;
            let last = self.finalized.last().unwrap().hash;
            let mut previous_slot = u64::MAX;
            while next != last {
                if next == self.active_anchor.hash {
                    return Err(Error::SafetyViolation);
                }
                let Some(block) = self.blocks.get(&next) else {
                    self.repair_unknown_slot(next, actions);
                    break;
                };
                if block.reference.slot >= previous_slot {
                    return Err(Error::InvalidAncestry);
                }
                if self
                    .parent_state(&block.parent)
                    .is_some_and(|root| root != block.execution.parent_state_root)
                {
                    return Err(Error::InvalidExecution);
                }
                previous_slot = block.reference.slot;
                chain.push(block.reference);
                next = block.parent;
                if chain.len() > self.config.slot_count as usize {
                    return Err(Error::InvalidAncestry);
                }
            }
            if next == last {
                for block in chain.into_iter().rev() {
                    if block.slot <= self.finalized.last().unwrap().slot {
                        return Err(Error::SafetyViolation);
                    }
                    self.finalized.push(block);
                    self.finalized_hashes.insert(block.hash);
                    actions.push(Action::Finalized(block));
                }
            }
        }
        Ok(())
    }
    /// Epoch boundary. The next validator/leader-key set must be committed by
    /// the finalized boundary block's payload; old/in-flight evidence never
    /// enters the new epoch pool. The anchor and epoch increment are checked.
    pub fn transition(
        self,
        next: Config,
        validators: Vec<Validator>,
        now_ms: u64,
    ) -> Result<(Self, Vec<Action>), Error> {
        let boundary = self.config.first_slot + self.config.slot_count - 1;
        let anchor = *self.finalized.last().unwrap();
        if !(anchor.slot + 1..=boundary).all(|s| {
            self.pool
                .has_certificate(s, CertificateKind::Skip, None, true)
        }) || next.finalized_anchor != anchor
            || next.chain != self.config.chain
            || next.epoch
                != self
                    .config
                    .epoch
                    .checked_add(1)
                    .ok_or(Error::EpochTransition)?
            || next.first_slot != boundary.checked_add(1).ok_or(Error::EpochTransition)?
            || self
                .blocks
                .get(&anchor.hash)
                .is_none_or(|b| b.execution.state_root != next.finalized_state_root)
        {
            return Err(Error::EpochTransition);
        }
        let mut fresh = Self::new(next, self.local, validators)?;
        let expected =
            epoch_configuration_commitment(&fresh.config, &fresh.pool.validator_set_commitment());
        if self.payload(&anchor.hash) != Some(expected.as_slice()) {
            return Err(Error::EpochTransition);
        }
        let actions = fresh.tick(now_ms)?;
        Ok((fresh, actions))
    }
}
fn at_least(stake: u64, total: u64, percent: u64) -> bool {
    u128::from(stake) * 100 >= u128::from(total) * u128::from(percent)
}
fn config_bytes(config: &Config, membership: &Commitment, include_anchor: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&config.chain);
    out.extend_from_slice(&config.epoch.to_le_bytes());
    out.extend_from_slice(&config.first_slot.to_le_bytes());
    out.extend_from_slice(&config.slot_count.to_le_bytes());
    out.extend_from_slice(&config.window_size.to_le_bytes());
    out.extend_from_slice(&config.network_delay_ms.to_le_bytes());
    out.extend_from_slice(&config.block_time_ms.to_le_bytes());
    out.extend_from_slice(&config.execution_rules);
    out.extend_from_slice(membership);
    for id in &config.leaders {
        out.extend_from_slice(id);
        out.extend_from_slice(config.leader_keys[id].as_bytes());
    }
    if include_anchor {
        out.extend_from_slice(&config.finalized_anchor.slot.to_le_bytes());
        out.extend_from_slice(&config.finalized_anchor.hash);
        out.extend_from_slice(&config.finalized_state_root);
    }
    out
}
fn config_binding(config: &Config, local: &[u8; 32], membership: &Commitment) -> Commitment {
    hash_commitment(
        b"pq-votor-local-journal-v1",
        &[&config_bytes(config, membership, true), local],
    )
}
/// Excludes the boundary block hash to avoid a circular commitment.
pub fn epoch_configuration_commitment(config: &Config, membership: &Commitment) -> Commitment {
    hash_commitment(
        b"pq-votor-next-epoch-v1",
        &[&config_bytes(config, membership, false)],
    )
}
fn input_bytes(input: &Input) -> Result<usize, Error> {
    Ok(match input {
        Input::Evidence(e, _) => e.encode()?.len() + 13,
        Input::Block(marker, shreds, _) => {
            shreds
                .iter()
                .try_fold(marker.encode().len() + 17, |size, shred| {
                    size.checked_add(
                        shred
                            .encoded_len()
                            .map_err(|_| Error::BlockAuthentication)?
                            + 4,
                    )
                    .ok_or(Error::BlockAuthentication)
                })?
        }
        Input::Tick(_) => 9,
    })
}

impl RecoveryJournal {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let update = self.update_since(0)?;
        let mut out = update.header.to_vec();
        out.extend_from_slice(&update.body);
        Ok(out)
    }

    fn update_since(&self, previous_records: u32) -> Result<RecoveryUpdate, Error> {
        let offset = previous_records
            .checked_sub(self.base_records)
            .ok_or(Error::Journal)?;
        let Some(records) = self.records.get(offset as usize..) else {
            return Err(Error::Journal);
        };
        let mut header = [0; 53];
        header[0] = 1;
        header[1..49].copy_from_slice(&self.binding);
        header[49..53]
            .copy_from_slice(&(self.base_records + self.records.len() as u32).to_le_bytes());
        let mut out = Vec::new();
        for record in records {
            match record {
                Input::Tick(now) => {
                    out.push(0);
                    out.extend_from_slice(&now.to_le_bytes());
                }
                Input::Evidence(e, now) => {
                    out.push(1);
                    out.extend_from_slice(&now.to_le_bytes());
                    put_bytes(&mut out, &e.encode()?);
                }
                Input::Block(marker, shreds, now) => {
                    out.push(2);
                    out.extend_from_slice(&now.to_le_bytes());
                    put_bytes(&mut out, &marker.encode());
                    out.extend_from_slice(&(shreds.len() as u32).to_le_bytes());
                    for shred in shreds {
                        let len = shred.encoded_len().map_err(|_| Error::Journal)?;
                        out.extend_from_slice(&(len as u32).to_le_bytes());
                        shred.encode_into(&mut out).map_err(|_| Error::Journal)?;
                    }
                }
            }
        }
        if out.len() > MAX_JOURNAL_BYTES - header.len() {
            return Err(Error::Bounds);
        }
        Ok(RecoveryUpdate {
            header,
            previous_records,
            body: out,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(Error::Bounds);
        }
        let mut r = Reader { bytes, pos: 0 };
        if r.take(1)? != [1] {
            return Err(Error::Journal);
        }
        let binding = r.take(48)?.try_into().map_err(|_| Error::Journal)?;
        let count = r.u32()?;
        if count as usize > bytes.len() / 9 || count as usize > MAX_JOURNAL_RECORDS {
            return Err(Error::Journal);
        }
        let mut records = Vec::new();
        let mut retained = 0;
        for _ in 0..count {
            let record = read_input(&mut r)?;
            retained += input_bytes(&record)?;
            records.push(record);
        }
        if r.pos != bytes.len() {
            return Err(Error::Journal);
        }
        Ok(Self {
            binding,
            records,
            bytes: retained,
            base_records: 0,
        })
    }
}
fn read_input(r: &mut Reader<'_>) -> Result<Input, Error> {
    let tag = r.take(1)?[0];
    let now = r.u64()?;
    let record = match tag {
        0 => Input::Tick(now),
        1 => Input::Evidence(SignedEvidence::decode(r.blob()?)?, now),
        2 => {
            let marker = FinalMarker::decode(r.blob()?).map_err(|_| Error::Journal)?;
            let n = r.u32()? as usize;
            if n > r.bytes.len() / 4 {
                return Err(Error::Journal);
            }
            let mut shreds = Vec::new();
            for _ in 0..n {
                shreds.push(AuthenticatedShred::decode(r.blob()?).map_err(|_| Error::Journal)?);
            }
            Input::Block(Box::new(marker), shreds, now)
        }
        _ => return Err(Error::Journal),
    };
    Ok(record)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Journal)?;
        let out = self.bytes.get(self.pos..end).ok_or(Error::Journal)?;
        self.pos = end;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Journal)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Journal)?,
        ))
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod recovery_update_tests {
    use {
        super::*,
        crate::{
            crypto::FalconKeypair,
            network::{BatchContext, SignedBatch},
        },
    };

    fn repair_backlog_fixture(
        slots: u32,
        window: u64,
    ) -> (
        FalconKeypair,
        crate::consensus::ConsensusKeypair,
        Config,
        Vec<Validator>,
    ) {
        let chain = [0xb1; 32];
        let local = [0xb2; 32];
        let leader = FalconKeypair::generate();
        let signer =
            crate::consensus::ConsensusKeypair::generate_for(chain, local, 1, 1, slots).unwrap();
        let validators = vec![Validator {
            id: local,
            stake: 1,
            key: signer.public_key(),
        }];
        let config = Config {
            chain,
            epoch: 1,
            first_slot: 1,
            slot_count: u64::from(slots),
            window_size: window,
            network_delay_ms: 100,
            block_time_ms: 1000,
            leaders: vec![local; slots as usize],
            leader_keys: BTreeMap::from([(local, leader.public_key())]),
            finalized_anchor: BlockRef {
                slot: 0,
                hash: [0xb3; 48],
            },
            finalized_state_root: repair_backlog_state(0),
            execution_rules: [0xb4; 48],
            validate_execution: Arc::new(|candidate| {
                let parent_slot = u64::from_le_bytes(candidate.payload.try_into().ok()?);
                Some(ExecutionState {
                    parent_state_root: repair_backlog_state(parent_slot),
                    state_root: repair_backlog_state(candidate.reference.slot),
                })
            }),
        };
        (leader, signer, config, validators)
    }

    fn repair_backlog_state(slot: u64) -> Commitment {
        hash_commitment(b"repair-backlog-state", &[&slot.to_le_bytes()])
    }

    // Original framed journal writer, including per-shred temporary encoding,
    // retained only as a byte/error oracle for the direct append path.
    fn legacy_journal_update(
        journal: &RecoveryJournal,
        previous_records: u32,
    ) -> Result<RecoveryUpdate, Error> {
        let offset = previous_records
            .checked_sub(journal.base_records)
            .ok_or(Error::Journal)?;
        let records = journal
            .records
            .get(offset as usize..)
            .ok_or(Error::Journal)?;
        let mut header = [0; 53];
        header[0] = 1;
        header[1..49].copy_from_slice(&journal.binding);
        header[49..53]
            .copy_from_slice(&(journal.base_records + journal.records.len() as u32).to_le_bytes());
        let mut out = Vec::new();
        for record in records {
            match record {
                Input::Tick(now) => {
                    out.push(0);
                    out.extend_from_slice(&now.to_le_bytes());
                }
                Input::Evidence(e, now) => {
                    out.push(1);
                    out.extend_from_slice(&now.to_le_bytes());
                    put_bytes(&mut out, &e.encode()?);
                }
                Input::Block(marker, shreds, now) => {
                    out.push(2);
                    out.extend_from_slice(&now.to_le_bytes());
                    put_bytes(&mut out, &marker.encode());
                    out.extend_from_slice(&(shreds.len() as u32).to_le_bytes());
                    for shred in shreds {
                        put_bytes(
                            &mut out,
                            &shred.encode_legacy_for_test().map_err(|_| Error::Journal)?,
                        );
                    }
                }
            }
        }
        if out.len() > MAX_JOURNAL_BYTES - header.len() {
            return Err(Error::Bounds);
        }
        Ok(RecoveryUpdate {
            header,
            previous_records,
            body: out,
        })
    }

    #[test]
    fn prepared_evidence_preserves_full_actions_raw_journal_and_authenticated_replay() {
        let (leader, signer, config, validators) = borrow_fixture();
        let local = config.leaders[0];
        let mut raw = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut live = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let candidate = borrow_candidate(&config, &leader, 1, config.finalized_anchor);
        let hash = candidate.marker().block_commitment;
        assert_eq!(
            raw.observe_verified(candidate.clone(), 3).unwrap(),
            live.observe_verified(candidate, 3).unwrap()
        );
        let mut inputs = Vec::new();
        for kind in [
            MessageKind::NotarVote,
            MessageKind::NotarApproval,
            MessageKind::FinalVote,
        ] {
            inputs.push(
                signer
                    .sign(
                        &config.chain,
                        local,
                        ConsensusMessage {
                            epoch: config.epoch,
                            slot: 1,
                            kind,
                            block: (kind != MessageKind::FinalVote).then_some(hash),
                        },
                    )
                    .unwrap(),
            );
        }
        inputs.push(inputs[0].clone());
        let verifier = live.evidence_verifier();
        let prepared = inputs
            .iter()
            .cloned()
            .map(|e| verifier.prepare(e))
            .collect::<Vec<_>>();
        for (position, (evidence, prepared)) in inputs.into_iter().zip(prepared).enumerate() {
            let now = 4 + position as u64;
            assert_eq!(
                raw.receive(evidence, now),
                live.receive_prepared(prepared, now)
            );
            assert_eq!(raw.authorized, live.authorized);
            assert_eq!(raw.finalized_chain(), live.finalized_chain());
            assert_eq!(
                raw.recovery_journal().encode().unwrap(),
                live.recovery_journal().encode().unwrap()
            );
        }
        let wire = live.recovery_journal().encode().unwrap();
        let restored = Quantumglow::restore(
            config.clone(),
            local,
            validators.clone(),
            RecoveryJournal::decode(&wire).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.recovery_journal().encode().unwrap(), wire);
        assert_eq!(restored.finalized_chain(), live.finalized_chain());
        let mut corrupt = RecoveryJournal::decode(&wire).unwrap();
        let evidence = corrupt
            .records
            .iter_mut()
            .find_map(|input| match input {
                Input::Evidence(evidence, _) => Some(evidence),
                _ => None,
            })
            .unwrap();
        *evidence.signature.last_mut().unwrap() ^= 1;
        assert!(matches!(
            Quantumglow::restore(config, local, validators, corrupt),
            Err(Error::Consensus(ConsensusError::Signature))
        ));
    }

    #[test]
    fn prepared_evidence_journal_and_clock_errors_precede_authentication_failure() {
        let (_leader, signer, config, validators) = borrow_fixture();
        let local = config.leaders[0];
        let mut raw = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut live = Quantumglow::new(config.clone(), local, validators).unwrap();
        let mut invalid = signer
            .sign(
                &config.chain,
                local,
                ConsensusMessage {
                    epoch: config.epoch,
                    slot: 1,
                    kind: MessageKind::NotarVote,
                    block: Some([0xf1; 48]),
                },
            )
            .unwrap();
        *invalid.signature.last_mut().unwrap() ^= 1;
        raw.journal.bytes = MAX_JOURNAL_BYTES;
        live.journal.bytes = MAX_JOURNAL_BYTES;
        let prepared = live.evidence_verifier().prepare(invalid.clone());
        assert_eq!(raw.receive(invalid.clone(), 1), Err(Error::JournalBounds));
        assert_eq!(
            live.receive_prepared(prepared, 1),
            Err(Error::JournalBounds)
        );
        assert_eq!(raw.recovery_record_count(), 0);
        assert_eq!(live.recovery_record_count(), 0);
        raw.journal.bytes = 0;
        live.journal.bytes = 0;
        raw.tick(10).unwrap();
        live.tick(10).unwrap();
        let before = live.recovery_journal().encode().unwrap();
        let prepared = live.evidence_verifier().prepare(invalid.clone());
        assert_eq!(raw.receive(invalid, 9), Err(Error::Clock));
        assert_eq!(live.receive_prepared(prepared, 9), Err(Error::Clock));
        assert_eq!(live.recovery_journal().encode().unwrap(), before);
        assert_eq!(raw.recovery_journal().encode().unwrap(), before);
    }

    #[test]
    fn direct_journal_append_preserves_legacy_framing_errors_and_temporary_work() {
        use crate::network::{take_shred_encoding_work, take_shred_temporary_encoding_work};
        let (leader, signer, config, validators) = borrow_fixture();
        let local = config.leaders[0];
        let mut machine = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let candidate = borrow_candidate(&config, &leader, 1, config.finalized_anchor);
        let hash = candidate.marker().block_commitment;
        machine.observe_verified(candidate, 3).unwrap();
        let vote = signer
            .sign(
                &config.chain,
                local,
                ConsensusMessage {
                    epoch: config.epoch,
                    slot: 1,
                    kind: MessageKind::NotarVote,
                    block: Some(hash),
                },
            )
            .unwrap();
        machine.receive(vote, 4).unwrap();
        machine.tick(5).unwrap();
        take_shred_encoding_work();
        take_shred_temporary_encoding_work();
        let old = legacy_journal_update(&machine.journal, 0).unwrap();
        let encoded = take_shred_encoding_work();
        assert!(encoded.0 > 0 && encoded.1 > 0);
        assert_eq!(take_shred_temporary_encoding_work(), encoded);
        let current = machine.journal.update_since(0).unwrap();
        assert_eq!(current.header, old.header);
        assert_eq!(current.body, old.body);
        assert_eq!(current.previous_records, old.previous_records);
        assert_eq!(take_shred_encoding_work(), encoded);
        assert_eq!(take_shred_temporary_encoding_work(), (0, 0));
        for previous in 0..=machine.recovery_record_count() {
            let old = legacy_journal_update(&machine.journal, previous).unwrap();
            let current = machine.journal.update_since(previous).unwrap();
            assert_eq!(current.header, old.header);
            assert_eq!(current.body, old.body);
        }
        let mut wire = old.header.to_vec();
        wire.extend_from_slice(&old.body);
        assert_eq!(machine.journal.encode().unwrap(), wire);
        let restored = Quantumglow::restore(
            config.clone(),
            local,
            validators.clone(),
            RecoveryJournal::decode(&wire).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.finalized_chain(), machine.finalized_chain());
        assert_eq!(restored.authorized, machine.authorized);
        assert_eq!(restored.recovery_journal().encode().unwrap(), wire);
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(RecoveryJournal::decode(&trailing).is_err());
        let mut damaged = RecoveryJournal::decode(&wire).unwrap();
        let Input::Block(_, shreds, _) = &mut damaged.records[0] else {
            unreachable!()
        };
        shreds[0].payload[0] ^= 1;
        assert!(matches!(
            Quantumglow::restore(config, local, validators, damaged),
            Err(Error::BlockAuthentication)
        ));
        let invalid_offset = machine.recovery_record_count() + 1;
        assert_eq!(
            machine.journal.update_since(invalid_offset).err(),
            legacy_journal_update(&machine.journal, invalid_offset).err()
        );
        let Input::Block(_, shreds, _) = &mut machine.journal.records[0] else {
            unreachable!()
        };
        shreds[0].metadata.data_shards = 0;
        assert_eq!(machine.journal.update_since(0).err(), Some(Error::Journal));
        assert_eq!(
            machine.journal.update_since(0).err(),
            legacy_journal_update(&machine.journal, 0).err()
        );
    }

    // The old sizing and owned-input application boundary are retained here as
    // a differential oracle. Only the verified-block path's clone work is
    // compared: borrowed raw replay still clones witnesses into its assembler.
    fn legacy_input_bytes(input: &Input) -> Result<usize, Error> {
        Ok(match input {
            Input::Evidence(e, _) => e.encode()?.len() + 13,
            Input::Block(marker, shreds, _) => {
                marker.encode().len()
                    + 17
                    + shreds
                        .iter()
                        .map(|s| s.encode().map(|b| b.len() + 4))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| Error::BlockAuthentication)?
                        .iter()
                        .sum::<usize>()
            }
            Input::Tick(_) => 9,
        })
    }

    fn legacy_accept(
        machine: &mut Quantumglow,
        input: Input,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<Action>, Error> {
        let size = legacy_input_bytes(&input)?;
        if machine.journal.bytes.saturating_add(size) > MAX_JOURNAL_BYTES
            || machine.recovery_record_count() as usize >= MAX_JOURNAL_RECORDS
        {
            return Err(Error::JournalBounds);
        }
        let owned = input.clone();
        let actions = machine.apply(&owned, payload)?;
        machine.journal.records.push(input);
        machine.journal.bytes += size;
        Ok(actions)
    }

    fn borrow_candidate(
        config: &Config,
        leader: &FalconKeypair,
        slot: u64,
        parent: BlockRef,
    ) -> VerifiedCandidate {
        let mut payload = vec![0xe3; 8192];
        payload[..8].copy_from_slice(&parent.slot.to_le_bytes());
        let batch = SignedBatch::build(
            &config.chain,
            leader,
            BatchContext {
                leader_epoch: config.epoch,
                slot,
                candidate: repair_backlog_state(slot),
                parent: parent.hash,
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            4,
            4,
        )
        .unwrap();
        FinalMarker::build_verified(&config.chain, leader, &[batch], &payload).unwrap()
    }

    fn borrow_fixture() -> (
        FalconKeypair,
        crate::consensus::ConsensusKeypair,
        Config,
        Vec<Validator>,
    ) {
        let (leader, signer, mut config, validators) = repair_backlog_fixture(8, 4);
        config.validate_execution = Arc::new(|candidate| {
            let parent_slot = u64::from_le_bytes(candidate.payload.get(..8)?.try_into().ok()?);
            Some(ExecutionState {
                parent_state_root: repair_backlog_state(parent_slot),
                state_root: repair_backlog_state(candidate.reference.slot),
            })
        });
        (leader, signer, config, validators)
    }

    #[test]
    fn borrowed_input_preserves_legacy_actions_full_journal_and_authenticated_replay() {
        let (leader, signer, config, validators) = borrow_fixture();
        let local = config.leaders[0];
        let mut live = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut legacy = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut raw = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut parent = config.finalized_anchor;
        let mut actions_by_record = Vec::new();
        for slot in 1..=4 {
            let candidate = borrow_candidate(&config, &leader, slot, parent);
            parent = BlockRef {
                slot,
                hash: candidate.marker().block_commitment,
            };
            let (marker, shreds, payload) = candidate
                .clone()
                .into_parts(&config.chain, &leader.public_key())
                .unwrap();
            let actions = live.observe_verified(candidate, slot * 3).unwrap();
            assert_eq!(
                actions,
                raw.observe_block(marker.clone(), shreds.clone(), slot * 3)
                    .unwrap()
            );
            assert_eq!(
                actions,
                legacy_accept(
                    &mut legacy,
                    Input::Block(Box::new(marker), shreds, slot * 3),
                    Some(payload)
                )
                .unwrap()
            );
            actions_by_record.push(actions);
            let evidence = signer
                .sign(
                    &config.chain,
                    local,
                    ConsensusMessage {
                        epoch: config.epoch,
                        slot,
                        kind: MessageKind::NotarVote,
                        block: Some(parent.hash),
                    },
                )
                .unwrap();
            let actions = live.receive(evidence.clone(), slot * 3 + 1).unwrap();
            assert_eq!(
                actions,
                raw.receive(evidence.clone(), slot * 3 + 1).unwrap()
            );
            assert_eq!(
                actions,
                legacy_accept(&mut legacy, Input::Evidence(evidence, slot * 3 + 1), None).unwrap()
            );
            actions_by_record.push(actions);
            let actions = live.tick(slot * 3 + 2).unwrap();
            assert_eq!(actions, raw.tick(slot * 3 + 2).unwrap());
            assert_eq!(
                actions,
                legacy_accept(&mut legacy, Input::Tick(slot * 3 + 2), None).unwrap()
            );
            actions_by_record.push(actions);
        }
        assert_eq!(live.finalized_chain().last(), Some(&parent));
        assert_eq!(live.finalized_chain().len(), 5);
        let wire = legacy.recovery_journal().encode().unwrap();
        assert_eq!(live.recovery_journal().encode().unwrap(), wire);
        assert_eq!(raw.recovery_journal().encode().unwrap(), wire);
        assert_eq!(live.journal.bytes, legacy.journal.bytes);
        let journal = RecoveryJournal::decode(&wire).unwrap();
        let restored =
            Quantumglow::restore(config.clone(), local, validators.clone(), journal).unwrap();
        assert_eq!(restored.finalized_chain(), live.finalized_chain());
        assert_eq!(restored.authorized, live.authorized);
        assert_eq!(restored.recovery_journal().encode().unwrap(), wire);
        let body = live.recovery_update_since(0).unwrap().body;
        let mut replay = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut offset = 0usize;
        for expected in actions_by_record {
            let (bytes, actual, _) = replay.replay_record(&body[offset..]).unwrap();
            assert_eq!(actual, expected);
            offset = offset.checked_add(bytes).unwrap();
        }
        assert_eq!(offset, body.len());
        assert_eq!(replay.finalized_chain(), live.finalized_chain());
        assert_eq!(replay.recovery_journal().encode().unwrap(), wire);
        let mut damaged = RecoveryJournal::decode(&wire).unwrap();
        let Input::Block(_, shreds, _) = &mut damaged.records[0] else {
            unreachable!()
        };
        shreds[0].payload[0] ^= 1;
        assert!(matches!(
            Quantumglow::restore(config, local, validators, damaged),
            Err(Error::BlockAuthentication)
        ));
    }

    #[test]
    fn verified_input_borrows_retained_witnesses_and_sizing_performs_no_shred_encoding() {
        use crate::network::take_shred_encoding_work;
        let (leader, _signer, config, validators) = borrow_fixture();
        let local = config.leaders[0];
        let candidate = borrow_candidate(&config, &leader, 1, config.finalized_anchor);
        let (marker, shreds, payload) = candidate
            .clone()
            .into_parts(&config.chain, &leader.public_key())
            .unwrap();
        let copied_dynamic_bytes = shreds
            .iter()
            .map(|shred| shred.payload.len() + std::mem::size_of_val(shred.proof.as_slice()))
            .sum::<usize>();
        let input = Input::Block(Box::new(marker), shreds, 1);
        take_shred_encoding_work();
        let old_size = legacy_input_bytes(&input).unwrap();
        let old_work = take_shred_encoding_work();
        assert_eq!(input_bytes(&input).unwrap(), old_size);
        assert_eq!(take_shred_encoding_work(), (0, 0));
        let Input::Block(_, shreds, _) = &input else {
            unreachable!()
        };
        assert_eq!(old_work.0, shreds.len());
        assert!(old_work.1 >= copied_dynamic_bytes);
        assert!(copied_dynamic_bytes >= 8192);
        let mut legacy = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let legacy_actions = legacy_accept(&mut legacy, input, Some(payload)).unwrap();
        let Input::Block(_, retained, _) = &legacy.journal.records[0] else {
            unreachable!()
        };
        let applied = legacy.applied_block_buffers.unwrap();
        assert_ne!(applied.0, retained.as_ptr() as usize);
        assert_ne!(applied.1, retained[0].payload.as_ptr() as usize);
        let mut live = Quantumglow::new(config, local, validators).unwrap();
        let original_buffers = (
            candidate.shreds().as_ptr() as usize,
            candidate.shreds()[0].payload.as_ptr() as usize,
        );
        take_shred_encoding_work();
        assert_eq!(live.observe_verified(candidate, 1).unwrap(), legacy_actions);
        assert_eq!(take_shred_encoding_work(), (0, 0));
        assert_eq!(live.applied_block_buffers, Some(original_buffers));
        let Input::Block(_, retained, _) = &live.journal.records[0] else {
            unreachable!()
        };
        assert_eq!(
            original_buffers,
            (
                retained.as_ptr() as usize,
                retained[0].payload.as_ptr() as usize
            )
        );
        assert_eq!(
            live.recovery_journal().encode().unwrap(),
            legacy.recovery_journal().encode().unwrap()
        );
    }

    #[test]
    fn borrowed_input_preserves_error_before_apply_and_exact_journal_bounds() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (leader, _signer, mut config, validators) = borrow_fixture();
        let local = config.leaders[0];
        let calls = Arc::new(AtomicUsize::new(0));
        let callback = config.validate_execution.clone();
        let callback_calls = calls.clone();
        config.validate_execution = Arc::new(move |candidate| {
            callback_calls.fetch_add(1, Ordering::Relaxed);
            callback(candidate)
        });
        let candidate = borrow_candidate(&config, &leader, 1, config.finalized_anchor);
        for case in 0..8 {
            let (marker, shreds, _) = candidate
                .clone()
                .into_parts(&config.chain, &leader.public_key())
                .unwrap();
            let mut input = Input::Block(Box::new(marker), shreds, 1);
            let mut live = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
            let mut legacy = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
            let Input::Block(marker, shreds, _) = &mut input else {
                unreachable!()
            };
            let expected = match case {
                0 => {
                    shreds[0].payload.pop();
                    Error::BlockAuthentication
                }
                1 => {
                    shreds[0].proof.pop();
                    Error::BlockAuthentication
                }
                2 => {
                    shreds[0].metadata.shard_bytes = 0;
                    Error::BlockAuthentication
                }
                3 => {
                    shreds[0].payload[0] ^= 1;
                    Error::BlockAuthentication
                }
                4 => {
                    marker.leader_epoch += 1;
                    Error::BlockAuthentication
                }
                5 => {
                    live.last_now = 2;
                    legacy.last_now = 2;
                    Error::Clock
                }
                6 => {
                    live.journal.bytes = MAX_JOURNAL_BYTES;
                    legacy.journal.bytes = MAX_JOURNAL_BYTES;
                    Error::JournalBounds
                }
                _ => {
                    live.journal.base_records = MAX_JOURNAL_RECORDS as u32;
                    legacy.journal.base_records = MAX_JOURNAL_RECORDS as u32;
                    Error::JournalBounds
                }
            };
            assert_eq!(input_bytes(&input), legacy_input_bytes(&input));
            let before_calls = calls.load(Ordering::Relaxed);
            let before_clock = live.clock();
            let before_bytes = live.journal.bytes;
            let before_records = live.recovery_record_count();
            assert_eq!(live.accept(input.clone()), Err(expected.clone()));
            assert_eq!(legacy_accept(&mut legacy, input, None), Err(expected));
            assert_eq!(calls.load(Ordering::Relaxed), before_calls);
            assert_eq!(live.clock(), before_clock);
            assert_eq!(live.journal.bytes, before_bytes);
            assert_eq!(live.recovery_record_count(), before_records);
            assert!(live.journal.records.is_empty());
            assert!(live.blocks.is_empty());
            assert_eq!(live.authorized, legacy.authorized);
            assert_eq!(live.repairs, legacy.repairs);
            assert_eq!(live.finalized_chain(), legacy.finalized_chain());
        }
        // The exact last permitted byte/record still accepts the same genuine
        // candidate; only exceeding the unchanged limits is an early failure.
        for byte_limit in [true, false] {
            let (marker, shreds, payload) = candidate
                .clone()
                .into_parts(&config.chain, &leader.public_key())
                .unwrap();
            let input = Input::Block(Box::new(marker), shreds, 1);
            let mut live = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
            let mut legacy = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
            if byte_limit {
                live.journal.bytes = MAX_JOURNAL_BYTES - legacy_input_bytes(&input).unwrap();
                legacy.journal.bytes = live.journal.bytes;
            } else {
                live.journal.base_records = MAX_JOURNAL_RECORDS as u32 - 1;
                legacy.journal.base_records = live.journal.base_records;
            }
            assert_eq!(
                live.accept_verified(input.clone(), Some(payload.clone()))
                    .unwrap(),
                legacy_accept(&mut legacy, input, Some(payload)).unwrap()
            );
            assert_eq!(live.journal.bytes, legacy.journal.bytes);
            assert_eq!(live.recovery_record_count(), legacy.recovery_record_count());
            assert_eq!(live.blocks.len(), 1);
        }
    }

    fn assert_finalized_index(machine: &Quantumglow) {
        assert_eq!(
            machine.finalized_hashes,
            machine
                .finalized
                .iter()
                .map(|block| block.hash)
                .collect::<BTreeSet<_>>()
        );
    }

    fn apply_finalized_index_pair(
        indexed: &mut Quantumglow,
        linear: &mut Quantumglow,
        input: Input,
        expected: &mut Vec<Vec<Action>>,
    ) {
        let actions = indexed.accept(input.clone()).unwrap();
        assert_eq!(actions, linear.accept(input).unwrap());
        expected.push(actions);
        assert_eq!(indexed.finalized_chain(), linear.finalized_chain());
        assert_eq!(indexed.authorized, linear.authorized);
        assert_eq!(indexed.repairs, linear.repairs);
        assert_finalized_index(indexed);
        assert_finalized_index(linear);
    }

    fn restore_finalized_linear(
        config: Config,
        local: [u8; 32],
        validators: Vec<Validator>,
        journal: RecoveryJournal,
    ) -> Result<Quantumglow, Error> {
        let mut restored = Quantumglow::new(config, local, validators)?;
        restored.linear_finalized_lookup = true;
        if restored.journal.binding != journal.binding {
            return Err(Error::Journal);
        }
        for input in &journal.records {
            restored.apply(input, None)?;
        }
        restored.journal = journal;
        Ok(restored)
    }

    #[test]
    fn finalized_full48_index_preserves_long_backlog_actions_repair_compaction_and_replay() {
        use std::sync::atomic::Ordering;
        const HISTORY: u64 = 64;
        const BACKLOG: u64 = 32;
        const TICKS: u64 = 8;
        const COLLISION_SLOT: u64 = HISTORY + BACKLOG + 1;
        let (leader, signer, config, validators) =
            repair_backlog_fixture((HISTORY + BACKLOG + 4) as u32, 4);
        let local = config.leaders[0];
        let mut indexed = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut linear = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        linear.linear_finalized_lookup = true;
        let mut parent = config.finalized_anchor;
        let mut bodies = Vec::new();
        let mut votes = Vec::new();
        for slot in 1..=HISTORY + BACKLOG {
            let payload = parent.slot.to_le_bytes();
            let batch = SignedBatch::build(
                &config.chain,
                &leader,
                BatchContext {
                    leader_epoch: config.epoch,
                    slot,
                    candidate: repair_backlog_state(slot),
                    parent: parent.hash,
                    batch_index: 0,
                    previous: [0; 48],
                },
                &payload,
                1,
                1,
            )
            .unwrap();
            let marker = FinalMarker::build(
                &config.chain,
                &leader,
                std::slice::from_ref(&batch),
                &payload,
            )
            .unwrap();
            parent = BlockRef {
                slot,
                hash: marker.block_commitment,
            };
            votes.push(
                signer
                    .sign(
                        &config.chain,
                        local,
                        ConsensusMessage {
                            epoch: config.epoch,
                            slot,
                            kind: MessageKind::NotarVote,
                            block: Some(parent.hash),
                        },
                    )
                    .unwrap(),
            );
            bodies.push((marker, batch.shreds));
        }
        let mut expected = Vec::new();
        let mut boundaries = Vec::new();
        for (index, (vote, (marker, shreds))) in
            votes.iter().zip(&bodies).take(HISTORY as usize).enumerate()
        {
            apply_finalized_index_pair(
                &mut indexed,
                &mut linear,
                Input::Evidence(vote.clone(), 0),
                &mut expected,
            );
            apply_finalized_index_pair(
                &mut indexed,
                &mut linear,
                Input::Block(Box::new(marker.clone()), shreds.clone(), 0),
                &mut expected,
            );
            assert_eq!(
                indexed.finalized_chain().last().unwrap().slot,
                index as u64 + 1
            );
        }
        let actual = *indexed.finalized_chain().last().unwrap();
        let anchor = indexed
            .compact_finalized(actual, repair_backlog_state(actual.slot))
            .unwrap();
        assert_eq!(
            linear
                .compact_finalized(actual, repair_backlog_state(actual.slot))
                .unwrap(),
            anchor
        );
        boundaries.push((expected.len(), actual, anchor));
        assert!(anchor.slot > 0);
        // Compaction deliberately retains the original full finalized Vec;
        // its membership mirror must have that exact same lifetime.
        assert_eq!(indexed.finalized.len(), HISTORY as usize + 1);
        assert_finalized_index(&indexed);
        for vote in &votes[HISTORY as usize..] {
            apply_finalized_index_pair(
                &mut indexed,
                &mut linear,
                Input::Evidence(vote.clone(), 0),
                &mut expected,
            );
        }
        let finalized_hash = indexed.finalized_chain().last().unwrap().hash;
        let mut collision = finalized_hash;
        collision[47] ^= 1;
        assert_eq!(&collision[..32], &finalized_hash[..32]);
        assert_ne!(&collision[32..], &finalized_hash[32..]);
        assert!(indexed.contains_finalized(&finalized_hash));
        assert!(!indexed.contains_finalized(&collision));
        let collision_vote = signer
            .sign(
                &config.chain,
                local,
                ConsensusMessage {
                    epoch: config.epoch,
                    slot: COLLISION_SLOT,
                    kind: MessageKind::NotarVote,
                    block: Some(collision),
                },
            )
            .unwrap();
        apply_finalized_index_pair(
            &mut indexed,
            &mut linear,
            Input::Evidence(collision_vote, 0),
            &mut expected,
        );
        assert!(expected.last().unwrap().contains(&Action::Repair {
            slot: Some(COLLISION_SLOT),
            block: collision,
        }));
        assert_eq!(indexed.pool.finalized(COLLISION_SLOT), Some(collision));
        for slot in HISTORY + 1..=HISTORY + BACKLOG {
            assert!(indexed.pool.finalized(slot).is_some());
        }
        let certified: Vec<_> = indexed
            .pool
            .active_slots()
            .filter_map(|slot| indexed.pool.finalized(slot))
            .collect();
        let comparisons_per_tick: usize = certified
            .iter()
            .map(|hash| {
                indexed
                    .finalized
                    .iter()
                    .rev()
                    .position(|block| block.hash == *hash)
                    .map_or(indexed.finalized.len(), |position| position + 1)
            })
            .sum();
        assert!(comparisons_per_tick >= (BACKLOG as usize + 1) * (HISTORY as usize + 1));
        indexed
            .finalized_linear_comparisons
            .store(0, Ordering::Relaxed);
        linear
            .finalized_linear_comparisons
            .store(0, Ordering::Relaxed);
        indexed.finalized_index_queries.store(0, Ordering::Relaxed);
        linear.finalized_index_queries.store(0, Ordering::Relaxed);
        indexed.known_slot_scan_work.store(0, Ordering::Relaxed);
        for now in 1..=TICKS {
            apply_finalized_index_pair(&mut indexed, &mut linear, Input::Tick(now), &mut expected);
        }
        assert_eq!(
            linear.finalized_linear_comparisons.load(Ordering::Relaxed),
            comparisons_per_tick * TICKS as usize
        );
        assert_eq!(
            indexed.finalized_linear_comparisons.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            indexed.finalized_index_queries.load(Ordering::Relaxed),
            certified.len() * TICKS as usize
        );
        assert_eq!(linear.finalized_index_queries.load(Ordering::Relaxed), 0);
        // The earlier lazy repair fix already suppresses these scans: the new
        // counter measures a separate retained-history membership cost.
        assert_eq!(indexed.known_slot_scan_work.load(Ordering::Relaxed), 0);
        assert_eq!(indexed.finalized_chain().last().unwrap().slot, HISTORY);
        for (marker, shreds) in &bodies[HISTORY as usize..] {
            apply_finalized_index_pair(
                &mut indexed,
                &mut linear,
                Input::Block(Box::new(marker.clone()), shreds.clone(), TICKS + 1),
                &mut expected,
            );
            assert_eq!(indexed.finalized_chain().last().unwrap().slot, marker.slot);
        }
        let actual = *indexed.finalized_chain().last().unwrap();
        let anchor = indexed
            .compact_finalized(actual, repair_backlog_state(actual.slot))
            .unwrap();
        assert_eq!(
            linear
                .compact_finalized(actual, repair_backlog_state(actual.slot))
                .unwrap(),
            anchor
        );
        boundaries.push((expected.len(), actual, anchor));
        apply_finalized_index_pair(
            &mut indexed,
            &mut linear,
            Input::Tick(TICKS + 2),
            &mut expected,
        );
        assert!(expected.last().unwrap().contains(&Action::Repair {
            slot: Some(COLLISION_SLOT),
            block: collision,
        }));
        assert_finalized_index(&indexed);
        let wire = indexed.recovery_journal().encode().unwrap();
        assert_eq!(wire, linear.recovery_journal().encode().unwrap());
        let body = indexed.recovery_update_since(0).unwrap().body;
        let mut replay = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut offset = 0;
        for (index, actions) in expected.iter().enumerate() {
            for (_, actual, anchor) in boundaries.iter().filter(|(record, _, _)| *record == index) {
                assert_eq!(
                    replay
                        .compact_finalized(*actual, repair_backlog_state(actual.slot))
                        .unwrap(),
                    *anchor
                );
            }
            let (consumed, replayed, _) = replay.replay_record(&body[offset..]).unwrap();
            assert_eq!(&replayed, actions);
            offset += consumed;
            assert_finalized_index(&replay);
        }
        assert_eq!(offset, body.len());
        assert_eq!(replay.finalized_chain(), indexed.finalized_chain());
        assert_eq!(replay.active_anchor, indexed.active_anchor);
        assert_eq!(replay.repairs, indexed.repairs);
        assert_eq!(replay.recovery_journal().encode().unwrap(), wire);
        let journal = RecoveryJournal::decode(&wire).unwrap();
        let restored =
            Quantumglow::restore(config.clone(), local, validators.clone(), journal.clone())
                .unwrap();
        assert_eq!(restored.finalized_chain(), indexed.finalized_chain());
        assert_finalized_index(&restored);
        assert_eq!(restored.recovery_journal().encode().unwrap(), wire);
        let linear_restored =
            restore_finalized_linear(config.clone(), local, validators.clone(), journal.clone())
                .unwrap();
        assert_eq!(
            restored.finalized_chain(),
            linear_restored.finalized_chain()
        );
        assert_eq!(restored.authorized, linear_restored.authorized);
        assert_eq!(restored.repairs, linear_restored.repairs);
        assert_finalized_index(&linear_restored);
        assert_eq!(linear_restored.recovery_journal().encode().unwrap(), wire);
        let mut corrupted = journal;
        let Input::Block(_, shreds, _) = &mut corrupted.records[1] else {
            unreachable!()
        };
        shreds[0].payload[0] ^= 1;
        assert!(matches!(
            Quantumglow::restore(config.clone(), local, validators.clone(), corrupted.clone()),
            Err(Error::BlockAuthentication)
        ));
        assert!(matches!(
            restore_finalized_linear(config.clone(), local, validators.clone(), corrupted),
            Err(Error::BlockAuthentication)
        ));
        // A trusted checkpoint restart starts a different machine with exactly
        // the Vec it already used before this index, not an invented old history.
        let mut checkpoint = config;
        checkpoint.first_slot = actual.slot + 1;
        checkpoint.slot_count = 4;
        checkpoint.leaders = vec![local; 4];
        checkpoint.finalized_anchor = actual;
        checkpoint.finalized_state_root = repair_backlog_state(actual.slot);
        let checkpoint_machine =
            Quantumglow::new(checkpoint.clone(), local, validators.clone()).unwrap();
        assert_eq!(checkpoint_machine.finalized_chain(), &[actual]);
        assert_eq!(
            checkpoint_machine.finalized_hashes,
            BTreeSet::from([actual.hash])
        );
        let restarted = Quantumglow::restore(
            checkpoint,
            local,
            validators,
            checkpoint_machine.recovery_journal(),
        )
        .unwrap();
        assert_eq!(restarted.finalized_chain(), &[actual]);
        assert_finalized_index(&restarted);
        assert!(!restarted.contains_finalized(&collision));
    }

    #[test]
    fn authenticated_missing_body_backlog_suppresses_quadratic_slot_scans_without_action_changes() {
        use std::sync::atomic::Ordering;
        const SLOTS: u32 = 64;
        const TICKS: usize = 8;
        let (_leader, signer, config, validators) = repair_backlog_fixture(SLOTS, 4);
        let local = config.leaders[0];
        let mut live = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut eager = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        eager.eager_repair_slot_lookup = true;
        let mut expected_actions = Vec::new();
        for slot in 1..=u64::from(SLOTS) {
            let block = hash_commitment(b"withheld-authenticated-block", &[&slot.to_le_bytes()]);
            // A real Ax consensus witness forms a real quorum certificate. No
            // block body or execution capability is invented for this backlog.
            let evidence = signer
                .sign(
                    &config.chain,
                    local,
                    ConsensusMessage {
                        epoch: 1,
                        slot,
                        kind: MessageKind::NotarVote,
                        block: Some(block),
                    },
                )
                .unwrap();
            let actions = live.receive(evidence.clone(), 0).unwrap();
            assert_eq!(actions, eager.receive(evidence, 0).unwrap());
            assert!(actions.contains(&Action::Repair {
                slot: Some(slot),
                block,
            }));
            assert_eq!(live.pool.finalized(slot), Some(block));
            expected_actions.push(actions);
        }
        assert_eq!(live.repairs.len(), SLOTS as usize);
        assert!(live.blocks.is_empty());
        assert_eq!(live.finalized_chain(), &[config.finalized_anchor]);
        live.known_slot_scan_work.store(0, Ordering::Relaxed);
        eager.known_slot_scan_work.store(0, Ordering::Relaxed);
        for tick in 1..=TICKS {
            let actions = live.tick(tick as u64).unwrap();
            assert_eq!(actions, eager.tick(tick as u64).unwrap());
            assert!(actions.is_empty());
            expected_actions.push(actions);
        }
        let old_work_per_tick = (1..=SLOTS as usize).sum::<usize>();
        assert_eq!(
            eager.known_slot_scan_work.load(Ordering::Relaxed),
            old_work_per_tick.checked_mul(TICKS).unwrap()
        );
        assert_eq!(live.known_slot_scan_work.load(Ordering::Relaxed), 0);
        assert_eq!(live.repairs, eager.repairs);
        assert_eq!(live.authorized, eager.authorized);
        let journal = live.recovery_journal().encode().unwrap();
        assert_eq!(journal, eager.recovery_journal().encode().unwrap());
        let body = live.recovery_update_since(0).unwrap().body;
        let mut restored = Quantumglow::new(config, local, validators).unwrap();
        let mut offset = 0usize;
        for actions in expected_actions {
            let (consumed, replayed, _) = restored.replay_record(&body[offset..]).unwrap();
            assert_eq!(replayed, actions);
            offset = offset.checked_add(consumed).unwrap();
        }
        assert_eq!(offset, body.len());
        assert_eq!(restored.recovery_journal().encode().unwrap(), journal);
        assert_eq!(restored.repairs, live.repairs);
        assert_eq!(restored.finalized_chain(), live.finalized_chain());
    }

    #[test]
    fn repair_hint_is_recomputed_after_real_body_observation_and_compaction() {
        use std::sync::atomic::Ordering;
        let (leader, signer, config, validators) = repair_backlog_fixture(8, 1);
        let local = config.leaders[0];
        let mut machine = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut blocks = Vec::new();
        let mut parent = config.finalized_anchor;
        for slot in 1..=6 {
            let payload = parent.slot.to_le_bytes();
            let batch = SignedBatch::build(
                &config.chain,
                &leader,
                BatchContext {
                    leader_epoch: 1,
                    slot,
                    candidate: repair_backlog_state(slot),
                    parent: parent.hash,
                    batch_index: 0,
                    previous: [0; 48],
                },
                &payload,
                1,
                1,
            )
            .unwrap();
            let marker = FinalMarker::build(
                &config.chain,
                &leader,
                std::slice::from_ref(&batch),
                &payload,
            )
            .unwrap();
            parent = BlockRef {
                slot,
                hash: marker.block_commitment,
            };
            blocks.push((marker, batch.shreds));
        }
        let missing = [0xb5; 48];
        let vote = |slot, block| {
            signer
                .sign(
                    &config.chain,
                    local,
                    ConsensusMessage {
                        epoch: 1,
                        slot,
                        kind: MessageKind::NotarVote,
                        block: Some(block),
                    },
                )
                .unwrap()
        };
        let mut expected_actions = vec![machine.receive(vote(8, missing), 0).unwrap()];
        assert!(expected_actions[0].contains(&Action::Repair {
            slot: Some(8),
            block: missing,
        }));
        for (marker, shreds) in blocks {
            let hash = marker.block_commitment;
            let slot = marker.slot;
            expected_actions.push(machine.receive(vote(slot, hash), 0).unwrap());
            assert!(machine.repairs.contains(&hash));
            expected_actions.push(machine.observe_block(marker, shreds, 0).unwrap());
            assert!(!machine.repairs.contains(&hash));
            assert_eq!(machine.finalized_chain().last().unwrap().slot, slot);
        }
        assert!(machine.repairs.contains(&missing));
        let before_compaction_records = expected_actions.len();
        let actual = *machine.finalized_chain().last().unwrap();
        let mut eager = Quantumglow::restore(
            config.clone(),
            local,
            validators.clone(),
            machine.recovery_journal(),
        )
        .unwrap();
        eager.eager_repair_slot_lookup = true;
        let anchor = machine
            .compact_finalized(actual, repair_backlog_state(actual.slot))
            .unwrap();
        assert_eq!(
            eager
                .compact_finalized(actual, repair_backlog_state(actual.slot))
                .unwrap(),
            anchor
        );
        assert!(anchor.slot > 0);
        assert!(!machine.repairs.contains(&missing));
        machine.known_slot_scan_work.store(0, Ordering::Relaxed);
        let actions = machine.tick(1).unwrap();
        assert_eq!(actions, eager.tick(1).unwrap());
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, Action::Repair { .. }))
                .cloned()
                .collect::<Vec<_>>(),
            vec![Action::Repair {
                slot: Some(8),
                block: missing,
            }]
        );
        assert!(machine.known_slot_scan_work.load(Ordering::Relaxed) > 0);
        expected_actions.push(actions);
        machine.known_slot_scan_work.store(0, Ordering::Relaxed);
        let actions = machine.tick(2).unwrap();
        assert_eq!(actions, eager.tick(2).unwrap());
        assert!(actions.is_empty());
        assert_eq!(machine.known_slot_scan_work.load(Ordering::Relaxed), 0);
        expected_actions.push(actions);
        assert_eq!(
            machine.recovery_journal().encode().unwrap(),
            eager.recovery_journal().encode().unwrap()
        );
        // Compaction is an actual-runtime boundary, not an input record. Apply
        // that same boundary while replaying and retain every action in order.
        let body = machine.recovery_update_since(0).unwrap().body;
        let mut restored = Quantumglow::new(config, local, validators).unwrap();
        let mut offset = 0usize;
        for (index, actions) in expected_actions.into_iter().enumerate() {
            if index == before_compaction_records {
                assert_eq!(
                    restored
                        .compact_finalized(actual, repair_backlog_state(actual.slot))
                        .unwrap(),
                    anchor
                );
            }
            let (consumed, replayed, _) = restored.replay_record(&body[offset..]).unwrap();
            assert_eq!(replayed, actions);
            offset = offset.checked_add(consumed).unwrap();
        }
        assert_eq!(offset, body.len());
        assert_eq!(
            restored.recovery_journal().encode().unwrap(),
            machine.recovery_journal().encode().unwrap()
        );
        assert_eq!(restored.active_anchor, machine.active_anchor);
        assert_eq!(restored.repairs, machine.repairs);
        assert_eq!(restored.finalized_chain(), machine.finalized_chain());
    }

    #[test]
    fn staged_journal_capacity_is_distinct_and_rejected_input_does_not_mutate_machine() {
        use {
            crate::consensus::ConsensusKeypair,
            std::sync::atomic::{AtomicUsize, Ordering},
        };
        let chain = [0xd1; 32];
        let local = [0xd2; 32];
        let leader = FalconKeypair::generate();
        let signer = ConsensusKeypair::generate_for(chain, local, 1, 1, 4).unwrap();
        let validators = vec![Validator {
            id: local,
            stake: 1,
            key: signer.public_key(),
        }];
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = calls.clone();
        let config = Config {
            chain,
            epoch: 1,
            first_slot: 1,
            slot_count: 4,
            window_size: 4,
            network_delay_ms: 100,
            block_time_ms: 100,
            leaders: vec![local; 4],
            leader_keys: BTreeMap::from([(local, leader.public_key())]),
            finalized_anchor: BlockRef {
                slot: 0,
                hash: [0xd3; 48],
            },
            finalized_state_root: [0xd4; 48],
            execution_rules: [0xd5; 48],
            validate_execution: Arc::new(move |_| {
                callback_calls.fetch_add(1, Ordering::Relaxed);
                Some(ExecutionState {
                    parent_state_root: [0xd4; 48],
                    state_root: [0xd6; 48],
                })
            }),
        };
        let batch = SignedBatch::build(
            &chain,
            &leader,
            BatchContext {
                leader_epoch: 1,
                slot: 1,
                candidate: [0xd7; 48],
                parent: config.finalized_anchor.hash,
                batch_index: 0,
                previous: [0; 48],
            },
            b"fixed authentic input",
            1,
            1,
        )
        .unwrap();
        let candidate = FinalMarker::build_verified(
            &chain,
            &leader,
            std::slice::from_ref(&batch),
            b"fixed authentic input",
        )
        .unwrap();
        for byte_limit in [true, false] {
            let mut machine = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
            if byte_limit {
                machine.journal.bytes = MAX_JOURNAL_BYTES;
            } else {
                machine.journal.base_records = MAX_JOURNAL_RECORDS as u32;
            }
            let before = machine.recovery_record_count();
            let before_bytes = machine.journal.bytes;
            let before_calls = calls.load(Ordering::Relaxed);
            assert_eq!(
                machine.observe_verified(candidate.clone(), 100),
                Err(Error::JournalBounds)
            );
            assert_eq!(machine.recovery_record_count(), before);
            assert_eq!(machine.journal.bytes, before_bytes);
            assert!(machine.journal.records.is_empty());
            assert!(machine.blocks.is_empty());
            assert_eq!(machine.clock(), 0);
            assert_eq!(calls.load(Ordering::Relaxed), before_calls);
            // No authority or input was consumed by the capacity failure.
            // Releasing durable staging permits the exact same input normally.
            machine.journal.bytes = 0;
            machine.journal.base_records = 0;
            machine.observe_verified(candidate.clone(), 100).unwrap();
            assert_eq!(
                machine.payload(&candidate.marker().block_commitment),
                Some(b"fixed authentic input".as_slice())
            );
            assert_eq!(calls.load(Ordering::Relaxed), before_calls + 1);
        }
    }

    #[test]
    fn long_epoch_compaction_stream_replay_and_delayed_evidence() {
        use crate::consensus::{ConsensusKeypair, ConsensusMessage, MessageKind};
        const SLOTS: u64 = 256;
        let chain = [0x91; 32];
        let local = [1; 32];
        let leader = FalconKeypair::generate();
        let signer = ConsensusKeypair::generate_for(chain, local, 1, 1, SLOTS as u32).unwrap();
        let validators = vec![Validator {
            id: local,
            stake: 1,
            key: signer.public_key(),
        }];
        let state = |slot: u64| hash_commitment(b"long-epoch-test-state", &[&slot.to_le_bytes()]);
        let config = Config {
            chain,
            epoch: 1,
            first_slot: 1,
            slot_count: SLOTS,
            window_size: 4,
            network_delay_ms: 100,
            block_time_ms: 1000,
            leaders: vec![local; SLOTS as usize],
            leader_keys: BTreeMap::from([(local, leader.public_key())]),
            finalized_anchor: BlockRef {
                slot: 0,
                hash: [0x92; 48],
            },
            finalized_state_root: state(0),
            execution_rules: [0x93; 48],
            validate_execution: Arc::new(move |candidate| {
                let parent_slot = u64::from_le_bytes(candidate.payload.get(..8)?.try_into().ok()?);
                Some(ExecutionState {
                    parent_state_root: state(parent_slot),
                    state_root: state(candidate.reference.slot),
                })
            }),
        };
        let mut live = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut durable = Vec::new();
        let mut cursor = 0;
        let mut first_evidence = None;
        let mut first_block = None;
        for slot in 1..=SLOTS {
            let parent = *live.finalized_chain().last().unwrap();
            if (201..=204).contains(&slot) {
                let evidence = signer
                    .sign(
                        &chain,
                        local,
                        ConsensusMessage {
                            epoch: 1,
                            slot,
                            kind: MessageKind::SkipVote,
                            block: None,
                        },
                    )
                    .unwrap();
                live.receive(evidence, slot).unwrap();
            } else {
                let payload = parent.slot.to_le_bytes().to_vec();
                let batch = SignedBatch::build(
                    &chain,
                    &leader,
                    BatchContext {
                        leader_epoch: 1,
                        slot,
                        candidate: state(slot),
                        parent: parent.hash,
                        batch_index: 0,
                        previous: [0; 48],
                    },
                    &payload,
                    1,
                    1,
                )
                .unwrap();
                let marker =
                    FinalMarker::build(&chain, &leader, std::slice::from_ref(&batch), &payload)
                        .unwrap();
                let hash = marker.block_commitment;
                live.observe_block(marker, batch.shreds, slot).unwrap();
                if slot == 1 {
                    first_block = Some(live.recovery_update_since(0).unwrap().body);
                }
                let evidence = signer
                    .sign(
                        &chain,
                        local,
                        ConsensusMessage {
                            epoch: 1,
                            slot,
                            kind: MessageKind::NotarVote,
                            block: Some(hash),
                        },
                    )
                    .unwrap();
                if slot == 1 {
                    first_evidence = Some(evidence.clone());
                }
                live.receive(evidence, slot).unwrap();
                assert_eq!(live.finalized_chain().last().unwrap().slot, slot);
            }
            let update = live.recovery_update_since(cursor).unwrap();
            durable.extend(update.body);
            cursor = live.recovery_record_count();
            assert!(live.discard_durable_records(cursor - 1).is_err());
            live.discard_durable_records(cursor).unwrap();
            let rooted = *live.finalized_chain().last().unwrap();
            assert!(live.compact_finalized(rooted, [0; 48]).is_err());
            live.compact_finalized(rooted, state(rooted.slot)).unwrap();
            assert!(live.pool.active_slots().count() <= 24);
            assert!(live.blocks.len() <= 24);
            assert!(live.journal.records.is_empty());
            assert!(live.recovery_update_since(0).is_err());
        }
        assert_eq!(live.finalized_chain().len(), SLOTS as usize - 4 + 1);
        assert!(live.active_anchor.slot > 128);
        let before = live.pool.active_slots().count();
        let mut forged = first_evidence.clone().unwrap();
        forged.signature[0] ^= 1;
        assert!(live.receive(forged, SLOTS).is_err());
        live.receive(first_evidence.unwrap(), SLOTS).unwrap();
        assert_eq!(live.pool.active_slots().count(), before);

        let mut restored = Quantumglow::new(config.clone(), local, validators.clone()).unwrap();
        let mut at = 0;
        while at < durable.len() {
            let (consumed, _, _) = restored.replay_record(&durable[at..]).unwrap();
            at += consumed;
            let rooted = *restored.finalized_chain().last().unwrap();
            restored
                .compact_finalized(rooted, state(rooted.slot))
                .unwrap();
            restored
                .discard_durable_records(restored.recovery_record_count())
                .unwrap();
            assert!(restored.blocks.len() <= 24);
        }
        assert_eq!(restored.recovery_record_count(), cursor);
        assert_eq!(restored.finalized_chain(), live.finalized_chain());
        assert_eq!(restored.active_anchor, live.active_anchor);
        let mut damaged = first_block.unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        let mut fresh = Quantumglow::new(config, local, validators).unwrap();
        assert!(fresh.replay_record(&damaged).is_err());
    }

    #[test]
    fn delta_encoding_preserves_the_complete_authenticated_record_wire() {
        let chain = [0x51; 32];
        let key = FalconKeypair::generate();
        let payload = vec![0x53; 8192];
        let batch = SignedBatch::build(
            &chain,
            &key,
            BatchContext {
                leader_epoch: 1,
                slot: 1,
                candidate: [0x54; 48],
                parent: [0x55; 48],
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            4,
            4,
        )
        .unwrap();
        let marker =
            FinalMarker::build(&chain, &key, std::slice::from_ref(&batch), &payload).unwrap();
        let mut journal = RecoveryJournal {
            binding: [0x56; 48],
            records: vec![Input::Block(Box::new(marker), batch.shreds, 100)],
            bytes: 0,
            base_records: 0,
        };
        let initial = journal.encode().unwrap();
        journal.records.push(Input::Tick(200));
        let update = journal.update_since(1).unwrap();
        assert_eq!(update.body.len(), 9);
        assert_eq!(update.previous_records, 1);
        let mut rebuilt = update.header.to_vec();
        rebuilt.extend_from_slice(&initial[53..]);
        rebuilt.extend_from_slice(&update.body);
        assert_eq!(rebuilt, journal.encode().unwrap());
        assert_eq!(
            RecoveryJournal::decode(&rebuilt).unwrap().encode().unwrap(),
            rebuilt
        );
        assert!(journal.update_since(3).is_err());
        assert!(journal.update_since(2).unwrap().body.is_empty());
        let mut corrupted_count = rebuilt;
        corrupted_count[49..53].copy_from_slice(&1u32.to_le_bytes());
        assert!(RecoveryJournal::decode(&corrupted_count).is_err());
    }

    #[test]
    fn live_capability_preserves_raw_recovery_authentication() {
        use crate::consensus::ConsensusKeypair;
        let chain = [0x81; 32];
        let leader = FalconKeypair::generate();
        let payload = vec![0x82; 8192];
        let batch = SignedBatch::build(
            &chain,
            &leader,
            BatchContext {
                leader_epoch: 1,
                slot: 1,
                candidate: [0x83; 48],
                parent: [0x84; 48],
                batch_index: 0,
                previous: [0; 48],
            },
            &payload,
            4,
            4,
        )
        .unwrap();
        let candidate = FinalMarker::build_verified(&chain, &leader, &[batch], &payload).unwrap();
        let validators = (1..=4)
            .map(|index| {
                let id = [index; 32];
                let signer = ConsensusKeypair::generate_for(chain, id, 1, 1, 4).unwrap();
                Validator {
                    id,
                    stake: 1,
                    key: signer.public_key(),
                }
            })
            .collect::<Vec<_>>();
        let config = Config {
            chain,
            epoch: 1,
            first_slot: 1,
            slot_count: 4,
            window_size: 4,
            network_delay_ms: 100,
            block_time_ms: 1000,
            leaders: vec![[1; 32]; 4],
            leader_keys: BTreeMap::from([([1; 32], leader.public_key())]),
            finalized_anchor: BlockRef {
                slot: 0,
                hash: [0x84; 48],
            },
            finalized_state_root: [0x85; 48],
            execution_rules: [0x86; 48],
            validate_execution: Arc::new(|candidate| {
                Some(ExecutionState {
                    parent_state_root: [0x85; 48],
                    state_root: hash_commitment(b"capability-test-state", &[candidate.payload]),
                })
            }),
        };
        let mut raw = Quantumglow::new(config.clone(), [1; 32], validators.clone()).unwrap();
        let mut live = Quantumglow::new(config.clone(), [1; 32], validators.clone()).unwrap();
        raw.observe_block(candidate.marker().clone(), candidate.shreds().to_vec(), 100)
            .unwrap();
        live.observe_verified(candidate, 100).unwrap();
        let journal = live.recovery_journal();
        assert_eq!(
            raw.recovery_journal().encode().unwrap(),
            journal.encode().unwrap()
        );
        let restored =
            Quantumglow::restore(config.clone(), [1; 32], validators.clone(), journal.clone())
                .unwrap();
        assert_eq!(restored.blocks.values().next().unwrap().payload, payload);
        let mut corrupted = journal;
        match &mut corrupted.records[0] {
            Input::Block(_, shreds, _) => shreds[0].payload[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(Quantumglow::restore(config, [1; 32], validators, corrupted).is_err());
    }
}
