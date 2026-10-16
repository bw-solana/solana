//! Durable Ax allocation with an independent monotonic authority.
//!
//! A counter in a snapshot cannot detect rollback. Every release requires the
//! `MonotonicStore` to atomically burn the key and fence obsolete signer instances.
//! The supplied memory store is a test backend; production must provide a durable,
//! independently administered HSM/service, outside signer backups and failover.
use {
    crate::{
        ax::{
            AX_KEYS_PER_SLOT, AxEpoch, AxError, AxKeypair, AxPublicMaterial, AxRole, AxRoot,
            AxSignature,
        },
        consensus::{ConsensusMessage, ConsensusPublicKey, SignedEvidence, sign_bytes},
        crypto::FalconKeypair,
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        fs::{self, File, OpenOptions},
        io::{BufWriter, Read, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex, MutexGuard},
    },
    zeroize::Zeroizing,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    Ax(AxError),
    Io(String),
    RollbackDetected,
    Fenced,
    AlreadyUsed,
    UnknownRoot,
    CorruptState,
    Store(String),
}
impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SignerError {}
impl From<AxError> for SignerError {
    fn from(value: AxError) -> Self {
        Self::Ax(value)
    }
}
impl From<std::io::Error> for SignerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[derive(Clone, Default)]
pub struct MonotonicRecord {
    pub sequence: u64,
    pub fence: u64,
    pub burned: BTreeSet<usize>,
}
/// Implementations must make each method atomic and durable before returning.
/// `register` must refuse to reset a previously registered root.
pub trait MonotonicStore: Send + Sync {
    fn register(&self, root: AxRoot) -> Result<(), SignerError>;
    fn inspect(&self, root: AxRoot) -> Result<MonotonicRecord, SignerError>;
    fn activate(
        &self,
        root: AxRoot,
        expected_sequence: u64,
    ) -> Result<MonotonicRecord, SignerError>;
    fn reserve(
        &self,
        root: AxRoot,
        fence: u64,
        expected_sequence: u64,
        ordinal: usize,
    ) -> Result<MonotonicRecord, SignerError>;
}
/// Independent object in tests, deliberately not serializable with signer state.
#[derive(Default)]
pub struct MemoryMonotonicStore(Mutex<BTreeMap<AxRoot, MonotonicRecord>>);
impl MonotonicStore for MemoryMonotonicStore {
    fn register(&self, root: AxRoot) -> Result<(), SignerError> {
        let mut roots = self
            .0
            .lock()
            .map_err(|_| SignerError::Store("poisoned".into()))?;
        if roots.contains_key(&root) {
            return Err(SignerError::Store("root already registered".into()));
        }
        roots.insert(root, MonotonicRecord::default());
        Ok(())
    }
    fn inspect(&self, root: AxRoot) -> Result<MonotonicRecord, SignerError> {
        self.0
            .lock()
            .map_err(|_| SignerError::Store("poisoned".into()))?
            .get(&root)
            .cloned()
            .ok_or(SignerError::UnknownRoot)
    }
    fn activate(
        &self,
        root: AxRoot,
        expected_sequence: u64,
    ) -> Result<MonotonicRecord, SignerError> {
        let mut roots = self
            .0
            .lock()
            .map_err(|_| SignerError::Store("poisoned".into()))?;
        let record = roots.get_mut(&root).ok_or(SignerError::UnknownRoot)?;
        if record.sequence != expected_sequence {
            return Err(SignerError::RollbackDetected);
        }
        record.fence = record
            .fence
            .checked_add(1)
            .ok_or(SignerError::CorruptState)?;
        Ok(record.clone())
    }
    fn reserve(
        &self,
        root: AxRoot,
        fence: u64,
        expected_sequence: u64,
        ordinal: usize,
    ) -> Result<MonotonicRecord, SignerError> {
        let mut roots = self
            .0
            .lock()
            .map_err(|_| SignerError::Store("poisoned".into()))?;
        let record = roots.get_mut(&root).ok_or(SignerError::UnknownRoot)?;
        if record.fence != fence {
            return Err(SignerError::Fenced);
        }
        if record.sequence != expected_sequence {
            return Err(SignerError::RollbackDetected);
        }
        if !record.burned.insert(ordinal) {
            return Err(SignerError::AlreadyUsed);
        }
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or(SignerError::CorruptState)?;
        Ok(record.clone())
    }
}

/// Fsync-backed prototype authority, stored separately from signer snapshots.
/// Its directory must be owned by the fencing service and excluded from signer
/// restore/failover. Restoring this authority's own backups can defeat protection;
/// a production HSM/quorum service must supply that independent trust boundary.
pub struct FileMonotonicStore {
    path: PathBuf,
    lock_path: PathBuf,
}
impl FileMonotonicStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SignerError> {
        let path = path.as_ref().to_path_buf();
        let lock_path = path.with_extension("monotonic-lock");
        let _lock = lock(&lock_path)?;
        if !path.exists() {
            write_records(&path, &BTreeMap::new())?;
        }
        read_records(&path)?;
        Ok(Self { path, lock_path })
    }
    fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut BTreeMap<AxRoot, MonotonicRecord>) -> Result<T, SignerError>,
    ) -> Result<T, SignerError> {
        let _lock = lock(&self.lock_path)?;
        let mut records = read_records(&self.path)?;
        let result = operation(&mut records)?;
        write_records(&self.path, &records)?;
        Ok(result)
    }
}
impl MonotonicStore for FileMonotonicStore {
    fn register(&self, root: AxRoot) -> Result<(), SignerError> {
        self.transaction(|records| {
            if records.contains_key(&root) {
                return Err(SignerError::Store("root already registered".into()));
            }
            records.insert(root, MonotonicRecord::default());
            Ok(())
        })
    }
    fn inspect(&self, root: AxRoot) -> Result<MonotonicRecord, SignerError> {
        let _lock = lock(&self.lock_path)?;
        read_records(&self.path)?
            .get(&root)
            .cloned()
            .ok_or(SignerError::UnknownRoot)
    }
    fn activate(
        &self,
        root: AxRoot,
        expected_sequence: u64,
    ) -> Result<MonotonicRecord, SignerError> {
        self.transaction(|records| {
            let record = records.get_mut(&root).ok_or(SignerError::UnknownRoot)?;
            if record.sequence != expected_sequence {
                return Err(SignerError::RollbackDetected);
            }
            record.fence = record
                .fence
                .checked_add(1)
                .ok_or(SignerError::CorruptState)?;
            Ok(record.clone())
        })
    }
    fn reserve(
        &self,
        root: AxRoot,
        fence: u64,
        expected_sequence: u64,
        ordinal: usize,
    ) -> Result<MonotonicRecord, SignerError> {
        self.transaction(|records| {
            let record = records.get_mut(&root).ok_or(SignerError::UnknownRoot)?;
            if record.fence != fence {
                return Err(SignerError::Fenced);
            }
            if record.sequence != expected_sequence {
                return Err(SignerError::RollbackDetected);
            }
            if !record.burned.insert(ordinal) {
                return Err(SignerError::AlreadyUsed);
            }
            record.sequence = record
                .sequence
                .checked_add(1)
                .ok_or(SignerError::CorruptState)?;
            Ok(record.clone())
        })
    }
}
fn write_records(
    path: &Path,
    records: &BTreeMap<AxRoot, MonotonicRecord>,
) -> Result<(), SignerError> {
    let temporary = path.with_extension("monotonic-writing");
    let file = secure_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    let mut file = BufWriter::with_capacity(64 * 1024, file);
    file.write_all(b"AXMONO01")?;
    file.write_all(&(records.len() as u32).to_le_bytes())?;
    for (root, record) in records {
        file.write_all(root)?;
        file.write_all(&record.sequence.to_le_bytes())?;
        file.write_all(&record.fence.to_le_bytes())?;
        file.write_all(&(record.burned.len() as u32).to_le_bytes())?;
        for ordinal in &record.burned {
            file.write_all(
                &u32::try_from(*ordinal)
                    .map_err(|_| SignerError::CorruptState)?
                    .to_le_bytes(),
            )?;
        }
    }
    file.flush()?;
    file.get_ref().sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn read_records(path: &Path) -> Result<BTreeMap<AxRoot, MonotonicRecord>, SignerError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > 64 * 1024 * 1024 {
        return Err(SignerError::CorruptState);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() < 12 || &bytes[..8] != b"AXMONO01" {
        return Err(SignerError::CorruptState);
    }
    let count = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| SignerError::CorruptState)?,
    ) as usize;
    let mut cursor = 12;
    let mut records = BTreeMap::new();
    for _ in 0..count {
        if bytes.len().saturating_sub(cursor) < 68 {
            return Err(SignerError::CorruptState);
        }
        let root = bytes[cursor..cursor + 48]
            .try_into()
            .map_err(|_| SignerError::CorruptState)?;
        cursor += 48;
        let sequence = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| SignerError::CorruptState)?,
        );
        cursor += 8;
        let fence = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| SignerError::CorruptState)?,
        );
        cursor += 8;
        let burned_count = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| SignerError::CorruptState)?,
        ) as usize;
        cursor += 4;
        if burned_count > 234_000
            || bytes.len().saturating_sub(cursor) / 4 < burned_count
            || sequence != burned_count as u64
        {
            return Err(SignerError::CorruptState);
        }
        let mut burned = BTreeSet::new();
        for _ in 0..burned_count {
            let ordinal = u32::from_le_bytes(
                bytes[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| SignerError::CorruptState)?,
            ) as usize;
            cursor += 4;
            if !burned.insert(ordinal) {
                return Err(SignerError::CorruptState);
            }
        }
        if records
            .insert(
                root,
                MonotonicRecord {
                    sequence,
                    fence,
                    burned,
                },
            )
            .is_some()
        {
            return Err(SignerError::CorruptState);
        }
    }
    if cursor != bytes.len() {
        return Err(SignerError::CorruptState);
    }
    Ok(records)
}

struct DiskState {
    epoch: AxEpoch,
    root: AxRoot,
    seed: Zeroizing<[u8; 32]>,
    sequence: u64,
    fence: u64,
    burned: Vec<u8>,
}
pub struct DurableAxSigner {
    path: PathBuf,
    lock_path: PathBuf,
    signer: AxKeypair,
    store: Arc<dyn MonotonicStore>,
    fence: u64,
}
impl DurableAxSigner {
    pub fn create(
        path: impl AsRef<Path>,
        epoch: AxEpoch,
        store: Arc<dyn MonotonicStore>,
    ) -> Result<Self, SignerError> {
        let path = path.as_ref().to_path_buf();
        let lock_path = path.with_extension("ax-lock");
        let _lock = lock(&lock_path)?;
        if path.exists() {
            return Err(SignerError::Io("state already exists".into()));
        }
        use rand::RngCore;
        let mut seed = Zeroizing::new([0; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        let signer = AxKeypair::from_seed(epoch.clone(), Zeroizing::new(*seed))?;
        let root = signer.material().root();
        store.register(root)?;
        let active = store.activate(root, 0)?;
        let state = DiskState {
            epoch: epoch.clone(),
            root,
            seed,
            sequence: 0,
            fence: active.fence,
            burned: vec![0; epoch.slots as usize * AX_KEYS_PER_SLOT],
        };
        persist(&path, &state)?;
        Ok(Self {
            path,
            lock_path,
            signer,
            store,
            fence: active.fence,
        })
    }
    /// Strict reopen refuses any mismatch with the independent high-water mark.
    /// Opening another instance fences all previously active instances.
    pub fn open(
        path: impl AsRef<Path>,
        store: Arc<dyn MonotonicStore>,
    ) -> Result<Self, SignerError> {
        Self::reopen(path.as_ref(), store, false)
    }
    /// Recovery only imports burned keys from the independent authority, never
    /// lowers a counter. This handles backups and a crash between external burn
    /// and local fsync; older instances become fenced.
    pub fn recover(
        path: impl AsRef<Path>,
        store: Arc<dyn MonotonicStore>,
    ) -> Result<Self, SignerError> {
        Self::reopen(path.as_ref(), store, true)
    }
    fn reopen(
        path: &Path,
        store: Arc<dyn MonotonicStore>,
        recover: bool,
    ) -> Result<Self, SignerError> {
        let path = path.to_path_buf();
        let lock_path = path.with_extension("ax-lock");
        let _lock = lock(&lock_path)?;
        let mut state = read_state(&path)?;
        let signer = AxKeypair::from_seed(state.epoch.clone(), Zeroizing::new(*state.seed))?;
        if signer.material().root() != state.root {
            return Err(SignerError::CorruptState);
        }
        let external = store.inspect(state.root)?;
        if state.sequence != external.sequence && !recover {
            return Err(SignerError::RollbackDetected);
        }
        if state.sequence > external.sequence {
            return Err(SignerError::RollbackDetected);
        }
        for &ordinal in &external.burned {
            let entry = state
                .burned
                .get_mut(ordinal)
                .ok_or(SignerError::CorruptState)?;
            *entry = 1;
        }
        // The local file cannot introduce externally unknown burned keys. Such
        // corruption is conservatively rejected rather than resetting history.
        if state
            .burned
            .iter()
            .enumerate()
            .any(|(i, &used)| used == 1 && !external.burned.contains(&i))
        {
            return Err(SignerError::CorruptState);
        }
        state.sequence = external.sequence;
        let active = store.activate(state.root, state.sequence)?;
        state.fence = active.fence;
        persist(&path, &state)?;
        Ok(Self {
            path,
            lock_path,
            signer,
            store,
            fence: active.fence,
        })
    }
    pub fn material(&self) -> Arc<AxPublicMaterial> {
        self.signer.material()
    }
    /// Key reservation is irrevocable even if signing or the caller subsequently
    /// fails. A retransmission must reuse a separately stored released signature.
    pub fn sign(
        &self,
        slot: u64,
        role: AxRole,
        index: u8,
        message: &[u8],
    ) -> Result<AxSignature, SignerError> {
        self.reserve(slot, role, index)?;
        self.signer
            .sign_reserved(slot, role, index, message)
            .map_err(Into::into)
    }
    fn reserve(&self, slot: u64, role: AxRole, index: u8) -> Result<(), SignerError> {
        let _lock = lock(&self.lock_path)?;
        let mut state = read_state(&self.path)?;
        if state.root != self.signer.material().root()
            || state.epoch != self.signer.material().epoch
        {
            return Err(SignerError::CorruptState);
        }
        if state.fence != self.fence {
            return Err(SignerError::Fenced);
        }
        let ordinal = self.signer.material().epoch.ordinal(slot, role, index)?;
        if state.burned[ordinal] != 0 {
            return Err(SignerError::AlreadyUsed);
        }
        let external = self
            .store
            .reserve(state.root, self.fence, state.sequence, ordinal)?;
        state.sequence = external.sequence;
        state.burned[ordinal] = 1;
        persist(&self.path, &state)?;
        Ok(())
    }
}

/// Durable consensus evidence, including a signature-release journal. The caller
/// must finalize `public_key()` in role configuration before broadcasting votes.
/// Journal replays return the original signature; crash-burned keys are skipped.
pub struct DurableConsensusSigner {
    signer: DurableAxSigner,
    public: ConsensusPublicKey,
    journal: PathBuf,
    journal_lock: PathBuf,
    verified_releases: Mutex<VerifiedReleases>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReleaseStamp {
    device: u64,
    inode: u64,
    length: u64,
    change: (i64, i64),
    modified: (i64, i64),
}

fn release_stamp(file: &File) -> Result<Option<ReleaseStamp>, SignerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Some(ReleaseStamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            change: (metadata.ctime(), metadata.ctime_nsec()),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        // Without reliable inode and change-time metadata, authenticate the
        // complete journal on every access instead of trusting a weak stamp.
        Ok(None)
    }
}

#[derive(Default)]
struct VerifiedReleases {
    stamp: Option<ReleaseStamp>,
    evidence: Vec<SignedEvidence>,
    by_message: BTreeMap<Vec<u8>, usize>,
    by_role: BTreeSet<(u64, u8)>,
    by_slot: BTreeMap<u64, Vec<usize>>,
    ordinals: BTreeSet<usize>,
    #[cfg(test)]
    authenticated_from_disk: usize,
}

impl VerifiedReleases {
    fn insert(
        &mut self,
        public: &ConsensusPublicKey,
        evidence: SignedEvidence,
    ) -> Result<(), SignerError> {
        let role = AxRole::from_byte(evidence.message.kind as u8)?;
        let ordinal = public
            .epoch()
            .ordinal(evidence.message.slot, role, evidence.signature[0])?;
        if !self.ordinals.insert(ordinal) {
            return Err(SignerError::CorruptState);
        }
        self.by_role
            .insert((evidence.message.slot, evidence.message.kind as u8));
        self.by_slot
            .entry(evidence.message.slot)
            .or_default()
            .push(self.evidence.len());
        let message = evidence
            .message
            .encode()
            .map_err(|_| SignerError::CorruptState)?;
        self.by_message
            .entry(message)
            .or_insert(self.evidence.len());
        self.evidence.push(evidence);
        Ok(())
    }

    fn find(&self, message: &ConsensusMessage) -> Result<Option<&SignedEvidence>, SignerError> {
        let bytes = message.encode().map_err(|_| SignerError::CorruptState)?;
        Ok(self
            .by_message
            .get(&bytes)
            .map(|index| &self.evidence[*index]))
    }
}

/// Read-only reconciliation of a caller's previously durable signing intent.
/// `Available` is advisory, not a reservation: `sign` still checks and burns the
/// key atomically. `CrashBurned` authorizes no signing or key reuse. The monotonic
/// authority records ordinals, not message hashes, so it establishes lost role
/// capacity, never which particular message was interrupted.
#[derive(Clone)]
pub enum IntentReconciliation {
    Released(Box<SignedEvidence>),
    Available { index: u8 },
    CrashBurned { ordinals: Vec<usize> },
    Conflict(ReplayConflict),
}
impl std::fmt::Debug for IntentReconciliation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Released(evidence) => f.debug_tuple("Released").field(&evidence.message).finish(),
            Self::Available { index } => f.debug_struct("Available").field("index", index).finish(),
            Self::CrashBurned { ordinals } => f
                .debug_struct("CrashBurned")
                .field("ordinals", ordinals)
                .finish(),
            Self::Conflict(conflict) => f.debug_tuple("Conflict").field(conflict).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayConflict {
    TerminalVote,
    AlternatePrimary,
    ReleasedDifferentMessage,
    FinalPrerequisite,
    RoleCapacity,
}

impl DurableConsensusSigner {
    pub fn create(
        path: impl AsRef<Path>,
        epoch: AxEpoch,
        authority: &FalconKeypair,
        store: Arc<dyn MonotonicStore>,
    ) -> Result<Self, SignerError> {
        let path = path.as_ref();
        let signer = DurableAxSigner::create(path, epoch, store)?;
        let public = ConsensusPublicKey::from_authorized_material(signer.material(), authority)
            .map_err(|_| SignerError::CorruptState)?;
        let journal = path.with_extension("consensus-releases");
        let journal_lock = path.with_extension("consensus-lock");
        let _lock = lock(&journal_lock)?;
        let mut file = secure_options()
            .write(true)
            .create_new(true)
            .open(&journal)?;
        file.write_all(b"AXRELS01")?;
        file.write_all(&public.commitment())?;
        file.sync_all()?;
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self {
            signer,
            public,
            journal,
            journal_lock,
            verified_releases: Mutex::default(),
        })
    }
    /// The expected public descriptor comes from finalized role configuration.
    pub fn open(
        path: impl AsRef<Path>,
        expected: ConsensusPublicKey,
        store: Arc<dyn MonotonicStore>,
    ) -> Result<Self, SignerError> {
        Self::reopen(path.as_ref(), expected, store, false)
    }
    pub fn recover(
        path: impl AsRef<Path>,
        expected: ConsensusPublicKey,
        store: Arc<dyn MonotonicStore>,
    ) -> Result<Self, SignerError> {
        Self::reopen(path.as_ref(), expected, store, true)
    }
    fn reopen(
        path: &Path,
        mut public: ConsensusPublicKey,
        store: Arc<dyn MonotonicStore>,
        recover: bool,
    ) -> Result<Self, SignerError> {
        let signer = if recover {
            DurableAxSigner::recover(path, store)?
        } else {
            DurableAxSigner::open(path, store)?
        };
        if public.epoch() != &signer.material().epoch
            || public.ax_root() != signer.material().root()
        {
            return Err(SignerError::CorruptState);
        }
        public
            .cache_material(signer.material())
            .map_err(|_| SignerError::CorruptState)?;
        let instance = Self {
            signer,
            public,
            journal: path.with_extension("consensus-releases"),
            journal_lock: path.with_extension("consensus-lock"),
            verified_releases: Mutex::default(),
        };
        let _lock = lock(&instance.journal_lock)?;
        drop(instance.released()?);
        Ok(instance)
    }
    pub fn public_key(&self) -> ConsensusPublicKey {
        self.public.clone()
    }

    /// Returns authenticated, durably released witnesses. Every release must
    /// correspond to a distinct key already burned by the independent authority.
    pub fn released_evidence(&self) -> Result<Vec<SignedEvidence>, SignerError> {
        let _lock = lock(&self.journal_lock)?;
        let released = self.released()?;
        let record = self.signer.store.inspect(self.public.ax_root())?;
        self.released_ordinals(&released, &record)?;
        Ok(released.evidence.clone())
    }

    /// Retry only still-active evidence without cloning the complete epoch.
    /// The independent authority is checked on every call, exactly as for the
    /// full recovery view; finalized evidence remains durably recoverable.
    pub fn released_evidence_after(&self, slot: u64) -> Result<Vec<SignedEvidence>, SignerError> {
        use std::ops::Bound::{Excluded, Unbounded};
        let _lock = lock(&self.journal_lock)?;
        let released = self.released()?;
        let record = self.signer.store.inspect(self.public.ax_root())?;
        self.released_ordinals(&released, &record)?;
        Ok(released
            .by_slot
            .range((Excluded(slot), Unbounded))
            .flat_map(|(_, indexes)| {
                indexes
                    .iter()
                    .map(|index| released.evidence[*index].clone())
            })
            .collect())
    }

    /// Repairs one historical slot without cloning every release in the epoch.
    /// The independent authority is re-read and its burned-key history checked
    /// on every call. A fenced instance may retransmit an authenticated release;
    /// it cannot advertise or reserve a fresh signing key.
    pub fn released_evidence_for_slot(
        &self,
        slot: u64,
    ) -> Result<Vec<SignedEvidence>, SignerError> {
        let _lock = lock(&self.journal_lock)?;
        let released = self.released()?;
        let record = self.signer.store.inspect(self.public.ax_root())?;
        self.released_ordinals(&released, &record)?;
        Ok(released
            .by_slot
            .get(&slot)
            .into_iter()
            .flat_map(|indexes| {
                indexes
                    .iter()
                    .map(|index| released.evidence[*index].clone())
            })
            .collect())
    }

    fn released_ordinals<'a>(
        &self,
        released: &'a VerifiedReleases,
        record: &MonotonicRecord,
    ) -> Result<&'a BTreeSet<usize>, SignerError> {
        // Every call still checks the current independent authority. Cached
        // signature mathematics never caches fencing or key-burn decisions.
        if !released.ordinals.is_subset(&record.burned) {
            return Err(SignerError::CorruptState);
        }
        Ok(&released.ordinals)
    }

    /// Reconciles a durable input intent without signing, allocating, or changing
    /// either journal. A burned, exhausted role with missing public witnesses can
    /// be withdrawn by the caller; it can never be signed again. This remains true
    /// if a later FinalVote fenced that historical role. Conflicting published
    /// messages and alternate primary choices remain errors. Only an identical
    /// published witness can be retransmitted after terminal fencing.
    pub fn reconcile_intent(
        &self,
        message: &ConsensusMessage,
    ) -> Result<IntentReconciliation, SignerError> {
        let _journal_lock = lock(&self.journal_lock)?;
        let epoch = self.public.epoch();
        if message.epoch != epoch.epoch {
            return Err(SignerError::Ax(AxError::Context));
        }
        message
            .encode()
            .map_err(|_| SignerError::Ax(AxError::Encoding))?;
        let role = AxRole::from_byte(message.kind as u8)?;
        epoch.ordinal(message.slot, role, 0)?;
        let released = self.released()?;
        let record = self.signer.store.inspect(self.public.ax_root())?;
        let released_ordinals = self.released_ordinals(&released, &record)?;
        if let Some(evidence) = released.find(message)? {
            return Ok(IntentReconciliation::Released(Box::new(evidence.clone())));
        }

        // A stale/fenced instance cannot advertise fresh signing capacity.
        let _signer_lock = lock(&self.signer.lock_path)?;
        let state = read_state(&self.signer.path)?;
        if state.root != self.public.ax_root() || state.epoch != *epoch {
            return Err(SignerError::CorruptState);
        }
        if state.fence != self.signer.fence || record.fence != self.signer.fence {
            return Err(SignerError::Fenced);
        }
        if state.sequence != record.sequence {
            return Err(SignerError::RollbackDetected);
        }
        if state.burned.iter().filter(|&&used| used == 1).count() != record.burned.len()
            || record
                .burned
                .iter()
                .any(|&ordinal| state.burned.get(ordinal) != Some(&1))
        {
            return Err(SignerError::CorruptState);
        }
        let burned = |other: AxRole| {
            (0..other.capacity()).any(|index| {
                epoch
                    .ordinal(message.slot, other, index)
                    .is_ok_and(|ordinal| record.burned.contains(&ordinal))
            })
        };
        let conflict = |reason| Ok(IntentReconciliation::Conflict(reason));
        if role.capacity() == 1
            && released
                .by_role
                .contains(&(message.slot, message.kind as u8))
        {
            return conflict(ReplayConflict::ReleasedDifferentMessage);
        }
        if matches!(role, AxRole::NotarVote | AxRole::SkipVote) {
            let other = if role == AxRole::NotarVote {
                AxRole::SkipVote
            } else {
                AxRole::NotarVote
            };
            if burned(other) {
                return conflict(ReplayConflict::AlternatePrimary);
            }
        }
        if role == AxRole::FinalVote
            && (!burned(AxRole::NotarVote)
                || burned(AxRole::SkipVote)
                || burned(AxRole::NotarFallbackVote)
                || burned(AxRole::SkipFallbackVote))
        {
            return conflict(ReplayConflict::FinalPrerequisite);
        }
        let available = (0..role.capacity()).find(|&index| {
            epoch
                .ordinal(message.slot, role, index)
                .is_ok_and(|ordinal| !record.burned.contains(&ordinal))
        });
        if available.is_none() {
            let ordinals = (0..role.capacity())
                .map(|index| epoch.ordinal(message.slot, role, index))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|ordinal| !released_ordinals.contains(ordinal))
                .collect::<Vec<_>>();
            if !ordinals.is_empty() {
                return Ok(IntentReconciliation::CrashBurned { ordinals });
            }
            return conflict(ReplayConflict::RoleCapacity);
        }
        if matches!(
            role,
            AxRole::NotarVote
                | AxRole::SkipVote
                | AxRole::NotarFallbackVote
                | AxRole::SkipFallbackVote
        ) && burned(AxRole::FinalVote)
        {
            return conflict(ReplayConflict::TerminalVote);
        }
        Ok(IntentReconciliation::Available {
            index: available.ok_or(SignerError::CorruptState)?,
        })
    }

    pub fn sign(&self, message: ConsensusMessage) -> Result<SignedEvidence, SignerError> {
        let _lock = lock(&self.journal_lock)?;
        let epoch = &self.signer.material().epoch;
        if message.epoch != epoch.epoch {
            return Err(SignerError::Ax(AxError::Context));
        }
        message
            .encode()
            .map_err(|_| SignerError::Ax(AxError::Encoding))?;
        let mut released = self.released()?;
        if let Some(evidence) = released.find(&message)? {
            return Ok(evidence.clone());
        }
        let role = AxRole::from_byte(message.kind as u8)?;
        let record = self.signer.store.inspect(self.public.ax_root())?;
        let burned = |role: AxRole| -> Result<bool, SignerError> {
            Ok((0..role.capacity()).any(|index| {
                epoch
                    .ordinal(message.slot, role, index)
                    .is_ok_and(|ordinal| record.burned.contains(&ordinal))
            }))
        };
        if matches!(
            role,
            AxRole::NotarVote
                | AxRole::SkipVote
                | AxRole::NotarFallbackVote
                | AxRole::SkipFallbackVote
        ) && burned(AxRole::FinalVote)?
        {
            return Err(SignerError::AlreadyUsed);
        }
        if role == AxRole::FinalVote
            && (!burned(AxRole::NotarVote)?
                || burned(AxRole::SkipVote)?
                || burned(AxRole::NotarFallbackVote)?
                || burned(AxRole::SkipFallbackVote)?)
        {
            return Err(SignerError::AlreadyUsed);
        }
        if matches!(role, AxRole::NotarVote | AxRole::SkipVote) {
            let other = if role == AxRole::NotarVote {
                AxRole::SkipVote
            } else {
                AxRole::NotarVote
            };
            if record
                .burned
                .contains(&epoch.ordinal(message.slot, other, 0)?)
            {
                return Err(SignerError::AlreadyUsed);
            }
        }
        let index = (0..role.capacity())
            .find(|&index| {
                epoch
                    .ordinal(message.slot, role, index)
                    .is_ok_and(|ordinal| !record.burned.contains(&ordinal))
            })
            .ok_or(SignerError::AlreadyUsed)?;
        let payload = if role.is_zero() {
            Vec::new()
        } else {
            sign_bytes(&epoch.chain, &epoch.validator, &message)
                .map_err(|_| SignerError::Ax(AxError::Encoding))?
        };
        let signature = self.signer.sign(message.slot, role, index, &payload)?;
        let evidence = SignedEvidence::from_ax_signature(
            epoch.validator,
            message,
            index,
            &self.signer.material(),
            &signature,
        )
        .map_err(|_| SignerError::CorruptState)?;
        let encoded = evidence.encode().map_err(|_| SignerError::CorruptState)?;
        let mut journal = secure_options().append(true).open(&self.journal)?;
        if released.stamp.is_some() && release_stamp(&journal)? != released.stamp {
            return Err(SignerError::CorruptState);
        }
        journal.write_all(&(encoded.len() as u32).to_le_bytes())?;
        journal.write_all(&encoded)?;
        journal.sync_all()?;
        evidence
            .verify(&self.public.epoch().chain, &self.public)
            .map_err(|_| SignerError::CorruptState)?;
        released.insert(&self.public, evidence.clone())?;
        released.stamp = release_stamp(&journal)?;
        Ok(evidence)
    }
    fn released(&self) -> Result<MutexGuard<'_, VerifiedReleases>, SignerError> {
        let mut file = File::open(&self.journal)?;
        let stamp = release_stamp(&file)?;
        let mut cached = self
            .verified_releases
            .lock()
            .map_err(|_| SignerError::CorruptState)?;
        if stamp.is_some() && cached.stamp == stamp {
            return Ok(cached);
        }
        if file.metadata()?.len() > 512 * 1024 * 1024 {
            return Err(SignerError::CorruptState);
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < 56
            || &bytes[..8] != b"AXRELS01"
            || bytes[8..56] != self.public.commitment()
        {
            return Err(SignerError::CorruptState);
        }
        let mut cursor = 56;
        let mut released = VerifiedReleases::default();
        while cursor < bytes.len() {
            if bytes.len() - cursor < 4 {
                return Err(SignerError::CorruptState);
            }
            let len = u32::from_le_bytes(
                bytes[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| SignerError::CorruptState)?,
            ) as usize;
            cursor += 4;
            let end = cursor
                .checked_add(len)
                .filter(|&end| end <= bytes.len())
                .ok_or(SignerError::CorruptState)?;
            let evidence = SignedEvidence::decode(&bytes[cursor..end])
                .map_err(|_| SignerError::CorruptState)?;
            evidence
                .verify(&self.public.epoch().chain, &self.public)
                .map_err(|_| SignerError::CorruptState)?;
            cursor = end;
            released.insert(&self.public, evidence)?;
            #[cfg(test)]
            {
                released.authenticated_from_disk += 1;
            }
        }
        if release_stamp(&file)? != stamp {
            return Err(SignerError::CorruptState);
        }
        released.stamp = stamp;
        *cached = released;
        Ok(cached)
    }
}
fn lock(path: &Path) -> Result<File, SignerError> {
    let file = secure_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock()?;
    Ok(file)
}
fn secure_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn persist(path: &Path, state: &DiskState) -> Result<(), SignerError> {
    let temporary = path.with_extension("ax-writing");
    let mut file = secure_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(b"AXSTATE1")?;
    file.write_all(&state.epoch.encode())?;
    file.write_all(&state.root)?;
    file.write_all(state.seed.as_ref())?;
    file.write_all(&state.sequence.to_le_bytes())?;
    file.write_all(&state.fence.to_le_bytes())?;
    file.write_all(&(state.burned.len() as u32).to_le_bytes())?;
    file.write_all(&state.burned)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn read_state(path: &Path) -> Result<DiskState, SignerError> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if !(200..=300_000).contains(&len) {
        return Err(SignerError::CorruptState);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(len as usize));
    file.read_to_end(&mut bytes)?;
    if bytes.len() < 200 || &bytes[..8] != b"AXSTATE1" {
        return Err(SignerError::CorruptState);
    }
    let epoch = AxEpoch::decode(&bytes[8..100])?;
    let root = bytes[100..148]
        .try_into()
        .map_err(|_| SignerError::CorruptState)?;
    let seed = Zeroizing::new(
        bytes[148..180]
            .try_into()
            .map_err(|_| SignerError::CorruptState)?,
    );
    let sequence = u64::from_le_bytes(
        bytes[180..188]
            .try_into()
            .map_err(|_| SignerError::CorruptState)?,
    );
    let fence = u64::from_le_bytes(
        bytes[188..196]
            .try_into()
            .map_err(|_| SignerError::CorruptState)?,
    );
    let count = u32::from_le_bytes(
        bytes[196..200]
            .try_into()
            .map_err(|_| SignerError::CorruptState)?,
    ) as usize;
    if count != epoch.slots as usize * AX_KEYS_PER_SLOT
        || bytes.len() != 200 + count
        || bytes[200..].iter().any(|&x| x > 1)
    {
        return Err(SignerError::CorruptState);
    }
    Ok(DiskState {
        epoch,
        root,
        seed,
        sequence,
        fence,
        burned: bytes[200..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn epoch() -> AxEpoch {
        AxEpoch {
            chain: [1; 32],
            validator: [2; 32],
            epoch: 3,
            generation: 4,
            first_slot: 0,
            slots: 1,
        }
    }

    // Retain the previous on-disk encoder as an independent compatibility
    // reference, including its atomic replacement and durability sequence.
    fn legacy_unbuffered_write_records(
        path: &Path,
        records: &BTreeMap<AxRoot, MonotonicRecord>,
    ) -> Result<(), SignerError> {
        let temporary = path.with_extension("monotonic-writing");
        let mut file = secure_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(b"AXMONO01")?;
        file.write_all(&(records.len() as u32).to_le_bytes())?;
        for (root, record) in records {
            file.write_all(root)?;
            file.write_all(&record.sequence.to_le_bytes())?;
            file.write_all(&record.fence.to_le_bytes())?;
            file.write_all(&(record.burned.len() as u32).to_le_bytes())?;
            for ordinal in &record.burned {
                file.write_all(
                    &u32::try_from(*ordinal)
                        .map_err(|_| SignerError::CorruptState)?
                        .to_le_bytes(),
                )?;
            }
        }
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    }

    #[test]
    fn buffered_monotonic_records_preserve_legacy_bytes_and_full_profile_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let old_path = directory.path().join("legacy-authority");
        let new_path = directory.path().join("buffered-authority");
        let epoch = AxEpoch {
            first_slot: 1,
            slots: 18_000,
            ..epoch()
        };
        let observed_history = (1..=4_818)
            .flat_map(|slot| {
                [AxRole::NotarVote, AxRole::NotarApproval, AxRole::FinalVote]
                    .map(|role| epoch.ordinal(slot, role, 0).unwrap())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(observed_history.len(), 14_454);
        let maximum = epoch.slots as usize * AX_KEYS_PER_SLOT;
        assert_eq!(maximum, 234_000);
        let root = [7; 48];
        let mut cases = vec![BTreeMap::new()];
        for burned in [
            BTreeSet::new(),
            BTreeSet::from([maximum - 1]),
            observed_history,
            (0..maximum).collect(),
        ] {
            cases.push(BTreeMap::from([(
                root,
                MonotonicRecord {
                    sequence: burned.len() as u64,
                    fence: 2,
                    burned,
                },
            )]));
        }
        cases.push(BTreeMap::from([
            (
                [9; 48],
                MonotonicRecord {
                    sequence: 3,
                    fence: 19,
                    burned: BTreeSet::from([0, 13, maximum - 1]),
                },
            ),
            (
                [2; 48],
                MonotonicRecord {
                    sequence: 2,
                    fence: 5,
                    burned: BTreeSet::from([77, 123]),
                },
            ),
        ]));
        for records in cases {
            legacy_unbuffered_write_records(&old_path, &records).unwrap();
            write_records(&new_path, &records).unwrap();
            let old = fs::read(&old_path).unwrap();
            let new = fs::read(&new_path).unwrap();
            assert_eq!(new, old);
            assert_eq!(
                new.len(),
                12 + records
                    .values()
                    .map(|record| 68 + 4 * record.burned.len())
                    .sum::<usize>()
            );
            let reopened = FileMonotonicStore::open(&new_path).unwrap();
            for (root, expected) in records {
                let actual = reopened.inspect(root).unwrap();
                assert_eq!(actual.sequence, expected.sequence);
                assert_eq!(actual.fence, expected.fence);
                assert_eq!(actual.burned, expected.burned);
            }
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn buffered_monotonic_encoder_failure_keeps_committed_authority() {
        let directory = tempfile::tempdir().unwrap();
        for buffered in [false, true] {
            let path = directory.path().join(if buffered { "new" } else { "old" });
            let root = [7; 48];
            let store = FileMonotonicStore::open(&path).unwrap();
            store.register(root).unwrap();
            let active = store.activate(root, 0).unwrap();
            store.reserve(root, active.fence, 0, 3).unwrap();
            let durable = fs::read(&path).unwrap();
            let invalid = BTreeMap::from([(
                root,
                MonotonicRecord {
                    sequence: 1,
                    fence: active.fence,
                    burned: BTreeSet::from([usize::MAX]),
                },
            )]);
            let result = if buffered {
                write_records(&path, &invalid)
            } else {
                legacy_unbuffered_write_records(&path, &invalid)
            };
            assert_eq!(result, Err(SignerError::CorruptState));
            assert_eq!(fs::read(&path).unwrap(), durable);
            let reopened = FileMonotonicStore::open(&path).unwrap();
            let record = reopened.inspect(root).unwrap();
            assert_eq!(record.sequence, 1);
            assert_eq!(record.fence, active.fence);
            assert_eq!(record.burned, BTreeSet::from([3]));
        }
    }

    #[test]
    fn verified_release_cache_preserves_tamper_rollback_and_restart_checks() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let signer = DurableConsensusSigner::create(
            &path,
            epoch(),
            &FalconKeypair::generate(),
            store.clone(),
        )
        .unwrap();
        let original_header = fs::read(&signer.journal).unwrap();
        let message = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::NotarVote,
            block: Some([9; 48]),
        };
        let evidence = signer.sign(message.clone()).unwrap();
        assert!(signer.released_evidence_after(0).unwrap().is_empty());
        assert_eq!(
            signer.released_evidence().unwrap()[0].encode().unwrap(),
            evidence.encode().unwrap()
        );
        for _ in 0..32 {
            assert_eq!(signer.released_evidence().unwrap().len(), 1);
            assert_eq!(
                signer.sign(message.clone()).unwrap().encode().unwrap(),
                evidence.encode().unwrap()
            );
        }
        #[cfg(unix)]
        assert_eq!(
            signer
                .verified_releases
                .lock()
                .unwrap()
                .authenticated_from_disk,
            0
        );
        let public = signer.public_key();
        drop(signer);
        let signer = DurableConsensusSigner::open(&path, public, store).unwrap();
        for _ in 0..32 {
            assert!(matches!(
                signer.reconcile_intent(&message).unwrap(),
                IntentReconciliation::Released(_)
            ));
        }
        #[cfg(unix)]
        assert_eq!(
            signer
                .verified_releases
                .lock()
                .unwrap()
                .authenticated_from_disk,
            1
        );
        let saved = fs::read(&signer.journal).unwrap();
        let mut tampered = saved.clone();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&signer.journal, tampered).unwrap();
        assert!(matches!(
            signer.released_evidence(),
            Err(SignerError::CorruptState)
        ));
        fs::write(&signer.journal, &saved).unwrap();
        assert_eq!(signer.released_evidence().unwrap().len(), 1);
        // Removing the released witness does not restore its independently
        // burned key, even while the same process has a warm cache.
        fs::write(&signer.journal, original_header).unwrap();
        assert!(signer.released_evidence().unwrap().is_empty());
        assert_eq!(signer.sign(message).err(), Some(SignerError::AlreadyUsed));
    }

    #[test]
    fn indexed_release_views_preserve_burn_validation_and_two_process_fencing() {
        use {crate::consensus::MessageKind, std::process::Command};

        const CHILD_DIRECTORY: &str = "AGAVE_PQ_AX_FENCE_CHILD_DIRECTORY";
        let message = |slot| ConsensusMessage {
            epoch: 3,
            slot,
            kind: MessageKind::NotarVote,
            block: Some([u8::try_from(slot).unwrap(); 48]),
        };
        if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
            let directory = PathBuf::from(directory);
            let public =
                ConsensusPublicKey::from_bytes(&fs::read(directory.join("public")).unwrap())
                    .unwrap();
            let store = Arc::new(FileMonotonicStore::open(directory.join("authority")).unwrap());
            let signer =
                DurableConsensusSigner::open(directory.join("signer"), public, store).unwrap();
            let evidence = signer.sign(message(1)).unwrap();
            fs::write(directory.join("child-release"), evidence.encode().unwrap()).unwrap();
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let authority_path = directory.path().join("authority");
        let store = Arc::new(FileMonotonicStore::open(&authority_path).unwrap());
        let signer = DurableConsensusSigner::create(
            &path,
            AxEpoch {
                slots: 4,
                ..epoch()
            },
            &FalconKeypair::generate(),
            store.clone(),
        )
        .unwrap();
        let later = signer.sign(message(2)).unwrap();
        let original = signer.sign(message(0)).unwrap();
        let encode = |items: Vec<SignedEvidence>| {
            items
                .into_iter()
                .map(|evidence| evidence.encode().unwrap())
                .collect::<Vec<_>>()
        };
        for _ in 0..16 {
            assert_eq!(
                encode(signer.released_evidence_for_slot(0).unwrap()),
                vec![original.encode().unwrap()]
            );
            assert_eq!(
                encode(signer.released_evidence_after(0).unwrap()),
                vec![later.encode().unwrap()]
            );
            assert!(signer.released_evidence_for_slot(1).unwrap().is_empty());
            assert!(signer.released_evidence_after(2).unwrap().is_empty());
        }
        #[cfg(unix)]
        assert_eq!(
            signer
                .verified_releases
                .lock()
                .unwrap()
                .authenticated_from_disk,
            0
        );
        let public = signer.public_key();
        fs::write(directory.path().join("public"), public.as_bytes()).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ax_state::tests::indexed_release_views_preserve_burn_validation_and_two_process_fencing",
                "--nocapture",
            ])
            .env(CHILD_DIRECTORY, directory.path())
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "fencing child failed: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        let child_release = fs::read(directory.path().join("child-release")).unwrap();
        let child_evidence = SignedEvidence::decode(&child_release).unwrap();
        child_evidence.verify(&epoch().chain, &public).unwrap();
        assert_eq!(child_evidence.message, message(1));
        assert_eq!(
            encode(signer.released_evidence_after(0).unwrap()),
            vec![child_release.clone(), later.encode().unwrap()]
        );
        assert_eq!(
            encode(signer.released_evidence_for_slot(1).unwrap()),
            vec![child_release]
        );
        // A warm, now-fenced process can retransmit a known release. It cannot
        // allocate a different role, even when its signature cache is valid.
        assert_eq!(
            signer.sign(message(0)).unwrap().encode().unwrap(),
            original.encode().unwrap()
        );
        let fresh = ConsensusMessage {
            kind: MessageKind::NotarApproval,
            ..message(0)
        };
        assert_eq!(signer.sign(fresh.clone()).err(), Some(SignerError::Fenced));
        assert!(matches!(
            signer.reconcile_intent(&fresh),
            Err(SignerError::Fenced)
        ));
        assert!(matches!(
            signer.reconcile_intent(&message(0)).unwrap(),
            IntentReconciliation::Released(evidence)
                if evidence.encode().unwrap() == original.encode().unwrap()
        ));
        #[cfg(unix)]
        assert_eq!(
            signer
                .verified_releases
                .lock()
                .unwrap()
                .authenticated_from_disk,
            3
        );

        // The fast slot index still checks independently burned ordinals on
        // every call. Removing a burn must invalidate even a warm exact view.
        let records = read_records(&authority_path).unwrap();
        let mut corrupted = records.clone();
        let ordinal = public.epoch().ordinal(1, AxRole::NotarVote, 0).unwrap();
        assert!(
            corrupted
                .get_mut(&public.ax_root())
                .unwrap()
                .burned
                .remove(&ordinal)
        );
        write_records(&authority_path, &corrupted).unwrap();
        assert!(matches!(
            signer.released_evidence_for_slot(1),
            Err(SignerError::CorruptState)
        ));
        assert!(matches!(
            signer.released_evidence_after(0),
            Err(SignerError::CorruptState)
        ));
        write_records(&authority_path, &records).unwrap();
        assert_eq!(signer.released_evidence_for_slot(1).unwrap().len(), 1);
        assert_eq!(store.inspect(public.ax_root()).unwrap().sequence, 3);
    }

    #[test]
    fn reserve_before_release_crash_and_restart_burns_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let signer = DurableAxSigner::create(&path, epoch(), store.clone()).unwrap();
        // Crash before reservation has no effect; crash after reservation burns
        // the key despite no signature ever being returned.
        signer.reserve(0, AxRole::SkipVote, 0).unwrap();
        drop(signer);
        let signer = DurableAxSigner::open(&path, store.clone()).unwrap();
        assert_eq!(
            signer.sign(0, AxRole::SkipVote, 0, b""),
            Err(SignerError::AlreadyUsed)
        );
        let sig = signer.sign(0, AxRole::FinalVote, 0, b"").unwrap();
        crate::ax::verify(
            &epoch(),
            0,
            AxRole::FinalVote,
            0,
            b"",
            &signer
                .material()
                .public_key(0, AxRole::FinalVote, 0)
                .unwrap(),
            &sig,
        )
        .unwrap();
        drop(signer);
        let signer = DurableAxSigner::open(&path, store).unwrap();
        assert_eq!(
            signer.sign(0, AxRole::FinalVote, 0, b""),
            Err(SignerError::AlreadyUsed)
        );
    }
    #[test]
    fn backup_rollback_detected_and_recovery_fences_old_instance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let signer = DurableAxSigner::create(&path, epoch(), store.clone()).unwrap();
        let backup = fs::read(&path).unwrap();
        signer.sign(0, AxRole::SkipVote, 0, b"").unwrap();
        fs::write(&path, backup).unwrap();
        assert!(matches!(
            DurableAxSigner::open(&path, store.clone()),
            Err(SignerError::RollbackDetected)
        ));
        let recovered = DurableAxSigner::recover(&path, store).unwrap();
        assert_eq!(
            recovered.sign(0, AxRole::SkipVote, 0, b""),
            Err(SignerError::AlreadyUsed)
        );
        assert_eq!(
            signer.sign(0, AxRole::FinalVote, 0, b""),
            Err(SignerError::Fenced)
        );
        recovered.sign(0, AxRole::FinalVote, 0, b"").unwrap();
    }
    #[test]
    fn concurrent_instances_failover_and_concurrent_calls_never_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let old = DurableAxSigner::create(&path, epoch(), store.clone()).unwrap();
        let signer = Arc::new(DurableAxSigner::open(&path, store).unwrap());
        assert_eq!(
            old.sign(0, AxRole::SkipVote, 0, b""),
            Err(SignerError::Fenced)
        );
        let results: Vec<_> = std::thread::scope(|scope| {
            let joins: Vec<_> = (0..8)
                .map(|_| {
                    let signer = signer.clone();
                    scope.spawn(move || signer.sign(0, AxRole::SkipVote, 0, b""))
                })
                .collect();
            joins.into_iter().map(|j| j.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|r| r.is_err())
                .all(|r| matches!(r, Err(SignerError::AlreadyUsed)))
        );
    }
    #[test]
    fn external_reservation_crash_requires_burn_reconciliation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let signer = DurableAxSigner::create(&path, epoch(), store.clone()).unwrap();
        let root = signer.material().root();
        store.reserve(root, signer.fence, 0, 9).unwrap();
        drop(signer);
        assert!(matches!(
            DurableAxSigner::open(&path, store.clone()),
            Err(SignerError::RollbackDetected)
        ));
        let signer = DurableAxSigner::recover(&path, store).unwrap();
        assert_eq!(
            signer.sign(0, AxRole::SkipVote, 0, b""),
            Err(SignerError::AlreadyUsed)
        );
        signer.sign(0, AxRole::FinalVote, 0, b"").unwrap();
    }
    #[test]
    fn fsync_authority_survives_restart_and_rejects_signer_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let authority = directory.path().join("independent-authority");
        let store = Arc::new(FileMonotonicStore::open(&authority).unwrap());
        let signer = DurableAxSigner::create(&path, epoch(), store).unwrap();
        let backup = fs::read(&path).unwrap();
        signer.sign(0, AxRole::SkipVote, 0, b"").unwrap();
        drop(signer);
        fs::write(&path, backup).unwrap();
        let store = Arc::new(FileMonotonicStore::open(&authority).unwrap());
        assert!(matches!(
            DurableAxSigner::open(&path, store.clone()),
            Err(SignerError::RollbackDetected)
        ));
        let signer = DurableAxSigner::recover(&path, store).unwrap();
        assert_eq!(
            signer.sign(0, AxRole::SkipVote, 0, b""),
            Err(SignerError::AlreadyUsed)
        );
        signer.sign(0, AxRole::FinalVote, 0, b"").unwrap();
    }
    #[test]
    fn durable_consensus_journal_retransmits_after_restart_and_rejects_conflict() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(FileMonotonicStore::open(directory.path().join("authority")).unwrap());
        let authority = FalconKeypair::generate();
        let signer =
            DurableConsensusSigner::create(&path, epoch(), &authority, store.clone()).unwrap();
        let public = signer.public_key();
        let message = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::NotarVote,
            block: Some([8; 48]),
        };
        let evidence = signer.sign(message.clone()).unwrap();
        evidence.verify(&epoch().chain, &public).unwrap();
        drop(signer);
        let signer = DurableConsensusSigner::open(&path, public.clone(), store).unwrap();
        assert_eq!(
            signer.sign(message).unwrap().encode().unwrap(),
            evidence.encode().unwrap()
        );
        assert_eq!(
            signer
                .sign(ConsensusMessage {
                    epoch: 3,
                    slot: 0,
                    kind: MessageKind::NotarVote,
                    block: Some([9; 48])
                })
                .err(),
            Some(SignerError::AlreadyUsed)
        );
        signer
            .sign(ConsensusMessage {
                epoch: 3,
                slot: 0,
                kind: MessageKind::FinalVote,
                block: None,
            })
            .unwrap()
            .verify(&epoch().chain, &public)
            .unwrap();
    }
    #[test]
    fn finalized_role_burns_survive_restored_state_and_release_journal() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(FileMonotonicStore::open(directory.path().join("authority")).unwrap());
        let signer = DurableConsensusSigner::create(
            &path,
            epoch(),
            &FalconKeypair::generate(),
            store.clone(),
        )
        .unwrap();
        let public = signer.public_key();
        let backup_state = fs::read(&path).unwrap();
        let backup_journal = fs::read(&signer.journal).unwrap();
        let notar = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::NotarVote,
            block: Some([9; 48]),
        };
        signer.sign(notar).unwrap();
        signer
            .sign(ConsensusMessage {
                epoch: 3,
                slot: 0,
                kind: MessageKind::FinalVote,
                block: None,
            })
            .unwrap();
        let journal_path = signer.journal.clone();
        drop(signer);
        fs::write(&path, backup_state).unwrap();
        fs::write(&journal_path, backup_journal).unwrap();
        let recovered = DurableConsensusSigner::recover(&path, public, store).unwrap();
        for kind in [
            MessageKind::NotarVote,
            MessageKind::SkipVote,
            MessageKind::NotarFallbackVote,
            MessageKind::SkipFallbackVote,
        ] {
            let block = if matches!(
                kind,
                MessageKind::NotarVote | MessageKind::NotarFallbackVote
            ) {
                Some([8; 48])
            } else {
                None
            };
            assert_eq!(
                recovered
                    .sign(ConsensusMessage {
                        epoch: 3,
                        slot: 0,
                        kind,
                        block
                    })
                    .err(),
                Some(SignerError::AlreadyUsed)
            );
        }
        recovered
            .sign(ConsensusMessage {
                epoch: 3,
                slot: 0,
                kind: MessageKind::NotarApproval,
                block: Some([9; 48]),
            })
            .unwrap();
    }
    #[test]
    fn final_vote_requires_notar_and_rejects_bad_window_burns() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        for preceding in [
            None,
            Some(MessageKind::SkipVote),
            Some(MessageKind::NotarFallbackVote),
            Some(MessageKind::SkipFallbackVote),
        ] {
            let path = directory.path().join(format!("signer-{preceding:?}"));
            let store = Arc::new(MemoryMonotonicStore::default());
            let signer =
                DurableConsensusSigner::create(&path, epoch(), &FalconKeypair::generate(), store)
                    .unwrap();
            if let Some(kind) = preceding {
                let block = if kind == MessageKind::NotarFallbackVote {
                    Some([9; 48])
                } else {
                    None
                };
                signer
                    .sign(ConsensusMessage {
                        epoch: 3,
                        slot: 0,
                        kind,
                        block,
                    })
                    .unwrap();
            }
            assert_eq!(
                signer
                    .sign(ConsensusMessage {
                        epoch: 3,
                        slot: 0,
                        kind: MessageKind::FinalVote,
                        block: None
                    })
                    .err(),
                Some(SignerError::AlreadyUsed)
            );
        }
    }

    #[test]
    fn intent_reconciliation_withdraws_crash_burn_without_unburning_after_final() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(FileMonotonicStore::open(directory.path().join("authority")).unwrap());
        let signer = DurableConsensusSigner::create(
            &path,
            epoch(),
            &FalconKeypair::generate(),
            store.clone(),
        )
        .unwrap();
        let public = signer.public_key();
        let notar = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::NotarVote,
            block: Some([7; 48]),
        };
        assert!(matches!(
            signer.reconcile_intent(&notar).unwrap(),
            IntentReconciliation::Available { index: 0 }
        ));
        // The crash point observed in the real cluster: external burn and local
        // state are durable, but no signature-release frame exists.
        signer.signer.reserve(0, AxRole::NotarVote, 0).unwrap();
        drop(signer);
        let signer = DurableConsensusSigner::recover(&path, public.clone(), store.clone()).unwrap();
        let ordinal = epoch().ordinal(0, AxRole::NotarVote, 0).unwrap();
        assert!(matches!(
            signer.reconcile_intent(&notar).unwrap(),
            IntentReconciliation::CrashBurned { ordinals } if ordinals == vec![ordinal]
        ));
        assert_eq!(
            signer.sign(notar.clone()).err(),
            Some(SignerError::AlreadyUsed)
        );
        assert!(signer.released_evidence().unwrap().is_empty());
        let final_vote = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::FinalVote,
            block: None,
        };
        signer.sign(final_vote.clone()).unwrap();
        drop(signer);
        let signer = DurableConsensusSigner::recover(&path, public, store.clone()).unwrap();
        let before = store.inspect(signer.public.ax_root()).unwrap();
        let state_before = fs::read(&path).unwrap();
        let journal_before = fs::read(&signer.journal).unwrap();
        assert!(matches!(
            signer.reconcile_intent(&notar).unwrap(),
            IntentReconciliation::CrashBurned { ordinals } if ordinals == vec![ordinal]
        ));
        assert!(matches!(
            signer.reconcile_intent(&final_vote).unwrap(),
            IntentReconciliation::Released(evidence) if evidence.message == final_vote
        ));
        assert_eq!(
            signer.sign(notar.clone()).err(),
            Some(SignerError::AlreadyUsed)
        );
        assert!(matches!(
            signer
                .reconcile_intent(&ConsensusMessage {
                    kind: MessageKind::SkipVote,
                    block: None,
                    ..notar.clone()
                })
                .unwrap(),
            IntentReconciliation::Conflict(ReplayConflict::AlternatePrimary)
        ));
        assert!(matches!(
            signer
                .reconcile_intent(&ConsensusMessage {
                    kind: MessageKind::NotarFallbackVote,
                    ..notar
                })
                .unwrap(),
            IntentReconciliation::Conflict(ReplayConflict::TerminalVote)
        ));
        let after = store.inspect(signer.public.ax_root()).unwrap();
        assert_eq!(before.sequence, after.sequence);
        assert_eq!(before.fence, after.fence);
        assert_eq!(before.burned, after.burned);
        assert_eq!(state_before, fs::read(path).unwrap());
        assert_eq!(journal_before, fs::read(&signer.journal).unwrap());
        assert_eq!(signer.released_evidence().unwrap().len(), 1);
    }

    #[test]
    fn intent_reconciliation_preserves_released_conflicts_and_fencing() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let signer = DurableConsensusSigner::create(
            &path,
            epoch(),
            &FalconKeypair::generate(),
            store.clone(),
        )
        .unwrap();
        let notar = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::NotarVote,
            block: Some([7; 48]),
        };
        let final_vote = ConsensusMessage {
            kind: MessageKind::FinalVote,
            block: None,
            ..notar.clone()
        };
        assert!(matches!(
            signer.reconcile_intent(&final_vote).unwrap(),
            IntentReconciliation::Conflict(ReplayConflict::FinalPrerequisite)
        ));
        let evidence = signer.sign(notar.clone()).unwrap();
        signer.sign(final_vote).unwrap();
        assert!(matches!(
            signer
                .reconcile_intent(&ConsensusMessage {
                    block: Some([8; 48]),
                    ..notar.clone()
                })
                .unwrap(),
            IntentReconciliation::Conflict(ReplayConflict::ReleasedDifferentMessage)
        ));
        let new_instance = DurableConsensusSigner::open(&path, signer.public_key(), store).unwrap();
        assert!(matches!(
            signer.reconcile_intent(&notar).unwrap(),
            IntentReconciliation::Released(released) if released.encode().unwrap() == evidence.encode().unwrap()
        ));
        assert!(matches!(
            signer.reconcile_intent(&ConsensusMessage {
                kind: MessageKind::NotarApproval,
                ..notar.clone()
            }),
            Err(SignerError::Fenced)
        ));
        assert!(matches!(
            new_instance
                .reconcile_intent(&ConsensusMessage {
                    kind: MessageKind::NotarApproval,
                    ..notar
                })
                .unwrap(),
            IntentReconciliation::Available { index: 0 }
        ));
    }

    #[test]
    fn intent_reconciliation_distinguishes_fresh_and_orphan_multikey_capacity() {
        use crate::consensus::MessageKind;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer");
        let store = Arc::new(MemoryMonotonicStore::default());
        let signer = DurableConsensusSigner::create(
            &path,
            epoch(),
            &FalconKeypair::generate(),
            store.clone(),
        )
        .unwrap();
        let message = ConsensusMessage {
            epoch: 3,
            slot: 0,
            kind: MessageKind::NotarFallbackVote,
            block: Some([7; 48]),
        };
        signer
            .signer
            .reserve(0, AxRole::NotarFallbackVote, 0)
            .unwrap();
        assert!(matches!(
            signer.reconcile_intent(&message).unwrap(),
            IntentReconciliation::Available { index: 1 }
        ));
        signer
            .sign(ConsensusMessage {
                block: Some([8; 48]),
                ..message.clone()
            })
            .unwrap();
        assert!(matches!(
            signer.reconcile_intent(&message).unwrap(),
            IntentReconciliation::Available { index: 2 }
        ));
        signer
            .signer
            .reserve(0, AxRole::NotarFallbackVote, 2)
            .unwrap();
        assert!(matches!(
            signer.reconcile_intent(&message).unwrap(),
            IntentReconciliation::CrashBurned { ordinals }
                if ordinals == vec![
                    epoch().ordinal(0, AxRole::NotarFallbackVote, 0).unwrap(),
                    epoch().ordinal(0, AxRole::NotarFallbackVote, 2).unwrap(),
                ]
        ));
        assert_eq!(signer.sign(message).err(), Some(SignerError::AlreadyUsed));
        assert_eq!(signer.released_evidence().unwrap().len(), 1);

        // Exhaustion exclusively accounted for by valid releases is a different
        // condition from a crash-burned reservation with no recoverable witness.
        for value in 0..AxRole::NotarFallbackApproval.capacity() {
            signer
                .sign(ConsensusMessage {
                    epoch: 3,
                    slot: 0,
                    kind: MessageKind::NotarFallbackApproval,
                    block: Some([value; 48]),
                })
                .unwrap();
        }
        assert!(matches!(
            signer
                .reconcile_intent(&ConsensusMessage {
                    epoch: 3,
                    slot: 0,
                    kind: MessageKind::NotarFallbackApproval,
                    block: Some([9; 48]),
                })
                .unwrap(),
            IntentReconciliation::Conflict(ReplayConflict::RoleCapacity)
        ));
    }
}
