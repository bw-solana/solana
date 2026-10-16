//! Quantumglow evidence using the fixed Ax research profile.
//!
//! The certificate pool retains transferable evidence. Local voting permission
//! and ancestry/timeouts belong to `quantumglow::Quantumglow`.
use {
    crate::{
        ax::{
            AxEpoch, AxKeypair, AxPublicMaterial, AxRole, AxRootBinding, AxSignature,
            verify as ax_verify, verify_inclusion,
        },
        crypto::{
            FALCON_PUBLIC_KEY_BYTES, FALCON_SIGNATURE_BYTES, FalconKeypair, FalconPublicKey,
            FalconSignature, hash_commitment,
        },
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        sync::{Arc, Mutex},
    },
};

pub type Commitment = [u8; 48];
pub const MAX_VALIDATORS: usize = 2048;
pub const MAX_SLOT_WINDOW: u64 = 128;
pub const MAX_EPOCH_SLOTS: u64 = crate::ax::AX_MAX_SLOTS as u64;
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SIGNED_EVIDENCE_WIRE_BYTES: usize = 4096;
pub const CONSENSUS_PUBLIC_KEY_BYTES: usize =
    1 + FALCON_PUBLIC_KEY_BYTES + AxEpoch::ENCODED_BYTES + 48 + FALCON_SIGNATURE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    Bounds,
    Encoding,
    Signature,
    Context,
    Membership,
    DuplicateValidator,
    Equivocation,
    EvidenceLimit,
}
impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ConsensusError {}

#[derive(Clone)]
pub struct ConsensusPublicKey {
    encoded: Vec<u8>,
    binding: AxRootBinding,
    material: Option<Arc<AxPublicMaterial>>,
}
impl std::fmt::Debug for ConsensusPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConsensusPublicKey")
            .field(&self.commitment())
            .finish()
    }
}
impl PartialEq for ConsensusPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}
impl Eq for ConsensusPublicKey {}
impl ConsensusPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConsensusError> {
        if bytes.len() != CONSENSUS_PUBLIC_KEY_BYTES || bytes[0] != 1 {
            return Err(ConsensusError::Encoding);
        }
        let authority_end = 1 + FALCON_PUBLIC_KEY_BYTES;
        let epoch_end = authority_end + AxEpoch::ENCODED_BYTES;
        let root_end = epoch_end + 48;
        let authority = FalconPublicKey::from_bytes(&bytes[1..authority_end])
            .map_err(|_| ConsensusError::Encoding)?;
        let epoch = AxEpoch::decode(&bytes[authority_end..epoch_end])
            .map_err(|_| ConsensusError::Encoding)?;
        let root = bytes[epoch_end..root_end]
            .try_into()
            .map_err(|_| ConsensusError::Encoding)?;
        let signature = FalconSignature::from_bytes(&bytes[root_end..])
            .map_err(|_| ConsensusError::Encoding)?;
        let binding = AxRootBinding {
            epoch,
            root,
            signature,
        };
        binding
            .verify(&binding.epoch, &authority)
            .map_err(|_| ConsensusError::Signature)?;
        Ok(Self {
            encoded: bytes.to_vec(),
            binding,
            material: None,
        })
    }
    pub fn from_authorized_material(
        material: Arc<AxPublicMaterial>,
        authority: &FalconKeypair,
    ) -> Result<Self, ConsensusError> {
        let binding = AxRootBinding::authorize(&material, authority)
            .map_err(|_| ConsensusError::Signature)?;
        let mut encoded = vec![1];
        encoded.extend_from_slice(authority.public_key().as_bytes());
        encoded.extend(binding.epoch.encode());
        encoded.extend_from_slice(&binding.root);
        encoded.extend_from_slice(binding.signature.as_bytes());
        Ok(Self {
            encoded,
            binding,
            material: Some(material),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
    pub fn commitment(&self) -> Commitment {
        consensus_key_commitment(&self.encoded)
    }
    pub fn epoch(&self) -> &AxEpoch {
        &self.binding.epoch
    }
    pub fn ax_root(&self) -> Commitment {
        self.binding.root
    }
    /// Installs only material committed in this already authenticated descriptor.
    pub fn cache_material(
        &mut self,
        material: Arc<AxPublicMaterial>,
    ) -> Result<(), ConsensusError> {
        if material.epoch != self.binding.epoch || material.root() != self.binding.root {
            return Err(ConsensusError::Context);
        }
        self.material = Some(material);
        Ok(())
    }
}
pub fn consensus_key_commitment(bytes: &[u8]) -> Commitment {
    hash_commitment(b"pq-consensus-ax-descriptor-v1", &[bytes])
}
struct SigningState {
    signer: AxKeypair,
    released: BTreeMap<(u64, MessageKind, Vec<u8>), Vec<u8>>,
    next: BTreeMap<(u64, MessageKind), u8>,
}
/// In-memory simulation signer; actual durable releases use `DurableAxSigner`.
/// The public descriptor commits the finite epoch root before any votes exist.
pub struct ConsensusKeypair {
    public: ConsensusPublicKey,
    state: Mutex<SigningState>,
}
impl ConsensusKeypair {
    pub fn generate_for(
        chain: [u8; 32],
        validator: [u8; 32],
        epoch: u64,
        first_slot: u64,
        slots: u32,
    ) -> Result<Self, ConsensusError> {
        Self::generate_for_generation(chain, validator, epoch, 0, first_slot, slots)
    }
    pub fn generate_for_generation(
        chain: [u8; 32],
        validator: [u8; 32],
        epoch: u64,
        generation: u64,
        first_slot: u64,
        slots: u32,
    ) -> Result<Self, ConsensusError> {
        let context = AxEpoch {
            chain,
            validator,
            epoch,
            generation,
            first_slot,
            slots,
        };
        let signer = AxKeypair::generate(context).map_err(|_| ConsensusError::Bounds)?;
        let material = signer.material();
        let authority = FalconKeypair::generate();
        let binding = AxRootBinding::authorize(&material, &authority)
            .map_err(|_| ConsensusError::Signature)?;
        let mut encoded = vec![1];
        encoded.extend_from_slice(authority.public_key().as_bytes());
        encoded.extend(binding.epoch.encode());
        encoded.extend_from_slice(&binding.root);
        encoded.extend_from_slice(binding.signature.as_bytes());
        let public = ConsensusPublicKey {
            encoded,
            binding,
            material: Some(material),
        };
        Ok(Self {
            public,
            state: Mutex::new(SigningState {
                signer,
                released: BTreeMap::new(),
                next: BTreeMap::new(),
            }),
        })
    }
    pub fn public_key(&self) -> ConsensusPublicKey {
        self.public.clone()
    }
    pub fn material(&self) -> Arc<AxPublicMaterial> {
        self.public
            .material
            .as_ref()
            .expect("signer material")
            .clone()
    }
    pub fn sign(
        &self,
        chain: &[u8; 32],
        validator: [u8; 32],
        message: ConsensusMessage,
    ) -> Result<SignedEvidence, ConsensusError> {
        let context = &self.public.binding.epoch;
        if chain != &context.chain
            || validator != context.validator
            || message.epoch != context.epoch
        {
            return Err(ConsensusError::Context);
        }
        let encoded_message = message.encode()?;
        let map_key = (message.slot, message.kind, encoded_message);
        let mut state = self.state.lock().map_err(|_| ConsensusError::Context)?;
        if let Some(signature) = state.released.get(&map_key) {
            return Ok(SignedEvidence {
                validator,
                message,
                signature: signature.clone(),
            });
        }
        if matches!(message.kind, MessageKind::NotarVote | MessageKind::SkipVote)
            && state.released.keys().any(|(slot, kind, _)| {
                *slot == message.slot
                    && *kind != message.kind
                    && matches!(kind, MessageKind::NotarVote | MessageKind::SkipVote)
            })
        {
            return Err(ConsensusError::Equivocation);
        }
        let role = ax_role(message.kind);
        let index = *state.next.get(&(message.slot, message.kind)).unwrap_or(&0);
        if index >= role.capacity() {
            return Err(ConsensusError::EvidenceLimit);
        }
        let payload = if role.is_zero() {
            Vec::new()
        } else {
            sign_bytes(chain, &validator, &message)?
        };
        let signature = state
            .signer
            .sign(message.slot, role, index, &payload)
            .map_err(|_| ConsensusError::Signature)?;
        let material = state.signer.material();
        let key = material
            .public_key(message.slot, role, index)
            .map_err(|_| ConsensusError::Context)?;
        let proof = material
            .proof(message.slot, role, index)
            .map_err(|_| ConsensusError::Context)?;
        let mut wire = vec![index];
        wire.extend_from_slice(&key);
        wire.push(proof.len() as u8);
        for sibling in proof {
            wire.extend_from_slice(&sibling);
        }
        wire.extend_from_slice(signature.as_bytes());
        state.next.insert((message.slot, message.kind), index + 1);
        state.released.insert(map_key, wire.clone());
        Ok(SignedEvidence {
            validator,
            message,
            signature: wire,
        })
    }
    #[cfg(test)]
    pub(crate) fn faulty_clone_for_test(&self) -> Self {
        let state = self.state.lock().expect("signer mutex");
        Self {
            public: self.public.clone(),
            state: Mutex::new(SigningState {
                signer: state.signer.faulty_clone_for_test(),
                released: BTreeMap::new(),
                next: BTreeMap::new(),
            }),
        }
    }
}
fn ax_role(kind: MessageKind) -> AxRole {
    AxRole::from_byte(kind as u8).expect("consensus message role")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MessageKind {
    NotarVote = 1,
    NotarFallbackVote = 2,
    SkipVote = 3,
    SkipFallbackVote = 4,
    FinalVote = 5,
    NotarApproval = 6,
    NotarFallbackApproval = 7,
    SkipApproval = 8,
}
impl MessageKind {
    fn requires_block(self) -> bool {
        matches!(
            self,
            Self::NotarVote
                | Self::NotarFallbackVote
                | Self::NotarApproval
                | Self::NotarFallbackApproval
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusMessage {
    pub epoch: u64,
    pub slot: u64,
    pub kind: MessageKind,
    pub block: Option<Commitment>,
}
impl ConsensusMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self, ConsensusError> {
        if bytes.len() != 19 && bytes.len() != 67 {
            return Err(ConsensusError::Encoding);
        }
        if bytes[0] != 1 {
            return Err(ConsensusError::Encoding);
        }
        let kind = match bytes[1] {
            1 => MessageKind::NotarVote,
            2 => MessageKind::NotarFallbackVote,
            3 => MessageKind::SkipVote,
            4 => MessageKind::SkipFallbackVote,
            5 => MessageKind::FinalVote,
            6 => MessageKind::NotarApproval,
            7 => MessageKind::NotarFallbackApproval,
            8 => MessageKind::SkipApproval,
            _ => return Err(ConsensusError::Encoding),
        };
        let epoch = u64::from_le_bytes(
            bytes[2..10]
                .try_into()
                .map_err(|_| ConsensusError::Encoding)?,
        );
        let slot = u64::from_le_bytes(
            bytes[10..18]
                .try_into()
                .map_err(|_| ConsensusError::Encoding)?,
        );
        let block = match bytes[18] {
            0 if bytes.len() == 19 => None,
            1 if bytes.len() == 67 => Some(
                bytes[19..67]
                    .try_into()
                    .map_err(|_| ConsensusError::Encoding)?,
            ),
            _ => return Err(ConsensusError::Encoding),
        };
        let message = Self {
            epoch,
            slot,
            kind,
            block,
        };
        message.encode()?;
        Ok(message)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ConsensusError> {
        if self.kind.requires_block() != self.block.is_some() {
            return Err(ConsensusError::Encoding);
        }
        let mut out = vec![1, self.kind as u8];
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.push(u8::from(self.block.is_some()));
        if let Some(block) = self.block {
            out.extend_from_slice(&block);
        }
        Ok(out)
    }
}
#[derive(Clone)]
pub struct SignedEvidence {
    pub validator: [u8; 32],
    pub message: ConsensusMessage,
    pub signature: Vec<u8>,
}
impl SignedEvidence {
    /// Removes the cold authentication path after receivers have authenticated
    /// the complete epoch material. Uncached receivers reject this encoding.
    pub fn for_cached_material(&self) -> Result<Self, ConsensusError> {
        if !valid_signature_wire(ax_role(self.message.kind), &self.signature) {
            return Err(ConsensusError::Encoding);
        }
        let proof_end = 26 + usize::from(self.signature[25]) * 48;
        let mut signature = self.signature[..26].to_vec();
        signature[25] = 0;
        signature.extend_from_slice(&self.signature[proof_end..]);
        Ok(Self {
            validator: self.validator,
            message: self.message.clone(),
            signature,
        })
    }
    pub fn from_ax_signature(
        validator: [u8; 32],
        message: ConsensusMessage,
        index: u8,
        material: &AxPublicMaterial,
        signature: &AxSignature,
    ) -> Result<Self, ConsensusError> {
        message.encode()?;
        let role = ax_role(message.kind);
        let key = material
            .public_key(message.slot, role, index)
            .map_err(|_| ConsensusError::Context)?;
        let proof = material
            .proof(message.slot, role, index)
            .map_err(|_| ConsensusError::Context)?;
        let mut wire = vec![index];
        wire.extend_from_slice(&key);
        wire.push(proof.len() as u8);
        for sibling in proof {
            wire.extend_from_slice(&sibling);
        }
        wire.extend_from_slice(signature.as_bytes());
        let evidence = Self {
            validator,
            message,
            signature: wire,
        };
        evidence.encode()?;
        Ok(evidence)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ConsensusError> {
        if !valid_signature_wire(ax_role(self.message.kind), &self.signature) {
            return Err(ConsensusError::Encoding);
        }
        let message = self.message.encode()?;
        let mut out = vec![1];
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(&(message.len() as u16).to_le_bytes());
        out.extend_from_slice(&message);
        out.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_SIGNED_EVIDENCE_WIRE_BYTES {
            return Err(ConsensusError::Bounds);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ConsensusError> {
        if bytes.len() > MAX_SIGNED_EVIDENCE_WIRE_BYTES {
            return Err(ConsensusError::Bounds);
        }
        if bytes.len() < 39 || bytes[0] != 1 {
            return Err(ConsensusError::Encoding);
        }
        let validator = bytes[1..33]
            .try_into()
            .map_err(|_| ConsensusError::Encoding)?;
        let message_len = usize::from(u16::from_le_bytes(
            bytes[33..35]
                .try_into()
                .map_err(|_| ConsensusError::Encoding)?,
        ));
        if message_len != 19 && message_len != 67 {
            return Err(ConsensusError::Encoding);
        }
        let message_end = 35 + message_len;
        let message =
            ConsensusMessage::decode(bytes.get(35..message_end).ok_or(ConsensusError::Encoding)?)?;
        let signature_len = u32::from_le_bytes(
            bytes
                .get(message_end..message_end + 4)
                .ok_or(ConsensusError::Encoding)?
                .try_into()
                .map_err(|_| ConsensusError::Encoding)?,
        ) as usize;
        if !valid_signature_wire(
            ax_role(message.kind),
            bytes
                .get(message_end + 4..)
                .ok_or(ConsensusError::Encoding)?,
        ) || bytes.len() != message_end + 4 + signature_len
        {
            return Err(ConsensusError::Encoding);
        }
        Ok(Self {
            validator,
            message,
            signature: bytes[message_end + 4..].to_vec(),
        })
    }
    pub fn verify(&self, chain: &[u8; 32], key: &ConsensusPublicKey) -> Result<(), ConsensusError> {
        let epoch = &key.binding.epoch;
        if chain != &epoch.chain
            || self.validator != epoch.validator
            || self.message.epoch != epoch.epoch
        {
            return Err(ConsensusError::Context);
        }
        self.message.encode()?;
        let role = ax_role(self.message.kind);
        if !valid_signature_wire(role, &self.signature) {
            return Err(ConsensusError::Encoding);
        }
        let index = self.signature[0];
        let public = self.signature[1..25]
            .try_into()
            .map_err(|_| ConsensusError::Encoding)?;
        let proof_len = usize::from(self.signature[25]);
        let proof_end = 26 + proof_len * 48;
        if let Some(material) = &key.material {
            if material
                .public_key(self.message.slot, role, index)
                .map_err(|_| ConsensusError::Context)?
                != public
            {
                return Err(ConsensusError::Signature);
            }
        } else {
            let proof: Vec<[u8; 48]> = self.signature[26..proof_end].as_chunks::<48>().0.to_vec();
            verify_inclusion(
                epoch,
                &key.binding.root,
                self.message.slot,
                role,
                index,
                &public,
                &proof,
            )
            .map_err(|_| ConsensusError::Signature)?;
        }
        let signature = AxSignature::from_bytes(role, &self.signature[proof_end..])
            .map_err(|_| ConsensusError::Encoding)?;
        let payload = if role.is_zero() {
            Vec::new()
        } else {
            sign_bytes(chain, &self.validator, &self.message)?
        };
        ax_verify(
            epoch,
            self.message.slot,
            role,
            index,
            &payload,
            &public,
            &signature,
        )
        .map_err(|_| ConsensusError::Signature)
    }
    pub fn wire_bytes(&self) -> Result<usize, ConsensusError> {
        Ok(32 + self.message.encode()?.len() + self.signature.len())
    }
}
// These outcomes authenticate one immutable input, never a voting decision.
// Raw and recovery entry points continue to verify every original witness.
struct EvidenceContext {
    instance: Arc<()>,
    chain: [u8; 32],
    epoch: u64,
    first_slot: u64,
    end_slot: u64,
    membership: Commitment,
    validators: BTreeMap<[u8; 32], Validator>,
    #[cfg(test)]
    verification_work: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Clone)]
pub struct EvidenceVerifier(Arc<EvidenceContext>);

/// A successful, immutable Ax authentication capability. The original witness
/// remains owned here; neither its message nor signature can be substituted.
pub struct VerifiedEvidence {
    evidence: SignedEvidence,
    context: Arc<EvidenceContext>,
}

struct RejectedEvidence {
    evidence: SignedEvidence,
    context: Arc<EvidenceContext>,
    error: ConsensusError,
}

/// An arrival-ordered authentication outcome. Failures retain the same context
/// as successes so a changed key or material cache cannot preserve a stale error.
pub struct PreparedEvidence(Result<VerifiedEvidence, RejectedEvidence>);

pub(crate) struct EvidenceAuthentication {
    context: Arc<EvidenceContext>,
    identity: Option<Commitment>,
    result: Result<(), ConsensusError>,
}

fn evidence_identity(evidence: &SignedEvidence) -> Option<Commitment> {
    evidence
        .encode()
        .ok()
        .map(|wire| hash_commitment(b"agave-pq-evidence-wire-v1", &[&wire]))
}

fn same_material(left: &ConsensusPublicKey, right: &ConsensusPublicKey) -> bool {
    match (&left.material, &right.material) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

impl EvidenceVerifier {
    pub fn prepare(&self, evidence: SignedEvidence) -> PreparedEvidence {
        let result = (|| {
            let message = &evidence.message;
            if message.epoch != self.0.epoch
                || message.slot < self.0.first_slot
                || message.slot >= self.0.end_slot
            {
                return Err(ConsensusError::Context);
            }
            message.encode()?;
            let member = self
                .0
                .validators
                .get(&evidence.validator)
                .ok_or(ConsensusError::Membership)?;
            #[cfg(test)]
            self.0
                .verification_work
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            evidence.verify(&self.0.chain, &member.key)
        })();
        PreparedEvidence(match result {
            Ok(()) => Ok(VerifiedEvidence {
                evidence,
                context: self.0.clone(),
            }),
            Err(error) => Err(RejectedEvidence {
                evidence,
                context: self.0.clone(),
                error,
            }),
        })
    }
}

impl PreparedEvidence {
    pub fn evidence(&self) -> &SignedEvidence {
        match &self.0 {
            Ok(verified) => &verified.evidence,
            Err(rejected) => &rejected.evidence,
        }
    }
    pub fn wire_commitment(&self) -> Option<Commitment> {
        evidence_identity(self.evidence())
    }
    pub(crate) fn into_parts(self) -> (SignedEvidence, EvidenceAuthentication) {
        let (evidence, context, result) = match self.0 {
            Ok(verified) => (verified.evidence, verified.context, Ok(())),
            Err(rejected) => (rejected.evidence, rejected.context, Err(rejected.error)),
        };
        let identity = evidence_identity(&evidence);
        (
            evidence,
            EvidenceAuthentication {
                context,
                identity,
                result,
            },
        )
    }
}

impl EvidenceAuthentication {
    fn matches(&self, pool: &ConsensusPool, evidence: &SignedEvidence) -> bool {
        let context = &self.context;
        // Epoch membership is private and immutable for this pool's lifetime.
        // A replacement pool gets another instance, even with the same epoch.
        let same_member = match (
            context.validators.get(&evidence.validator),
            pool.validators.get(&evidence.validator),
        ) {
            (Some(old), Some(current)) => {
                old.id == current.id
                    && old.stake == current.stake
                    && old.key == current.key
                    && old.key.commitment() == current.key.commitment()
                    && same_material(&old.key, &current.key)
            }
            (None, None) => true,
            _ => false,
        };
        Arc::ptr_eq(&context.instance, &pool.authentication_instance)
            && context.chain == pool.chain
            && context.epoch == pool.epoch
            && context.first_slot == pool.first_slot
            && context.end_slot == pool.end_slot
            && context.membership == pool.authentication_membership
            && same_member
            && self.identity == evidence_identity(evidence)
    }
}

fn valid_signature_wire(role: AxRole, bytes: &[u8]) -> bool {
    if bytes.len() < 26 || bytes[0] >= role.capacity() || bytes[25] > 19 {
        return false;
    }
    let actual = if role.is_zero() { 24 } else { 952 };
    bytes.len() == 26 + usize::from(bytes[25]) * 48 + actual
}
pub(crate) fn sign_bytes(
    chain: &[u8; 32],
    validator: &[u8; 32],
    message: &ConsensusMessage,
) -> Result<Vec<u8>, ConsensusError> {
    let domain = b"agave-pq-consensus-ax-research-v1";
    let encoded = message.encode()?;
    let mut out = Vec::new();
    out.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(chain);
    out.extend_from_slice(validator);
    out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    out.extend_from_slice(&encoded);
    Ok(out)
}
#[derive(Clone)]
pub struct Validator {
    pub id: [u8; 32],
    pub stake: u64,
    pub key: ConsensusPublicKey,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CertificateKind {
    FastFinalization,
    Notar,
    NotarFallback,
    Skip,
    Finalization,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusEvent {
    WeakCertificate {
        slot: u64,
        kind: CertificateKind,
        block: Option<Commitment>,
    },
    StrongCertificate {
        slot: u64,
        kind: CertificateKind,
        block: Option<Commitment>,
    },
    /// The local validator must apply its voting machine, then sign and broadcast.
    BroadcastApproval {
        slot: u64,
        kind: MessageKind,
        block: Option<Commitment>,
    },
    FastFinalized {
        slot: u64,
        block: Commitment,
    },
    SlowFinalized {
        slot: u64,
        block: Commitment,
    },
}
type EvidenceKey = ([u8; 32], MessageKind, Option<Commitment>);
type CertKey = (CertificateKind, Option<Commitment>);
#[derive(Default)]
struct SlotPool {
    evidence: BTreeMap<EvidenceKey, SignedEvidence>,
    weak: BTreeSet<CertKey>,
    strong: BTreeSet<CertKey>,
    finalized: Option<Commitment>,
}
/// Bounded authenticated evidence, stake deduplication and local certificate
/// events. The validator set must come from finalized authenticated state.
pub struct ConsensusPool {
    chain: [u8; 32],
    epoch: u64,
    validators: BTreeMap<[u8; 32], Validator>,
    total: u64,
    first_slot: u64,
    end_slot: u64,
    slots: BTreeMap<u64, SlotPool>,
    evidence_bytes: usize,
    equivocations: Vec<(SignedEvidence, SignedEvidence)>,
    pruned_through: u64,
    authentication_instance: Arc<()>,
    authentication_membership: Commitment,
    #[cfg(test)]
    verification_work: Arc<std::sync::atomic::AtomicUsize>,
}
impl ConsensusPool {
    pub fn new(
        chain: [u8; 32],
        epoch: u64,
        validators: Vec<Validator>,
        first_slot: u64,
        slot_count: u64,
    ) -> Result<Self, ConsensusError> {
        if validators.is_empty()
            || validators.len() > MAX_VALIDATORS
            || slot_count == 0
            || slot_count > MAX_EPOCH_SLOTS
        {
            return Err(ConsensusError::Bounds);
        }
        let end_slot = first_slot
            .checked_add(slot_count)
            .ok_or(ConsensusError::Bounds)?;
        let mut members = BTreeMap::new();
        let mut keys = BTreeSet::new();
        let mut total = 0u64;
        for validator in validators {
            if validator.stake == 0 {
                return Err(ConsensusError::Bounds);
            }
            total = total
                .checked_add(validator.stake)
                .ok_or(ConsensusError::Bounds)?;
            if !keys.insert(validator.key.as_bytes().to_vec())
                || members.insert(validator.id, validator).is_some()
            {
                return Err(ConsensusError::DuplicateValidator);
            }
        }
        let mut pool = Self {
            chain,
            epoch,
            validators: members,
            total,
            first_slot,
            end_slot,
            slots: BTreeMap::new(),
            evidence_bytes: 0,
            equivocations: Vec::new(),
            pruned_through: first_slot.saturating_sub(1),
            authentication_instance: Arc::new(()),
            authentication_membership: [0; 48],
            #[cfg(test)]
            verification_work: Arc::default(),
        };
        pool.authentication_membership = pool.validator_set_commitment();
        Ok(pool)
    }
    /// Snapshot only the immutable public authentication registry. All workers
    /// share this one bounded snapshot, including the actual material-cache mode.
    pub fn evidence_verifier(&self) -> EvidenceVerifier {
        EvidenceVerifier(Arc::new(EvidenceContext {
            instance: self.authentication_instance.clone(),
            chain: self.chain,
            epoch: self.epoch,
            first_slot: self.first_slot,
            end_slot: self.end_slot,
            membership: self.authentication_membership,
            validators: self.validators.clone(),
            #[cfg(test)]
            verification_work: self.verification_work.clone(),
        }))
    }
    pub fn insert_prepared(
        &mut self,
        prepared: PreparedEvidence,
    ) -> Result<Vec<ConsensusEvent>, ConsensusError> {
        let (evidence, authentication) = prepared.into_parts();
        self.insert_authenticated(evidence, Some(authentication))
    }
    pub fn insert(
        &mut self,
        evidence: SignedEvidence,
    ) -> Result<Vec<ConsensusEvent>, ConsensusError> {
        self.insert_authenticated(evidence, None)
    }
    pub(crate) fn insert_authenticated(
        &mut self,
        evidence: SignedEvidence,
        authentication: Option<EvidenceAuthentication>,
    ) -> Result<Vec<ConsensusEvent>, ConsensusError> {
        let m = &evidence.message;
        if m.epoch != self.epoch || m.slot < self.first_slot || m.slot >= self.end_slot {
            return Err(ConsensusError::Context);
        }
        m.encode()?;
        let member = self
            .validators
            .get(&evidence.validator)
            .ok_or(ConsensusError::Membership)?;
        // Verify before classifying an alleged conflict or retaining any attacker data.
        // Prepared outcomes save only math; current context and all stateful
        // insertion checks remain on this arrival-ordered owner path.
        if let Some(authentication) = authentication.filter(|proof| proof.matches(self, &evidence))
        {
            authentication.result?;
        } else {
            #[cfg(test)]
            self.verification_work
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            evidence.verify(&self.chain, &member.key)?;
        }
        if m.slot <= self.pruned_through {
            return Ok(vec![]);
        }
        let key = (evidence.validator, m.kind, m.block);
        let slot = self.slots.entry(m.slot).or_default();
        if slot.evidence.contains_key(&key) {
            return Ok(vec![]);
        }
        let prior: Vec<_> = slot
            .evidence
            .keys()
            .filter(|(id, _, _)| *id == evidence.validator)
            .copied()
            .collect();
        match m.kind {
            MessageKind::NotarVote | MessageKind::SkipVote => {
                if let Some(conflict) = prior.iter().find(|(_, kind, _)| {
                    matches!(kind, MessageKind::NotarVote | MessageKind::SkipVote)
                }) {
                    // Definition 12 retains the first initial vote. Keep the authenticated
                    // pair separately for attribution, without counting the stake twice.
                    let old = slot.evidence[conflict].clone();
                    let size = evidence.wire_bytes()?;
                    if self.evidence_bytes.saturating_add(size) > MAX_EVIDENCE_BYTES {
                        return Err(ConsensusError::Bounds);
                    }
                    if !self.equivocations.iter().any(|(_, second)| {
                        second.validator == evidence.validator && second.message == evidence.message
                    }) {
                        self.evidence_bytes += size;
                        self.equivocations.push((old, evidence));
                    }
                    return Err(ConsensusError::Equivocation);
                }
            }
            MessageKind::NotarFallbackVote => {
                if prior
                    .iter()
                    .filter(|(_, kind, _)| *kind == MessageKind::NotarFallbackVote)
                    .count()
                    >= 3
                {
                    return Err(ConsensusError::EvidenceLimit);
                }
            }
            MessageKind::NotarApproval | MessageKind::NotarFallbackApproval => {
                let blocks: BTreeSet<_> = prior
                    .iter()
                    .filter(|(_, kind, _)| {
                        matches!(
                            kind,
                            MessageKind::NotarApproval | MessageKind::NotarFallbackApproval
                        )
                    })
                    .filter_map(|(_, _, block)| *block)
                    .collect();
                if blocks.len() >= 4 && !blocks.contains(&m.block.unwrap()) {
                    return Err(ConsensusError::EvidenceLimit);
                }
            }
            _ => {}
        }
        let size = evidence.wire_bytes()?;
        if self.evidence_bytes.saturating_add(size) > MAX_EVIDENCE_BYTES {
            return Err(ConsensusError::Bounds);
        }
        self.evidence_bytes += size;
        let slot_number = m.slot;
        slot.evidence.insert(key, evidence);
        Ok(recompute_events(
            slot_number,
            slot,
            &self.validators,
            self.total,
        ))
    }
    pub fn retained_evidence(&self, slot: u64) -> Vec<SignedEvidence> {
        self.slots
            .get(&slot)
            .map(|s| s.evidence.values().cloned().collect())
            .unwrap_or_default()
    }
    pub fn active_slots(&self) -> impl Iterator<Item = u64> + '_ {
        self.slots.keys().copied()
    }
    pub fn prune_through(&mut self, slot: u64) -> Result<(), ConsensusError> {
        self.pruned_through = self.pruned_through.max(slot);
        self.slots.retain(|number, _| *number > slot);
        self.equivocations
            .retain(|(_, second)| second.message.slot > slot);
        self.evidence_bytes = 0;
        for evidence in self
            .slots
            .values()
            .flat_map(|state| state.evidence.values())
        {
            self.evidence_bytes += evidence.wire_bytes()?;
        }
        for (_, evidence) in &self.equivocations {
            self.evidence_bytes += evidence.wire_bytes()?;
        }
        Ok(())
    }
    pub fn equivocations(&self) -> &[(SignedEvidence, SignedEvidence)] {
        &self.equivocations
    }
    pub fn has_certificate(
        &self,
        slot: u64,
        kind: CertificateKind,
        block: Option<Commitment>,
        strong: bool,
    ) -> bool {
        self.slots
            .get(&slot)
            .is_some_and(|s| if strong { &s.strong } else { &s.weak }.contains(&(kind, block)))
    }
    /// Initial-vote stake only, with exactly one counted choice per member (Def. 12).
    pub fn initial_stakes(&self, slot: u64) -> (u64, BTreeMap<Commitment, u64>) {
        let mut skip = 0;
        let mut notar = BTreeMap::new();
        if let Some(s) = self.slots.get(&slot) {
            for (id, kind, block) in s.evidence.keys() {
                match (kind, block) {
                    (MessageKind::SkipVote, None) => skip += self.validators[id].stake,
                    (MessageKind::NotarVote, Some(block)) => {
                        *notar.entry(*block).or_default() += self.validators[id].stake;
                    }
                    _ => {}
                }
            }
        }
        (skip, notar)
    }
    pub fn total_stake(&self) -> u64 {
        self.total
    }
    pub fn certificate_blocks(&self, slot: u64, strong: bool) -> Vec<Commitment> {
        let Some(s) = self.slots.get(&slot) else {
            return vec![];
        };
        let certs = if strong { &s.strong } else { &s.weak };
        certs
            .iter()
            .filter_map(|(kind, block)| {
                if matches!(
                    kind,
                    CertificateKind::Notar | CertificateKind::NotarFallback
                ) {
                    *block
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub fn finalized(&self, slot: u64) -> Option<Commitment> {
        self.slots.get(&slot).and_then(|s| s.finalized)
    }
    pub fn evidence_bytes(&self) -> usize {
        self.evidence_bytes
    }
    pub fn validator_set_commitment(&self) -> Commitment {
        let mut out = Vec::new();
        out.extend_from_slice(&self.chain);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        for (id, v) in &self.validators {
            out.extend_from_slice(id);
            out.extend_from_slice(&v.stake.to_le_bytes());
            out.extend_from_slice(v.key.as_bytes());
        }
        hash_commitment(b"pq-consensus-validator-set-v1", &[&out])
    }
}
fn stake_for(
    slot: &SlotPool,
    validators: &BTreeMap<[u8; 32], Validator>,
    kinds: &[MessageKind],
    block: Option<Commitment>,
) -> u64 {
    let mut seen = BTreeSet::new();
    let mut total = 0;
    for (id, kind, b) in slot.evidence.keys() {
        if *b == block && kinds.contains(kind) && seen.insert(*id) {
            total += validators[id].stake;
        }
    }
    total
}
fn threshold(stake: u64, total: u64, percentage: u64) -> bool {
    u128::from(stake) * 100 >= u128::from(total) * u128::from(percentage)
}
fn recompute_events(
    number: u64,
    slot: &mut SlotPool,
    validators: &BTreeMap<[u8; 32], Validator>,
    total: u64,
) -> Vec<ConsensusEvent> {
    let mut events = Vec::new();
    let blocks: BTreeSet<Commitment> = slot
        .evidence
        .keys()
        .filter_map(|(_, _, block)| *block)
        .collect();
    for block in blocks {
        let notar = stake_for(slot, validators, &[MessageKind::NotarVote], Some(block));
        let fallback = stake_for(
            slot,
            validators,
            &[MessageKind::NotarVote, MessageKind::NotarFallbackVote],
            Some(block),
        );
        let notar_approvals =
            stake_for(slot, validators, &[MessageKind::NotarApproval], Some(block));
        let fallback_approvals = stake_for(
            slot,
            validators,
            &[
                MessageKind::NotarApproval,
                MessageKind::NotarFallbackApproval,
            ],
            Some(block),
        );
        add_cert(
            slot,
            &mut events,
            number,
            CertificateKind::Notar,
            Some(block),
            threshold(notar, total, 60) || threshold(notar_approvals, total, 20),
            threshold(notar_approvals, total, 60),
            Some(MessageKind::NotarApproval),
        );
        let notar_exists = slot.weak.contains(&(CertificateKind::Notar, Some(block)));
        add_cert(
            slot,
            &mut events,
            number,
            CertificateKind::NotarFallback,
            Some(block),
            threshold(fallback, total, 60) || threshold(fallback_approvals, total, 20),
            threshold(fallback_approvals, total, 60),
            if notar_exists {
                None
            } else {
                Some(MessageKind::NotarFallbackApproval)
            },
        );
        add_cert(
            slot,
            &mut events,
            number,
            CertificateKind::FastFinalization,
            Some(block),
            threshold(notar, total, 80),
            false,
            None,
        );
        if threshold(notar, total, 80) && slot.finalized.is_none() {
            slot.finalized = Some(block);
            events.push(ConsensusEvent::FastFinalized {
                slot: number,
                block,
            });
        }
    }
    let skip = stake_for(
        slot,
        validators,
        &[MessageKind::SkipVote, MessageKind::SkipFallbackVote],
        None,
    );
    let skip_approvals = stake_for(slot, validators, &[MessageKind::SkipApproval], None);
    add_cert(
        slot,
        &mut events,
        number,
        CertificateKind::Skip,
        None,
        threshold(skip, total, 60) || threshold(skip_approvals, total, 20),
        threshold(skip_approvals, total, 60),
        Some(MessageKind::SkipApproval),
    );
    let finals = stake_for(slot, validators, &[MessageKind::FinalVote], None);
    add_cert(
        slot,
        &mut events,
        number,
        CertificateKind::Finalization,
        None,
        threshold(finals, total, 60),
        false,
        None,
    );
    if threshold(finals, total, 60) && slot.finalized.is_none() {
        let notarized: Vec<_> = slot
            .weak
            .iter()
            .filter_map(|(kind, block)| {
                if *kind == CertificateKind::Notar {
                    *block
                } else {
                    None
                }
            })
            .collect();
        if notarized.len() == 1 {
            slot.finalized = Some(notarized[0]);
            events.push(ConsensusEvent::SlowFinalized {
                slot: number,
                block: notarized[0],
            });
        }
    }
    events
}
fn add_cert(
    slot: &mut SlotPool,
    events: &mut Vec<ConsensusEvent>,
    number: u64,
    kind: CertificateKind,
    block: Option<Commitment>,
    weak: bool,
    strong: bool,
    approval: Option<MessageKind>,
) {
    if weak && slot.weak.insert((kind, block)) {
        events.push(ConsensusEvent::WeakCertificate {
            slot: number,
            kind,
            block,
        });
        if let Some(kind) = approval {
            events.push(ConsensusEvent::BroadcastApproval {
                slot: number,
                kind,
                block,
            });
        }
    }
    if strong && slot.strong.insert((kind, block)) {
        events.push(ConsensusEvent::StrongCertificate {
            slot: number,
            kind,
            block,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (Vec<ConsensusKeypair>, Vec<Validator>) {
        let keys: Vec<_> = (0..5)
            .map(|i| ConsensusKeypair::generate_for([1; 32], [i as u8; 32], 2, 10, 1).unwrap())
            .collect();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(i, key)| Validator {
                id: [i as u8; 32],
                stake: 20,
                key: key.public_key(),
            })
            .collect();
        (keys, validators)
    }
    fn sign(
        key: &ConsensusKeypair,
        index: usize,
        kind: MessageKind,
        block: Option<Commitment>,
    ) -> SignedEvidence {
        key.sign(
            &[1; 32],
            [index as u8; 32],
            ConsensusMessage {
                epoch: 2,
                slot: 10,
                kind,
                block,
            },
        )
        .unwrap()
    }
    #[test]
    fn prepared_evidence_parallel_math_matches_serial_events_and_work() {
        use {rayon::prelude::*, std::sync::atomic::Ordering};
        let (keys, validators) = setup();
        let mut serial = ConsensusPool::new([1; 32], 2, validators.clone(), 10, 1).unwrap();
        let mut prepared = ConsensusPool::new([1; 32], 2, validators, 10, 1).unwrap();
        let mut inputs = Vec::new();
        for kind in [
            MessageKind::NotarVote,
            MessageKind::NotarApproval,
            MessageKind::FinalVote,
        ] {
            for (index, key) in keys.iter().enumerate() {
                inputs.push(sign(
                    key,
                    index,
                    kind,
                    kind.requires_block().then_some([9; 48]),
                ));
            }
        }
        for (index, key) in keys.iter().enumerate() {
            for kind in [MessageKind::SkipFallbackVote, MessageKind::SkipApproval] {
                inputs.push(sign(key, index, kind, None));
            }
            for variant in 0..3 {
                inputs.push(sign(
                    key,
                    index,
                    MessageKind::NotarFallbackVote,
                    Some([20 + variant; 48]),
                ));
            }
            for variant in 0..4 {
                inputs.push(sign(
                    key,
                    index,
                    MessageKind::NotarFallbackApproval,
                    Some([30 + variant; 48]),
                ));
            }
        }
        inputs.push(inputs[0].clone());
        let faulty = keys[0].faulty_clone_for_test();
        inputs.push(sign(&faulty, 0, MessageKind::NotarVote, Some([8; 48])));
        let mut invalid = inputs[0].clone();
        *invalid.signature.last_mut().unwrap() ^= 1;
        inputs.push(invalid);
        let mut outside = inputs[0].clone();
        outside.message.slot += 1;
        inputs.push(outside);
        let mut unknown = inputs[0].clone();
        unknown.validator = [0xf0; 32];
        inputs.push(unknown);
        let verifier = prepared.evidence_verifier();
        let outcomes = inputs
            .par_iter()
            .cloned()
            .map(|input| verifier.prepare(input))
            .collect::<Vec<_>>();
        let math = prepared.verification_work.load(Ordering::Relaxed);
        assert!(math > 0);
        for (input, outcome) in inputs.into_iter().zip(outcomes) {
            assert_eq!(prepared.insert_prepared(outcome), serial.insert(input));
            assert_eq!(prepared.evidence_bytes(), serial.evidence_bytes());
            assert_eq!(prepared.finalized(10), serial.finalized(10));
            let wire = |pool: &ConsensusPool| {
                pool.retained_evidence(10)
                    .into_iter()
                    .map(|e| e.encode().unwrap())
                    .collect::<Vec<_>>()
            };
            assert_eq!(wire(&prepared), wire(&serial));
        }
        assert_eq!(
            prepared.verification_work.load(Ordering::Relaxed),
            math,
            "matching successful AND rejected outcomes must not redo Ax math on the owner"
        );
        assert_eq!(serial.verification_work.load(Ordering::Relaxed), math);
        assert_eq!(prepared.equivocations().len(), 1);
        prepared.prune_through(10).unwrap();
        serial.prune_through(10).unwrap();
        let mut invalid = sign(&keys[1], 1, MessageKind::NotarVote, Some([9; 48]));
        *invalid.signature.last_mut().unwrap() ^= 1;
        let outcome = prepared.evidence_verifier().prepare(invalid.clone());
        assert_eq!(prepared.insert_prepared(outcome), serial.insert(invalid));
        assert_eq!(
            prepared.evidence_bytes(),
            0,
            "pruned inputs still authenticate before ignoring"
        );
    }

    #[test]
    fn prepared_evidence_rechecks_cache_modes_material_identity_and_pool_context() {
        use std::sync::atomic::Ordering;
        let (keys, validators) = setup();
        let mut pool = ConsensusPool::new([1; 32], 2, validators.clone(), 10, 1).unwrap();
        let full = sign(&keys[0], 0, MessageKind::NotarVote, Some([9; 48]));
        let compact = full.for_cached_material().unwrap();
        let cached = pool.evidence_verifier().prepare(compact.clone());
        let cold_key = ConsensusPublicKey::from_bytes(keys[0].public_key().as_bytes()).unwrap();
        pool.validators.get_mut(&[0; 32]).unwrap().key = cold_key;
        let before = pool.verification_work.load(Ordering::Relaxed);
        assert!(
            pool.insert_prepared(cached).is_err(),
            "old cached success must not bypass cold verification"
        );
        assert_eq!(pool.verification_work.load(Ordering::Relaxed), before + 1);
        assert_eq!(pool.evidence_bytes(), 0);
        let rejected = pool.evidence_verifier().prepare(compact.clone());
        pool.validators.get_mut(&[0; 32]).unwrap().key = keys[0].public_key();
        let before = pool.verification_work.load(Ordering::Relaxed);
        assert!(
            pool.insert_prepared(rejected).is_ok(),
            "old cold failure cannot reject current cached valid input"
        );
        assert_eq!(pool.verification_work.load(Ordering::Relaxed), before + 1);
        let token = pool.evidence_verifier().prepare(full.clone());
        let material = Arc::new((*keys[0].material()).clone());
        pool.validators
            .get_mut(&[0; 32])
            .unwrap()
            .key
            .cache_material(material)
            .unwrap();
        let before = pool.verification_work.load(Ordering::Relaxed);
        pool.insert_prepared(token).unwrap();
        assert_eq!(
            pool.verification_work.load(Ordering::Relaxed),
            before + 1,
            "equal-root but different cached Arc must recheck the exact current material"
        );
        let token = pool.evidence_verifier().prepare(full.clone());
        pool.authentication_membership[47] ^= 1;
        let before = pool.verification_work.load(Ordering::Relaxed);
        pool.insert_prepared(token).unwrap();
        assert_eq!(
            pool.verification_work.load(Ordering::Relaxed),
            before + 1,
            "same first32 bytes with a changed final16 must invalidate membership binding"
        );
        let old = pool.evidence_verifier();
        let mut other = ConsensusPool::new([2; 32], 3, validators.clone(), 10, 1).unwrap();
        assert_eq!(
            other.insert_prepared(old.prepare(full.clone())),
            Err(ConsensusError::Context)
        );
        let mut other = ConsensusPool::new([1; 32], 2, validators, 10, 1).unwrap();
        let before = other.verification_work.load(Ordering::Relaxed);
        other.insert_prepared(old.prepare(full)).unwrap();
        assert_eq!(
            other.verification_work.load(Ordering::Relaxed),
            before + 1,
            "an independently constructed pool never trusts another instance's proof"
        );
    }

    #[test]
    fn prepared_evidence_keeps_capacity_and_error_before_apply() {
        let (keys, validators) = setup();
        let mut pool = ConsensusPool::new([1; 32], 2, validators.clone(), 10, 1).unwrap();
        let mut serial = ConsensusPool::new([1; 32], 2, validators, 10, 1).unwrap();
        let good = sign(&keys[0], 0, MessageKind::NotarVote, Some([9; 48]));
        let token = pool.evidence_verifier().prepare(good.clone());
        pool.evidence_bytes = MAX_EVIDENCE_BYTES;
        serial.evidence_bytes = MAX_EVIDENCE_BYTES;
        assert_eq!(pool.insert_prepared(token), serial.insert(good.clone()));
        assert_eq!(pool.evidence_bytes(), MAX_EVIDENCE_BYTES);
        assert!(pool.retained_evidence(10).is_empty());
        let mut malformed = good;
        malformed.message.block = None;
        let prepared = pool.evidence_verifier().prepare(malformed.clone());
        assert_eq!(pool.insert_prepared(prepared), serial.insert(malformed));
        assert_eq!(pool.evidence_bytes(), MAX_EVIDENCE_BYTES);
    }

    #[test]
    fn ax_cached_packets_root_binding_reuse_and_exhaustion() {
        let (keys, _) = setup();
        let key = &keys[0];
        let good = sign(key, 0, MessageKind::NotarVote, Some([5; 48]));
        let cached = good.for_cached_material().unwrap();
        assert!(cached.encode().unwrap().len() <= 1120);
        cached.verify(&[1; 32], &key.public_key()).unwrap();
        let mut restored = ConsensusPublicKey::from_bytes(key.public_key().as_bytes()).unwrap();
        assert!(cached.verify(&[1; 32], &restored).is_err());
        restored.cache_material(key.material()).unwrap();
        cached.verify(&[1; 32], &restored).unwrap();
        assert_eq!(
            sign(key, 0, MessageKind::NotarVote, Some([5; 48])).signature,
            good.signature
        );
        assert_eq!(
            key.sign(
                &[1; 32],
                [0; 32],
                ConsensusMessage {
                    epoch: 2,
                    slot: 10,
                    kind: MessageKind::NotarVote,
                    block: Some([6; 48])
                }
            )
            .err(),
            Some(ConsensusError::EvidenceLimit)
        );
        let faulty = key.faulty_clone_for_test();
        let conflicting = sign(&faulty, 0, MessageKind::NotarVote, Some([6; 48]));
        conflicting.verify(&[1; 32], &key.public_key()).unwrap();
        let mut invalid = key.public_key().as_bytes().to_vec();
        invalid[1 + FALCON_PUBLIC_KEY_BYTES + AxEpoch::ENCODED_BYTES] ^= 1;
        assert!(ConsensusPublicKey::from_bytes(&invalid).is_err());
    }
    #[test]
    fn fast_path_uses_real_hash_signatures_and_retains_transferable_evidence() {
        let (keys, validators) = setup();
        let mut pool = ConsensusPool::new([1; 32], 2, validators.clone(), 10, 1).unwrap();
        let block = [9; 48];
        for (i, key) in keys.iter().take(3).enumerate() {
            pool.insert(sign(key, i, MessageKind::NotarVote, Some(block)))
                .unwrap();
        }
        assert_eq!(pool.finalized(10), None);
        let events = pool
            .insert(sign(&keys[3], 3, MessageKind::NotarVote, Some(block)))
            .unwrap();
        assert!(events.contains(&ConsensusEvent::FastFinalized { slot: 10, block }));
        assert_eq!(pool.finalized(10), Some(block));
        let retained = pool.retained_evidence(10);
        assert_eq!(retained.len(), 4);
        let encoded = retained[0].encode().unwrap();
        SignedEvidence::decode(&encoded)
            .unwrap()
            .verify(&[1; 32], &keys[0].public_key())
            .unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            SignedEvidence::decode(&trailing).err(),
            Some(ConsensusError::Encoding)
        );
        assert_eq!(
            SignedEvidence::decode(&encoded[..100]).err(),
            Some(ConsensusError::Encoding)
        );
        let mut restored = ConsensusPool::new([1; 32], 2, validators, 10, 1).unwrap();
        for evidence in retained {
            restored.insert(evidence).unwrap();
        }
        assert_eq!(restored.finalized(10), Some(block));
    }
    #[test]
    fn weak_and_strong_events_follow_approval_thresholds_and_deduplicate_stake() {
        let (keys, validators) = setup();
        let mut pool = ConsensusPool::new([1; 32], 2, validators, 10, 1).unwrap();
        let block = [7; 48];
        let first = sign(&keys[0], 0, MessageKind::NotarApproval, Some(block));
        let events = pool.insert(first.clone()).unwrap();
        assert!(events.contains(&ConsensusEvent::WeakCertificate {
            slot: 10,
            kind: CertificateKind::Notar,
            block: Some(block)
        }));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ConsensusEvent::StrongCertificate { .. }))
        );
        assert!(pool.insert(first).unwrap().is_empty());
        pool.insert(sign(&keys[1], 1, MessageKind::NotarApproval, Some(block)))
            .unwrap();
        // A fallback approval from the same validator does not count twice.
        let events = pool
            .insert(sign(
                &keys[1],
                1,
                MessageKind::NotarFallbackApproval,
                Some(block),
            ))
            .unwrap();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ConsensusEvent::StrongCertificate { .. }))
        );
        let events = pool
            .insert(sign(&keys[2], 2, MessageKind::NotarApproval, Some(block)))
            .unwrap();
        assert!(events.contains(&ConsensusEvent::StrongCertificate {
            slot: 10,
            kind: CertificateKind::Notar,
            block: Some(block)
        }));
        assert!(events.contains(&ConsensusEvent::StrongCertificate {
            slot: 10,
            kind: CertificateKind::NotarFallback,
            block: Some(block)
        }));
        assert_eq!(pool.finalized(10), None);
    }
    #[test]
    fn slow_finalization_and_skip_fallback_preserve_signature_and_stake_checks() {
        let (keys, validators) = setup();
        let mut pool = ConsensusPool::new([1; 32], 2, validators, 10, 1).unwrap();
        let block = [8; 48];
        for (i, key) in keys.iter().take(3).enumerate() {
            pool.insert(sign(key, i, MessageKind::NotarVote, Some(block)))
                .unwrap();
        }
        for (i, key) in keys.iter().take(2).enumerate() {
            pool.insert(sign(key, i, MessageKind::FinalVote, None))
                .unwrap();
        }
        assert_eq!(pool.finalized(10), None);
        let events = pool
            .insert(sign(&keys[2], 2, MessageKind::FinalVote, None))
            .unwrap();
        assert!(events.contains(&ConsensusEvent::SlowFinalized { slot: 10, block }));
        let conflicting = sign(
            &keys[0].faulty_clone_for_test(),
            0,
            MessageKind::SkipVote,
            None,
        );
        assert_eq!(
            pool.insert(conflicting).err(),
            Some(ConsensusError::Equivocation)
        );
        let mut bad = sign(&keys[4], 4, MessageKind::SkipFallbackVote, None);
        *bad.signature.last_mut().unwrap() ^= 1;
        assert_eq!(pool.insert(bad).err(), Some(ConsensusError::Signature));
        let good = sign(&keys[4], 4, MessageKind::SkipFallbackVote, None);
        assert_eq!(
            good.verify(&[2; 32], &keys[4].public_key()),
            Err(ConsensusError::Context)
        );
    }
}
