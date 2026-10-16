//! Fixed experimental Ax profile: target-sum Winternitz and cached epoch keys.
//!
//! The Alpenglow paper fixes the construction and suggested parameters, but not
//! the hash/wire profile. This file defines `agave-ax-research-v1`; it does not
//! claim interoperability with an upstream Ax implementation or a security audit.
use {
    crate::crypto::{Domain, FalconKeypair, FalconPublicKey, FalconSignature, hash_commitment},
    hkdf::Hkdf,
    rand::{RngCore, rngs::OsRng},
    rayon::prelude::*,
    sha2::{Digest, Sha256},
    std::{collections::BTreeSet, sync::Arc},
    zeroize::Zeroizing,
};

pub const AX_MAX_SLOTS: u32 = 18_000;
pub const AX_KEYS_PER_SLOT: usize = 13;
pub const AX_PUBLIC_KEY_BYTES: usize = 24;
pub const AX_WOTS_SIGNATURE_BYTES: usize = 952;
pub const AX_ZERO_SIGNATURE_BYTES: usize = 24;
pub const AX_CHAINS: usize = 39;
pub const AX_WINTERNITZ: u8 = 32;
pub const AX_TARGET_SUM: u16 = 781;
const MAX_GRIND: u32 = 1 << 24;
pub type AxPublicKey = [u8; AX_PUBLIC_KEY_BYTES];
pub type AxRoot = [u8; 48];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxError {
    Bounds,
    Context,
    Encoding,
    Signature,
    Root,
    AlreadyUsed,
    Exhausted,
    Grinding,
    NotCached,
    Authority,
}
impl std::fmt::Display for AxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AxError {}

/// A root authorizes this exact validator, role generation, epoch and slot range.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AxEpoch {
    pub chain: [u8; 32],
    pub validator: [u8; 32],
    pub epoch: u64,
    pub generation: u64,
    pub first_slot: u64,
    pub slots: u32,
}
impl AxEpoch {
    pub const ENCODED_BYTES: usize = 92;
    pub fn validate(&self) -> Result<(), AxError> {
        if self.slots == 0
            || self.slots > AX_MAX_SLOTS
            || self.first_slot.checked_add(u64::from(self.slots)).is_none()
        {
            return Err(AxError::Bounds);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_BYTES);
        out.extend_from_slice(&self.chain);
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.first_slot.to_le_bytes());
        out.extend_from_slice(&self.slots.to_le_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, AxError> {
        if bytes.len() != Self::ENCODED_BYTES {
            return Err(AxError::Encoding);
        }
        let value = Self {
            chain: bytes[..32].try_into().map_err(|_| AxError::Encoding)?,
            validator: bytes[32..64].try_into().map_err(|_| AxError::Encoding)?,
            epoch: u64::from_le_bytes(bytes[64..72].try_into().map_err(|_| AxError::Encoding)?),
            generation: u64::from_le_bytes(
                bytes[72..80].try_into().map_err(|_| AxError::Encoding)?,
            ),
            first_slot: u64::from_le_bytes(
                bytes[80..88].try_into().map_err(|_| AxError::Encoding)?,
            ),
            slots: u32::from_le_bytes(bytes[88..92].try_into().map_err(|_| AxError::Encoding)?),
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn ordinal(&self, slot: u64, role: AxRole, index: u8) -> Result<usize, AxError> {
        self.validate()?;
        let relative = slot.checked_sub(self.first_slot).ok_or(AxError::Context)?;
        if relative >= u64::from(self.slots) {
            return Err(AxError::Exhausted);
        }
        Ok(relative as usize * AX_KEYS_PER_SLOT + role.offset(index)?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AxRole {
    NotarVote = 1,
    NotarFallbackVote = 2,
    SkipVote = 3,
    SkipFallbackVote = 4,
    FinalVote = 5,
    NotarApproval = 6,
    NotarFallbackApproval = 7,
    SkipApproval = 8,
}
impl AxRole {
    pub fn from_byte(byte: u8) -> Result<Self, AxError> {
        match byte {
            1 => Ok(Self::NotarVote),
            2 => Ok(Self::NotarFallbackVote),
            3 => Ok(Self::SkipVote),
            4 => Ok(Self::SkipFallbackVote),
            5 => Ok(Self::FinalVote),
            6 => Ok(Self::NotarApproval),
            7 => Ok(Self::NotarFallbackApproval),
            8 => Ok(Self::SkipApproval),
            _ => Err(AxError::Encoding),
        }
    }
    pub fn capacity(self) -> u8 {
        match self {
            Self::NotarFallbackVote => 3,
            Self::NotarFallbackApproval => 4,
            _ => 1,
        }
    }
    pub fn is_zero(self) -> bool {
        matches!(
            self,
            Self::SkipVote | Self::SkipFallbackVote | Self::FinalVote | Self::SkipApproval
        )
    }
    fn offset(self, index: u8) -> Result<usize, AxError> {
        if index >= self.capacity() {
            return Err(AxError::Bounds);
        }
        Ok(match self {
            Self::NotarVote => 0,
            Self::NotarFallbackVote => 1,
            Self::NotarApproval => 4,
            Self::NotarFallbackApproval => 5,
            Self::SkipVote => 9,
            Self::SkipFallbackVote => 10,
            Self::FinalVote => 11,
            Self::SkipApproval => 12,
        } + usize::from(index))
    }
    fn at_offset(offset: usize) -> (Self, u8) {
        match offset {
            0 => (Self::NotarVote, 0),
            1..=3 => (Self::NotarFallbackVote, (offset - 1) as u8),
            4 => (Self::NotarApproval, 0),
            5..=8 => (Self::NotarFallbackApproval, (offset - 5) as u8),
            9 => (Self::SkipVote, 0),
            10 => (Self::SkipFallbackVote, 0),
            11 => (Self::FinalVote, 0),
            12 => (Self::SkipApproval, 0),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AxSignature(Vec<u8>);
impl AxSignature {
    pub fn from_bytes(role: AxRole, bytes: &[u8]) -> Result<Self, AxError> {
        let size = if role.is_zero() {
            AX_ZERO_SIGNATURE_BYTES
        } else {
            AX_WOTS_SIGNATURE_BYTES
        };
        if bytes.len() != size {
            return Err(AxError::Encoding);
        }
        Ok(Self(bytes.to_vec()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Public values pre-distributed before the epoch. No private values are retained.
#[derive(Clone)]
pub struct AxPublicMaterial {
    pub epoch: AxEpoch,
    keys: Vec<AxPublicKey>,
    slot_trees: Vec<Vec<Vec<AxRoot>>>,
    epoch_tree: Vec<Vec<AxRoot>>,
}
impl AxPublicMaterial {
    pub fn from_keys(epoch: AxEpoch, keys: Vec<AxPublicKey>) -> Result<Self, AxError> {
        epoch.validate()?;
        if keys.len() != epoch.slots as usize * AX_KEYS_PER_SLOT {
            return Err(AxError::Bounds);
        }
        let slot_trees: Vec<_> = (0..epoch.slots as usize)
            .map(|s| {
                let leaves = (0..16)
                    .map(|i| {
                        if i < AX_KEYS_PER_SLOT {
                            leaf(
                                &epoch,
                                s as u64 + epoch.first_slot,
                                i,
                                &keys[s * AX_KEYS_PER_SLOT + i],
                            )
                        } else {
                            hash_commitment(
                                b"agave-ax-slot-padding-v1",
                                &[
                                    &epoch.encode(),
                                    &(s as u32).to_le_bytes(),
                                    &(i as u32).to_le_bytes(),
                                ],
                            )
                        }
                    })
                    .collect();
                tree(leaves, b"agave-ax-slot-node-v1")
            })
            .collect();
        let extent = (epoch.slots as usize).next_power_of_two();
        let roots = (0..extent)
            .map(|s| {
                if s < epoch.slots as usize {
                    slot_trees[s].last().expect("tree")[0]
                } else {
                    hash_commitment(
                        b"agave-ax-epoch-padding-v1",
                        &[&epoch.encode(), &(s as u32).to_le_bytes()],
                    )
                }
            })
            .collect();
        let epoch_tree = tree(roots, b"agave-ax-epoch-node-v1");
        Ok(Self {
            epoch,
            keys,
            slot_trees,
            epoch_tree,
        })
    }
    pub fn root(&self) -> AxRoot {
        self.epoch_tree.last().expect("tree")[0]
    }
    pub fn keys(&self) -> &[AxPublicKey] {
        &self.keys
    }
    pub fn public_key(&self, slot: u64, role: AxRole, index: u8) -> Result<AxPublicKey, AxError> {
        Ok(self.keys[self.epoch.ordinal(slot, role, index)?])
    }
    pub fn proof(&self, slot: u64, role: AxRole, index: u8) -> Result<Vec<AxRoot>, AxError> {
        self.epoch.ordinal(slot, role, index)?;
        let relative = (slot - self.epoch.first_slot) as usize;
        let mut out = path(&self.slot_trees[relative], role.offset(index)?);
        out.extend(path(&self.epoch_tree, relative));
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AxRootBinding {
    pub epoch: AxEpoch,
    pub root: AxRoot,
    pub signature: FalconSignature,
}
impl AxRootBinding {
    pub fn authorize(
        material: &AxPublicMaterial,
        authority: &FalconKeypair,
    ) -> Result<Self, AxError> {
        let root = material.root();
        let signature = authority
            .sign(
                &material.epoch.chain,
                Domain::ConsensusRoot,
                &root_payload(&material.epoch, &root),
            )
            .map_err(|_| AxError::Authority)?;
        Ok(Self {
            epoch: material.epoch.clone(),
            root,
            signature,
        })
    }
    /// `expected` and the authority must come from finalized role configuration.
    pub fn verify(&self, expected: &AxEpoch, authority: &FalconPublicKey) -> Result<(), AxError> {
        expected.validate()?;
        if &self.epoch != expected {
            return Err(AxError::Context);
        }
        authority
            .verify(
                &expected.chain,
                Domain::ConsensusRoot,
                &root_payload(expected, &self.root),
                &self.signature,
            )
            .map_err(|_| AxError::Authority)
    }
}

/// Authenticated cache: compact signatures contain no Merkle authentication path.
pub struct AxVerifier {
    binding: AxRootBinding,
    material: Option<Arc<AxPublicMaterial>>,
}
impl AxVerifier {
    pub fn new(
        binding: AxRootBinding,
        expected: &AxEpoch,
        authority: &FalconPublicKey,
    ) -> Result<Self, AxError> {
        binding.verify(expected, authority)?;
        Ok(Self {
            binding,
            material: None,
        })
    }
    pub fn install(&mut self, material: Arc<AxPublicMaterial>) -> Result<(), AxError> {
        if material.epoch != self.binding.epoch || material.root() != self.binding.root {
            return Err(AxError::Root);
        }
        self.material = Some(material);
        Ok(())
    }
    pub fn verify_cached(
        &self,
        slot: u64,
        role: AxRole,
        index: u8,
        message: &[u8],
        signature: &AxSignature,
    ) -> Result<(), AxError> {
        let material = self.material.as_ref().ok_or(AxError::NotCached)?;
        verify(
            &self.binding.epoch,
            slot,
            role,
            index,
            message,
            &material.public_key(slot, role, index)?,
            signature,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_proof(
        &self,
        slot: u64,
        role: AxRole,
        index: u8,
        message: &[u8],
        key: &AxPublicKey,
        proof: &[AxRoot],
        signature: &AxSignature,
    ) -> Result<(), AxError> {
        verify_inclusion(
            &self.binding.epoch,
            &self.binding.root,
            slot,
            role,
            index,
            key,
            proof,
        )?;
        verify(
            &self.binding.epoch,
            slot,
            role,
            index,
            message,
            key,
            signature,
        )
    }
}

/// In-memory one-use signer for tests and deterministic protocol simulation.
/// Durable releases must use `ax_state::DurableAxSigner`, including its independent
/// monotonic store. This type alone does not protect backup restore or failover.
pub struct AxKeypair {
    seed: Zeroizing<[u8; 32]>,
    material: Arc<AxPublicMaterial>,
    used: BTreeSet<usize>,
}
impl AxKeypair {
    pub fn generate(epoch: AxEpoch) -> Result<Self, AxError> {
        let mut seed = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Self::from_seed(epoch, seed)
    }
    pub(crate) fn from_seed(epoch: AxEpoch, seed: Zeroizing<[u8; 32]>) -> Result<Self, AxError> {
        epoch.validate()?;
        let keys: Vec<_> = (0..epoch.slots as usize * AX_KEYS_PER_SLOT)
            .into_par_iter()
            .map(|ordinal| {
                let (role, index) = AxRole::at_offset(ordinal % AX_KEYS_PER_SLOT);
                let slot = epoch.first_slot + (ordinal / AX_KEYS_PER_SLOT) as u64;
                public_from_seed(&seed, &epoch, slot, role, index)
            })
            .collect();
        Ok(Self {
            seed,
            material: Arc::new(AxPublicMaterial::from_keys(epoch, keys)?),
            used: BTreeSet::new(),
        })
    }
    pub fn material(&self) -> Arc<AxPublicMaterial> {
        Arc::clone(&self.material)
    }
    pub fn sign(
        &mut self,
        slot: u64,
        role: AxRole,
        index: u8,
        message: &[u8],
    ) -> Result<AxSignature, AxError> {
        let ordinal = self.material.epoch.ordinal(slot, role, index)?;
        if !self.used.insert(ordinal) {
            return Err(AxError::AlreadyUsed);
        }
        self.sign_reserved(slot, role, index, message)
    }
    pub(crate) fn sign_reserved(
        &self,
        slot: u64,
        role: AxRole,
        index: u8,
        message: &[u8],
    ) -> Result<AxSignature, AxError> {
        self.material.epoch.ordinal(slot, role, index)?;
        let context = key_context(&self.material.epoch, slot, role, index);
        if role.is_zero() {
            if !message.is_empty() {
                return Err(AxError::Context);
            }
            return Ok(AxSignature(zero_secret(&self.seed, &context).to_vec()));
        }
        if message.len() > crate::crypto::MAX_SIGNED_MESSAGE_BYTES {
            return Err(AxError::Bounds);
        }
        let digest = hash_commitment(b"agave-ax-message-v1", &[message]);
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);
        let first = u128::from_le_bytes(salt);
        let mut selected = None;
        for attempt in 0..MAX_GRIND {
            salt = first.wrapping_add(u128::from(attempt)).to_le_bytes();
            let digits = digits(&context, &digest, &salt);
            if digits.iter().map(|&x| u16::from(x)).sum::<u16>() == AX_TARGET_SUM {
                selected = Some(digits);
                break;
            }
        }
        let digits = selected.ok_or(AxError::Grinding)?;
        let secrets = chain_secrets(&self.seed, &context);
        let mut out = Vec::with_capacity(AX_WOTS_SIGNATURE_BYTES);
        out.extend_from_slice(&salt);
        for (i, &digit) in digits.iter().enumerate() {
            let secret: AxPublicKey = secrets[i * 24..(i + 1) * 24].try_into().expect("secret");
            out.extend_from_slice(&chain(&context, i as u8, 0, digit, secret));
        }
        Ok(AxSignature(out))
    }
    #[cfg(test)]
    pub(crate) fn faulty_clone_for_test(&self) -> Self {
        Self {
            seed: Zeroizing::new(*self.seed),
            material: Arc::clone(&self.material),
            used: BTreeSet::new(),
        }
    }
}

pub fn verify(
    epoch: &AxEpoch,
    slot: u64,
    role: AxRole,
    index: u8,
    message: &[u8],
    public: &AxPublicKey,
    signature: &AxSignature,
) -> Result<(), AxError> {
    epoch.ordinal(slot, role, index)?;
    let context = key_context(epoch, slot, role, index);
    if role.is_zero() {
        if !message.is_empty() || signature.0.len() != 24 {
            return Err(AxError::Context);
        }
        let actual = hash24(b"agave-ax-zero-key-v1", &[&context, &signature.0]);
        return if &actual == public {
            Ok(())
        } else {
            Err(AxError::Signature)
        };
    }
    if signature.0.len() != AX_WOTS_SIGNATURE_BYTES
        || message.len() > crate::crypto::MAX_SIGNED_MESSAGE_BYTES
    {
        return Err(AxError::Encoding);
    }
    let digest = hash_commitment(b"agave-ax-message-v1", &[message]);
    let salt: [u8; 16] = signature.0[..16]
        .try_into()
        .map_err(|_| AxError::Encoding)?;
    let digits = digits(&context, &digest, &salt);
    if digits.iter().map(|&x| u16::from(x)).sum::<u16>() != AX_TARGET_SUM {
        return Err(AxError::Signature);
    }
    let mut endpoints = Vec::with_capacity(AX_CHAINS * 24);
    for (i, &digit) in digits.iter().enumerate() {
        let value = signature.0[16 + i * 24..16 + (i + 1) * 24]
            .try_into()
            .map_err(|_| AxError::Encoding)?;
        endpoints.extend_from_slice(&chain(&context, i as u8, digit, 31 - digit, value));
    }
    if &hash24(b"agave-ax-wots-key-v1", &[&context, &endpoints]) == public {
        Ok(())
    } else {
        Err(AxError::Signature)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_inclusion(
    epoch: &AxEpoch,
    root: &AxRoot,
    slot: u64,
    role: AxRole,
    index: u8,
    key: &AxPublicKey,
    proof: &[AxRoot],
) -> Result<(), AxError> {
    epoch.ordinal(slot, role, index)?;
    let height = (epoch.slots as usize).next_power_of_two().trailing_zeros() as usize;
    if proof.len() != 4 + height {
        return Err(AxError::Encoding);
    }
    let offset = role.offset(index)?;
    let mut value = leaf(epoch, slot, offset, key);
    for (level, sibling) in proof.iter().take(4).enumerate() {
        value = if (offset >> level) & 1 == 0 {
            node(b"agave-ax-slot-node-v1", &value, sibling)
        } else {
            node(b"agave-ax-slot-node-v1", sibling, &value)
        };
    }
    let relative = (slot - epoch.first_slot) as usize;
    for (level, sibling) in proof.iter().skip(4).enumerate() {
        value = if (relative >> level) & 1 == 0 {
            node(b"agave-ax-epoch-node-v1", &value, sibling)
        } else {
            node(b"agave-ax-epoch-node-v1", sibling, &value)
        };
    }
    if &value == root {
        Ok(())
    } else {
        Err(AxError::Root)
    }
}
fn root_payload(epoch: &AxEpoch, root: &AxRoot) -> Vec<u8> {
    let mut out = b"agave-ax-research-root-v1".to_vec();
    out.extend(epoch.encode());
    out.extend_from_slice(root);
    out
}
fn key_context(epoch: &AxEpoch, slot: u64, role: AxRole, index: u8) -> Vec<u8> {
    let mut out = b"agave-ax-research-v1".to_vec();
    out.extend(epoch.encode());
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(&[role as u8, index]);
    out
}
fn hash24(domain: &[u8], parts: &[&[u8]]) -> AxPublicKey {
    let mut h = Sha256::new();
    h.update((domain.len() as u32).to_le_bytes());
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize()[..24].try_into().expect("hash")
}
fn zero_secret(seed: &[u8; 32], context: &[u8]) -> Zeroizing<AxPublicKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(context), seed);
    let mut out = Zeroizing::new([0; 24]);
    hkdf.expand(b"agave-ax-zero-secret-v1", out.as_mut())
        .expect("HKDF bound");
    out
}
fn chain_secrets(seed: &[u8; 32], context: &[u8]) -> Zeroizing<[u8; AX_CHAINS * 24]> {
    let hkdf = Hkdf::<Sha256>::new(Some(context), seed);
    let mut out = Zeroizing::new([0; AX_CHAINS * 24]);
    hkdf.expand(b"agave-ax-chain-secrets-v1", out.as_mut())
        .expect("HKDF bound");
    out
}
fn chain(context: &[u8], index: u8, start: u8, steps: u8, mut value: AxPublicKey) -> AxPublicKey {
    for step in start..start + steps {
        value = hash24(
            b"agave-ax-chain-step-v1",
            &[context, &[index, step], &value],
        );
    }
    value
}
fn public_from_seed(
    seed: &[u8; 32],
    epoch: &AxEpoch,
    slot: u64,
    role: AxRole,
    index: u8,
) -> AxPublicKey {
    let context = key_context(epoch, slot, role, index);
    if role.is_zero() {
        return hash24(
            b"agave-ax-zero-key-v1",
            &[&context, zero_secret(seed, &context).as_ref()],
        );
    }
    let secrets = chain_secrets(seed, &context);
    let mut endpoints = Vec::with_capacity(AX_CHAINS * 24);
    for i in 0..AX_CHAINS {
        endpoints.extend_from_slice(&chain(
            &context,
            i as u8,
            0,
            31,
            secrets[i * 24..(i + 1) * 24].try_into().expect("secret"),
        ));
    }
    hash24(b"agave-ax-wots-key-v1", &[&context, &endpoints])
}
fn digits(context: &[u8], message: &AxRoot, salt: &[u8; 16]) -> [u8; AX_CHAINS] {
    let mut hash = Sha256::new();
    hash.update(b"agave-ax-target-sum-v1");
    hash.update(context);
    hash.update(message);
    hash.update(salt);
    let bytes = hash.finalize();
    std::array::from_fn(|i| {
        let mut digit = 0;
        for bit in 0..5 {
            let position = i * 5 + bit;
            digit = (digit << 1) | ((bytes[position / 8] >> (7 - position % 8)) & 1);
        }
        digit
    })
}
fn leaf(epoch: &AxEpoch, slot: u64, offset: usize, key: &AxPublicKey) -> AxRoot {
    hash_commitment(
        b"agave-ax-key-leaf-v1",
        &[
            &epoch.encode(),
            &slot.to_le_bytes(),
            &(offset as u32).to_le_bytes(),
            key,
        ],
    )
}
fn node(domain: &[u8], left: &AxRoot, right: &AxRoot) -> AxRoot {
    hash_commitment(domain, &[left, right])
}
fn tree(leaves: Vec<AxRoot>, domain: &[u8]) -> Vec<Vec<AxRoot>> {
    let mut levels = vec![leaves];
    while levels.last().expect("level").len() > 1 {
        let parents = levels
            .last()
            .expect("level")
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| node(domain, &pair[0], &pair[1]))
            .collect();
        levels.push(parents);
    }
    levels
}
fn path(tree: &[Vec<AxRoot>], mut index: usize) -> Vec<AxRoot> {
    tree.iter()
        .take(tree.len() - 1)
        .map(|level| {
            let sibling = level[index ^ 1];
            index >>= 1;
            sibling
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_python_known_answer_signature_keys_and_root() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../test-vectors/ax.json")).unwrap();
        fn bytes(value: &serde_json::Value) -> Vec<u8> {
            let hex = value.as_str().unwrap();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }
        let context = AxEpoch::decode(&bytes(&vector["epoch_hex"])).unwrap();
        let seed = Zeroizing::new(bytes(&vector["seed_hex"]).try_into().unwrap());
        let signer = AxKeypair::from_seed(context.clone(), seed).unwrap();
        assert_eq!(
            signer.material().root().as_slice(),
            bytes(&vector["root_hex"])
        );
        for (actual, expected) in signer
            .material()
            .keys()
            .iter()
            .zip(vector["public_keys_hex"].as_array().unwrap())
        {
            assert_eq!(actual.as_slice(), bytes(expected));
        }
        let signature =
            AxSignature::from_bytes(AxRole::NotarVote, &bytes(&vector["signature_hex"])).unwrap();
        verify(
            &context,
            20,
            AxRole::NotarVote,
            0,
            &bytes(&vector["message_hex"]),
            &signer
                .material()
                .public_key(20, AxRole::NotarVote, 0)
                .unwrap(),
            &signature,
        )
        .unwrap();
        assert_eq!(
            vector["verification_chain_steps"].as_u64().unwrap(),
            (AX_CHAINS * 31 - AX_TARGET_SUM as usize) as u64
        );
    }
    fn epoch() -> AxEpoch {
        AxEpoch {
            chain: [1; 32],
            validator: [2; 32],
            epoch: 3,
            generation: 4,
            first_slot: 20,
            slots: 2,
        }
    }
    #[test]
    fn target_sum_roundtrip_context_tamper_and_one_use() {
        let mut signer = AxKeypair::generate(epoch()).unwrap();
        let material = signer.material();
        let sig = signer.sign(20, AxRole::NotarVote, 0, b"block A").unwrap();
        assert_eq!(sig.as_bytes().len(), 952);
        let pk = material.public_key(20, AxRole::NotarVote, 0).unwrap();
        verify(&epoch(), 20, AxRole::NotarVote, 0, b"block A", &pk, &sig).unwrap();
        assert!(verify(&epoch(), 20, AxRole::NotarVote, 0, b"block B", &pk, &sig).is_err());
        let mut modified = sig.clone();
        modified.0[25] ^= 1;
        assert!(
            verify(
                &epoch(),
                20,
                AxRole::NotarVote,
                0,
                b"block A",
                &pk,
                &modified
            )
            .is_err()
        );
        assert_eq!(
            signer.sign(20, AxRole::NotarVote, 0, b"block A"),
            Err(AxError::AlreadyUsed)
        );
        assert!(verify(&epoch(), 21, AxRole::NotarVote, 0, b"block A", &pk, &sig).is_err());
        assert_eq!(
            signer.sign(22, AxRole::NotarVote, 0, b"block A"),
            Err(AxError::Exhausted)
        );
    }
    #[test]
    fn authenticated_distribution_cached_verification_and_spoof_rejection() {
        let mut signer = AxKeypair::generate(epoch()).unwrap();
        let authority = FalconKeypair::generate();
        let material = signer.material();
        let binding = AxRootBinding::authorize(&material, &authority).unwrap();
        let mut verifier =
            AxVerifier::new(binding.clone(), &epoch(), &authority.public_key()).unwrap();
        let sig = signer.sign(20, AxRole::SkipVote, 0, b"").unwrap();
        assert_eq!(sig.as_bytes().len(), 24);
        assert_eq!(
            verifier.verify_cached(20, AxRole::SkipVote, 0, b"", &sig),
            Err(AxError::NotCached)
        );
        verifier
            .verify_proof(
                20,
                AxRole::SkipVote,
                0,
                b"",
                &material.public_key(20, AxRole::SkipVote, 0).unwrap(),
                &material.proof(20, AxRole::SkipVote, 0).unwrap(),
                &sig,
            )
            .unwrap();
        verifier.install(material.clone()).unwrap();
        verifier
            .verify_cached(20, AxRole::SkipVote, 0, b"", &sig)
            .unwrap();
        assert!(
            verifier
                .verify_cached(20, AxRole::FinalVote, 0, b"", &sig)
                .is_err()
        );
        let mut keys = material.keys().to_vec();
        keys[9][0] ^= 1;
        assert_eq!(
            verifier.install(Arc::new(
                AxPublicMaterial::from_keys(epoch(), keys).unwrap()
            )),
            Err(AxError::Root)
        );
        let mut wrong_epoch = epoch();
        wrong_epoch.generation += 1;
        assert!(AxVerifier::new(binding.clone(), &wrong_epoch, &authority.public_key()).is_err());
        assert!(
            AxVerifier::new(binding, &epoch(), &FalconKeypair::generate().public_key()).is_err()
        );
    }
    #[test]
    fn all_roles_have_disjoint_keys_and_exhaustion_is_per_role() {
        let mut signer = AxKeypair::generate(epoch()).unwrap();
        let mut keys = BTreeSet::new();
        for offset in 0..13 {
            let (role, index) = AxRole::at_offset(offset);
            assert!(keys.insert(signer.material.public_key(20, role, index).unwrap()));
        }
        for index in 0..3 {
            signer
                .sign(20, AxRole::NotarFallbackVote, index, b"candidate")
                .unwrap();
        }
        assert_eq!(
            signer.sign(20, AxRole::NotarFallbackVote, 3, b"candidate"),
            Err(AxError::Bounds)
        );
    }
}
