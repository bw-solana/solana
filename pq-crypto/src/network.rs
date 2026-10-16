//! Falcon-authenticated, independently verifiable logical shreds.
//!
//! This is the design document's streaming Turbine batch adaptation, rather than
//! Quantumglow's published Rotor whole-block dissemination protocol.
use {
    crate::crypto::{Domain, FalconKeypair, FalconPublicKey, FalconSignature, hash_commitment},
    rayon::prelude::*,
    reed_solomon_erasure::galois_8::ReedSolomon,
    std::collections::BTreeMap,
};

pub type Commitment = [u8; 48];
pub const MAX_LOGICAL_SHRED: usize = 4096;
pub const MAX_SHARDS: usize = 256;
pub const MAX_SHARD_PAYLOAD: usize = 2600;
pub const MAX_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CANDIDATE_BUFFER_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_BATCHES: usize = 1024;
pub const MAX_AUTHENTICATION_BATCH: usize = 128;
const PROTOCOL_VERSION: u16 = 1;
const METADATA_BYTES: usize = 2 + 8 + 8 + 48 + 48 + 4 + 48 + 2 + 2 + 4 + 8 + 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkError {
    Bounds,
    Encoding,
    Signature,
    MerkleProof,
    Context,
    Equivocation,
    Incomplete,
    Erasure,
    Extent,
}
impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for NetworkError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchContext {
    pub leader_epoch: u64,
    pub slot: u64,
    pub candidate: Commitment,
    pub parent: Commitment,
    pub batch_index: u32,
    pub previous: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchMetadata {
    pub context: BatchContext,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub shard_bytes: u32,
    pub payload_bytes: u64,
    pub merkle_root: Commitment,
}
impl BatchMetadata {
    fn validate(&self) -> Result<(), NetworkError> {
        let total = usize::from(self.data_shards) + usize::from(self.parity_shards);
        if self.data_shards == 0
            || self.parity_shards == 0
            || total > MAX_SHARDS
            || self.shard_bytes == 0
            || self.shard_bytes as usize > MAX_SHARD_PAYLOAD
            || self.payload_bytes == 0
            || self.payload_bytes > u64::from(self.shard_bytes) * u64::from(self.data_shards)
            || self.context.batch_index as usize >= MAX_BATCHES
        {
            return Err(NetworkError::Bounds);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let c = &self.context;
        let mut bytes = Vec::with_capacity(METADATA_BYTES);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&c.leader_epoch.to_le_bytes());
        bytes.extend_from_slice(&c.slot.to_le_bytes());
        bytes.extend_from_slice(&c.candidate);
        bytes.extend_from_slice(&c.parent);
        bytes.extend_from_slice(&c.batch_index.to_le_bytes());
        bytes.extend_from_slice(&c.previous);
        bytes.extend_from_slice(&self.data_shards.to_le_bytes());
        bytes.extend_from_slice(&self.parity_shards.to_le_bytes());
        bytes.extend_from_slice(&self.shard_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.payload_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.merkle_root);
        bytes
    }
    fn encode_into(&self, bytes: &mut Vec<u8>) {
        let c = &self.context;
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&c.leader_epoch.to_le_bytes());
        bytes.extend_from_slice(&c.slot.to_le_bytes());
        bytes.extend_from_slice(&c.candidate);
        bytes.extend_from_slice(&c.parent);
        bytes.extend_from_slice(&c.batch_index.to_le_bytes());
        bytes.extend_from_slice(&c.previous);
        bytes.extend_from_slice(&self.data_shards.to_le_bytes());
        bytes.extend_from_slice(&self.parity_shards.to_le_bytes());
        bytes.extend_from_slice(&self.shard_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.payload_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.merkle_root);
    }
    fn sign_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![1]; // Distinct from the terminal marker in the same signing domain.
        bytes.extend_from_slice(&self.encode());
        bytes
    }
    pub fn commitment(&self) -> Commitment {
        hash_commitment(b"pq-batch-commitment-v1", &[&self.encode()])
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, NetworkError> {
        if r.u16()? != PROTOCOL_VERSION {
            return Err(NetworkError::Encoding);
        }
        let metadata = Self {
            context: BatchContext {
                leader_epoch: r.u64()?,
                slot: r.u64()?,
                candidate: r.array()?,
                parent: r.array()?,
                batch_index: r.u32()?,
                previous: r.array()?,
            },
            data_shards: r.u16()?,
            parity_shards: r.u16()?,
            shard_bytes: r.u32()?,
            payload_bytes: r.u64()?,
            merkle_root: r.array()?,
        };
        metadata.validate()?;
        Ok(metadata)
    }
}

#[derive(Clone)]
pub struct AuthenticatedShred {
    pub metadata: BatchMetadata,
    pub signature: FalconSignature,
    pub index: u16,
    pub is_parity: bool,
    pub payload: Vec<u8>,
    pub proof: Vec<Commitment>,
}
impl AuthenticatedShred {
    /// Bounded, canonical encoding. The leader public key comes from finalized role state.
    pub fn encode(&self) -> Result<Vec<u8>, NetworkError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        #[cfg(test)]
        SHRED_TEMPORARY_ENCODING_WORK.with(|work| {
            let (calls, bytes) = work.get();
            work.set((calls + 1, bytes + out.len()));
        });
        Ok(out)
    }
    /// Append the canonical wire directly to an owned buffer. All fallible
    /// structure/length checks finish before changing the existing prefix.
    /// This is serialization only; signature and Merkle verification are unchanged.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), NetworkError> {
        let len = self.encoded_len()?;
        out.len().checked_add(len).ok_or(NetworkError::Bounds)?;
        out.reserve(len);
        self.metadata.encode_into(out);
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(&self.index.to_le_bytes());
        out.push(u8::from(self.is_parity));
        out.push(self.proof.len() as u8);
        out.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.payload);
        for sibling in &self.proof {
            out.extend_from_slice(sibling);
        }
        #[cfg(test)]
        SHRED_ENCODING_WORK.with(|work| {
            let (calls, bytes) = work.get();
            work.set((calls + 1, bytes + len));
        });
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn encode_legacy_for_test(&self) -> Result<Vec<u8>, NetworkError> {
        self.validate_structure()?;
        let mut out = self.metadata.encode();
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(&self.index.to_le_bytes());
        out.push(u8::from(self.is_parity));
        out.push(self.proof.len() as u8);
        out.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.payload);
        for sibling in &self.proof {
            out.extend_from_slice(sibling);
        }
        if out.len() > MAX_LOGICAL_SHRED {
            return Err(NetworkError::Bounds);
        }
        #[cfg(test)]
        SHRED_ENCODING_WORK.with(|work| {
            let (calls, bytes) = work.get();
            work.set((calls + 1, bytes + out.len()));
        });
        SHRED_TEMPORARY_ENCODING_WORK.with(|work| {
            let (calls, bytes) = work.get();
            work.set((calls + 1, bytes + out.len()));
        });
        Ok(out)
    }
    /// The canonical wire length, with the same structure and size checks as
    /// `encode`, without allocating or copying the encoded witness.
    pub fn encoded_len(&self) -> Result<usize, NetworkError> {
        self.validate_structure()?;
        let len = METADATA_BYTES
            .checked_add(self.signature.as_bytes().len())
            .and_then(|len| len.checked_add(6))
            .and_then(|len| len.checked_add(self.payload.len()))
            .and_then(|len| len.checked_add(self.proof.len().checked_mul(48)?))
            .filter(|len| *len <= MAX_LOGICAL_SHRED)
            .ok_or(NetworkError::Bounds)?;
        Ok(len)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() > MAX_LOGICAL_SHRED {
            return Err(NetworkError::Bounds);
        }
        let mut r = Reader { bytes, offset: 0 };
        let metadata = BatchMetadata::decode(&mut r)?;
        let signature =
            FalconSignature::from_bytes(r.take(666)?).map_err(|_| NetworkError::Encoding)?;
        let index = r.u16()?;
        let is_parity = match r.byte()? {
            0 => false,
            1 => true,
            _ => return Err(NetworkError::Encoding),
        };
        let proof_len = usize::from(r.byte()?);
        let payload_len = usize::from(r.u16()?);
        if proof_len > 8 || payload_len > MAX_SHARD_PAYLOAD {
            return Err(NetworkError::Bounds);
        }
        let payload = r.take(payload_len)?.to_vec();
        let proof = (0..proof_len)
            .map(|_| r.array())
            .collect::<Result<Vec<_>, _>>()?;
        if r.offset != bytes.len() {
            return Err(NetworkError::Encoding);
        }
        let shred = Self {
            metadata,
            signature,
            index,
            is_parity,
            payload,
            proof,
        };
        shred.validate_structure()?;
        Ok(shred)
    }
    fn validate_structure(&self) -> Result<(), NetworkError> {
        self.metadata.validate()?;
        let n = usize::from(self.metadata.data_shards) + usize::from(self.metadata.parity_shards);
        if usize::from(self.index) >= n
            || self.is_parity != (self.index >= self.metadata.data_shards)
            || self.payload.len() != self.metadata.shard_bytes as usize
            || self.proof.len() != n.next_power_of_two().trailing_zeros() as usize
        {
            return Err(NetworkError::Encoding);
        }
        Ok(())
    }
    pub fn verify(&self, chain: &[u8; 32], leader: &FalconPublicKey) -> Result<(), NetworkError> {
        self.validate_structure()?;
        leader
            .verify(
                chain,
                Domain::LeaderBatch,
                &self.metadata.sign_bytes(),
                &self.signature,
            )
            .map_err(|_| NetworkError::Signature)?;
        self.verify_proof()
    }
    fn verify_proof(&self) -> Result<(), NetworkError> {
        self.validate_structure()?;
        let mut node = leaf_hash(self.index, self.is_parity, &self.payload);
        let mut index = usize::from(self.index);
        for sibling in &self.proof {
            node = if index & 1 == 0 {
                parent_hash(&node, sibling)
            } else {
                parent_hash(sibling, &node)
            };
            index >>= 1;
        }
        if node != self.metadata.merkle_root {
            return Err(NetworkError::MerkleProof);
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static SHRED_ENCODING_WORK: std::cell::Cell<(usize, usize)> = const {
        std::cell::Cell::new((0, 0))
    };
    static SHRED_TEMPORARY_ENCODING_WORK: std::cell::Cell<(usize, usize)> = const {
        std::cell::Cell::new((0, 0))
    };
}

#[cfg(test)]
pub(crate) fn take_shred_encoding_work() -> (usize, usize) {
    SHRED_ENCODING_WORK.with(|work| work.replace((0, 0)))
}

#[cfg(test)]
pub(crate) fn take_shred_temporary_encoding_work() -> (usize, usize) {
    SHRED_TEMPORARY_ENCODING_WORK.with(|work| work.replace((0, 0)))
}

/// Pure bounded RS/Merkle work, independent of the ordered batch context.
/// Fields are private: callers cannot mint unchecked coding material before seal.
pub struct PreparedBatch {
    data_shards: u16,
    parity_shards: u16,
    shard_bytes: u32,
    payload_bytes: u64,
    shards: Vec<Vec<u8>>,
    tree: Vec<Vec<Commitment>>,
}
impl PreparedBatch {
    pub fn prepare(
        payload: &[u8],
        data_shards: u16,
        parity_shards: u16,
    ) -> Result<Self, NetworkError> {
        let data = usize::from(data_shards);
        let parity = usize::from(parity_shards);
        if data == 0
            || parity == 0
            || data + parity > MAX_SHARDS
            || payload.is_empty()
            || payload.len() > MAX_SHARD_PAYLOAD.saturating_mul(data)
        {
            return Err(NetworkError::Bounds);
        }
        let size = payload.len().div_ceil(data);
        let mut shards = vec![vec![0u8; size]; data + parity];
        for (i, &byte) in payload.iter().enumerate() {
            shards[i / size][i % size] = byte;
        }
        ReedSolomon::new(data, parity)
            .map_err(|_| NetworkError::Erasure)?
            .encode(&mut shards)
            .map_err(|_| NetworkError::Erasure)?;
        let leaves = shards
            .iter()
            .enumerate()
            .map(|(i, p)| leaf_hash(i as u16, i >= data, p))
            .collect();
        let tree = merkle_tree(leaves);
        Ok(Self {
            data_shards,
            parity_shards,
            shard_bytes: size as u32,
            payload_bytes: payload.len() as u64,
            shards,
            tree,
        })
    }
    /// The commitment depends only on validated metadata, allowing callers to
    /// establish the ordered `previous` chain before independent signatures.
    pub fn metadata(&self, context: BatchContext) -> Result<BatchMetadata, NetworkError> {
        let metadata = BatchMetadata {
            context,
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            shard_bytes: self.shard_bytes,
            payload_bytes: self.payload_bytes,
            merkle_root: self.tree.last().unwrap()[0],
        };
        metadata.validate()?;
        Ok(metadata)
    }
    /// Seal an already ordered context without changing its wire encoding.
    pub fn seal(
        self,
        chain: &[u8; 32],
        leader: &FalconKeypair,
        context: BatchContext,
    ) -> Result<SignedBatch, NetworkError> {
        let metadata = self.metadata(context)?;
        let signature = leader
            .sign(chain, Domain::LeaderBatch, &metadata.sign_bytes())
            .map_err(|_| NetworkError::Signature)?;
        let data = usize::from(self.data_shards);
        let tree = self.tree;
        let shreds = self
            .shards
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                let mut index = i;
                let proof = tree
                    .iter()
                    .take(tree.len() - 1)
                    .map(|level| {
                        let sibling = level[index ^ 1];
                        index >>= 1;
                        sibling
                    })
                    .collect();
                AuthenticatedShred {
                    metadata: metadata.clone(),
                    signature: signature.clone(),
                    index: i as u16,
                    is_parity: i >= data,
                    payload,
                    proof,
                }
            })
            .collect();
        Ok(SignedBatch { metadata, shreds })
    }

    /// Seal immutable material constructed here, checking the signing operation
    /// once before it can be streamed. This capability cannot be reconstructed
    /// from received bytes or a mutable `SignedBatch`.
    pub fn seal_local(
        self,
        chain: &[u8; 32],
        leader: &FalconKeypair,
        context: BatchContext,
    ) -> Result<LocalSignedBatch, NetworkError> {
        let batch = self.seal(chain, leader, context)?;
        let public = leader.public_key();
        let signature = &batch
            .shreds
            .first()
            .ok_or(NetworkError::Incomplete)?
            .signature;
        public
            .verify(
                chain,
                Domain::LeaderBatch,
                &batch.metadata.sign_bytes(),
                signature,
            )
            .map_err(|_| NetworkError::Signature)?;
        for shred in &batch.shreds {
            shred.validate_structure()?;
        }
        Ok(LocalSignedBatch {
            chain: *chain,
            leader: public,
            batch,
        })
    }
}

/// An immutable locally constructed RS/Merkle codeword and checked Falcon
/// signature. Borrowed access permits streaming without permitting mutation of
/// the material subsequently used to authorize its terminal marker.
pub struct LocalSignedBatch {
    chain: [u8; 32],
    leader: FalconPublicKey,
    batch: SignedBatch,
}

impl LocalSignedBatch {
    pub fn metadata(&self) -> &BatchMetadata {
        &self.batch.metadata
    }

    pub fn commitment(&self) -> Commitment {
        self.batch.commitment()
    }

    pub fn shreds(&self) -> &[AuthenticatedShred] {
        &self.batch.shreds
    }

    pub fn data_shreds(&self) -> &[AuthenticatedShred] {
        &self.batch.shreds[..usize::from(self.batch.metadata.data_shards)]
    }
}

pub struct SignedBatch {
    pub metadata: BatchMetadata,
    pub shreds: Vec<AuthenticatedShred>,
}
impl SignedBatch {
    pub fn build(
        chain: &[u8; 32],
        leader: &FalconKeypair,
        context: BatchContext,
        payload: &[u8],
        data_shards: u16,
        parity_shards: u16,
    ) -> Result<Self, NetworkError> {
        PreparedBatch::prepare(payload, data_shards, parity_shards)?.seal(chain, leader, context)
    }
    pub fn commitment(&self) -> Commitment {
        self.metadata.commitment()
    }
}

#[derive(Clone)]
pub struct FinalMarker {
    pub leader_epoch: u64,
    pub slot: u64,
    pub candidate: Commitment,
    pub parent: Commitment,
    pub terminal_batch: u32,
    pub terminal_commitment: Commitment,
    pub total_payload_bytes: u64,
    pub block_commitment: Commitment,
    pub signature: FalconSignature,
}
impl FinalMarker {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.sign_bytes();
        out.extend_from_slice(self.signature.as_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() > MAX_LOGICAL_SHRED {
            return Err(NetworkError::Bounds);
        }
        let mut r = Reader { bytes, offset: 0 };
        if r.byte()? != 2 || r.u16()? != PROTOCOL_VERSION {
            return Err(NetworkError::Encoding);
        }
        let marker = Self {
            leader_epoch: r.u64()?,
            slot: r.u64()?,
            candidate: r.array()?,
            parent: r.array()?,
            terminal_batch: r.u32()?,
            terminal_commitment: r.array()?,
            total_payload_bytes: r.u64()?,
            block_commitment: r.array()?,
            signature: FalconSignature::from_bytes(r.take(666)?)
                .map_err(|_| NetworkError::Encoding)?,
        };
        if r.offset != bytes.len() {
            return Err(NetworkError::Encoding);
        }
        if marker.terminal_batch as usize >= MAX_BATCHES
            || marker.total_payload_bytes == 0
            || marker.total_payload_bytes > MAX_CANDIDATE_BYTES as u64
        {
            return Err(NetworkError::Bounds);
        }
        Ok(marker)
    }
    fn sign_bytes(&self) -> Vec<u8> {
        let mut out = vec![2];
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        out.extend_from_slice(&self.leader_epoch.to_le_bytes());
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.candidate);
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.terminal_batch.to_le_bytes());
        out.extend_from_slice(&self.terminal_commitment);
        out.extend_from_slice(&self.total_payload_bytes.to_le_bytes());
        out.extend_from_slice(&self.block_commitment);
        out
    }
    /// Seal a complete ordered candidate. Signatures are excluded from its identity.
    pub fn build(
        chain: &[u8; 32],
        leader: &FalconKeypair,
        batches: &[SignedBatch],
        payload: &[u8],
    ) -> Result<Self, NetworkError> {
        Ok(Self::build_verified(chain, leader, batches, payload)?.marker)
    }
    pub fn build_verified(
        chain: &[u8; 32],
        leader: &FalconKeypair,
        batches: &[SignedBatch],
        payload: &[u8],
    ) -> Result<VerifiedCandidate, NetworkError> {
        let last = batches.last().ok_or(NetworkError::Incomplete)?;
        let first = &batches[0].metadata.context;
        let mut previous = [0u8; 48];
        let mut bytes = 0u64;
        for (i, batch) in batches.iter().enumerate() {
            let c = &batch.metadata.context;
            if c.leader_epoch != first.leader_epoch
                || c.slot != first.slot
                || c.candidate != first.candidate
                || c.parent != first.parent
                || c.batch_index as usize != i
                || c.previous != previous
            {
                return Err(NetworkError::Context);
            }
            previous = batch.commitment();
            bytes = bytes
                .checked_add(batch.metadata.payload_bytes)
                .ok_or(NetworkError::Bounds)?;
        }
        if bytes != payload.len() as u64 || payload.len() > MAX_CANDIDATE_BYTES {
            return Err(NetworkError::Extent);
        }
        // Reconstruct and authenticate the payload before authorizing its terminal marker.
        let mut assembler = CandidateAssembler::new(
            *chain,
            leader.public_key(),
            first.leader_epoch,
            first.slot,
            first.candidate,
            first.parent,
        );
        for batch in batches {
            let data = usize::from(batch.metadata.data_shards).min(batch.shreds.len());
            for shreds in batch.shreds[..data].chunks(MAX_AUTHENTICATION_BATCH) {
                // Authenticate every unchanged header/signature/inclusion
                // proof in the caller's bounded pool, then admit in the exact
                // original order. Recovery and terminal checks still follow.
                for verified in assembler.authenticate_batch(shreds.to_vec())? {
                    assembler.insert_verified(verified?)?;
                }
            }
        }
        let recovered = assembler.ordered_payload(last.metadata.context.batch_index)?;
        if recovered != payload {
            return Err(NetworkError::Extent);
        }
        let mut marker = Self {
            leader_epoch: first.leader_epoch,
            slot: first.slot,
            candidate: first.candidate,
            parent: first.parent,
            terminal_batch: last.metadata.context.batch_index,
            terminal_commitment: last.commitment(),
            total_payload_bytes: bytes,
            block_commitment: block_hash(first, &last.commitment(), payload),
            signature: last.shreds[0].signature.clone(),
        };
        marker.signature = leader
            .sign(chain, Domain::LeaderBatch, &marker.sign_bytes())
            .map_err(|_| NetworkError::Signature)?;
        assembler.finish_verified_payload(marker, recovered)
    }

    /// Close an ordered stream of immutable, locally constructed batches.
    /// External candidates still use the complete signature, proof and erasure
    /// verification path. Here the private construction capability establishes
    /// that work; exact chain/key/context and byte-for-byte payload checks remain.
    pub fn build_local_verified(
        chain: &[u8; 32],
        leader: &FalconKeypair,
        batches: Vec<LocalSignedBatch>,
        payload: Vec<u8>,
    ) -> Result<VerifiedCandidate, NetworkError> {
        let first = batches
            .first()
            .ok_or(NetworkError::Incomplete)?
            .metadata()
            .context
            .clone();
        if payload.is_empty() || payload.len() > MAX_CANDIDATE_BYTES {
            return Err(NetworkError::Bounds);
        }
        let public = leader.public_key();
        let mut previous = [0; 48];
        let mut offset = 0usize;
        for (index, batch) in batches.iter().enumerate() {
            let metadata = batch.metadata();
            let context = &metadata.context;
            if batch.chain != *chain
                || batch.leader != public
                || context.leader_epoch != first.leader_epoch
                || context.slot != first.slot
                || context.candidate != first.candidate
                || context.parent != first.parent
                || context.batch_index as usize != index
                || context.previous != previous
            {
                return Err(NetworkError::Context);
            }
            let mut remaining =
                usize::try_from(metadata.payload_bytes).map_err(|_| NetworkError::Bounds)?;
            for shred in batch.data_shreds() {
                let length = remaining.min(shred.payload.len());
                let end = offset.checked_add(length).ok_or(NetworkError::Bounds)?;
                if payload.get(offset..end) != Some(&shred.payload[..length]) {
                    return Err(NetworkError::Extent);
                }
                offset = end;
                remaining -= length;
            }
            if remaining != 0 {
                return Err(NetworkError::Incomplete);
            }
            previous = batch.commitment();
        }
        if offset != payload.len() {
            return Err(NetworkError::Extent);
        }
        let last = batches.last().ok_or(NetworkError::Incomplete)?;
        let mut marker = Self {
            leader_epoch: first.leader_epoch,
            slot: first.slot,
            candidate: first.candidate,
            parent: first.parent,
            terminal_batch: last.metadata().context.batch_index,
            terminal_commitment: previous,
            total_payload_bytes: payload.len() as u64,
            block_commitment: block_hash(&first, &previous, &payload),
            signature: last.data_shreds()[0].signature.clone(),
        };
        marker.signature = leader
            .sign(chain, Domain::LeaderBatch, &marker.sign_bytes())
            .map_err(|_| NetworkError::Signature)?;
        public
            .verify(
                chain,
                Domain::LeaderBatch,
                &marker.sign_bytes(),
                &marker.signature,
            )
            .map_err(|_| NetworkError::Signature)?;
        let shreds = batches
            .into_iter()
            .flat_map(|batch| {
                let data = usize::from(batch.batch.metadata.data_shards);
                batch.batch.shreds.into_iter().take(data)
            })
            .collect();
        Ok(VerifiedCandidate {
            chain: *chain,
            leader: public,
            marker,
            shreds,
            payload,
        })
    }
}

struct ReceivedBatch {
    metadata: BatchMetadata,
    signature: FalconSignature,
    shards: Vec<Option<Vec<u8>>>,
}
/// Authentication evidence for one unchanged shred and exact chain/leader key.
/// The original arrival order is applied serially after bounded parallel work.
pub struct VerifiedShred {
    chain: [u8; 32],
    leader: FalconPublicKey,
    shred: AuthenticatedShred,
}
impl VerifiedShred {
    pub fn shred(&self) -> &AuthenticatedShred {
        &self.shred
    }
}
/// A live authenticated candidate. Private fields prevent substituting payload,
/// marker, role key or recovery witnesses after complete network verification.
/// Recovery journals retain the raw witnesses and verify them again on replay.
#[derive(Clone)]
pub struct VerifiedCandidate {
    chain: [u8; 32],
    leader: FalconPublicKey,
    marker: FinalMarker,
    shreds: Vec<AuthenticatedShred>,
    payload: Vec<u8>,
}
impl VerifiedCandidate {
    pub fn marker(&self) -> &FinalMarker {
        &self.marker
    }
    pub fn shreds(&self) -> &[AuthenticatedShred] {
        &self.shreds
    }
    /// Borrow the payload bound to this authenticated candidate. This accessor
    /// does not construct a capability or bypass its chain/leader binding.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn into_parts(
        self,
        chain: &[u8; 32],
        leader: &FalconPublicKey,
    ) -> Result<(FinalMarker, Vec<AuthenticatedShred>, Vec<u8>), NetworkError> {
        if self.chain != *chain || self.leader != *leader {
            return Err(NetworkError::Context);
        }
        Ok((self.marker, self.shreds, self.payload))
    }
}
/// Buffers only independently authenticated material, within a fixed candidate budget.
pub struct CandidateAssembler {
    chain: [u8; 32],
    leader: FalconPublicKey,
    epoch: u64,
    slot: u64,
    candidate: Commitment,
    parent: Commitment,
    batches: BTreeMap<u32, ReceivedBatch>,
    buffered: usize,
    allocated: usize,
    accepted: Vec<AuthenticatedShred>,
}
impl CandidateAssembler {
    pub fn new(
        chain: [u8; 32],
        leader: FalconPublicKey,
        epoch: u64,
        slot: u64,
        candidate: Commitment,
        parent: Commitment,
    ) -> Self {
        Self {
            chain,
            leader,
            epoch,
            slot,
            candidate,
            parent,
            batches: BTreeMap::new(),
            buffered: 0,
            allocated: 0,
            accepted: Vec::new(),
        }
    }
    pub fn insert(&mut self, shred: AuthenticatedShred) -> Result<bool, NetworkError> {
        shred.validate_structure()?;
        let c = &shred.metadata.context;
        if c.leader_epoch != self.epoch
            || c.slot != self.slot
            || c.candidate != self.candidate
            || c.parent != self.parent
        {
            return Err(NetworkError::Context);
        }
        if let Some(batch) = self.batches.get(&c.batch_index) {
            if batch.metadata != shred.metadata {
                // Equivocation evidence must itself authenticate the alternative commitment.
                self.leader
                    .verify(
                        &self.chain,
                        Domain::LeaderBatch,
                        &shred.metadata.sign_bytes(),
                        &shred.signature,
                    )
                    .map_err(|_| NetworkError::Signature)?;
                return Err(NetworkError::Equivocation);
            }
            if batch.signature.as_bytes() != shred.signature.as_bytes() {
                self.leader
                    .verify(
                        &self.chain,
                        Domain::LeaderBatch,
                        &shred.metadata.sign_bytes(),
                        &shred.signature,
                    )
                    .map_err(|_| NetworkError::Signature)?;
            }
        } else {
            self.leader
                .verify(
                    &self.chain,
                    Domain::LeaderBatch,
                    &shred.metadata.sign_bytes(),
                    &shred.signature,
                )
                .map_err(|_| NetworkError::Signature)?;
        }
        // Every shred requires its own inclusion proof, even with cached batch authentication.
        shred.verify_proof()?;
        self.insert_authenticated(shred)
    }
    pub fn authenticate_batch(
        &self,
        shreds: Vec<AuthenticatedShred>,
    ) -> Result<Vec<Result<VerifiedShred, NetworkError>>, NetworkError> {
        if shreds.len() > MAX_AUTHENTICATION_BATCH {
            return Err(NetworkError::Bounds);
        }
        if shreds.len() == 1 {
            let shred = shreds.into_iter().next().unwrap();
            return Ok(vec![(|| {
                shred.validate_structure()?;
                let c = &shred.metadata.context;
                if c.leader_epoch != self.epoch
                    || c.slot != self.slot
                    || c.candidate != self.candidate
                    || c.parent != self.parent
                {
                    return Err(NetworkError::Context);
                }
                if !self.batches.get(&c.batch_index).is_some_and(|batch| {
                    batch.metadata == shred.metadata && batch.signature == shred.signature
                }) {
                    self.leader
                        .verify(
                            &self.chain,
                            Domain::LeaderBatch,
                            &shred.metadata.sign_bytes(),
                            &shred.signature,
                        )
                        .map_err(|_| NetworkError::Signature)?;
                }
                shred.verify_proof()?;
                Ok(VerifiedShred {
                    chain: self.chain,
                    leader: self.leader.clone(),
                    shred,
                })
            })()]);
        }
        let signature_key = |shred: &AuthenticatedShred| {
            let mut key = shred.metadata.encode();
            key.extend_from_slice(shred.signature.as_bytes());
            key
        };
        let unique = shreds
            .iter()
            .map(|shred| (signature_key(shred), shred))
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();
        let signatures = unique
            .into_par_iter()
            .map(|(key, shred)| {
                let cached = self
                    .batches
                    .get(&shred.metadata.context.batch_index)
                    .is_some_and(|batch| {
                        batch.metadata == shred.metadata && batch.signature == shred.signature
                    });
                let result = if cached {
                    Ok(())
                } else {
                    self.leader
                        .verify(
                            &self.chain,
                            Domain::LeaderBatch,
                            &shred.metadata.sign_bytes(),
                            &shred.signature,
                        )
                        .map_err(|_| NetworkError::Signature)
                };
                (key, result)
            })
            .collect::<BTreeMap<_, _>>();
        Ok(shreds
            .into_par_iter()
            .map(|shred| {
                shred.validate_structure()?;
                let c = &shred.metadata.context;
                if c.leader_epoch != self.epoch
                    || c.slot != self.slot
                    || c.candidate != self.candidate
                    || c.parent != self.parent
                {
                    return Err(NetworkError::Context);
                }
                signatures[&signature_key(&shred)].clone()?;
                shred.verify_proof()?;
                Ok(VerifiedShred {
                    chain: self.chain,
                    leader: self.leader.clone(),
                    shred,
                })
            })
            .collect())
    }
    pub fn insert_verified(&mut self, verified: VerifiedShred) -> Result<bool, NetworkError> {
        let c = &verified.shred.metadata.context;
        if verified.chain != self.chain
            || verified.leader != self.leader
            || c.leader_epoch != self.epoch
            || c.slot != self.slot
            || c.candidate != self.candidate
            || c.parent != self.parent
        {
            return Err(NetworkError::Context);
        }
        self.insert_authenticated(verified.shred)
    }
    fn insert_authenticated(&mut self, shred: AuthenticatedShred) -> Result<bool, NetworkError> {
        let c = &shred.metadata.context;
        if self
            .batches
            .get(&c.batch_index)
            .is_some_and(|batch| batch.metadata != shred.metadata)
        {
            return Err(NetworkError::Equivocation);
        }
        if let Some(existing) = self
            .batches
            .get(&c.batch_index)
            .and_then(|b| b.shards[usize::from(shred.index)].as_ref())
        {
            if existing != &shred.payload {
                return Err(NetworkError::Equivocation);
            }
            return Ok(false);
        }
        let allocation = 2 * shred.payload.len()
            + std::mem::size_of::<AuthenticatedShred>()
            + shred.proof.len() * std::mem::size_of::<Commitment>()
            + if self.batches.contains_key(&c.batch_index) {
                0
            } else {
                // Include the empty shard slots and batch/map storage, not just payload bytes.
                std::mem::size_of::<ReceivedBatch>()
                    + 128
                    + (usize::from(shred.metadata.data_shards)
                        + usize::from(shred.metadata.parity_shards))
                        * std::mem::size_of::<Option<Vec<u8>>>()
            };
        if self.buffered.saturating_add(shred.payload.len()) > MAX_CANDIDATE_BYTES
            || self.allocated.saturating_add(allocation) > MAX_CANDIDATE_BUFFER_BYTES
        {
            return Err(NetworkError::Bounds);
        }
        let batch = self
            .batches
            .entry(c.batch_index)
            .or_insert_with(|| ReceivedBatch {
                metadata: shred.metadata.clone(),
                signature: shred.signature.clone(),
                shards: vec![
                    None;
                    usize::from(shred.metadata.data_shards)
                        + usize::from(shred.metadata.parity_shards)
                ],
            });
        self.buffered += shred.payload.len();
        self.allocated += allocation;
        self.accepted.push(shred.clone());
        batch.shards[usize::from(shred.index)] = Some(shred.payload);
        Ok(true)
    }
    pub fn buffered_bytes(&self) -> usize {
        self.allocated
    }
    pub fn finish(&self, marker: &FinalMarker) -> Result<Vec<u8>, NetworkError> {
        self.verify_terminal_header(marker)?;
        let payload = self.ordered_payload(marker.terminal_batch)?;
        self.verify_terminal_extent(marker, &payload)?;
        Ok(payload)
    }
    fn verify_terminal_header(&self, marker: &FinalMarker) -> Result<(), NetworkError> {
        if marker.leader_epoch != self.epoch
            || marker.slot != self.slot
            || marker.candidate != self.candidate
            || marker.parent != self.parent
            || marker.terminal_batch as usize >= MAX_BATCHES
        {
            return Err(NetworkError::Context);
        }
        self.leader
            .verify(
                &self.chain,
                Domain::LeaderBatch,
                &marker.sign_bytes(),
                &marker.signature,
            )
            .map_err(|_| NetworkError::Signature)?;
        if self
            .batches
            .keys()
            .any(|&index| index > marker.terminal_batch)
        {
            return Err(NetworkError::Extent);
        }
        Ok(())
    }
    fn verify_terminal_extent(
        &self,
        marker: &FinalMarker,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let last = self
            .batches
            .get(&marker.terminal_batch)
            .ok_or(NetworkError::Incomplete)?;
        let first = &self
            .batches
            .get(&0)
            .ok_or(NetworkError::Incomplete)?
            .metadata
            .context;
        if last.metadata.commitment() != marker.terminal_commitment
            || payload.len() as u64 != marker.total_payload_bytes
            || block_hash(first, &marker.terminal_commitment, payload) != marker.block_commitment
        {
            return Err(NetworkError::Extent);
        }
        Ok(())
    }
    pub fn finish_verified(self, marker: FinalMarker) -> Result<VerifiedCandidate, NetworkError> {
        let payload = self.finish(&marker)?;
        self.into_verified(marker, payload)
    }

    /// Cheap scheduling probe for a terminal marker that arrived before bulk
    /// data. This never authenticates a candidate: complete context, signature,
    /// codeword, extent and commitment checks still run in `finish_verified`.
    pub fn is_reconstructable(&self, marker: &FinalMarker) -> bool {
        (marker.terminal_batch as usize) < MAX_BATCHES
            && (0..=marker.terminal_batch).all(|index| {
                self.batches.get(&index).is_some_and(|batch| {
                    batch.shards.iter().filter(|shard| shard.is_some()).count()
                        >= usize::from(batch.metadata.data_shards)
                })
            })
    }
    /// Retain the partially authenticated assembler when a terminal marker
    /// arrives before its data. Successful completion runs reconstruction and
    /// authentication once before moving the exact witnesses into a capability.
    pub fn try_finish_verified(
        self,
        marker: FinalMarker,
    ) -> Result<VerifiedCandidate, (NetworkError, Box<Self>)> {
        match self.finish(&marker) {
            Ok(payload) => Ok(VerifiedCandidate {
                chain: self.chain,
                leader: self.leader,
                marker,
                shreds: self.accepted,
                payload,
            }),
            Err(error) => Err((error, Box::new(self))),
        }
    }
    // Private: only build_verified calls this after ordered_payload has checked
    // every codeword and inclusion root against the proposed bytes.
    fn finish_verified_payload(
        self,
        marker: FinalMarker,
        payload: Vec<u8>,
    ) -> Result<VerifiedCandidate, NetworkError> {
        self.verify_terminal_header(&marker)?;
        self.verify_terminal_extent(&marker, &payload)?;
        self.into_verified(marker, payload)
    }
    fn into_verified(
        self,
        marker: FinalMarker,
        payload: Vec<u8>,
    ) -> Result<VerifiedCandidate, NetworkError> {
        Ok(VerifiedCandidate {
            chain: self.chain,
            leader: self.leader,
            marker,
            shreds: self.accepted,
            payload,
        })
    }
    fn ordered_payload(&self, terminal: u32) -> Result<Vec<u8>, NetworkError> {
        let mut previous = [0u8; 48];
        let mut bytes = 0usize;
        let mut batches = Vec::new();
        // Authenticate ordering and bound the complete allocation before workers
        // recover batches independently. No context or terminal checks are skipped.
        for index in 0..=terminal {
            let batch = self.batches.get(&index).ok_or(NetworkError::Incomplete)?;
            if batch.metadata.context.previous != previous {
                return Err(NetworkError::Context);
            }
            previous = batch.metadata.commitment();
            if batch.shards.iter().filter(|shard| shard.is_some()).count()
                < usize::from(batch.metadata.data_shards)
            {
                return Err(NetworkError::Incomplete);
            }
            bytes = bytes
                .checked_add(batch.metadata.payload_bytes as usize)
                .ok_or(NetworkError::Bounds)?;
            if bytes > MAX_CANDIDATE_BYTES {
                return Err(NetworkError::Bounds);
            }
            batches.push(batch);
        }
        let recovered = batches
            .par_iter()
            .map(|batch| recover_batch(batch))
            .collect::<Result<Vec<_>, _>>()?;
        let mut payload = Vec::with_capacity(bytes);
        for batch in recovered {
            payload.extend_from_slice(&batch);
        }
        Ok(payload)
    }
}
fn recover_batch(batch: &ReceivedBatch) -> Result<Vec<u8>, NetworkError> {
    let data = usize::from(batch.metadata.data_shards);
    let parity = usize::from(batch.metadata.parity_shards);
    let mut shards = batch.shards.clone();
    let erasure = ReedSolomon::new(data, parity).map_err(|_| NetworkError::Erasure)?;
    erasure
        .reconstruct(&mut shards)
        .map_err(|_| NetworkError::Erasure)?;
    let reconstructed = shards
        .iter()
        .map(|shard| shard.as_ref().unwrap().as_slice())
        .collect::<Vec<_>>();
    // A complete received set still requires coding verification; reconstruct
    // alone is a no-op in that case. Reject inconsistent leader-signed parity.
    if !erasure
        .verify(&reconstructed)
        .map_err(|_| NetworkError::Erasure)?
    {
        return Err(NetworkError::Erasure);
    }
    let leaves = shards
        .iter()
        .enumerate()
        .map(|(index, payload)| leaf_hash(index as u16, index >= data, payload.as_ref().unwrap()))
        .collect();
    if merkle_tree(leaves).last().unwrap()[0] != batch.metadata.merkle_root {
        return Err(NetworkError::Erasure);
    }
    let mut payload = Vec::with_capacity(data * batch.metadata.shard_bytes as usize);
    for shard in shards.iter().take(data) {
        payload.extend_from_slice(shard.as_ref().unwrap());
    }
    if payload[batch.metadata.payload_bytes as usize..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(NetworkError::Extent);
    }
    payload.truncate(batch.metadata.payload_bytes as usize);
    Ok(payload)
}

/// Predict the existing final block identity from pure coding metadata.
/// This grants no authentication capability: sealing and external verification
/// still require every original signature, payload and erasure check.
pub fn prepared_block_commitment(
    mut context: BatchContext,
    batches: &[PreparedBatch],
    payload: &[u8],
) -> Result<Commitment, NetworkError> {
    if batches.is_empty() {
        return Err(NetworkError::Incomplete);
    }
    if payload.is_empty()
        || payload.len() > MAX_CANDIDATE_BYTES
        || context.batch_index != 0
        || context.previous != [0; 48]
    {
        return Err(NetworkError::Bounds);
    }
    let first = context.clone();
    let mut extent = 0u64;
    for (index, batch) in batches.iter().enumerate() {
        context.batch_index = u32::try_from(index).map_err(|_| NetworkError::Bounds)?;
        let metadata = batch.metadata(context.clone())?;
        extent = extent
            .checked_add(metadata.payload_bytes)
            .ok_or(NetworkError::Bounds)?;
        context.previous = metadata.commitment();
    }
    if extent != payload.len() as u64 {
        return Err(NetworkError::Extent);
    }
    Ok(block_hash(&first, &context.previous, payload))
}

fn block_hash(c: &BatchContext, terminal: &Commitment, payload: &[u8]) -> Commitment {
    hash_commitment(
        b"pq-block-v1",
        &[
            &c.leader_epoch.to_le_bytes(),
            &c.slot.to_le_bytes(),
            &c.candidate,
            &c.parent,
            terminal,
            payload,
        ],
    )
}
fn leaf_hash(index: u16, parity: bool, payload: &[u8]) -> Commitment {
    hash_commitment(
        b"pq-shred-leaf-v1",
        &[
            &index.to_le_bytes(),
            &[u8::from(parity)],
            &(payload.len() as u32).to_le_bytes(),
            payload,
        ],
    )
}
fn parent_hash(left: &Commitment, right: &Commitment) -> Commitment {
    hash_commitment(b"pq-shred-node-v1", &[left, right])
}
fn merkle_tree(mut leaves: Vec<Commitment>) -> Vec<Vec<Commitment>> {
    leaves.resize(
        leaves.len().next_power_of_two(),
        hash_commitment(b"pq-shred-padding-v1", &[]),
    );
    let mut tree = vec![leaves];
    while tree.last().unwrap().len() > 1 {
        let parents = tree
            .last()
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| parent_hash(&pair[0], &pair[1]))
            .collect();
        tree.push(parents);
    }
    tree
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], NetworkError> {
        let end = self.offset.checked_add(n).ok_or(NetworkError::Bounds)?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or(NetworkError::Encoding)?;
        self.offset = end;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], NetworkError> {
        self.take(N)?.try_into().map_err(|_| NetworkError::Encoding)
    }
    fn byte(&mut self) -> Result<u8, NetworkError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, NetworkError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, NetworkError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, NetworkError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_shred_append_matches_legacy_data_parity_and_preserves_invalid_prefix() {
        let chain = [0xe6; 32];
        let key = FalconKeypair::generate();
        for (data, parity, bytes) in [
            (1, 1, 1),
            (4, 4, 8192),
            (64, 64, 128 * 1024),
            (128, 128, 128 * MAX_SHARD_PAYLOAD),
        ] {
            let batch = SignedBatch::build(
                &chain,
                &key,
                context(0, [0; 48]),
                &vec![0xe7; bytes],
                data,
                parity,
            )
            .unwrap();
            for shred in &batch.shreds {
                shred.verify(&chain, &key.public_key()).unwrap();
                take_shred_encoding_work();
                take_shred_temporary_encoding_work();
                let legacy = shred.encode_legacy_for_test().unwrap();
                assert_eq!(take_shred_encoding_work(), (1, legacy.len()));
                assert_eq!(take_shred_temporary_encoding_work(), (1, legacy.len()));
                let prefix = [0xa1, 0xa2, 0xa3];
                let mut direct = prefix.to_vec();
                shred.encode_into(&mut direct).unwrap();
                assert_eq!(&direct[..prefix.len()], &prefix);
                assert_eq!(&direct[prefix.len()..], legacy);
                assert_eq!(take_shred_encoding_work(), (1, legacy.len()));
                assert_eq!(take_shred_temporary_encoding_work(), (0, 0));
                assert_eq!(shred.encode().unwrap(), legacy);
                assert_eq!(shred.encoded_len().unwrap(), legacy.len());
                assert!(legacy.len() <= MAX_LOGICAL_SHRED);
                assert_eq!(
                    AuthenticatedShred::decode(&legacy)
                        .unwrap()
                        .encode()
                        .unwrap(),
                    legacy
                );
                let mut trailing = legacy;
                trailing.push(0);
                assert_eq!(
                    AuthenticatedShred::decode(&trailing).err(),
                    Some(NetworkError::Encoding)
                );
            }
            for field in 0..12 {
                let mut invalid = batch.shreds[0].clone();
                match field {
                    0 => invalid.metadata.data_shards = 0,
                    1 => invalid.metadata.parity_shards = 0,
                    2 => invalid.metadata.shard_bytes = 0,
                    3 => invalid.metadata.shard_bytes = (MAX_SHARD_PAYLOAD + 1) as u32,
                    4 => invalid.metadata.payload_bytes = 0,
                    5 => invalid.metadata.payload_bytes = u64::MAX,
                    6 => invalid.metadata.context.batch_index = MAX_BATCHES as u32,
                    7 => invalid.index = data + parity,
                    8 => invalid.is_parity = !invalid.is_parity,
                    9 => {
                        invalid.payload.pop();
                    }
                    10 => {
                        invalid.proof.pop();
                    }
                    _ => {
                        // Bounds must keep precedence over the subsequent encoding error.
                        invalid.metadata.data_shards = 0;
                        invalid.index = u16::MAX;
                    }
                }
                let error = invalid.encode_legacy_for_test().unwrap_err();
                let mut direct = vec![0xa4; 17];
                let prefix = direct.clone();
                assert_eq!(invalid.encode_into(&mut direct), Err(error.clone()));
                assert_eq!(invalid.encode().unwrap_err(), error);
                assert_eq!(direct, prefix);
            }
        }
    }

    #[test]
    fn validated_shred_length_matches_legacy_encoding_and_all_structure_errors() {
        let chain = [0xe1; 32];
        let key = FalconKeypair::generate();
        for (data, parity, bytes) in [
            (1, 1, 1),
            (4, 4, 8192),
            (64, 64, 128 * 1024),
            (128, 128, 128 * MAX_SHARD_PAYLOAD),
        ] {
            let batch = SignedBatch::build(
                &chain,
                &key,
                context(0, [0; 48]),
                &vec![0xe2; bytes],
                data,
                parity,
            )
            .unwrap();
            for shred in &batch.shreds {
                let wire = shred.encode().unwrap();
                assert_eq!(shred.encoded_len(), Ok(wire.len()));
                assert!(wire.len() <= MAX_LOGICAL_SHRED);
                assert_eq!(
                    AuthenticatedShred::decode(&wire).unwrap().encode().unwrap(),
                    wire
                );
            }
            let original = &batch.shreds[0];
            for field in 0..10 {
                let mut invalid = original.clone();
                match field {
                    0 => invalid.metadata.data_shards = 0,
                    1 => invalid.metadata.parity_shards = 0,
                    2 => invalid.metadata.shard_bytes = (MAX_SHARD_PAYLOAD + 1) as u32,
                    3 => invalid.metadata.payload_bytes = 0,
                    4 => invalid.metadata.context.batch_index = MAX_BATCHES as u32,
                    5 => invalid.index = data + parity,
                    6 => invalid.is_parity = !invalid.is_parity,
                    7 => {
                        invalid.payload.pop();
                    }
                    8 => {
                        invalid.proof.pop();
                    }
                    _ => invalid.metadata.payload_bytes = u64::MAX,
                }
                assert_eq!(
                    invalid.encoded_len(),
                    invalid.encode_legacy_for_test().map(|wire| wire.len())
                );
                assert!(invalid.encoded_len().is_err());
            }
            // Neither size check is a substitute for signature/Merkle checks.
            let mut damaged = original.clone();
            damaged.payload[0] ^= 1;
            assert_eq!(
                damaged.encoded_len(),
                damaged.encode().map(|wire| wire.len())
            );
            assert_eq!(
                damaged.verify(&chain, &key.public_key()),
                Err(NetworkError::MerkleProof)
            );
        }
    }

    #[test]
    fn cached_batch_math_still_checks_every_shred_and_signed_context() {
        let chain = [0x79; 32];
        let key = FalconKeypair::generate();
        let public = key.public_key();
        let payload = (0..128 * 1024).map(|i| i as u8).collect::<Vec<_>>();
        let batch =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload, 64, 64).unwrap();
        let before = crate::crypto::falcon_verification_cache_stats();
        for shred in &batch.shreds {
            shred.verify(&chain, &public).unwrap();
        }
        let after = crate::crypto::falcon_verification_cache_stats();
        assert!(after.hits >= before.hits + batch.shreds.len() as u64 - 1);
        assert!(after.misses > before.misses);
        assert!(after.entries <= after.maximum_entries);
        let original = &batch.shreds[0];
        let mut changed = original.clone();
        changed.payload[0] ^= 1;
        assert_eq!(
            changed.verify(&chain, &public),
            Err(NetworkError::MerkleProof)
        );
        changed = original.clone();
        changed.proof[0][47] ^= 1;
        assert_eq!(
            changed.verify(&chain, &public),
            Err(NetworkError::MerkleProof)
        );
        changed = original.clone();
        changed.index = 1;
        assert_eq!(
            changed.verify(&chain, &public),
            Err(NetworkError::MerkleProof)
        );
        changed = original.clone();
        changed.is_parity = true;
        assert_eq!(changed.verify(&chain, &public), Err(NetworkError::Encoding));
        changed = original.clone();
        changed.payload.pop();
        assert_eq!(changed.verify(&chain, &public), Err(NetworkError::Encoding));
        for field in 0..8 {
            changed = original.clone();
            match field {
                0 => changed.metadata.context.leader_epoch += 1,
                1 => changed.metadata.context.slot += 1,
                2 => changed.metadata.context.candidate[47] ^= 1,
                3 => changed.metadata.context.parent[47] ^= 1,
                4 => changed.metadata.context.batch_index += 1,
                5 => changed.metadata.context.previous[47] ^= 1,
                6 => changed.metadata.merkle_root[47] ^= 1,
                _ => changed.metadata.payload_bytes -= 1,
            }
            assert_eq!(
                changed.verify(&chain, &public),
                Err(NetworkError::Signature)
            );
        }
        assert_eq!(
            original.verify(&[0x7a; 32], &public),
            Err(NetworkError::Signature)
        );
        assert_eq!(
            original.verify(&chain, &FalconKeypair::generate().public_key()),
            Err(NetworkError::Signature)
        );
        changed = original.clone();
        let mut signature = changed.signature.as_bytes().to_vec();
        signature[17] ^= 1;
        changed.signature = crate::crypto::FalconSignature::from_bytes(&signature).unwrap();
        assert_eq!(
            changed.verify(&chain, &public),
            Err(NetworkError::Signature)
        );
        for shred in &batch.shreds {
            shred.verify(&chain, &public).unwrap();
        }
    }

    fn local_test_batches(
        chain: &[u8; 32],
        key: &FalconKeypair,
        payload: &[u8],
    ) -> Vec<LocalSignedBatch> {
        let mut previous = [0; 48];
        payload
            .chunks(128 * 1024)
            .enumerate()
            .map(|(index, bytes)| {
                let data = bytes.len().div_ceil(2048) as u16;
                let batch = PreparedBatch::prepare(bytes, data, data)
                    .unwrap()
                    .seal_local(chain, key, context(index as u32, previous))
                    .unwrap();
                previous = batch.commitment();
                batch
            })
            .collect()
    }

    #[test]
    fn local_streamed_batches_match_independent_complete_receiver() {
        let chain = [0x71; 32];
        let key = FalconKeypair::generate();
        for length in [4001, 8 * 1024 * 1024] {
            let payload = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let batches = local_test_batches(&chain, &key, &payload);
            let first = &batches[0].metadata().context;
            let mut receiver = CandidateAssembler::new(
                chain,
                key.public_key(),
                first.leader_epoch,
                first.slot,
                first.candidate,
                first.parent,
            );
            for batch in &batches {
                for shred in batch.data_shreds() {
                    // Actual raw network verification remains mandatory at the
                    // peer and is independent of the local construction token.
                    receiver
                        .insert(AuthenticatedShred::decode(&shred.encode().unwrap()).unwrap())
                        .unwrap();
                }
            }
            let candidate =
                FinalMarker::build_local_verified(&chain, &key, batches, payload.clone()).unwrap();
            let remote = receiver
                .finish_verified(candidate.marker().clone())
                .unwrap();
            assert_eq!(remote.payload(), payload);
            assert_eq!(remote.marker().encode(), candidate.marker().encode());
            assert_eq!(remote.shreds().len(), candidate.shreds().len());
            for (received, local) in remote.shreds().iter().zip(candidate.shreds()) {
                assert_eq!(received.encode().unwrap(), local.encode().unwrap());
            }
        }
    }

    #[test]
    fn local_stream_closure_rejects_wrong_payload_extent_and_content() {
        let chain = [0x72; 32];
        let key = FalconKeypair::generate();
        for supplied in [b"wrong".to_vec(), b"good!".to_vec(), b"goo".to_vec()] {
            assert_eq!(
                FinalMarker::build_local_verified(
                    &chain,
                    &key,
                    local_test_batches(&chain, &key, b"good"),
                    supplied
                )
                .err(),
                Some(NetworkError::Extent)
            );
        }
        assert_eq!(
            FinalMarker::build_local_verified(&chain, &key, Vec::new(), b"good".to_vec()).err(),
            Some(NetworkError::Incomplete)
        );
    }

    #[test]
    fn early_terminal_readiness_probe_never_authorizes_wrong_extent_or_context() {
        let chain = [0x78; 32];
        let key = FalconKeypair::generate();
        let batch =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), b"early terminal", 4, 4).unwrap();
        let marker = FinalMarker::build(
            &chain,
            &key,
            std::slice::from_ref(&batch),
            b"early terminal",
        )
        .unwrap();
        let mut receiver = CandidateAssembler::new(
            chain,
            key.public_key(),
            marker.leader_epoch,
            marker.slot,
            marker.candidate,
            marker.parent,
        );
        assert!(!receiver.is_reconstructable(&marker));
        for shred in &batch.shreds[..3] {
            receiver.insert(shred.clone()).unwrap();
            assert!(!receiver.is_reconstructable(&marker));
        }
        receiver.insert(batch.shreds[3].clone()).unwrap();
        assert!(receiver.is_reconstructable(&marker));
        let mut oversized = marker.clone();
        oversized.terminal_batch = MAX_BATCHES as u32;
        assert!(!receiver.is_reconstructable(&oversized));
        let mut corrupted = marker.clone();
        corrupted.total_payload_bytes += 1;
        assert!(receiver.is_reconstructable(&corrupted));
        assert!(receiver.finish_verified(corrupted).is_err());
        let mut receiver = CandidateAssembler::new(
            chain,
            key.public_key(),
            marker.leader_epoch,
            marker.slot,
            marker.candidate,
            marker.parent,
        );
        for shred in &batch.shreds[..4] {
            receiver.insert(shred.clone()).unwrap();
        }
        assert_eq!(
            receiver.finish_verified(marker).unwrap().payload(),
            b"early terminal"
        );
    }

    #[test]
    fn local_stream_closure_rejects_other_chain_key_and_ordered_context() {
        let chain = [0x73; 32];
        let key = FalconKeypair::generate();
        let other_key = FalconKeypair::generate();
        assert_eq!(
            FinalMarker::build_local_verified(
                &[0x74; 32],
                &key,
                local_test_batches(&chain, &key, b"good"),
                b"good".to_vec()
            )
            .err(),
            Some(NetworkError::Context)
        );
        assert_eq!(
            FinalMarker::build_local_verified(
                &chain,
                &other_key,
                local_test_batches(&chain, &key, b"good"),
                b"good".to_vec()
            )
            .err(),
            Some(NetworkError::Context)
        );
        for field in 0..6 {
            let first = PreparedBatch::prepare(b"a", 1, 1)
                .unwrap()
                .seal_local(&chain, &key, context(0, [0; 48]))
                .unwrap();
            let mut next = context(1, first.commitment());
            match field {
                0 => next.leader_epoch += 1,
                1 => next.slot += 1,
                2 => next.candidate[47] ^= 1,
                3 => next.parent[47] ^= 1,
                4 => next.batch_index += 1,
                _ => next.previous[47] ^= 1,
            }
            let second = PreparedBatch::prepare(b"b", 1, 1)
                .unwrap()
                .seal_local(&chain, &key, next)
                .unwrap();
            assert_eq!(
                FinalMarker::build_local_verified(
                    &chain,
                    &key,
                    vec![first, second],
                    b"ab".to_vec()
                )
                .err(),
                Some(NetworkError::Context)
            );
        }
    }

    #[test]
    fn mutated_stream_copy_cannot_change_local_construction_or_pass_receiver() {
        let chain = [0x75; 32];
        let key = FalconKeypair::generate();
        let batches = local_test_batches(&chain, &key, b"bound bytes");
        let original = &batches[0].data_shreds()[0];
        let mut altered = original.clone();
        altered.payload[0] ^= 1;
        let c = &original.metadata.context;
        let mut receiver = CandidateAssembler::new(
            chain,
            key.public_key(),
            c.leader_epoch,
            c.slot,
            c.candidate,
            c.parent,
        );
        assert_eq!(
            receiver.insert(altered).err(),
            Some(NetworkError::MerkleProof)
        );
        receiver.insert(original.clone()).unwrap();
        let local =
            FinalMarker::build_local_verified(&chain, &key, batches, b"bound bytes".to_vec())
                .unwrap();
        assert_eq!(
            receiver
                .finish_verified(local.marker().clone())
                .unwrap()
                .payload(),
            b"bound bytes"
        );
    }

    fn serial_builder_admission(
        chain: &[u8; 32],
        key: &FalconKeypair,
        batches: &[SignedBatch],
        marker: FinalMarker,
    ) -> Result<VerifiedCandidate, NetworkError> {
        let first = &batches
            .first()
            .ok_or(NetworkError::Incomplete)?
            .metadata
            .context;
        let mut previous = [0; 48];
        let mut bytes = 0;
        for (index, batch) in batches.iter().enumerate() {
            let context = &batch.metadata.context;
            if context.leader_epoch != first.leader_epoch
                || context.slot != first.slot
                || context.candidate != first.candidate
                || context.parent != first.parent
                || context.batch_index as usize != index
                || context.previous != previous
            {
                return Err(NetworkError::Context);
            }
            previous = batch.commitment();
            bytes += batch.metadata.payload_bytes;
        }
        if bytes != marker.total_payload_bytes || bytes as usize > MAX_CANDIDATE_BYTES {
            return Err(NetworkError::Extent);
        }
        let mut assembler = CandidateAssembler::new(
            *chain,
            key.public_key(),
            first.leader_epoch,
            first.slot,
            first.candidate,
            first.parent,
        );
        // The original producer path: raw serial insert verifies every header
        // and inclusion proof before admitting it. Reuse the signed marker so
        // the complete output is byte-comparable despite randomized signing.
        for batch in batches {
            for shred in batch
                .shreds
                .iter()
                .take(usize::from(batch.metadata.data_shards))
            {
                assembler.insert(shred.clone())?;
            }
        }
        assembler.finish_verified(marker)
    }

    #[test]
    fn parallel_producer_authentication_matches_serial_full_witness_and_marker() {
        let chain = [0x65; 32];
        let key = FalconKeypair::generate();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();
        for length in [4001usize, 8 * 1024 * 1024] {
            let payload = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let mut batches = Vec::new();
            let mut previous = [0; 48];
            for (index, part) in payload.chunks(128 * 1024).enumerate() {
                let data = part.len().div_ceil(2048) as u16;
                let batch = SignedBatch::build(
                    &chain,
                    &key,
                    context(index as u32, previous),
                    part,
                    data,
                    data,
                )
                .unwrap();
                previous = batch.commitment();
                batches.push(batch);
            }
            let candidate = pool
                .install(|| FinalMarker::build_verified(&chain, &key, &batches, &payload))
                .unwrap();
            let serial = pool
                .install(|| {
                    serial_builder_admission(&chain, &key, &batches, candidate.marker().clone())
                })
                .unwrap();
            assert_eq!(candidate.marker().encode(), serial.marker().encode());
            assert_eq!(candidate.payload, serial.payload);
            assert_eq!(candidate.payload, payload);
            assert_eq!(candidate.shreds().len(), length.div_ceil(2048));
            for (parallel, original) in candidate.shreds().iter().zip(serial.shreds()) {
                assert_eq!(parallel.encode().unwrap(), original.encode().unwrap());
            }
        }
        // A legitimate batch can contain more data shards than the parallel
        // authentication bound, so the producer must split its work safely.
        let payload = vec![0x47; 72_001];
        let batch =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload, 200, 56).unwrap();
        let batches = [batch];
        let candidate = pool
            .install(|| FinalMarker::build_verified(&chain, &key, &batches, &payload))
            .unwrap();
        let serial = pool
            .install(|| {
                serial_builder_admission(&chain, &key, &batches, candidate.marker().clone())
            })
            .unwrap();
        assert_eq!(candidate.marker().encode(), serial.marker().encode());
        assert_eq!(candidate.payload, serial.payload);
        assert_eq!(candidate.shreds().len(), 200);
        for (parallel, original) in candidate.shreds().iter().zip(serial.shreds()) {
            assert_eq!(parallel.encode().unwrap(), original.encode().unwrap());
        }
    }

    #[test]
    fn parallel_producer_rejects_tampered_headers_proofs_conflicts_and_order() {
        let chain = [0x66; 32];
        let key = FalconKeypair::generate();
        let payload = vec![0x48; 8000];
        let first =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload[..4000], 4, 4).unwrap();
        let second = SignedBatch::build(
            &chain,
            &key,
            context(1, first.commitment()),
            &payload[4000..],
            4,
            4,
        )
        .unwrap();
        let batches = [first, second];
        let marker = FinalMarker::build(&chain, &key, &batches, &payload).unwrap();
        let clone_batches = || {
            batches
                .iter()
                .map(|batch| SignedBatch {
                    metadata: batch.metadata.clone(),
                    shreds: batch.shreds.clone(),
                })
                .collect::<Vec<_>>()
        };
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let rejected_by_both = |bad: &[SignedBatch]| {
            assert!(
                pool.install(|| FinalMarker::build_verified(&chain, &key, bad, &payload))
                    .is_err()
            );
            assert!(
                pool.install(|| serial_builder_admission(&chain, &key, bad, marker.clone()))
                    .is_err()
            );
        };
        let mut bad = clone_batches();
        bad[0].shreds[1].metadata.context.parent[0] ^= 1;
        rejected_by_both(&bad);
        let mut bad = clone_batches();
        bad[0].shreds[1].proof[0][0] ^= 1;
        rejected_by_both(&bad);
        let mut bad = clone_batches();
        bad[0].shreds[1].is_parity = true;
        rejected_by_both(&bad);
        let alternative =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), &[0x49; 4000], 4, 4).unwrap();
        let mut bad = clone_batches();
        // Both shreds are genuinely signed with valid inclusion proofs but
        // contradict one another about the same batch's commitment.
        bad[0].shreds[1] = alternative.shreds[1].clone();
        rejected_by_both(&bad);
        let mut bad = clone_batches();
        bad[0].shreds.truncate(3);
        rejected_by_both(&bad);
        let mut bad = clone_batches();
        bad[1].metadata.context.previous[0] ^= 1;
        assert!(
            pool.install(|| FinalMarker::build_verified(&chain, &key, &bad, &payload))
                .is_err()
        );
        let mut bad = clone_batches();
        bad.reverse();
        rejected_by_both(&bad);
        assert_eq!(
            FinalMarker::build_verified(&chain, &key, &[], &[]).err(),
            Some(NetworkError::Incomplete)
        );
        assert_eq!(
            FinalMarker::build_verified(&chain, &key, &batches, &[]).err(),
            Some(NetworkError::Extent)
        );
    }

    #[test]
    fn authentication_worker_counts_preserve_order_errors_and_coding_recovery() {
        let chain = [0x61; 32];
        let key = FalconKeypair::generate();
        let payload = vec![3; 8000];
        let batch = SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload, 4, 4).unwrap();
        let marker =
            FinalMarker::build(&chain, &key, std::slice::from_ref(&batch), &payload).unwrap();
        for workers in [1, 4, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            let mut receiver =
                CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
            let mut input = batch.shreds.iter().take(5).cloned().collect::<Vec<_>>();
            input[1].payload[0] ^= 1;
            let tokens = pool.install(|| receiver.authenticate_batch(input)).unwrap();
            let results = tokens
                .into_iter()
                .map(|token| token.and_then(|token| receiver.insert_verified(token)))
                .collect::<Vec<_>>();
            assert_eq!(
                results,
                vec![
                    Ok(true),
                    Err(NetworkError::MerkleProof),
                    Ok(true),
                    Ok(true),
                    Ok(true)
                ]
            );
            assert_eq!(pool.install(|| receiver.finish(&marker)).unwrap(), payload);
        }
    }
    #[test]
    fn leader_signed_nonzero_padding_cannot_mint_verified_candidate() {
        let chain = [0x71; 32];
        let key = FalconKeypair::generate();
        let mut prepared = PreparedBatch::prepare(b"1234567", 4, 4).unwrap();
        prepared.shards[3][1] = 9;
        ReedSolomon::new(4, 4)
            .unwrap()
            .encode(&mut prepared.shards)
            .unwrap();
        prepared.tree = merkle_tree(
            prepared
                .shards
                .iter()
                .enumerate()
                .map(|(index, bytes)| leaf_hash(index as u16, index >= 4, bytes))
                .collect(),
        );
        let batch = prepared.seal(&chain, &key, context(0, [0; 48])).unwrap();
        assert!(matches!(
            FinalMarker::build(&chain, &key, std::slice::from_ref(&batch), b"1234567"),
            Err(NetworkError::Extent)
        ));
        let mut marker = FinalMarker {
            leader_epoch: 3,
            slot: 42,
            candidate: [7; 48],
            parent: [9; 48],
            terminal_batch: 0,
            terminal_commitment: batch.commitment(),
            total_payload_bytes: 7,
            block_commitment: block_hash(&batch.metadata.context, &batch.commitment(), b"1234567"),
            signature: batch.shreds[0].signature.clone(),
        };
        marker.signature = key
            .sign(&chain, Domain::LeaderBatch, &marker.sign_bytes())
            .unwrap();
        let mut receiver =
            CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
        for token in receiver.authenticate_batch(batch.shreds).unwrap() {
            receiver.insert_verified(token.unwrap()).unwrap();
        }
        assert!(matches!(
            receiver.finish_verified(marker),
            Err(NetworkError::Extent)
        ));
    }
    #[test]
    fn parallel_authentication_rejects_bad_items_and_binds_exact_role_context() {
        let chain = [0x81; 32];
        let key = FalconKeypair::generate();
        let payload = vec![7; 8000];
        let batch = SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload, 4, 4).unwrap();
        let marker =
            FinalMarker::build(&chain, &key, std::slice::from_ref(&batch), &payload).unwrap();
        let mut receiver =
            CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
        let mut tampered = batch.shreds[2].clone();
        tampered.payload[0] ^= 1;
        let input = vec![
            batch.shreds[0].clone(),
            batch.shreds[0].clone(),
            tampered,
            batch.shreds[1].clone(),
        ];
        let tokens = receiver.authenticate_batch(input).unwrap();
        let mut results = tokens
            .into_iter()
            .map(|result| result.and_then(|token| receiver.insert_verified(token)))
            .collect::<Vec<_>>();
        assert_eq!(results.remove(0), Ok(true));
        assert_eq!(results.remove(0), Ok(false));
        assert_eq!(results.remove(0), Err(NetworkError::MerkleProof));
        assert_eq!(results.remove(0), Ok(true));
        assert!(matches!(
            receiver.finish(&marker),
            Err(NetworkError::Incomplete)
        ));
        for token in receiver.authenticate_batch(batch.shreds.clone()).unwrap() {
            receiver.insert_verified(token.unwrap()).unwrap();
        }
        assert_eq!(receiver.finish(&marker).unwrap(), payload);
        for (other_chain, other_epoch, other_parent) in [
            ([0x82; 32], 3, [9; 48]),
            (chain, 4, [9; 48]),
            (chain, 3, [8; 48]),
        ] {
            let token = receiver
                .authenticate_batch(vec![batch.shreds[0].clone()])
                .unwrap()
                .pop()
                .unwrap()
                .unwrap();
            let mut other = CandidateAssembler::new(
                other_chain,
                key.public_key(),
                other_epoch,
                42,
                [7; 48],
                other_parent,
            );
            assert_eq!(other.insert_verified(token), Err(NetworkError::Context));
        }
        let token = receiver
            .authenticate_batch(vec![batch.shreds[0].clone()])
            .unwrap()
            .pop()
            .unwrap()
            .unwrap();
        let mut wrong_key = CandidateAssembler::new(
            chain,
            FalconKeypair::generate().public_key(),
            3,
            42,
            [7; 48],
            [9; 48],
        );
        assert_eq!(wrong_key.insert_verified(token), Err(NetworkError::Context));
        let too_many = vec![batch.shreds[0].clone(); MAX_AUTHENTICATION_BATCH + 1];
        assert!(matches!(
            receiver.authenticate_batch(too_many),
            Err(NetworkError::Bounds)
        ));
        let verified = receiver.finish_verified(marker).unwrap();
        assert_eq!(verified.shreds().len(), 8);
        assert!(matches!(
            verified.clone().into_parts(&[0x82; 32], &key.public_key()),
            Err(NetworkError::Context)
        ));
        assert!(matches!(
            verified.clone().into_parts(&chain, &wrong_key.leader),
            Err(NetworkError::Context)
        ));
        assert_eq!(
            verified.into_parts(&chain, &key.public_key()).unwrap().2,
            payload
        );
    }
    #[test]
    fn predicted_block_identity_matches_real_falcon_sealing_in_any_work_order() {
        let chain = [0xb7; 32];
        let key = FalconKeypair::generate();
        for size in [1, 7999, 24_001] {
            let payload = (0..size)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            for reverse in [false, true] {
                let batches = payload
                    .chunks(8000)
                    .map(|bytes| PreparedBatch::prepare(bytes, 4, 2).unwrap())
                    .collect::<Vec<_>>();
                let predicted =
                    prepared_block_commitment(context(0, [0; 48]), &batches, &payload).unwrap();
                let mut previous = [0; 48];
                let contexts = batches
                    .iter()
                    .enumerate()
                    .map(|(index, batch)| {
                        let context = context(index as u32, previous);
                        previous = batch.metadata(context.clone()).unwrap().commitment();
                        context
                    })
                    .collect::<Vec<_>>();
                let mut indices = (0..batches.len()).collect::<Vec<_>>();
                if reverse {
                    indices.reverse();
                }
                let mut prepared = batches.into_iter().map(Some).collect::<Vec<_>>();
                let mut signed = (0..prepared.len()).map(|_| None).collect::<Vec<_>>();
                for index in indices {
                    signed[index] = Some(
                        prepared[index]
                            .take()
                            .unwrap()
                            .seal_local(&chain, &key, contexts[index].clone())
                            .unwrap(),
                    );
                }
                let candidate = FinalMarker::build_local_verified(
                    &chain,
                    &key,
                    signed.into_iter().map(Option::unwrap).collect(),
                    payload.clone(),
                )
                .unwrap();
                assert_eq!(candidate.marker().block_commitment, predicted);
                assert_eq!(candidate.payload(), payload.as_slice());
                let mut changed = context(0, [0; 48]);
                changed.parent[0] ^= 1;
                let batches = payload
                    .chunks(8000)
                    .map(|bytes| PreparedBatch::prepare(bytes, 4, 2).unwrap())
                    .collect::<Vec<_>>();
                assert_ne!(
                    prepared_block_commitment(changed, &batches, &payload).unwrap(),
                    predicted
                );
                assert_eq!(
                    prepared_block_commitment(context(1, [0; 48]), &batches, &payload),
                    Err(NetworkError::Bounds)
                );
                assert_eq!(
                    prepared_block_commitment(context(0, [1; 48]), &batches, &payload),
                    Err(NetworkError::Bounds)
                );
                assert_eq!(
                    prepared_block_commitment(context(0, [0; 48]), &batches, &[]),
                    Err(NetworkError::Bounds)
                );
                let mut longer = payload.clone();
                longer.push(1);
                assert_eq!(
                    prepared_block_commitment(context(0, [0; 48]), &batches, &longer),
                    Err(NetworkError::Extent)
                );
            }
        }
        assert_eq!(
            prepared_block_commitment(context(0, [0; 48]), &[], &[1]),
            Err(NetworkError::Incomplete)
        );
    }

    #[test]
    fn parallel_preparation_and_sealing_preserve_order_and_worker_independent_payload() {
        let chain = [0xa1; 32];
        let key = FalconKeypair::generate();
        let payload = (0..24_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            let batches = pool.install(|| {
                let prepared = payload
                    .par_chunks(8000)
                    .map(|chunk| PreparedBatch::prepare(chunk, 4, 2))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                let mut previous = [0; 48];
                let contexts = prepared
                    .iter()
                    .enumerate()
                    .map(|(index, prepared)| {
                        let context = context(index as u32, previous);
                        previous = prepared.metadata(context.clone()).unwrap().commitment();
                        context
                    })
                    .collect::<Vec<_>>();
                prepared
                    .into_par_iter()
                    .zip(contexts.into_par_iter())
                    .map(|(prepared, context)| prepared.seal(&chain, &key, context))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            });
            let mut previous = [0; 48];
            for (index, batch) in batches.iter().enumerate() {
                let direct = SignedBatch::build(
                    &chain,
                    &key,
                    context(index as u32, previous),
                    &payload[index * 8000..(index + 1) * 8000],
                    4,
                    2,
                )
                .unwrap();
                assert_eq!(batch.metadata, direct.metadata);
                for (shred, original) in batch.shreds.iter().zip(direct.shreds) {
                    assert_eq!(shred.payload, original.payload);
                    assert_eq!(shred.proof, original.proof);
                    shred.verify(&chain, &key.public_key()).unwrap();
                }
                previous = batch.commitment();
            }
            let marker = FinalMarker::build(&chain, &key, &batches, &payload).unwrap();
            let mut receiver =
                CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
            for batch in &batches {
                for shred in batch.shreds.iter().skip(2) {
                    receiver.insert(shred.clone()).unwrap();
                }
            }
            assert_eq!(pool.install(|| receiver.finish(&marker)).unwrap(), payload);
        }
        let prepared = PreparedBatch::prepare(&payload[..8000], 4, 2).unwrap();
        assert_eq!(
            prepared.metadata(context(MAX_BATCHES as u32, [0; 48])),
            Err(NetworkError::Bounds),
            "precomputed commitments still reject an invalid context"
        );
    }
    fn context(index: u32, previous: Commitment) -> BatchContext {
        BatchContext {
            leader_epoch: 3,
            slot: 42,
            candidate: [7; 48],
            parent: [9; 48],
            batch_index: index,
            previous,
        }
    }
    #[test]
    fn independently_authenticated_shreds_repair_and_terminal_extent() {
        let chain = [1; 32];
        let key = FalconKeypair::generate();
        let payload = vec![11; 8000];
        let a =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload[..4000], 4, 2).unwrap();
        let b = SignedBatch::build(
            &chain,
            &key,
            context(1, a.commitment()),
            &payload[4000..],
            4,
            2,
        )
        .unwrap();
        let marker = FinalMarker::build(&chain, &key, &[a, b], &payload).unwrap();
        let a =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), &payload[..4000], 4, 2).unwrap();
        let b = SignedBatch::build(
            &chain,
            &key,
            context(1, a.commitment()),
            &payload[4000..],
            4,
            2,
        )
        .unwrap();
        let mut receiver =
            CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
        // Lose two data shards; authenticated parity recovers the exact payload.
        for batch in [&b, &a] {
            for shred in batch.shreds.iter().skip(2) {
                let bytes = shred.encode().unwrap();
                assert!(bytes.len() <= MAX_LOGICAL_SHRED);
                let decoded = AuthenticatedShred::decode(&bytes).unwrap();
                decoded.verify(&chain, &key.public_key()).unwrap();
                assert!(receiver.insert(decoded.clone()).unwrap());
                assert!(!receiver.insert(decoded).unwrap());
            }
        }
        let marker = FinalMarker::decode(&marker.encode()).unwrap();
        assert_eq!(receiver.finish(&marker).unwrap(), payload);
        let mut trailing = marker.encode();
        trailing.push(0);
        assert_eq!(
            FinalMarker::decode(&trailing).err(),
            Some(NetworkError::Encoding)
        );
        assert_eq!(
            FinalMarker::decode(&marker.encode()[..100]).err(),
            Some(NetworkError::Encoding)
        );
        let mut bad = marker.clone();
        bad.total_payload_bytes += 1;
        assert_eq!(receiver.finish(&bad), Err(NetworkError::Signature));
    }
    #[test]
    fn tampering_and_chain_replay_are_rejected_before_admission() {
        let chain = [2; 32];
        let key = FalconKeypair::generate();
        let batch = SignedBatch::build(
            &chain,
            &key,
            context(0, [0; 48]),
            b"authenticated payload",
            2,
            1,
        )
        .unwrap();
        let mut shred = batch.shreds[0].clone();
        shred.payload[0] ^= 1;
        assert_eq!(
            shred.verify(&chain, &key.public_key()),
            Err(NetworkError::MerkleProof)
        );
        assert_eq!(
            batch.shreds[0].verify(&[3; 32], &key.public_key()),
            Err(NetworkError::Signature)
        );
        assert_eq!(
            AuthenticatedShred::decode(&vec![0; 4097]).err(),
            Some(NetworkError::Bounds)
        );
        let mut bytes = batch.shreds[0].encode().unwrap();
        bytes.push(0);
        assert_eq!(
            AuthenticatedShred::decode(&bytes).err(),
            Some(NetworkError::Encoding)
        );
    }
    #[test]
    fn missing_batches_and_equivocating_roots_do_not_complete() {
        let chain = [4; 32];
        let key = FalconKeypair::generate();
        let a = SignedBatch::build(&chain, &key, context(0, [0; 48]), b"a", 1, 1).unwrap();
        let b = SignedBatch::build(&chain, &key, context(1, a.commitment()), b"b", 1, 1).unwrap();
        let marker = FinalMarker::build(&chain, &key, &[a, b], b"ab").unwrap();
        let a = SignedBatch::build(&chain, &key, context(0, [0; 48]), b"a", 1, 1).unwrap();
        let evil = SignedBatch::build(&chain, &key, context(0, [0; 48]), b"evil", 1, 1).unwrap();
        let mut receiver =
            CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
        receiver.insert(a.shreds[0].clone()).unwrap();
        assert_eq!(
            receiver.insert(evil.shreds[0].clone()),
            Err(NetworkError::Equivocation)
        );
        assert_eq!(receiver.finish(&marker), Err(NetworkError::Incomplete));
    }
    #[test]
    fn a_leader_signed_inconsistent_parity_batch_is_rejected_for_every_subset() {
        let chain = [8; 32];
        let key = FalconKeypair::generate();
        let mut batch =
            SignedBatch::build(&chain, &key, context(0, [0; 48]), b"bytes", 2, 1).unwrap();
        batch.shreds[2].payload[0] ^= 1;
        let tree = merkle_tree(
            batch
                .shreds
                .iter()
                .map(|s| leaf_hash(s.index, s.is_parity, &s.payload))
                .collect(),
        );
        batch.metadata.merkle_root = tree.last().unwrap()[0];
        let signature = key
            .sign(&chain, Domain::LeaderBatch, &batch.metadata.sign_bytes())
            .unwrap();
        for shred in &mut batch.shreds {
            shred.metadata = batch.metadata.clone();
            shred.signature = signature.clone();
            let mut index = usize::from(shred.index);
            shred.proof = tree
                .iter()
                .take(tree.len() - 1)
                .map(|level| {
                    let sibling = level[index ^ 1];
                    index >>= 1;
                    sibling
                })
                .collect();
        }
        for received in [vec![0, 1], vec![0, 2], vec![0, 1, 2]] {
            let mut receiver =
                CandidateAssembler::new(chain, key.public_key(), 3, 42, [7; 48], [9; 48]);
            for index in received {
                receiver.insert(batch.shreds[index].clone()).unwrap();
            }
            assert_eq!(receiver.ordered_payload(0), Err(NetworkError::Erasure));
        }
        assert_eq!(
            FinalMarker::build(&chain, &key, &[batch], b"bytes").err(),
            Some(NetworkError::Erasure)
        );
    }
}

/// Public network records use independent signing domains and the role key
/// resolved from authenticated validator state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicRecordKind {
    Gossip,
    Repair,
}
impl PublicRecordKind {
    fn domain(self) -> Domain {
        match self {
            Self::Gossip => Domain::Gossip,
            Self::Repair => Domain::Repair,
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::Gossip => 1,
            Self::Repair => 2,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecordContext {
    pub validator: [u8; 32],
    pub epoch: u64,
    pub generation: u64,
    pub sequence: u64,
}
#[derive(Clone)]
pub struct SignedPublicRecord {
    pub kind: PublicRecordKind,
    pub context: PublicRecordContext,
    pub payload: Vec<u8>,
    pub signature: FalconSignature,
}
impl SignedPublicRecord {
    fn sign_bytes(
        kind: PublicRecordKind,
        context: &PublicRecordContext,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        if payload.len() > 1024 || context.generation == 0 || context.sequence == 0 {
            return Err(NetworkError::Bounds);
        }
        let mut out = vec![1, kind.tag()];
        out.extend_from_slice(&context.validator);
        out.extend_from_slice(&context.epoch.to_le_bytes());
        out.extend_from_slice(&context.generation.to_le_bytes());
        out.extend_from_slice(&context.sequence.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }
    pub fn sign(
        chain: &[u8; 32],
        role_key: &FalconKeypair,
        kind: PublicRecordKind,
        context: PublicRecordContext,
        payload: Vec<u8>,
    ) -> Result<Self, NetworkError> {
        let signature = role_key
            .sign(
                chain,
                kind.domain(),
                &Self::sign_bytes(kind, &context, &payload)?,
            )
            .map_err(|_| NetworkError::Signature)?;
        Ok(Self {
            kind,
            context,
            payload,
            signature,
        })
    }
    pub fn verify(
        &self,
        chain: &[u8; 32],
        role_key: &FalconPublicKey,
        expected_validator: &[u8; 32],
        epoch: u64,
        generation: u64,
    ) -> Result<(), NetworkError> {
        if self.context.validator != *expected_validator
            || self.context.epoch != epoch
            || self.context.generation != generation
        {
            return Err(NetworkError::Context);
        }
        role_key
            .verify(
                chain,
                self.kind.domain(),
                &Self::sign_bytes(self.kind, &self.context, &self.payload)?,
                &self.signature,
            )
            .map_err(|_| NetworkError::Signature)
    }
}
/// A caller persists this high-water mark with the authorized epoch/generation.
/// Gossip and repair have separate sequence namespaces.
pub struct PublicRecordTracker {
    kind: PublicRecordKind,
    validator: [u8; 32],
    epoch: u64,
    generation: u64,
    last_sequence: u64,
}
impl PublicRecordTracker {
    pub fn new(
        kind: PublicRecordKind,
        validator: [u8; 32],
        epoch: u64,
        generation: u64,
        last_sequence: u64,
    ) -> Self {
        Self {
            kind,
            validator,
            epoch,
            generation,
            last_sequence,
        }
    }
    pub fn accept(
        &mut self,
        chain: &[u8; 32],
        role_key: &FalconPublicKey,
        record: &SignedPublicRecord,
    ) -> Result<(), NetworkError> {
        if record.kind != self.kind || record.context.sequence <= self.last_sequence {
            return Err(NetworkError::Context);
        }
        record.verify(
            chain,
            role_key,
            &self.validator,
            self.epoch,
            self.generation,
        )?;
        self.last_sequence = record.context.sequence;
        Ok(())
    }
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}
#[derive(Clone)]
pub struct SignedRepairResponse {
    pub record: SignedPublicRecord,
    pub logical_shred: Vec<u8>,
}
impl SignedRepairResponse {
    pub fn sign(
        chain: &[u8; 32],
        repair_key: &FalconKeypair,
        context: PublicRecordContext,
        shred: &AuthenticatedShred,
    ) -> Result<Self, NetworkError> {
        let logical_shred = shred.encode()?;
        let commitment = hash_commitment(b"pq-repair-preserved-shred-v1", &[&logical_shred]);
        let record = SignedPublicRecord::sign(
            chain,
            repair_key,
            PublicRecordKind::Repair,
            context,
            commitment.to_vec(),
        )?;
        Ok(Self {
            record,
            logical_shred,
        })
    }
    pub fn verify(
        &self,
        chain: &[u8; 32],
        repair_key: &FalconPublicKey,
        leader_key: &FalconPublicKey,
        expected_validator: &[u8; 32],
        epoch: u64,
        generation: u64,
    ) -> Result<AuthenticatedShred, NetworkError> {
        if self.record.kind != PublicRecordKind::Repair
            || self.logical_shred.len() > MAX_LOGICAL_SHRED
        {
            return Err(NetworkError::Bounds);
        }
        self.record
            .verify(chain, repair_key, expected_validator, epoch, generation)?;
        let commitment = hash_commitment(b"pq-repair-preserved-shred-v1", &[&self.logical_shred]);
        if self.record.payload.as_slice() != commitment {
            return Err(NetworkError::Context);
        }
        let shred = AuthenticatedShred::decode(&self.logical_shred)?;
        shred.verify(chain, leader_key)?;
        Ok(shred)
    }
}

#[cfg(test)]
mod record_tests {
    use super::*;
    #[test]
    fn gossip_and_repair_bind_role_epoch_and_preserve_leader_authentication() {
        let chain = [5; 32];
        let network = FalconKeypair::generate();
        let leader = FalconKeypair::generate();
        let context = PublicRecordContext {
            validator: [6; 32],
            epoch: 3,
            generation: 2,
            sequence: 1,
        };
        let gossip = SignedPublicRecord::sign(
            &chain,
            &network,
            PublicRecordKind::Gossip,
            context.clone(),
            b"peer routing info".to_vec(),
        )
        .unwrap();
        let mut tracker = PublicRecordTracker::new(PublicRecordKind::Gossip, [6; 32], 3, 2, 0);
        tracker
            .accept(&chain, &network.public_key(), &gossip)
            .unwrap();
        assert_eq!(tracker.last_sequence(), 1);
        assert_eq!(
            tracker.accept(&chain, &network.public_key(), &gossip),
            Err(NetworkError::Context)
        );
        let mut wrong_role = gossip.clone();
        wrong_role.kind = PublicRecordKind::Repair;
        assert_eq!(
            wrong_role.verify(&chain, &network.public_key(), &[6; 32], 3, 2),
            Err(NetworkError::Signature)
        );
        let batch = SignedBatch::build(
            &chain,
            &leader,
            BatchContext {
                leader_epoch: 3,
                slot: 1,
                candidate: [1; 48],
                parent: [0; 48],
                batch_index: 0,
                previous: [0; 48],
            },
            b"repair bytes",
            2,
            1,
        )
        .unwrap();
        let response =
            SignedRepairResponse::sign(&chain, &network, context, &batch.shreds[0]).unwrap();
        response
            .verify(
                &chain,
                &network.public_key(),
                &leader.public_key(),
                &[6; 32],
                3,
                2,
            )
            .unwrap();
        let mut modified = response.clone();
        let last = modified.logical_shred.len() - 1;
        modified.logical_shred[last] ^= 1;
        assert_eq!(
            modified
                .verify(
                    &chain,
                    &network.public_key(),
                    &leader.public_key(),
                    &[6; 32],
                    3,
                    2
                )
                .err(),
            Some(NetworkError::Context)
        );
    }
}
