//! Role-separated Falcon credentials and independently anchored state restoration.
use {
    crate::crypto::{Domain, FalconKeypair, FalconPublicKey, FalconSignature, hash_commitment},
    std::collections::{BTreeMap, BTreeSet},
};
pub type Commitment = [u8; 48];
pub const MAX_CHECKPOINT_AUTHORITIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Bounds,
    Duplicate,
    UnknownAuthority,
    Signature,
    Chain,
    Threshold,
    Snapshot,
    Anchor,
    Credential,
}
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CheckpointError {}

/// Includes the exact candidate identity; a slot number alone is insufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub chain: [u8; 32],
    pub slot: u64,
    pub block_commitment: Commitment,
    pub executed_state: Commitment,
    pub validator_set: Commitment,
    pub role_credentials: Commitment,
    pub consensus_roots: Commitment,
    pub activation_epoch: u64,
    pub classical_cutoff: u64,
}
impl Checkpoint {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![1];
        out.extend_from_slice(&self.chain);
        out.extend_from_slice(&self.slot.to_le_bytes());
        for commitment in [
            &self.block_commitment,
            &self.executed_state,
            &self.validator_set,
            &self.role_credentials,
            &self.consensus_roots,
        ] {
            out.extend_from_slice(commitment);
        }
        out.extend_from_slice(&self.activation_epoch.to_le_bytes());
        out.extend_from_slice(&self.classical_cutoff.to_le_bytes());
        out
    }
    pub fn commitment(&self) -> Commitment {
        hash_commitment(b"pq-checkpoint-v1", &[&self.encode()])
    }
}
pub fn snapshot_commitment(bytes: &[u8]) -> Commitment {
    hash_commitment(b"pq-executed-snapshot-v1", &[bytes])
}

#[derive(Clone)]
pub struct CheckpointAuthority {
    pub id: [u8; 32],
    pub key: FalconPublicKey,
    pub weight: u64,
}
#[derive(Clone)]
pub struct CheckpointAttestation {
    pub authority: [u8; 32],
    pub signature: FalconSignature,
}
#[derive(Clone)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub attestations: Vec<CheckpointAttestation>,
}

/// A checkpoint-signing set transition authenticated by the previous independent
/// set. The exact executed activation checkpoint is part of the signed intent.
#[derive(Clone)]
pub struct SignedAnchorTransition {
    pub previous_anchor: Commitment,
    pub next_anchor: Commitment,
    pub activation_checkpoint: Checkpoint,
    pub attestations: Vec<CheckpointAttestation>,
}
impl SignedAnchorTransition {
    fn sign_bytes(&self) -> Vec<u8> {
        let mut out = vec![2]; // Distinct from a checkpoint's version/discriminant.
        out.extend_from_slice(&self.previous_anchor);
        out.extend_from_slice(&self.next_anchor);
        out.extend_from_slice(&self.activation_checkpoint.encode());
        out
    }
    pub fn sign(
        previous: &TrustAnchor,
        next: &TrustAnchor,
        activation_checkpoint: Checkpoint,
        signers: &[([u8; 32], &FalconKeypair)],
    ) -> Result<Self, CheckpointError> {
        if signers.is_empty() || signers.len() > MAX_CHECKPOINT_AUTHORITIES {
            return Err(CheckpointError::Bounds);
        }
        if previous.chain != next.chain || activation_checkpoint.chain != previous.chain {
            return Err(CheckpointError::Chain);
        }
        let mut transition = Self {
            previous_anchor: previous.commitment(),
            next_anchor: next.commitment(),
            activation_checkpoint,
            attestations: Vec::with_capacity(signers.len()),
        };
        let mut seen = BTreeSet::new();
        for &(authority, key) in signers {
            if !seen.insert(authority) {
                return Err(CheckpointError::Duplicate);
            }
            let signature = key
                .sign(
                    &previous.chain,
                    Domain::Checkpoint,
                    &transition.sign_bytes(),
                )
                .map_err(|_| CheckpointError::Signature)?;
            transition.attestations.push(CheckpointAttestation {
                authority,
                signature,
            });
        }
        Ok(transition)
    }
}
impl SignedCheckpoint {
    pub fn sign(
        checkpoint: Checkpoint,
        signers: &[([u8; 32], &FalconKeypair)],
    ) -> Result<Self, CheckpointError> {
        if signers.is_empty() || signers.len() > MAX_CHECKPOINT_AUTHORITIES {
            return Err(CheckpointError::Bounds);
        }
        let mut ids = BTreeSet::new();
        let mut attestations = Vec::with_capacity(signers.len());
        for &(authority, key) in signers {
            if !ids.insert(authority) {
                return Err(CheckpointError::Duplicate);
            }
            let signature = key
                .sign(&checkpoint.chain, Domain::Checkpoint, &checkpoint.encode())
                .map_err(|_| CheckpointError::Signature)?;
            attestations.push(CheckpointAttestation {
                authority,
                signature,
            });
        }
        Ok(Self {
            checkpoint,
            attestations,
        })
    }
}

/// This set must come from independent trusted configuration established before
/// the classical break. The constructor does not establish that provenance.
pub struct TrustAnchor {
    chain: [u8; 32],
    authorities: BTreeMap<[u8; 32], CheckpointAuthority>,
    threshold: u64,
}
impl TrustAnchor {
    pub fn new(
        chain: [u8; 32],
        authorities: Vec<CheckpointAuthority>,
        threshold: u64,
    ) -> Result<Self, CheckpointError> {
        if authorities.is_empty()
            || authorities.len() > MAX_CHECKPOINT_AUTHORITIES
            || threshold == 0
        {
            return Err(CheckpointError::Bounds);
        }
        let mut map = BTreeMap::new();
        let mut total = 0u64;
        let mut keys = BTreeSet::new();
        for authority in authorities {
            if authority.weight == 0 {
                return Err(CheckpointError::Bounds);
            }
            total = total
                .checked_add(authority.weight)
                .ok_or(CheckpointError::Bounds)?;
            // One key cannot count as two independently configured authorities.
            if !keys.insert(authority.key.as_bytes().to_vec())
                || map.insert(authority.id, authority).is_some()
            {
                return Err(CheckpointError::Duplicate);
            }
        }
        if threshold > total {
            return Err(CheckpointError::Threshold);
        }
        Ok(Self {
            chain,
            authorities: map,
            threshold,
        })
    }
    /// Verify signatures and snapshot integrity. Call `verify_expected` for
    /// restoration: valid signatures alone do not prevent checkpoint rollback.
    pub fn verify(
        &self,
        signed: &SignedCheckpoint,
        snapshot: &[u8],
    ) -> Result<Checkpoint, CheckpointError> {
        let checkpoint = &signed.checkpoint;
        if checkpoint.chain != self.chain {
            return Err(CheckpointError::Chain);
        }
        if signed.attestations.is_empty() || signed.attestations.len() > self.authorities.len() {
            return Err(CheckpointError::Bounds);
        }
        let mut seen = BTreeSet::new();
        let mut weight = 0u64;
        for attestation in &signed.attestations {
            if !seen.insert(attestation.authority) {
                return Err(CheckpointError::Duplicate);
            }
            let authority = self
                .authorities
                .get(&attestation.authority)
                .ok_or(CheckpointError::UnknownAuthority)?;
            authority
                .key
                .verify(
                    &self.chain,
                    Domain::Checkpoint,
                    &checkpoint.encode(),
                    &attestation.signature,
                )
                .map_err(|_| CheckpointError::Signature)?;
            weight = weight
                .checked_add(authority.weight)
                .ok_or(CheckpointError::Bounds)?;
        }
        if weight < self.threshold {
            return Err(CheckpointError::Threshold);
        }
        if snapshot_commitment(snapshot) != checkpoint.executed_state {
            return Err(CheckpointError::Snapshot);
        }
        Ok(checkpoint.clone())
    }
    /// Pin every trust component, including exact block, validator/stake set,
    /// role keys, consensus roots, activation and cutoff. Reject old valid state.
    pub fn verify_expected(
        &self,
        signed: &SignedCheckpoint,
        snapshot: &[u8],
        expected: &Checkpoint,
    ) -> Result<Checkpoint, CheckpointError> {
        if &signed.checkpoint != expected {
            return Err(CheckpointError::Anchor);
        }
        self.verify(signed, snapshot)
    }
    pub fn commitment(&self) -> Commitment {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.chain);
        bytes.extend_from_slice(&self.threshold.to_le_bytes());
        for (id, authority) in &self.authorities {
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&authority.weight.to_le_bytes());
            bytes.extend_from_slice(authority.key.as_bytes());
        }
        hash_commitment(b"pq-independent-checkpoint-authorities-v1", &[&bytes])
    }
    /// Verify a successor set against the exact trusted executed activation
    /// checkpoint. Establishing that checkpoint's finality belongs to the caller.
    pub fn authorize_successor(
        &self,
        next: TrustAnchor,
        transition: &SignedAnchorTransition,
        expected_activation: &Checkpoint,
    ) -> Result<TrustAnchor, CheckpointError> {
        if next.chain != self.chain || transition.activation_checkpoint.chain != self.chain {
            return Err(CheckpointError::Chain);
        }
        if transition.previous_anchor != self.commitment()
            || transition.next_anchor != next.commitment()
            || &transition.activation_checkpoint != expected_activation
        {
            return Err(CheckpointError::Anchor);
        }
        if transition.attestations.is_empty()
            || transition.attestations.len() > self.authorities.len()
        {
            return Err(CheckpointError::Bounds);
        }
        let mut seen = BTreeSet::new();
        let mut weight = 0u64;
        for attestation in &transition.attestations {
            if !seen.insert(attestation.authority) {
                return Err(CheckpointError::Duplicate);
            }
            let authority = self
                .authorities
                .get(&attestation.authority)
                .ok_or(CheckpointError::UnknownAuthority)?;
            authority
                .key
                .verify(
                    &self.chain,
                    Domain::Checkpoint,
                    &transition.sign_bytes(),
                    &attestation.signature,
                )
                .map_err(|_| CheckpointError::Signature)?;
            weight = weight
                .checked_add(authority.weight)
                .ok_or(CheckpointError::Bounds)?;
        }
        if weight < self.threshold {
            return Err(CheckpointError::Threshold);
        }
        Ok(next)
    }
}

/// Credential publication is authorized by the validator's current onchain
/// Falcon authority. Stake/withdrawal ownership remains a separate state item.
#[derive(Clone)]
pub struct ValidatorRoles {
    pub validator: [u8; 32],
    pub vote_identity: [u8; 32],
    pub stake_set: Commitment,
    pub activation_epoch: u64,
    pub generation: u64,
    pub network: FalconPublicKey,
    pub leader: FalconPublicKey,
    pub consensus_key: Vec<u8>,
    pub consensus_root: Commitment,
}
impl ValidatorRoles {
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        if self.generation == 0
            || self.consensus_key.len() != crate::consensus::CONSENSUS_PUBLIC_KEY_BYTES
            || self.network.as_bytes() == self.leader.as_bytes()
            || self.consensus_root
                != crate::consensus::consensus_key_commitment(&self.consensus_key)
        {
            return Err(CheckpointError::Credential);
        }
        let consensus = crate::consensus::ConsensusPublicKey::from_bytes(&self.consensus_key)
            .map_err(|_| CheckpointError::Credential)?;
        if consensus.epoch().validator != self.validator
            || consensus.epoch().epoch != self.activation_epoch
            || consensus.epoch().generation != self.generation
        {
            return Err(CheckpointError::Credential);
        }
        let mut out = vec![1];
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(&self.vote_identity);
        out.extend_from_slice(&self.stake_set);
        out.extend_from_slice(&self.activation_epoch.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(self.network.as_bytes());
        out.extend_from_slice(self.leader.as_bytes());
        out.extend_from_slice(&self.consensus_key);
        out.extend_from_slice(&self.consensus_root);
        Ok(out)
    }
    pub fn commitment(&self) -> Result<Commitment, CheckpointError> {
        Ok(hash_commitment(
            b"pq-validator-roles-v1",
            &[&self.encode()?],
        ))
    }
}
#[derive(Clone)]
pub struct SignedValidatorRoles {
    pub roles: ValidatorRoles,
    pub signature: FalconSignature,
}
impl SignedValidatorRoles {
    pub fn sign(
        chain: &[u8; 32],
        roles: ValidatorRoles,
        authority: &FalconKeypair,
    ) -> Result<Self, CheckpointError> {
        let signature = authority
            .sign(chain, Domain::ValidatorBinding, &roles.encode()?)
            .map_err(|_| CheckpointError::Signature)?;
        Ok(Self { roles, signature })
    }
    pub fn verify(
        &self,
        chain: &[u8; 32],
        authority: &FalconPublicKey,
        expected_validator: &[u8; 32],
        expected_vote: &[u8; 32],
        expected_stake_set: &Commitment,
        active_epoch: u64,
        expected_generation: u64,
    ) -> Result<(), CheckpointError> {
        if self.roles.validator != *expected_validator
            || self.roles.vote_identity != *expected_vote
            || self.roles.stake_set != *expected_stake_set
            || self.roles.activation_epoch != active_epoch
            || self.roles.generation != expected_generation
        {
            return Err(CheckpointError::Credential);
        }
        let consensus = crate::consensus::ConsensusPublicKey::from_bytes(&self.roles.consensus_key)
            .map_err(|_| CheckpointError::Credential)?;
        if &consensus.epoch().chain != chain {
            return Err(CheckpointError::Credential);
        }
        authority
            .verify(
                chain,
                Domain::ValidatorBinding,
                &self.roles.encode()?,
                &self.signature,
            )
            .map_err(|_| CheckpointError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checkpoint(chain: [u8; 32], bytes: &[u8]) -> Checkpoint {
        Checkpoint {
            chain,
            slot: 20,
            block_commitment: [1; 48],
            executed_state: snapshot_commitment(bytes),
            validator_set: [2; 48],
            role_credentials: [3; 48],
            consensus_roots: [4; 48],
            activation_epoch: 2,
            classical_cutoff: 19,
        }
    }
    #[test]
    fn independently_anchored_threshold_rejects_forgery_duplicates_rollback_and_state_changes() {
        let chain = [1; 32];
        let a = FalconKeypair::generate();
        let b = FalconKeypair::generate();
        let c = FalconKeypair::generate();
        let authorities = vec![
            CheckpointAuthority {
                id: [1; 32],
                key: a.public_key(),
                weight: 2,
            },
            CheckpointAuthority {
                id: [2; 32],
                key: b.public_key(),
                weight: 1,
            },
            CheckpointAuthority {
                id: [3; 32],
                key: c.public_key(),
                weight: 1,
            },
        ];
        let anchor = TrustAnchor::new(chain, authorities, 3).unwrap();
        let bytes = b"auth records, consumed claims, validator state";
        let expected = checkpoint(chain, bytes);
        let signed =
            SignedCheckpoint::sign(expected.clone(), &[([1; 32], &a), ([2; 32], &b)]).unwrap();
        assert_eq!(
            anchor.verify_expected(&signed, bytes, &expected).unwrap(),
            expected
        );
        assert_eq!(
            anchor.verify_expected(&signed, b"modified", &expected),
            Err(CheckpointError::Snapshot)
        );
        let low = SignedCheckpoint::sign(expected.clone(), &[([1; 32], &a)]).unwrap();
        assert_eq!(anchor.verify(&low, bytes), Err(CheckpointError::Threshold));
        let mut duplicates = signed.clone();
        duplicates.attestations[1] = duplicates.attestations[0].clone();
        assert_eq!(
            anchor.verify(&duplicates, bytes),
            Err(CheckpointError::Duplicate)
        );
        let mut old = expected.clone();
        old.slot -= 1;
        let old = SignedCheckpoint::sign(old, &[([1; 32], &a), ([2; 32], &b)]).unwrap();
        assert_eq!(
            anchor.verify_expected(&old, bytes, &expected),
            Err(CheckpointError::Anchor)
        );
        let mut forged = signed.clone();
        forged.checkpoint.validator_set = [99; 48];
        assert_eq!(
            anchor.verify(&forged, bytes),
            Err(CheckpointError::Signature)
        );
    }
    #[test]
    fn validator_bindings_are_epoch_generation_stake_and_role_specific() {
        let chain = [9; 32];
        let authority = FalconKeypair::generate();
        let network = FalconKeypair::generate();
        let leader = FalconKeypair::generate();
        let consensus =
            crate::consensus::ConsensusKeypair::generate_for_generation(chain, [1; 32], 8, 2, 1, 1)
                .unwrap()
                .public_key();
        let roles = ValidatorRoles {
            validator: [1; 32],
            vote_identity: [2; 32],
            stake_set: [3; 48],
            activation_epoch: 8,
            generation: 2,
            network: network.public_key(),
            leader: leader.public_key(),
            consensus_key: consensus.as_bytes().to_vec(),
            consensus_root: consensus.commitment(),
        };
        let signed = SignedValidatorRoles::sign(&chain, roles, &authority).unwrap();
        signed
            .verify(
                &chain,
                &authority.public_key(),
                &[1; 32],
                &[2; 32],
                &[3; 48],
                8,
                2,
            )
            .unwrap();
        assert_eq!(
            signed.verify(
                &chain,
                &authority.public_key(),
                &[1; 32],
                &[2; 32],
                &[3; 48],
                8,
                1
            ),
            Err(CheckpointError::Credential)
        );
        assert_eq!(
            signed.verify(
                &chain,
                &authority.public_key(),
                &[1; 32],
                &[2; 32],
                &[3; 48],
                7,
                2
            ),
            Err(CheckpointError::Credential)
        );
        let mut swapped = signed.clone();
        std::mem::swap(&mut swapped.roles.network, &mut swapped.roles.leader);
        assert_eq!(
            swapped.verify(
                &chain,
                &authority.public_key(),
                &[1; 32],
                &[2; 32],
                &[3; 48],
                8,
                2
            ),
            Err(CheckpointError::Signature)
        );
    }
    #[test]
    fn independent_authority_transitions_bind_successor_and_exact_activation_state() {
        let chain = [4; 32];
        let old_key = FalconKeypair::generate();
        let new_key = FalconKeypair::generate();
        let old = TrustAnchor::new(
            chain,
            vec![CheckpointAuthority {
                id: [1; 32],
                key: old_key.public_key(),
                weight: 1,
            }],
            1,
        )
        .unwrap();
        let next = || {
            TrustAnchor::new(
                chain,
                vec![CheckpointAuthority {
                    id: [2; 32],
                    key: new_key.public_key(),
                    weight: 1,
                }],
                1,
            )
            .unwrap()
        };
        let activation = checkpoint(chain, b"finalized activation state");
        let transition =
            SignedAnchorTransition::sign(&old, &next(), activation.clone(), &[([1; 32], &old_key)])
                .unwrap();
        let successor = old
            .authorize_successor(next(), &transition, &activation)
            .unwrap();
        assert_ne!(successor.commitment(), old.commitment());
        let mut stale = activation.clone();
        stale.slot -= 1;
        assert_eq!(
            old.authorize_successor(next(), &transition, &stale).err(),
            Some(CheckpointError::Anchor)
        );
        let mut forged = transition.clone();
        forged.activation_checkpoint.role_credentials = [77; 48];
        assert_eq!(
            old.authorize_successor(next(), &forged, &forged.activation_checkpoint)
                .err(),
            Some(CheckpointError::Signature)
        );
        let signed = SignedCheckpoint::sign(activation.clone(), &[([2; 32], &new_key)]).unwrap();
        successor
            .verify_expected(&signed, b"finalized activation state", &activation)
            .unwrap();
        assert_eq!(
            old.verify(&signed, b"finalized activation state"),
            Err(CheckpointError::UnknownAuthority)
        );
    }
}
