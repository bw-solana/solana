//! Sealed, funded ledger uploads for fixed private RFC 8032 proof profiles.
//! Native execution writes a program-owned verification record; finalization
//! consumes it while rechecking eligibility under the auth policy write lock.
//! Uploading, sealing and finalizing grant no spending signer privileges.

use {
    crate::{
        Address, Commitment,
        crypto::{FalconPublicKey, hash_commitment},
    },
    solana_account::Account,
    solana_pubkey::Pubkey,
    thiserror::Error,
};

/// Fixed experimental RFC 8032 / intent-binding Plonky3 profile. A profile ID
/// does not replace independent cryptographic review of its implementation.
pub const COMPLETE_SEED_PROFILE: u32 = 2;
pub const LEGACY_COMPLETE_SEED_PROFILE: u32 = 1;
/// Public intent serialization version is independent of the proof profile.
pub const INTENT_FORMAT_VERSION: u32 = 1;
pub const MAX_SEED_PROOF_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_UPLOAD_CHUNK_BYTES: usize = 2048;
/// Experimental native-program namespace, with ordinary ledger account state.
pub const SEED_CLAIM_PROGRAM: Address = [0x53; 32];
pub const MAX_SEED_ACCOUNT_BYTES: usize = MAX_SEED_PROOF_BYTES + 2048;
const ACCOUNT_MAGIC: &[u8; 8] = b"PQSEED02";
const PROOF_MAGIC: &[u8; 8] = b"SEEDPQ01";
const INTENT_DOMAIN: &[u8] = b"agave/pq/seed-migration/intent/v1";

/// Every value influencing the installed policy belongs to the proved intent.
/// `context` is a trusted migration activation/checkpoint context, not a context
/// selected by an unauthenticated claimant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationIntent {
    pub chain_id: Address,
    pub context: Address,
    pub authority: Address,
    pub replacement_key: FalconPublicKey,
    pub expected_generation: u64,
    pub claim_nonce: Address,
}

impl MigrationIntent {
    /// Fixed-width except for the validated Falcon encoding, whose length is
    /// also included explicitly. Includes an immutable unmigrated-state marker.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let key = self.replacement_key.as_bytes();
        let mut out = Vec::with_capacity(256 + key.len());
        out.extend_from_slice(INTENT_DOMAIN);
        out.extend_from_slice(&INTENT_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.authority);
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&self.expected_generation.to_le_bytes());
        out.push(1); // Must be an eligible, unmigrated external authority.
        out.extend_from_slice(&self.claim_nonce);
        out
    }

    pub fn commitment(&self) -> Commitment {
        hash_commitment(
            b"agave/pq/seed-migration/intent-hash/v1",
            &[&self.canonical_bytes()],
        )
    }
}

/// The circuit proves BOTH complete seed-to-address derivation and
/// C = SHA512("agave/pq/seed-migration/secret-intent/v1" || canonical_intent || s).
/// Including only a public transcript hash cannot prevent intent adaptation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedClaimStatement {
    pub intent: MigrationIntent,
    pub secret_intent_commitment: [u8; 64],
}

impl SeedClaimStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent.canonical_bytes();
        out.extend_from_slice(&self.secret_intent_commitment);
        out
    }

    /// One bounded, canonical public-input encoding for transactions/accounts.
    pub fn decode(bytes: &[u8]) -> Result<Self, SeedProofError> {
        let parse = || -> Result<Self, crate::transaction::WireError> {
            let mut r = crate::transaction::Reader::new(bytes);
            if r.take(INTENT_DOMAIN.len())? != INTENT_DOMAIN || r.u32()? != INTENT_FORMAT_VERSION {
                return Err(crate::transaction::WireError::Malformed);
            }
            let chain_id = r.take(32)?.try_into().unwrap();
            let context = r.take(32)?.try_into().unwrap();
            let authority = r.take(32)?.try_into().unwrap();
            if r.u32()? != 897 {
                return Err(crate::transaction::WireError::Malformed);
            }
            let replacement_key = FalconPublicKey::from_bytes(r.take(897)?)
                .map_err(|_| crate::transaction::WireError::Malformed)?;
            let expected_generation = r.u64()?;
            if r.u8()? != 1 {
                return Err(crate::transaction::WireError::Malformed);
            }
            let claim_nonce = r.take(32)?.try_into().unwrap();
            let secret_intent_commitment = r.take(64)?.try_into().unwrap();
            if !r.done() {
                return Err(crate::transaction::WireError::Malformed);
            }
            Ok(Self {
                intent: MigrationIntent {
                    chain_id,
                    context,
                    authority,
                    replacement_key,
                    expected_generation,
                    claim_nonce,
                },
                secret_intent_commitment,
            })
        };
        parse().map_err(|_| SeedProofError::InvalidProofEncoding)
    }
}

/// A sponsor cannot seize an arbitrary preexisting system account as an upload.
pub fn claim_address(sponsor: &Address, statement: &SeedClaimStatement) -> Address {
    let digest = hash_commitment(
        b"agave/pq/seed-migration/claim-address/v1",
        &[&statement.canonical_bytes()],
    );
    Pubkey::find_program_address(
        &[b"seedclaim", sponsor, &digest[..32]],
        &Pubkey::new_from_array(SEED_CLAIM_PROGRAM),
    )
    .0
    .to_bytes()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeedProofError {
    #[error("seed claims require generation zero and an unmigrated authority")]
    AlreadyMigrated,
    #[error("proof byte budget must be positive and at most 8 MiB")]
    InvalidProofBudget,
    #[error("only the authenticated sponsor may write or seal the claim buffer")]
    SponsorMismatch,
    #[error("claim buffer is sealed")]
    Sealed,
    #[error("upload chunks must be nonempty and at most 2048 bytes")]
    InvalidChunkSize,
    #[error("upload offset must equal the current byte length")]
    InvalidOffset,
    #[error("uploaded proof exceeds the funded byte budget")]
    ProofTooLarge,
    #[error("cannot seal an incomplete proof")]
    IncompleteUpload,
    #[error("claim buffer must be sealed before verification")]
    NotSealed,
    #[error("seed proof has an invalid canonical envelope")]
    InvalidProofEncoding,
    #[error("unsupported seed proof profile")]
    UnsupportedProfile,
    #[error("seed does not derive the claimed RFC 8032 public address")]
    InvalidSeedWitness,
    #[error("seed proof verification failed")]
    InvalidProof,
    #[error("seed claim account address, owner, funding or layout is invalid")]
    InvalidAccount,
    #[error("seed claim is already verified or consumed")]
    Completed,
}

/// Caller addresses must be resolved by the runtime's authoritative signer
/// checks. A caller-supplied address alone is not authentication. Funding/rent,
/// aggregate upload limits and cleanup refunds belong to the embedding runtime.
#[derive(Clone, Debug)]
pub struct SeedClaimBuffer {
    sponsor: Address,
    statement: SeedClaimStatement,
    funded_byte_budget: usize,
    proof: Vec<u8>,
    sealed_commitment: Option<Commitment>,
    verified_commitment: Option<Commitment>,
    consumed: bool,
}

impl SeedClaimBuffer {
    pub fn new(
        sponsor: Address,
        statement: SeedClaimStatement,
        proof_bytes: usize,
    ) -> Result<Self, SeedProofError> {
        if statement.intent.expected_generation != 0 {
            return Err(SeedProofError::AlreadyMigrated);
        }
        if proof_bytes == 0 || proof_bytes > MAX_SEED_PROOF_BYTES {
            return Err(SeedProofError::InvalidProofBudget);
        }
        Ok(Self {
            sponsor,
            statement,
            funded_byte_budget: proof_bytes,
            // Do not allocate an attacker-declared full proof before uploads.
            proof: Vec::new(),
            sealed_commitment: None,
            verified_commitment: None,
            consumed: false,
        })
    }

    pub fn append(
        &mut self,
        authenticated_sponsor: Address,
        offset: usize,
        chunk: &[u8],
    ) -> Result<(), SeedProofError> {
        if authenticated_sponsor != self.sponsor {
            return Err(SeedProofError::SponsorMismatch);
        }
        if self.sealed_commitment.is_some() {
            return Err(SeedProofError::Sealed);
        }
        if chunk.is_empty() || chunk.len() > MAX_UPLOAD_CHUNK_BYTES {
            return Err(SeedProofError::InvalidChunkSize);
        }
        if offset != self.proof.len() {
            return Err(SeedProofError::InvalidOffset);
        }
        let new_len = self
            .proof
            .len()
            .checked_add(chunk.len())
            .ok_or(SeedProofError::ProofTooLarge)?;
        if new_len > self.funded_byte_budget {
            return Err(SeedProofError::ProofTooLarge);
        }
        self.proof.extend_from_slice(chunk);
        Ok(())
    }

    pub fn seal(&mut self, authenticated_sponsor: Address) -> Result<Commitment, SeedProofError> {
        if authenticated_sponsor != self.sponsor {
            return Err(SeedProofError::SponsorMismatch);
        }
        if self.sealed_commitment.is_some() {
            return Err(SeedProofError::Sealed);
        }
        if self.proof.len() != self.funded_byte_budget {
            return Err(SeedProofError::IncompleteUpload);
        }
        let digest = hash_commitment(
            b"agave/pq/seed-migration/sealed-upload/v1",
            &[
                &self.sponsor,
                &self.statement.canonical_bytes(),
                &self.proof,
            ],
        );
        self.sealed_commitment = Some(digest);
        Ok(digest)
    }

    pub fn statement(&self) -> &SeedClaimStatement {
        &self.statement
    }

    pub fn uploaded_bytes(&self) -> usize {
        self.proof.len()
    }

    pub fn sealed_commitment(&self) -> Option<Commitment> {
        self.sealed_commitment
    }

    pub fn sponsor(&self) -> Address {
        self.sponsor
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn funded_byte_budget(&self) -> usize {
        self.funded_byte_budget
    }
    pub fn verified_commitment(&self) -> Option<Commitment> {
        self.verified_commitment
    }
    pub fn consumed(&self) -> bool {
        self.consumed
    }

    fn verification_binding(&self) -> Result<Commitment, SeedProofError> {
        Ok(hash_commitment(
            b"agave/pq/seed-migration/verified-ledger/v1",
            &[
                &self.proof_profile()?.to_le_bytes(),
                &self.sealed_commitment.ok_or(SeedProofError::NotSealed)?,
                &self.statement.canonical_bytes(),
            ],
        ))
    }

    pub fn proof_profile(&self) -> Result<u32, SeedProofError> {
        if self.proof.len() <= 16 || self.proof[..8] != *PROOF_MAGIC {
            return Err(SeedProofError::InvalidProofEncoding);
        }
        let profile = u32::from_le_bytes(self.proof[8..12].try_into().unwrap());
        if ![LEGACY_COMPLETE_SEED_PROFILE, COMPLETE_SEED_PROFILE].contains(&profile) {
            return Err(SeedProofError::UnsupportedProfile);
        }
        let size = u32::from_le_bytes(self.proof[12..16].try_into().unwrap()) as usize;
        if size != self.proof.len() - 16 {
            return Err(SeedProofError::InvalidProofEncoding);
        }
        if crate::seed_proof::proof_profile(&self.proof[16..])? != profile {
            return Err(SeedProofError::UnsupportedProfile);
        }
        Ok(profile)
    }

    /// Only native execution calls this after loading the program-owned account.
    /// There is no instruction that supplies a success flag or a verification root.
    pub fn verify_in_ledger(&mut self) -> Result<(), SeedProofError> {
        if self.verified_commitment.is_some() || self.consumed {
            return Err(SeedProofError::Completed);
        }
        self.verify()?;
        self.verified_commitment = Some(self.verification_binding()?);
        Ok(())
    }

    pub fn consume(&mut self) -> Result<(), SeedProofError> {
        if self.consumed || self.verified_commitment != Some(self.verification_binding()?) {
            return Err(SeedProofError::InvalidProof);
        }
        self.consumed = true;
        Ok(())
    }

    pub fn encode_account(&self) -> Vec<u8> {
        let statement = self.statement.canonical_bytes();
        let mut out = ACCOUNT_MAGIC.to_vec();
        out.extend_from_slice(&self.sponsor);
        out.extend_from_slice(&(self.funded_byte_budget as u32).to_le_bytes());
        out.extend_from_slice(&(statement.len() as u16).to_le_bytes());
        out.extend_from_slice(&statement);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        for commitment in [self.sealed_commitment, self.verified_commitment] {
            out.push(commitment.is_some() as u8);
            out.extend_from_slice(&commitment.unwrap_or([0; 48]));
        }
        out.push(self.consumed as u8);
        out
    }

    /// Rent reserves the full funded upload before any bytes are accepted.
    pub fn funded_account_bytes(&self) -> usize {
        // Fixed header + two optional 48-byte records + consumed flag. Do not
        // copy a multi-megabyte proof merely to calculate its reserved rent.
        149 + self.statement.canonical_bytes().len() + self.funded_byte_budget
    }

    pub fn from_account(address: &Address, account: &Account) -> Result<Self, SeedProofError> {
        if account.owner.to_bytes() != SEED_CLAIM_PROGRAM
            || account.executable
            || account.data.len() > MAX_SEED_ACCOUNT_BYTES
        {
            return Err(SeedProofError::InvalidAccount);
        }
        let parse = || -> Result<Self, crate::transaction::WireError> {
            let mut r = crate::transaction::Reader::new(&account.data);
            if r.take(8)? != ACCOUNT_MAGIC {
                return Err(crate::transaction::WireError::Malformed);
            }
            let sponsor = r.take(32)?.try_into().unwrap();
            let capacity = r.u32()? as usize;
            if capacity == 0 || capacity > MAX_SEED_PROOF_BYTES {
                return Err(crate::transaction::WireError::Bounds);
            }
            let statement_len = r.u16()? as usize;
            if statement_len > 2048 {
                return Err(crate::transaction::WireError::Bounds);
            }
            let statement = SeedClaimStatement::decode(r.take(statement_len)?)
                .map_err(|_| crate::transaction::WireError::Malformed)?;
            if statement.intent.expected_generation != 0 {
                return Err(crate::transaction::WireError::Malformed);
            }
            let proof_len = r.u32()? as usize;
            if proof_len > capacity {
                return Err(crate::transaction::WireError::Bounds);
            }
            let proof = r.take(proof_len)?.to_vec();
            let mut read_commitment =
                || -> Result<Option<Commitment>, crate::transaction::WireError> {
                    let flag = r.u8()?;
                    let bytes = r.take(48)?.try_into().unwrap();
                    match flag {
                        0 if bytes == [0; 48] => Ok(None),
                        1 => Ok(Some(bytes)),
                        _ => Err(crate::transaction::WireError::Malformed),
                    }
                };
            let sealed_commitment = read_commitment()?;
            let verified_commitment = read_commitment()?;
            let consumed = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(crate::transaction::WireError::Malformed),
            };
            if !r.done() {
                return Err(crate::transaction::WireError::Malformed);
            }
            Ok(Self {
                sponsor,
                statement,
                funded_byte_budget: capacity,
                proof,
                sealed_commitment,
                verified_commitment,
                consumed,
            })
        };
        let result = parse().map_err(|_| SeedProofError::InvalidAccount)?;
        if *address != claim_address(&result.sponsor, &result.statement)
            || account.lamports < result.funded_account_bytes() as u64
        {
            return Err(SeedProofError::InvalidAccount);
        }
        if let Some(sealed) = result.sealed_commitment
            && (result.proof.len() != result.funded_byte_budget
                || sealed
                    != hash_commitment(
                        b"agave/pq/seed-migration/sealed-upload/v1",
                        &[
                            &result.sponsor,
                            &result.statement.canonical_bytes(),
                            &result.proof,
                        ],
                    ))
        {
            return Err(SeedProofError::InvalidAccount);
        }
        if result.verified_commitment.is_some()
            && result.verified_commitment != Some(result.verification_binding()?)
            || result.consumed && result.verified_commitment.is_none()
        {
            return Err(SeedProofError::InvalidAccount);
        }
        Ok(result)
    }

    /// No injectable success callback, classical-signature fallback, revealed
    /// seed shortcut or test-only accepted proof exists. This uses recognized
    /// compiled-in circuit profiles and public inputs reconstructed
    /// from the sealed statement. Finalization must recheck on-chain eligibility
    /// atomically while holding the canonical auth account's write lock.
    pub fn verify(&self) -> Result<VerifiedSeedClaim, SeedProofError> {
        if self.sealed_commitment.is_none() {
            return Err(SeedProofError::NotSealed);
        }
        self.proof_profile()?;
        crate::seed_proof::verify_seed_proof(&self.statement, &self.proof[16..])?;
        Ok(VerifiedSeedClaim {
            intent: self.statement.intent.clone(),
            sealed_commitment: self.sealed_commitment.unwrap(),
        })
    }
}

/// Host verification result for diagnostics and compatibility. The bank never
/// trusts this object as migration authorization: only ledger records count.
#[derive(Debug)]
pub struct VerifiedSeedClaim {
    intent: MigrationIntent,
    sealed_commitment: Commitment,
}

/// Generate the private proof and its canonical upload envelope. Never upload
/// the seed: it is only a witness to the locally generated hiding STARK.
pub fn prove_seed_claim(
    seed: &[u8; 32],
    intent: MigrationIntent,
) -> Result<(SeedClaimStatement, Vec<u8>), SeedProofError> {
    let (statement, body) = crate::seed_proof::prove_seed_claim(seed, intent)?;
    if body.is_empty() || body.len() > MAX_SEED_PROOF_BYTES - 16 {
        return Err(SeedProofError::ProofTooLarge);
    }
    let mut proof = PROOF_MAGIC.to_vec();
    proof.extend_from_slice(&COMPLETE_SEED_PROFILE.to_le_bytes());
    proof.extend_from_slice(&(body.len() as u32).to_le_bytes());
    proof.extend_from_slice(&body);
    Ok((statement, proof))
}

impl VerifiedSeedClaim {
    pub fn intent(&self) -> &MigrationIntent {
        &self.intent
    }

    pub fn sealed_commitment(&self) -> Commitment {
        self.sealed_commitment
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::crypto::FalconKeypair};

    fn statement() -> SeedClaimStatement {
        SeedClaimStatement {
            intent: MigrationIntent {
                chain_id: [1; 32],
                context: [2; 32],
                authority: [3; 32],
                replacement_key: FalconKeypair::generate().public_key(),
                expected_generation: 0,
                claim_nonce: [4; 32],
            },
            secret_intent_commitment: [5; 64],
        }
    }

    fn alleged_proof(profile: u32) -> Vec<u8> {
        let mut proof = PROOF_MAGIC.to_vec();
        proof.extend_from_slice(&profile.to_le_bytes());
        proof.extend_from_slice(&1u32.to_le_bytes());
        proof.push(0);
        proof
    }

    #[test]
    fn staged_claim_cannot_authorize_migration() {
        let sponsor = [9; 32];
        let proof = alleged_proof(COMPLETE_SEED_PROFILE);
        let mut upload = SeedClaimBuffer::new(sponsor, statement(), proof.len()).unwrap();
        assert_eq!(upload.verify().unwrap_err(), SeedProofError::NotSealed);
        upload.append(sponsor, 0, &proof).unwrap();
        upload.seal(sponsor).unwrap();
        assert_eq!(
            upload.verify().unwrap_err(),
            SeedProofError::InvalidProofEncoding
        );
        assert_eq!(
            upload.append(sponsor, proof.len(), &[0]).unwrap_err(),
            SeedProofError::Sealed
        );
    }

    #[test]
    fn upload_guards_sponsor_offsets_funding_and_sealing() {
        let sponsor = [9; 32];
        let mut upload = SeedClaimBuffer::new(sponsor, statement(), 3).unwrap();
        assert_eq!(
            upload.append([8; 32], 0, &[1]).unwrap_err(),
            SeedProofError::SponsorMismatch
        );
        assert_eq!(
            upload.append(sponsor, 1, &[1]).unwrap_err(),
            SeedProofError::InvalidOffset
        );
        assert_eq!(
            upload.append(sponsor, 0, &[]).unwrap_err(),
            SeedProofError::InvalidChunkSize
        );
        assert_eq!(
            upload.seal(sponsor).unwrap_err(),
            SeedProofError::IncompleteUpload
        );
        upload.append(sponsor, 0, &[1, 2]).unwrap();
        assert_eq!(
            upload.append(sponsor, 2, &[3, 4]).unwrap_err(),
            SeedProofError::ProofTooLarge
        );
        assert_eq!(upload.uploaded_bytes(), 2);
        upload.append(sponsor, 2, &[3]).unwrap();
        assert_eq!(
            upload.seal([8; 32]).unwrap_err(),
            SeedProofError::SponsorMismatch
        );
        upload.seal(sponsor).unwrap();
        assert_eq!(
            upload.verify().unwrap_err(),
            SeedProofError::InvalidProofEncoding
        );
    }

    #[test]
    fn statement_and_upload_bind_all_replacement_intent() {
        let statement = statement();
        let original = statement.intent.commitment();
        let mut changed = statement.clone();
        changed.intent.chain_id[0] ^= 1;
        assert_ne!(original, changed.intent.commitment());
        changed = statement.clone();
        changed.intent.context[0] ^= 1;
        assert_ne!(original, changed.intent.commitment());
        changed = statement.clone();
        changed.intent.authority[0] ^= 1;
        assert_ne!(original, changed.intent.commitment());
        changed = statement.clone();
        changed.intent.replacement_key = FalconKeypair::generate().public_key();
        assert_ne!(original, changed.intent.commitment());
        changed = statement.clone();
        changed.intent.claim_nonce[0] ^= 1;
        assert_ne!(original, changed.intent.commitment());

        let proof = alleged_proof(COMPLETE_SEED_PROFILE);
        let mut a = SeedClaimBuffer::new([9; 32], statement.clone(), proof.len()).unwrap();
        a.append([9; 32], 0, &proof).unwrap();
        let seal_a = a.seal([9; 32]).unwrap();
        let mut b = SeedClaimBuffer::new([9; 32], changed, proof.len()).unwrap();
        b.append([9; 32], 0, &proof).unwrap();
        assert_ne!(seal_a, b.seal([9; 32]).unwrap());
    }

    #[test]
    fn accepts_no_unknown_profile_or_migrated_generation() {
        let proof = alleged_proof(3);
        let mut upload = SeedClaimBuffer::new([9; 32], statement(), proof.len()).unwrap();
        upload.append([9; 32], 0, &proof).unwrap();
        upload.seal([9; 32]).unwrap();
        assert_eq!(
            upload.verify().unwrap_err(),
            SeedProofError::UnsupportedProfile
        );
        let mut migrated = statement();
        migrated.intent.expected_generation = 1;
        assert_eq!(
            SeedClaimBuffer::new([9; 32], migrated, 1).unwrap_err(),
            SeedProofError::AlreadyMigrated
        );
        assert_eq!(
            SeedClaimBuffer::new([9; 32], statement(), MAX_SEED_PROOF_BYTES + 1).unwrap_err(),
            SeedProofError::InvalidProofBudget
        );
    }
}
