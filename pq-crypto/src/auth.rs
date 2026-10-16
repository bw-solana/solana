//! Canonical authentication accounts using Agave's account/address SDK types.

use {
    crate::{
        Address, Commitment,
        crypto::{FalconPublicKey, hash_commitment},
    },
    solana_account::Account,
    solana_pubkey::Pubkey,
    thiserror::Error,
};

/// Experimental namespace; a production AUTH_PROGRAM address needs a SIMD.
pub const AUTH_PROGRAM: Address = [0x51; 32];
pub const SYSTEM_PROGRAM: Address = [0; 32];
pub const MAX_ROTATIONS: usize = 128;
pub const AUTH_BASE_BYTES: usize = 8 + 32 + 897 + 48 + 8 + 1 + 1 + 2;
const MAGIC: &[u8; 8] = b"PQAUTH01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    OriginalSeed = 1,
    FreshIdentity = 2,
    /// Explicit classical consent accepted only before the immutable cutoff.
    LegacySignature = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRecord {
    pub authority: Address,
    pub public_key: FalconPublicKey,
    pub key_commitment: Commitment,
    pub generation: u64,
    pub origin: Origin,
    /// Retaining these prevents unexpired messages signed with retired keys
    /// becoming valid again. History is bounded and rotation fails on exhaustion.
    pub retired_keys: Vec<Commitment>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("authentication account address, owner, executable bit or layout is invalid")]
    InvalidRecord,
    #[error("Falcon public key is not canonically encoded")]
    InvalidKey,
    #[error("authentication generation changed")]
    GenerationMismatch,
    #[error("reinstating a retired or active key is forbidden")]
    RetiredKey,
    #[error("authentication rotation history is exhausted")]
    RotationExhausted,
}

pub fn auth_address(authority: &Address) -> Address {
    Pubkey::find_program_address(&[b"auth", authority], &Pubkey::new_from_array(AUTH_PROGRAM))
        .0
        .to_bytes()
}

pub fn key_commitment(key: &FalconPublicKey) -> Commitment {
    hash_commitment(b"agave-pq/auth-key/v1", &[key.as_bytes()])
}

pub fn fresh_address(chain: &Address, key: &FalconPublicKey, nonce: &Address) -> Address {
    let digest = hash_commitment(
        b"agave-pq/fresh-address/v1",
        &[chain, key.as_bytes(), nonce],
    );
    digest[..32].try_into().unwrap()
}

impl AuthRecord {
    pub fn new(authority: Address, public_key: FalconPublicKey, origin: Origin) -> Self {
        Self {
            authority,
            key_commitment: key_commitment(&public_key),
            public_key,
            generation: 1,
            origin,
            retired_keys: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_BASE_BYTES + 48 * self.retired_keys.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.authority);
        out.extend_from_slice(self.public_key.as_bytes());
        out.extend_from_slice(&self.key_commitment);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.push(self.origin as u8);
        out.push(1); // permanent legacy-disable and seed-claim-consumed policy
        out.extend_from_slice(&(self.retired_keys.len() as u16).to_le_bytes());
        for key in &self.retired_keys {
            out.extend_from_slice(key);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, AuthError> {
        if data.len() < AUTH_BASE_BYTES
            || data.len() > AUTH_BASE_BYTES + 48 * MAX_ROTATIONS
            || &data[..8] != MAGIC
        {
            return Err(AuthError::InvalidRecord);
        }
        let authority = data[8..40].try_into().unwrap();
        let public_key =
            FalconPublicKey::from_bytes(&data[40..937]).map_err(|_| AuthError::InvalidKey)?;
        let commitment: Commitment = data[937..985].try_into().unwrap();
        let generation = u64::from_le_bytes(data[985..993].try_into().unwrap());
        let origin = match data[993] {
            1 => Origin::OriginalSeed,
            2 => Origin::FreshIdentity,
            3 => Origin::LegacySignature,
            _ => return Err(AuthError::InvalidRecord),
        };
        let count = u16::from_le_bytes(data[995..997].try_into().unwrap()) as usize;
        if data[994] != 1
            || count > MAX_ROTATIONS
            || data.len() != AUTH_BASE_BYTES + count * 48
            || generation != (count as u64 + 1)
            || commitment != key_commitment(&public_key)
        {
            return Err(AuthError::InvalidRecord);
        }
        let retired_keys: Vec<Commitment> = data[AUTH_BASE_BYTES..].as_chunks::<48>().0.to_vec();
        let unique: std::collections::BTreeSet<_> = retired_keys.iter().collect();
        if unique.len() != count || retired_keys.contains(&commitment) {
            return Err(AuthError::InvalidRecord);
        }
        Ok(Self {
            authority,
            public_key,
            key_commitment: commitment,
            generation,
            origin,
            retired_keys,
        })
    }

    pub fn from_account(
        address: &Address,
        authority: &Address,
        account: &Account,
    ) -> Result<Self, AuthError> {
        if address != &auth_address(authority)
            || account.owner.to_bytes() != AUTH_PROGRAM
            || account.executable
        {
            return Err(AuthError::InvalidRecord);
        }
        let record = Self::decode(&account.data)?;
        if record.authority != *authority {
            return Err(AuthError::InvalidRecord);
        }
        Ok(record)
    }

    pub fn rotate(&mut self, expected: u64, key: FalconPublicKey) -> Result<(), AuthError> {
        if expected != self.generation {
            return Err(AuthError::GenerationMismatch);
        }
        let commitment = key_commitment(&key);
        if commitment == self.key_commitment || self.retired_keys.contains(&commitment) {
            return Err(AuthError::RetiredKey);
        }
        if self.retired_keys.len() == MAX_ROTATIONS {
            return Err(AuthError::RotationExhausted);
        }
        self.retired_keys.push(self.key_commitment);
        self.public_key = key;
        self.key_commitment = commitment;
        self.generation += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::crypto::FalconKeypair};

    #[test]
    fn record_checks_and_retired_key_guard() {
        let k = FalconKeypair::generate().public_key();
        let mut r = AuthRecord::new([7; 32], k.clone(), Origin::FreshIdentity);
        assert_eq!(AuthRecord::decode(&r.encode()).unwrap(), r);
        let mut malformed = r.encode();
        malformed[994] = 0;
        assert_eq!(
            AuthRecord::decode(&malformed),
            Err(AuthError::InvalidRecord)
        );
        let next = FalconKeypair::generate().public_key();
        assert_eq!(
            r.rotate(2, next.clone()),
            Err(AuthError::GenerationMismatch)
        );
        r.rotate(1, next).unwrap();
        assert_eq!(r.rotate(2, k), Err(AuthError::RetiredKey));
        assert_eq!(AuthRecord::decode(&r.encode()).unwrap(), r);
    }
}
