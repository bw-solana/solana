//! Experimental post-quantum authentication in the real Agave Bank and SVM.
//!
//! Public-key and proof uploads are ordinary program-owned AccountsDB accounts.
//! The existing 64-byte transaction signature field is an identifier in a PQ
//! envelope; authorization is the Falcon witness, checked again under account
//! locks before execution. This module does not use the research reference Bank.

use {
    crate::bank::Bank,
    agave_pq_crypto::{
        auth::{AUTH_PROGRAM, AuthRecord, auth_address},
        crypto::{Domain, FalconKeypair, FalconSignature, hash_commitment},
    },
    solana_account::{Account, AccountSharedData, ReadableAccount},
    solana_hash::Hash,
    solana_instruction::{AccountMeta, Instruction},
    solana_message::VersionedMessage,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_svm_transaction::svm_message::{SVMMessage, SVMStaticMessage},
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
    std::{
        collections::{BTreeMap, HashSet},
        sync::Arc,
    },
};

pub const CONFIG_ADDRESS: Pubkey = Pubkey::new_from_array([0x50; 32]);
/// Trusted immutable consensus bindings are part of the genuine genesis
/// AccountsDB state. This native program exposes no mutation instruction.
pub const ROLE_REGISTRY_ADDRESS: Pubkey = Pubkey::new_from_array([0x54; 32]);
pub const PROGRAM_ID: Pubkey = Pubkey::new_from_array(AUTH_PROGRAM);
const CONFIG_MAGIC: &[u8; 8] = b"AGAVEPQC";
pub const ENVELOPE_MAGIC: &[u8; 8] = b"AGAVEPQ1";
pub const MAX_TRANSACTION_BYTES: usize = 16 * 1024;
pub const MAX_SIGNERS: usize = 16;
pub const WITNESS_BYTES: usize = 666;
pub const ENVELOPE_HEADER_BYTES: usize = 9;
pub const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_UPLOAD_CHUNK_BYTES: usize = 8192;
pub const CREATE_UPLOAD: u8 = 1;
pub const WRITE_UPLOAD: u8 = 2;
pub const SEAL_UPLOAD: u8 = 3;
pub const INSTALL_LEGACY: u8 = 4;
pub const INSTALL_FRESH: u8 = 5;
pub const ROTATE: u8 = 6;
pub const VERIFY_SEED: u8 = 7;
pub const FINALIZE_SEED: u8 = 8;
pub const CLOSE_UPLOAD: u8 = 9;
pub const ROTATE_SPONSORED: u8 = 10;

/// Full-width replay authorization is separate from the stock truncated RPC
/// status cache. Native snapshots do not serialize it and therefore cannot
/// independently authorize PQ execution; genesis/journal replay rebuilds it.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReplayCache {
    slots: BTreeMap<u64, Arc<ReplaySlot>>,
    pub(crate) snapshot_incomplete: bool,
}

const REPLAY_BLOOM_WORDS: usize = 1024;

/// Immutable completed-slot buckets are shared by speculative branches. The
/// Bloom filter is only a negative lookup accelerator: a possible match always
/// requires the complete SHA384 identity in the exact set.
#[derive(Clone, Debug)]
struct ReplaySlot {
    identities: HashSet<[u8; 48]>,
    bloom: Box<[u64; REPLAY_BLOOM_WORDS]>,
}

impl Default for ReplaySlot {
    fn default() -> Self {
        Self {
            identities: HashSet::new(),
            bloom: Box::new([0; REPLAY_BLOOM_WORDS]),
        }
    }
}

impl ReplaySlot {
    fn positions(identity: &[u8; 48]) -> [usize; 4] {
        let start = u64::from_le_bytes(identity[..8].try_into().unwrap());
        let step = u64::from_le_bytes(identity[8..16].try_into().unwrap()) | 1;
        std::array::from_fn(|index| {
            start.wrapping_add(step.wrapping_mul(index as u64)) as usize
                & (REPLAY_BLOOM_WORDS * 64 - 1)
        })
    }

    fn insert(&mut self, identity: [u8; 48]) {
        for bit in Self::positions(&identity) {
            self.bloom[bit / 64] |= 1u64 << (bit % 64);
        }
        self.identities.insert(identity);
    }

    fn contains(&self, identity: &[u8; 48], positions: &[usize; 4]) -> bool {
        positions
            .iter()
            .all(|bit| self.bloom[bit / 64] & (1u64 << (bit % 64)) != 0)
            && self.identities.contains(identity)
    }
}

impl ReplayCache {
    pub(crate) fn unsupported_snapshot() -> Self {
        Self {
            snapshot_incomplete: true,
            ..Self::default()
        }
    }

    pub(crate) fn insert(&mut self, identity: [u8; 48], slot: u64) {
        Arc::make_mut(self.slots.entry(slot).or_default()).insert(identity);
    }

    pub(crate) fn processed_slot(
        &self,
        identity: &[u8; 48],
        ancestors: &solana_accounts_db::ancestors::Ancestors,
        roots: &HashSet<u64>,
    ) -> Option<u64> {
        let positions = ReplaySlot::positions(identity);
        self.slots.iter().rev().find_map(|(slot, bucket)| {
            (bucket.contains(identity, &positions)
                && (roots.contains(slot) || ancestors.contains_key(slot)))
            .then_some(*slot)
        })
    }

    pub(crate) fn clone_for_branch(
        &self,
        ancestors: &solana_accounts_db::ancestors::Ancestors,
        roots: &HashSet<u64>,
    ) -> Self {
        let parent_slot = ancestors.max_slot();
        Self {
            slots: self
                .slots
                .iter()
                .filter(|(slot, _)| {
                    ancestors.contains_key(slot) || (**slot <= parent_slot && roots.contains(slot))
                })
                .map(|(slot, bucket)| (*slot, Arc::clone(bucket)))
                .collect(),
            snapshot_incomplete: self.snapshot_incomplete,
        }
    }

    pub(crate) fn prune(&mut self, roots: &HashSet<u64>) {
        if let Some(oldest_root) = roots.iter().min() {
            self.slots.retain(|slot, _| slot >= oldest_root);
        }
    }

    pub(crate) fn clear_slot(&mut self, slot: u64) {
        self.slots.remove(&slot);
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub(crate) fn clear(&mut self) {
        self.slots.clear();
    }
}

/// Reconstruct every signed wire field from static message metadata, avoiding
/// the legacy SHA256 message hash entirely. Randomized Falcon witnesses are
/// normalized exactly as they are for signing.
pub(crate) fn replay_identity(
    message: &impl SVMStaticMessage,
    chain: &[u8; 32],
) -> Result<Option<[u8; 48]>, TransactionError> {
    use {
        solana_message::{Message, MessageHeader, compiled_instruction::CompiledInstruction, v0},
        solana_transaction::versioned::TransactionVersion,
    };
    let Some(first) = message.instructions_iter().next() else {
        return Ok(None);
    };
    if message
        .static_account_keys()
        .get(usize::from(first.program_id_index))
        != Some(&PROGRAM_ID)
        || !first.data.starts_with(ENVELOPE_MAGIC)
    {
        return Ok(None);
    }
    let header = MessageHeader {
        num_required_signatures: u8::try_from(message.num_transaction_signatures())
            .map_err(|_| TransactionError::SanitizeFailure)?,
        num_readonly_signed_accounts: message.num_readonly_signed_static_accounts(),
        num_readonly_unsigned_accounts: message.num_readonly_unsigned_static_accounts(),
    };
    let instructions = message
        .instructions_iter()
        .map(|instruction| CompiledInstruction {
            program_id_index: instruction.program_id_index,
            accounts: instruction.accounts.to_vec(),
            data: instruction.data.to_vec(),
        })
        .collect();
    let account_keys = message.static_account_keys().to_vec();
    let recent_blockhash = *message.recent_blockhash();
    let canonical = match message.version() {
        TransactionVersion::Legacy(_) => VersionedMessage::Legacy(Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        }),
        TransactionVersion::Number(0) => VersionedMessage::V0(v0::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups: message
                .message_address_table_lookups()
                .map(|lookup| v0::MessageAddressTableLookup {
                    account_key: *lookup.account_key,
                    writable_indexes: lookup.writable_indexes.to_vec(),
                    readonly_indexes: lookup.readonly_indexes.to_vec(),
                })
                .collect(),
        }),
        _ => return Err(TransactionError::UnsupportedVersion),
    };
    Ok(Some(hash_commitment(
        b"agave/pq/transaction-replay/v1",
        &[chain, &canonical_message(&canonical)?],
    )))
}

/// Each consensus leaf commits the complete native account, without first
/// compressing its state through Agave's legacy BLAKE3 accumulator.
pub(crate) fn account_leaf(address: &Pubkey, account: &impl ReadableAccount) -> [u8; 48] {
    hash_commitment(
        b"agave/pq/accounts-leaf/v1",
        &[
            address.as_ref(),
            account.owner().as_ref(),
            &account.lamports().to_le_bytes(),
            &[u8::from(account.executable())],
            &account.rent_epoch().to_le_bytes(),
            &(account.data().len() as u64).to_le_bytes(),
            account.data(),
        ],
    )
}

/// Pubkey order, field framing, distinct unary/binary domains and the leaf
/// count give every complete account set one canonical SHA384 Merkle root.
pub(crate) fn accounts_merkle_root(mut leaves: Vec<(Pubkey, [u8; 48])>) -> [u8; 48] {
    leaves.sort_unstable_by_key(|(address, _)| *address);
    assert!(
        leaves.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "AccountsDB scan returned duplicate visible addresses"
    );
    let count = leaves.len() as u64;
    let mut layer: Vec<_> = leaves.into_iter().map(|(_, leaf)| leaf).collect();
    let mut depth = 0u64;
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => hash_commitment(
                    b"agave/pq/accounts-inner/v1",
                    &[&depth.to_le_bytes(), left, right],
                ),
                [only] => {
                    hash_commitment(b"agave/pq/accounts-unary/v1", &[&depth.to_le_bytes(), only])
                }
                _ => unreachable!(),
            })
            .collect();
        depth += 1;
    }
    let tree = layer
        .first()
        .copied()
        .unwrap_or_else(|| hash_commitment(b"agave/pq/accounts-empty/v1", &[]));
    hash_commitment(b"agave/pq/accounts-root/v1", &[&count.to_le_bytes(), &tree])
}

pub fn upload_address(sponsor: &Pubkey, nonce: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"upload", sponsor.as_ref(), nonce], &PROGRAM_ID).0
}

/// Bind authority consent to the exact sealed payload, independently of the
/// reusable sponsor-owned upload address.
pub fn sealed_upload_commitment(sponsor: &Pubkey, nonce: &[u8; 32], payload: &[u8]) -> [u8; 48] {
    hash_commitment(
        b"agave/pq/svm-sealed-upload/v1",
        &[sponsor.as_ref(), nonce, payload],
    )
}

fn native_instruction(opcode: u8, mut accounts: Vec<AccountMeta>, bytes: &[u8]) -> Instruction {
    accounts.push(AccountMeta::new_readonly(CONFIG_ADDRESS, false));
    let mut data = vec![opcode];
    data.extend_from_slice(bytes);
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

pub fn create_upload_instruction(sponsor: &Pubkey, nonce: &[u8; 32], capacity: u32) -> Instruction {
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&capacity.to_le_bytes());
    native_instruction(
        CREATE_UPLOAD,
        vec![
            AccountMeta::new(*sponsor, true),
            AccountMeta::new(upload_address(sponsor, nonce), false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
        &bytes,
    )
}

pub fn write_upload_instruction(
    sponsor: &Pubkey,
    upload: &Pubkey,
    offset: u32,
    chunk: &[u8],
) -> Instruction {
    let mut bytes = offset.to_le_bytes().to_vec();
    bytes.extend_from_slice(chunk);
    native_instruction(
        WRITE_UPLOAD,
        vec![
            AccountMeta::new_readonly(*sponsor, true),
            AccountMeta::new(*upload, false),
        ],
        &bytes,
    )
}

pub fn seal_upload_instruction(sponsor: &Pubkey, upload: &Pubkey) -> Instruction {
    native_instruction(
        SEAL_UPLOAD,
        vec![
            AccountMeta::new_readonly(*sponsor, true),
            AccountMeta::new(*upload, false),
        ],
        &[],
    )
}

pub fn install_legacy_instruction(
    sponsor: &Pubkey,
    authority: &Pubkey,
    upload: &Pubkey,
    expected_commitment: &[u8; 48],
) -> Instruction {
    native_instruction(
        INSTALL_LEGACY,
        vec![
            AccountMeta::new(*sponsor, true),
            AccountMeta::new(*authority, true),
            AccountMeta::new(policy_address(authority), false),
            AccountMeta::new_readonly(*upload, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
        expected_commitment,
    )
}

pub fn install_fresh_instruction(
    sponsor: &Pubkey,
    authority: &Pubkey,
    upload: &Pubkey,
) -> Instruction {
    native_instruction(
        INSTALL_FRESH,
        vec![
            AccountMeta::new(*sponsor, true),
            AccountMeta::new(*authority, false),
            AccountMeta::new(policy_address(authority), false),
            AccountMeta::new_readonly(*upload, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
        &[],
    )
}

pub fn rotate_instruction(
    authority: &Pubkey,
    upload: &Pubkey,
    expected_generation: u64,
) -> Instruction {
    native_instruction(
        ROTATE,
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(policy_address(authority), false),
            AccountMeta::new_readonly(*upload, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
        &expected_generation.to_le_bytes(),
    )
}

/// Rotate any migrated authority, including program-owned accounts, using a
/// System-owned sponsor for upload and policy rent. Both parties consent to
/// the exact sealed key commitment and current generation.
pub fn rotate_sponsored_instruction(
    authority: &Pubkey,
    sponsor: &Pubkey,
    upload: &Pubkey,
    expected_generation: u64,
    expected_commitment: &[u8; 48],
) -> Instruction {
    let mut data = expected_generation.to_le_bytes().to_vec();
    data.extend_from_slice(expected_commitment);
    native_instruction(
        ROTATE_SPONSORED,
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(policy_address(authority), false),
            AccountMeta::new(*sponsor, true),
            AccountMeta::new_readonly(*upload, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
        &data,
    )
}

pub fn verify_seed_instruction(sponsor: &Pubkey, upload: &Pubkey) -> Instruction {
    native_instruction(
        VERIFY_SEED,
        vec![
            AccountMeta::new_readonly(*sponsor, true),
            AccountMeta::new(*upload, false),
        ],
        &[],
    )
}

pub fn finalize_seed_instruction(
    sponsor: &Pubkey,
    authority: &Pubkey,
    upload: &Pubkey,
) -> Instruction {
    native_instruction(
        FINALIZE_SEED,
        vec![
            AccountMeta::new(*sponsor, true),
            AccountMeta::new(*authority, false),
            AccountMeta::new(policy_address(authority), false),
            AccountMeta::new(*upload, false),
            AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        ],
        &[],
    )
}

pub fn close_upload_instruction(sponsor: &Pubkey, upload: &Pubkey) -> Instruction {
    native_instruction(
        CLOSE_UPLOAD,
        vec![
            AccountMeta::new(*sponsor, true),
            AccountMeta::new(*upload, false),
        ],
        &[],
    )
}

/// This immutable account is supplied by trusted genesis/checkpoint setup. No
/// instruction in the PQ program creates or modifies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub chain_id: [u8; 32],
    pub migration_context: [u8; 32],
    pub cutoff_slot: u64,
}

impl Config {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = CONFIG_MAGIC.to_vec();
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.migration_context);
        out.extend_from_slice(&self.cutoff_slot.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, TransactionError> {
        if data.len() != 80 || &data[..8] != CONFIG_MAGIC {
            return Err(TransactionError::InvalidAccountForFee);
        }
        Ok(Self {
            chain_id: data[8..40].try_into().unwrap(),
            migration_context: data[40..72].try_into().unwrap(),
            cutoff_slot: u64::from_le_bytes(data[72..80].try_into().unwrap()),
        })
    }

    pub fn account(&self, lamports: u64) -> Account {
        Account {
            lamports: lamports.max(1),
            data: self.encode(),
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
        }
    }
}

pub fn policy_address(authority: &Pubkey) -> Pubkey {
    Pubkey::new_from_array(auth_address(&authority.to_bytes()))
}

pub fn is_classical_authentication_program(program: &Pubkey) -> bool {
    program == &solana_sdk_ids::ed25519_program::id()
        || program == &solana_sdk_ids::secp256k1_program::id()
        || program == &solana_sdk_ids::secp256r1_program::id()
        || program == &solana_sdk_ids::zk_token_proof_program::id()
        || program == &solana_sdk_ids::zk_elgamal_proof_program::id()
}

/// PQ uses a bounded 16 KiB carrier on its dedicated validator branch. Every
/// transaction signer has one witness and one canonical policy dependency.
pub fn authenticate_instruction(authorities: &[Pubkey]) -> Instruction {
    assert!(!authorities.is_empty() && authorities.len() <= MAX_SIGNERS);
    let mut data = ENVELOPE_MAGIC.to_vec();
    data.push(authorities.len() as u8);
    data.resize(ENVELOPE_HEADER_BYTES + authorities.len() * WITNESS_BYTES, 0);
    let mut accounts = Vec::with_capacity(authorities.len() * 2 + 1);
    for authority in authorities {
        accounts.push(AccountMeta::new_readonly(*authority, true));
        accounts.push(AccountMeta::new_readonly(policy_address(authority), false));
    }
    accounts.push(AccountMeta::new_readonly(CONFIG_ADDRESS, false));
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

fn envelope(tx: &VersionedTransaction) -> Result<Option<Vec<FalconSignature>>, TransactionError> {
    let Some(ix) = tx.message.instructions().first() else {
        return Ok(None);
    };
    if tx
        .message
        .static_account_keys()
        .get(usize::from(ix.program_id_index))
        != Some(&PROGRAM_ID)
        || !ix.data.starts_with(ENVELOPE_MAGIC)
    {
        return Ok(None);
    }
    let count = usize::from(tx.message.header().num_required_signatures);
    if count == 0
        || count > MAX_SIGNERS
        || ix.data.len() != ENVELOPE_HEADER_BYTES + count * WITNESS_BYTES
        || usize::from(ix.data[8]) != count
    {
        return Err(TransactionError::SignatureFailure);
    }
    ix.data[ENVELOPE_HEADER_BYTES..]
        .as_chunks::<WITNESS_BYTES>()
        .0
        .iter()
        .map(|bytes| {
            FalconSignature::from_bytes(bytes).map_err(|_| TransactionError::SignatureFailure)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

pub fn is_pq_transaction(tx: &VersionedTransaction) -> bool {
    tx.message.instructions().first().is_some_and(|ix| {
        tx.message
            .static_account_keys()
            .get(usize::from(ix.program_id_index))
            == Some(&PROGRAM_ID)
            && ix.data.starts_with(ENVELOPE_MAGIC)
    })
}

pub fn canonical_message(message: &VersionedMessage) -> Result<Vec<u8>, TransactionError> {
    let count = usize::from(message.header().num_required_signatures);
    let mut message = message.clone();
    let instructions = match &mut message {
        VersionedMessage::Legacy(message) => &mut message.instructions,
        VersionedMessage::V0(message) => &mut message.instructions,
        VersionedMessage::V1(_) => return Err(TransactionError::UnsupportedVersion),
    };
    let ix = instructions
        .first_mut()
        .ok_or(TransactionError::SignatureFailure)?;
    if count == 0
        || count > MAX_SIGNERS
        || ix.data.len() != ENVELOPE_HEADER_BYTES + count * WITNESS_BYTES
        || !ix.data.starts_with(ENVELOPE_MAGIC)
        || usize::from(ix.data[8]) != count
    {
        return Err(TransactionError::SignatureFailure);
    }
    ix.data[ENVELOPE_HEADER_BYTES..].fill(0);
    Ok(message.serialize())
}

/// Sign a canonical ordinary Agave message with Falcon. The 64-byte ID commits
/// to the exact randomized witness and cannot be used to grant signer rights.
pub fn sign_transaction(
    mut message: VersionedMessage,
    config: &Config,
    keys: &[&FalconKeypair],
) -> Result<VersionedTransaction, TransactionError> {
    if keys.len() != usize::from(message.header().num_required_signatures) {
        return Err(TransactionError::SignatureFailure);
    }
    // Message compilation can reorder non-payer signers. The supplied keys
    // follow authenticate_instruction's authority order; the wire witnesses
    // and policy pairs follow the actual sanitized message-header order.
    let instructions = match &mut message {
        VersionedMessage::Legacy(message) => &mut message.instructions,
        VersionedMessage::V0(message) => &mut message.instructions,
        VersionedMessage::V1(_) => return Err(TransactionError::UnsupportedVersion),
    };
    let first = instructions
        .first_mut()
        .ok_or(TransactionError::SignatureFailure)?;
    if first.accounts.len() != keys.len() * 2 + 1 {
        return Err(TransactionError::SignatureFailure);
    }
    let pairs = first.accounts.clone();
    let mut ordered_keys = Vec::with_capacity(keys.len());
    for signer in 0..keys.len() {
        let position = (0..keys.len())
            .find(|position| usize::from(pairs[*position * 2]) == signer)
            .ok_or(TransactionError::SignatureFailure)?;
        first.accounts[signer * 2..signer * 2 + 2]
            .copy_from_slice(&pairs[position * 2..position * 2 + 2]);
        ordered_keys.push(keys[position]);
    }
    let unsigned = canonical_message(&message)?;
    let signatures = ordered_keys
        .iter()
        .map(|key| {
            key.sign(&config.chain_id, Domain::Transaction, &unsigned)
                .map_err(|_| TransactionError::SignatureFailure)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut message = message;
    let instructions = match &mut message {
        VersionedMessage::Legacy(message) => &mut message.instructions,
        VersionedMessage::V0(message) => &mut message.instructions,
        VersionedMessage::V1(_) => return Err(TransactionError::UnsupportedVersion),
    };
    for (position, signature) in signatures.iter().enumerate() {
        let start = ENVELOPE_HEADER_BYTES + position * WITNESS_BYTES;
        instructions[0].data[start..start + WITNESS_BYTES].copy_from_slice(signature.as_bytes());
    }
    let id = transaction_identifier(&message);
    Ok(VersionedTransaction {
        signatures: vec![id; keys.len()],
        message,
    })
}

/// Consensus replay keys transaction intent, not randomized Falcon witnesses.
pub fn canonical_message_hash(tx: &VersionedTransaction) -> Result<Hash, TransactionError> {
    if is_pq_transaction(tx) {
        canonical_message(&tx.message).map(|bytes| VersionedMessage::hash_raw_message(&bytes))
    } else {
        Ok(tx.message.hash())
    }
}

fn transaction_identifier(message: &VersionedMessage) -> Signature {
    use sha2::{Digest, Sha512};
    let mut hash = Sha512::new();
    hash.update(b"agave/pq/agave-transaction-id/v1");
    hash.update(message.serialize());
    Signature::from(<[u8; 64]>::from(hash.finalize()))
}

/// Cacheable complete canonical identity for native PQ admission bookkeeping.
/// This only identifies intent; it grants no signer or execution privileges.
pub fn transaction_intent_identity(
    transaction: &VersionedTransaction,
    chain: &[u8; 32],
) -> Result<[u8; 48], TransactionError> {
    if !is_pq_transaction(transaction) {
        return Err(TransactionError::UnsupportedVersion);
    }
    let sanitized =
        solana_transaction::versioned::sanitized::SanitizedVersionedTransaction::try_from(
            transaction.clone(),
        )
        .map_err(|_| TransactionError::SanitizeFailure)?;
    replay_identity(&sanitized, chain)?.ok_or(TransactionError::SignatureFailure)
}

impl Bank {
    /// Whether this canonical PQ intent is already committed on the visible
    /// fork. Exact SHA384 keys are independent of randomized witness/SDK IDs.
    /// This lookup does not authenticate a signature; callers must separately
    /// run ingress authentication and the authoritative locked execution gate.
    /// Legacy transactions use their separate pre-cutoff admission path.
    pub fn pq_transaction_processed(
        &self,
        transaction: &VersionedTransaction,
    ) -> Result<bool, TransactionError> {
        if !is_pq_transaction(transaction) {
            return Err(TransactionError::UnsupportedVersion);
        }
        let config = self
            .pq_config()?
            .ok_or(TransactionError::InvalidProgramForExecution)?;
        let identity = transaction_intent_identity(transaction, &config.chain_id)?;
        self.pq_intent_processed(&identity)
    }

    /// Query a locally prepared exact intent. Callers must still authenticate
    /// the current onchain signer policies under account locks before execution.
    pub fn pq_intent_processed(&self, identity: &[u8; 48]) -> Result<bool, TransactionError> {
        if self.pq_config()?.is_none() || !self.pq_replay_state_ready() {
            return Err(TransactionError::InvalidProgramForExecution);
        }
        // Match commit/root pruning's native-status -> exact-replay lock order.
        let statuses = self.status_cache.read().unwrap();
        let replay = self.pq_replay_cache.read().unwrap();
        Ok(replay
            .processed_slot(identity, &self.ancestors, statuses.roots())
            .is_some())
    }

    /// Experimental recovery must replay the PQ durable journal from genesis.
    /// Stock snapshots cannot restore full-width replay identities.
    pub fn pq_replay_state_ready(&self) -> bool {
        !self.pq_replay_cache.read().unwrap().snapshot_incomplete
    }
    pub fn verify_pq_transaction_for_ingress(
        &self,
        tx: &VersionedTransaction,
    ) -> Result<(), TransactionError> {
        use {
            solana_runtime_transaction::runtime_transaction::RuntimeTransaction,
            solana_transaction::sanitized::{MessageHash, SanitizedTransaction},
        };
        let limit = if is_pq_transaction(tx) {
            MAX_TRANSACTION_BYTES
        } else {
            solana_packet::PACKET_DATA_SIZE
        };
        if wincode::serialized_size(tx).map_err(|_| TransactionError::SanitizeFailure)? as usize
            > limit
        {
            return Err(TransactionError::SanitizeFailure);
        }
        let runtime = RuntimeTransaction::<SanitizedTransaction>::try_create(
            tx.clone(),
            MessageHash::Precomputed(canonical_message_hash(tx)?),
            None,
            self,
            self.get_reserved_account_keys(),
        )?;
        self.verify_pq_transaction(tx, &runtime)
    }

    pub fn pq_config(&self) -> Result<Option<Config>, TransactionError> {
        let Some(account) = self.get_account(&CONFIG_ADDRESS) else {
            return Ok(None);
        };
        // Merely funding this public address must not activate PQ checks or
        // break an ordinary cluster. Activation requires the trusted native
        // program-owned config; opted-in validator startup requires Some.
        if account.owner() != &PROGRAM_ID {
            return Ok(None);
        }
        if account.executable() {
            return Err(TransactionError::InvalidAccountForFee);
        }
        Config::decode(account.data()).map(Some)
    }

    /// Ingress may call this for early rejection. It MUST still run from
    /// check_transactions_before_execution after account locks are acquired.
    pub fn verify_pq_transaction(
        &self,
        tx: &VersionedTransaction,
        message: &impl SVMMessage,
    ) -> Result<(), TransactionError> {
        let Some(config) = self.pq_config()? else {
            return if is_pq_transaction(tx) {
                Err(TransactionError::SignatureFailure)
            } else {
                Ok(())
            };
        };
        if self.slot() >= config.cutoff_slot
            && message
                .program_instructions_iter()
                .any(|(program, _)| is_classical_authentication_program(program))
        {
            return Err(TransactionError::InvalidProgramForExecution);
        }
        if wincode::serialized_size(tx).map_err(|_| TransactionError::SanitizeFailure)? as usize
            > MAX_TRANSACTION_BYTES
        {
            return Err(TransactionError::SanitizeFailure);
        }
        let Some(signatures) = envelope(tx)? else {
            if self.slot() >= config.cutoff_slot {
                return Err(TransactionError::SignatureFailure);
            }
            // Migration permanently retires Ed25519 even before global cutoff.
            for authority in tx
                .message
                .static_account_keys()
                .iter()
                .take(usize::from(tx.message.header().num_required_signatures))
            {
                if self.get_account(&policy_address(authority)).is_some() {
                    return Err(TransactionError::SignatureFailure);
                }
            }
            // The PQ block execution bridge does not traverse classical TPU
            // sigverify, so authenticate allowed pre-cutoff legacy transactions.
            tx.verify_and_hash_message().map(|_| ())?;
            return Ok(());
        };
        if !self.pq_replay_state_ready() {
            return Err(TransactionError::InvalidProgramForExecution);
        }
        let keys = message.account_keys();
        let ix = tx.message.instructions().first().unwrap();
        if ix.accounts.len() != signatures.len() * 2 + 1
            || keys.get(usize::from(*ix.accounts.last().unwrap())) != Some(&CONFIG_ADDRESS)
            || message.is_writable(usize::from(*ix.accounts.last().unwrap()))
            || tx.signatures.len() != signatures.len()
            || tx
                .signatures
                .iter()
                .any(|signature| *signature != transaction_identifier(&tx.message))
        {
            return Err(TransactionError::SignatureFailure);
        }
        let canonical = canonical_message(&tx.message)?;
        for (position, signature) in signatures.iter().enumerate() {
            let authority = &tx.message.static_account_keys()[position];
            let policy = policy_address(authority);
            let authority_index = usize::from(ix.accounts[position * 2]);
            let policy_index = usize::from(ix.accounts[position * 2 + 1]);
            let rotates_policy = tx.message.instructions().iter().skip(1).any(|instruction| {
                tx.message
                    .static_account_keys()
                    .get(usize::from(instruction.program_id_index))
                    == Some(&PROGRAM_ID)
                    && matches!(
                        (instruction.data.first().copied(), instruction.data.len()),
                        (Some(ROTATE), 9) | (Some(ROTATE_SPONSORED), 57)
                    )
                    && instruction.accounts.len() >= 2
                    && usize::from(instruction.accounts[0]) == authority_index
                    && usize::from(instruction.accounts[1]) == policy_index
            });
            if keys.get(authority_index) != Some(authority)
                || keys.get(policy_index) != Some(&policy)
                || (message.is_writable(policy_index)
                    && !(rotates_policy && message.is_writable(authority_index)))
                || !message.is_signer(authority_index)
            {
                return Err(TransactionError::SignatureFailure);
            }
            let account: AccountSharedData = self
                .get_account(&policy)
                .ok_or(TransactionError::SignatureFailure)?;
            let account: Account = account.into();
            let record =
                AuthRecord::from_account(&policy.to_bytes(), &authority.to_bytes(), &account)
                    .map_err(|_| TransactionError::SignatureFailure)?;
            record
                .public_key
                .verify(&config.chain_id, Domain::Transaction, &canonical, signature)
                .map_err(|_| TransactionError::SignatureFailure)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::genesis_utils::{GenesisConfigInfo, create_genesis_config_with_leader},
        agave_pq_crypto::auth::{AuthRecord, Origin},
        solana_fee_calculator::FeeRateGovernor,
        solana_instruction_error::InstructionError,
        solana_keypair::Keypair,
        solana_message::Message,
        solana_program_runtime::{
            declare_process_instruction, program_cache_entry::ProgramCacheEntry,
            solana_sbpf::program::BuiltinFunctionDefinition,
        },
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
    };

    #[test]
    fn replay_slot_sharing_filters_forks_and_bloom_never_authorizes_a_match() {
        use solana_accounts_db::ancestors::Ancestors;
        let mut original = ReplayCache::default();
        let identities = (0u64..8192)
            .map(|index| hash_commitment(b"pq-replay-cache-test", &[&index.to_le_bytes()]))
            .collect::<Vec<_>>();
        for (index, identity) in identities.iter().enumerate() {
            original.insert(*identity, (index % 4) as u64);
        }
        let roots = HashSet::from([0, 1, 4]);
        let ancestors = Ancestors::from(vec![0, 1, 2]);
        let mut branch = original.clone_for_branch(&ancestors, &roots);
        assert_eq!(
            branch.slots.keys().copied().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(Arc::ptr_eq(&original.slots[&1], &branch.slots[&1]));
        for (index, identity) in identities.iter().enumerate() {
            assert_eq!(
                branch
                    .processed_slot(identity, &ancestors, &roots)
                    .is_some(),
                index % 4 != 3
            );
        }
        let independent = hash_commitment(b"pq-replay-other-branch", &[]);
        branch.insert(independent, 1);
        assert!(!Arc::ptr_eq(&original.slots[&1], &branch.slots[&1]));
        assert_eq!(
            original.processed_slot(&independent, &ancestors, &roots),
            None
        );
        assert_eq!(
            branch.processed_slot(&independent, &ancestors, &roots),
            Some(1)
        );
        let absent = hash_commitment(b"pq-replay-forced-bloom-false-positive", &[]);
        Arc::make_mut(branch.slots.get_mut(&1).unwrap())
            .bloom
            .fill(u64::MAX);
        assert_eq!(branch.processed_slot(&absent, &ancestors, &roots), None);
        branch.clear_slot(1);
        assert!(original.slots.contains_key(&1));
        branch.prune(&HashSet::from([2]));
        assert_eq!(branch.slots.keys().copied().collect::<Vec<_>>(), vec![2]);
        assert_eq!(original.slots.len(), 4);
    }

    declare_process_instruction!(NativeAuthorityCpiProbe, 2_000, |invoke| {
        let context = invoke
            .transaction_context
            .get_current_instruction_context()?;
        let data = context.get_instruction_data();
        if data.len() != 8 || !context.is_instruction_account_signer(0)? {
            return Err(InstructionError::MissingRequiredSignature);
        }
        let authority = *context.get_key_of_instruction_account(0)?;
        let recipient = *context.get_key_of_instruction_account(2)?;
        let amount = u64::from_le_bytes(data.try_into().unwrap());
        let counter = {
            let state = context.try_borrow_instruction_account(1)?;
            if state.get_owner() != context.get_program_key()?
                || state.get_data().len() != 40
                || state.get_data()[..32] != authority.to_bytes()
            {
                return Err(InstructionError::InvalidAccountData);
            }
            u64::from_le_bytes(state.get_data()[32..].try_into().unwrap())
        };
        // This custom program cannot debit the system-owned authority directly.
        // It delegates to the actual System Program, propagating the signer
        // privilege supplied only after the Bank authenticated Falcon.
        invoke.native_invoke_signed(
            system_instruction::transfer(&authority, &recipient, amount),
            &[],
        )?;
        let context = invoke
            .transaction_context
            .get_current_instruction_context()?;
        let mut state = context.try_borrow_instruction_account(1)?;
        state.get_data_mut()?[32..].copy_from_slice(
            &counter
                .checked_add(1)
                .ok_or(InstructionError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        Ok(())
    });

    declare_process_instruction!(NativeClassicalProofCpiProbe, 1_000, |invoke| {
        let context = invoke
            .transaction_context
            .get_current_instruction_context()?;
        let program = *context.get_key_of_instruction_account(0)?;
        let data = context.get_instruction_data().to_vec();
        invoke.native_invoke_signed(
            Instruction {
                program_id: program,
                accounts: vec![],
                data,
            },
            &[],
        )
    });

    fn configured_bank(
        cutoff_slot: u64,
        install_policy: bool,
    ) -> (Bank, Keypair, FalconKeypair, Config) {
        configured_bank_with_config(
            Config {
                chain_id: [0x23; 32],
                migration_context: [0x29; 32],
                cutoff_slot,
            },
            install_policy,
            10_000_000_000,
        )
    }

    fn configured_bank_with_config(
        config: Config,
        install_policy: bool,
        lamports: u64,
    ) -> (Bank, Keypair, FalconKeypair, Config) {
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(lamports, &Pubkey::new_unique(), 1_000_000_000);
        genesis_config.rent = solana_rent::Rent::default();
        genesis_config.fee_rate_governor = FeeRateGovernor::new(5_000, 0);
        genesis_config.accounts.insert(
            CONFIG_ADDRESS,
            config.account(genesis_config.rent.minimum_balance(80)),
        );
        let key = FalconKeypair::generate();
        if install_policy {
            let record = AuthRecord::new(
                mint_keypair.pubkey().to_bytes(),
                key.public_key(),
                Origin::FreshIdentity,
            );
            let data = record.encode();
            genesis_config.accounts.insert(
                policy_address(&mint_keypair.pubkey()),
                Account {
                    lamports: genesis_config.rent.minimum_balance(data.len()),
                    data,
                    owner: PROGRAM_ID,
                    executable: false,
                    rent_epoch: u64::MAX,
                },
            );
        }
        let bank = Bank::new_for_tests(&genesis_config);
        assert_eq!(bank.pq_config().unwrap(), Some(config.clone()));
        assert!(bank.get_account(&PROGRAM_ID).is_some());
        (bank, mint_keypair, key, config)
    }

    fn signed(
        bank: &Bank,
        authority: Pubkey,
        key: &FalconKeypair,
        config: &Config,
        instructions: &[Instruction],
    ) -> VersionedTransaction {
        let mut all = vec![authenticate_instruction(&[authority])];
        all.extend_from_slice(instructions);
        sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &all,
                Some(&authority),
                &bank.last_blockhash(),
            )),
            config,
            &[key],
        )
        .unwrap()
    }

    fn execute_ok(bank: &Bank, tx: VersionedTransaction) {
        let result = bank.process_transaction_with_metadata(tx).unwrap();
        assert_eq!(result.status, Ok(()), "{:?}", result.log_messages);
    }

    #[test]
    fn full_width_accounts_merkle_binds_every_native_field_and_canonical_order() {
        let address = Pubkey::new_unique();
        let original = Account {
            lamports: 42,
            data: vec![1, 2, 3],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 7,
        };
        let original_leaf = account_leaf(&address, &original);
        assert_ne!(
            original_leaf,
            account_leaf(&Pubkey::new_unique(), &original)
        );
        for changed in [
            Account {
                lamports: 43,
                ..original.clone()
            },
            Account {
                owner: Pubkey::new_unique(),
                ..original.clone()
            },
            Account {
                executable: true,
                ..original.clone()
            },
            Account {
                rent_epoch: 8,
                ..original.clone()
            },
            Account {
                data: vec![1, 2, 4],
                ..original.clone()
            },
            Account {
                data: vec![1, 2, 3, 0],
                ..original.clone()
            },
        ] {
            assert_ne!(original_leaf, account_leaf(&address, &changed));
        }
        let a = (address, original_leaf);
        let b = (
            Pubkey::new_unique(),
            account_leaf(&Pubkey::new_unique(), &original),
        );
        let c = (
            Pubkey::new_unique(),
            account_leaf(&Pubkey::new_unique(), &original),
        );
        let canonical = accounts_merkle_root(vec![a, b, c]);
        assert_eq!(canonical, accounts_merkle_root(vec![c, a, b]));
        assert_ne!(canonical, accounts_merkle_root(vec![a, b]));
        assert_ne!(accounts_merkle_root(vec![]), accounts_merkle_root(vec![a]));
    }

    #[test]
    fn real_bank_frozen_pq_root_is_cached_and_cow_child_ignores_stale_storage() {
        let (bank, authority, _key, _config) = configured_bank(0, true);
        let (parent, _forks) = bank.wrap_with_bank_forks_for_tests();
        parent.freeze();
        let frozen_root = parent.pq_state_commitment();
        let original = parent.get_account(&authority.pubkey()).unwrap();
        let mut changed = original.clone();
        changed.set_data_from_slice(b"inconsistent storage visible after freeze");
        // This deliberately bypasses normal immutable Bank commits to reproduce
        // the stale shared-storage failure private candidate isolation prevents.
        parent.rc.accounts.store_accounts(
            (parent.slot(), &[(authority.pubkey(), changed)][..]),
            parent.bank_id(),
            None,
            &parent.ancestors,
        );
        assert_eq!(parent.pq_state_commitment(), frozen_root);
        let child = Bank::new_isolated_pq_child(parent.clone(), *parent.leader(), 1).unwrap();
        // The child inherits the actual immutable account view bound by the
        // cached commitment, rather than re-reading corrupted backing storage.
        assert_eq!(child.get_account(&authority.pubkey()).unwrap(), original);
        assert_ne!(
            child.get_account(&authority.pubkey()),
            parent.get_account(&authority.pubkey())
        );
    }

    fn upload_key(
        bank: &Bank,
        sponsor: Pubkey,
        key: &FalconKeypair,
        config: &Config,
        bytes: &[u8],
        nonce: [u8; 32],
    ) -> Pubkey {
        let upload = upload_address(&sponsor, &nonce);
        execute_ok(
            bank,
            signed(
                bank,
                sponsor,
                key,
                config,
                &[create_upload_instruction(
                    &sponsor,
                    &nonce,
                    bytes.len() as u32,
                )],
            ),
        );
        execute_ok(
            bank,
            signed(
                bank,
                sponsor,
                key,
                config,
                &[write_upload_instruction(&sponsor, &upload, 0, bytes)],
            ),
        );
        execute_ok(
            bank,
            signed(
                bank,
                sponsor,
                key,
                config,
                &[seal_upload_instruction(&sponsor, &upload)],
            ),
        );
        upload
    }

    fn legacy_upload_key(bank: &Bank, sponsor: &Keypair, bytes: &[u8], nonce: [u8; 32]) -> Pubkey {
        let upload = upload_address(&sponsor.pubkey(), &nonce);
        for instruction in [
            create_upload_instruction(&sponsor.pubkey(), &nonce, bytes.len() as u32),
            write_upload_instruction(&sponsor.pubkey(), &upload, 0, bytes),
            seal_upload_instruction(&sponsor.pubkey(), &upload),
        ] {
            execute_ok(
                bank,
                Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&sponsor.pubkey()),
                    &[sponsor],
                    bank.last_blockhash(),
                )
                .into(),
            );
        }
        upload
    }

    fn store_move_funds_sbf(bank: &Bank, program: Pubkey) {
        let elf = include_bytes!("../tests/fixtures/pq-svm/move_funds.so").to_vec();
        let account: AccountSharedData = Account {
            lamports: bank.get_minimum_balance_for_rent_exemption(elf.len()),
            data: elf,
            owner: solana_sdk_ids::bpf_loader::id(),
            executable: true,
            rent_epoch: u64::MAX,
        }
        .into();
        bank.store_account(&program, &account);
    }

    fn sbf_move_instruction(source: Pubkey, program: Pubkey, recipient: Pubkey) -> Instruction {
        Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(source, true),
                AccountMeta::new_readonly(program, false),
                AccountMeta::new(recipient, false),
            ],
            data: 1_000_000u64.to_le_bytes().to_vec(),
        }
    }

    fn signed_sbf_move(
        bank: &Bank,
        participants: [(Pubkey, &FalconKeypair); 2],
        config: &Config,
        program: Pubkey,
        recipient: Pubkey,
    ) -> VersionedTransaction {
        let [(sponsor, sponsor_key), (authority, authority_key)] = participants;
        sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[sponsor, authority]),
                    sbf_move_instruction(authority, program, recipient),
                ],
                Some(&sponsor),
                &bank.last_blockhash(),
            )),
            config,
            &[sponsor_key, authority_key],
        )
        .unwrap()
    }

    #[test]
    fn real_sbf_nonce_and_spl_assets_survive_legacy_enrollment_and_cutoff() {
        use crate::pq_workload as app;
        let (bank, owner, owner_key, config) = configured_bank(3, false);
        let recipient = Keypair::new();
        let recipient_key = FalconKeypair::generate();
        let mint = Pubkey::new_unique();
        let token = spl_generic_token::token::ID;
        let ata = spl_generic_token::associated_token_account::ID;
        let associated = |authority: &Pubkey| {
            Pubkey::find_program_address(&[authority.as_ref(), token.as_ref(), mint.as_ref()], &ata)
                .0
        };
        let source = associated(&owner.pubkey());
        let destination = associated(&recipient.pubkey());
        for (address, account) in
            solana_program_binaries::spl_programs(&solana_rent::Rent::default())
        {
            bank.store_account(&address, &account);
        }
        for (address, account) in app::program_accounts(&solana_rent::Rent::default()) {
            bank.store_account(&address, &account.into());
        }
        bank.store_account(
            &recipient.pubkey(),
            &AccountSharedData::new(10_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        let mut mint_data = vec![0; 82];
        mint_data[..4].copy_from_slice(&1u32.to_le_bytes());
        mint_data[4..36].copy_from_slice(owner.pubkey().as_ref());
        mint_data[36..44].copy_from_slice(&1_000_000u64.to_le_bytes());
        mint_data[44] = 6;
        mint_data[45] = 1;
        mint_data[46..50].copy_from_slice(&1u32.to_le_bytes());
        mint_data[50..82].copy_from_slice(owner.pubkey().as_ref());
        let mut source_data = vec![0; 165];
        source_data[..32].copy_from_slice(mint.as_ref());
        source_data[32..64].copy_from_slice(owner.pubkey().as_ref());
        source_data[64..72].copy_from_slice(&1_000_000u64.to_le_bytes());
        source_data[108] = 1;
        for (address, data) in [(mint, mint_data), (source, source_data)] {
            bank.store_account(
                &address,
                &Account {
                    lamports: bank.get_minimum_balance_for_rent_exemption(data.len()),
                    data,
                    owner: token,
                    ..Account::default()
                }
                .into(),
            );
        }
        let (genesis, _forks) = bank.wrap_with_bank_forks_for_tests();
        let bank = std::sync::Arc::new(
            Bank::new_isolated_pq_child(genesis.clone(), *genesis.leader(), 1).unwrap(),
        );
        let create_ata = Instruction {
            program_id: ata,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(recipient.pubkey(), false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
                AccountMeta::new_readonly(token, false),
            ],
            data: vec![1],
        };
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[create_ata],
                Some(&owner.pubkey()),
                &[&owner],
                bank.last_blockhash(),
            )
            .into(),
        );
        let transfer = |from: Pubkey, to: Pubkey, authority: Pubkey, amount: u64| {
            let mut data = vec![12];
            data.extend_from_slice(&amount.to_le_bytes());
            data.push(6);
            Instruction {
                program_id: token,
                accounts: vec![
                    AccountMeta::new(from, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new(to, false),
                    AccountMeta::new_readonly(authority, true),
                ],
                data,
            }
        };
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[transfer(source, destination, owner.pubkey(), 17)],
                Some(&owner.pubkey()),
                &[&owner],
                bank.last_blockhash(),
            )
            .into(),
        );
        let before_mint = bank.get_account(&mint).unwrap();
        let before_source = bank.get_account(&source).unwrap();
        let before_destination = bank.get_account(&destination).unwrap();
        for (authority, key, nonce) in [
            (&recipient, &recipient_key, [0x75; 32]),
            (&owner, &owner_key, [0x76; 32]),
        ] {
            let upload = legacy_upload_key(&bank, &owner, key.public_key().as_bytes(), nonce);
            let signers = if authority.pubkey() == owner.pubkey() {
                vec![&owner]
            } else {
                vec![&owner, authority]
            };
            execute_ok(
                &bank,
                Transaction::new_signed_with_payer(
                    &[install_legacy_instruction(
                        &owner.pubkey(),
                        &authority.pubkey(),
                        &upload,
                        &sealed_upload_commitment(
                            &owner.pubkey(),
                            &nonce,
                            key.public_key().as_bytes(),
                        ),
                    )],
                    Some(&owner.pubkey()),
                    &signers,
                    bank.last_blockhash(),
                )
                .into(),
            );
        }
        assert_eq!(bank.get_account(&mint).unwrap(), before_mint);
        assert_eq!(bank.get_account(&source).unwrap(), before_source);
        assert_eq!(bank.get_account(&destination).unwrap(), before_destination);
        let post = Bank::new_isolated_pq_child(bank.clone(), *bank.leader(), 3).unwrap();
        let token_transfer = transfer(source, destination, owner.pubkey(), 23);
        let mut instructions = vec![
            authenticate_instruction(&[owner.pubkey()]),
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                20_000,
            ),
            token_transfer,
            app::nonce_instruction(5, 1),
        ];
        let tx = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &instructions,
                Some(&owner.pubkey()),
                &post.last_blockhash(),
            )),
            &config,
            &[&owner_key],
        )
        .unwrap();
        let metadata = post.process_transaction_with_metadata(tx.clone()).unwrap();
        assert_eq!(metadata.status, Ok(()), "{:?}", metadata.log_messages);
        println!(
            "PQ_SOAK_SPL_TRANSFER_AND_SBF_NONCE_CU={}",
            metadata.executed_units
        );
        assert!(metadata.executed_units < 20_000);
        let amount = |account: AccountSharedData| {
            u64::from_le_bytes(account.data()[64..72].try_into().unwrap())
        };
        assert_eq!(amount(post.get_account(&source).unwrap()), 999_960);
        assert_eq!(amount(post.get_account(&destination).unwrap()), 40);
        let before_fee = post.get_balance(&owner.pubkey());
        let replay = sign_transaction(tx.message.clone(), &config, &[&owner_key]).unwrap();
        assert_eq!(
            post.process_transaction_with_metadata(replay).unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        assert_eq!(post.get_balance(&owner.pubkey()), before_fee);
        let wrong_owner = transfer(source, destination, recipient.pubkey(), 1);
        let failed = post
            .process_transaction_with_metadata(signed(
                &post,
                recipient.pubkey(),
                &recipient_key,
                &config,
                &[wrong_owner],
            ))
            .unwrap();
        assert!(failed.status.is_err());
        assert_eq!(amount(post.get_account(&source).unwrap()), 999_960);
        assert_eq!(amount(post.get_account(&destination).unwrap()), 40);
        let freeze = |opcode| Instruction {
            program_id: token,
            accounts: vec![
                AccountMeta::new(source, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(owner.pubkey(), true),
            ],
            data: vec![opcode],
        };
        execute_ok(
            &post,
            signed(&post, owner.pubkey(), &owner_key, &config, &[freeze(10)]),
        );
        assert_eq!(post.get_account(&source).unwrap().data()[108], 2);
        let frozen_attempt = post
            .process_transaction_with_metadata(signed(
                &post,
                owner.pubkey(),
                &owner_key,
                &config,
                &[transfer(source, destination, owner.pubkey(), 1)],
            ))
            .unwrap();
        assert!(frozen_attempt.status.is_err());
        assert_eq!(amount(post.get_account(&source).unwrap()), 999_960);
        execute_ok(
            &post,
            signed(&post, owner.pubkey(), &owner_key, &config, &[freeze(11)]),
        );
        assert_eq!(post.get_account(&source).unwrap().data()[108], 1);
        execute_ok(
            &post,
            signed(
                &post,
                recipient.pubkey(),
                &recipient_key,
                &config,
                &[transfer(destination, source, recipient.pubkey(), 5)],
            ),
        );
        assert_eq!(amount(post.get_account(&source).unwrap()), 999_965);
        assert_eq!(amount(post.get_account(&destination).unwrap()), 35);
        assert_eq!(post.get_account(&mint).unwrap(), before_mint);
        assert_eq!(
            &post.get_account(&source).unwrap().data()[32..64],
            owner.pubkey().as_ref()
        );
        assert_eq!(
            &post.get_account(&destination).unwrap().data()[32..64],
            recipient.pubkey().as_ref()
        );
        instructions = vec![
            authenticate_instruction(&[owner.pubkey()]),
            app::nonce_instruction(6, 2),
        ];
        let noop = post
            .process_transaction_with_metadata(
                sign_transaction(
                    VersionedMessage::Legacy(Message::new_with_blockhash(
                        &instructions,
                        Some(&owner.pubkey()),
                        &post.last_blockhash(),
                    )),
                    &config,
                    &[&owner_key],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(noop.status, Ok(()));
        println!("PQ_SOAK_SBF_NONCE_CU={}", noop.executed_units);
        assert!(noop.executed_units < 20_000);
    }

    #[test]
    fn rich_sbf_legacy_migration_preserves_pda_multisig_and_atomic_cpi_state() {
        use crate::pq_workload::{self as app, Accounts as AppAccounts, State as AppState};
        let (bank, sponsor, sponsor_key, config) = configured_bank(2, false);
        let primary = Keypair::new();
        let secondary = Keypair::new();
        let primary_key = FalconKeypair::generate();
        let secondary_key = FalconKeypair::generate();
        let recipient = Pubkey::new_unique();
        let mut initial_data = AppState::new(primary.pubkey(), secondary.pubkey()).encode(4096);
        for (index, byte) in initial_data[app::STATE_BYTES..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        for (address, account) in app::program_accounts(&solana_rent::Rent::default()) {
            bank.store_account(&address, &account.into());
        }
        bank.store_account(
            &primary.pubkey(),
            &Account {
                lamports: 50_000_000,
                data: initial_data,
                owner: app::PROGRAM_ID,
                ..Account::default()
            }
            .into(),
        );
        for address in [secondary.pubkey(), recipient] {
            bank.store_account(
                &address,
                &AccountSharedData::new(10_000_000, 0, &solana_sdk_ids::system_program::id()),
            );
        }
        let accounts = AppAccounts {
            state: primary.pubkey(),
            primary: primary.pubkey(),
            secondary: secondary.pubkey(),
            sponsor: sponsor.pubkey(),
            recipient,
        };
        let escrow = app::escrow_address(&accounts.state);
        let escrow_rent = bank.get_minimum_balance_for_rent_exemption(0);
        let (genesis, _forks) = bank.wrap_with_bank_forks_for_tests();
        // UpgradeableLoader's slot-zero genesis program becomes executable in
        // slot one, exactly as it does in the native validator replay path.
        let bank = std::sync::Arc::new(
            Bank::new_isolated_pq_child(genesis.clone(), *genesis.leader(), 1).unwrap(),
        );
        for instruction in [
            accounts.initialize(escrow_rent, 1),
            accounts.deposit(5_000_000, 2),
        ] {
            execute_ok(
                &bank,
                Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&sponsor.pubkey()),
                    &[&sponsor, &primary],
                    bank.last_blockhash(),
                )
                .into(),
            );
        }
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[accounts.withdraw(1_000_000, 3)],
                Some(&sponsor.pubkey()),
                &[&sponsor, &primary, &secondary],
                bank.last_blockhash(),
            )
            .into(),
        );
        let before_migration = bank.get_account(&primary.pubkey()).unwrap();
        let escrow_before_migration = bank.get_account(&escrow).unwrap();
        assert_eq!(
            escrow_before_migration.owner(),
            &solana_sdk_ids::system_program::id()
        );
        assert_eq!(escrow_before_migration.lamports(), escrow_rent + 4_000_000);
        // Both actual Ed authorities consent; the fee sponsor is enrolled last
        // because installed policies immediately disable its legacy signatures.
        for (authority, key, nonce) in [
            (&primary, &primary_key, [0x71; 32]),
            (&secondary, &secondary_key, [0x72; 32]),
            (&sponsor, &sponsor_key, [0x73; 32]),
        ] {
            let upload = legacy_upload_key(&bank, &sponsor, key.public_key().as_bytes(), nonce);
            let instruction = install_legacy_instruction(
                &sponsor.pubkey(),
                &authority.pubkey(),
                &upload,
                &sealed_upload_commitment(&sponsor.pubkey(), &nonce, key.public_key().as_bytes()),
            );
            let signers = if authority.pubkey() == sponsor.pubkey() {
                vec![&sponsor]
            } else {
                vec![&sponsor, authority]
            };
            execute_ok(
                &bank,
                Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&sponsor.pubkey()),
                    &signers,
                    bank.last_blockhash(),
                )
                .into(),
            );
        }
        assert_eq!(
            bank.get_account(&primary.pubkey()).unwrap(),
            before_migration
        );
        assert_eq!(bank.get_account(&escrow).unwrap(), escrow_before_migration);
        let post = Bank::new_isolated_pq_child(bank.clone(), *bank.leader(), 2).unwrap();
        let sign_with = |instruction: Instruction, current_primary: &FalconKeypair| {
            sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[
                        authenticate_instruction(&[
                            sponsor.pubkey(),
                            primary.pubkey(),
                            secondary.pubkey(),
                        ]),
                        instruction,
                    ],
                    Some(&sponsor.pubkey()),
                    &post.last_blockhash(),
                )),
                &config,
                &[&sponsor_key, current_primary, &secondary_key],
            )
            .unwrap()
        };
        let sign = |instruction| sign_with(instruction, &primary_key);
        let valid = sign(accounts.withdraw(2_000_000, 4));
        execute_ok(&post, valid.clone());
        let baseline_state = post.get_account(&primary.pubkey()).unwrap();
        let baseline_escrow = post.get_account(&escrow).unwrap();
        let baseline_recipient = post.get_account(&recipient).unwrap();
        assert_eq!(baseline_escrow.lamports(), escrow_rent + 2_000_000);
        assert_eq!(baseline_state.owner(), &app::PROGRAM_ID);
        assert_eq!(
            &baseline_state.data()[app::STATE_BYTES..],
            &before_migration.data()[app::STATE_BYTES..]
        );
        let failed = |instruction: Instruction, expected: InstructionError| {
            let before_fee = post.get_balance(&sponsor.pubkey());
            let result = post
                .process_transaction_with_metadata(sign(instruction))
                .unwrap();
            assert_eq!(
                result.status,
                Err(TransactionError::InstructionError(1, expected))
            );
            assert_eq!(post.get_balance(&sponsor.pubkey()), before_fee - 15_000);
            assert_eq!(post.get_account(&primary.pubkey()).unwrap(), baseline_state);
            assert_eq!(post.get_account(&escrow).unwrap(), baseline_escrow);
            assert_eq!(post.get_account(&recipient).unwrap(), baseline_recipient);
        };
        failed(
            accounts.failed_withdraw(1_000_000, 5),
            InstructionError::Custom(app::EXPECTED_ROLLBACK),
        );
        failed(accounts.withdraw(u64::MAX, 6), InstructionError::Custom(1));
        let mut wrong_pda = accounts.withdraw(1, 7);
        wrong_pda.accounts[3].pubkey = Pubkey::new_unique();
        failed(wrong_pda, InstructionError::Custom(app::BAD_ESCROW));
        let mut readonly_pda = accounts.withdraw(1, 8);
        readonly_pda.accounts[3].is_writable = false;
        failed(readonly_pda, InstructionError::PrivilegeEscalation);
        let mut readonly_state = accounts.withdraw(1, 9);
        readonly_state.accounts[0].is_writable = false;
        failed(readonly_state, InstructionError::Custom(app::BAD_STATE));
        let mut substituted_authority = accounts.withdraw(1, 10);
        substituted_authority.accounts.swap(1, 2);
        failed(
            substituted_authority,
            InstructionError::Custom(app::BAD_AUTHORITY),
        );
        let wrong_owner = Pubkey::new_unique();
        post.store_account(
            &wrong_owner,
            &Account {
                lamports: 50_000_000,
                data: baseline_state.data().to_vec(),
                owner: solana_sdk_ids::system_program::id(),
                ..Account::default()
            }
            .into(),
        );
        let mut wrong_owner_instruction = accounts.withdraw(1, 11);
        wrong_owner_instruction.accounts[0].pubkey = wrong_owner;
        failed(
            wrong_owner_instruction,
            InstructionError::Custom(app::BAD_OWNER),
        );
        let mut missing_peer = accounts.withdraw(1, 12);
        missing_peer.accounts[2].is_signer = false;
        let before_missing_fee = post.get_balance(&sponsor.pubkey());
        let missing_peer = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[sponsor.pubkey(), primary.pubkey()]),
                    missing_peer,
                ],
                Some(&sponsor.pubkey()),
                &post.last_blockhash(),
            )),
            &config,
            &[&sponsor_key, &primary_key],
        )
        .unwrap();
        assert_eq!(
            post.process_transaction_with_metadata(missing_peer)
                .unwrap()
                .status,
            Err(TransactionError::InstructionError(
                1,
                InstructionError::Custom(app::BAD_AUTHORITY)
            ))
        );
        assert_eq!(
            post.get_balance(&sponsor.pubkey()),
            before_missing_fee - 10_000
        );
        let application_replay = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[
                        sponsor.pubkey(),
                        primary.pubkey(),
                        secondary.pubkey(),
                    ]),
                    app::nonce_instruction(88, 99),
                    accounts.withdraw(1, 4),
                ],
                Some(&sponsor.pubkey()),
                &post.last_blockhash(),
            )),
            &config,
            &[&sponsor_key, &primary_key, &secondary_key],
        )
        .unwrap();
        assert_eq!(
            post.process_transaction_with_metadata(application_replay)
                .unwrap()
                .status,
            Err(TransactionError::InstructionError(
                2,
                InstructionError::Custom(app::BAD_SEQUENCE)
            ))
        );
        let before_fee = post.get_balance(&sponsor.pubkey());
        let resigned = sign_transaction(
            valid.message.clone(),
            &config,
            &[&sponsor_key, &primary_key, &secondary_key],
        )
        .unwrap();
        assert_eq!(
            post.process_transaction_with_metadata(resigned)
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        let forged_key = FalconKeypair::generate();
        let forged = sign_transaction(
            sign(accounts.withdraw(1, 12)).message,
            &config,
            &[&sponsor_key, &primary_key, &forged_key],
        )
        .unwrap();
        assert_eq!(
            post.process_transaction_with_metadata(forged).unwrap_err(),
            TransactionError::SignatureFailure
        );
        assert_eq!(post.get_balance(&sponsor.pubkey()), before_fee);
        assert_eq!(post.get_account(&primary.pubkey()).unwrap(), baseline_state);
        assert_eq!(post.get_account(&escrow).unwrap(), baseline_escrow);
        // A program-owned migrated signer cannot pay System rent itself.
        // Its separately authenticated sponsor uploads and funds key rotation.
        let next_primary = FalconKeypair::generate();
        let nonce = [0x74; 32];
        let upload = upload_key(
            &post,
            sponsor.pubkey(),
            &sponsor_key,
            &config,
            next_primary.public_key().as_bytes(),
            nonce,
        );
        let rotation = rotate_sponsored_instruction(
            &primary.pubkey(),
            &sponsor.pubkey(),
            &upload,
            1,
            &sealed_upload_commitment(
                &sponsor.pubkey(),
                &nonce,
                next_primary.public_key().as_bytes(),
            ),
        );
        let mut wrong_digest = rotation.clone();
        wrong_digest.data[56] ^= 1;
        failed(wrong_digest, InstructionError::InvalidInstructionData);
        let mut missing_sponsor = rotation.clone();
        missing_sponsor.accounts[2].is_signer = false;
        let missing_sponsor = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &[
                    authenticate_instruction(&[secondary.pubkey(), primary.pubkey()]),
                    missing_sponsor,
                ],
                Some(&secondary.pubkey()),
                &post.last_blockhash(),
            )),
            &config,
            &[&secondary_key, &primary_key],
        )
        .unwrap();
        assert_eq!(
            post.process_transaction_with_metadata(missing_sponsor)
                .unwrap()
                .status,
            Err(TransactionError::InstructionError(
                1,
                InstructionError::MissingRequiredSignature
            ))
        );
        let authority_lamports = post.get_balance(&primary.pubkey());
        let policy_before = post
            .get_account(&policy_address(&primary.pubkey()))
            .unwrap();
        execute_ok(&post, sign(rotation.clone()));
        let policy_after = post
            .get_account(&policy_address(&primary.pubkey()))
            .unwrap();
        let rotated_key = AuthRecord::decode(policy_after.data()).unwrap();
        assert_eq!(rotated_key.generation, 2);
        assert_eq!(rotated_key.public_key, next_primary.public_key());
        assert_eq!(rotated_key.retired_keys.len(), 1);
        assert!(policy_after.lamports() > policy_before.lamports());
        assert_eq!(post.get_balance(&primary.pubkey()), authority_lamports);
        assert_eq!(post.get_account(&primary.pubkey()).unwrap(), baseline_state);
        let before_retired_fee = post.get_balance(&sponsor.pubkey());
        assert_eq!(
            post.process_transaction_with_metadata(sign(accounts.withdraw(1, 13)))
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        assert_eq!(
            post.process_transaction_with_metadata(sign_with(rotation, &next_primary))
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        assert_eq!(post.get_balance(&sponsor.pubkey()), before_retired_fee);
        // Rotate the application's authority while keeping its existing state
        // and escrow addresses. The migrated signer must consent with its peer.
        execute_ok(
            &post,
            sign_with(
                accounts.rotate(sponsor.pubkey(), secondary.pubkey(), 5),
                &next_primary,
            ),
        );
        let rotated =
            AppState::decode(post.get_account(&primary.pubkey()).unwrap().data()).unwrap();
        assert_eq!(rotated.primary, sponsor.pubkey());
        assert_eq!(rotated.rotations, 1);
        let after_rotation = AppAccounts {
            primary: sponsor.pubkey(),
            ..accounts
        };
        let mut instructions = vec![authenticate_instruction(&[
            sponsor.pubkey(),
            secondary.pubkey(),
        ])];
        instructions.push(after_rotation.withdraw(2_000_000 + escrow_rent, 6));
        execute_ok(
            &post,
            sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &instructions,
                    Some(&sponsor.pubkey()),
                    &post.last_blockhash(),
                )),
                &config,
                &[&sponsor_key, &secondary_key],
            )
            .unwrap(),
        );
        assert_eq!(post.get_balance(&escrow), 0);
        assert_eq!(post.get_balance(&recipient), 15_000_000 + escrow_rent);
        assert_eq!(
            post.get_account(&primary.pubkey()).unwrap().owner(),
            &app::PROGRAM_ID
        );
    }

    #[test]
    fn legacy_program_owned_authority_migrates_without_data_changes_then_signs_real_sbf() {
        let (bank, sponsor, sponsor_key, config) = configured_bank(2, false);
        let source = Keypair::new();
        let source_key = FalconKeypair::generate();
        let program = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let data = b"existing application authority data".to_vec();
        store_move_funds_sbf(&bank, program);
        bank.store_account(
            &source.pubkey(),
            &Account {
                lamports: 10_000_000,
                owner: program,
                data: data.clone(),
                ..Account::default()
            }
            .into(),
        );
        bank.store_account(
            &recipient,
            &AccountSharedData::new(1_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        let (bank, _forks) = bank.wrap_with_bank_forks_for_tests();
        let source_upload = legacy_upload_key(
            &bank,
            &sponsor,
            source_key.public_key().as_bytes(),
            [0x45; 32],
        );
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[install_legacy_instruction(
                    &sponsor.pubkey(),
                    &source.pubkey(),
                    &source_upload,
                    &sealed_upload_commitment(
                        &sponsor.pubkey(),
                        &[0x45; 32],
                        source_key.public_key().as_bytes(),
                    ),
                )],
                Some(&sponsor.pubkey()),
                &[&sponsor, &source],
                bank.last_blockhash(),
            )
            .into(),
        );
        let preserved = bank.get_account(&source.pubkey()).unwrap();
        assert_eq!(preserved.owner(), &program);
        assert_eq!(preserved.data(), data);
        assert_eq!(preserved.lamports(), 10_000_000);
        let sponsor_upload = legacy_upload_key(
            &bank,
            &sponsor,
            sponsor_key.public_key().as_bytes(),
            [0x46; 32],
        );
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[install_legacy_instruction(
                    &sponsor.pubkey(),
                    &sponsor.pubkey(),
                    &sponsor_upload,
                    &sealed_upload_commitment(
                        &sponsor.pubkey(),
                        &[0x46; 32],
                        sponsor_key.public_key().as_bytes(),
                    ),
                )],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bank.last_blockhash(),
            )
            .into(),
        );
        let post_cutoff = Bank::new_isolated_pq_child(bank.clone(), *bank.leader(), 2).unwrap();
        let instructions = [
            authenticate_instruction(&[sponsor.pubkey(), source.pubkey()]),
            sbf_move_instruction(source.pubkey(), program, recipient),
        ];
        let message = VersionedMessage::Legacy(Message::new_with_blockhash(
            &instructions,
            Some(&sponsor.pubkey()),
            &post_cutoff.last_blockhash(),
        ));
        let unrelated = FalconKeypair::generate();
        let forged =
            sign_transaction(message.clone(), &config, &[&sponsor_key, &unrelated]).unwrap();
        assert_eq!(
            post_cutoff
                .process_transaction_with_metadata(forged)
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        assert_eq!(post_cutoff.get_balance(&recipient), 1_000_000);
        let valid = sign_transaction(message, &config, &[&sponsor_key, &source_key]).unwrap();
        let result = post_cutoff
            .process_transaction_with_metadata(valid)
            .unwrap();
        assert_eq!(result.status, Ok(()));
        assert!(
            result
                .log_messages
                .unwrap()
                .iter()
                .any(|line| line.contains("consumed"))
        );
        let preserved = post_cutoff.get_account(&source.pubkey()).unwrap();
        assert_eq!(preserved.owner(), &program);
        assert_eq!(preserved.data(), data);
        assert_eq!(preserved.lamports(), 9_000_000);
        assert_eq!(post_cutoff.get_balance(&recipient), 2_000_000);
    }

    #[test]
    fn real_sbf_deployed_in_private_candidate_executes_in_descendant_and_matches_live_replay() {
        use {
            solana_loader_v3_interface::{
                instruction::deploy_with_max_program_len, state::UpgradeableLoaderState,
            },
            std::sync::Arc,
        };
        let (bank, payer, payer_key, config) = configured_bank(0, true);
        let program = Pubkey::new_unique();
        let source = Pubkey::new_unique();
        let program_key = FalconKeypair::generate();
        let source_key = FalconKeypair::generate();
        for (authority, key) in [(program, &program_key), (source, &source_key)] {
            let data = AuthRecord::new(
                authority.to_bytes(),
                key.public_key(),
                Origin::FreshIdentity,
            )
            .encode();
            bank.store_account(
                &policy_address(&authority),
                &Account {
                    lamports: bank.get_minimum_balance_for_rent_exemption(data.len()),
                    data,
                    owner: PROGRAM_ID,
                    ..Account::default()
                }
                .into(),
            );
        }
        let elf = include_bytes!("../tests/fixtures/pq-svm/move_funds_v3.so");
        let buffer = Pubkey::new_unique();
        let mut buffer_data = wincode::serialize(&UpgradeableLoaderState::Buffer {
            authority_address: Some(payer.pubkey()),
        })
        .unwrap();
        assert_eq!(
            buffer_data.len(),
            UpgradeableLoaderState::size_of_buffer_metadata()
        );
        buffer_data.extend_from_slice(elf);
        bank.store_account(
            &buffer,
            &Account {
                lamports: bank.get_minimum_balance_for_rent_exemption(buffer_data.len()),
                data: buffer_data,
                owner: solana_sdk_ids::bpf_loader_upgradeable::id(),
                ..Account::default()
            }
            .into(),
        );
        bank.store_account(
            &source,
            &Account {
                lamports: 10_000_000,
                data: b"existing authority state".to_vec(),
                owner: program,
                ..Account::default()
            }
            .into(),
        );
        let recipient = Pubkey::new_unique();
        bank.store_account(
            &recipient,
            &AccountSharedData::new(1_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        let (parent, forks) = bank.wrap_with_bank_forks_for_tests();
        parent.freeze();
        let leader = *parent.leader();
        let deployed = Arc::new(Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap());
        let mut deploy_instructions = vec![authenticate_instruction(&[payer.pubkey(), program])];
        deploy_instructions.extend(
            deploy_with_max_program_len(
                &payer.pubkey(),
                &program,
                &buffer,
                &payer.pubkey(),
                deployed.get_minimum_balance_for_rent_exemption(
                    UpgradeableLoaderState::size_of_program(),
                ),
                elf.len(),
            )
            .unwrap(),
        );
        let transaction = sign_transaction(
            VersionedMessage::Legacy(Message::new_with_blockhash(
                &deploy_instructions,
                Some(&payer.pubkey()),
                &deployed.last_blockhash(),
            )),
            &config,
            &[&payer_key, &program_key],
        )
        .unwrap();
        let result = deployed
            .process_transaction_with_metadata(transaction.clone())
            .unwrap();
        assert_eq!(result.status, Ok(()), "{:?}", result.log_messages);
        assert_eq!(
            deployed.get_account(&program).unwrap().owner(),
            &solana_sdk_ids::bpf_loader_upgradeable::id()
        );
        deployed.freeze();
        deployed.detach_isolated_pq_parent().unwrap();
        assert!(deployed.parent().is_none());
        let private_child = Bank::new_isolated_pq_child(deployed.clone(), leader, 2).unwrap();
        let invocation = signed_sbf_move(
            &private_child,
            [(payer.pubkey(), &payer_key), (source, &source_key)],
            &config,
            program,
            recipient,
        );
        let result = private_child
            .process_transaction_with_metadata(invocation.clone())
            .unwrap();
        assert_eq!(result.status, Ok(()), "{:?}", result.log_messages);
        assert!(
            result
                .log_messages
                .unwrap()
                .iter()
                .any(|line| line.contains("consumed"))
        );
        private_child.freeze();
        private_child.detach_isolated_pq_parent().unwrap();
        assert_eq!(private_child.get_balance(&recipient), 2_000_000);
        assert_eq!(parent.get_balance(&recipient), 1_000_000);

        forks
            .write()
            .unwrap()
            .set_pq_execution_context(1, parent.ancestors.clone());
        let live_deployed = Arc::new(Bank::new_from_parent(parent.clone(), leader, 1));
        execute_ok(&live_deployed, transaction);
        live_deployed.freeze();
        assert_eq!(
            live_deployed.pq_state_commitment(),
            deployed.pq_state_commitment()
        );
        forks.write().unwrap().clear_pq_execution_context(1);
        forks
            .write()
            .unwrap()
            .set_pq_execution_context(2, live_deployed.ancestors.clone());
        let live_child = Bank::new_from_parent(live_deployed, leader, 2);
        execute_ok(&live_child, invocation);
        live_child.freeze();
        assert_eq!(
            live_child.pq_state_commitment(),
            private_child.pq_state_commitment()
        );
        assert_eq!(live_child.get_balance(&recipient), 2_000_000);
        forks.write().unwrap().clear_pq_execution_context(2);
    }

    #[test]
    fn detached_private_candidates_release_banks_and_preserve_exact_replay() {
        use std::sync::Arc;
        let (bank, payer, key, config) = configured_bank(0, true);
        let parent = Arc::new(bank);
        parent.freeze();
        assert!(parent.detach_isolated_pq_parent().is_err());
        let parent_weak = Arc::downgrade(&parent);
        let leader = *parent.leader();
        let child = Arc::new(Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap());
        assert!(child.detach_isolated_pq_parent().is_err());
        let recipient = Pubkey::new_unique();
        let transaction = signed(
            &child,
            payer.pubkey(),
            &key,
            &config,
            &[system_instruction::transfer(
                &payer.pubkey(),
                &recipient,
                1_000_000,
            )],
        );
        execute_ok(&child, transaction.clone());
        child.freeze();
        let commitment = child.pq_state_commitment();
        let ancestry = child.ancestors.clone();
        let roots = child.status_cache.read().unwrap().roots().clone();
        child.detach_isolated_pq_parent().unwrap();
        assert!(child.parent().is_none());
        assert_eq!(child.pq_state_commitment(), commitment);
        assert_eq!(child.ancestors, ancestry);
        assert_eq!(*child.status_cache.read().unwrap().roots(), roots);
        assert!(child.pq_transaction_processed(&transaction).unwrap());
        drop(parent);
        assert!(
            parent_weak.upgrade().is_none(),
            "private graph retains an ancestor Bank"
        );

        let child_weak = Arc::downgrade(&child);
        let descendant = Bank::new_isolated_pq_child(child.clone(), leader, 2).unwrap();
        assert!(descendant.pq_transaction_processed(&transaction).unwrap());
        assert_eq!(descendant.get_balance(&recipient), 1_000_000);
        assert_eq!(
            descendant
                .process_transaction_with_metadata(transaction)
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        descendant.freeze();
        descendant.detach_isolated_pq_parent().unwrap();
        drop(child);
        assert!(
            child_weak.upgrade().is_none(),
            "detached descendant retains its parent"
        );
        assert_eq!(descendant.get_balance(&recipient), 1_000_000);
    }

    #[test]
    fn real_bank_transfer_rejects_legacy_and_resigned_intent_replay() {
        let (bank, authority, key, config) = configured_bank(0, true);
        let recipient = Pubkey::new_unique();
        let transfer = system_instruction::transfer(&authority.pubkey(), &recipient, 1_000_000);
        let tx = signed(
            &bank,
            authority.pubkey(),
            &key,
            &config,
            std::slice::from_ref(&transfer),
        );
        let resign = signed(&bank, authority.pubkey(), &key, &config, &[transfer]);
        assert_ne!(tx.signatures, resign.signatures);
        assert_eq!(
            canonical_message_hash(&tx).unwrap(),
            canonical_message_hash(&resign).unwrap()
        );
        bank.verify_pq_transaction_for_ingress(&tx).unwrap();
        execute_ok(&bank, tx);
        assert_eq!(bank.get_balance(&recipient), 1_000_000);
        let balance = bank.get_balance(&authority.pubkey());
        assert_eq!(
            bank.process_transaction_with_metadata(resign).unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        assert_eq!(bank.get_balance(&authority.pubkey()), balance);
        let legacy = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &authority.pubkey(),
                &recipient,
                2,
            )],
            Some(&authority.pubkey()),
            &[&authority],
            bank.last_blockhash(),
        );
        assert_eq!(
            bank.process_transaction_with_metadata(legacy).unwrap_err(),
            TransactionError::SignatureFailure
        );
    }

    #[test]
    fn full_width_replay_ignores_legacy_cache_collisions_and_survives_private_journal_replay() {
        use std::sync::Arc;
        let (bank, authority, key, config) = configured_bank(0, true);
        let (parent, _forks) = bank.wrap_with_bank_forks_for_tests();
        parent.freeze();
        let leader = *parent.leader();
        let a = Arc::new(Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap());
        let recipient = Pubkey::new_unique();
        let instructions = [system_instruction::transfer(
            &authority.pubkey(),
            &recipient,
            1_000_000,
        )];
        let first = signed(&a, authority.pubkey(), &key, &config, &instructions);
        let resign = signed(&a, authority.pubkey(), &key, &config, &instructions);
        assert_ne!(first.signatures, resign.signatures);
        // Reproduce an exact legacy-cache false positive; full-width PQ
        // admission must ignore it and authenticate the canonical intent.
        a.status_cache.write().unwrap().insert(
            &a.last_blockhash(),
            canonical_message_hash(&first).unwrap(),
            0,
            Ok(()),
        );
        assert!(!a.pq_transaction_processed(&first).unwrap());
        assert!(!a.pq_transaction_processed(&resign).unwrap());
        execute_ok(&a, first.clone());
        assert!(a.pq_transaction_processed(&first).unwrap());
        assert!(a.pq_transaction_processed(&resign).unwrap());
        assert_eq!(
            a.process_transaction_with_metadata(resign.clone())
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        a.freeze();
        let child = Bank::new_isolated_pq_child(a.clone(), leader, 2).unwrap();
        assert!(child.pq_transaction_processed(&resign).unwrap());
        assert_eq!(
            child
                .process_transaction_with_metadata(resign.clone())
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        let distinct = signed(
            &child,
            authority.pubkey(),
            &key,
            &config,
            &[system_instruction::transfer(
                &authority.pubkey(),
                &recipient,
                2_000_000,
            )],
        );
        assert!(!child.pq_transaction_processed(&distinct).unwrap());
        execute_ok(&child, distinct.clone());
        assert!(child.pq_transaction_processed(&distinct).unwrap());
        assert_eq!(child.get_balance(&recipient), 3_000_000);

        // Independent recovery starts from the same genuine genesis Bank and
        // reconstructs full-width identities by executing its durable journal.
        let recovered = Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap();
        assert!(!recovered.pq_transaction_processed(&first).unwrap());
        execute_ok(&recovered, first);
        assert!(recovered.pq_transaction_processed(&resign).unwrap());
        assert_eq!(
            recovered
                .process_transaction_with_metadata(resign.clone())
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        recovered.freeze();
        assert_eq!(recovered.pq_state_commitment(), a.pq_state_commitment());

        // Ordinary certified live replay has its own exact identity state and
        // subsequently rooted history remains authoritative to new children.
        let live = Arc::new(Bank::new_from_parent(parent, leader, 1));
        let live_first = signed(&live, authority.pubkey(), &key, &config, &instructions);
        execute_ok(&live, live_first);
        live.squash();
        let live_child = Bank::new_isolated_pq_child(live.clone(), leader, 2).unwrap();
        assert!(live_child.pq_transaction_processed(&resign).unwrap());
        assert_eq!(
            live_child
                .process_transaction_with_metadata(resign)
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
    }

    #[test]
    fn full_width_replay_identity_binds_v0_lookup_metadata_and_snapshot_recovery_fails_closed() {
        let (bank, authority, key, config) = configured_bank(0, true);
        let tx = signed(&bank, authority.pubkey(), &key, &config, &[]);
        let VersionedMessage::Legacy(message) = tx.message else {
            unreachable!()
        };
        let mut v0 = solana_message::v0::Message {
            header: message.header,
            account_keys: message.account_keys,
            recent_blockhash: message.recent_blockhash,
            instructions: message.instructions,
            address_table_lookups: vec![solana_message::v0::MessageAddressTableLookup {
                account_key: Pubkey::new_unique(),
                writable_indexes: vec![1],
                readonly_indexes: vec![2],
            }],
        };
        let first = sign_transaction(VersionedMessage::V0(v0.clone()), &config, &[&key]).unwrap();
        let first_static =
            solana_transaction::versioned::sanitized::SanitizedVersionedTransaction::try_from(
                first.clone(),
            )
            .unwrap();
        let original = replay_identity(&first_static, &config.chain_id)
            .unwrap()
            .unwrap();
        let resign = sign_transaction(VersionedMessage::V0(v0.clone()), &config, &[&key]).unwrap();
        let resign_static =
            solana_transaction::versioned::sanitized::SanitizedVersionedTransaction::try_from(
                resign,
            )
            .unwrap();
        assert_eq!(
            original,
            replay_identity(&resign_static, &config.chain_id)
                .unwrap()
                .unwrap()
        );
        v0.address_table_lookups[0].readonly_indexes.push(3);
        let changed = sign_transaction(VersionedMessage::V0(v0), &config, &[&key]).unwrap();
        let changed_static =
            solana_transaction::versioned::sanitized::SanitizedVersionedTransaction::try_from(
                changed,
            )
            .unwrap();
        assert_ne!(
            original,
            replay_identity(&changed_static, &config.chain_id)
                .unwrap()
                .unwrap()
        );
        assert_ne!(
            original,
            replay_identity(&first_static, &[0; 32]).unwrap().unwrap()
        );
        // Native snapshot construction uses this unavailable state because its
        // classical serialized status keys cannot recover full intent digests.
        *bank.pq_replay_cache.write().unwrap() = ReplayCache::unsupported_snapshot();
        assert!(!bank.pq_replay_state_ready());
        let tx = signed(&bank, authority.pubkey(), &key, &config, &[]);
        assert_eq!(
            bank.pq_transaction_processed(&tx),
            Err(TransactionError::InvalidProgramForExecution)
        );
        assert_eq!(
            bank.verify_pq_transaction_for_ingress(&tx),
            Err(TransactionError::InvalidProgramForExecution)
        );
        assert_eq!(
            bank.process_transaction_with_metadata(tx).unwrap_err(),
            TransactionError::InvalidProgramForExecution
        );
    }

    #[test]
    fn real_bank_authenticates_every_multisig_witness_after_message_signer_reordering() {
        let (bank, payer, first, config) = configured_bank(0, true);
        let second_authority = Pubkey::new_from_array([0x31; 32]);
        let third_authority = Pubkey::new_from_array([0x19; 32]);
        let second = FalconKeypair::generate();
        let third = FalconKeypair::generate();
        for (authority, key) in [(second_authority, &second), (third_authority, &third)] {
            let data = AuthRecord::new(
                authority.to_bytes(),
                key.public_key(),
                Origin::FreshIdentity,
            )
            .encode();
            bank.store_account(
                &policy_address(&authority),
                &AccountSharedData::from(Account {
                    lamports: bank.get_minimum_balance_for_rent_exemption(data.len()),
                    data,
                    owner: PROGRAM_ID,
                    executable: false,
                    rent_epoch: u64::MAX,
                }),
            );
        }
        let recipient = Pubkey::new_unique();
        let instructions = [
            authenticate_instruction(&[payer.pubkey(), second_authority, third_authority]),
            system_instruction::transfer(&payer.pubkey(), &recipient, 1_000_000),
        ];
        let message = VersionedMessage::Legacy(Message::new_with_blockhash(
            &instructions,
            Some(&payer.pubkey()),
            &bank.last_blockhash(),
        ));
        let valid = sign_transaction(message.clone(), &config, &[&first, &second, &third]).unwrap();
        assert_eq!(valid.signatures.len(), 3);
        bank.verify_pq_transaction_for_ingress(&valid).unwrap();
        let wrong = sign_transaction(message, &config, &[&first, &third, &second]).unwrap();
        assert_eq!(
            bank.process_transaction_with_metadata(wrong).unwrap_err(),
            TransactionError::SignatureFailure
        );
        execute_ok(&bank, valid);
        assert_eq!(bank.get_balance(&recipient), 1_000_000);
    }

    #[test]
    fn real_bank_pq_signer_authorizes_program_owned_state_and_native_system_cpi() {
        let (bank, authority, key, config) = configured_bank(0, true);
        let program = Pubkey::new_unique();
        let state_address = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        bank.add_builtin(
            program,
            "pq_authority_cpi_probe",
            ProgramCacheEntry::new_builtin(NativeAuthorityCpiProbe::register),
        );
        let mut state_data = authority.pubkey().to_bytes().to_vec();
        state_data.extend_from_slice(&0u64.to_le_bytes());
        bank.store_account(
            &state_address,
            &AccountSharedData::from(Account {
                lamports: bank.get_minimum_balance_for_rent_exemption(state_data.len()),
                data: state_data.clone(),
                owner: program,
                executable: false,
                rent_epoch: u64::MAX,
            }),
        );
        let instruction = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(state_address, false),
                AccountMeta::new(recipient, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
            ],
            data: 1_000_000u64.to_le_bytes().to_vec(),
        };
        let before = bank.get_balance(&authority.pubkey());
        let forged_key = FalconKeypair::generate();
        let forged = signed(
            &bank,
            authority.pubkey(),
            &forged_key,
            &config,
            std::slice::from_ref(&instruction),
        );
        assert_eq!(
            bank.process_transaction_with_metadata(forged).unwrap_err(),
            TransactionError::SignatureFailure
        );
        assert_eq!(
            bank.get_account(&state_address).unwrap().data(),
            &state_data
        );
        assert_eq!(bank.get_balance(&authority.pubkey()), before);
        assert_eq!(bank.get_balance(&recipient), 0);
        let valid = bank
            .process_transaction_with_metadata(signed(
                &bank,
                authority.pubkey(),
                &key,
                &config,
                &[instruction],
            ))
            .unwrap();
        assert_eq!(valid.status, Ok(()));
        assert!(
            valid
                .log_messages
                .unwrap()
                .iter()
                .any(|line| line == "Program 11111111111111111111111111111111 invoke [2]")
        );
        assert_eq!(bank.get_balance(&recipient), 1_000_000);
        assert_eq!(bank.get_balance(&authority.pubkey()), before - 1_005_000);
        assert_eq!(
            bank.get_account(&state_address).unwrap().data()[32..],
            1u64.to_le_bytes()
        );
    }

    #[test]
    fn real_same_slot_candidates_are_isolated_and_certified_promotion_reuses_private_bank() {
        let (parent, authority, key, config) = configured_bank(0, true);
        let (parent, forks) = parent.wrap_with_bank_forks_for_tests();
        parent.freeze();
        let parent_root = parent.pq_state_commitment();
        let parent_balance = parent.get_balance(&authority.pubkey());
        let leader = *parent.leader();
        let recipient = Pubkey::new_unique();
        let a =
            std::sync::Arc::new(Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap());
        let b = Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap();
        let first = signed(
            &a,
            authority.pubkey(),
            &key,
            &config,
            &[system_instruction::transfer(
                &authority.pubkey(),
                &recipient,
                1_000_000,
            )],
        );
        execute_ok(&a, first.clone());
        a.freeze();
        let a_root = a.pq_state_commitment();
        let descendant = Bank::new_isolated_pq_child(a.clone(), leader, 2).unwrap();
        let other = Pubkey::new_unique();
        execute_ok(
            &descendant,
            signed(
                &descendant,
                authority.pubkey(),
                &key,
                &config,
                &[system_instruction::transfer(
                    &authority.pubkey(),
                    &other,
                    1_000_000,
                )],
            ),
        );
        descendant.freeze();
        let descendant_root = descendant.pq_state_commitment();
        // Exact same wire/intent is valid on the alternate candidate: neither
        // AccountsDB cache nor replay lookup is shared with candidate A.
        execute_ok(&b, first.clone());
        execute_ok(
            &b,
            signed(
                &b,
                authority.pubkey(),
                &key,
                &config,
                &[system_instruction::transfer(
                    &authority.pubkey(),
                    &recipient,
                    2_000_000,
                )],
            ),
        );
        b.freeze();
        assert_ne!(b.pq_state_commitment(), a_root);
        assert_eq!(b.get_balance(&recipient), 3_000_000);
        assert_eq!(a.get_balance(&recipient), 1_000_000);
        assert_eq!(a.pq_state_commitment(), a_root);
        assert_eq!(descendant.pq_state_commitment(), descendant_root);
        assert_eq!(parent.get_balance(&authority.pubkey()), parent_balance);
        assert_eq!(parent.get_balance(&recipient), 0);
        assert!(!parent.has_signature(&first.signatures[0]));
        drop(b);
        assert_eq!(a.get_balance(&recipient), 1_000_000);
        assert_eq!(descendant.pq_state_commitment(), descendant_root);
        // Rejecting a block after one valid transaction must discard only its
        // private DB, without purging or corrupting an earlier frozen branch.
        let rejected = Bank::new_isolated_pq_child(parent.clone(), leader, 1).unwrap();
        execute_ok(
            &rejected,
            signed(
                &rejected,
                authority.pubkey(),
                &key,
                &config,
                &[system_instruction::transfer(
                    &authority.pubkey(),
                    &other,
                    2_000_000,
                )],
            ),
        );
        let forged_key = FalconKeypair::generate();
        let invalid = signed(
            &rejected,
            authority.pubkey(),
            &forged_key,
            &config,
            &[system_instruction::transfer(
                &authority.pubkey(),
                &other,
                3_000_000,
            )],
        );
        assert_eq!(
            rejected
                .process_transaction_with_metadata(invalid)
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        drop(rejected);
        assert_eq!(a.get_balance(&recipient), 1_000_000);
        assert_eq!(parent.pq_state_commitment(), parent_root);
        assert_eq!(parent.get_balance(&authority.pubkey()), parent_balance);
        let executed_count = a.transaction_count();
        a.detach_isolated_pq_parent().unwrap();
        let promoted = forks
            .write()
            .unwrap()
            .promote_pq_candidate(a.clone(), parent_root)
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&promoted, &a));
        assert_eq!(promoted.transaction_count(), executed_count);
        assert!(promoted.has_signature(&first.signatures[0]));
        assert_eq!(promoted.pq_state_commitment(), a_root);
        assert_eq!(promoted.get_balance(&recipient), 1_000_000);
        assert_eq!(parent.get_balance(&authority.pubkey()), parent_balance);
        let promoted_descendant = forks
            .write()
            .unwrap()
            .promote_pq_candidate(std::sync::Arc::new(descendant), a_root)
            .unwrap();
        assert_eq!(promoted_descendant.pq_state_commitment(), descendant_root);
        assert_eq!(promoted_descendant.get_balance(&other), 1_000_000);
    }

    #[test]
    fn certified_preexecuted_descendants_keep_native_replay_retention_and_visibility() {
        let (initial, authority, key, config) = configured_bank(0, true);
        let recipient = Pubkey::new_unique();
        initial.store_account(
            &recipient,
            &AccountSharedData::new(1_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        let (initial, forks) = initial.wrap_with_bank_forks_for_tests();
        initial.freeze();
        let leader = *initial.leader();
        let mut transactions = Vec::new();
        let mut charged_failure = None;

        // Each window executes and detaches all four descendants before any
        // parent is promoted. Their root sets therefore start out stale; the
        // actual production promotion must repair retention without importing
        // execution or replay state from any alternative branch.
        for first_slot in (1u64..=640).step_by(4) {
            let mut parent = forks.read().unwrap().root_bank();
            let mut candidates = Vec::new();
            for slot in first_slot..first_slot + 4 {
                let child = Arc::new(
                    Bank::new_isolated_pq_child(Arc::clone(&parent), leader, slot).unwrap(),
                );
                let operation = system_instruction::transfer(&authority.pubkey(), &recipient, 1);
                let wire = signed(
                    &child,
                    authority.pubkey(),
                    &key,
                    &config,
                    std::slice::from_ref(&operation),
                );
                let identity = transaction_intent_identity(&wire, &config.chain_id).unwrap();
                execute_ok(&child, wire.clone());
                assert!(child.pq_intent_processed(&identity).unwrap());

                if slot == 1 || slot == 521 {
                    let alias = signed(&child, authority.pubkey(), &key, &config, &[operation]);
                    assert_eq!(
                        transaction_intent_identity(&alias, &config.chain_id).unwrap(),
                        identity
                    );
                    assert_eq!(
                        child.process_transaction_with_metadata(alias).unwrap_err(),
                        TransactionError::AlreadyProcessed
                    );
                    let sibling =
                        Bank::new_isolated_pq_child(Arc::clone(&parent), leader, slot).unwrap();
                    assert!(!sibling.pq_intent_processed(&identity).unwrap());
                    execute_ok(&sibling, wire.clone());
                    assert!(!parent.pq_intent_processed(&identity).unwrap());
                }

                if slot == 521 {
                    let failure = signed(
                        &child,
                        authority.pubkey(),
                        &key,
                        &config,
                        &[system_instruction::transfer(
                            &authority.pubkey(),
                            &recipient,
                            u64::MAX,
                        )],
                    );
                    let failed_identity =
                        transaction_intent_identity(&failure, &config.chain_id).unwrap();
                    let balance = child.get_balance(&authority.pubkey());
                    let result = child
                        .process_transaction_with_metadata(failure.clone())
                        .unwrap();
                    assert!(result.status.is_err());
                    assert_eq!(child.get_balance(&authority.pubkey()), balance - 5_000);
                    assert!(child.pq_intent_processed(&failed_identity).unwrap());
                    charged_failure = Some((failed_identity, failure));
                }

                let mut hash = [0xc7; 32];
                hash[..8].copy_from_slice(&slot.to_le_bytes());
                child.register_recent_blockhash_for_test(&Hash::new_from_array(hash), None);
                child.freeze();
                child.detach_isolated_pq_parent().unwrap();
                transactions.push((slot, identity, wire));
                parent = Arc::clone(&child);
                candidates.push(child);
            }
            for child in candidates {
                let root = forks.read().unwrap().root_bank();
                let state = child.pq_state_commitment();
                let count = child.transaction_count();
                let promoted = forks
                    .write()
                    .unwrap()
                    .promote_pq_candidate(Arc::clone(&child), root.pq_state_commitment())
                    .unwrap();
                assert!(Arc::ptr_eq(&promoted, &child));
                assert_eq!(promoted.pq_state_commitment(), state);
                assert_eq!(promoted.transaction_count(), count);

                let statuses = promoted.status_cache.read().unwrap();
                let limit = statuses.max_root_entries();
                assert_eq!(limit, solana_clock::MAX_RECENT_BLOCKHASHES);
                let oldest = promoted.slot().saturating_sub(limit as u64 - 1);
                assert_eq!(
                    statuses.roots(),
                    &(oldest..=promoted.slot()).collect::<HashSet<_>>(),
                    "promotion must import this exact certified parent's roots"
                );
                let replay = promoted.pq_replay_cache.read().unwrap();
                assert!(replay.slots.keys().all(|slot| *slot >= oldest));
                assert_eq!(replay.slots.len(), (promoted.slot() as usize).min(limit));
            }
        }

        let root = forks.read().unwrap().root_bank();
        assert_eq!(root.ancestors.len(), 641, "logical ancestry remains intact");
        let probe = Bank::new_isolated_pq_child(Arc::clone(&root), leader, 641).unwrap();
        let (_, old_identity, old_wire) = &transactions[199];
        assert!(!probe.pq_intent_processed(old_identity).unwrap());
        assert_eq!(
            probe
                .process_transaction_with_metadata(old_wire.clone())
                .unwrap_err(),
            TransactionError::BlockhashNotFound
        );
        let (_, recent_identity, recent_wire) = &transactions[520];
        assert!(probe.pq_intent_processed(recent_identity).unwrap());
        assert_eq!(
            probe
                .process_transaction_with_metadata(recent_wire.clone())
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        let (failed_identity, failure) = charged_failure.unwrap();
        assert!(probe.pq_intent_processed(&failed_identity).unwrap());
        assert_eq!(
            probe
                .process_transaction_with_metadata(failure)
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        let balance = probe.get_balance(&recipient);
        execute_ok(
            &probe,
            signed(
                &probe,
                authority.pubkey(),
                &key,
                &config,
                &[system_instruction::transfer(
                    &authority.pubkey(),
                    &recipient,
                    1,
                )],
            ),
        );
        assert_eq!(probe.get_balance(&recipient), balance + 1);
    }

    #[test]
    fn rejected_pq_promotion_does_not_import_certified_parent_roots() {
        let (initial, _authority, _key, _config) = configured_bank(0, true);
        let (initial, forks) = initial.wrap_with_bank_forks_for_tests();
        initial.freeze();
        let leader = *initial.leader();
        let parent =
            Arc::new(Bank::new_isolated_pq_child(Arc::clone(&initial), leader, 1).unwrap());
        parent.freeze();
        let child = Arc::new(Bank::new_isolated_pq_child(Arc::clone(&parent), leader, 2).unwrap());
        child.freeze();
        parent.detach_isolated_pq_parent().unwrap();
        child.detach_isolated_pq_parent().unwrap();
        let child_roots = child.status_cache.read().unwrap().roots().clone();
        let initial_state = initial.pq_state_commitment();
        assert!(
            forks
                .write()
                .unwrap()
                .promote_pq_candidate(Arc::clone(&parent), [0; 48])
                .is_err()
        );
        assert!(Arc::ptr_eq(&forks.read().unwrap().root_bank(), &initial));
        forks
            .write()
            .unwrap()
            .promote_pq_candidate(Arc::clone(&parent), initial_state)
            .unwrap();
        assert_eq!(
            parent.status_cache.read().unwrap().roots(),
            &HashSet::from([0, 1])
        );
        assert_eq!(child_roots, HashSet::from([0]));
        let child_state = child.pq_state_commitment();
        assert!(
            forks
                .write()
                .unwrap()
                .promote_pq_candidate(Arc::clone(&child), initial_state)
                .is_err()
        );
        assert_eq!(*child.status_cache.read().unwrap().roots(), child_roots);
        assert_eq!(child.pq_state_commitment(), child_state);

        // Force the subsequent AccountsDB promotion guard to fail as well.
        // Parent/state checks pass, but unsuccessful persistence must leave
        // root visibility and the canonical Bank unchanged.
        parent.rc.accounts.accounts_db.pq_storage_db().add_root(3);
        assert!(
            forks
                .write()
                .unwrap()
                .promote_pq_candidate(Arc::clone(&child), parent.pq_state_commitment())
                .is_err()
        );
        assert_eq!(*child.status_cache.read().unwrap().roots(), child_roots);
        assert_eq!(child.pq_state_commitment(), child_state);
        assert!(Arc::ptr_eq(&forks.read().unwrap().root_bank(), &parent));
    }

    #[test]
    fn stock_bank_funding_experimental_config_address_does_not_activate_pq() {
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(1_000_000, &Pubkey::new_unique(), 1_000_000_000);
        let bank = Bank::new_for_tests(&genesis_config);
        let funded = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &mint_keypair.pubkey(),
                &CONFIG_ADDRESS,
                1,
            )],
            Some(&mint_keypair.pubkey()),
            &[&mint_keypair],
            bank.last_blockhash(),
        );
        execute_ok(&bank, funded.into());
        assert_eq!(bank.get_balance(&CONFIG_ADDRESS), 1);
        assert_eq!(bank.pq_config().unwrap(), None);
        assert!(
            !solana_svm_callback::InvokeContextCallback::is_classical_authentication_disabled(
                &bank
            )
        );
        let recipient = Pubkey::new_unique();
        let ordinary = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &mint_keypair.pubkey(),
                &recipient,
                2,
            )],
            Some(&mint_keypair.pubkey()),
            &[&mint_keypair],
            bank.last_blockhash(),
        );
        execute_ok(&bank, ordinary.into());
        assert_eq!(bank.get_balance(&recipient), 2);
        bank.freeze();
    }

    #[test]
    fn real_bank_cutoff_retires_classical_permits_in_admission_and_svm_callback() {
        use solana_svm_callback::InvokeContextCallback;
        let (bank, payer, key, config) = configured_bank(2, true);
        let permit_authority = Keypair::new();
        let permit_message = b"authorize contract-state change";
        let permit_signature: [u8; 64] = permit_authority
            .sign_message(permit_message)
            .as_ref()
            .try_into()
            .unwrap();
        let permit = solana_ed25519_program::new_ed25519_instruction_with_signature(
            permit_message,
            &permit_signature,
            &permit_authority.pubkey().to_bytes(),
        );
        assert!(!bank.is_classical_authentication_disabled());
        assert_eq!(
            bank.process_precompile(&permit.program_id, &permit.data, vec![&permit.data]),
            Ok(())
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                payer.pubkey(),
                &key,
                &config,
                std::slice::from_ref(&permit),
            ),
        );
        let (bank, _forks) = bank.wrap_with_bank_forks_for_tests();
        let leader = *bank.leader();
        bank.freeze();
        let post_cutoff = Bank::new_from_parent(bank, leader, 2);
        assert!(post_cutoff.is_classical_authentication_disabled());
        let witness = signed(
            &post_cutoff,
            payer.pubkey(),
            &key,
            &config,
            std::slice::from_ref(&permit),
        );
        assert_eq!(
            post_cutoff.verify_pq_transaction_for_ingress(&witness),
            Err(TransactionError::InvalidProgramForExecution)
        );
        assert_eq!(
            post_cutoff
                .process_transaction_with_metadata(witness)
                .unwrap_err(),
            TransactionError::InvalidProgramForExecution
        );
        assert_eq!(
            post_cutoff.process_precompile(&permit.program_id, &permit.data, vec![&permit.data]),
            Err(solana_precompile_error::PrecompileError::InvalidSignature)
        );
        for program in [
            solana_sdk_ids::secp256k1_program::id(),
            solana_sdk_ids::secp256r1_program::id(),
        ] {
            let tx = signed(
                &post_cutoff,
                payer.pubkey(),
                &key,
                &config,
                &[Instruction {
                    program_id: program,
                    accounts: vec![],
                    data: vec![0],
                }],
            );
            assert_eq!(
                post_cutoff
                    .process_transaction_with_metadata(tx)
                    .unwrap_err(),
                TransactionError::InvalidProgramForExecution
            );
            assert_eq!(
                post_cutoff.process_precompile(&program, &[0], vec![&[0]]),
                Err(solana_precompile_error::PrecompileError::InvalidSignature)
            );
        }
    }

    #[test]
    fn real_svm_classical_zk_proof_works_before_cutoff_and_is_retired_through_cpi() {
        use {
            solana_zk_elgamal_proof_interface::instruction::ProofInstruction,
            solana_zk_sdk::{
                encryption::elgamal::ElGamalKeypair,
                zk_elgamal_proof_program::build_pubkey_validity_proof_data,
            },
        };
        let proof = build_pubkey_validity_proof_data(&ElGamalKeypair::new_rand()).unwrap();
        let proof_program = solana_sdk_ids::zk_elgamal_proof_program::id();
        let mut data = vec![ProofInstruction::VerifyPubkeyValidity as u8];
        data.extend_from_slice(bytemuck::bytes_of(&proof));
        let verify = Instruction {
            program_id: proof_program,
            accounts: vec![],
            data: data.clone(),
        };
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config_with_leader(10_000_000_000, &Pubkey::new_unique(), 1_000_000_000);
        let stock = Bank::new_for_tests(&genesis_config);
        execute_ok(
            &stock,
            Transaction::new_signed_with_payer(
                std::slice::from_ref(&verify),
                Some(&mint_keypair.pubkey()),
                &[&mint_keypair],
                stock.last_blockhash(),
            )
            .into(),
        );

        let (bank, payer, key, config) = configured_bank(2, true);
        let probe = Pubkey::new_unique();
        bank.add_builtin(
            probe,
            "pq_classical_proof_cpi_probe",
            ProgramCacheEntry::new_builtin(NativeClassicalProofCpiProbe::register),
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                payer.pubkey(),
                &key,
                &config,
                std::slice::from_ref(&verify),
            ),
        );
        let cpi = Instruction {
            program_id: probe,
            accounts: vec![AccountMeta::new_readonly(proof_program, false)],
            data,
        };
        execute_ok(
            &bank,
            signed(
                &bank,
                payer.pubkey(),
                &key,
                &config,
                std::slice::from_ref(&cpi),
            ),
        );
        let (bank, _forks) = bank.wrap_with_bank_forks_for_tests();
        let child = Bank::new_isolated_pq_child(bank.clone(), *bank.leader(), 2).unwrap();
        let top_level = signed(&child, payer.pubkey(), &key, &config, &[verify]);
        assert_eq!(
            child
                .process_transaction_with_metadata(top_level)
                .unwrap_err(),
            TransactionError::InvalidProgramForExecution
        );
        let cpi_result = child.process_transaction_with_metadata(signed(&child, payer.pubkey(), &key, &config, &[
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(199_999),
            cpi,
        ])).unwrap();
        assert_eq!(
            cpi_result.status,
            Err(TransactionError::InstructionError(
                2,
                InstructionError::UnsupportedProgramId
            ))
        );
        assert_eq!(
            cpi_result
                .log_messages
                .unwrap()
                .iter()
                .filter(|line| line.contains("VerifyPubkeyValidity"))
                .count(),
            0
        );
        // The old token proof program is also retired at ingress even though
        // current Agave has already replaced its native implementation.
        let legacy = signed(
            &child,
            payer.pubkey(),
            &key,
            &config,
            &[Instruction {
                program_id: solana_sdk_ids::zk_token_proof_program::id(),
                accounts: vec![],
                data: vec![0],
            }],
        );
        assert_eq!(
            child.verify_pq_transaction_for_ingress(&legacy),
            Err(TransactionError::InvalidProgramForExecution)
        );
    }

    #[test]
    fn real_bank_rejects_tampering_chain_and_unlocked_policy_and_charges_program_failure() {
        let (bank, authority, key, config) = configured_bank(0, true);
        let recipient = Pubkey::new_unique();
        let instruction = system_instruction::transfer(&authority.pubkey(), &recipient, 1_000_000);
        let mut tampered = signed(
            &bank,
            authority.pubkey(),
            &key,
            &config,
            std::slice::from_ref(&instruction),
        );
        match &mut tampered.message {
            VersionedMessage::Legacy(message) => message.instructions[1].data[4] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            bank.process_transaction_with_metadata(tampered)
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        let mut other_chain = config.clone();
        other_chain.chain_id[0] ^= 1;
        let wrong = signed(
            &bank,
            authority.pubkey(),
            &key,
            &other_chain,
            &[instruction],
        );
        assert_eq!(
            bank.process_transaction_with_metadata(wrong).unwrap_err(),
            TransactionError::SignatureFailure
        );
        let mut missing_lock = signed(
            &bank,
            authority.pubkey(),
            &key,
            &config,
            &[system_instruction::transfer(
                &authority.pubkey(),
                &recipient,
                3,
            )],
        );
        if let VersionedMessage::Legacy(message) = &mut missing_lock.message {
            message.instructions[0].accounts[1] = message.instructions[0].accounts[0];
        }
        let missing_lock = sign_transaction(missing_lock.message, &config, &[&key]).unwrap();
        assert_eq!(
            bank.process_transaction_with_metadata(missing_lock)
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        let before = bank.get_balance(&authority.pubkey());
        let failed = signed(
            &bank,
            authority.pubkey(),
            &key,
            &config,
            &[system_instruction::transfer(
                &authority.pubkey(),
                &recipient,
                u64::MAX,
            )],
        );
        let committed = bank.process_transaction_with_metadata(failed).unwrap();
        assert!(matches!(
            committed.status,
            Err(TransactionError::InstructionError(..))
        ));
        assert_eq!(bank.get_balance(&authority.pubkey()), before - 5_000);
        assert_eq!(bank.get_balance(&recipient), 0);
    }

    #[test]
    fn real_svm_upload_rotate_retired_keys_and_fresh_install() {
        let (bank, authority, first, config) = configured_bank(0, true);
        let next = FalconKeypair::generate();
        let uploaded = upload_key(
            &bank,
            authority.pubkey(),
            &first,
            &config,
            next.public_key().as_bytes(),
            [0x31; 32],
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                authority.pubkey(),
                &first,
                &config,
                &[rotate_instruction(&authority.pubkey(), &uploaded, 1)],
            ),
        );
        let account: Account = bank
            .get_account(&policy_address(&authority.pubkey()))
            .unwrap()
            .into();
        let record = AuthRecord::from_account(
            &policy_address(&authority.pubkey()).to_bytes(),
            &authority.pubkey().to_bytes(),
            &account,
        )
        .unwrap();
        assert_eq!(record.generation, 2);
        assert_eq!(record.public_key, next.public_key());
        let recipient = Pubkey::new_unique();
        let old = signed(
            &bank,
            authority.pubkey(),
            &first,
            &config,
            &[system_instruction::transfer(
                &authority.pubkey(),
                &recipient,
                1_000_000,
            )],
        );
        assert_eq!(
            bank.process_transaction_with_metadata(old).unwrap_err(),
            TransactionError::SignatureFailure
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                authority.pubkey(),
                &next,
                &config,
                &[system_instruction::transfer(
                    &authority.pubkey(),
                    &recipient,
                    1_000_000,
                )],
            ),
        );
        let retired = upload_key(
            &bank,
            authority.pubkey(),
            &next,
            &config,
            first.public_key().as_bytes(),
            [0x32; 32],
        );
        let failed = bank
            .process_transaction_with_metadata(signed(
                &bank,
                authority.pubkey(),
                &next,
                &config,
                &[rotate_instruction(&authority.pubkey(), &retired, 2)],
            ))
            .unwrap();
        assert!(matches!(
            failed.status,
            Err(TransactionError::InstructionError(..))
        ));
        let fresh = FalconKeypair::generate();
        let nonce = [0x39; 32];
        let fresh_authority = Pubkey::new_from_array(agave_pq_crypto::auth::fresh_address(
            &config.chain_id,
            &fresh.public_key(),
            &nonce,
        ));
        let mut bytes = fresh.public_key().as_bytes().to_vec();
        bytes.extend_from_slice(&nonce);
        let uploaded = upload_key(
            &bank,
            authority.pubkey(),
            &next,
            &config,
            &bytes,
            [0x33; 32],
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                authority.pubkey(),
                &next,
                &config,
                &[install_fresh_instruction(
                    &authority.pubkey(),
                    &fresh_authority,
                    &uploaded,
                )],
            ),
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                authority.pubkey(),
                &next,
                &config,
                &[system_instruction::transfer(
                    &authority.pubkey(),
                    &fresh_authority,
                    2_000_000,
                )],
            ),
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                fresh_authority,
                &fresh,
                &config,
                &[system_instruction::transfer(
                    &fresh_authority,
                    &recipient,
                    1_000_000,
                )],
            ),
        );
        assert_eq!(bank.get_balance(&recipient), 2_000_000);
    }

    #[test]
    fn sponsored_legacy_migration_rejects_recreated_upload_with_another_key() {
        let (bank, sponsor, original, _config) = configured_bank(2, false);
        let authority = Keypair::new();
        bank.store_account(
            &authority.pubkey(),
            &AccountSharedData::new(10_000_000, 0, &solana_sdk_ids::system_program::id()),
        );
        let nonce = [0x4a; 32];
        let upload = legacy_upload_key(&bank, &sponsor, original.public_key().as_bytes(), nonce);
        // The authority consents before the sponsor replaces its reusable PDA.
        let previously_signed = Transaction::new_signed_with_payer(
            &[install_legacy_instruction(
                &sponsor.pubkey(),
                &authority.pubkey(),
                &upload,
                &sealed_upload_commitment(
                    &sponsor.pubkey(),
                    &nonce,
                    original.public_key().as_bytes(),
                ),
            )],
            Some(&sponsor.pubkey()),
            &[&sponsor, &authority],
            bank.last_blockhash(),
        );
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[close_upload_instruction(&sponsor.pubkey(), &upload)],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bank.last_blockhash(),
            )
            .into(),
        );
        let replacement = FalconKeypair::generate();
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[
                    create_upload_instruction(&sponsor.pubkey(), &nonce, 897),
                    write_upload_instruction(
                        &sponsor.pubkey(),
                        &upload,
                        0,
                        replacement.public_key().as_bytes(),
                    ),
                    seal_upload_instruction(&sponsor.pubkey(), &upload),
                ],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bank.last_blockhash(),
            )
            .into(),
        );
        let rejected = bank
            .process_transaction_with_metadata(previously_signed)
            .unwrap();
        assert_eq!(
            rejected.status,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::InvalidInstructionData,
            ))
        );
        assert!(
            bank.get_account(&policy_address(&authority.pubkey()))
                .is_none()
        );

        // A new signature explicitly consenting to the current sealed digest
        // preserves sponsored migration without granting the sponsor key choice.
        execute_ok(
            &bank,
            Transaction::new_signed_with_payer(
                &[install_legacy_instruction(
                    &sponsor.pubkey(),
                    &authority.pubkey(),
                    &upload,
                    &sealed_upload_commitment(
                        &sponsor.pubkey(),
                        &nonce,
                        replacement.public_key().as_bytes(),
                    ),
                )],
                Some(&sponsor.pubkey()),
                &[&sponsor, &authority],
                bank.last_blockhash(),
            )
            .into(),
        );
        let account = bank
            .get_account(&policy_address(&authority.pubkey()))
            .unwrap();
        let record = AuthRecord::decode(account.data()).unwrap();
        assert_eq!(record.public_key, replacement.public_key());
        assert_eq!(record.origin, Origin::LegacySignature);
    }

    #[test]
    fn real_svm_pre_cutoff_legacy_install_permanently_disables_classical_authority() {
        let (bank, authority, key, _config) = configured_bank(2, false);
        let nonce = [0x41; 32];
        let upload = upload_address(&authority.pubkey(), &nonce);
        for instruction in [
            create_upload_instruction(&authority.pubkey(), &nonce, 897),
            write_upload_instruction(&authority.pubkey(), &upload, 0, key.public_key().as_bytes()),
            seal_upload_instruction(&authority.pubkey(), &upload),
            install_legacy_instruction(
                &authority.pubkey(),
                &authority.pubkey(),
                &upload,
                &sealed_upload_commitment(&authority.pubkey(), &nonce, key.public_key().as_bytes()),
            ),
        ] {
            let tx = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&authority.pubkey()),
                &[&authority],
                bank.last_blockhash(),
            );
            execute_ok(&bank, tx.into());
        }
        let legacy = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &authority.pubkey(),
                &Pubkey::new_unique(),
                1_000_000,
            )],
            Some(&authority.pubkey()),
            &[&authority],
            bank.last_blockhash(),
        );
        assert_eq!(
            bank.process_transaction_with_metadata(legacy).unwrap_err(),
            TransactionError::SignatureFailure
        );
    }

    #[test]
    fn real_svm_seed_claim_cannot_finalize_without_native_proof_verification() {
        use agave_pq_crypto::{
            crypto::FalconPublicKey,
            migration::{MigrationIntent, SeedClaimStatement},
        };
        let (bank, sponsor, key, config) = configured_bank(0, true);
        let authority = Pubkey::new_unique();
        let statement = SeedClaimStatement {
            intent: MigrationIntent {
                chain_id: config.chain_id,
                context: config.migration_context,
                authority: authority.to_bytes(),
                replacement_key: FalconPublicKey::from_bytes(key.public_key().as_bytes()).unwrap(),
                expected_generation: 0,
                claim_nonce: [0x71; 32],
            },
            secret_intent_commitment: [0; 64],
        };
        let statement_bytes = statement.canonical_bytes();
        let mut payload = (statement_bytes.len() as u16).to_le_bytes().to_vec();
        payload.extend_from_slice(&statement_bytes);
        payload.extend_from_slice(b"SEEDPQ01");
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(&[0; 4]);
        let upload = upload_key(&bank, sponsor.pubkey(), &key, &config, &payload, [0x72; 32]);
        let finalized = bank
            .process_transaction_with_metadata(signed(
                &bank,
                sponsor.pubkey(),
                &key,
                &config,
                &[finalize_seed_instruction(
                    &sponsor.pubkey(),
                    &authority,
                    &upload,
                )],
            ))
            .unwrap();
        assert!(matches!(
            finalized.status,
            Err(TransactionError::InstructionError(..))
        ));
        assert!(bank.get_account(&policy_address(&authority)).is_none());
        let verify = signed(
            &bank,
            sponsor.pubkey(),
            &key,
            &config,
            &[
                solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
                    1_400_000,
                ),
                verify_seed_instruction(&sponsor.pubkey(), &upload),
            ],
        );
        let verified = bank.process_transaction_with_metadata(verify).unwrap();
        assert!(matches!(
            verified.status,
            Err(TransactionError::InstructionError(..))
        ));
        assert_eq!(bank.get_account(&upload).unwrap().data()[81], 0);
        assert!(bank.get_account(&policy_address(&authority)).is_none());
    }

    #[test]
    #[ignore = "requires AGAVE_PQ_SEED_FIXTURE and AGAVE_PQ_SEED_REPLACEMENT_KEY"]
    fn real_svm_complete_private_seed_proof_verifies_and_migrates_accountsdb() {
        complete_private_seed_migration(false, false);
    }

    #[test]
    #[ignore = "requires AGAVE_PQ_SEED_FIXTURE and AGAVE_PQ_SEED_REPLACEMENT_KEY"]
    fn real_svm_complete_private_seed_proof_migrates_program_owned_authority_and_executes_sbf() {
        complete_private_seed_migration(true, false);
    }

    #[test]
    #[ignore = "requires AGAVE_PQ_SEED_FIXTURE and AGAVE_PQ_SEED_REPLACEMENT_KEY"]
    fn real_svm_complete_private_seed_proof_claims_absent_key_only_authority_then_funds_and_spends()
    {
        complete_private_seed_migration(false, true);
    }

    fn complete_private_seed_migration(program_owned: bool, key_only: bool) {
        use agave_pq_crypto::{
            crypto::FalconPublicKey,
            migration::{MigrationIntent, SeedClaimStatement},
        };
        #[derive(serde::Deserialize)]
        struct Fixture {
            authority: [u8; 32],
            chain: [u8; 32],
            context: [u8; 32],
            nonce: [u8; 32],
            replacement_key: Vec<u8>,
            proof: Vec<u8>,
            secret_commitment: Vec<u8>,
        }
        let fixture_path =
            std::env::var("AGAVE_PQ_SEED_FIXTURE").expect("public proof fixture path required");
        let fixture: Fixture =
            serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
        let config = Config {
            chain_id: fixture.chain,
            migration_context: fixture.context,
            cutoff_slot: 0,
        };
        let (bank, sponsor, key, config) =
            configured_bank_with_config(config, true, 100_000_000_000);
        let replacement = FalconPublicKey::from_bytes(&fixture.replacement_key).unwrap();
        let replacement_key = FalconKeypair::load_private(
            std::env::var("AGAVE_PQ_SEED_REPLACEMENT_KEY")
                .expect("replacement credential path required"),
        )
        .unwrap();
        assert_eq!(replacement_key.public_key(), replacement);
        let authority = Pubkey::new_from_array(fixture.authority);
        let program = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        if program_owned {
            store_move_funds_sbf(&bank, program);
            bank.store_account(
                &authority,
                &Account {
                    lamports: 10_000_000,
                    owner: program,
                    data: b"existing seed-authorized program state".to_vec(),
                    ..Account::default()
                }
                .into(),
            );
            bank.store_account(
                &recipient,
                &AccountSharedData::new(1_000_000, 0, &solana_sdk_ids::system_program::id()),
            );
        }
        let (bank, _forks) = bank.wrap_with_bank_forks_for_tests();
        if !program_owned && !key_only {
            execute_ok(
                &bank,
                signed(
                    &bank,
                    sponsor.pubkey(),
                    &key,
                    &config,
                    &[system_instruction::transfer(
                        &sponsor.pubkey(),
                        &authority,
                        2_000_000,
                    )],
                ),
            );
        }
        let original_account = bank.get_account(&authority);
        let statement = SeedClaimStatement {
            intent: MigrationIntent {
                chain_id: fixture.chain,
                context: fixture.context,
                authority: fixture.authority,
                replacement_key: replacement.clone(),
                expected_generation: 0,
                claim_nonce: fixture.nonce,
            },
            secret_intent_commitment: fixture.secret_commitment.try_into().unwrap(),
        };
        let encoded_statement = statement.canonical_bytes();
        let mut payload = (encoded_statement.len() as u16).to_le_bytes().to_vec();
        payload.extend_from_slice(&encoded_statement);
        payload.extend_from_slice(&fixture.proof);
        let nonce = [0x73; 32];
        let upload = upload_address(&sponsor.pubkey(), &nonce);
        execute_ok(
            &bank,
            signed(
                &bank,
                sponsor.pubkey(),
                &key,
                &config,
                &[create_upload_instruction(
                    &sponsor.pubkey(),
                    &nonce,
                    payload.len() as u32,
                )],
            ),
        );
        for (position, chunk) in payload.chunks(MAX_UPLOAD_CHUNK_BYTES).enumerate() {
            execute_ok(
                &bank,
                signed(
                    &bank,
                    sponsor.pubkey(),
                    &key,
                    &config,
                    &[write_upload_instruction(
                        &sponsor.pubkey(),
                        &upload,
                        (position * MAX_UPLOAD_CHUNK_BYTES) as u32,
                        chunk,
                    )],
                ),
            );
        }
        execute_ok(
            &bank,
            signed(
                &bank,
                sponsor.pubkey(),
                &key,
                &config,
                &[seal_upload_instruction(&sponsor.pubkey(), &upload)],
            ),
        );
        // Preparation only caches verifier parameters, never an accepted proof.
        agave_pq_crypto::seed_proof::prewarm_seed_verifier().unwrap();
        let before = std::time::Instant::now();
        let verified = bank.process_transaction_with_metadata(signed(&bank, sponsor.pubkey(), &key, &config, &[
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            verify_seed_instruction(&sponsor.pubkey(), &upload),
        ])).unwrap();
        assert_eq!(verified.status, Ok(()));
        eprintln!(
            "Actual SVM native seed verification: {:?}, {} compute units",
            before.elapsed(),
            verified.executed_units
        );
        execute_ok(
            &bank,
            signed(
                &bank,
                sponsor.pubkey(),
                &key,
                &config,
                &[finalize_seed_instruction(
                    &sponsor.pubkey(),
                    &authority,
                    &upload,
                )],
            ),
        );
        let account: Account = bank
            .get_account(&policy_address(&authority))
            .unwrap()
            .into();
        let record = AuthRecord::from_account(
            &policy_address(&authority).to_bytes(),
            &fixture.authority,
            &account,
        )
        .unwrap();
        assert_eq!(record.public_key, replacement);
        assert_eq!(record.origin, Origin::OriginalSeed);
        assert_eq!(bank.get_account(&authority), original_account);
        assert_eq!(bank.get_account(&upload).unwrap().data()[81], 2);
        let consumed = bank.process_transaction_with_metadata(signed(&bank, sponsor.pubkey(), &key, &config, &[
            solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(199_999),
            finalize_seed_instruction(&sponsor.pubkey(), &authority, &upload),
        ])).unwrap();
        assert!(matches!(
            consumed.status,
            Err(TransactionError::InstructionError(..))
        ));
        if key_only {
            assert!(bank.get_account(&authority).is_none());
            execute_ok(
                &bank,
                signed(
                    &bank,
                    sponsor.pubkey(),
                    &key,
                    &config,
                    &[system_instruction::transfer(
                        &sponsor.pubkey(),
                        &authority,
                        2_000_000,
                    )],
                ),
            );
        }
        // SBF programs loaded at slot zero become visible in a descendant,
        // exactly as ordinary Agave's deployment visibility rules require.
        let bank = if program_owned {
            std::sync::Arc::new(
                Bank::new_isolated_pq_child(bank.clone(), *bank.leader(), 1).unwrap(),
            )
        } else {
            bank
        };
        let unrelated = FalconKeypair::generate();
        let forged = if program_owned {
            signed_sbf_move(
                &bank,
                [(sponsor.pubkey(), &key), (authority, &unrelated)],
                &config,
                program,
                recipient,
            )
        } else {
            signed(
                &bank,
                authority,
                &unrelated,
                &config,
                &[system_instruction::transfer(
                    &authority, &recipient, 1_000_000,
                )],
            )
        };
        assert_eq!(
            bank.process_transaction_with_metadata(forged).unwrap_err(),
            TransactionError::SignatureFailure
        );
        let valid = if program_owned {
            signed_sbf_move(
                &bank,
                [(sponsor.pubkey(), &key), (authority, &replacement_key)],
                &config,
                program,
                recipient,
            )
        } else {
            signed(
                &bank,
                authority,
                &replacement_key,
                &config,
                &[system_instruction::transfer(
                    &authority, &recipient, 1_000_000,
                )],
            )
        };
        let spent = bank.process_transaction_with_metadata(valid).unwrap();
        assert_eq!(spent.status, Ok(()));
        if program_owned {
            assert!(
                spent
                    .log_messages
                    .unwrap()
                    .iter()
                    .any(|line| line.contains("consumed"))
            );
            assert_eq!(bank.get_balance(&recipient), 2_000_000);
            assert_eq!(bank.get_balance(&authority), 9_000_000);
            let preserved = bank.get_account(&authority).unwrap();
            let original_account = original_account.as_ref().unwrap();
            assert_eq!(preserved.owner(), original_account.owner());
            assert_eq!(preserved.data(), original_account.data());
        } else {
            assert_eq!(bank.get_balance(&recipient), 1_000_000);
            assert_eq!(bank.get_balance(&authority), 995_000);
        }
        execute_ok(
            &bank,
            signed(
                &bank,
                sponsor.pubkey(),
                &key,
                &config,
                &[close_upload_instruction(&sponsor.pubkey(), &upload)],
            ),
        );
        assert!(bank.get_account(&upload).is_none());
        assert!(bank.get_account(&policy_address(&authority)).is_some());
    }

    #[test]
    fn real_vote_and_stake_authorities_survive_legacy_enrollment_and_cutoff() {
        use {
            solana_account::state_traits::StateMutWincode,
            solana_stake_interface::{
                instruction as stake_instruction,
                state::{Authorized, Meta, StakeAuthorize, StakeStateV2},
            },
            solana_vote_interface::{instruction as vote_instruction, state::VoteAuthorize},
        };
        let (bank, sponsor, sponsor_key, config) = configured_bank(2, false);
        let authority = Keypair::new();
        let authority_key = FalconKeypair::generate();
        let recipient = Pubkey::new_unique();
        let vote = Pubkey::new_unique();
        let unlocked_stake = Pubkey::new_unique();
        let delegated_stake = Pubkey::new_unique();
        let rent = solana_rent::Rent::default();
        for (address, account) in
            solana_program_binaries::by_id(&solana_sdk_ids::stake::ID, &rent).unwrap()
        {
            bank.store_account(&address, &account);
        }
        for address in [authority.pubkey(), recipient] {
            bank.store_account(
                &address,
                &AccountSharedData::new(20_000_000, 0, &solana_sdk_ids::system_program::ID),
            );
        }
        let vote_account = solana_vote_program::vote_state::create_v4_account_with_authorized(
            &Pubkey::new_unique(),
            &authority.pubkey(),
            [0; 48],
            &authority.pubkey(),
            0,
            &authority.pubkey(),
            10_000,
            &authority.pubkey(),
            500_000_000,
        );
        bank.store_account(&vote, &vote_account);
        let stake_rent = rent.minimum_balance(StakeStateV2::size_of());
        let mut account = AccountSharedData::new(
            stake_rent + 20_000_000,
            StakeStateV2::size_of(),
            &solana_sdk_ids::stake::ID,
        );
        #[expect(deprecated)]
        let stake_meta = Meta {
            rent_exempt_reserve: stake_rent,
            authorized: Authorized::auto(&authority.pubkey()),
            ..Meta::default()
        };
        account
            .set_state(&StakeStateV2::Initialized(stake_meta))
            .unwrap();
        bank.store_account(&unlocked_stake, &account);
        let delegation = crate::stake_utils::create_stake_account(
            &authority.pubkey(),
            &vote,
            &vote_account,
            &rent,
            stake_rent + 2_000_000_000,
        );
        bank.store_account(&delegated_stake, &delegation);
        let role_registry = AccountSharedData::from(Account {
            lamports: 5_000_000,
            data: b"test-only immutable role registry".to_vec(),
            owner: PROGRAM_ID,
            ..Account::default()
        });
        bank.store_account(&ROLE_REGISTRY_ADDRESS, &role_registry);
        let (genesis, _forks) = bank.wrap_with_bank_forks_for_tests();
        let pre =
            Arc::new(Bank::new_isolated_pq_child(genesis.clone(), *genesis.leader(), 1).unwrap());
        for instruction in [
            vote_instruction::withdraw(&vote, &authority.pubkey(), 5, &recipient),
            stake_instruction::withdraw(&unlocked_stake, &authority.pubkey(), &recipient, 7, None),
        ] {
            execute_ok(
                &pre,
                Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&sponsor.pubkey()),
                    &[&sponsor, &authority],
                    pre.last_blockhash(),
                )
                .into(),
            );
        }
        let preserved = [authority.pubkey(), vote, unlocked_stake, delegated_stake]
            .map(|address| (address, pre.get_account(&address).unwrap()));
        let mut authority_upload = None;
        for (actor, key, nonce) in [
            (&authority, &authority_key, [0x91; 32]),
            (&sponsor, &sponsor_key, [0x92; 32]),
        ] {
            let upload = legacy_upload_key(&pre, &sponsor, key.public_key().as_bytes(), nonce);
            let instruction = install_legacy_instruction(
                &sponsor.pubkey(),
                &actor.pubkey(),
                &upload,
                &sealed_upload_commitment(&sponsor.pubkey(), &nonce, key.public_key().as_bytes()),
            );
            let signers = if actor.pubkey() == sponsor.pubkey() {
                vec![&sponsor]
            } else {
                authority_upload = Some(upload);
                vec![&sponsor, &authority]
            };
            execute_ok(
                &pre,
                Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&sponsor.pubkey()),
                    &signers,
                    pre.last_blockhash(),
                )
                .into(),
            );
        }
        for (address, account) in preserved {
            assert_eq!(pre.get_account(&address).unwrap(), account);
        }
        let post = Bank::new_isolated_pq_child(pre.clone(), *pre.leader(), 2).unwrap();
        let signed_authority = |instruction| {
            sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[
                        authenticate_instruction(&[sponsor.pubkey(), authority.pubkey()]),
                        instruction,
                    ],
                    Some(&sponsor.pubkey()),
                    &post.last_blockhash(),
                )),
                &config,
                &[&sponsor_key, &authority_key],
            )
            .unwrap()
        };
        let before = post.get_balance(&recipient);
        for instruction in [
            vote_instruction::withdraw(&vote, &authority.pubkey(), 11, &recipient),
            stake_instruction::withdraw(&unlocked_stake, &authority.pubkey(), &recipient, 13, None),
            stake_instruction::deactivate_stake(&delegated_stake, &authority.pubkey()),
        ] {
            execute_ok(&post, signed_authority(instruction));
        }
        assert_eq!(post.get_balance(&recipient), before + 24);
        let delegated: StakeStateV2 = post.get_account(&delegated_stake).unwrap().state().unwrap();
        let StakeStateV2::Stake(meta, stake, _) = delegated else {
            panic!("actual Stake program lost delegated state");
        };
        assert_eq!(meta.authorized, Authorized::auto(&authority.pubkey()));
        assert_eq!(stake.delegation.deactivation_epoch, post.clock().epoch);
        for (address, instruction) in [
            (
                vote,
                vote_instruction::withdraw(&vote, &sponsor.pubkey(), 1, &recipient),
            ),
            (
                unlocked_stake,
                stake_instruction::withdraw(
                    &unlocked_stake,
                    &sponsor.pubkey(),
                    &recipient,
                    1,
                    None,
                ),
            ),
        ] {
            let account = post.get_account(&address).unwrap();
            let destination = post.get_account(&recipient).unwrap();
            let payer = post.get_balance(&sponsor.pubkey());
            let failed = post
                .process_transaction_with_metadata(signed(
                    &post,
                    sponsor.pubkey(),
                    &sponsor_key,
                    &config,
                    &[instruction],
                ))
                .unwrap();
            assert!(matches!(
                failed.status,
                Err(TransactionError::InstructionError(_, _))
            ));
            assert!(failed.executed_units > 4_000);
            assert_eq!(post.get_account(&address).unwrap(), account);
            assert_eq!(post.get_account(&recipient).unwrap(), destination);
            assert_eq!(post.get_balance(&sponsor.pubkey()), payer - 5_000);
        }
        for (address, instruction) in [
            (
                vote,
                vote_instruction::withdraw(&vote, &authority.pubkey(), 17, &recipient),
            ),
            (
                unlocked_stake,
                stake_instruction::withdraw(
                    &unlocked_stake,
                    &authority.pubkey(),
                    &recipient,
                    17,
                    None,
                ),
            ),
        ] {
            let before = post.get_account(&address).unwrap();
            let destination = post.get_account(&recipient).unwrap();
            let fee_before = post.get_balance(&sponsor.pubkey());
            let classical: VersionedTransaction = Transaction::new_signed_with_payer(
                std::slice::from_ref(&instruction),
                Some(&sponsor.pubkey()),
                &[&sponsor, &authority],
                post.last_blockhash(),
            )
            .into();
            assert_eq!(
                post.process_transaction_with_metadata(classical)
                    .unwrap_err(),
                TransactionError::SignatureFailure
            );
            assert_eq!(post.get_account(&address).unwrap(), before);
            assert_eq!(post.get_account(&recipient).unwrap(), destination);
            assert_eq!(post.get_balance(&sponsor.pubkey()), fee_before);
            let forged_key = FalconKeypair::generate();
            let forged = sign_transaction(
                signed_authority(instruction.clone()).message,
                &config,
                &[&sponsor_key, &forged_key],
            )
            .unwrap();
            assert_eq!(
                post.process_transaction_with_metadata(forged).unwrap_err(),
                TransactionError::SignatureFailure
            );
            assert_eq!(post.get_account(&address).unwrap(), before);
            assert_eq!(post.get_balance(&sponsor.pubkey()), fee_before);
            let mut missing = instruction;
            missing.accounts[2].is_signer = false;
            let failure = post
                .process_transaction_with_metadata(signed(
                    &post,
                    sponsor.pubkey(),
                    &sponsor_key,
                    &config,
                    &[missing],
                ))
                .unwrap();
            assert!(matches!(
                failure.status,
                Err(TransactionError::InstructionError(_, _))
            ));
            assert_eq!(post.get_account(&address).unwrap(), before);
            assert_eq!(post.get_account(&recipient).unwrap(), destination);
            assert_eq!(post.get_balance(&sponsor.pubkey()), fee_before - 5_000);
        }
        execute_ok(
            &post,
            signed_authority(vote_instruction::authorize(
                &vote,
                &authority.pubkey(),
                &sponsor.pubkey(),
                VoteAuthorize::Withdrawer,
            )),
        );
        execute_ok(
            &post,
            signed_authority(stake_instruction::authorize(
                &unlocked_stake,
                &authority.pubkey(),
                &sponsor.pubkey(),
                StakeAuthorize::Withdrawer,
                None,
            )),
        );
        for instruction in [
            vote_instruction::withdraw(&vote, &sponsor.pubkey(), 19, &recipient),
            stake_instruction::withdraw(&unlocked_stake, &sponsor.pubkey(), &recipient, 23, None),
        ] {
            execute_ok(
                &post,
                signed(
                    &post,
                    sponsor.pubkey(),
                    &sponsor_key,
                    &config,
                    &[instruction],
                ),
            );
        }
        let vote_state = solana_vote_interface::state::VoteStateV4::deserialize(
            post.get_account(&vote).unwrap().data(),
            &vote,
        )
        .unwrap();
        assert_eq!(vote_state.authorized_withdrawer, sponsor.pubkey());
        assert_eq!(
            post.get_account(&vote).unwrap().owner(),
            &solana_sdk_ids::vote::ID
        );
        assert_eq!(
            post.get_account(&unlocked_stake).unwrap().owner(),
            &solana_sdk_ids::stake::ID
        );
        let mut forbidden = close_upload_instruction(&sponsor.pubkey(), &authority_upload.unwrap());
        forbidden
            .accounts
            .push(AccountMeta::new(ROLE_REGISTRY_ADDRESS, false));
        assert_eq!(
            post.process_transaction_with_metadata(signed(
                &post,
                sponsor.pubkey(),
                &sponsor_key,
                &config,
                &[forbidden],
            ))
            .unwrap()
            .status,
            Err(TransactionError::InstructionError(
                1,
                InstructionError::ReadonlyDataModified
            ))
        );
        assert_eq!(
            post.get_account(&ROLE_REGISTRY_ADDRESS).unwrap(),
            role_registry
        );
    }

    #[test]
    fn real_lookup_table_authority_migrates_and_v0_executes_across_banks() {
        use {
            solana_address_lookup_table_interface::{
                instruction as lookup_instruction,
                state::{AddressLookupTable, LookupTableStatus},
            },
            solana_message::{AddressLookupTableAccount, v0},
        };
        let (bank, sponsor, sponsor_key, config) = configured_bank(3, false);
        let authority = Keypair::new();
        let authority_key = FalconKeypair::generate();
        let recipients = [Pubkey::new_unique(), Pubkey::new_unique()];
        let complete = |bank: &Bank| {
            let digest = hash_commitment(b"pq-alt-test-native-tick", &[&bank.slot().to_le_bytes()]);
            let hash = Hash::new_from_array(digest[..32].try_into().unwrap());
            while bank.tick_height() < bank.max_tick_height() {
                bank.register_tick_for_test(&hash);
            }
            bank.freeze();
        };
        for (address, account) in solana_program_binaries::by_id(
            &solana_sdk_ids::address_lookup_table::ID,
            &solana_rent::Rent::default(),
        )
        .unwrap()
        {
            bank.store_account(&address, &account);
        }
        for address in [authority.pubkey(), recipients[0], recipients[1]] {
            bank.store_account(
                &address,
                &AccountSharedData::new(20_000_000, 0, &solana_sdk_ids::system_program::ID),
            );
        }
        let (genesis, _forks) = bank.wrap_with_bank_forks_for_tests();
        let pre =
            Arc::new(Bank::new_isolated_pq_child(genesis.clone(), *genesis.leader(), 1).unwrap());
        let (create, table) =
            lookup_instruction::create_lookup_table(authority.pubkey(), sponsor.pubkey(), 0);
        execute_ok(
            &pre,
            Transaction::new_signed_with_payer(
                &[
                    create,
                    lookup_instruction::extend_lookup_table(
                        table,
                        authority.pubkey(),
                        Some(sponsor.pubkey()),
                        vec![recipients[0]],
                    ),
                ],
                Some(&sponsor.pubkey()),
                &[&sponsor, &authority],
                pre.last_blockhash(),
            )
            .into(),
        );
        let before_table = pre.get_account(&table).unwrap();
        let before_authority = pre.get_account(&authority.pubkey()).unwrap();
        for (actor, key, nonce) in [
            (&authority, &authority_key, [0xa1; 32]),
            (&sponsor, &sponsor_key, [0xa2; 32]),
        ] {
            let upload = legacy_upload_key(&pre, &sponsor, key.public_key().as_bytes(), nonce);
            let signers = if actor.pubkey() == sponsor.pubkey() {
                vec![&sponsor]
            } else {
                vec![&sponsor, &authority]
            };
            execute_ok(
                &pre,
                Transaction::new_signed_with_payer(
                    &[install_legacy_instruction(
                        &sponsor.pubkey(),
                        &actor.pubkey(),
                        &upload,
                        &sealed_upload_commitment(
                            &sponsor.pubkey(),
                            &nonce,
                            key.public_key().as_bytes(),
                        ),
                    )],
                    Some(&sponsor.pubkey()),
                    &signers,
                    pre.last_blockhash(),
                )
                .into(),
            );
        }
        assert_eq!(pre.get_account(&table).unwrap(), before_table);
        assert_eq!(
            pre.get_account(&authority.pubkey()).unwrap(),
            before_authority
        );
        complete(&pre);
        let post = Arc::new(Bank::new_isolated_pq_child(pre.clone(), *pre.leader(), 3).unwrap());
        let authority_transaction = |bank: &Bank, instruction: Instruction| {
            sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &[
                        authenticate_instruction(&[sponsor.pubkey(), authority.pubkey()]),
                        instruction,
                    ],
                    Some(&sponsor.pubkey()),
                    &bank.last_blockhash(),
                )),
                &config,
                &[&sponsor_key, &authority_key],
            )
            .unwrap()
        };
        execute_ok(
            &post,
            authority_transaction(
                &post,
                lookup_instruction::extend_lookup_table(
                    table,
                    authority.pubkey(),
                    Some(sponsor.pubkey()),
                    vec![recipients[1]],
                ),
            ),
        );
        let lookup_account = AddressLookupTableAccount {
            key: table,
            addresses: recipients.to_vec(),
        };
        let versioned = |bank: &Bank, destination: Pubkey, amount| {
            let message = v0::Message::try_compile(
                &sponsor.pubkey(),
                &[
                    authenticate_instruction(&[sponsor.pubkey()]),
                    system_instruction::transfer(&sponsor.pubkey(), &destination, amount),
                ],
                std::slice::from_ref(&lookup_account),
                bank.last_blockhash(),
            )
            .unwrap();
            assert!(!message.account_keys.contains(&destination));
            assert_eq!(message.address_table_lookups.len(), 1);
            sign_transaction(VersionedMessage::V0(message), &config, &[&sponsor_key]).unwrap()
        };
        // The post-cut extension is real SBF execution; its new entry is not
        // usable in that same slot. Existing pre-cut entries remain usable.
        let not_warm = versioned(&post, recipients[1], 29);
        assert_eq!(
            post.process_transaction_with_metadata(not_warm)
                .unwrap_err(),
            TransactionError::InvalidAddressLookupTableIndex
        );
        execute_ok(&post, versioned(&post, recipients[0], 31));
        let after_table = post.get_account(&table).unwrap();
        let parsed = AddressLookupTable::deserialize(after_table.data()).unwrap();
        assert_eq!(parsed.meta.authority, Some(authority.pubkey()));
        assert_eq!(parsed.meta.last_extended_slot, 3);
        assert_eq!(parsed.addresses.as_ref(), &recipients);
        for instruction in [
            lookup_instruction::extend_lookup_table(
                table,
                sponsor.pubkey(),
                Some(sponsor.pubkey()),
                vec![Pubkey::new_unique()],
            ),
            lookup_instruction::deactivate_lookup_table(table, sponsor.pubkey()),
            lookup_instruction::close_lookup_table(table, sponsor.pubkey(), recipients[0]),
        ] {
            let fee_before = post.get_balance(&sponsor.pubkey());
            let failed = post
                .process_transaction_with_metadata(signed(
                    &post,
                    sponsor.pubkey(),
                    &sponsor_key,
                    &config,
                    &[instruction],
                ))
                .unwrap();
            assert!(matches!(
                failed.status,
                Err(TransactionError::InstructionError(_, _))
            ));
            assert_eq!(post.get_account(&table).unwrap(), after_table);
            assert_eq!(post.get_balance(&sponsor.pubkey()), fee_before - 5_000);
        }
        let classical: VersionedTransaction = Transaction::new_signed_with_payer(
            &[lookup_instruction::deactivate_lookup_table(
                table,
                authority.pubkey(),
            )],
            Some(&sponsor.pubkey()),
            &[&sponsor, &authority],
            post.last_blockhash(),
        )
        .into();
        assert_eq!(
            post.process_transaction_with_metadata(classical)
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        complete(&post);
        let active =
            Arc::new(Bank::new_isolated_pq_child(post.clone(), *post.leader(), 4).unwrap());
        let transfer = versioned(&active, recipients[1], 37);
        let static_tx =
            solana_transaction::versioned::sanitized::SanitizedVersionedTransaction::try_from(
                transfer.clone(),
            )
            .unwrap();
        let identity = replay_identity(&static_tx, &config.chain_id)
            .unwrap()
            .unwrap();
        assert_eq!(identity.len(), 48);
        assert!(!active.pq_transaction_processed(&transfer).unwrap());
        execute_ok(&active, transfer.clone());
        assert!(active.pq_transaction_processed(&transfer).unwrap());
        let resigned =
            sign_transaction(transfer.message.clone(), &config, &[&sponsor_key]).unwrap();
        assert_eq!(
            active
                .process_transaction_with_metadata(resigned)
                .unwrap_err(),
            TransactionError::AlreadyProcessed
        );
        // Same payer, amount and compiled transfer; the distinct resolved
        // address comes from a different lookup index and is a new intent.
        let other_lookup = versioned(&active, recipients[0], 37);
        let other_static =
            solana_transaction::versioned::sanitized::SanitizedVersionedTransaction::try_from(
                other_lookup.clone(),
            )
            .unwrap();
        assert_ne!(
            identity,
            replay_identity(&other_static, &config.chain_id)
                .unwrap()
                .unwrap()
        );
        execute_ok(&active, other_lookup);
        execute_ok(
            &active,
            authority_transaction(
                &active,
                lookup_instruction::deactivate_lookup_table(table, authority.pubkey()),
            ),
        );
        let close =
            lookup_instruction::close_lookup_table(table, authority.pubkey(), authority.pubkey());
        let before_close = active.get_account(&table).unwrap();
        let premature_fee_before = active.get_balance(&sponsor.pubkey());
        let refund_before = active.get_balance(&authority.pubkey());
        let premature = active
            .process_transaction_with_metadata(authority_transaction(&active, close.clone()))
            .unwrap();
        assert!(matches!(
            premature.status,
            Err(TransactionError::InstructionError(_, _))
        ));
        assert_eq!(active.get_account(&table).unwrap(), before_close);
        assert_eq!(
            active.get_balance(&sponsor.pubkey()),
            premature_fee_before - 10_000
        );
        assert_eq!(active.get_balance(&authority.pubkey()), refund_before);
        complete(&active);
        active.detach_isolated_pq_parent().unwrap();
        let mut mature = active;
        // Skipping slots does not remove a deactivation slot from SlotHashes.
        // Execute real Bank boundaries and reclaim each private physical parent.
        for _ in 0..=solana_slot_hashes::MAX_ENTRIES {
            let next = Arc::new(
                Bank::new_isolated_pq_child(mature.clone(), *mature.leader(), mature.slot() + 1)
                    .unwrap(),
            );
            complete(&next);
            next.detach_isolated_pq_parent().unwrap();
            mature = next;
        }
        assert!(mature.pq_transaction_processed(&transfer).unwrap());
        let slot_hashes: solana_slot_hashes::SlotHashes = wincode::deserialize(
            mature
                .get_account(&solana_sdk_ids::sysvar::slot_hashes::ID)
                .unwrap()
                .data(),
        )
        .unwrap();
        let account = mature.get_account(&table).unwrap();
        let table_state = AddressLookupTable::deserialize(account.data()).unwrap();
        assert_eq!(
            table_state.meta.status(mature.slot(), &slot_hashes),
            LookupTableStatus::Deactivated
        );
        // Closing executes in an unfrozen actual child, after the native cooldown.
        let closed =
            Bank::new_isolated_pq_child(mature.clone(), *mature.leader(), mature.slot() + 1)
                .unwrap();
        let recipient_before = closed.get_balance(&authority.pubkey());
        execute_ok(&closed, authority_transaction(&closed, close));
        assert!(closed.get_account(&table).is_none());
        assert_eq!(
            closed.get_balance(&authority.pubkey()),
            recipient_before + account.lamports()
        );
        assert_eq!(closed.get_balance(&recipients[0]), 20_000_000 + 31 + 37);
        assert_eq!(closed.get_balance(&recipients[1]), 20_000_000 + 37);
        assert_eq!(
            closed
                .process_transaction_with_metadata(versioned(&closed, recipients[1], 41))
                .unwrap_err(),
            TransactionError::AddressLookupTableNotFound
        );
    }

    #[test]
    fn real_funded_nonce_authority_migrates_and_funds_remain_accessible() {
        use {
            solana_account::state_traits::StateMutWincode,
            solana_nonce::{state::State as NonceState, versions::Versions as NonceVersions},
        };
        let (bank, sponsor, sponsor_key, config) = configured_bank(3, false);
        let authority = Keypair::new();
        let authority_key = FalconKeypair::generate();
        let recipient = Keypair::new();
        bank.store_account(
            &recipient.pubkey(),
            &AccountSharedData::new(20_000_000, 0, &solana_sdk_ids::system_program::ID),
        );
        let complete = |bank: &Bank| {
            let digest =
                hash_commitment(b"pq-nonce-test-native-tick", &[&bank.slot().to_le_bytes()]);
            let hash = Hash::new_from_array(digest[..32].try_into().unwrap());
            while bank.tick_height() < bank.max_tick_height() {
                bank.register_tick_for_test(&hash);
            }
            bank.freeze();
        };
        let (genesis, _forks) = bank.wrap_with_bank_forks_for_tests();
        let pre =
            Arc::new(Bank::new_isolated_pq_child(genesis.clone(), *genesis.leader(), 1).unwrap());
        let nonce = authority.pubkey();
        execute_ok(
            &pre,
            Transaction::new_signed_with_payer(
                &system_instruction::create_nonce_account(
                    &sponsor.pubkey(),
                    &nonce,
                    &authority.pubkey(),
                    pre.get_minimum_balance_for_rent_exemption(80) + 20_000_000,
                ),
                Some(&sponsor.pubkey()),
                &[&sponsor, &authority],
                pre.last_blockhash(),
            )
            .into(),
        );
        execute_ok(
            &pre,
            Transaction::new_signed_with_payer(
                &[system_instruction::withdraw_nonce_account(
                    &nonce,
                    &authority.pubkey(),
                    &recipient.pubkey(),
                    5,
                )],
                Some(&sponsor.pubkey()),
                &[&sponsor, &authority],
                pre.last_blockhash(),
            )
            .into(),
        );
        let original = pre.get_account(&nonce).unwrap();
        assert_eq!(original.owner(), &solana_sdk_ids::system_program::ID);
        assert_eq!(original.data().len(), 80);
        let original_versions: NonceVersions = original.state().unwrap();
        let NonceState::Initialized(original_data) = original_versions.state() else {
            panic!("actual System program did not initialize nonce");
        };
        assert_eq!(original_data.authority, nonce);
        for (actor, key, nonce_seed) in [
            (&authority, &authority_key, [0xb1; 32]),
            (&sponsor, &sponsor_key, [0xb2; 32]),
        ] {
            let upload = legacy_upload_key(&pre, &sponsor, key.public_key().as_bytes(), nonce_seed);
            let signers = if actor.pubkey() == sponsor.pubkey() {
                vec![&sponsor]
            } else {
                vec![&sponsor, &authority]
            };
            execute_ok(
                &pre,
                Transaction::new_signed_with_payer(
                    &[install_legacy_instruction(
                        &sponsor.pubkey(),
                        &actor.pubkey(),
                        &upload,
                        &sealed_upload_commitment(
                            &sponsor.pubkey(),
                            &nonce_seed,
                            key.public_key().as_bytes(),
                        ),
                    )],
                    Some(&sponsor.pubkey()),
                    &signers,
                    pre.last_blockhash(),
                )
                .into(),
            );
        }
        assert_eq!(pre.get_account(&nonce).unwrap(), original);
        complete(&pre);
        let post = Arc::new(Bank::new_isolated_pq_child(pre.clone(), *pre.leader(), 3).unwrap());
        let with_authority = |instructions: &[Instruction], hash| {
            let mut all = vec![authenticate_instruction(&[sponsor.pubkey(), nonce])];
            all.extend_from_slice(instructions);
            sign_transaction(
                VersionedMessage::Legacy(Message::new_with_blockhash(
                    &all,
                    Some(&sponsor.pubkey()),
                    &hash,
                )),
                &config,
                &[&sponsor_key, &authority_key],
            )
            .unwrap()
        };
        let withdraw =
            system_instruction::withdraw_nonce_account(&nonce, &nonce, &recipient.pubkey(), 11);
        execute_ok(
            &post,
            with_authority(std::slice::from_ref(&withdraw), post.last_blockhash()),
        );
        assert_eq!(post.get_balance(&recipient.pubkey()), 20_000_000 + 5 + 11);
        assert_eq!(post.get_account(&nonce).unwrap().data(), original.data());
        let nonce_before = post.get_account(&nonce).unwrap();
        let recipient_before = post.get_account(&recipient.pubkey()).unwrap();
        let fee_before = post.get_balance(&sponsor.pubkey());
        let wrong = post
            .process_transaction_with_metadata(signed(
                &post,
                sponsor.pubkey(),
                &sponsor_key,
                &config,
                &[system_instruction::withdraw_nonce_account(
                    &nonce,
                    &sponsor.pubkey(),
                    &recipient.pubkey(),
                    13,
                )],
            ))
            .unwrap();
        assert!(matches!(
            wrong.status,
            Err(TransactionError::InstructionError(_, _))
        ));
        assert_eq!(post.get_account(&nonce).unwrap(), nonce_before);
        assert_eq!(
            post.get_account(&recipient.pubkey()).unwrap(),
            recipient_before
        );
        assert_eq!(post.get_balance(&sponsor.pubkey()), fee_before - 5_000);
        let fee_before = post.get_balance(&sponsor.pubkey());
        let classical: VersionedTransaction = Transaction::new_signed_with_payer(
            &[system_instruction::withdraw_nonce_account(
                &nonce,
                &nonce,
                &recipient.pubkey(),
                17,
            )],
            Some(&sponsor.pubkey()),
            &[&sponsor, &authority],
            post.last_blockhash(),
        )
        .into();
        assert_eq!(
            post.process_transaction_with_metadata(classical)
                .unwrap_err(),
            TransactionError::SignatureFailure
        );
        assert_eq!(post.get_account(&nonce).unwrap(), nonce_before);
        assert_eq!(post.get_balance(&sponsor.pubkey()), fee_before);
        let lifetime = with_authority(
            &[system_instruction::advance_nonce_account(&nonce, &nonce)],
            original_data.blockhash(),
        );
        let VersionedMessage::Legacy(message) = lifetime.message.clone() else {
            unreachable!()
        };
        assert!(
            solana_transaction::uses_durable_nonce(&Transaction {
                signatures: lifetime.signatures.clone(),
                message,
            })
            .is_none()
        );
        assert_eq!(
            post.process_transaction_with_metadata(lifetime)
                .unwrap_err(),
            TransactionError::BlockhashNotFound
        );
        assert_eq!(post.get_account(&nonce).unwrap(), nonce_before);
        // Ordinary recent-blockhash authorization still permits changing the
        // native nonce authority. It does not grant durable-nonce lifetime.
        execute_ok(
            &post,
            with_authority(
                &[system_instruction::authorize_nonce_account(
                    &nonce,
                    &nonce,
                    &sponsor.pubkey(),
                )],
                post.last_blockhash(),
            ),
        );
        execute_ok(
            &post,
            signed(
                &post,
                sponsor.pubkey(),
                &sponsor_key,
                &config,
                &[system_instruction::advance_nonce_account(
                    &nonce,
                    &sponsor.pubkey(),
                )],
            ),
        );
        let advanced = post.get_account(&nonce).unwrap();
        let advanced_versions: NonceVersions = advanced.state().unwrap();
        let NonceState::Initialized(advanced_data) = advanced_versions.state() else {
            unreachable!()
        };
        assert_eq!(advanced_data.authority, sponsor.pubkey());
        assert_ne!(advanced_data.blockhash(), original_data.blockhash());
        complete(&post);
        let closed = Bank::new_isolated_pq_child(post.clone(), *post.leader(), 4).unwrap();
        let nonce_balance = closed.get_balance(&nonce);
        let recipient_before = closed.get_balance(&recipient.pubkey());
        execute_ok(
            &closed,
            signed(
                &closed,
                sponsor.pubkey(),
                &sponsor_key,
                &config,
                &[system_instruction::withdraw_nonce_account(
                    &nonce,
                    &sponsor.pubkey(),
                    &recipient.pubkey(),
                    nonce_balance,
                )],
            ),
        );
        assert!(closed.get_account(&nonce).is_none());
        assert_eq!(
            closed.get_balance(&recipient.pubkey()),
            recipient_before + nonce_balance
        );
        assert!(closed.get_account(&policy_address(&nonce)).is_some());
    }
}
