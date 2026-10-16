//! Native PQ instruction execution through the ordinary Agave SVM dispatcher.

use {
    crate::pq::{self, Config},
    agave_pq_crypto::{
        auth::{AuthRecord, Origin, fresh_address},
        crypto::FalconPublicKey,
        migration::{COMPLETE_SEED_PROFILE, SeedClaimStatement},
    },
    solana_account::Account,
    solana_instruction_error::InstructionError,
    solana_program_runtime::{declare_process_instruction, invoke_context::InvokeContext},
    solana_pubkey::Pubkey,
    solana_sdk_ids::system_program,
    solana_system_interface::instruction as system_instruction,
    solana_transaction_context::instruction::InstructionContext,
};

const UPLOAD_MAGIC: &[u8; 8] = b"AGAVEPQU";
const HEADER_BYTES: usize = 130;
const CAPACITY_OFFSET: usize = 72;
const LENGTH_OFFSET: usize = 76;
const SEALED_OFFSET: usize = 80;
const VERIFIED_OFFSET: usize = 81;
const DIGEST_OFFSET: usize = 82;

struct Upload<'a> {
    sponsor: Pubkey,
    nonce: [u8; 32],
    capacity: usize,
    sealed: bool,
    verified: u8,
    payload: &'a [u8],
}

impl<'a> Upload<'a> {
    fn decode(address: &Pubkey, data: &'a [u8]) -> Result<Self, InstructionError> {
        if data.len() < HEADER_BYTES || &data[..8] != UPLOAD_MAGIC {
            return Err(InstructionError::InvalidAccountData);
        }
        let sponsor = Pubkey::new_from_array(data[8..40].try_into().unwrap());
        let nonce = data[40..72].try_into().unwrap();
        let capacity = u32::from_le_bytes(
            data[CAPACITY_OFFSET..CAPACITY_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let length =
            u32::from_le_bytes(data[LENGTH_OFFSET..LENGTH_OFFSET + 4].try_into().unwrap()) as usize;
        if capacity == 0
            || capacity > pq::MAX_UPLOAD_BYTES
            || length > capacity
            || data.len() != HEADER_BYTES + length
            || data[SEALED_OFFSET] > 1
            || data[VERIFIED_OFFSET] > 2
            || pq::upload_address(&sponsor, &nonce) != *address
        {
            return Err(InstructionError::InvalidAccountData);
        }
        let result = Self {
            sponsor,
            nonce,
            capacity,
            sealed: data[SEALED_OFFSET] == 1,
            verified: data[VERIFIED_OFFSET],
            payload: &data[HEADER_BYTES..],
        };
        if result.sealed {
            if length != capacity || data[DIGEST_OFFSET..HEADER_BYTES] != result.commitment() {
                return Err(InstructionError::InvalidAccountData);
            }
        } else if data[DIGEST_OFFSET..HEADER_BYTES] != [0; 48] || result.verified != 0 {
            return Err(InstructionError::InvalidAccountData);
        }
        Ok(result)
    }

    fn commitment(&self) -> [u8; 48] {
        pq::sealed_upload_commitment(&self.sponsor, &self.nonce, self.payload)
    }
}

fn require_signer(context: &InstructionContext, index: u16) -> Result<Pubkey, InstructionError> {
    if !context.is_instruction_account_signer(index)? {
        return Err(InstructionError::MissingRequiredSignature);
    }
    Ok(*context.get_key_of_instruction_account(index)?)
}

fn config(context: &InstructionContext) -> Result<Config, InstructionError> {
    let index = context
        .get_number_of_instruction_accounts()
        .checked_sub(1)
        .ok_or(InstructionError::MissingAccount)?;
    let account = context.try_borrow_instruction_account(index)?;
    if account.get_key() != &pq::CONFIG_ADDRESS
        || account.get_owner() != &pq::PROGRAM_ID
        || context.is_instruction_account_writable(index)?
    {
        return Err(InstructionError::InvalidAccountOwner);
    }
    Config::decode(account.get_data()).map_err(|_| InstructionError::InvalidAccountData)
}

fn check_upload(
    context: &InstructionContext,
    index: u16,
    sponsor: &Pubkey,
) -> Result<Vec<u8>, InstructionError> {
    let account = context.try_borrow_instruction_account(index)?;
    if account.get_owner() != &pq::PROGRAM_ID {
        return Err(InstructionError::InvalidAccountOwner);
    }
    let upload = Upload::decode(account.get_key(), account.get_data())?;
    if upload.sponsor != *sponsor || !upload.sealed || upload.verified == 2 {
        return Err(InstructionError::InvalidAccountData);
    }
    Ok(upload.payload.to_vec())
}

fn create_upload(invoke: &mut InvokeContext, data: &[u8]) -> Result<(), InstructionError> {
    if data.len() != 36 {
        return Err(InstructionError::InvalidInstructionData);
    }
    let nonce: [u8; 32] = data[..32].try_into().unwrap();
    let capacity = u32::from_le_bytes(data[32..].try_into().unwrap()) as usize;
    if capacity == 0 || capacity > pq::MAX_UPLOAD_BYTES {
        return Err(InstructionError::InvalidInstructionData);
    }
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let sponsor = require_signer(&context, 0)?;
    let upload = *context.get_key_of_instruction_account(1)?;
    if upload != pq::upload_address(&sponsor, &nonce) {
        return Err(InstructionError::InvalidSeeds);
    }
    let (_, bump) =
        Pubkey::find_program_address(&[b"upload", sponsor.as_ref(), &nonce], &pq::PROGRAM_ID);
    let rent = invoke.environment_config.sysvar_cache().get_rent()?;
    // Reserve rent for the complete upload, while allocating bytes gradually
    // within the ordinary SVM per-instruction account-growth limit.
    invoke.native_invoke_signed(
        system_instruction::create_account(
            &sponsor,
            &upload,
            rent.minimum_balance(HEADER_BYTES + capacity).max(1),
            HEADER_BYTES as u64,
            &pq::PROGRAM_ID,
        ),
        &[&[b"upload", sponsor.as_ref(), &nonce, &[bump]]],
    )?;
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let mut account = context.try_borrow_instruction_account(1)?;
    let mut header = vec![0u8; HEADER_BYTES];
    header[..8].copy_from_slice(UPLOAD_MAGIC);
    header[8..40].copy_from_slice(sponsor.as_ref());
    header[40..72].copy_from_slice(&nonce);
    header[CAPACITY_OFFSET..CAPACITY_OFFSET + 4].copy_from_slice(&(capacity as u32).to_le_bytes());
    account.set_data_from_slice(&header)
}

fn write_upload(invoke: &mut InvokeContext, data: &[u8]) -> Result<(), InstructionError> {
    if data.len() <= 4 || data.len() > 4 + pq::MAX_UPLOAD_CHUNK_BYTES {
        return Err(InstructionError::InvalidInstructionData);
    }
    let offset = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let sponsor = require_signer(&context, 0)?;
    let mut account = context.try_borrow_instruction_account(1)?;
    if account.get_owner() != &pq::PROGRAM_ID {
        return Err(InstructionError::InvalidAccountOwner);
    }
    let upload = Upload::decode(account.get_key(), account.get_data())?;
    let new_length = offset
        .checked_add(data.len() - 4)
        .ok_or(InstructionError::ArithmeticOverflow)?;
    if upload.sponsor != sponsor
        || upload.sealed
        || offset != upload.payload.len()
        || new_length > upload.capacity
    {
        return Err(InstructionError::InvalidInstructionData);
    }
    account.extend_from_slice(&data[4..])?;
    account.get_data_mut()?[LENGTH_OFFSET..LENGTH_OFFSET + 4]
        .copy_from_slice(&(new_length as u32).to_le_bytes());
    Ok(())
}

fn seal_upload(invoke: &mut InvokeContext) -> Result<(), InstructionError> {
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let sponsor = require_signer(&context, 0)?;
    let mut account = context.try_borrow_instruction_account(1)?;
    if account.get_owner() != &pq::PROGRAM_ID {
        return Err(InstructionError::InvalidAccountOwner);
    }
    let upload = Upload::decode(account.get_key(), account.get_data())?;
    if upload.sponsor != sponsor || upload.sealed || upload.payload.len() != upload.capacity {
        return Err(InstructionError::InvalidInstructionData);
    }
    let digest = upload.commitment();
    let data = account.get_data_mut()?;
    data[SEALED_OFFSET] = 1;
    data[DIGEST_OFFSET..HEADER_BYTES].copy_from_slice(&digest);
    Ok(())
}

fn create_policy(
    invoke: &mut InvokeContext,
    authority: Pubkey,
    sponsor: Pubkey,
    key: FalconPublicKey,
    origin: Origin,
    external_claim: bool,
) -> Result<(), InstructionError> {
    let policy = pq::policy_address(&authority);
    {
        let context = invoke
            .transaction_context
            .get_current_instruction_context()?;
        let authority_account = context.try_borrow_instruction_account(1)?;
        // Migration preserves legacy owner/data, but executable program accounts
        // cannot become transaction authorities. Owner checks alone do not expose
        // the legacy executable bit for arbitrary program-owned accounts.
        #[expect(
            deprecated,
            reason = "migration must reject executable legacy accounts"
        )]
        let executable = authority_account.is_executable();
        if authority_account.get_key() != &authority
            || executable
            || (!external_claim
                && (authority_account.get_owner() != &system_program::id()
                    || !authority_account.get_data().is_empty()))
            || !context.is_instruction_account_writable(1)?
            || context.get_key_of_instruction_account(2)? != &policy
        {
            return Err(InstructionError::InvalidAccountData);
        }
        let existing = context.try_borrow_instruction_account(2)?;
        if existing.get_owner() != &system_program::id()
            || !existing.get_data().is_empty()
            || existing.get_lamports() != 0
        {
            return Err(InstructionError::AccountAlreadyInitialized);
        }
    }
    let record = AuthRecord::new(authority.to_bytes(), key, origin);
    let encoded = record.encode();
    let rent = invoke.environment_config.sysvar_cache().get_rent()?;
    let (_, bump) = Pubkey::find_program_address(&[b"auth", authority.as_ref()], &pq::PROGRAM_ID);
    invoke.native_invoke_signed(
        system_instruction::create_account(
            &sponsor,
            &policy,
            rent.minimum_balance(encoded.len()).max(1),
            encoded.len() as u64,
            &pq::PROGRAM_ID,
        ),
        &[&[b"auth", authority.as_ref(), &[bump]]],
    )?;
    invoke
        .transaction_context
        .get_current_instruction_context()?
        .try_borrow_instruction_account(2)?
        .set_data_from_slice(&encoded)
}

fn install(
    invoke: &mut InvokeContext,
    legacy: bool,
    expected_commitment: &[u8],
) -> Result<(), InstructionError> {
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let cfg = config(&context)?;
    let sponsor = require_signer(&context, 0)?;
    let authority = *context.get_key_of_instruction_account(1)?;
    let payload = check_upload(&context, 3, &sponsor)?;
    if legacy {
        let upload = context.try_borrow_instruction_account(3)?;
        if upload.get_data()[DIGEST_OFFSET..HEADER_BYTES] != *expected_commitment {
            return Err(InstructionError::InvalidInstructionData);
        }
    }
    let key_bytes = if legacy {
        if require_signer(&context, 1)? != authority
            || invoke.environment_config.sysvar_cache().get_clock()?.slot >= cfg.cutoff_slot
            || payload.len() != 897
        {
            return Err(InstructionError::InvalidInstructionData);
        }
        &payload[..]
    } else {
        if payload.len() != 929 {
            return Err(InstructionError::InvalidInstructionData);
        }
        &payload[..897]
    };
    let key = FalconPublicKey::from_bytes(key_bytes)
        .map_err(|_| InstructionError::InvalidInstructionData)?;
    if !legacy {
        let nonce: [u8; 32] = payload[897..].try_into().unwrap();
        if authority.to_bytes() != fresh_address(&cfg.chain_id, &key, &nonce) {
            return Err(InstructionError::InvalidSeeds);
        }
    }
    // Pre-cutoff installation uses the legacy authority's authenticated consent;
    // it does not claim that a private seed proof was supplied.
    create_policy(
        invoke,
        authority,
        sponsor,
        key,
        if legacy {
            Origin::LegacySignature
        } else {
            Origin::FreshIdentity
        },
        legacy,
    )
}

fn rotate(
    invoke: &mut InvokeContext,
    data: &[u8],
    sponsored: bool,
) -> Result<(), InstructionError> {
    if data.len() != if sponsored { 56 } else { 8 } {
        return Err(InstructionError::InvalidInstructionData);
    }
    let expected = u64::from_le_bytes(data[..8].try_into().unwrap());
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let authority = require_signer(&context, 0)?;
    if !context.is_instruction_account_writable(0)? {
        return Err(InstructionError::InvalidInstructionData);
    }
    let sponsor = if sponsored {
        let sponsor = require_signer(&context, 2)?;
        let account = context.try_borrow_instruction_account(2)?;
        if account.get_owner() != &system_program::id() || !account.get_data().is_empty() {
            return Err(InstructionError::InvalidAccountOwner);
        }
        sponsor
    } else {
        authority
    };
    let upload_index = if sponsored { 3 } else { 2 };
    let payload = check_upload(&context, upload_index, &sponsor)?;
    if sponsored {
        let account = context.try_borrow_instruction_account(upload_index)?;
        if account.get_data()[DIGEST_OFFSET..HEADER_BYTES] != data[8..] {
            return Err(InstructionError::InvalidInstructionData);
        }
    }
    let key = FalconPublicKey::from_bytes(&payload)
        .map_err(|_| InstructionError::InvalidInstructionData)?;
    let (encoded, lamports) = {
        let account = context.try_borrow_instruction_account(1)?;
        let state = Account {
            lamports: account.get_lamports(),
            data: account.get_data().to_vec(),
            owner: *account.get_owner(),
            executable: false,
            rent_epoch: u64::MAX,
        };
        let mut record =
            AuthRecord::from_account(&account.get_key().to_bytes(), &authority.to_bytes(), &state)
                .map_err(|_| InstructionError::InvalidAccountData)?;
        record
            .rotate(expected, key)
            .map_err(|_| InstructionError::InvalidInstructionData)?;
        (record.encode(), account.get_lamports())
    };
    let minimum = invoke
        .environment_config
        .sysvar_cache()
        .get_rent()?
        .minimum_balance(encoded.len());
    if let Some(deficit) = minimum.checked_sub(lamports).filter(|amount| *amount > 0) {
        invoke.native_invoke_signed(
            system_instruction::transfer(&sponsor, &pq::policy_address(&authority), deficit),
            &[],
        )?;
    }
    invoke
        .transaction_context
        .get_current_instruction_context()?
        .try_borrow_instruction_account(1)?
        .set_data_from_slice(&encoded)
}

fn seed_payload<'a>(
    payload: &'a [u8],
    cfg: &Config,
) -> Result<(SeedClaimStatement, &'a [u8]), InstructionError> {
    let length = payload
        .get(..2)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()) as usize)
        .ok_or(InstructionError::InvalidInstructionData)?;
    let statement_bytes = payload
        .get(2..2 + length)
        .ok_or(InstructionError::InvalidInstructionData)?;
    let statement = SeedClaimStatement::decode(statement_bytes)
        .map_err(|_| InstructionError::InvalidInstructionData)?;
    let proof = payload
        .get(2 + length..)
        .ok_or(InstructionError::InvalidInstructionData)?;
    if statement.intent.chain_id != cfg.chain_id
        || statement.intent.context != cfg.migration_context
        || statement.intent.expected_generation != 0
        || proof.len() < 16
        || &proof[..8] != b"SEEDPQ01"
        || u32::from_le_bytes(proof[8..12].try_into().unwrap()) != COMPLETE_SEED_PROFILE
        || u32::from_le_bytes(proof[12..16].try_into().unwrap()) as usize != proof.len() - 16
        || agave_pq_crypto::seed_proof::proof_profile(&proof[16..])
            .map_err(|_| InstructionError::InvalidInstructionData)?
            != COMPLETE_SEED_PROFILE
    {
        return Err(InstructionError::InvalidInstructionData);
    }
    Ok((statement, &proof[16..]))
}

fn verify_seed(invoke: &mut InvokeContext) -> Result<(), InstructionError> {
    invoke
        .consume_checked(1_000_000)
        .map_err(|_| InstructionError::ComputationalBudgetExceeded)?;
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let cfg = config(&context)?;
    let sponsor = require_signer(&context, 0)?;
    let mut account = context.try_borrow_instruction_account(1)?;
    if account.get_owner() != &pq::PROGRAM_ID {
        return Err(InstructionError::InvalidAccountOwner);
    }
    let upload = Upload::decode(account.get_key(), account.get_data())?;
    if upload.sponsor != sponsor || !upload.sealed || upload.verified != 0 {
        return Err(InstructionError::InvalidAccountData);
    }
    let (statement, proof) = seed_payload(upload.payload, &cfg)?;
    agave_pq_crypto::seed_proof::verify_seed_proof(&statement, proof)
        .map_err(|_| InstructionError::InvalidInstructionData)?;
    account.get_data_mut()?[VERIFIED_OFFSET] = 1;
    Ok(())
}

fn finalize_seed(invoke: &mut InvokeContext) -> Result<(), InstructionError> {
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let cfg = config(&context)?;
    let sponsor = require_signer(&context, 0)?;
    let authority = *context.get_key_of_instruction_account(1)?;
    let statement = {
        let account = context.try_borrow_instruction_account(3)?;
        if account.get_owner() != &pq::PROGRAM_ID {
            return Err(InstructionError::InvalidAccountOwner);
        }
        let upload = Upload::decode(account.get_key(), account.get_data())?;
        if upload.sponsor != sponsor || !upload.sealed || upload.verified != 1 {
            return Err(InstructionError::InvalidAccountData);
        }
        seed_payload(upload.payload, &cfg)?.0
    };
    if statement.intent.authority != authority.to_bytes() {
        return Err(InstructionError::InvalidInstructionData);
    }
    // The claimed authority deliberately is not a transaction signer. Only
    // execution of the complete private seed proof authorizes this migration.
    create_policy(
        invoke,
        authority,
        sponsor,
        statement.intent.replacement_key,
        Origin::OriginalSeed,
        true,
    )?;
    invoke
        .transaction_context
        .get_current_instruction_context()?
        .try_borrow_instruction_account(3)?
        .get_data_mut()?[VERIFIED_OFFSET] = 2;
    Ok(())
}

fn close_upload(invoke: &mut InvokeContext) -> Result<(), InstructionError> {
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let sponsor = require_signer(&context, 0)?;
    let mut account = context.try_borrow_instruction_account(1)?;
    if account.get_owner() != &pq::PROGRAM_ID {
        return Err(InstructionError::InvalidAccountOwner);
    }
    if Upload::decode(account.get_key(), account.get_data())?.sponsor != sponsor
        || account.get_key() == &sponsor
    {
        return Err(InstructionError::InvalidAccountData);
    }
    context
        .try_borrow_instruction_account(0)?
        .checked_add_lamports(account.get_lamports())?;
    account.set_lamports(0)?;
    account.set_data_length(0)?;
    account.set_owner(system_program::id().as_ref())
}

declare_process_instruction!(Entrypoint, 0, |invoke| {
    let context = invoke
        .transaction_context
        .get_current_instruction_context()?;
    let data = context.get_instruction_data().to_vec();
    for index in 0..context.get_number_of_instruction_accounts() {
        let address = context.get_key_of_instruction_account(index)?;
        if (address == &pq::CONFIG_ADDRESS || address == &pq::ROLE_REGISTRY_ADDRESS)
            && context.is_instruction_account_writable(index)?
        {
            return Err(InstructionError::ReadonlyDataModified);
        }
    }
    config(&context)?;
    if data.starts_with(pq::ENVELOPE_MAGIC) {
        if context.get_index_in_trace() != 0 {
            return Err(InstructionError::InvalidInstructionData);
        }
        // Bank performed full authorization before SVM granted transaction
        // signer privileges. Bill deterministic cost in ordinary compute units.
        let count = *data
            .get(8)
            .ok_or(InstructionError::InvalidInstructionData)?;
        invoke
            .consume_checked(4_000 * u64::from(count))
            .map_err(|_| InstructionError::ComputationalBudgetExceeded)?;
        return Ok(());
    }
    let (&opcode, payload) = data
        .split_first()
        .ok_or(InstructionError::InvalidInstructionData)?;
    invoke
        .consume_checked(2_000 + data.len() as u64)
        .map_err(|_| InstructionError::ComputationalBudgetExceeded)?;
    match opcode {
        pq::CREATE_UPLOAD => create_upload(invoke, payload),
        pq::WRITE_UPLOAD => write_upload(invoke, payload),
        pq::SEAL_UPLOAD if payload.is_empty() => seal_upload(invoke),
        pq::INSTALL_LEGACY if payload.len() == 48 => install(invoke, true, payload),
        pq::INSTALL_FRESH if payload.is_empty() => install(invoke, false, payload),
        pq::ROTATE => rotate(invoke, payload, false),
        pq::ROTATE_SPONSORED => rotate(invoke, payload, true),
        pq::VERIFY_SEED if payload.is_empty() => verify_seed(invoke),
        pq::FINALIZE_SEED if payload.is_empty() => finalize_seed(invoke),
        pq::CLOSE_UPLOAD if payload.is_empty() => close_upload(invoke),
        _ => Err(InstructionError::InvalidInstructionData),
    }
});
