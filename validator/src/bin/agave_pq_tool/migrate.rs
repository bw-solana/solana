//! Real onchain pre-cut consent, application state migration and post-cut use.
use {super::*, solana_runtime::pq_workload as app, std::collections::BTreeMap};

fn default_true() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationSpec {
    manifest: PathBuf,
    #[serde(default)]
    sponsor_wallet: Option<usize>,
    #[serde(default)]
    rpc_url: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_true")]
    wait_for_cutoff: bool,
    #[serde(default = "default_true")]
    exercise_rich_state: bool,
    output: PathBuf,
}

fn default_probe_states() -> usize {
    4
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SharedAuthorityProbeSpec {
    manifest: PathBuf,
    sponsor_wallet: usize,
    #[serde(default)]
    rpc_url: Option<String>,
    #[serde(default = "default_probe_states")]
    state_count: usize,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    output: PathBuf,
}

struct Client {
    manifest: Manifest,
    config: RuntimeConfig,
    rpc: Rpc,
    url: String,
    sponsor: usize,
    classical: BTreeMap<usize, Keypair>,
    pq: BTreeMap<usize, FalconKeypair>,
    receipts: Vec<Value>,
    timeout: Duration,
}

fn account_snapshots(
    rpc: &Rpc,
    url: &str,
    addresses: &[String],
) -> Result<BTreeMap<String, Value>> {
    let mut accounts = BTreeMap::new();
    for chunk in addresses.chunks(100) {
        let response = rpc.call(
            url,
            "getMultipleAccounts",
            json!([chunk,{"encoding":"base64","commitment":"finalized"}]),
        )?;
        let values = response["value"]
            .as_array()
            .context("migration account snapshot response")?;
        ensure!(
            values.len() == chunk.len(),
            "migration account snapshot response length mismatch"
        );
        for (address, value) in chunk.iter().zip(values) {
            ensure!(
                accounts.insert(address.clone(), value.clone()).is_none(),
                "duplicate migration account snapshot address"
            );
        }
    }
    Ok(accounts)
}

impl Client {
    fn address(&self, index: usize) -> Result<Pubkey> {
        Pubkey::from_str(
            &self
                .manifest
                .wallets
                .get(index)
                .context("migration wallet index")?
                .address,
        )
        .map_err(Into::into)
    }
    fn transaction(
        &self,
        instructions: &[Instruction],
        participants: &[usize],
        quantum: bool,
    ) -> Result<VersionedTransaction> {
        let mut indices = vec![self.sponsor];
        for index in participants {
            if !indices.contains(index) {
                indices.push(*index);
            }
        }
        let payer = self.address(self.sponsor)?;
        let hash = self.rpc.hash(&self.url)?;
        if quantum {
            let authorities = indices
                .iter()
                .map(|index| self.address(*index))
                .collect::<Result<Vec<_>>>()?;
            let mut all = vec![authenticate_instruction(&authorities)];
            all.extend_from_slice(instructions);
            let message = Message::new_with_blockhash(&all, Some(&payer), &hash);
            let keys = indices
                .iter()
                .map(|index| -> Result<_> { self.pq.get(index).context("PQ signer key") })
                .collect::<Result<Vec<_>>>()?;
            pq::sign_transaction(VersionedMessage::Legacy(message), &self.config, &keys)
                .map_err(Into::into)
        } else {
            let message = VersionedMessage::Legacy(Message::new_with_blockhash(
                instructions,
                Some(&payer),
                &hash,
            ));
            let keys = indices
                .iter()
                .map(|index| self.classical.get(index).context("classical signer key"))
                .collect::<Result<Vec<_>>>()?;
            VersionedTransaction::try_new(message, &keys).map_err(Into::into)
        }
    }
    fn confirm(
        &mut self,
        label: &str,
        instructions: &[Instruction],
        participants: &[usize],
        quantum: bool,
        expected_error: Option<u32>,
    ) -> Result<String> {
        let tx = self.transaction(instructions, participants, quantum)?;
        let id = self.rpc.submit(&self.url, &tx)?;
        let started = Instant::now();
        loop {
            let status = self.rpc.call(
                &self.url,
                "getSignatureStatuses",
                json!([[id],{"searchTransactionHistory":true}]),
            )?;
            let row = &status["value"][0];
            if row["confirmationStatus"] == "finalized" {
                if let Some(code) = expected_error {
                    ensure!(
                        row["err"]["InstructionError"][1]["Custom"].as_u64()
                            == Some(u64::from(code)),
                        "expected exact SBF rollback error, got {}",
                        row["err"]
                    );
                } else {
                    ensure!(
                        row["err"].is_null(),
                        "migration transaction failed onchain: {}",
                        row["err"]
                    );
                }
                break;
            }
            ensure!(
                started.elapsed() < self.timeout,
                "migration transaction finality timeout: {label} {id}"
            );
            thread::sleep(Duration::from_millis(25));
        }
        let receipt=self.rpc.call(&self.url,"getTransaction",json!([id,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]))?;
        ensure!(
            !receipt.is_null()
                && receipt["transaction"][0] == BASE64_STANDARD.encode(wincode::serialize(&tx)?),
            "exact finalized migration receipt missing or changed"
        );
        self.receipts.push(json!({"label":label,"id":id,"quantum":quantum,"expected_error":expected_error,"receipt":receipt}));
        Ok(id)
    }
    fn account(&self, address: &Pubkey) -> Result<Value> {
        Ok(self.rpc.call(
            &self.url,
            "getAccountInfo",
            json!([address.to_string(),{"encoding":"base64","commitment":"finalized"}]),
        )?["value"]
            .clone())
    }
    fn key_upload(
        &mut self,
        key: &FalconKeypair,
        quantum: bool,
        label: &str,
    ) -> Result<(Pubkey, [u8; 32])> {
        let sponsor = self.address(self.sponsor)?;
        let nonce: [u8; 32] = rand::random();
        let upload = upload_address(&sponsor, &nonce);
        let bytes = key.public_key();
        self.confirm(
            label,
            &[
                create_upload_instruction(&sponsor, &nonce, u32::try_from(bytes.as_bytes().len())?),
                write_upload_instruction(&sponsor, &upload, 0, bytes.as_bytes()),
                seal_upload_instruction(&sponsor, &upload),
            ],
            &[],
            quantum,
            None,
        )?;
        Ok((upload, nonce))
    }
    fn enroll(&mut self, index: usize, sponsor_quantum: bool) -> Result<()> {
        let authority = self.address(index)?;
        let before = self.account(&authority)?;
        let public = self
            .pq
            .get(&index)
            .context("enrollment Falcon key")?
            .public_key();
        let sponsor = self.address(self.sponsor)?;
        let nonce: [u8; 32] = rand::random();
        let upload = upload_address(&sponsor, &nonce);
        self.confirm(
            "legacy_key_upload",
            &[
                create_upload_instruction(
                    &sponsor,
                    &nonce,
                    u32::try_from(public.as_bytes().len())?,
                ),
                write_upload_instruction(&sponsor, &upload, 0, public.as_bytes()),
                seal_upload_instruction(&sponsor, &upload),
            ],
            &[],
            sponsor_quantum,
            None,
        )?;
        self.confirm(
            "install_legacy_consent",
            &[pq::install_legacy_instruction(
                &sponsor,
                &authority,
                &upload,
                &pq::sealed_upload_commitment(&sponsor, &nonce, public.as_bytes()),
            )],
            &[index],
            false,
            None,
        )?;
        let after = self.account(&authority)?;
        ensure!(
            before["owner"] == after["owner"]
                && before["data"] == after["data"]
                && before["executable"] == after["executable"],
            "legacy migration changed application account layout or owner"
        );
        if index != self.sponsor {
            ensure!(
                before["lamports"] == after["lamports"],
                "sponsored migration changed authority lamports"
            );
        }
        self.confirm(
            "close_legacy_key_upload",
            &[close_upload_instruction(&sponsor, &upload)],
            &[],
            index == self.sponsor,
            None,
        )?;
        ensure!(
            self.account(&upload)?.is_null(),
            "legacy upload refund failed"
        );
        Ok(())
    }
    fn app_accounts(
        &self,
        state: &WorkloadStateManifest,
        primary: usize,
        secondary: usize,
    ) -> Result<app::Accounts> {
        Ok(app::Accounts {
            state: Pubkey::from_str(&state.state)?,
            primary: self.address(primary)?,
            secondary: self.address(secondary)?,
            sponsor: self.address(self.sponsor)?,
            recipient: Pubkey::from_str(&self.manifest.recipient)?,
        })
    }
    fn token_transfer(
        &mut self,
        index: usize,
        amount: u64,
        quantum: bool,
        label: &str,
    ) -> Result<()> {
        if self.manifest.token_mint.is_none() {
            return Ok(());
        }
        let instruction = spl_token_interface::instruction::transfer_checked(
            &spl_generic_token::token::id(),
            &Pubkey::from_str(&self.manifest.wallet_token_accounts[index])?,
            &Pubkey::from_str(self.manifest.token_mint.as_deref().unwrap())?,
            &Pubkey::from_str(&self.manifest.recipient_token_accounts[0])?,
            &self.address(index)?,
            &[],
            amount,
            0,
        )?;
        self.confirm(label, &[instruction], &[index], quantum, None)?;
        Ok(())
    }
}

pub(super) fn run(spec: MigrationSpec) -> Result<Value> {
    run_inner(spec, false)
}

pub(super) fn resume_rich_migration(spec: MigrationSpec) -> Result<Value> {
    run_inner(spec, true)
}

fn genesis_snapshot(genesis: &GenesisConfig, address: &str) -> Result<Value> {
    let account = genesis
        .accounts
        .get(&Pubkey::from_str(address)?)
        .context("trusted genesis account")?;
    Ok(
        json!({"data":[BASE64_STANDARD.encode(&account.data),"base64"],"executable":account.executable,"lamports":account.lamports,"owner":account.owner.to_string(),"rentEpoch":account.rent_epoch,"space":account.data.len()}),
    )
}

fn validate_specific_resume(
    client: &Client,
    states: &[WorkloadStateManifest],
    legacy: &[usize],
    genesis: &GenesisConfig,
    token_addresses: &[String],
) -> Result<Value> {
    ensure!(
        states.len() == 16 && states[0].primary_wallet == 0,
        "unsupported interrupted vault layout"
    );
    let expected_recipient_tokens = 42u64
        .checked_mul(u64::try_from(states.len())?)
        .and_then(|n| n.checked_add(43))
        .context("resume token sum")?;
    let policy_addresses = legacy
        .iter()
        .map(|index| Ok(policy_address(&client.address(*index)?).to_string()))
        .collect::<Result<Vec<_>>>()?;
    let app_addresses = states
        .iter()
        .map(|state| state.state.clone())
        .collect::<Vec<_>>();
    let mut snapshots = Vec::new();
    for (node_index, node) in client.manifest.nodes.iter().enumerate() {
        let status = client
            .rpc
            .call(&node.rpc_url, "getExperimentalPqStatus", json!([]))?;
        ensure!(
            status["finalized_transactions"] == 172
                && status["mempool"] == 0
                && status["slot"].as_u64().context("resume native slot")?
                    >= client.manifest.cutoff_slot,
            "resume requires exactly172 committed transactions, empty ingress and actual postcut \
             state"
        );
        let policies = account_snapshots(&client.rpc, &node.rpc_url, &policy_addresses)?;
        let apps = account_snapshots(&client.rpc, &node.rpc_url, &app_addresses)?;
        let escrows = account_snapshots(
            &client.rpc,
            &node.rpc_url,
            &states
                .iter()
                .map(|state| state.escrow.clone())
                .collect::<Vec<_>>(),
        )?;
        for (index, address) in legacy.iter().zip(&policy_addresses) {
            let value = &policies[address];
            ensure!(
                value["owner"] == pq::PROGRAM_ID.to_string() && value["executable"] == false,
                "resume legacy policy owner mismatch"
            );
            let record = AuthRecord::decode(
                &BASE64_STANDARD
                    .decode(value["data"][0].as_str().context("resume policy bytes")?)?,
            )?;
            ensure!(
                record.authority == client.address(*index)?.to_bytes()
                    && record.origin == Origin::LegacySignature
                    && record.generation == if *index == 0 { 2 } else { 1 }
                    && record.public_key == client.pq[index].public_key(),
                "resume policy generation, origin or saved private key does not match live \
                 finalized state"
            );
        }
        for state in states {
            let original = genesis
                .accounts
                .get(&Pubkey::from_str(&state.state)?)
                .context("resume trusted app")?;
            let value = &apps[&state.state];
            let bytes =
                BASE64_STANDARD.decode(value["data"][0].as_str().context("resume app bytes")?)?;
            let mut expected = if state.primary_wallet == 0 {
                app::State::new(client.address(33)?, client.address(34)?)
            } else {
                app::State::new(
                    client.address(state.primary_wallet)?,
                    client.address(state.secondary_wallet)?,
                )
            };
            expected.initialized = true;
            if state.primary_wallet == 0 {
                expected.last_sequence = 7;
                expected.operations = 7;
                expected.deposited = 15;
                expected.withdrawn = 6;
                expected.rotations = 1;
            } else {
                expected.last_sequence = 3;
                expected.operations = 3;
                expected.deposited = 7;
                expected.withdrawn = 3;
            }
            let mut expected_bytes = expected.encode(original.data.len());
            expected_bytes[app::STATE_BYTES..].copy_from_slice(&original.data[app::STATE_BYTES..]);
            ensure!(
                bytes == expected_bytes
                    && value["owner"] == original.owner.to_string()
                    && value["lamports"] == original.lamports
                    && value["executable"] == original.executable,
                "resume only accepts first vault exactsequence7 and remaining pristine \
                 post-enrollment sequence3, with original owner/rent/padding"
            );
            let escrow = &escrows[&state.escrow];
            let expected_lamports = genesis
                .rent
                .minimum_balance(0)
                .checked_add(if state.primary_wallet == 0 { 9 } else { 4 })
                .context("resume escrow sum")?;
            ensure!(
                escrow["owner"] == system_program::id().to_string()
                    && escrow["lamports"] == expected_lamports
                    && escrow["executable"] == false
                    && BASE64_STANDARD
                        .decode(escrow["data"][0].as_str().context("resume escrow bytes")?)?
                        .is_empty(),
                "resume live PDA collateral differs from exact supported stage"
            );
        }
        let mint = client
            .manifest
            .token_mint
            .as_ref()
            .context("resume requires genuine SPL state")?;
        let current_mint = client.rpc.call(
            &node.rpc_url,
            "getAccountInfo",
            json!([mint,{"encoding":"base64","commitment":"finalized"}]),
        )?["value"]
            .clone();
        ensure!(
            current_mint == genesis_snapshot(genesis, mint)?,
            "resume mint supply/authority/data changed"
        );
        let tokens = account_snapshots(&client.rpc, &node.rpc_url, token_addresses)?;
        for address in token_addresses {
            let original = genesis
                .accounts
                .get(&Pubkey::from_str(address)?)
                .context("resume trusted token")?;
            ensure!(
                original.data.len() == 165,
                "resume supports canonical SPL token accounts"
            );
            let mut expected = original.data.clone();
            let before = u64::from_le_bytes(expected[64..72].try_into().unwrap());
            let outgoing = states.iter().find(|state| {
                client
                    .manifest
                    .wallet_token_accounts
                    .get(state.primary_wallet)
                    == Some(address)
            });
            let expected_amount = if let Some(state) = outgoing {
                before.checked_sub(if state.primary_wallet == 0 { 85 } else { 42 })
            } else if client.manifest.recipient_token_accounts.first() == Some(address) {
                before.checked_add(expected_recipient_tokens)
            } else {
                Some(before)
            }
            .context("resume expected token amount")?;
            expected[64..72].copy_from_slice(&expected_amount.to_le_bytes());
            let value = &tokens[address];
            ensure!(
                BASE64_STANDARD
                    .decode(value["data"][0].as_str().context("resume current token")?)?
                    == expected
                    && value["owner"] == original.owner.to_string()
                    && value["lamports"] == original.lamports,
                "resume token assets/owners differ from exact supported interrupted stage"
            );
        }
        let recipient = genesis
            .accounts
            .get(&Pubkey::from_str(&client.manifest.recipient)?)
            .context("resume trusted recipient")?;
        ensure!(
            client
                .rpc
                .balance(&node.rpc_url, &client.manifest.recipient)?
                == recipient
                    .lamports
                    .checked_add(51)
                    .context("resume initial recipient sum")?,
            "resume recipient assets changed outside supported migration"
        );
        snapshots.push(json!({"node_index":node_index,"committed_transactions":172,"slot":status["slot"],"applications":apps,"policies":policies,"escrows":escrows,"all_token_accounts_match_supported_stage":true,"mint_unchanged":true}));
    }
    Ok(
        json!({"supported_interruption":"first_vault_sequence7_after_app_rotation_remaining15_sequence3","trusted_genesis_hash":genesis.hash().to_string(),"previous_committed_transactions":172,"previous_success":171,"previous_expected_cpi_rollback":1,"nodes":snapshots}),
    )
}

/// Final custody auditing is readonly: no transaction construction, signing,
/// migration writes or credential replacement can enter this worker scope.
struct MigrationFinalAudit<'a> {
    client: &'a Client,
    legacy: &'a [usize],
    states: &'a [WorkloadStateManifest],
    successful_ids: &'a [String],
    initial_app_accounts: &'a BTreeMap<String, Value>,
    initial_mint: Option<&'a Value>,
    initial_tokens: &'a BTreeMap<String, Value>,
    token_addresses: &'a [String],
    trusted_genesis: &'a GenesisConfig,
    exercise_rich_state: bool,
    resume: bool,
}

const FINAL_AUDIT_WORKERS: usize = 8;

fn audit_migration_node(audit: &MigrationFinalAudit<'_>, node: &NodeManifest) -> Result<Value> {
    audit
        .client
        .rpc
        .wait(&node.rpc_url, audit.successful_ids, audit.client.timeout)?;
    let mut policies = Vec::new();
    for index in audit.legacy {
        let authority = audit.client.address(*index)?;
        let account=audit.client.rpc.call(&node.rpc_url,"getAccountInfo",json!([policy_address(&authority).to_string(),{"encoding":"base64","commitment":"finalized"}]))?;
        let value = &account["value"];
        let record = AuthRecord::decode(
            &BASE64_STANDARD.decode(
                value["data"][0]
                    .as_str()
                    .context("installed legacy policy data")?,
            )?,
        )?;
        ensure!(
            record.authority == authority.to_bytes()
                && record.public_key == audit.client.pq[index].public_key()
                && record.origin == Origin::LegacySignature,
            "all-node installed migrated policy mismatch"
        );
        policies.push(json!({"wallet":index,"authority":authority,"generation":record.generation,"origin":"LegacySignature"}));
    }
    let mut app_states = Vec::new();
    for state in audit.states {
        let value = audit.client.rpc.call(
            &node.rpc_url,
            "getAccountInfo",
            json!([state.state,{"encoding":"base64","commitment":"finalized"}]),
        )?["value"]
            .clone();
        ensure!(
            value["owner"] == app::PROGRAM_ID.to_string(),
            "migrated app state owner changed"
        );
        let bytes = BASE64_STANDARD.decode(value["data"][0].as_str().context("app data")?)?;
        ensure!(
            bytes.len() == state.data_bytes,
            "migrated application padding lost"
        );
        let decoded = app::State::decode(&bytes).context("migrated application layout")?;
        let original = &audit.initial_app_accounts[&state.state];
        let old_bytes = BASE64_STANDARD.decode(
            original["data"][0]
                .as_str()
                .context("original app state bytes")?,
        )?;
        ensure!(
            bytes[app::STATE_BYTES..] == old_bytes[app::STATE_BYTES..]
                && value["lamports"] == original["lamports"]
                && value["executable"] == original["executable"],
            "application padding, rent or executable bit changed during migration"
        );
        if audit.exercise_rich_state {
            ensure!(
                decoded.last_sequence == 8 && decoded.rotations == 1 && decoded.initialized,
                "postcut application transition missing"
            );
        }
        app_states.push(json!({"state":state.state,"data_sha384":agave_pq_crypto::crypto::hash_commitment(b"pq-live-app-state/v1",&[&bytes]).to_vec(),"last_sequence":decoded.last_sequence,"rotations":decoded.rotations}));
    }
    let mut token_accounts = Vec::new();
    if let Some(mint) = &audit.client.manifest.token_mint {
        let account = audit.client.rpc.call(
            &node.rpc_url,
            "getAccountInfo",
            json!([mint,{"encoding":"base64","commitment":"finalized"}]),
        )?["value"]
            .clone();
        ensure!(
            Some(&account) == audit.initial_mint,
            "mint owner/authority/supply/rent changed across migration"
        );
        use solana_program_pack::Pack;
        let current_tokens =
            account_snapshots(&audit.client.rpc, &node.rpc_url, audit.token_addresses)?;
        for (address, before) in audit.initial_tokens {
            let current = &current_tokens[address];
            let before_data = BASE64_STANDARD.decode(
                before["data"][0]
                    .as_str()
                    .context("initial token account")?,
            )?;
            let current_data = BASE64_STANDARD.decode(
                current["data"][0]
                    .as_str()
                    .context("current token account")?,
            )?;
            let old = spl_token_interface::state::Account::unpack(&before_data)?;
            let new = spl_token_interface::state::Account::unpack(&current_data)?;
            let outgoing = audit
                .states
                .iter()
                .filter(|state| {
                    audit
                        .client
                        .manifest
                        .wallet_token_accounts
                        .get(state.primary_wallet)
                        == Some(address)
                })
                .count();
            let incoming = usize::from(
                audit.client.manifest.recipient_token_accounts.first() == Some(address),
            );
            let transferred = if audit.exercise_rich_state { 85u64 } else { 0 };
            let expected = old
                .amount
                .checked_sub(
                    u64::try_from(outgoing)?
                        .checked_mul(transferred)
                        .context("token debit overflow")?,
                )
                .and_then(|amount| {
                    amount.checked_add(
                        u64::try_from(audit.states.len())
                            .ok()?
                            .checked_mul(transferred)?
                            .checked_mul(u64::try_from(incoming).ok()?)?,
                    )
                })
                .context("migrated token balance overflow")?;
            ensure!(
                new.amount == expected
                    && new.owner == old.owner
                    && new.mint == old.mint
                    && before_data[..64] == current_data[..64]
                    && before_data[72..] == current_data[72..]
                    && current["owner"] == before["owner"]
                    && current["lamports"] == before["lamports"],
                "token owner/amount/delegate/account state changed unexpectedly"
            );
            token_accounts.push(json!({"address":address,"authority":new.owner,"amount":new.amount,"mint":new.mint}));
        }
    }
    let recipient_balance = audit
        .client
        .rpc
        .balance(&node.rpc_url, &audit.client.manifest.recipient)?;
    if audit.resume {
        let baseline = audit
            .trusted_genesis
            .accounts
            .get(&Pubkey::from_str(&audit.client.manifest.recipient)?)
            .context("resumed recipient genesis")?
            .lamports;
        let increase = audit
            .trusted_genesis
            .rent
            .minimum_balance(0)
            .checked_add(15)
            .and_then(|per| per.checked_mul(u64::try_from(audit.states.len()).ok()?))
            .context("resumed full recipient total")?;
        ensure!(
            Some(recipient_balance) == baseline.checked_add(increase),
            "resumed complete PDA asset/rent accounting mismatch"
        );
    }
    let status = audit
        .client
        .rpc
        .call(&node.rpc_url, "getExperimentalPqStatus", json!([]))?;
    if audit.resume {
        ensure!(
            status["finalized_transactions"] == 323,
            "resumed migration must have exactly323 actual committed transactions"
        );
    }
    Ok(
        json!({"host":node.host,"policies":policies,"application_states":app_states,"token_accounts":token_accounts,"mint_unchanged":audit.initial_mint.is_some(),"recipient_balance":recipient_balance,"status":status}),
    )
}

fn audit_final_nodes(audit: &MigrationFinalAudit<'_>) -> Result<Vec<Value>> {
    let nodes = &audit.client.manifest.nodes;
    ensure!(
        !nodes.is_empty(),
        "migration requires validators for final custody audit"
    );
    // A dedicated pool gives the audit a finite concurrency bound independent
    // of the tool's global Rayon configuration. Indexed collection preserves
    // manifest order even when a later validator finishes first.
    let workers = FINAL_AUDIT_WORKERS.min(nodes.len());
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()?;
    let result = pool.install(|| {
        nodes
            .par_iter()
            .map(|node| audit_migration_node(audit, node))
            .collect::<Result<Vec<_>>>()
    })?;
    ensure!(
        result
            .iter()
            .all(|node| node["policies"] == result[0]["policies"]
                && node["application_states"] == result[0]["application_states"]
                && node["token_accounts"] == result[0]["token_accounts"]
                && node["recipient_balance"] == result[0]["recipient_balance"]),
        "all-node migrated state/balance mismatch"
    );
    Ok(result)
}

fn run_inner(spec: MigrationSpec, resume: bool) -> Result<Value> {
    let manifest: Manifest = read_json(&spec.manifest)?;
    ensure!(
        manifest.cutoff_slot > 0,
        "migration needs immutable future cutoff"
    );
    ensure!(!spec.output.exists(), "migration output must be fresh");
    let legacy: Vec<_> = manifest
        .wallets
        .iter()
        .filter(|wallet| wallet.legacy_private_key.is_some())
        .map(|wallet| wallet.index)
        .collect();
    ensure!(
        !legacy.is_empty(),
        "no genuine legacy authorities in genesis"
    );
    let sponsor = spec.sponsor_wallet.unwrap_or(*legacy.last().unwrap());
    ensure!(
        legacy.contains(&sponsor),
        "enrollment sponsor must be a genuine uninstalled legacy System authority"
    );
    let rpc = Rpc::new()?;
    let url = spec
        .rpc_url
        .clone()
        .unwrap_or_else(|| manifest.nodes[0].rpc_url.clone());
    let entry_slot = rpc
        .call(&url, "getSlot", json!([{"commitment":"finalized"}]))?
        .as_u64()
        .context("cutoff slot")?;
    ensure!(
        if resume {
            entry_slot >= manifest.cutoff_slot
        } else {
            entry_slot < manifest.cutoff_slot
        },
        "migration cutoff does not match requested stage"
    );
    let mut classical = BTreeMap::new();
    let mut pq_keys = BTreeMap::new();
    for wallet in &manifest.wallets {
        pq_keys.insert(
            wallet.index,
            FalconKeypair::load_private(&wallet.private_key)?,
        );
        if let Some(path) = &wallet.legacy_private_key {
            classical.insert(
                wallet.index,
                solana_keypair::read_keypair_file(path)
                    .map_err(|error| anyhow!(error.to_string()))?,
            );
        }
    }
    if resume {
        ensure!(
            legacy.len() == 33 && sponsor == 32 && spec.exercise_rich_state,
            "resume supports only the interrupted 33-authority rich custody scenario"
        );
        pq_keys.insert(
            0,
            FalconKeypair::load_private(manifest.directory.join("rotated-wallet-0.key"))?,
        );
    }
    let mut client = Client {
        config: native_config(&manifest)?,
        url,
        rpc,
        sponsor,
        classical,
        pq: pq_keys,
        manifest,
        receipts: Vec::new(),
        timeout: Duration::from_secs(spec.timeout_seconds),
    };
    let states: Vec<_> = client
        .manifest
        .workload_states
        .iter()
        .filter(|state| state.authority_is_state_address)
        .cloned()
        .collect();
    let trusted_genesis = GenesisConfig::load(&client.manifest.nodes[0].ledger)?;
    ensure!(
        trusted_genesis.hash().to_string() == client.manifest.genesis_hash,
        "serialized genesis baseline does not match pinned manifest"
    );
    let before_slot =
        client
            .rpc
            .call(&client.url, "getSlot", json!([{"commitment":"finalized"}]))?;
    let initial_app_accounts = states
        .iter()
        .map(|state| -> Result<_> {
            Ok((
                state.state.clone(),
                if resume {
                    genesis_snapshot(&trusted_genesis, &state.state)?
                } else {
                    client.account(&Pubkey::from_str(&state.state)?)?
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let initial_mint = client
        .manifest
        .token_mint
        .as_ref()
        .map(|mint| -> Result<_> {
            if resume {
                genesis_snapshot(&trusted_genesis, mint)
            } else {
                client.account(&Pubkey::from_str(mint)?)
            }
        })
        .transpose()?;
    let token_addresses = client
        .manifest
        .wallet_token_accounts
        .iter()
        .chain(&client.manifest.recipient_token_accounts)
        .cloned()
        .collect::<Vec<_>>();
    let initial_tokens = if resume {
        token_addresses
            .iter()
            .map(|address| {
                Ok((
                    address.clone(),
                    genesis_snapshot(&trusted_genesis, address)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?
    } else {
        account_snapshots(&client.rpc, &client.url, &token_addresses)?
    };
    let resume_before = if resume {
        Some(validate_specific_resume(
            &client,
            &states,
            &legacy,
            &trusted_genesis,
            &token_addresses,
        )?)
    } else {
        None
    };
    if let Some(before) = &resume_before {
        write_json(&spec.output.with_extension("resume-before.json"), before)?;
    }
    if spec.exercise_rich_state && !resume {
        for state in &states {
            let accounts =
                client.app_accounts(state, state.primary_wallet, state.secondary_wallet)?;
            client.confirm(
                "precut_sbf_initialize_pda",
                &[accounts.initialize(solana_rent::Rent::default().minimum_balance(0), 1)],
                &[state.primary_wallet],
                false,
                None,
            )?;
            client.confirm(
                "precut_sbf_deposit",
                &[accounts.deposit(7, 2)],
                &[state.primary_wallet],
                false,
                None,
            )?;
            client.confirm(
                "precut_sbf_multisig_withdraw",
                &[accounts.withdraw(3, 3)],
                &[state.primary_wallet, state.secondary_wallet],
                false,
                None,
            )?;
            client.token_transfer(state.primary_wallet, 42, false, "precut_spl_transfer")?;
        }
    }
    let prior_accounts = legacy
        .iter()
        .map(|index| -> Result<_> {
            Ok((index.to_string(), client.account(&client.address(*index)?)?))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if !resume {
        for index in legacy.iter().filter(|index| **index != sponsor) {
            client.enroll(*index, false)?;
        }
        client.enroll(sponsor, false)?;
    }
    if spec.wait_for_cutoff {
        let started = Instant::now();
        loop {
            let slot = client
                .rpc
                .call(&client.url, "getSlot", json!([{"commitment":"finalized"}]))?
                .as_u64()
                .context("postcut slot")?;
            if slot >= client.manifest.cutoff_slot {
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(spec.timeout_seconds.max(3600)),
                "waiting for actual immutable cutoff timed out"
            );
            thread::sleep(Duration::from_millis(250));
        }
    }
    let postcut_slot =
        client
            .rpc
            .call(&client.url, "getSlot", json!([{"commitment":"finalized"}]))?;
    let recipient = Pubkey::from_str(&client.manifest.recipient)?;
    // A valid old Ed signature must be rejected after enrollment, even when
    // it would otherwise satisfy the application's signer requirements.
    let old = client.transaction(
        &[system_instruction::transfer(
            &client.address(sponsor)?,
            &recipient,
            1,
        )],
        &[],
        false,
    )?;
    ensure!(
        client.rpc.submit(&client.url, &old).is_err(),
        "retired classical authorization accepted after enrollment"
    );
    let mut rotated_keys = BTreeMap::new();
    let mut updated_app_authorities = BTreeMap::new();
    if spec.exercise_rich_state {
        for state in &states {
            if resume && state.primary_wallet == 0 {
                let fresh = client
                    .manifest
                    .wallets
                    .iter()
                    .filter(|wallet| wallet.legacy_private_key.is_none())
                    .map(|wallet| wallet.index)
                    .take(2)
                    .collect::<Vec<_>>();
                ensure!(
                    fresh == [33, 34],
                    "resume fresh application authorities changed"
                );
                let rotated = client.app_accounts(state, 33, 34)?;
                let escrow = Pubkey::from_str(&state.escrow)?;
                let escrow_lamports = client.account(&escrow)?["lamports"]
                    .as_u64()
                    .context("resumed escrow drain")?;
                client.confirm(
                    "resume_first_rotated_app_pda_drain",
                    &[rotated.withdraw(escrow_lamports, 8)],
                    &fresh,
                    true,
                    None,
                )?;
                ensure!(
                    client.account(&escrow)?.is_null(),
                    "resumed first escrow did not drain"
                );
                rotated_keys.insert(0, client.manifest.directory.join("rotated-wallet-0.key"));
                updated_app_authorities.insert(state.state.clone(), (33, 34));
                continue;
            }
            let accounts =
                client.app_accounts(state, state.primary_wallet, state.secondary_wallet)?;
            client.confirm(
                "postcut_sbf_deposit",
                &[accounts.deposit(7, 4)],
                &[state.primary_wallet],
                true,
                None,
            )?;
            client.confirm(
                "postcut_sbf_multisig_withdraw",
                &[accounts.withdraw(3, 5)],
                &[state.primary_wallet, state.secondary_wallet],
                true,
                None,
            )?;
            client.token_transfer(state.primary_wallet, 43, true, "postcut_spl_transfer")?;
            let state_address = Pubkey::from_str(&state.state)?;
            let escrow = Pubkey::from_str(&state.escrow)?;
            let before_state = client.account(&state_address)?;
            let before_escrow = client.account(&escrow)?;
            let before_recipient = client.account(&recipient)?;
            let before_sponsor = client
                .rpc
                .balance(&client.url, &client.manifest.wallets[sponsor].address)?;
            client.confirm(
                "postcut_sbf_cpi_rollback",
                &[accounts.failed_withdraw(1, 6)],
                &[state.primary_wallet, state.secondary_wallet],
                true,
                Some(app::EXPECTED_ROLLBACK),
            )?;
            ensure!(
                client.account(&state_address)? == before_state
                    && client.account(&escrow)? == before_escrow
                    && client.account(&recipient)? == before_recipient,
                "failed SBF CPI did not atomically restore state, escrow and destination"
            );
            let fee = client.receipts.last().unwrap()["receipt"]["meta"]["fee"]
                .as_u64()
                .context("charged rollback fee")?;
            ensure!(
                before_sponsor.checked_sub(fee)
                    == Some(
                        client
                            .rpc
                            .balance(&client.url, &client.manifest.wallets[sponsor].address)?
                    ),
                "failed CPI sponsor fee debit mismatch"
            );
            let replacement = FalconKeypair::generate();
            let path = client
                .manifest
                .directory
                .join(format!("rotated-wallet-{}.key", state.primary_wallet));
            replacement.save_private(&path)?;
            let (upload, nonce) =
                client.key_upload(&replacement, true, "sponsored_rotation_key_upload")?;
            let authority = client.address(state.primary_wallet)?;
            let fee_sponsor = client.address(sponsor)?;
            client.confirm(
                "program_owned_sponsored_falcon_rotation",
                &[pq::rotate_sponsored_instruction(
                    &authority,
                    &fee_sponsor,
                    &upload,
                    1,
                    &pq::sealed_upload_commitment(
                        &fee_sponsor,
                        &nonce,
                        replacement.public_key().as_bytes(),
                    ),
                )],
                &[state.primary_wallet],
                true,
                None,
            )?;
            let old_key_tx =
                client.transaction(&[accounts.deposit(1, 6)], &[state.primary_wallet], true)?;
            ensure!(
                client.rpc.submit(&client.url, &old_key_tx).is_err(),
                "retired Falcon key accepted at native ingress"
            );
            client.pq.insert(state.primary_wallet, replacement);
            rotated_keys.insert(state.primary_wallet, path);
            client.confirm(
                "new_falcon_key_sbf_spend",
                &[accounts.deposit(1, 6)],
                &[state.primary_wallet],
                true,
                None,
            )?;
            client.confirm(
                "close_rotation_upload",
                &[close_upload_instruction(&fee_sponsor, &upload)],
                &[],
                true,
                None,
            )?;
            ensure!(
                client.account(&upload)?.is_null(),
                "rotation upload refund failed"
            );
            let fresh: Vec<_> = client
                .manifest
                .wallets
                .iter()
                .filter(|wallet| wallet.legacy_private_key.is_none())
                .map(|wallet| wallet.index)
                .take(2)
                .collect();
            ensure!(
                fresh.len() == 2,
                "app authority rotation needs two fresh PQ authorities"
            );
            client.confirm(
                "application_multisig_authority_rotation",
                &[accounts.rotate(client.address(fresh[0])?, client.address(fresh[1])?, 7)],
                &[state.primary_wallet, state.secondary_wallet],
                true,
                None,
            )?;
            let rotated = client.app_accounts(state, fresh[0], fresh[1])?;
            updated_app_authorities.insert(state.state.clone(), (fresh[0], fresh[1]));
            let escrow_lamports = client.account(&escrow)?["lamports"]
                .as_u64()
                .context("escrow balance")?;
            client.confirm(
                "new_app_authorities_drain_pda_escrow",
                &[rotated.withdraw(escrow_lamports, 8)],
                &fresh,
                true,
                None,
            )?;
            ensure!(
                client.account(&escrow)?.is_null(),
                "PDA escrow rent/asset drain failed"
            );
        }
    }
    let ids: Vec<_> = client
        .receipts
        .iter()
        .map(|receipt| receipt["id"].as_str().unwrap().to_string())
        .collect();
    let successful_ids: Vec<_> =
        ids.iter()
            .filter(|id| {
                client.receipts.iter().any(|receipt| {
                    receipt["id"] == id.as_str() && receipt["expected_error"].is_null()
                })
            })
            .cloned()
            .collect();
    let nodes = audit_final_nodes(&MigrationFinalAudit {
        client: &client,
        legacy: &legacy,
        states: &states,
        successful_ids: &successful_ids,
        initial_app_accounts: &initial_app_accounts,
        initial_mint: initial_mint.as_ref(),
        initial_tokens: &initial_tokens,
        token_addresses: &token_addresses,
        trusted_genesis: &trusted_genesis,
        exercise_rich_state: spec.exercise_rich_state,
        resume,
    })?;
    let mut updated_manifest = client.manifest.clone();
    for (index, path) in &rotated_keys {
        updated_manifest.wallets[*index].private_key = path.clone();
    }
    for state in &mut updated_manifest.workload_states {
        if let Some((primary, secondary)) = updated_app_authorities.get(&state.state) {
            state.primary_wallet = *primary;
            state.secondary_wallet = *secondary;
            state.authority_is_state_address = false;
        }
    }
    let updated_manifest_path = spec.output.with_extension("migrated-manifest.json");
    write_json(&updated_manifest_path, &updated_manifest)?;
    let total_expected = legacy
        .len()
        .checked_mul(3)
        .and_then(|pre| {
            pre.checked_add(if spec.exercise_rich_state {
                states.len().checked_mul(14)?
            } else {
                0
            })
        })
        .context("migration transaction count overflow")?;
    if resume {
        ensure!(
            client.receipts.len() == 151,
            "constrained resume must commit exactly151 new transactions"
        );
    }
    let result = json!({"actual_bank_svm":true,"resumed_specific_postcut_interruption":resume,"initial_token_and_padding_baseline":if resume {"pinned_serialized_genesis"} else {"actual_precut_account_snapshots"},"resume_before":resume_before,"new_committed_transactions":client.receipts.len(),"previous_committed_transactions":if resume {172} else {0},"expected_total_migration_transactions":total_expected,"real_sbf_and_system_cpi":spec.exercise_rich_state,"real_spl_programs":client.manifest.token_mint.is_some(),"immutable_cutoff":client.manifest.cutoff_slot,"precut_slot":if resume {Value::Null} else {before_slot.clone()},"entry_slot":before_slot,"postcut_slot":postcut_slot,"legacy_authorities_enrolled":legacy.len(),"prior_accounts":prior_accounts,"all_nodes_match":true,"old_ed_authorization_rejected":true,"rotated_private_key_paths":rotated_keys,"migrated_manifest":updated_manifest_path,"receipts":client.receipts,"nodes":nodes,"completed_unix_ms":wall_ms()});
    write_json(&spec.output, &result)?;
    Ok(result)
}

/// Exercise other existing application references to the same original authority
/// after its own state and its Falcon credential have independently rotated.
pub(super) fn probe_shared_authority(spec: SharedAuthorityProbeSpec) -> Result<Value> {
    ensure!(
        !spec.output.exists(),
        "shared authority probe output must be fresh"
    );
    ensure!(
        (1..=16).contains(&spec.state_count),
        "bounded shared state probe"
    );
    let manifest: Manifest = read_json(&spec.manifest)?;
    let states = manifest
        .workload_states
        .iter()
        .filter(|state| {
            !state.authority_is_state_address
                && state.primary_wallet == 0
                && state.secondary_wallet == 1
        })
        .take(spec.state_count)
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        states.len() == spec.state_count,
        "missing original shared-authority states"
    );
    let rpc = Rpc::new()?;
    let url = spec
        .rpc_url
        .clone()
        .unwrap_or_else(|| manifest.nodes[0].rpc_url.clone());
    ensure!(
        rpc.call(&url, "getSlot", json!([{"commitment":"finalized"}]))?
            .as_u64()
            .context("probe cutoff slot")?
            >= manifest.cutoff_slot,
        "shared-authority probe requires actual postcut execution"
    );
    let mut keys = BTreeMap::new();
    for index in BTreeSet::from([0, 1, spec.sponsor_wallet]) {
        let wallet = manifest
            .wallets
            .get(index)
            .context("shared authority wallet")?;
        keys.insert(index, FalconKeypair::load_private(&wallet.private_key)?);
    }
    let mut client = Client {
        config: native_config(&manifest)?,
        rpc,
        url,
        sponsor: spec.sponsor_wallet,
        classical: BTreeMap::new(),
        pq: keys,
        manifest,
        receipts: Vec::new(),
        timeout: Duration::from_secs(spec.timeout_seconds),
    };
    let authority = client.address(0)?;
    let secondary = client.address(1)?;
    let sponsor = client.address(client.sponsor)?;
    let recipient = Pubkey::from_str(&client.manifest.recipient)?;
    let authority_before = client.account(&authority)?;
    ensure!(
        authority_before["owner"] == app::PROGRAM_ID.to_string(),
        "original authority must still be program owned"
    );
    let own_state = app::State::decode(
        &BASE64_STANDARD.decode(
            authority_before["data"][0]
                .as_str()
                .context("original authority application data")?,
        )?,
    )
    .context("original authority application layout")?;
    ensure!(
        own_state.rotations > 0 && own_state.primary != authority,
        "original authority's own application authority must already have rotated"
    );
    let policy = client.account(&policy_address(&authority))?;
    let record = AuthRecord::decode(
        &BASE64_STANDARD.decode(
            policy["data"][0]
                .as_str()
                .context("rotated shared authority policy")?,
        )?,
    )?;
    ensure!(
        record.authority == authority.to_bytes()
            && record.generation >= 2
            && record.public_key == client.pq[&0].public_key()
            && record.origin == Origin::LegacySignature,
        "probe must use finalized rotated original Falcon credential"
    );
    let addresses = states
        .iter()
        .map(|state| state.state.clone())
        .collect::<Vec<_>>();
    let initial = account_snapshots(&client.rpc, &client.url, &addresses)?;
    let sponsor_before = client.rpc.balance(&client.url, &sponsor.to_string())?;
    let recipient_before = client.rpc.balance(&client.url, &recipient.to_string())?;
    let escrow_rent = solana_rent::Rent::default().minimum_balance(0);
    let amount = 7u64;
    let operation = (|| -> Result<()> {
        for state in &states {
            let state_address = Pubkey::from_str(&state.state)?;
            let escrow = Pubkey::from_str(&state.escrow)?;
            let bytes = BASE64_STANDARD.decode(
                initial[&state.state]["data"][0]
                    .as_str()
                    .context("original background state data")?,
            )?;
            let original =
                app::State::decode(&bytes).context("original background state layout")?;
            ensure!(
                original.primary == authority
                    && original.secondary == secondary
                    && !original.initialized
                    && original.last_sequence == 0,
                "shared state must retain original pre-migration authorities and pristine sequence"
            );
            ensure!(
                client.account(&escrow)?.is_null(),
                "shared escrow must be initially absent"
            );
            let accounts = client.app_accounts(state, 0, 1)?;
            client.confirm(
                "shared_authority_initialize_pda",
                &[accounts.initialize(escrow_rent, 1)],
                &[0],
                true,
                None,
            )?;
            client.confirm(
                "shared_authority_deposit",
                &[accounts.deposit(amount, 2)],
                &[0],
                true,
                None,
            )?;
            client.confirm(
                "shared_authority_multisig_withdraw",
                &[accounts.withdraw(3, 3)],
                &[0, 1],
                true,
                None,
            )?;
            let before_state = client.account(&state_address)?;
            let before_escrow = client.account(&escrow)?;
            let before_recipient = client.account(&recipient)?;
            let before_sponsor = client.rpc.balance(&client.url, &sponsor.to_string())?;
            client.confirm(
                "shared_authority_cpi_rollback",
                &[accounts.failed_withdraw(1, 4)],
                &[0, 1],
                true,
                Some(app::EXPECTED_ROLLBACK),
            )?;
            let fee = client.receipts.last().unwrap()["receipt"]["meta"]["fee"]
                .as_u64()
                .context("shared rollback receipt fee")?;
            ensure!(
                client.account(&state_address)? == before_state
                    && client.account(&escrow)? == before_escrow
                    && client.account(&recipient)? == before_recipient
                    && before_sponsor.checked_sub(fee)
                        == Some(client.rpc.balance(&client.url, &sponsor.to_string())?),
                "shared-authority failed CPI did not restore exact assets/state and charge only \
                 the actual fee"
            );
            let balance = client.account(&escrow)?["lamports"]
                .as_u64()
                .context("shared escrow drain balance")?;
            client.confirm(
                "shared_authority_complete_pda_drain",
                &[accounts.withdraw(balance, 4)],
                &[0, 1],
                true,
                None,
            )?;
            ensure!(
                client.account(&escrow)?.is_null(),
                "shared escrow asset/rent drain failed"
            );
        }
        Ok(())
    })();
    if let Err(error) = operation {
        write_json(
            &spec.output.with_extension("failure.json"),
            &json!({"failure":error.to_string(),"affected_states":addresses,"receipts":client.receipts}),
        )?;
        return Err(error);
    }
    let transferred = escrow_rent
        .checked_add(amount)
        .and_then(|value| value.checked_mul(u64::try_from(states.len()).ok()?))
        .context("shared transfer total overflow")?;
    let fees = client.receipts.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(
            row["receipt"]["meta"]["fee"]
                .as_u64()
                .context("shared receipt fee")?,
        )
        .context("shared fee sum overflow")
    })?;
    let expected_sponsor = sponsor_before
        .checked_sub(transferred)
        .and_then(|balance| balance.checked_sub(fees))
        .context("shared sponsor accounting overflow")?;
    let expected_recipient = recipient_before
        .checked_add(transferred)
        .context("shared recipient accounting overflow")?;
    let successful_ids = client
        .receipts
        .iter()
        .filter(|row| row["expected_error"].is_null())
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let mut nodes = Vec::new();
    for (node_index, node) in client.manifest.nodes.iter().enumerate() {
        client
            .rpc
            .wait(&node.rpc_url, &successful_ids, client.timeout)?;
        let values = account_snapshots(&client.rpc, &node.rpc_url, &addresses)?;
        let actor = client.rpc.call(
            &node.rpc_url,
            "getAccountInfo",
            json!([authority.to_string(),{"encoding":"base64","commitment":"finalized"}]),
        )?["value"]
            .clone();
        ensure!(
            actor == authority_before,
            "original authority's independently rotated application state changed during shared \
             use"
        );
        let mut expected_accounts = Vec::new();
        for state in &states {
            let value = &values[&state.state];
            let before = &initial[&state.state];
            let bytes = BASE64_STANDARD.decode(
                value["data"][0]
                    .as_str()
                    .context("shared final state bytes")?,
            )?;
            let original = BASE64_STANDARD.decode(
                before["data"][0]
                    .as_str()
                    .context("shared initial state bytes")?,
            )?;
            let decoded = app::State::decode(&bytes).context("shared final state layout")?;
            ensure!(
                value["owner"] == before["owner"]
                    && value["owner"] == app::PROGRAM_ID.to_string()
                    && value["lamports"] == before["lamports"]
                    && value["executable"] == before["executable"]
                    && bytes.len() == original.len()
                    && bytes[app::STATE_BYTES..] == original[app::STATE_BYTES..],
                "shared-authority owner/rent/executable/padding changed"
            );
            ensure!(
                decoded.primary == authority
                    && decoded.secondary == secondary
                    && decoded.initialized
                    && decoded.last_sequence == 4
                    && decoded.operations == 4
                    && decoded.deposited == amount
                    && Some(decoded.withdrawn) == escrow_rent.checked_add(amount)
                    && decoded.rotations == 0,
                "shared original authority references or final application counters changed"
            );
            let escrow = client.rpc.call(
                &node.rpc_url,
                "getAccountInfo",
                json!([state.escrow,{"encoding":"base64","commitment":"finalized"}]),
            )?["value"]
                .clone();
            ensure!(escrow.is_null(), "all-node shared escrow not fully drained");
            expected_accounts.push(json!({"state":state.state,"owner":value["owner"],"lamports":value["lamports"],"executable":value["executable"],"data_bytes":bytes.len(),"expected_data_base64":value["data"][0],"data_commitment_sha384":hex(&agave_pq_crypto::crypto::hash_commitment(b"pq-shared-authority-probe/v1",&[&bytes])),"primary":decoded.primary,"secondary":decoded.secondary,"last_sequence":decoded.last_sequence,"operations":decoded.operations,"deposited":decoded.deposited,"withdrawn":decoded.withdrawn,"rotations":decoded.rotations,"escrow":state.escrow,"escrow_absent":true}));
        }
        ensure!(
            client.rpc.balance(&node.rpc_url, &sponsor.to_string())? == expected_sponsor
                && client.rpc.balance(&node.rpc_url, &recipient.to_string())? == expected_recipient,
            "all-node shared sponsor fee/deposit or recipient asset accounting mismatch"
        );
        nodes.push(json!({"node_index":node_index,"expected_accounts":expected_accounts,"sponsor_balance":expected_sponsor,"recipient_balance":expected_recipient,"original_authority_application_unchanged":true}));
    }
    ensure!(
        nodes
            .iter()
            .all(|node| node["expected_accounts"] == nodes[0]["expected_accounts"]),
        "all-node shared application states differ"
    );
    let result = json!({"actual_bank_svm":true,"postcut_rotated_original_falcon_authority":authority,"original_authority_generation":record.generation,"own_application_primary":own_state.primary,"own_application_secondary":own_state.secondary,"own_application_rotations":own_state.rotations,"secondary":secondary,"sponsor":sponsor,"state_count":states.len(),"affected_states":addresses,"other_original_authority_application_unchanged":true,"owner_rent_padding_preserved":true,"exact_fee_charged_rollback":true,"no_token_or_mint_modifications":true,"expected_recipient_delta":transferred,"actual_fees":fees,"all_nodes_match":true,"receipts":client.receipts,"nodes":nodes,"completed_unix_ms":wall_ms()});
    write_json(&spec.output, &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{
            io::Read,
            net::TcpListener,
            sync::{Condvar, atomic::AtomicIsize},
        },
    };

    #[derive(Clone, Copy)]
    enum Fault {
        Policy,
        AppOwner,
        Padding,
        Mint,
        Token,
        Receipt,
        Recipient,
        ResumeCount,
    }

    struct AuditFixture {
        client: Client,
        genesis: GenesisConfig,
        states: Vec<WorkloadStateManifest>,
        legacy: Vec<usize>,
        successful_ids: Vec<String>,
        app_accounts: BTreeMap<String, Value>,
        mint: Option<Value>,
        tokens: BTreeMap<String, Value>,
        token_addresses: Vec<String>,
        current: BTreeMap<String, Value>,
        recipient_balance: u64,
    }

    impl AuditFixture {
        fn new() -> Self {
            let wallets = (0..2)
                .map(|index| WalletManifest {
                    index,
                    address: Pubkey::new_unique().to_string(),
                    private_key: PathBuf::from(format!("untouched-wallet-{index}.key")),
                    nonce: "00".repeat(32),
                    legacy_private_key: Some(PathBuf::from("untouched-legacy.key")),
                })
                .collect::<Vec<_>>();
            let recipient = WalletManifest {
                index: 0,
                address: Pubkey::new_unique().to_string(),
                private_key: PathBuf::from("untouched-recipient.key"),
                nonce: "00".repeat(32),
                legacy_private_key: None,
            };
            let primary = Pubkey::from_str(&wallets[0].address).unwrap();
            let secondary = Pubkey::from_str(&wallets[1].address).unwrap();
            let mut genesis = GenesisConfig::default();
            let mut original = app::State::new(primary, secondary).encode(160);
            original[app::STATE_BYTES..].fill(0x5a);
            genesis.accounts.insert(
                primary,
                Account {
                    lamports: 5_000_000,
                    data: original,
                    owner: app::PROGRAM_ID,
                    executable: false,
                    rent_epoch: u64::MAX,
                },
            );
            genesis.accounts.insert(
                Pubkey::from_str(&recipient.address).unwrap(),
                Account {
                    lamports: 1_000_000_000,
                    data: Vec::new(),
                    owner: system_program::id(),
                    executable: false,
                    rent_epoch: u64::MAX,
                },
            );
            let (mint_address, wallet_tokens, recipient_tokens) =
                install_spl_state(&mut genesis, &wallets, std::slice::from_ref(&recipient))
                    .unwrap();
            let token_addresses = wallet_tokens
                .iter()
                .chain(&recipient_tokens)
                .cloned()
                .collect::<Vec<_>>();
            let tokens = token_addresses
                .iter()
                .map(|address| {
                    (
                        address.clone(),
                        genesis_snapshot(&genesis, address).unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mint = Some(genesis_snapshot(&genesis, mint_address.as_ref().unwrap()).unwrap());
            let app_accounts = BTreeMap::from([(
                primary.to_string(),
                genesis_snapshot(&genesis, &primary.to_string()).unwrap(),
            )]);
            let mut current = tokens.clone();
            current.insert(mint_address.clone().unwrap(), mint.clone().unwrap());
            let mut state = app::State::new(primary, secondary);
            state.last_sequence = 8;
            state.rotations = 1;
            state.initialized = true;
            let mut bytes = state.encode(160);
            bytes[app::STATE_BYTES..].fill(0x5a);
            let mut account = app_accounts[&primary.to_string()].clone();
            account["data"][0] = json!(BASE64_STANDARD.encode(bytes));
            current.insert(primary.to_string(), account);
            for (address, delta) in [
                (wallet_tokens[0].clone(), -85i64),
                (recipient_tokens[0].clone(), 85),
            ] {
                let value = current.get_mut(&address).unwrap();
                let mut bytes = BASE64_STANDARD
                    .decode(value["data"][0].as_str().unwrap())
                    .unwrap();
                let amount = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
                bytes[64..72]
                    .copy_from_slice(&amount.checked_add_signed(delta).unwrap().to_le_bytes());
                value["data"][0] = json!(BASE64_STANDARD.encode(bytes));
            }
            let keys = (0..2)
                .map(|index| (index, FalconKeypair::generate()))
                .collect::<BTreeMap<_, _>>();
            for (index, key) in &keys {
                let authority = Pubkey::from_str(&wallets[*index].address).unwrap();
                let record = AuthRecord::new(
                    authority.to_bytes(),
                    key.public_key(),
                    Origin::LegacySignature,
                );
                current.insert(policy_address(&authority).to_string(), json!({"data":[BASE64_STANDARD.encode(record.encode()),"base64"],"owner":pq::PROGRAM_ID,"lamports":10_000_000,"executable":false,"rentEpoch":u64::MAX}));
            }
            let successful_ids = vec![
                Keypair::new()
                    .sign_message(b"readonly-existing-receipt-id")
                    .to_string(),
            ];
            let manifest = Manifest {
                format: "agave-native-pq-v1".into(),
                directory: PathBuf::from("unchanged-fixture"),
                genesis_hash: genesis.hash().to_string(),
                chain: "00".repeat(32),
                migration_context: "11".repeat(32),
                cutoff_slot: 768,
                recipient: recipient.address.clone(),
                recipients: vec![recipient.address.clone()],
                recipient_wallets: vec![recipient],
                nodes: Vec::new(),
                wallets,
                token_mint: mint_address,
                wallet_token_accounts: wallet_tokens,
                recipient_token_accounts: recipient_tokens,
                workload_program: Some(app::PROGRAM_ID.to_string()),
                workload_states: Vec::new(),
                seed_escrow: None,
                seed_token_account: None,
                seed_secondary_wallet: None,
                public_seed_fixture: None,
                legacy_authority: None,
            };
            let client = Client {
                manifest,
                config: RuntimeConfig {
                    chain_id: [0; 32],
                    migration_context: [0x11; 32],
                    cutoff_slot: 768,
                },
                rpc: Rpc::new().unwrap(),
                url: String::new(),
                sponsor: 1,
                classical: BTreeMap::new(),
                pq: keys,
                receipts: vec![
                    json!({"id":successful_ids[0],"expected_error":null}),
                    json!({"id":Keypair::new().sign_message(b"readonly-existing-receipt-id").to_string(),"expected_error":7005,"receipt":{"meta":{"fee":15000,"err":{"InstructionError":[1,{"Custom":7005}]}}}}),
                ],
                timeout: Duration::from_secs(2),
            };
            let recipient_balance = 1_000_000_000u64
                .checked_add(genesis.rent.minimum_balance(0))
                .and_then(|value| value.checked_add(15))
                .unwrap();
            Self {
                client,
                genesis,
                states: vec![WorkloadStateManifest {
                    state: primary.to_string(),
                    primary_wallet: 0,
                    secondary_wallet: 1,
                    escrow: Pubkey::new_unique().to_string(),
                    data_bytes: 160,
                    authority_is_state_address: true,
                }],
                legacy: vec![0, 1],
                successful_ids,
                app_accounts,
                mint,
                tokens,
                token_addresses,
                current,
                recipient_balance,
            }
        }

        fn audit(&self, resume: bool) -> MigrationFinalAudit<'_> {
            MigrationFinalAudit {
                client: &self.client,
                legacy: &self.legacy,
                states: &self.states,
                successful_ids: &self.successful_ids,
                initial_app_accounts: &self.app_accounts,
                initial_mint: self.mint.as_ref(),
                initial_tokens: &self.tokens,
                token_addresses: &self.token_addresses,
                trusted_genesis: &self.genesis,
                exercise_rich_state: true,
                resume,
            }
        }
    }

    struct ReadOnlyCluster {
        stop: Arc<AtomicBool>,
        servers: Vec<thread::JoinHandle<()>>,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        fault_node: Arc<AtomicIsize>,
        fault: Arc<Mutex<Fault>>,
        completed: Arc<Mutex<Vec<usize>>>,
        methods: Arc<Mutex<Vec<String>>>,
        simultaneous: Arc<AtomicBool>,
    }

    impl ReadOnlyCluster {
        fn new(fixture: &mut AuditFixture, count: usize, slow: bool) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let active = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let fault_node = Arc::new(AtomicIsize::new(-1));
            let fault = Arc::new(Mutex::new(Fault::Policy));
            let completed = Arc::new(Mutex::new(Vec::new()));
            let methods = Arc::new(Mutex::new(Vec::new()));
            let simultaneous = Arc::new(AtomicBool::new(false));
            let gate = Arc::new((Mutex::new(BTreeSet::<usize>::new()), Condvar::new()));
            let current = Arc::new(fixture.current.clone());
            let recipient_balance = fixture.recipient_balance;
            let state_address = fixture.states[0].state.clone();
            let policy = policy_address(&fixture.client.address(0).unwrap()).to_string();
            let mint = fixture.client.manifest.token_mint.clone().unwrap();
            let token = fixture.client.manifest.wallet_token_accounts[0].clone();
            let mut servers = Vec::new();
            for index in 0..count {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let address = listener.local_addr().unwrap();
                fixture.client.manifest.nodes.push(NodeManifest {
                    index,
                    host: address.ip(),
                    config: PathBuf::from("untouched-config"),
                    identity: PathBuf::from("untouched-identity"),
                    id: Pubkey::new_unique().to_string(),
                    ledger: PathBuf::from("untouched-ledger"),
                    keys: PathBuf::from("untouched-Ax-keys"),
                    rpc_port: address.port(),
                    rpc_url: format!("http://{address}"),
                    pq_address: address,
                    vote_account: Pubkey::new_unique().to_string(),
                    stake_account: Pubkey::new_unique().to_string(),
                });
                let (
                    stop,
                    active,
                    peak,
                    fault_node,
                    fault,
                    completed,
                    methods,
                    simultaneous,
                    gate,
                    current,
                    policy,
                    mint,
                    token,
                    state_address,
                ) = (
                    Arc::clone(&stop),
                    Arc::clone(&active),
                    Arc::clone(&peak),
                    Arc::clone(&fault_node),
                    Arc::clone(&fault),
                    Arc::clone(&completed),
                    Arc::clone(&methods),
                    Arc::clone(&simultaneous),
                    Arc::clone(&gate),
                    Arc::clone(&current),
                    policy.clone(),
                    mint.clone(),
                    token.clone(),
                    state_address.clone(),
                );
                servers.push(thread::spawn(move || {
                    let mut first=true;
                    while !stop.load(Ordering::Acquire) {
                        let mut stream=match listener.accept() { Ok((stream,_))=>stream,Err(error)if error.kind()==std::io::ErrorKind::WouldBlock=>{thread::sleep(Duration::from_millis(1));continue},Err(error)=>panic!("readonly mock accept: {error}") };
                        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                        let mut headers=Vec::new();while !headers.ends_with(b"\r\n\r\n") { let mut byte=[0];stream.read_exact(&mut byte).unwrap();headers.push(byte[0]);assert!(headers.len()<32768); }
                        let length=String::from_utf8(headers).unwrap().lines().find_map(|line|{let(name,value)=line.split_once(':')?;name.eq_ignore_ascii_case("content-length").then(||value.trim().parse::<usize>().unwrap())}).unwrap();assert!(length<65536);
                        let mut body=vec![0;length];stream.read_exact(&mut body).unwrap();let request:Value=serde_json::from_slice(&body).unwrap();
                        let busy=active.fetch_add(1,Ordering::AcqRel).checked_add(1).unwrap();peak.fetch_max(busy,Ordering::AcqRel);
                        if slow && first {
                            first=false;let deadline=Instant::now().checked_add(Duration::from_secs(2)).unwrap();let(entered,condition)=(&gate.0,&gate.1);let mut entries=entered.lock().unwrap();entries.insert(index);condition.notify_all();
                            while entries.len()<count.min(FINAL_AUDIT_WORKERS) && Instant::now()<deadline { let wait=deadline.saturating_duration_since(Instant::now());entries=condition.wait_timeout(entries,wait).unwrap().0; }
                            simultaneous.store(entries.len()>=count.min(FINAL_AUDIT_WORKERS),Ordering::Release);drop(entries);
                            thread::sleep(Duration::from_millis(u64::try_from(count.checked_sub(index).unwrap()).unwrap().checked_mul(15).unwrap()));
                        }
                        let fail=fault_node.load(Ordering::Acquire)==index as isize;let failure=*fault.lock().unwrap();
                        let response=|call:&Value| {
                            let method=call["method"].as_str().unwrap();methods.lock().unwrap().push(method.into());
                            let result=match method {
                                "getSignatureStatuses"=>json!({"value":call["params"][0].as_array().unwrap().iter().map(|_|json!({"slot":1000,"confirmationStatus":"finalized","err":if fail&&matches!(failure,Fault::Receipt){json!("bad receipt")}else{Value::Null}})).collect::<Vec<_>>()}),
                                "getAccountInfo"=>{
                                    let key=call["params"][0].as_str().unwrap();let mut value=current[key].clone();
                                    if fail { if key==policy&&matches!(failure,Fault::Policy) {let mut bytes=BASE64_STANDARD.decode(value["data"][0].as_str().unwrap()).unwrap();bytes[993]=Origin::FreshIdentity as u8;value["data"][0]=json!(BASE64_STANDARD.encode(bytes));}
                                        if key==state_address&&matches!(failure,Fault::AppOwner){value["owner"]=json!(system_program::id());}
                                        if key==state_address&&matches!(failure,Fault::Padding){let mut bytes=BASE64_STANDARD.decode(value["data"][0].as_str().unwrap()).unwrap();bytes[app::STATE_BYTES+1]^=1;value["data"][0]=json!(BASE64_STANDARD.encode(bytes));}
                                        if key==mint&&matches!(failure,Fault::Mint){value["lamports"]=json!(1);}
                                    } json!({"value":value})
                                },
                                "getMultipleAccounts"=>json!({"value":call["params"][0].as_array().unwrap().iter().map(|key|{let key=key.as_str().unwrap();let mut value=current[key].clone();if fail&&key==token&&matches!(failure,Fault::Token){let mut bytes=BASE64_STANDARD.decode(value["data"][0].as_str().unwrap()).unwrap();bytes[64]^=1;value["data"][0]=json!(BASE64_STANDARD.encode(bytes));}value}).collect::<Vec<_>>()}),
                                "getBalance"=>json!({"value":recipient_balance.checked_add(u64::from(fail&&matches!(failure,Fault::Recipient))).unwrap()}),
                                "getExperimentalPqStatus"=>{completed.lock().unwrap().push(index);json!({"finalized_transactions":if fail&&matches!(failure,Fault::ResumeCount){322}else{323},"fixture_node_index":index})},
                                other=>panic!("readonly audit invoked unexpected method {other}"),
                            };json!({"jsonrpc":"2.0","id":call["id"],"result":result})
                        };
                        let value=if let Some(batch)=request.as_array(){json!(batch.iter().map(response).collect::<Vec<_>>())}else{response(&request)};
                        let bytes=serde_json::to_vec(&value).unwrap();active.fetch_sub(1,Ordering::AcqRel);write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();stream.write_all(&bytes).unwrap();
                    }
                }));
            }
            Self {
                stop,
                servers,
                active,
                peak,
                fault_node,
                fault,
                completed,
                methods,
                simultaneous,
            }
        }
    }

    impl Drop for ReadOnlyCluster {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            for server in self.servers.drain(..) {
                server.join().unwrap();
            }
        }
    }

    #[test]
    fn slow_all_eight_final_custody_audits_overlap_and_keep_manifest_order() {
        let mut fixture = AuditFixture::new();
        let cluster = ReadOnlyCluster::new(&mut fixture, 8, true);
        let manifest = serde_json::to_vec(&fixture.client.manifest).unwrap();
        let receipts = fixture.client.receipts.clone();
        let rows = audit_final_nodes(&fixture.audit(false)).unwrap();
        assert!(cluster.simultaneous.load(Ordering::Acquire));
        assert_eq!(cluster.peak.load(Ordering::Acquire), 8);
        assert_eq!(
            rows.iter()
                .map(|row| row["status"]["fixture_node_index"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert_ne!(cluster.completed.lock().unwrap()[0], 0);
        assert_eq!(cluster.active.load(Ordering::Acquire), 0);
        assert_eq!(
            serde_json::to_vec(&fixture.client.manifest).unwrap(),
            manifest
        );
        assert_eq!(fixture.client.receipts, receipts);
        assert!(
            cluster
                .methods
                .lock()
                .unwrap()
                .iter()
                .all(|method| matches!(
                    method.as_str(),
                    "getSignatureStatuses"
                        | "getAccountInfo"
                        | "getMultipleAccounts"
                        | "getBalance"
                        | "getExperimentalPqStatus"
                ))
        );
    }

    #[test]
    fn final_audit_worker_cap_is_independent_of_node_count() {
        let mut fixture = AuditFixture::new();
        let cluster = ReadOnlyCluster::new(&mut fixture, 10, true);
        assert_eq!(audit_final_nodes(&fixture.audit(false)).unwrap().len(), 10);
        assert!(cluster.simultaneous.load(Ordering::Acquire));
        assert!(cluster.peak.load(Ordering::Acquire) <= FINAL_AUDIT_WORKERS);
    }

    #[test]
    fn every_validator_failure_prevents_a_completed_final_audit() {
        let mut fixture = AuditFixture::new();
        let cluster = ReadOnlyCluster::new(&mut fixture, 8, false);
        for node in 0..8 {
            cluster.fault_node.store(node, Ordering::Release);
            assert!(
                audit_final_nodes(&fixture.audit(false)).is_err(),
                "failed node {node} was omitted"
            );
        }
    }

    #[test]
    fn parallel_audits_preserve_owner_padding_policy_mint_token_receipt_and_resume_checks() {
        let mut fixture = AuditFixture::new();
        let cluster = ReadOnlyCluster::new(&mut fixture, 8, false);
        assert_eq!(audit_final_nodes(&fixture.audit(true)).unwrap().len(), 8);
        cluster.fault_node.store(7, Ordering::Release);
        for fault in [
            Fault::Policy,
            Fault::AppOwner,
            Fault::Padding,
            Fault::Mint,
            Fault::Token,
            Fault::Receipt,
            Fault::Recipient,
            Fault::ResumeCount,
        ] {
            *cluster.fault.lock().unwrap() = fault;
            assert!(
                audit_final_nodes(&fixture.audit(true)).is_err(),
                "mutated final custody condition accepted"
            );
        }
    }
}
