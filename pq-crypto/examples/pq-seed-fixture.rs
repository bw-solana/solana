//! Generate a fresh synthetic complete private-seed proof for native Agave tests.
//! This is an offchain prover, not a runtime or a substitute for VerifySeed.
//! The original seed is a public synthetic test vector; no wallet seed is used.

use {
    agave_pq_crypto::{
        auth::key_commitment,
        crypto::FalconKeypair,
        migration::{COMPLETE_SEED_PROFILE, MigrationIntent, prove_seed_claim},
        seed_proof::{profile_commitment, verify_seed_proof},
    },
    ed25519_dalek::SigningKey,
    serde_json::json,
    sha2::{Digest, Sha384},
    std::{
        error::Error,
        fs::{DirBuilder, File, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let directory = PathBuf::from(
        args.next()
            .ok_or("one fresh private directory is required")?,
    );
    if args.next().is_some() || !directory.is_absolute() {
        return Err("usage: pq-seed-fixture /absolute/fresh/private/directory".into());
    }
    let parent = directory
        .parent()
        .ok_or("output directory needs a parent")?;
    let canonical_parent = parent.canonicalize()?;
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate repository parent")?
        .canonicalize()?;
    if canonical_parent.starts_with(repository) {
        return Err("private output must be outside the repository".into());
    }
    let directory = canonical_parent.join(directory.file_name().ok_or("directory name")?);
    DirBuilder::new().mode(0o700).create(&directory)?;
    let started_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let seed = [11; 32];
    let authority = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let replacement = FalconKeypair::generate();
    replacement.save_private(directory.join("replacement.key"))?;
    let intent = MigrationIntent {
        chain_id: rand::random(),
        context: rand::random(),
        authority,
        replacement_key: replacement.public_key(),
        expected_generation: 0,
        claim_nonce: rand::random(),
    };
    let started = Instant::now();
    let (statement, proof) = prove_seed_claim(&seed, intent)?;
    let prove_seconds = started.elapsed().as_secs_f64();
    let verified = Instant::now();
    verify_seed_proof(&statement, &proof[16..])?;
    let local_verify_seconds = verified.elapsed().as_secs_f64();
    let fixture = serde_json::to_vec(&json!({
        "chain": statement.intent.chain_id,
        "context": statement.intent.context,
        "authority": statement.intent.authority,
        "replacement_key": statement.intent.replacement_key.as_bytes(),
        "nonce": statement.intent.claim_nonce,
        "secret_commitment": statement.secret_intent_commitment.to_vec(),
        "proof": proof,
    }))?;
    write_private(&directory.join("public-fixture.json"), &fixture)?;
    let summary = json!({
        "format": "agave-pq-fresh-synthetic-seed-fixture-v1",
        "offchain_proving_only": true,
        "native_onchain_verification_still_required": true,
        "public_synthetic_original_authority": true,
        "fresh_replacement_key_and_domains": true,
        "started_unix_ms": started_ms,
        "completed_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        "authority": hex(&authority),
        "chain": hex(&statement.intent.chain_id),
        "context": hex(&statement.intent.context),
        "replacement_public_key_commitment": hex(&key_commitment(&replacement.public_key())),
        "complete_seed_profile": COMPLETE_SEED_PROFILE,
        "profile_commitment": hex(&profile_commitment()),
        "proof_bytes": proof.len(),
        "proof_sha384": hex(&Sha384::digest(&proof)),
        "public_fixture_sha384": hex(&Sha384::digest(&fixture)),
        "prove_seconds": prove_seconds,
        "local_verify_seconds": local_verify_seconds,
        "local_complete_relation_verified": true,
    });
    write_private(
        &directory.join("summary.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    File::open(&directory)?.sync_all()?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}
