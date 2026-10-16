//! Complete original RFC8032 seed-ownership relation, with a fixed hiding
//! Plonky3 batch-STARK profile. This research circuit has not been audited.
mod circuit;
mod edwards;
mod encoding;
mod sha512;
mod sha512_constants;
mod stark;

use {
    crate::{
        Commitment,
        migration::{MAX_SEED_PROOF_BYTES, MigrationIntent, SeedClaimStatement, SeedProofError},
    },
    circuit::Circuit,
    ed25519_dalek::SigningKey,
    num_bigint::BigUint,
    p3_field::PrimeCharacteristicRing,
    p3_goldilocks::Goldilocks,
    sha2::{Digest, Sha384, Sha512},
    std::{
        collections::VecDeque,
        sync::{Arc, Mutex, OnceLock},
    },
};

const SECRET_INTENT_DOMAIN: &[u8] = b"agave/pq/seed-migration/secret-intent/v1";
const SECRET_INTENT_DOMAIN_V2: &[u8] = b"agave/pq/seed-migration/secret-intent/v2";
const INTENT_BYTES: usize =
    b"agave/pq/seed-migration/intent/v1".len() + 4 + 3 * 32 + 4 + 897 + 8 + 1 + 32;
const PREFIX_BYTES: usize = SECRET_INTENT_DOMAIN_V2.len() + INTENT_BYTES;
const TAIL_BYTES: usize = PREFIX_BYTES % 128;
const UNIVERSAL_GATE_COUNT: usize = 3_283_789;
const UNIVERSAL_DEGREE_BITS: [usize; 3] = [23, 18, 9];
const HEADER_BYTES: usize = 104;
const VERIFIER_CACHE_ENTRIES: usize = 8;

/// Locally derived verifier metadata. Profile 1 binds an exact statement;
/// profile 2 binds universal routing and takes each statement as public inputs.
/// Neither can be constructed from an uploaded preprocessing root.
pub struct PreparedSeedVerifier {
    statement_hash: Commitment,
    gate_count: usize,
    profile: u32,
    verifier: stark::PreparedVerifier,
}

/// Legacy profile 1's statement-specific deterministic preparation. Only compact
/// metadata remains; witness vectors, matrices and prover trees are freed.
pub fn prepare_legacy_seed_verifier(
    statement: &SeedClaimStatement,
) -> Result<Arc<PreparedSeedVerifier>, SeedProofError> {
    validate_statement(statement)?;
    let circuit = build_circuit(&[0; 32], statement);
    Ok(Arc::new(PreparedSeedVerifier {
        statement_hash: statement_hash(statement),
        gate_count: circuit.gates.len(),
        profile: 1,
        verifier: stark::prepare_verifier(&circuit),
    }))
}

/// Prepare profile 2 once before advertising a validator as ready. All claims
/// share this locally computed relation commitment; no claimant supplies it.
/// Cold setup is separate from the cost of verifying each fresh statement.
pub fn prewarm_seed_verifier() -> Result<(), SeedProofError> {
    universal_verifier().map(|_| ())
}

fn universal_verifier() -> Result<Arc<PreparedSeedVerifier>, SeedProofError> {
    static UNIVERSAL: OnceLock<Arc<PreparedSeedVerifier>> = OnceLock::new();
    static PREPARING: Mutex<()> = Mutex::new(());
    if let Some(verifier) = UNIVERSAL.get() {
        return Ok(Arc::clone(verifier));
    }
    let _preparing = PREPARING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(verifier) = UNIVERSAL.get() {
        return Ok(Arc::clone(verifier));
    }
    // This all-zero template is only public routing. It is deliberately not an
    // accepting seed witness, and no witness data survives preprocessing.
    let circuit = build_universal_relation(&[0; 32], &[0; 32], [0; 8], &[0; TAIL_BYTES], &[0; 64]);
    if circuit.gates.len() != UNIVERSAL_GATE_COUNT {
        return Err(SeedProofError::UnsupportedProfile);
    }
    let verifier = Arc::new(PreparedSeedVerifier {
        statement_hash: [0; 48],
        gate_count: circuit.gates.len(),
        profile: 2,
        verifier: stark::prepare_universal_verifier(&circuit),
    });
    let _ = UNIVERSAL.set(Arc::clone(&verifier));
    Ok(verifier)
}

type VerifierCache = VecDeque<Arc<PreparedSeedVerifier>>;

fn cached_verifier(
    statement: &SeedClaimStatement,
) -> Result<Arc<PreparedSeedVerifier>, SeedProofError> {
    static CACHE: OnceLock<Mutex<VerifierCache>> = OnceLock::new();
    // Serialize expensive cold preprocessing: concurrent claims must not each
    // allocate a ~32 GiB preprocessing tree. Cache hits do not take this lock.
    static COLD_SETUP: Mutex<()> = Mutex::new(());
    let cache = CACHE.get_or_init(Mutex::default);
    let hash = statement_hash(statement);
    let lookup = || {
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|entry| entry.statement_hash == hash)
            .cloned()
    };
    if let Some(entry) = lookup() {
        return Ok(entry);
    }
    let _cold = COLD_SETUP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = lookup() {
        return Ok(entry);
    }
    let entry = prepare_legacy_seed_verifier(statement)?;
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() == VERIFIER_CACHE_ENTRIES {
        cache.pop_front();
    }
    cache.push_back(Arc::clone(&entry));
    Ok(entry)
}

impl PreparedSeedVerifier {
    /// This still checks the canonical proof and verifies every cryptographic
    /// opening. Caching public metadata does not cache an acceptance result.
    pub fn verify(
        &self,
        statement: &SeedClaimStatement,
        body: &[u8],
    ) -> Result<(), SeedProofError> {
        let proof = decode_proof(statement, body)?;
        if proof_profile(body)? != self.profile
            || (self.profile == 1 && self.statement_hash != statement_hash(statement))
            || body[96..104] != (self.gate_count as u64).to_le_bytes()
        {
            return Err(SeedProofError::InvalidProof);
        }
        verify_decoded(self, statement, &proof)
    }
}

fn verify_decoded(
    verifier: &PreparedSeedVerifier,
    statement: &SeedClaimStatement,
    proof: &stark::Proof,
) -> Result<(), SeedProofError> {
    let public = if verifier.profile == 2 {
        universal_public_values(statement)
    } else {
        vec![]
    };
    // An upstream malformed-shape assertion is rejection, never authorization.
    let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stark::verify_prepared(&verifier.verifier, proof, &public)
    }))
    .unwrap_or(false);
    if valid {
        Ok(())
    } else {
        Err(SeedProofError::InvalidProof)
    }
}

/// Commits to all fixed cryptographic and relation parameters. No proof may
/// supply FRI settings, a circuit description, or an alternative profile.
pub fn profile_commitment() -> Commitment {
    profile_commitment_for(2).unwrap()
}

pub fn profile_commitment_for(profile: u32) -> Result<Commitment, SeedProofError> {
    let description = match profile {
        1 => stark::PROFILE_DESCRIPTION,
        2 => stark::UNIVERSAL_PROFILE_DESCRIPTION,
        _ => return Err(SeedProofError::UnsupportedProfile),
    };
    Ok(Sha384::digest(description).into())
}

/// Reads only a recognized fixed profile commitment; no parameters or
/// preprocessing root are imported from the proof body.
pub fn proof_profile(body: &[u8]) -> Result<u32, SeedProofError> {
    let digest = body.get(..48).ok_or(SeedProofError::InvalidProofEncoding)?;
    for profile in [1, 2] {
        if digest == profile_commitment_for(profile)? {
            return Ok(profile);
        }
    }
    Err(SeedProofError::UnsupportedProfile)
}

/// Public circuit size, reconstructed without a secret seed. This is useful
/// for resource estimation and for adversarial tests adapting every public
/// header field before exercising the cryptographic verifier.
pub fn circuit_gate_count(statement: &SeedClaimStatement) -> Result<usize, SeedProofError> {
    circuit_gate_count_for_profile(statement, 2)
}

pub fn circuit_gate_count_for_profile(
    statement: &SeedClaimStatement,
    profile: u32,
) -> Result<usize, SeedProofError> {
    validate_statement(statement)?;
    match profile {
        1 => Ok(build_circuit(&[0; 32], statement).gates.len()),
        2 => Ok(UNIVERSAL_GATE_COUNT),
        _ => Err(SeedProofError::UnsupportedProfile),
    }
}

fn statement_hash(statement: &SeedClaimStatement) -> Commitment {
    let mut hash = Sha384::new();
    hash.update(b"agave/pq/seed-proof/statement/v1");
    hash.update(statement.canonical_bytes());
    hash.finalize().into()
}

fn validate_statement(statement: &SeedClaimStatement) -> Result<(), SeedProofError> {
    if statement.intent.expected_generation != 0 {
        return Err(SeedProofError::AlreadyMigrated);
    }
    let mut y = statement.intent.authority;
    y[31] &= 127;
    if BigUint::from_bytes_le(&y) >= edwards::modulus() {
        return Err(SeedProofError::InvalidSeedWitness);
    }
    Ok(())
}

fn build_circuit(seed: &[u8; 32], statement: &SeedClaimStatement) -> Circuit {
    let mut circuit = Circuit::new();
    let seed_bits: Vec<_> = seed
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| u64::from((byte >> i) & 1)))
        .map(|bit| circuit.input(bit, 1))
        .collect();
    let digest = sha512::hash(&mut circuit, &seed_bits);
    edwards::constrain_address(&mut circuit, &digest, &statement.intent.authority);
    let mut message = sha512::constant_bytes(&mut circuit, SECRET_INTENT_DOMAIN);
    message.extend(sha512::constant_bytes(
        &mut circuit,
        &statement.intent.canonical_bytes(),
    ));
    message.extend(seed_bits);
    let commitment = sha512::hash(&mut circuit, &message);
    let expected = sha512::constant_bytes(&mut circuit, &statement.secret_intent_commitment);
    for (actual, expected) in commitment.into_iter().zip(expected) {
        circuit.assert_eq(actual, expected);
    }
    circuit
}

fn prefix(statement: &SeedClaimStatement) -> ([u64; 8], Vec<u8>) {
    let mut bytes = SECRET_INTENT_DOMAIN_V2.to_vec();
    bytes.extend(statement.intent.canonical_bytes());
    assert_eq!(
        bytes.len(),
        PREFIX_BYTES,
        "fixed Falcon-512 intent encoding"
    );
    let (state, tail) = sha512::public_prefix(&bytes);
    (state, tail.to_vec())
}

fn build_universal_relation(
    seed: &[u8; 32],
    authority: &[u8; 32],
    state: [u64; 8],
    tail: &[u8],
    expected: &[u8; 64],
) -> Circuit {
    assert_eq!(tail.len(), TAIL_BYTES);
    let mut circuit = Circuit::new();
    let seed_bits: Vec<_> = seed
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| u64::from((byte >> i) & 1)))
        .map(|bit| circuit.input(bit, 1))
        .collect();
    let digest = sha512::hash(&mut circuit, &seed_bits);
    edwards::constrain_public_address(&mut circuit, &digest, authority);
    let commitment = sha512::hash_public_prefix(
        &mut circuit,
        state,
        tail,
        PREFIX_BYTES - TAIL_BYTES,
        &seed_bits,
    );
    for (actual, expected_bit) in commitment.into_iter().zip(
        expected
            .iter()
            .flat_map(|&byte| (0..8).map(move |i| u64::from((byte >> i) & 1))),
    ) {
        let expected = circuit.public_input(expected_bit, 1);
        circuit.assert_eq(actual, expected);
    }
    circuit
}

fn build_universal_circuit(seed: &[u8; 32], statement: &SeedClaimStatement) -> Circuit {
    let (state, tail) = prefix(statement);
    build_universal_relation(
        seed,
        &statement.intent.authority,
        state,
        &tail,
        &statement.secret_intent_commitment,
    )
}

/// Public input ordering is fixed independently of private witness values.
/// Native SHA-512 prefix state is recomputed from the exact canonical intent.
fn universal_public_values(statement: &SeedClaimStatement) -> Vec<Goldilocks> {
    let mut y = statement.intent.authority;
    y[31] &= 127;
    let mut values: Vec<u64> = y
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u64::from(u16::from_le_bytes(*bytes)))
        .collect();
    values.push(u64::from(statement.intent.authority[31] >> 7));
    let (state, tail) = prefix(statement);
    values.extend(
        state
            .into_iter()
            .flat_map(|word| (0..64).map(move |i| (word >> i) & 1)),
    );
    values.extend(
        tail.iter()
            .flat_map(|byte| (0..8).map(move |i| u64::from((byte >> i) & 1))),
    );
    values.extend(
        statement
            .secret_intent_commitment
            .iter()
            .flat_map(|byte| (0..8).map(move |i| u64::from((byte >> i) & 1))),
    );
    values.into_iter().map(Goldilocks::from_u64).collect()
}

/// Generate an accepting, private proof of the *complete* relation. The local
/// Ed25519 calculation is only an early witness check; verifier authorization
/// comes exclusively from the SHA512/pruning/Edwards/intent circuit proof.
/// The returned bytes are the canonical proof body, before the upload envelope.
pub fn prove_seed_claim(
    seed: &[u8; 32],
    intent: MigrationIntent,
) -> Result<(SeedClaimStatement, Vec<u8>), SeedProofError> {
    if SigningKey::from_bytes(seed).verifying_key().to_bytes() != intent.authority {
        return Err(SeedProofError::InvalidSeedWitness);
    }
    let mut commitment = Sha512::new();
    commitment.update(SECRET_INTENT_DOMAIN_V2);
    commitment.update(intent.canonical_bytes());
    commitment.update(seed);
    let statement = SeedClaimStatement {
        intent,
        secret_intent_commitment: commitment.finalize().into(),
    };
    validate_statement(&statement)?;
    let circuit = build_universal_circuit(seed, &statement);
    if circuit.gates.len() != UNIVERSAL_GATE_COUNT {
        return Err(SeedProofError::UnsupportedProfile);
    }
    if !circuit.audit_witness() {
        return Err(SeedProofError::InvalidSeedWitness);
    }
    let proof = stark::prove_universal(&circuit);
    let encoded =
        postcard::to_allocvec(&proof).map_err(|_| SeedProofError::InvalidProofEncoding)?;
    let mut body = Vec::with_capacity(HEADER_BYTES + encoded.len());
    body.extend(profile_commitment());
    body.extend(statement_hash(&statement));
    body.extend((circuit.gates.len() as u64).to_le_bytes());
    body.extend(encoded);
    if body.len() + 16 > MAX_SEED_PROOF_BYTES {
        return Err(SeedProofError::ProofTooLarge);
    }
    Ok((statement, body))
}

/// Decode only recognized profiles and bounded, canonical proof encodings.
fn decode_proof(
    statement: &SeedClaimStatement,
    body: &[u8],
) -> Result<stark::Proof, SeedProofError> {
    validate_statement(statement)?;
    if body.len() <= HEADER_BYTES || body.len() + 16 > MAX_SEED_PROOF_BYTES {
        return Err(SeedProofError::InvalidProofEncoding);
    }
    let profile = proof_profile(body)?;
    if body[48..96] != statement_hash(statement) {
        return Err(SeedProofError::InvalidProof);
    }
    // Bounded canonical decoding: reject each collection's dimensions *before*
    // serde allocates it, including nested proof-supplied Merkle/FRI paths.
    let (proof, remainder): (stark::Proof, _) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            encoding::decode(&body[HEADER_BYTES..])
        }))
        .map_err(|_| SeedProofError::InvalidProofEncoding)?
        .map_err(|_| SeedProofError::InvalidProofEncoding)?;
    if !remainder.is_empty()
        || postcard::to_allocvec(&proof).map_err(|_| SeedProofError::InvalidProofEncoding)?
            != body[HEADER_BYTES..]
    {
        return Err(SeedProofError::InvalidProofEncoding);
    }
    let instances = if profile == 1 { 2 } else { 3 };
    if proof.degree_bits.len() != instances
        || proof
            .degree_bits
            .iter()
            .any(|&bits| !(2..=24).contains(&bits))
        || proof.opened_values.instances.len() != instances
        || proof.lookup_terminals.len() != instances
    {
        return Err(SeedProofError::InvalidProof);
    }
    if profile == 2
        && (proof.degree_bits != UNIVERSAL_DEGREE_BITS
            || body[96..104] != (UNIVERSAL_GATE_COUNT as u64).to_le_bytes())
    {
        return Err(SeedProofError::InvalidProof);
    }
    Ok(proof)
}

/// Verify every proof cryptographically. Profile 2 uses locally derived
/// universal preprocessing and fresh transcript-bound public inputs. Profile 1
/// uses a bounded statement-specific metadata cache for compatibility.
pub fn verify_seed_proof(
    statement: &SeedClaimStatement,
    body: &[u8],
) -> Result<(), SeedProofError> {
    let proof = decode_proof(statement, body)?;
    let verifier = if proof_profile(body)? == 1 {
        cached_verifier(statement)?
    } else {
        universal_verifier()?
    };
    if body[96..104] != (verifier.gate_count as u64).to_le_bytes() {
        return Err(SeedProofError::InvalidProof);
    }
    verify_decoded(&verifier, statement, &proof)
}

#[cfg(test)]
mod tests {
    use {super::*, crate::crypto::FalconKeypair};

    fn intent(seed: &[u8; 32]) -> MigrationIntent {
        MigrationIntent {
            chain_id: [1; 32],
            context: [2; 32],
            authority: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
            replacement_key: FalconKeypair::generate().public_key(),
            expected_generation: 0,
            claim_nonce: [3; 32],
        }
    }

    fn statement(seed: &[u8; 32], intent: MigrationIntent) -> SeedClaimStatement {
        let mut hash = Sha512::new();
        hash.update(SECRET_INTENT_DOMAIN);
        hash.update(intent.canonical_bytes());
        hash.update(seed);
        SeedClaimStatement {
            intent,
            secret_intent_commitment: hash.finalize().into(),
        }
    }

    #[test]
    fn complete_native_constraint_witness_matches_rfc8032_and_intent() {
        let seed = [0x37; 32];
        let statement = statement(&seed, intent(&seed));
        let circuit = build_circuit(&seed, &statement);
        assert!(
            circuit.audit_witness(),
            "every complete derivation/intent constraint must hold"
        );
        assert!(circuit.gates.len() < (1 << 23));
        let wrong_seed = build_circuit(&[0x38; 32], &statement);
        assert!(!wrong_seed.audit_witness());
        // Routing and fixed gate constants must be independent of private
        // seed bits, carries and quotient values; only trace values may differ.
        assert_eq!(circuit.gates.len(), wrong_seed.gates.len());
        for (a, b) in circuit.gates.iter().zip(&wrong_seed.gates) {
            assert_eq!(
                (a.a, a.b, a.k, a.enforced, a.range, a.assert_zero),
                (b.a, b.b, b.k, b.enforced, b.range, b.assert_zero)
            );
        }
    }

    #[test]
    fn wrong_seed_is_rejected_before_expensive_proving() {
        assert!(matches!(
            prove_seed_claim(&[9; 32], intent(&[8; 32])),
            Err(SeedProofError::InvalidSeedWitness)
        ));
    }

    #[test]
    fn complete_circuit_matches_official_rfc8032_first_key_vector() {
        fn decode(hex: &str) -> [u8; 32] {
            std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        }
        let seed = decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected = decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let mut intent = intent(&seed);
        intent.authority = expected;
        let statement = statement(&seed, intent);
        assert!(build_circuit(&seed, &statement).audit_witness());
        let mut wrong_sign = statement.clone();
        wrong_sign.intent.authority[31] ^= 128;
        assert!(!build_circuit(&seed, &wrong_sign).audit_witness());
        let mut wrong_intent = statement.clone();
        wrong_intent.intent.claim_nonce[0] ^= 1;
        assert!(!build_circuit(&seed, &wrong_intent).audit_witness());
    }

    #[test]
    fn universal_relation_binds_public_values_with_statement_independent_routing() {
        let seed = [0x37; 32];
        let mut statement = statement(&seed, intent(&seed));
        let mut hash = Sha512::new();
        hash.update(SECRET_INTENT_DOMAIN_V2);
        hash.update(statement.intent.canonical_bytes());
        hash.update(seed);
        statement.secret_intent_commitment = hash.finalize().into();
        let circuit = build_universal_circuit(&seed, &statement);
        assert!(circuit.audit_witness());
        assert_eq!(circuit.public_values, universal_public_values(&statement));
        assert!(stark::public_input_shape_is_bounded(
            circuit.public_values.len()
        ));
        let template =
            build_universal_relation(&[0; 32], &[0; 32], [0; 8], &[0; TAIL_BYTES], &[0; 64]);
        assert_eq!(circuit.gates.len(), template.gates.len());
        assert_eq!(circuit.public_values.len(), template.public_values.len());
        for (a, b) in circuit.gates.iter().zip(&template.gates) {
            assert_eq!(
                (a.a, a.b, a.k, a.enforced, a.range, a.assert_zero, a.public),
                (b.a, b.b, b.k, b.enforced, b.range, b.assert_zero, b.public)
            );
        }
        let mut changed = statement.clone();
        changed.intent.claim_nonce[0] ^= 1;
        assert_ne!(
            universal_public_values(&statement),
            universal_public_values(&changed)
        );
        assert!(!build_universal_circuit(&seed, &changed).audit_witness());
    }

    #[test]
    #[ignore = "complete RFC8032 fixed-profile proof: run with --release --ignored"]
    fn complete_private_proof_accepts_and_binds_all_intent_fields() {
        let seed = [0x47; 32];
        let (statement, proof) = prove_seed_claim(&seed, intent(&seed)).unwrap();
        verify_seed_proof(&statement, &proof).unwrap();
        assert!(!proof.windows(32).any(|bytes| bytes == seed));
        let mut altered = statement.clone();
        altered.intent.chain_id[0] ^= 1;
        assert!(verify_seed_proof(&altered, &proof).is_err());
        let mut altered = statement.clone();
        altered.intent.context[0] ^= 1;
        assert!(verify_seed_proof(&altered, &proof).is_err());
        let mut altered = statement.clone();
        altered.intent.claim_nonce[0] ^= 1;
        assert!(verify_seed_proof(&altered, &proof).is_err());
        let mut altered = statement.clone();
        altered.intent.authority[0] ^= 1;
        assert!(verify_seed_proof(&altered, &proof).is_err());
        let mut altered = statement.clone();
        altered.intent.replacement_key = FalconKeypair::generate().public_key();
        assert!(verify_seed_proof(&altered, &proof).is_err());
        let mut altered = statement.clone();
        altered.secret_intent_commitment[0] ^= 1;
        assert!(verify_seed_proof(&altered, &proof).is_err());
        let mut altered = proof.clone();
        altered[0] ^= 1;
        assert!(matches!(
            verify_seed_proof(&statement, &altered),
            Err(SeedProofError::UnsupportedProfile)
        ));
        let mut altered = proof.clone();
        altered.push(0);
        assert!(verify_seed_proof(&statement, &altered).is_err());
    }

    #[test]
    #[ignore = "requires public synthetic fixture from pq-seed-migration; does not re-prove"]
    fn public_complete_fixture_rejects_adapted_headers_and_tampered_opening() {
        use {
            p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField},
            p3_goldilocks::Goldilocks,
        };
        type Challenge = BinomialExtensionField<Goldilocks, 5>;
        let path = std::env::var_os("PQ_SYNTHETIC_PROOF_FIXTURE")
            .unwrap_or_else(|| "/tmp/agave-pq-seed-public-fixture.json".into());
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read(path).expect("generate the public synthetic proof fixture first"),
        )
        .unwrap();
        let array = |name: &str| serde_json::from_value::<[u8; 32]>(fixture[name].clone()).unwrap();
        let replacement: Vec<u8> =
            serde_json::from_value(fixture["replacement_key"].clone()).unwrap();
        let commitment: Vec<u8> =
            serde_json::from_value(fixture["secret_commitment"].clone()).unwrap();
        let statement = SeedClaimStatement {
            intent: MigrationIntent {
                chain_id: array("chain"),
                context: array("context"),
                authority: array("authority"),
                replacement_key: crate::crypto::FalconPublicKey::from_bytes(&replacement).unwrap(),
                expected_generation: 0,
                claim_nonce: array("nonce"),
            },
            secret_intent_commitment: commitment.try_into().unwrap(),
        };
        let envelope: Vec<u8> = serde_json::from_value(fixture["proof"].clone()).unwrap();
        let body = &envelope[16..];
        verify_seed_proof(&statement, body).unwrap();
        assert!(!body.windows(32).any(|bytes| bytes == [11; 32]));
        let (mut proof, remainder): (stark::Proof, _) =
            encoding::decode(&body[HEADER_BYTES..]).unwrap();
        assert!(remainder.is_empty());
        let opened = &proof.opened_values.instances[0]
            .base_opened_values
            .trace_local;
        assert!(opened.iter().all(|value| *value != Challenge::ZERO
            && *value != Challenge::ONE
            && *value != Challenge::from_u64(0x0b0b0b0b)));
        let mut changed = statement.clone();
        changed.intent.claim_nonce[0] ^= 1;
        let mut adapted = body.to_vec();
        adapted[48..96].copy_from_slice(&statement_hash(&changed));
        adapted[96..104].copy_from_slice(
            &(circuit_gate_count_for_profile(&changed, proof_profile(body).unwrap()).unwrap()
                as u64)
                .to_le_bytes(),
        );
        assert_eq!(
            verify_seed_proof(&changed, &adapted),
            Err(SeedProofError::InvalidProof),
            "rewriting every public header cannot adapt the private proof"
        );
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += Challenge::ONE;
        let mut tampered = body[..HEADER_BYTES].to_vec();
        tampered.extend(postcard::to_allocvec(&proof).unwrap());
        assert_eq!(
            verify_seed_proof(&statement, &tampered),
            Err(SeedProofError::InvalidProof)
        );
    }
}
