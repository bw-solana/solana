//! Fixed Plonky3 0.7 hiding batch-STARK profile.
use {
    super::circuit::{Circuit, Gate},
    p3_air::{Air, BaseAir, PermutationAirBuilder, WindowAccess},
    p3_batch_stark::{
        BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
    },
    p3_challenger::{HashChallenger, SerializingChallenger64},
    p3_commit::ExtensionMmcs,
    p3_dft::Radix2DitParallel,
    p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField},
    p3_fri::{FriParameters, HidingFriPcs},
    p3_goldilocks::Goldilocks,
    p3_lookup::{Count, InteractionBuilder, LookupBus},
    p3_matrix::dense::RowMajorMatrix,
    p3_merkle_tree::MerkleTreeHidingMmcs,
    p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher},
    p3_uni_stark::StarkConfig,
    rand::RngCore,
    rand_p3::{SeedableRng, rngs::StdRng},
    sha2::{Digest, Sha384},
    std::sync::Arc,
};

const PREP_WIDTH: usize = 12;
const UNIVERSAL_PREP_WIDTH: usize = 14;
const RANGE_ROWS: usize = 1 << 17;
const WIRE_BUS: LookupBus<'static> = LookupBus::new("agave_seed_fixed_wires_v1");
const RANGE_BUS: LookupBus<'static> = LookupBus::new("agave_seed_fixed_unsigned_v1");
const PUBLIC_BUS: LookupBus<'static> = LookupBus::new("agave_seed_public_inputs_v2");

pub(super) const PROFILE_DESCRIPTION: &[u8] = b"agave/pq/seed-proof/v1;p3=0.7.0;goldilocks;ext=binomial5;sha384-digest384;fri-blowup16;fri-final16;fri-arity2;fri-queries96;pow0;merkle-salt6;random-codewords6;complete-rfc8032-sha512-prune-edwards-canonical;intent-sha512;wire-logup;u16-limbs;carry23;canonical-p-minus1-complement";
pub(super) const UNIVERSAL_PROFILE_DESCRIPTION: &[u8] = b"agave/pq/seed-proof/v2;proof-profile2;intent-schema1;p3=0.7.0;goldilocks;ext=binomial5;sha384-digest384;fri-blowup16;fri-final16;fri-arity2;fri-queries96;pow0;merkle-salt6;random-codewords6;complete-rfc8032-sha512-prune-edwards-canonical;secret-intent-domain-v2;public-prefix-sha512-compression;fixed-universal-routing;public-input-logup-preprocessed-firstrow-table;wire-logup;u16-limbs;carry23;canonical-p-minus1-complement";

#[derive(Clone, Copy, Debug)]
pub(super) struct ByteHash(u8);

impl CryptographicHasher<u8, [u8; 48]> for ByteHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(b"agave/pq/seed-proof/sha384/v1");
        hasher.update([self.0]);
        let mut buffer = [0_u8; 256];
        let mut used = 0;
        for byte in input {
            buffer[used] = byte;
            used += 1;
            if used == buffer.len() {
                hasher.update(buffer);
                used = 0;
            }
        }
        hasher.update(&buffer[..used]);
        hasher.finalize().into()
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct WordHash(u8);

impl CryptographicHasher<u64, [u64; 6]> for WordHash {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 6] {
        let bytes = ByteHash(self.0).hash_iter(input.into_iter().flat_map(u64::to_le_bytes));
        std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()))
    }
}

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 5>;
type FieldHash = SerializingHasher<WordHash>;
type Compress = CompressionFunctionFromHasher<WordHash, 2, 6>;
type Mmcs = MerkleTreeHidingMmcs<Val, u64, FieldHash, Compress, StdRng, 2, 6, 6>;
type ExtMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 48>>;
type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ExtMmcs, StdRng>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub(super) type Proof = BatchProof<Config>;

fn configuration(deterministic_public_preprocessing: bool, universal: bool) -> Config {
    let fresh_rng = || {
        let mut seed = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        StdRng::from_seed(seed)
    };
    let salt_rng = if deterministic_public_preprocessing {
        StdRng::from_seed([0x41; 32])
    } else {
        fresh_rng()
    };
    let codeword_rng = if deterministic_public_preprocessing {
        StdRng::from_seed([0x92; 32])
    } else {
        fresh_rng()
    };
    let mmcs = Mmcs::new(
        FieldHash::new(WordHash(1)),
        Compress::new(WordHash(2)),
        0,
        salt_rng,
    );
    let fri = FriParameters {
        log_blowup: 4,
        log_final_poly_len: 4,
        max_log_arity: 1,
        num_queries: 96,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ExtMmcs::new(mmcs.clone()),
    };
    let pcs = Pcs::new(Radix2DitParallel::default(), mmcs, fri, 6, codeword_rng);
    let challenger = Challenger::new(HashChallenger::new(
        if universal {
            UNIVERSAL_PROFILE_DESCRIPTION
        } else {
            PROFILE_DESCRIPTION
        }
        .to_vec(),
        ByteHash(3),
    ));
    StarkConfig::new(pcs, challenger)
}

#[derive(Clone)]
enum CircuitAir {
    Gates {
        prep: Option<Arc<RowMajorMatrix<Val>>>,
        universal: bool,
    },
    Range,
    Public {
        count: usize,
    },
}

impl BaseAir<Val> for CircuitAir {
    fn width(&self) -> usize {
        match self {
            Self::Gates { .. } => 3,
            Self::Range => 1,
            Self::Public { .. } => 1,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Gates { universal, .. } => {
                if *universal {
                    UNIVERSAL_PREP_WIDTH
                } else {
                    PREP_WIDTH
                }
            }
            Self::Range => 2,
            Self::Public { .. } => 1,
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Public { count } => *count,
            _ => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Self::Gates { prep, .. } => prep.as_ref().map(|prep| (**prep).clone()),
            Self::Range => {
                let mut values = Vec::with_capacity(2 * RANGE_ROWS);
                for bits in 1..=16 {
                    for value in 0..(1 << bits) {
                        values.extend([Val::from_usize(bits), Val::from_usize(value)]);
                    }
                }
                values.resize(2 * RANGE_ROWS, Val::ZERO);
                Some(RowMajorMatrix::new(values, 2))
            }
            Self::Public { .. } => {
                let mut first_row = vec![Val::ZERO; 256];
                first_row[0] = Val::ONE;
                Some(RowMajorMatrix::new(first_row, 1))
            }
        }
    }
}

impl<AB: PermutationAirBuilder<F = Val> + InteractionBuilder> Air<AB> for CircuitAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        match self {
            Self::Gates { universal, .. } => {
                let prep = builder.preprocessed();
                let p = prep.current_slice().to_vec();
                let [a, b, output] = [local[0], local[1], local[2]];
                let expression = p[3] + p[4] * a + p[5] * b + p[6] * a * b;
                builder.assert_zero(p[7] * (output - expression));
                builder.assert_zero(p[11] * output);
                WIRE_BUS.lookup_key(builder, [p[0].into(), a.into()], 1);
                WIRE_BUS.lookup_key(builder, [p[1].into(), b.into()], 1);
                WIRE_BUS.table_entry(builder, [p[2].into(), output.into()], p[8]);
                RANGE_BUS.lookup_key(
                    builder,
                    [p[9].into(), output.into()],
                    Count::bounded(p[10].into(), 1),
                );
                if *universal {
                    // Each public input occurs in exactly one fixed gate. The
                    // index and selector are committed public preprocessing.
                    PUBLIC_BUS.lookup_key(
                        builder,
                        [p[12].into(), output.into()],
                        Count::bounded(p[13].into(), 1),
                    );
                }
            }
            Self::Public { .. } => {
                builder.assert_zero(local[0]);
                // AIR boundary selectors are not normalized Boolean table
                // weights. A committed [1,0,...,0] polynomial supplies the
                // exact multiplicity used to generate the lookup trace.
                let first = builder.preprocessed().current_slice()[0];
                let public = builder.public_values().to_vec();
                for (i, value) in public.into_iter().enumerate() {
                    // Provide each transcript-bound public value once, on the
                    // unique first row. No witness chooses this table.
                    PUBLIC_BUS.table_entry(builder, [AB::Expr::from_usize(i), value.into()], first);
                }
            }
            Self::Range => {
                let prep = builder.preprocessed();
                let p = prep.current_slice();
                // The table is public and contains exactly every (bits,value)
                // pair with 1<=bits<=16 and 0<=value<2^bits. Multiplicities
                // need not be supplied publicly; global bus balance fixes them.
                RANGE_BUS.table_entry(builder, [p[0], p[1]], local[0]);
            }
        }
    }
}

fn setup(circuit: &Circuit, universal: bool) -> (Vec<CircuitAir>, Vec<usize>) {
    let rows = circuit.gates.len().next_power_of_two().max(256);
    let mut use_counts = vec![0_usize; rows];
    for gate in &circuit.gates {
        use_counts[gate.a] += 1;
        use_counts[gate.b] += 1;
    }
    // Padded gates read the zero wire twice, and constrain their own output
    // zero. Their identifiers are distinct and never produced with weight.
    use_counts[0] += 2 * (rows - circuit.gates.len());
    let width = if universal {
        UNIVERSAL_PREP_WIDTH
    } else {
        PREP_WIDTH
    };
    let mut prep = Vec::with_capacity(rows * width);
    for (i, &use_count) in use_counts.iter().enumerate() {
        let dummy = Gate {
            a: 0,
            b: 0,
            k: [Val::ZERO; 4],
            enforced: true,
            range: 0,
            assert_zero: false,
            public: None,
        };
        let gate = circuit.gates.get(i).unwrap_or(&dummy);
        prep.extend([
            Val::from_usize(gate.a),
            Val::from_usize(gate.b),
            Val::from_usize(i),
            gate.k[0],
            gate.k[1],
            gate.k[2],
            gate.k[3],
            Val::from_bool(gate.enforced),
            Val::from_usize(use_count),
            Val::from_usize(gate.range),
            Val::from_bool(gate.range != 0),
            Val::from_bool(gate.assert_zero),
        ]);
        if universal {
            prep.extend([
                Val::from_usize(gate.public.unwrap_or(0)),
                Val::from_bool(gate.public.is_some()),
            ]);
        }
    }
    let mut airs = vec![
        CircuitAir::Gates {
            prep: Some(Arc::new(RowMajorMatrix::new(prep, width))),
            universal,
        },
        CircuitAir::Range,
    ];
    let mut degrees = vec![
        rows.trailing_zeros() as usize + 1,
        RANGE_ROWS.trailing_zeros() as usize + 1,
    ];
    if universal {
        airs.push(CircuitAir::Public {
            count: circuit.public_values.len(),
        });
        degrees.push(9);
    }
    (airs, degrees)
}

#[cfg(test)]
pub(super) fn prove(circuit: &Circuit) -> Proof {
    prove_inner(circuit, false)
}

pub(super) fn prove_universal(circuit: &Circuit) -> Proof {
    prove_inner(circuit, true)
}

pub(super) fn public_input_shape_is_bounded(count: usize) -> bool {
    use p3_lookup::{LogUpGadget, Lookups};
    let air = CircuitAir::Public { count };
    let lookups =
        Lookups::<Val>::from_air::<Challenge, _>(&air).pack_same_bus(&LogUpGadget::new(), 2);
    // Transcript public variables have degree zero. The fixed one-row selector
    // has degree one, allowing same-bus packing without expanding the quotient.
    // The resulting auxiliary openings must fit the recursive decoder bound.
    count <= 4096 && (lookups.len() + 1) * 5 <= 4096
}

fn prove_inner(circuit: &Circuit, universal: bool) -> Proof {
    if universal {
        assert!(public_input_shape_is_bounded(circuit.public_values.len()));
    }
    let (airs, degrees) = setup(circuit, universal);
    // Predictable preprocessing randomness only commits a *public* circuit.
    // This config never commits any witness. Proof masks and leaf salts use
    // the independently OS-seeded config below.
    let public_config = configuration(true, universal);
    let prover_data = ProverData::<Config>::from_airs_and_degrees(&public_config, &airs, &degrees);
    assert!(
        prover_data
            .common
            .lookups
            .iter()
            .all(|lookups| (lookups.len() + 1) * 5 <= 4096)
    );
    let rows = 1 << (degrees[0] - 1);
    let mut trace = Vec::with_capacity(3 * rows);
    for (i, gate) in circuit.gates.iter().enumerate() {
        trace.extend([
            circuit.values[gate.a],
            circuit.values[gate.b],
            circuit.values[i],
        ]);
    }
    trace.resize(3 * rows, Val::ZERO);
    let main = RowMajorMatrix::new(trace, 3);
    let mut ranges: Vec<Val> = circuit
        .range_counts
        .iter()
        .map(|&n| Val::from_u64(n))
        .collect();
    ranges.resize(RANGE_ROWS, Val::ZERO);
    let range = RowMajorMatrix::new(ranges, 1);
    let public_trace = RowMajorMatrix::new(vec![Val::ZERO; 256], 1);
    let mut traces = vec![&main, &range];
    let mut public_values = vec![vec![], vec![]];
    if universal {
        traces.push(&public_trace);
        public_values.push(circuit.public_values.clone());
    }
    let instances = StarkInstance::new_multiple(&airs, &traces, &public_values);
    prove_batch(&configuration(false, universal), &instances, &prover_data)
}

/// Only the small, locally computed root/metadata/lookup descriptions are
/// needed for verification. Never retain the multi-GiB prover FFT/tree data.
pub(super) struct PreparedVerifier {
    common: CommonData<Config>,
    degrees: Vec<usize>,
    universal: bool,
    public_count: usize,
}

pub(super) fn prepare_verifier(circuit: &Circuit) -> PreparedVerifier {
    prepare_verifier_inner(circuit, false)
}

pub(super) fn prepare_universal_verifier(circuit: &Circuit) -> PreparedVerifier {
    prepare_verifier_inner(circuit, true)
}

fn prepare_verifier_inner(circuit: &Circuit, universal: bool) -> PreparedVerifier {
    let (airs, degrees) = setup(circuit, universal);
    let config = configuration(true, universal);
    let data = ProverData::<Config>::from_airs_and_degrees(&config, &airs, &degrees);
    PreparedVerifier {
        common: data.common,
        degrees,
        universal,
        public_count: circuit.public_values.len(),
    }
}

pub(super) fn verify_prepared(data: &PreparedVerifier, proof: &Proof, public: &[Val]) -> bool {
    if proof.degree_bits != data.degrees
        || proof.opened_values.instances.len() != data.degrees.len()
        || proof.lookup_terminals.len() != data.degrees.len()
        || public.len() != data.public_count
    {
        return false;
    }
    let config = configuration(true, data.universal);
    // AIR evaluation uses opened preprocessing, never the original matrix.
    // Its commitment was established by prepare_verifier, not by the proof.
    let mut airs = vec![
        CircuitAir::Gates {
            prep: None,
            universal: data.universal,
        },
        CircuitAir::Range,
    ];
    let mut public_values = vec![vec![], vec![]];
    if data.universal {
        airs.push(CircuitAir::Public {
            count: public.len(),
        });
        public_values.push(public.to_vec());
    }
    verify_batch(&config, &airs, proof, &public_values, &data.common).is_ok()
}

#[cfg(test)]
pub(super) fn verify(circuit: &Circuit, proof: &Proof) -> bool {
    verify_prepared(&prepare_verifier(circuit), proof, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "two real fixed-profile public-input proofs: run with --release --ignored"]
    fn universal_preprocessing_verifies_distinct_public_inputs() {
        fn relation(a: u64, expected: u64) -> Circuit {
            let mut circuit = Circuit::new();
            let a = circuit.input(a, 4);
            let b = circuit.input(9, 4);
            let product = circuit.mul(a, b);
            let expected = circuit.public_input(expected, 7);
            circuit.assert_eq(product, expected);
            circuit
        }
        let first = relation(7, 63);
        let second = relation(8, 72);
        let data = prepare_universal_verifier(&relation(0, 0));
        let first_proof = prove_universal(&first);
        assert!(verify_prepared(&data, &first_proof, &first.public_values));
        assert!(!verify_prepared(&data, &first_proof, &second.public_values));
        let second_proof = prove_universal(&second);
        assert!(verify_prepared(&data, &second_proof, &second.public_values));
        assert!(!verify_prepared(&data, &second_proof, &first.public_values));
        let mut malicious = relation(7, 62);
        *malicious.values.last_mut().unwrap() = Val::ONE;
        assert!(!malicious.audit_witness());
        let invalid = prove_universal(&malicious);
        assert!(!verify_prepared(&data, &invalid, &malicious.public_values));
    }

    #[test]
    #[ignore = "fixed 96-query hiding proof: run with --release --ignored"]
    fn fixed_profile_proves_private_range_and_wires_and_assertions() {
        let mut circuit = Circuit::new();
        let a = circuit.input(7, 3);
        let b = circuit.input(9, 4);
        let product = circuit.mul(a, b);
        let expected = circuit.constant(63);
        circuit.assert_eq(product, expected);
        assert!(circuit.audit_witness());
        let proof = prove(&circuit);
        assert!(verify(&circuit, &proof));
        let encoded = postcard::to_allocvec(&proof).unwrap();
        let second = prove(&circuit);
        assert!(verify(&circuit, &second));
        assert_ne!(
            postcard::to_allocvec(&proof.commitments.main).unwrap(),
            postcard::to_allocvec(&second.commitments.main).unwrap()
        );
        assert_ne!(
            encoded,
            postcard::to_allocvec(&second).unwrap(),
            "fresh OS masks/salts must change each proof"
        );
        let (mut decoded, remainder): (Proof, _) =
            super::super::encoding::decode(&encoded).unwrap();
        assert!(remainder.is_empty());
        assert!(verify(&circuit, &decoded));
        // Opened evaluations are masked extension elements, not plaintext
        // private input columns. This specifically checks the old direct
        // trace-opening seed-disclosure failure; it is not a formal ZK audit.
        let opened = &decoded.opened_values.instances[0]
            .base_opened_values
            .trace_local;
        assert!(
            opened
                .iter()
                .all(|value| *value != Challenge::from_u64(7) && *value != Challenge::from_u64(9))
        );
        decoded.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += Challenge::ONE;
        assert!(!verify(&circuit, &decoded));
        let mut wrong = Circuit::new();
        let a = wrong.input(7, 3);
        let b = wrong.input(9, 4);
        let product = wrong.mul(a, b);
        let expected = wrong.constant(62);
        wrong.assert_eq(product, expected);
        assert!(!verify(&wrong, &proof));
        // A malicious prover makes the assertion's output equal to 63-62=1,
        // satisfying its arithmetic gate. Its *independent* zero-output AIR
        // constraint must still reject the proof. Bypass the honest native
        // witness audit deliberately; prove_batch's release path is exercised.
        *wrong.values.last_mut().unwrap() = Val::ONE;
        assert!(!wrong.audit_witness());
        let invalid = prove(&wrong);
        assert!(!verify(&wrong, &invalid));
    }
}
