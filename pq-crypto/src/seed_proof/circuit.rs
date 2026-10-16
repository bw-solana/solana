//! A fixed, straight-line arithmetic circuit. Private wire consistency is
//! established by the batch-STARK's global LogUp bus, not by the host evaluator.
use {
    p3_field::{PrimeCharacteristicRing, PrimeField64},
    p3_goldilocks::Goldilocks,
    std::collections::HashMap,
};

pub(super) type Wire = usize;
pub(super) type Word = [Wire; 64];
pub(super) const ZERO: Wire = 0;

#[derive(Clone)]
pub(super) struct Gate {
    pub a: Wire,
    pub b: Wire,
    pub k: [Goldilocks; 4], // constant, a, b, a*b
    pub enforced: bool,
    pub range: usize,
    pub assert_zero: bool,
    /// Profile 2 public input slot. Profile 1 has no public-input gates.
    pub public: Option<usize>,
}

pub(super) struct Circuit {
    pub gates: Vec<Gate>,
    pub values: Vec<Goldilocks>,
    pub constants: Vec<Option<u64>>,
    constant_cache: HashMap<u64, Wire>,
    pub range_counts: Vec<u64>,
    pub public_values: Vec<Goldilocks>,
}

impl Circuit {
    pub fn new() -> Self {
        let mut circuit = Self {
            gates: Vec::new(),
            values: Vec::new(),
            constants: Vec::new(),
            constant_cache: HashMap::new(),
            range_counts: vec![0; (1 << 17) - 2],
            public_values: Vec::new(),
        };
        circuit.constant(0);
        circuit
    }

    pub fn value(&self, wire: Wire) -> u64 {
        self.values[wire].as_canonical_u64()
    }

    fn emit(&mut self, gate: Gate, value: Goldilocks, constant: Option<u64>) -> Wire {
        let wire = self.gates.len();
        if gate.range != 0 {
            let idx = (1 << gate.range) - 2 + value.as_canonical_u64() as usize;
            self.range_counts[idx] += 1;
        }
        self.gates.push(gate);
        self.values.push(value);
        self.constants.push(constant);
        wire
    }

    pub fn constant(&mut self, value: u64) -> Wire {
        let value = Goldilocks::from_u64(value).as_canonical_u64();
        if let Some(&wire) = self.constant_cache.get(&value) {
            return wire;
        }
        let wire = self.emit(
            Gate {
                a: ZERO,
                b: ZERO,
                k: [
                    Goldilocks::from_u64(value),
                    Goldilocks::ZERO,
                    Goldilocks::ZERO,
                    Goldilocks::ZERO,
                ],
                enforced: true,
                range: 0,
                assert_zero: false,
                public: None,
            },
            Goldilocks::from_u64(value),
            Some(value),
        );
        self.constant_cache.insert(value, wire);
        wire
    }

    pub fn input(&mut self, value: u64, bits: usize) -> Wire {
        assert!((1..=16).contains(&bits));
        assert!(value < (1 << bits));
        self.emit(
            Gate {
                a: ZERO,
                b: ZERO,
                k: [Goldilocks::ZERO; 4],
                enforced: false,
                range: bits,
                assert_zero: false,
                public: None,
            },
            Goldilocks::from_u64(value),
            None,
        )
    }

    pub fn public_input(&mut self, value: u64, bits: usize) -> Wire {
        let wire = self.input(value, bits);
        self.gates[wire].public = Some(self.public_values.len());
        self.public_values.push(Goldilocks::from_u64(value));
        wire
    }

    pub fn gate(&mut self, a: Wire, b: Wire, k: [i64; 4]) -> Wire {
        let k = k.map(Goldilocks::from_i64);
        self.gate_field(a, b, k)
    }

    pub fn gate_field(&mut self, a: Wire, b: Wire, k: [Goldilocks; 4]) -> Wire {
        let value = k[0]
            + k[1] * self.values[a]
            + k[2] * self.values[b]
            + k[3] * self.values[a] * self.values[b];
        if (self.constants[a].is_some() || (k[1] == Goldilocks::ZERO && k[3] == Goldilocks::ZERO))
            && (self.constants[b].is_some()
                || (k[2] == Goldilocks::ZERO && k[3] == Goldilocks::ZERO))
        {
            return self.constant(value.as_canonical_u64());
        }
        self.emit(
            Gate {
                a,
                b,
                k,
                enforced: true,
                range: 0,
                assert_zero: false,
                public: None,
            },
            value,
            None,
        )
    }

    pub fn add(&mut self, a: Wire, b: Wire) -> Wire {
        self.gate(a, b, [0, 1, 1, 0])
    }

    pub fn sub(&mut self, a: Wire, b: Wire) -> Wire {
        self.gate(a, b, [0, 1, -1, 0])
    }

    pub fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        self.gate(a, b, [0, 0, 0, 1])
    }

    pub fn assert_eq(&mut self, a: Wire, b: Wire) {
        // An asserted gate produces zero. Its output is fixed independently of
        // the evaluated expression; this is a constraint, not a host comparison.
        self.emit(
            Gate {
                a,
                b,
                k: [
                    Goldilocks::ZERO,
                    Goldilocks::ONE,
                    -Goldilocks::ONE,
                    Goldilocks::ZERO,
                ],
                enforced: true,
                range: 0,
                assert_zero: true,
                public: None,
            },
            Goldilocks::ZERO,
            None,
        );
    }

    pub fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        self.gate(a, b, [0, 1, 1, -2])
    }

    pub fn word_constant(&mut self, value: u64) -> Word {
        std::array::from_fn(|bit| self.constant((value >> bit) & 1))
    }

    pub fn xor_word(&mut self, a: Word, b: Word) -> Word {
        std::array::from_fn(|i| self.xor(a[i], b[i]))
    }

    pub fn xor3_word(&mut self, a: Word, b: Word, c: Word) -> Word {
        let ab = self.xor_word(a, b);
        self.xor_word(ab, c)
    }

    pub fn rotr(word: Word, n: usize) -> Word {
        std::array::from_fn(|i| word[(i + n) % 64])
    }

    pub fn shr(word: Word, n: usize) -> Word {
        std::array::from_fn(|i| if i + n < 64 { word[i + n] } else { ZERO })
    }

    pub fn pack(&mut self, bits: &[Wire]) -> Wire {
        let mut packed = ZERO;
        for &bit in bits.iter().rev() {
            packed = self.gate(packed, bit, [0, 2, 1, 0]);
        }
        packed
    }

    /// Addition modulo 2^64, with four exact 16-bit integer equations. The
    /// output bits and every carry are range constrained by the lookup table.
    pub fn add_words(&mut self, words: &[Word]) -> Word {
        if words.iter().flatten().all(|&w| self.constants[w].is_some()) {
            let value = words.iter().fold(0_u64, |sum, word| {
                sum.wrapping_add(
                    word.iter()
                        .enumerate()
                        .fold(0, |n, (i, &w)| n | (self.value(w) << i)),
                )
            });
            return self.word_constant(value);
        }
        let native = words.iter().fold(0_u64, |sum, word| {
            sum.wrapping_add(
                word.iter()
                    .enumerate()
                    .fold(0, |n, (i, &w)| n | (self.value(w) << i)),
            )
        });
        let result: Word = std::array::from_fn(|i| self.input((native >> i) & 1, 1));
        let mut carry = ZERO;
        let carry_bits = (usize::BITS - words.len().leading_zeros()) as usize;
        for limb in 0..4 {
            let mut sum = carry;
            let mut sum_value = self.value(carry);
            for word in words {
                let packed = self.pack(&word[limb * 16..(limb + 1) * 16]);
                sum_value += self.value(packed);
                sum = self.add(sum, packed);
            }
            let out = self.pack(&result[limb * 16..(limb + 1) * 16]);
            let next_carry = self.input(sum_value >> 16, carry_bits);
            let expected = self.gate(out, next_carry, [0, 1, 65536, 0]);
            self.assert_eq(sum, expected);
            carry = next_carry;
        }
        result
    }

    pub fn audit_witness(&self) -> bool {
        self.gates.iter().enumerate().all(|(i, gate)| {
            (!gate.enforced
                || self.values[i]
                    == gate.k[0]
                        + gate.k[1] * self.values[gate.a]
                        + gate.k[2] * self.values[gate.b]
                        + gate.k[3] * self.values[gate.a] * self.values[gate.b])
                && (gate.range == 0 || self.value(i) < (1 << gate.range))
                && (!gate.assert_zero || self.value(i) == 0)
        })
    }
}
