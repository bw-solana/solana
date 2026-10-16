//! Complete bit-constrained SHA-512, including exact input length and padding.
use super::{
    circuit::{Circuit, Wire, Word},
    sha512_constants::{INITIAL_STATE, K},
};

pub(super) fn hash(circuit: &mut Circuit, message_bits: &[Wire]) -> Vec<Wire> {
    assert_eq!(message_bits.len() % 8, 0);
    let mut message = message_bits.to_vec();
    message.extend((0..8).map(|i| circuit.constant(u64::from(i == 7))));
    while message.len() % 1024 != 896 {
        message.extend([0; 8]);
    }
    let length = (message_bits.len() as u128).to_be_bytes();
    for byte in length {
        message.extend((0..8).map(|i| circuit.constant(u64::from((byte >> i) & 1))));
    }
    let mut state: [Word; 8] = INITIAL_STATE.map(|value| circuit.word_constant(value));
    for block in message.as_chunks::<1024>().0 {
        compress_block(circuit, &mut state, block);
    }
    let mut digest = Vec::with_capacity(512);
    for word in state {
        for byte in (0..8).rev() {
            digest.extend_from_slice(&word[byte * 8..(byte + 1) * 8]);
        }
    }
    digest
}

fn compress_block(circuit: &mut Circuit, state: &mut [Word; 8], block: &[Wire; 1024]) {
    let mut schedule = Vec::with_capacity(80);
    for bytes in block.as_chunks::<64>().0 {
        schedule.push(std::array::from_fn(|i| bytes[(7 - i / 8) * 8 + i % 8]));
    }
    for i in 16..80 {
        let s0 = circuit.xor3_word(
            Circuit::rotr(schedule[i - 15], 1),
            Circuit::rotr(schedule[i - 15], 8),
            Circuit::shr(schedule[i - 15], 7),
        );
        let s1 = circuit.xor3_word(
            Circuit::rotr(schedule[i - 2], 19),
            Circuit::rotr(schedule[i - 2], 61),
            Circuit::shr(schedule[i - 2], 6),
        );
        schedule.push(circuit.add_words(&[schedule[i - 16], s0, schedule[i - 7], s1]));
    }
    let mut work = *state;
    for i in 0..80 {
        let [a, b, c, d, e, f, g, h] = work;
        let sigma1 = circuit.xor3_word(
            Circuit::rotr(e, 14),
            Circuit::rotr(e, 18),
            Circuit::rotr(e, 41),
        );
        // Ch(e,f,g) = g + e*(f-g) for Boolean inputs.
        let ch: Word = std::array::from_fn(|j| {
            let diff = circuit.sub(f[j], g[j]);
            let product = circuit.mul(e[j], diff);
            circuit.add(g[j], product)
        });
        let k = circuit.word_constant(K[i]);
        let t1 = circuit.add_words(&[h, sigma1, ch, k, schedule[i]]);
        let sigma0 = circuit.xor3_word(
            Circuit::rotr(a, 28),
            Circuit::rotr(a, 34),
            Circuit::rotr(a, 39),
        );
        let maj: Word = std::array::from_fn(|j| {
            let ab = circuit.mul(a[j], b[j]);
            let axb = circuit.xor(a[j], b[j]);
            let cx = circuit.mul(c[j], axb);
            circuit.add(ab, cx)
        });
        let t2 = circuit.add_words(&[sigma0, maj]);
        work = [
            circuit.add_words(&[t1, t2]),
            a,
            b,
            c,
            circuit.add_words(&[d, t1]),
            e,
            f,
            g,
        ];
    }
    *state = std::array::from_fn(|i| circuit.add_words(&[state[i], work[i]]));
}

pub(super) fn constant_bytes(circuit: &mut Circuit, bytes: &[u8]) -> Vec<Wire> {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| u64::from((byte >> i) & 1)))
        .map(|bit| circuit.constant(bit))
        .collect()
}

/// SHA-512 compression over complete *public* prefix blocks. No private byte
/// enters this host computation. The verifier repeats it from canonical intent.
pub(super) fn public_prefix(bytes: &[u8]) -> ([u64; 8], &[u8]) {
    let (blocks, tail) = bytes.as_chunks::<128>();
    let mut state = INITIAL_STATE;
    for block in blocks {
        let mut schedule = [0_u64; 80];
        for (slot, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
            *slot = u64::from_be_bytes(*bytes);
        }
        for i in 16..80 {
            let a = schedule[i - 15];
            let b = schedule[i - 2];
            let s0 = a.rotate_right(1) ^ a.rotate_right(8) ^ (a >> 7);
            let s1 = b.rotate_right(19) ^ b.rotate_right(61) ^ (b >> 6);
            schedule[i] = schedule[i - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[i - 7])
                .wrapping_add(s1);
        }
        let mut work = state;
        for i in 0..80 {
            let [a, b, c, d, e, f, g, h] = work;
            let t1 = h
                .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(schedule[i]);
            let t2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            work = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
        }
        state = std::array::from_fn(|i| state[i].wrapping_add(work[i]));
    }
    (state, tail)
}

/// Fixed routing SHA-512 continuation: all prefix-state and remaining public
/// message bits are nonconstant circuit inputs bound by the public-input bus.
/// Padding uses the full prefix+tail+seed length, never a shortened message.
pub(super) fn hash_public_prefix(
    circuit: &mut Circuit,
    state: [u64; 8],
    tail: &[u8],
    prefix_bytes: usize,
    seed_bits: &[Wire],
) -> Vec<Wire> {
    assert_eq!(prefix_bytes % 128, 0);
    let mut state =
        state.map(|word| std::array::from_fn(|i| circuit.public_input((word >> i) & 1, 1)));
    let mut message: Vec<_> = tail
        .iter()
        .flat_map(|byte| (0..8).map(move |i| u64::from((byte >> i) & 1)))
        .map(|bit| circuit.public_input(bit, 1))
        .collect();
    message.extend_from_slice(seed_bits);
    let full_bit_length = 8 * prefix_bytes + message.len();
    message.extend((0..8).map(|i| circuit.constant(u64::from(i == 7))));
    while message.len() % 1024 != 896 {
        message.extend([0; 8]);
    }
    for byte in (full_bit_length as u128).to_be_bytes() {
        message.extend((0..8).map(|i| circuit.constant(u64::from((byte >> i) & 1))));
    }
    for block in message.as_chunks::<1024>().0 {
        compress_block(circuit, &mut state, block);
    }
    let mut digest = Vec::with_capacity(512);
    for word in state {
        for byte in (0..8).rev() {
            digest.extend_from_slice(&word[byte * 8..(byte + 1) * 8]);
        }
    }
    digest
}

#[cfg(test)]
pub(super) fn read_bytes(circuit: &Circuit, bits: &[Wire]) -> Vec<u8> {
    bits.as_chunks::<8>()
        .0
        .iter()
        .map(|byte| {
            byte.iter()
                .enumerate()
                .fold(0, |out, (i, &bit)| out | ((circuit.value(bit) as u8) << i))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        sha2::{Digest, Sha512},
    };

    #[test]
    fn sha512_private_bytes_match_fips_at_padding_boundaries() {
        for length in [0, 32, 111, 112, 128, 257] {
            let bytes: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let mut circuit = Circuit::new();
            let bits: Vec<Wire> = bytes
                .iter()
                .flat_map(|&byte| (0..8).map(move |i| u64::from((byte >> i) & 1)))
                .map(|bit| circuit.input(bit, 1))
                .collect();
            let digest = hash(&mut circuit, &bits);
            assert_eq!(
                read_bytes(&circuit, &digest),
                Sha512::digest(&bytes).as_slice()
            );
            assert!(circuit.audit_witness());
        }
    }

    #[test]
    fn public_compression_continuation_matches_complete_sha512() {
        for public_length in [0, 111, 112, 127, 128, 129, 256, 1109] {
            let public: Vec<u8> = (0..public_length).map(|i| i as u8).collect();
            let seed = [0x37; 32];
            let (state, tail) = public_prefix(&public);
            let mut circuit = Circuit::new();
            let seed_bits: Vec<_> = seed
                .iter()
                .flat_map(|byte| (0..8).map(move |i| u64::from((byte >> i) & 1)))
                .map(|bit| circuit.input(bit, 1))
                .collect();
            let digest = hash_public_prefix(
                &mut circuit,
                state,
                tail,
                public.len() - tail.len(),
                &seed_bits,
            );
            let mut complete = public;
            complete.extend(seed);
            assert_eq!(
                read_bytes(&circuit, &digest),
                Sha512::digest(&complete).as_slice()
            );
            assert!(circuit.audit_witness());
        }
    }
}
