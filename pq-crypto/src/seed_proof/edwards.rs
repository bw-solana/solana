//! Integer emulation of F_(2^255-19). All operands, quotient limbs and signed
//! carries are bounded; equations cannot wrap around the Goldilocks modulus.
use {
    super::circuit::{Circuit, Wire, ZERO},
    num_bigint::BigUint,
    num_traits::{One, Zero},
};

const LIMBS: usize = 16;
const RADIX: i128 = 65536;
const MUL_CARRY_OFFSET: i128 = 1 << 22;

#[derive(Clone)]
pub(super) struct Element {
    pub limbs: [Wire; LIMBS],
    pub native: BigUint,
}

#[derive(Clone)]
struct Point {
    x: Element,
    y: Element,
    z: Element,
    t: Element,
}

pub(super) fn modulus() -> BigUint {
    (BigUint::one() << 255) - BigUint::from(19_u32)
}

fn split(value: &BigUint) -> [u64; LIMBS] {
    let mut bytes = value.to_bytes_le();
    bytes.resize(32, 0);
    std::array::from_fn(|i| u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u64)
}

fn ranged_limbs(circuit: &mut Circuit, value: &BigUint) -> [Wire; LIMBS] {
    let limbs = split(value);
    std::array::from_fn(|i| circuit.input(limbs[i], if i == 15 { 15 } else { 16 }))
}

fn constant(circuit: &mut Circuit, value: BigUint) -> Element {
    assert!(value < modulus());
    Element {
        limbs: split(&value).map(|n| circuit.constant(n)),
        native: value,
    }
}

/// Canonicality: n + (p-1-n) = p-1 as an exact 256-bit integer. Both
/// summands have 15-bit top limbs; all carries are Boolean. Merely giving n
/// 255 bits would also admit the nineteen noncanonical residues p..2^255-1.
fn private(circuit: &mut Circuit, value: BigUint) -> Element {
    let p = modulus();
    assert!(value < p);
    let limbs = ranged_limbs(circuit, &value);
    let complement = ranged_limbs(circuit, &(&p - BigUint::one() - &value));
    let target = split(&(&p - BigUint::one()));
    let mut carry = ZERO;
    for i in 0..LIMBS {
        let sum = circuit.add(limbs[i], complement[i]);
        let sum = circuit.add(sum, carry);
        let carry_value =
            (circuit.value(limbs[i]) + circuit.value(complement[i]) + circuit.value(carry)) >> 16;
        let next = if i + 1 == LIMBS {
            ZERO
        } else {
            circuit.input(carry_value, 1)
        };
        let expected = circuit.gate(next, ZERO, [target[i] as i64, 65536, 0, 0]);
        circuit.assert_eq(sum, expected);
        carry = next;
    }
    Element {
        limbs,
        native: value,
    }
}

fn shifted_carry(circuit: &mut Circuit, carry: i128) -> Wire {
    // |carry| < 2^21 in a 16-limb product. The wider explicit bound also
    // covers the quotient*p convolution and makes the integer proof local.
    let shifted = carry + MUL_CARRY_OFFSET;
    assert!((0..(1 << 23)).contains(&shifted));
    let low = circuit.input(shifted as u64 & 65535, 16);
    let high = circuit.input((shifted as u64) >> 16, 7);
    circuit.gate(low, high, [0, 1, 65536, 0])
}

// This convolution has 32 positions while each operand has 16 limbs; indices
// intentionally address differently sized operands, quotient and carry chains.
#[allow(clippy::needless_range_loop)]
fn mul(circuit: &mut Circuit, a: &Element, b: &Element) -> Element {
    let p = modulus();
    let product = &a.native * &b.native;
    let out = private(circuit, &product % &p);
    let quotient = &product / &p;
    let q = ranged_limbs(circuit, &quotient);
    let pn = split(&p);
    let an = split(&a.native);
    let bn = split(&b.native);
    let qn = split(&quotient);
    let cn = split(&out.native);
    let offset = circuit.constant(MUL_CARRY_OFFSET as u64);
    let mut previous = offset;
    let mut previous_native = 0_i128;
    for i in 0..(2 * LIMBS) {
        let mut sum = ZERO;
        let mut native_sum = previous_native;
        for j in 0..LIMBS {
            if i >= j && i - j < LIMBS {
                let k = i - j;
                let term = circuit.mul(a.limbs[j], b.limbs[k]);
                sum = circuit.add(sum, term);
                sum = circuit.gate(sum, q[j], [0, 1, -(pn[k] as i64), 0]);
                native_sum +=
                    i128::from(an[j]) * i128::from(bn[k]) - i128::from(qn[j]) * i128::from(pn[k]);
            }
        }
        if i < LIMBS {
            sum = circuit.sub(sum, out.limbs[i]);
            native_sum -= i128::from(cn[i]);
        }
        sum = circuit.add(sum, previous);
        assert_eq!(native_sum % RADIX, 0);
        let next_native = native_sum / RADIX;
        let next = if i + 1 == 2 * LIMBS {
            assert_eq!(next_native, 0);
            offset
        } else {
            shifted_carry(circuit, next_native)
        };
        // A*B-Q*p-C+carry_prev = radix*carry_next.
        let expected = circuit.gate(
            next,
            ZERO,
            [-((RADIX - 1) * MUL_CARRY_OFFSET) as i64, 65536, 0, 0],
        );
        circuit.assert_eq(sum, expected);
        previous = next;
        previous_native = next_native;
    }
    out
}

fn add_sub(circuit: &mut Circuit, a: &Element, b: &Element, subtract: bool) -> Element {
    let p = modulus();
    let (native, quotient) = if subtract {
        let q = a.native < b.native;
        ((&a.native + &p - &b.native) % &p, q)
    } else {
        let sum = &a.native + &b.native;
        let q = sum >= p;
        (sum % &p, q)
    };
    let out = private(circuit, native);
    let q = circuit.input(u64::from(quotient), 1);
    let pn = split(&p);
    let an = split(&a.native);
    let bn = split(&b.native);
    let cn = split(&out.native);
    let sign = if subtract { -1_i64 } else { 1_i64 };
    let offset = circuit.constant(4);
    let mut previous = offset;
    let mut previous_native = 0_i128;
    for i in 0..LIMBS {
        let delta = i128::from(an[i]) + i128::from(sign) * i128::from(bn[i])
            - i128::from(cn[i])
            - i128::from(sign) * i128::from(u8::from(quotient)) * i128::from(pn[i]);
        let sum = circuit.gate(a.limbs[i], b.limbs[i], [0, 1, sign, 0]);
        let sum = circuit.gate(sum, q, [0, 1, -sign * pn[i] as i64, 0]);
        let sum = circuit.sub(sum, out.limbs[i]);
        let sum = circuit.add(sum, previous);
        assert_eq!((delta + previous_native) % RADIX, 0);
        let next_native = (delta + previous_native) / RADIX;
        let next = if i + 1 == LIMBS {
            assert_eq!(next_native, 0);
            offset
        } else {
            circuit.input((next_native + 4) as u64, 3)
        };
        let expected = circuit.gate(next, ZERO, [-4 * 65535, 65536, 0, 0]);
        circuit.assert_eq(sum, expected);
        previous = next;
        previous_native = next_native;
    }
    out
}

fn add(circuit: &mut Circuit, a: &Element, b: &Element) -> Element {
    add_sub(circuit, a, b, false)
}

fn sub(circuit: &mut Circuit, a: &Element, b: &Element) -> Element {
    add_sub(circuit, a, b, true)
}

fn select_constant(circuit: &mut Circuit, bit: Wire, yes: &BigUint, no: &BigUint) -> Element {
    let yn = split(yes);
    let nn = split(no);
    Element {
        limbs: std::array::from_fn(|i| {
            circuit.gate(bit, ZERO, [nn[i] as i64, yn[i] as i64 - nn[i] as i64, 0, 0])
        }),
        native: if circuit.value(bit) == 1 {
            yes.clone()
        } else {
            no.clone()
        },
    }
}

fn add_affine(
    circuit: &mut Circuit,
    point: &Point,
    x: &Element,
    y: &Element,
    t: &Element,
    d2: &Element,
) -> Point {
    let ymx = sub(circuit, &point.y, &point.x);
    let ypx = add(circuit, &point.y, &point.x);
    let qymx = sub(circuit, y, x);
    let qypx = add(circuit, y, x);
    let a = mul(circuit, &ymx, &qymx);
    let b = mul(circuit, &ypx, &qypx);
    let td = mul(circuit, t, d2);
    let c = mul(circuit, &point.t, &td);
    let d = add(circuit, &point.z, &point.z);
    let e = sub(circuit, &b, &a);
    let f = sub(circuit, &d, &c);
    let g = add(circuit, &d, &c);
    let h = add(circuit, &b, &a);
    Point {
        x: mul(circuit, &e, &f),
        y: mul(circuit, &g, &h),
        z: mul(circuit, &f, &g),
        t: mul(circuit, &e, &h),
    }
}

fn double_affine(x: &BigUint, y: &BigUint, d: &BigUint) -> (BigUint, BigUint) {
    let p = modulus();
    let x2 = x * x % &p;
    let y2 = y * y % &p;
    let t = d * &x2 * &y2 % &p;
    let inverse_exponent = &p - BigUint::from(2_u32);
    let xx = (BigUint::from(2_u32) * x * y)
        * ((BigUint::one() + &t) % &p).modpow(&inverse_exponent, &p)
        % &p;
    let yy = (&y2 + &x2) * ((BigUint::one() + &p - &t) % &p).modpow(&inverse_exponent, &p) % &p;
    (xx, yy)
}

pub(super) fn constrain_address(circuit: &mut Circuit, digest: &[Wire], authority: &[u8; 32]) {
    constrain_address_inner(circuit, digest, authority, false);
}

pub(super) fn constrain_public_address(
    circuit: &mut Circuit,
    digest: &[Wire],
    authority: &[u8; 32],
) {
    constrain_address_inner(circuit, digest, authority, true);
}

fn constrain_address_inner(
    circuit: &mut Circuit,
    digest: &[Wire],
    authority: &[u8; 32],
    public: bool,
) {
    assert_eq!(digest.len(), 512);
    let p = modulus();
    let inverse_exponent = &p - BigUint::from(2_u32);
    let d = (&p - BigUint::from(121665_u32))
        * BigUint::from(121666_u32).modpow(&inverse_exponent, &p)
        % &p;
    let d2 = constant(circuit, BigUint::from(2_u32) * &d % &p);
    let zero = constant(circuit, BigUint::zero());
    let one = constant(circuit, BigUint::one());
    let mut point = Point {
        x: zero.clone(),
        y: one.clone(),
        z: one,
        t: zero,
    };
    let mut gx = BigUint::parse_bytes(
        b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
        10,
    )
    .unwrap();
    let mut gy = BigUint::from(4_u32) * BigUint::from(5_u32).modpow(&inverse_exponent, &p) % &p;
    // RFC8032 pruning: bits0..2=0, bit254=1, bit255=0. SHA512's
    // digest is supplied in byte order, with little-endian bits within bytes.
    for (i, &digest_bit) in digest.iter().take(255).enumerate() {
        if i >= 3 {
            let bit = if i == 254 {
                circuit.constant(1)
            } else {
                digest_bit
            };
            let qt = &gx * &gy % &p;
            let x = select_constant(circuit, bit, &gx, &BigUint::zero());
            let y = select_constant(circuit, bit, &gy, &BigUint::one());
            let t = select_constant(circuit, bit, &qt, &BigUint::zero());
            point = add_affine(circuit, &point, &x, &y, &t, &d2);
        }
        (gx, gy) = double_affine(&gx, &gy, &d);
    }
    // Require an invertible projective denominator; constrain both affine
    // coordinates and the *canonical* y encoding and x parity bit.
    let inverse = private(circuit, point.z.native.modpow(&inverse_exponent, &p));
    let unit = mul(circuit, &point.z, &inverse);
    let one = constant(circuit, BigUint::one());
    for i in 0..LIMBS {
        circuit.assert_eq(unit.limbs[i], one.limbs[i]);
    }
    let affine_x = private(circuit, &point.x.native * &inverse.native % &p);
    let xz = mul(circuit, &affine_x, &point.z);
    for i in 0..LIMBS {
        circuit.assert_eq(xz.limbs[i], point.x.limbs[i]);
    }
    let mut y_bytes = *authority;
    y_bytes[31] &= 127;
    let y_native = BigUint::from_bytes_le(&y_bytes);
    let y = if public {
        Element {
            limbs: std::array::from_fn(|i| {
                circuit.public_input(
                    u16::from_le_bytes([y_bytes[2 * i], y_bytes[2 * i + 1]]) as u64,
                    if i == 15 { 15 } else { 16 },
                )
            }),
            native: y_native,
        }
    } else {
        constant(circuit, y_native)
    };
    let yz = mul(circuit, &y, &point.z);
    for i in 0..LIMBS {
        circuit.assert_eq(yz.limbs[i], point.y.limbs[i]);
    }
    let half = circuit.input(circuit.value(affine_x.limbs[0]) >> 1, 15);
    let signed_low = if public {
        let sign = circuit.public_input(u64::from(authority[31] >> 7), 1);
        circuit.gate(half, sign, [0, 2, 1, 0])
    } else {
        circuit.gate(half, ZERO, [i64::from(authority[31] >> 7), 2, 0, 0])
    };
    circuit.assert_eq(signed_low, affine_x.limbs[0]);
}

#[cfg(test)]
mod tests {
    use {super::*, p3_field::PrimeCharacteristicRing, p3_goldilocks::Goldilocks};

    #[test]
    fn emulation_handles_modulus_edges_and_rejects_forged_carry() {
        let p = modulus();
        let mut circuit = Circuit::new();
        let a = private(&mut circuit, &p - BigUint::one());
        let b = private(&mut circuit, &p - BigUint::from(2_u8));
        let product = mul(&mut circuit, &a, &b);
        assert_eq!(product.native, BigUint::from(2_u8));
        let sum = add(&mut circuit, &a, &b);
        assert_eq!(sum.native, &p - BigUint::from(3_u8));
        let difference = sub(&mut circuit, &b, &a);
        assert_eq!(difference.native, &p - BigUint::one());
        assert!(circuit.audit_witness());
        let carry = circuit
            .gates
            .iter()
            .position(|gate| !gate.enforced && gate.range == 7)
            .unwrap();
        // This forged carry remains in its permitted seven-bit range. The
        // exact limb equation must reject it independently of range checking.
        let old = circuit.value(carry);
        circuit.values[carry] = Goldilocks::from_u64(if old == 127 { 126 } else { old + 1 });
        assert!(!circuit.audit_witness());
    }
}
