use ff::Field;
use midnight_curves::Fq as Fp;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{fe_to_be_bits, Bits};
use crate::packed_chip::utils::{try_be_bits_to_fe, DenseBits, SpreadBits, SPREAD_BASE_BITS};

#[test]
fn test_bits_from_u64() {
    // test 0b111
    let input = 0b111u64;
    let output_3 = Bits::try_from_u64(input, 3).unwrap();
    let expected_3 = Bits {
        inner: vec![true, true, true],
        upper_bound: 3,
    };
    assert_eq!(expected_3, output_3);

    // same as a 4 bit number
    let output_4 = Bits::try_from_u64(input, 4).unwrap();
    let expected_4 = Bits {
        inner: vec![false, true, true, true],
        upper_bound: 4,
    };
    assert_eq!(expected_4, output_4);

    // should fail as a two bit number
    let expected_err = Bits::try_from_u64(input, 2);
    assert!(expected_err.is_err());

    // test 0b111001u32
    let input = 0b111001u64;
    let output_6 = Bits::try_from_u64(input, 6).unwrap();
    let expected_6 = Bits {
        inner: vec![true, true, true, false, false, true],
        upper_bound: 6,
    };
    assert_eq!(expected_6, output_6);

    // same as a 7 bit number
    let output_7 = Bits::try_from_u64(input, 7).unwrap();
    let expected_7 = Bits {
        inner: vec![false, true, true, true, false, false, true],
        upper_bound: 7,
    };
    assert_eq!(expected_7, output_7);

    // should fail as a 5 bit number
    let expected_err = Bits::try_from_u64(input, 5);
    assert!(expected_err.is_err());

    // test 0
    let input = 0u64;
    let output_1 = Bits::try_from_u64(input, 1).unwrap();
    let expected_1 = Bits {
        inner: vec![false],
        upper_bound: 1,
    };
    assert_eq!(expected_1, output_1);

    // same as 3 bit number
    let output_3 = Bits::try_from_u64(input, 3).unwrap();
    let expected_3 = Bits {
        inner: vec![false, false, false],
        upper_bound: 3,
    };
    assert_eq!(expected_3, output_3);

    // should not be able to use 0 bits!
    let expected_err = Bits::try_from_u64(input, 0);
    assert!(expected_err.is_err());

    // test 2^64
    let input = u64::MAX;
    let output_64 = Bits::try_from_u64(input, 64).unwrap();
    let expected_64 = Bits {
        inner: vec![true; 64],
        upper_bound: 64,
    };
    assert_eq!(expected_64, output_64);

    // should fail with 63 bits
    let expected_err = Bits::try_from_u64(input, 63);
    assert!(expected_err.is_err());
}

// helper function to generate a n random numbers with a bound
fn gen_bounded_random<const N: usize>(rng: &mut impl Rng) -> ([u64; N], usize) {
    let bound = rng.gen_range(1..=64);
    let ubound = if bound == 64 { u64::MAX } else { 1 << bound };
    let res = [0; N].map(|_| rng.gen_range(0..ubound));
    (res, bound)
}

#[test]
fn test_bits_to_field() {
    // test a few random inputs
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        let (input, bound) = gen_bounded_random::<1>(&mut rng);
        // convert the input to bits and then to an F element
        let output: Fp = Bits::try_from_u64(input[0], bound).unwrap().to_field();
        // directly convert input to a field element
        let expected: Fp = input[0].into();
        assert_eq!(output, expected);
    });
}

#[test]
fn test_bits_from_field() {
    // test a few random inputs
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        let (input, bound) = gen_bounded_random::<1>(&mut rng);
        // compute Bits directly from the input
        let expected = Bits::try_from_u64(input[0], bound).unwrap();
        // convert to an F element and then to Bits
        let v = Fp::from(input[0]);
        let output: Bits = Bits::try_from_f(v, bound).unwrap();
        assert_eq!(output, expected);
    });
}

#[test]
fn test_spread_bits() {
    // test a few random inputs
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        let (input, bound) = gen_bounded_random::<1>(&mut rng);

        let dense = DenseBits(Bits::try_from_u64(input[0], bound).unwrap());

        // manually compute the spread bits
        let bits: Vec<bool> =
            dense.0.inner.iter().flat_map(|&b| [false, false, b]).collect::<Vec<_>>();
        let expected = SpreadBits(Bits {
            inner: bits,
            upper_bound: SPREAD_BASE_BITS * bound,
        });

        assert_eq!(dense.spread(), expected);
    });
}

#[test]
fn test_dense_parts() {
    // test a few random inputs
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        // sample two random numbers
        let (input, bound) = gen_bounded_random::<2>(&mut rng);
        let (a, b) = (input[0], input[1]);

        // create the dense parts
        let a_dense = DenseBits::try_from_u64(a, bound).unwrap();
        let b_dense = DenseBits::try_from_u64(b, bound).unwrap();

        // create the spread parts
        let a_spread = a_dense.spread();
        let b_spread = b_dense.spread();

        // 1. test that if we split a_spread in parts we take a_dense and zeros
        // the zero represented in bits
        let zero = DenseBits(Bits::try_from_u64(0, bound).unwrap());
        let a_output = a_spread.dense_parts();

        let expected = [zero.clone(), zero.clone(), a_dense];
        assert_eq!(a_output, expected);

        // 2. check that summing the spread give the dense of (0, a & b, a ^ b)
        // sum the values
        let a_as_f = try_be_bits_to_fe::<Fp>(a_spread.0.inner.as_slice()).unwrap();
        let b_as_f = try_be_bits_to_fe::<Fp>(b_spread.0.inner.as_slice()).unwrap();
        let c = a_as_f + b_as_f;
        // convert to spread bits
        let spread_c = SpreadBits(Bits::try_from_f(c, SPREAD_BASE_BITS * bound).unwrap());
        let parts = spread_c.dense_parts();
        // compute the expected values
        let a_xor_b = DenseBits::try_from_u64(a ^ b, bound).unwrap();
        let a_and_b = DenseBits::try_from_u64(a & b, bound).unwrap();
        let expected = [zero, a_and_b, a_xor_b];

        assert_eq!(parts, expected);
    });
}

#[test]
fn test_f_bits_conversions() {
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        let v = Fp::random(&mut rng);
        // convert to bits and back
        let bits = fe_to_be_bits(&v);
        let output = try_be_bits_to_fe(&bits).unwrap();
        assert_eq!(v, output);
    });
}

#[test]
fn test_spread_to_lane() {
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        let input = rng.next_u64();
        let spread = SpreadBits::try_from_u64(input, 64).unwrap();
        // convert back to lane
        let result = spread.try_to_lane().unwrap();
        let expected = input;
        assert_eq!(result, expected);
    });
}

#[test]
fn test_spread_to_le_bytes() {
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    (0..tries).for_each(|_| {
        let input = rng.next_u64();
        let spread = SpreadBits::try_from_u64(input, 64).unwrap();
        // convert back to lane
        let result = spread.try_to_le_bytes().unwrap();
        let expected = input.to_le_bytes().map(|v| v as u64);
        assert_eq!(result, expected);
    });
}

#[test]
fn test_spread_bit_ops() {
    let mut rng = ChaCha8Rng::from_entropy();
    let tries = 100;
    // test xoring via parity
    (0..tries).for_each(|_| {
        // sample 7 number. The error is always small enough for these numbers
        let input = (0..7).map(|_| rng.next_u64()).collect::<Vec<_>>();
        let spread_bits = input
            .iter()
            .map(|&v| DenseBits::try_from_u64(v, 64).unwrap().spread())
            .collect::<Vec<_>>();
        let mut sum = spread_bits[0].clone();
        spread_bits.iter().skip(1).for_each(|sb| sum = sum.try_add(sb).unwrap());

        // assert field result
        let f = sum.to_field::<Fp>();
        let expected = spread_bits.iter().fold(Fp::ZERO, |acc, x| acc + x.to_field::<Fp>());
        assert_eq!(f, expected);

        // xor is in the parity bit
        let result = sum.dense_parts()[SPREAD_BASE_BITS - 1].to_field::<Fp>();
        let expected = Fp::from(input.iter().take(7).fold(0, |acc, x| acc ^ x));
        assert_eq!(result, expected);
    });
    // test and is in the middle bit
    (0..tries).for_each(|_| {
        let a = rng.next_u64();
        let b = rng.next_u64();
        let spread_a = DenseBits::try_from_u64(a, 64).unwrap().spread();
        let spread_b = DenseBits::try_from_u64(b, 64).unwrap().spread();
        let sum = spread_a.try_add(&spread_b).unwrap();

        // assert field result
        let f = sum.to_field::<Fp>();
        let expected = spread_a.to_field::<Fp>() + spread_b.to_field::<Fp>();
        assert_eq!(f, expected);

        // and is in the second bits
        let result = sum.dense_parts()[SPREAD_BASE_BITS - 2].to_field::<Fp>();
        let expected = Fp::from(a & b);
        assert_eq!(result, expected);
    });
    // test negation
    (0..tries).for_each(|_| {
        let a = rng.next_u64();
        let spread_a = DenseBits::try_from_u64(a, 64).unwrap().spread();
        let spread_res = spread_a.negate().unwrap();

        // assert field result
        let f = spread_res.to_field::<Fp>();
        let ones = DenseBits::try_from_u64(u64::MAX, 64).unwrap().spread().to_field::<Fp>();
        let expected = ones - spread_a.to_field::<Fp>();
        assert_eq!(f, expected);

        // not is in the lsbs
        let result = spread_res.dense_parts()[SPREAD_BASE_BITS - 1].to_field::<Fp>();
        let expected = Fp::from(!a);
        assert_eq!(result, expected);
    });
    // compute the expresion a \xor ((not b) and c) of the chi step of keccak
    // this corresponds to the second bits of (spread(1..1) - b + c) + 2 * a
    (0..tries).for_each(|_| {
        let a = rng.next_u64();
        let b = rng.next_u64();
        let c = rng.next_u64();
        let spread_a = DenseBits::try_from_u64(a, 64).unwrap().spread();
        let spread_b = DenseBits::try_from_u64(b, 64).unwrap().spread();
        let spread_c = DenseBits::try_from_u64(c, 64).unwrap().spread();
        // 2 * a
        let two_a = spread_a.mul2().unwrap();
        // spread(1..1) - b
        let neg_b = spread_b.negate().unwrap();
        // spread(1..1) - b + c
        let neg_b_plus_c = neg_b.try_add(&spread_c).unwrap();
        // result = 2 * a + spread(1..1) - b + c
        let spread_res = two_a.try_add(&neg_b_plus_c).unwrap();

        let ones = DenseBits::try_from_u64(u64::MAX, 64).unwrap().spread().to_field::<Fp>();
        let f = spread_res.to_field::<Fp>();
        let expected = Fp::from(2) * spread_a.to_field::<Fp>()
            + (ones - spread_b.to_field::<Fp>() + spread_c.to_field::<Fp>());

        // assert field result
        assert_eq!(f, expected);

        // the result should be in the middle bits
        let result = spread_res.dense_parts()[SPREAD_BASE_BITS - 2].to_field::<Fp>();
        let expected = Fp::from(a ^ ((!b) & c));
        assert_eq!(result, expected);
    });
}
