use super::*;
use crate::tests::tests_xor::xor_circuit::XorCircuit;
use midnight_proofs::dev::MockProver;
use rand::Rng;

#[test]
fn test_positive_random_duplicate_xor() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let valid_xor_trace: [[Value<Fq>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(n), // a
        row_decomposed_in_8_limbs_from_u64(n), // b
        row_decomposed_in_8_limbs_from_u64(0), // a xor b
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(valid_xor_trace);
    let prover = MockProver::run(&circuit, vec![]).unwrap();

    prover.verify().unwrap();
}

#[test]
fn test_positive_random_xor_with_0() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let valid_xor_trace: [[Value<Fq>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(n),
        row_decomposed_in_8_limbs_from_u64(0),
        row_decomposed_in_8_limbs_from_u64(n),
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(valid_xor_trace);
    let prover = MockProver::run(&circuit, vec![]).unwrap();

    prover.verify().unwrap();
}

#[test]
fn test_positive_random_xor() {
    let mut rng = rand::thread_rng();
    let n1: u64 = rng.gen();
    let n2: u64 = rng.gen();
    let valid_xor_trace: [[Value<Fq>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(n1),      // a
        row_decomposed_in_8_limbs_from_u64(n2),      // b
        row_decomposed_in_8_limbs_from_u64(n1 ^ n2), // a xor b
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(valid_xor_trace);
    let prover = MockProver::run(&circuit, vec![]).unwrap();

    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_xor_badly_done() {
    let incorrect_xor_trace: [[Value<Fq>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 2) as u64), // b
        row_decomposed_in_8_limbs_from_u64(0),                          // a xor b
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(incorrect_xor_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_incorrect_xor_in_fifth_limb() {
    let incorrect_xor_trace: [[Value<Fq>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(1u64 << 33), // a
        row_decomposed_in_8_limbs_from_u64((1u64 << 33) + (1u64 << 34)), // b
        row_decomposed_in_8_limbs_from_u64(0),          // a xor b
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(incorrect_xor_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_bad_decomposition_in_8_bit_limbs() {
    let mut badly_decomposed_row = [value_for(0u16); 9];
    badly_decomposed_row[4] = value_for(1u16);

    let badly_decomposed_xor_trace: [[Value<Fq>; 9]; 3] = [
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // a
        row_decomposed_in_8_limbs_from_u64(((1u128 << 64) - 1) as u64), // b
        badly_decomposed_row,                                           // a xor b
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(badly_decomposed_xor_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_bad_range_check_limb_u8() {
    let out_of_range_decomposition_row = [
        value_for((1u32 << 16) - 1),
        value_for((1u32 << 16) - 1),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
        value_for(0u16),
    ];

    let badly_decomposed_xor_trace: [[Value<Fq>; 9]; 3] = [
        out_of_range_decomposition_row,
        row_decomposed_in_8_limbs_from_u64(0u64), // b
        out_of_range_decomposition_row,           // a xor b
    ];

    let circuit = XorCircuit::<Fq>::new_for_trace(badly_decomposed_xor_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

fn row_decomposed_in_8_limbs_from_u64(x: u64) -> [Value<Fq>; 9] {
    let mut x_aux = x;
    let mut limbs: [u64; 8] = [0; 8];
    for limb in limbs.iter_mut() {
        *limb = x_aux % 256;
        x_aux /= 256;
    }

    [
        value_for(x),
        value_for(limbs[0]),
        value_for(limbs[1]),
        value_for(limbs[2]),
        value_for(limbs[3]),
        value_for(limbs[4]),
        value_for(limbs[5]),
        value_for(limbs[6]),
        value_for(limbs[7]),
    ]
}
