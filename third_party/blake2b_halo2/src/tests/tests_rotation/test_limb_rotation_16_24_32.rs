use super::*;
use crate::tests::tests_rotation::limb_rotation_circuit::LimbRotationCircuit;
use midnight_proofs::dev::MockProver;
use rand::Rng;

// ------------ ROTATION 32 ------------ //

#[test]
fn test_positive_rotate_right_32() {
    let first_row: [Value<Fq>; 9] =
        generate_row_8bits((1u64 << 32) - 1u64)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] =
        generate_row_8bits((1u128 << 64) - (1u128 << 32))[0..9].try_into().unwrap();
    let valid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 32>::new_for_trace(valid_rotation_32_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_random_rotate_right_32() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let pow32 = 1u64 << 32;
    let expected_result = ((n % pow32) << 32) + (n / pow32);
    let first_row: [Value<Fq>; 9] = generate_row_8bits(n)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(expected_result)[0..9].try_into().unwrap();
    let valid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 32>::new_for_trace(valid_rotation_32_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_32() {
    let first_row: [Value<Fq>; 9] =
        generate_row_8bits((1u64 << 32) - 1u64)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] =
        generate_row_8bits((1u128 << 64) - 1)[0..9].try_into().unwrap();
    let invalid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 32>::new_for_trace(invalid_rotation_32_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_correct_rotation32_wrong_decomposition() {
    let mut first_row: [Value<Fq>; 9] = generate_row_8bits(1u64 << 32)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(1u64)[0..9].try_into().unwrap();
    first_row[4] = value_for(0u8);
    first_row[3] = value_for(1u16 << 8);
    let invalid_rotation_32_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 32>::new_for_trace(invalid_rotation_32_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

// ------------ ROTATION 24 ------------ //
#[test]
fn test_positive_rotate_right_24_limbs() {
    let first_row: [Value<Fq>; 9] = generate_row_8bits(1u128 << 24)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(1u128)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 24>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_random_rotate_right_24() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let pow24 = 1u64 << 24;
    let expected_result = ((n % pow24) << 40) + (n / pow24);
    let first_row: [Value<Fq>; 9] = generate_row_8bits(n)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(expected_result)[0..9].try_into().unwrap();
    let valid_rotation_24_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 24>::new_for_trace(valid_rotation_24_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_24_limbs() {
    let first_row: [Value<Fq>; 9] = generate_row_8bits(1u128 << 24)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(2u8)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 24>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_correct_rotation24_wrong_decomposition() {
    let mut first_row: [Value<Fq>; 9] = generate_row_8bits(1u64 << 32)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(1u64 << 8)[0..9].try_into().unwrap();
    first_row[4] = value_for(0u8);
    first_row[3] = value_for(1u16 << 8);
    let invalid_rotation_24_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 24>::new_for_trace(invalid_rotation_24_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

// ------------ ROTATION 16 ------------ //
#[test]
fn test_positive_rotate_right_16_limbs() {
    let first_row: [Value<Fq>; 9] = generate_row_8bits(1u128 << 16)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(1u128)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 16>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_positive_random_rotate_right_16() {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    let pow16 = 1u64 << 16;
    let expected_result = ((n % pow16) << 48) + (n / pow16);
    let first_row: [Value<Fq>; 9] = generate_row_8bits(n)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(expected_result)[0..9].try_into().unwrap();
    let valid_rotation_16_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 16>::new_for_trace(valid_rotation_16_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_rotate_right_16_limbs() {
    let first_row: [Value<Fq>; 9] = generate_row_8bits(1u128 << 16)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(2u8)[0..9].try_into().unwrap();
    let valid_rotation_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 16>::new_for_trace(valid_rotation_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negative_correct_rotation16_wrong_decomposition() {
    let mut first_row: [Value<Fq>; 9] = generate_row_8bits(1u64 << 32)[0..9].try_into().unwrap();
    let second_row: [Value<Fq>; 9] = generate_row_8bits(1u64 << 16)[0..9].try_into().unwrap();
    first_row[4] = value_for(0u8);
    first_row[3] = value_for(1u16 << 8);
    let invalid_rotation_16_trace = [first_row, second_row];

    let circuit = LimbRotationCircuit::<Fq, 16>::new_for_trace(invalid_rotation_16_trace);

    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
