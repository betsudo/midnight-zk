use super::*;
mod negate_circuit;

use crate::tests::test_negate::negate_circuit::NegateCircuit;
use midnight_proofs::dev::MockProver;

#[test]
fn test_negate_zero_should_result_in_max_number() {
    let x = blake2b_value_for(0);
    let not_x = blake2b_value_for(((1u128 << 64) - 1) as u64);

    let circuit = NegateCircuit::<Fq>::new_for(x, not_x);
    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
fn test_negate_number_should_result_in_max_number_minus_that_number() {
    let number = ((1u128 << 40) - 1) as u64;
    let max_number = ((1u128 << 64) - 1) as u64;
    let not_x = blake2b_value_for(max_number - number);

    let circuit = NegateCircuit::<Fq>::new_for(blake2b_value_for(number), not_x);
    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}

#[test]
#[should_panic]
fn test_negate_number_fails_when_given_a_wrong_result() {
    let number = (1u64 << 40) - 1;
    let max_number = ((1u128 << 64) - 1) as u64;
    let not_x = blake2b_value_for(max_number - number - 1);

    let circuit = NegateCircuit::<Fq>::new_for(blake2b_value_for(number), not_x);
    let prover = MockProver::run(&circuit, vec![]).unwrap();
    prover.verify().unwrap();
}
