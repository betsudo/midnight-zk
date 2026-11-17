use crate::usage_utils::circuit_runner::CircuitRunner;
use super::*;

#[test]
fn test_blake2b_circuit_can_verify_an_output_of_length_1() {
    let output_size = 1;
    let input = vec![];
    let input_size = 0;
    let expected_output_state = correct_output_for_empty_input_1();
    run_variable_output_length_test(output_size, input, input_size, expected_output_state);
}

#[test]
#[should_panic]
fn test_blake2b_circuit_can_verify_an_output_of_length_1_negative() {
    let output_size = 1;
    let input = vec![];
    let input_size = 0;
    let mut expected_output_state = correct_output_for_empty_input_1();
    expected_output_state[0] = Fq::from(14u64); // Wrong value
    run_variable_output_length_test(output_size, input, input_size, expected_output_state);
}

#[test]
fn test_blake2b_circuit_can_verify_an_output_of_length_32() {
    let output_size = 32;
    let input = vec![];
    let input_size = 0;
    let expected_output_state = correct_output_for_empty_input_32();
    run_variable_output_length_test(output_size, input, input_size, expected_output_state);
}

#[test]
#[should_panic]
fn test_blake2b_circuit_can_verify_an_output_of_length_32_negative() {
    let output_size = 32;
    let input = vec![];
    let input_size = 0;
    let mut expected_output_state = correct_output_for_empty_input_32();
    expected_output_state[0] = Fq::from(15u64); // Wrong value
    run_variable_output_length_test(output_size, input, input_size, expected_output_state);
}

#[test]
#[should_panic(expected = "Output size must be between 1 and 64 bytes")]
fn test_blake2b_circuit_should_receive_an_output_length_less_or_equal_64() {
    let output_size = 65;
    let input = vec![];
    let input_size = 0;
    let expected_output_state = [Fq::ZERO; 65];
    run_variable_output_length_test(output_size, input, input_size, expected_output_state);
}

#[test]
#[should_panic(expected = "Output size must be between 1 and 64 bytes")]
fn test_blake2b_circuit_should_receive_an_output_length_bigger_or_equal_1() {
    let output_size = 0;
    let input = vec![];
    let input_size = 0;
    let expected_output_state = [Fq::ZERO; 65];
    run_variable_output_length_test(output_size, input, input_size, expected_output_state);
}

fn run_variable_output_length_test<const OUT_SIZE: usize>(
    output_size: usize,
    input: Vec<Value<Fq>>,
    input_size: usize,
    expected_output_state: [Fq; OUT_SIZE],
) {
    let circuit =
        CircuitRunner::create_circuit_for_inputs(input, input_size, vec![], 0, output_size);
    let prover = CircuitRunner::mock_prove_with_public_inputs_ref(&expected_output_state, &circuit);
    CircuitRunner::verify_mock_prover(prover);
}

fn correct_output_for_empty_input_1() -> [Fq; 1] {
    [Fq::from(46)]
}

fn correct_output_for_empty_input_32() -> [Fq; 32] {
    [
        14, 87, 81, 192, 38, 229, 67, 178, 232, 171, 46, 176, 96, 153, 218, 161, 209, 229, 223, 71,
        119, 143, 119, 135, 250, 171, 69, 205, 241, 47, 227, 168,
    ]
    .iter()
    .map(|x| Fq::from(*x as u64))
    .collect::<Vec<_>>()
    .try_into()
    .unwrap()
}
