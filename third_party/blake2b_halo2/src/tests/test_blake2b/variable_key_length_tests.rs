use crate::usage_utils::circuit_runner::CircuitRunner;
use super::*;

#[test]
#[should_panic(expected = "Key size must be between 1 and 64 bytes")]
fn test_blake2b_circuit_should_receive_an_key_length_less_or_equal_64() {
    let input = vec![];
    let input_size = 0;
    let key: Vec<Value<Fq>> = vec![value_for(0u64); 65];
    let key_size = 65;

    let expected_output_state = [Fq::ZERO; 65];
    let circuit = CircuitRunner::create_circuit_for_inputs(input, input_size, key, key_size, 64);
    let prover = CircuitRunner::mock_prove_with_public_inputs_ref(&expected_output_state, &circuit);
    CircuitRunner::verify_mock_prover(prover);
}
