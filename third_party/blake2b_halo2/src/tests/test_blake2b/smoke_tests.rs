use crate::usage_utils::circuit_runner::CircuitRunner;
use super::*;

#[test]
fn test_blake2b_single_empty_block_positive() {
    let output_size = 64;
    let input = vec![];
    let input_size = 0;
    let expected_output_state = correct_output_for_empty_input_64();

    let circuit =
        CircuitRunner::create_circuit_for_inputs(input, input_size, vec![], 0, output_size);
    let prover = CircuitRunner::mock_prove_with_public_inputs_ref(&expected_output_state, &circuit);
    CircuitRunner::verify_mock_prover(prover);
}

#[test]
#[should_panic]
fn test_blake2b_single_empty_block_negative() {
    let output_size = 64;
    let input = vec![];
    let input_size = 0;
    let mut expected_output_state = correct_output_for_empty_input_64();
    expected_output_state[7] = Fq::from(14u64); // Wrong value

    let circuit =
        CircuitRunner::create_circuit_for_inputs(input, input_size, vec![], 0, output_size);
    let prover = CircuitRunner::mock_prove_with_public_inputs_ref(&expected_output_state, &circuit);
    CircuitRunner::verify_mock_prover(prover);
}

fn correct_output_for_empty_input_64() -> [Fq; 64] {
    [
        Fq::from(120),
        Fq::from(106),
        Fq::from(2),
        Fq::from(247),
        Fq::from(66),
        Fq::from(1),
        Fq::from(89),
        Fq::from(3),
        Fq::from(198),
        Fq::from(198),
        Fq::from(253),
        Fq::from(133),
        Fq::from(37),
        Fq::from(82),
        Fq::from(210),
        Fq::from(114),
        Fq::from(145),
        Fq::from(47),
        Fq::from(71),
        Fq::from(64),
        Fq::from(225),
        Fq::from(88),
        Fq::from(71),
        Fq::from(97),
        Fq::from(138),
        Fq::from(134),
        Fq::from(226),
        Fq::from(23),
        Fq::from(247),
        Fq::from(31),
        Fq::from(84),
        Fq::from(25),
        Fq::from(210),
        Fq::from(94),
        Fq::from(16),
        Fq::from(49),
        Fq::from(175),
        Fq::from(238),
        Fq::from(88),
        Fq::from(83),
        Fq::from(19),
        Fq::from(137),
        Fq::from(100),
        Fq::from(68),
        Fq::from(147),
        Fq::from(78),
        Fq::from(176),
        Fq::from(75),
        Fq::from(144),
        Fq::from(58),
        Fq::from(104),
        Fq::from(91),
        Fq::from(20),
        Fq::from(72),
        Fq::from(183),
        Fq::from(85),
        Fq::from(213),
        Fq::from(111),
        Fq::from(112),
        Fq::from(26),
        Fq::from(254),
        Fq::from(155),
        Fq::from(226),
        Fq::from(206),
    ]
}
