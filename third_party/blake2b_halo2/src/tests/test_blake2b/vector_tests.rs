use serde::Deserialize;
use crate::usage_utils::circuit_runner::CircuitRunner;

#[derive(Deserialize, Debug)]
struct TestCase {
    #[serde(rename = "in")]
    input: String,
    key: String,
    out: String,
}

pub(crate) fn run_test(input: &String, key: &String, expected: &String) {
    CircuitRunner::mocked_preprocess_inputs_synthesize_prove_and_verify(input, key, expected);
}

#[test]
fn test_hashes_in_circuit_one_block() {
    let test_cases = obtain_test_cases();

    for (i, case) in test_cases.iter().enumerate() {
        if !case.key.is_empty() || case.input.len() > 256 {
            continue;
        }

        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

#[test]
fn test_hashes_in_circuit_more_than_one_block() {
    let test_cases = obtain_test_cases();

    for (i, case) in test_cases.iter().enumerate() {
        if !case.key.is_empty() || case.input.len() <= 256 {
            continue;
        }

        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

#[test]
fn test_hashes_in_circuit_with_key() {
    let test_cases = obtain_test_cases();

    for (i, case) in test_cases.iter().enumerate() {
        if case.key.is_empty() {
            continue;
        }

        // Uncomment to run representative tests of edge cases
        // if i != 256 && i != 257 && i != 384 && i != 385 {
        //     continue;
        // }

        println!("Running test case {}", i);
        run_test(&case.input, &case.key, &case.out);
    }
}

fn obtain_test_cases() -> Vec<TestCase> {
    let file_content = std::fs::read_to_string("./test_vector.json").expect("Failed to read file");
    serde_json::from_str(&file_content).expect("Failed to parse JSON")
}
