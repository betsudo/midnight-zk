//! Circuit runner module for creating Blake2bCircuit, synthesizing, proving and verifying it.
//! It can work with both Mock Prover and Real Prover.

use midnight_proofs::dev::MockProver;
use midnight_curves::bls12_381::{Bls12, Fq};
use midnight_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk_with_k, prepare, ProvingKey, VerifyingKey},
    poly::{
        commitment::Guard,
        kzg::{params::ParamsKZG, KZGCommitmentScheme},
    },
    transcript::{CircuitTranscript, Transcript},
};
use blake2b_simd::State as Blake2bState;
use midnight_proofs::circuit::Value;
use midnight_proofs::plonk::Error;
use crate::usage_utils::blake2b_circuit::Blake2bCircuit;

/// The inputs for the Blake2bCircuit. This helps us to avoid passing multiple parameters to the
/// methods that create circuits
pub type Blake2bCircuitInputs = (Vec<Value<Fq>>, usize, Vec<Value<Fq>>, usize, [Fq; 64], usize);

/// Circuit runner struct
#[derive(Debug)]
pub struct CircuitRunner;

/// Circuit runner methods for Mock Prover
impl CircuitRunner {
    /// Preprocess inputs, synthesize, prove and verify the circuit using Mock Prover
    pub fn mocked_preprocess_inputs_synthesize_prove_and_verify(
        input: &String,
        key: &String,
        expected: &String,
    ) {
        let circuit_inputs = Self::prepare_parameters_for_test(input, key, expected);

        let circuit = Self::create_circuit_for_packed_inputs(circuit_inputs.clone());
        let prover = Self::mock_prove_with_public_inputs_ref(&circuit_inputs.4, &circuit);
        Self::verify_mock_prover(prover);
    }

    /// Verify the circuit using Mock Prover
    pub fn verify_mock_prover(prover: MockProver<Fq>) {
        prover.verify().unwrap()
    }

    /// Create and run the Mock Prover using public inputs
    pub fn mock_prove_with_public_inputs_ref(
        expected_output_fields: &[Fq],
        circuit: &Blake2bCircuit<Fq>,
    ) -> MockProver<Fq> {
        MockProver::run(circuit, vec![expected_output_fields.to_vec()]).unwrap()
    }

    /// Create circuit for the given inputs
    pub fn create_circuit_for_inputs(
        input_values: Vec<Value<Fq>>,
        input_size: usize,
        key_values: Vec<Value<Fq>>,
        key_size: usize,
        output_size: usize,
    ) -> Blake2bCircuit<Fq> {
        Blake2bCircuit::<Fq>::new(input_values, input_size, key_values, key_size, output_size)
    }

    /// Create circuit for the given inputs. In this function the inputs are packed in a
    /// Blake2bCircuitInputs struct to avoid passing multiple parameters to the function
    pub fn create_circuit_for_packed_inputs(ci: Blake2bCircuitInputs) -> Blake2bCircuit<Fq> {
        Blake2bCircuit::<Fq>::new(ci.0, ci.1, ci.2, ci.3, ci.5)
    }

    /// Convert the input, key and expected output in byte blocks
    /// For the input and key, blocks are made of values, since they are private inputs of the
    /// circuit
    pub fn prepare_parameters_for_test(
        input: &String,
        key: &String,
        expected: &String,
    ) -> Blake2bCircuitInputs {
        // INPUT
        let input_size = input.len() / 2; // Amount of bytes
        let input_bytes = hex::decode(input).expect("Invalid hex string");
        let input_values =
            input_bytes.iter().map(|x| Value::known(Fq::from(*x as u64))).collect::<Vec<_>>();

        // OUTPUT
        let (expected_output, output_size) = Self::formed_output_block_for(expected);
        let expected_output_fields: [Fq; 64] = expected_output
            .iter()
            .map(|x| Fq::from(*x as u64))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // KEY
        let key_size = key.len() / 2; // Amount of bytes
        let key_bytes = hex::decode(key).expect("Invalid hex string");
        let key_values =
            key_bytes.iter().map(|x| Value::known(Fq::from(*x as u64))).collect::<Vec<_>>();

        (input_values, input_size, key_values, key_size, expected_output_fields, output_size)
    }

    /// Convert the expected output of the circuit in byte blocks
    pub fn formed_output_block_for(output: &String) -> ([u8; 64], usize) {
        let output_block_size = output.len() / 2; // Amount of bytes
        let output_bytes = hex::decode(output).expect("Invalid hex string");
        (output_bytes.try_into().unwrap(), output_block_size)
    }
}

/// Circuit runner methods for Real Prover
impl CircuitRunner {
    /// Preprocess inputs, synthesize, prove and verify the circuit using a real prover
    pub fn real_preprocess_inputs_synthesize_prove_and_verify(
        input: String,
        out: String,
        key: String,
    ) -> Result<(), Error> {
        let circuit_inputs = Self::prepare_parameters_for_test(&input, &key, &out);

        let circuit: Blake2bCircuit<Fq> =
            Self::create_circuit_for_packed_inputs(circuit_inputs.clone());

        let params = ParamsKZG::<Bls12>::unsafe_setup(17, &mut rand::thread_rng());
        let vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>> = Self::create_vk(&circuit, &params);
        let pk: ProvingKey<Fq, KZGCommitmentScheme<Bls12>> = Self::create_pk(&circuit, vk);
        let proof = Self::create_proof(&circuit_inputs.4, circuit, &params, &pk);
        Self::verify(&circuit_inputs.4, &params, pk, &proof)
    }

    /// Create the verifying key for the given circuit and parameters
    pub fn create_vk(
        circuit: &Blake2bCircuit<Fq>,
        params: &ParamsKZG<Bls12>,
    ) -> VerifyingKey<Fq, KZGCommitmentScheme<Bls12>> {
        keygen_vk_with_k(params, circuit, 17).expect("Verifying key should be created")
    }

    /// Create the proving key for the given circuit and parameters
    pub fn create_pk(
        circuit: &Blake2bCircuit<Fq>,
        vk: VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
    ) -> ProvingKey<Fq, KZGCommitmentScheme<Bls12>> {
        keygen_pk(vk.clone(), circuit).expect("Proving key should be created")
    }

    /// Create the proof for the given circuit and parameters
    pub fn create_proof(
        expected_output_fields: &[Fq],
        circuit: Blake2bCircuit<Fq>,
        params: &ParamsKZG<Bls12>,
        pk: &ProvingKey<Fq, KZGCommitmentScheme<Bls12>>,
    ) -> Vec<u8> {
        let mut transcript: CircuitTranscript<Blake2bState> = CircuitTranscript::init();
        create_proof(
            params,
            pk,
            &[circuit],
            0,
            &[&[expected_output_fields]],
            &mut transcript,
            rand::thread_rng(),
        )
        .expect("Proof generation should work");
        transcript.finalize()
    }

    /// Verify the proof for the given circuit and parameters
    pub fn verify(
        expected_output_fields: &[Fq],
        params: &ParamsKZG<Bls12>,
        pk: ProvingKey<Fq, KZGCommitmentScheme<Bls12>>,
        proof: &[u8],
    ) -> Result<(), Error> {
        let mut transcript: CircuitTranscript<Blake2bState> =
            CircuitTranscript::init_from_bytes(proof);

        assert!(prepare::<Fq, KZGCommitmentScheme<Bls12>, _>(
            pk.get_vk(),
            &[&[]],
            &[&[expected_output_fields]],
            &mut transcript,
        )?
        .verify(&params.verifier_params())
        .is_ok());
        Ok(())
    }
}
