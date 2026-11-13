//! Serialization of the proving and verifying keys: the bytes a key writes are
//! the bytes it reads back, `bytes_length` is the length of those bytes, and
//! the `transcript_repr` derived from them is the same on both paths (keygen
//! and deserialization).

use blake2b_simd::State;
use midnight_curves::{Bls12, Fq};
use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, ProvingKey, Selector,
        VerifyingKey, keygen_pk, keygen_vk_with_k, prepare,
    },
    poly::{
        Rotation,
        commitment::Guard,
        kzg::{KZGCommitmentScheme, params::ParamsKZG},
    },
    transcript::{CircuitTranscript, Transcript},
    utils::{SerdeFormat, arithmetic::Field},
};
use rand::{SeedableRng, rngs::StdRng};

const K: u32 = 5;

#[derive(Clone)]
struct Config {
    a: Column<Advice>,
    b: Column<Advice>,
    s: Selector,
}

#[derive(Default)]
struct MyCircuit;

impl Circuit<Fq> for MyCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        MyCircuit
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let q = meta.fixed_column();
        let s = meta.selector();

        // Three columns in the permutation argument: two advice and the fixed
        // column carrying constants.
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_constant(q);

        meta.create_gate("a = b", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            Constraints::with_selector(s, vec![a - b])
        });

        Config { a, b, s }
    }

    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fq>) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                config.s.enable(&mut region, 0)?;
                let a = region.assign_advice(|| "", config.a, 0, || Value::known(Fq::ONE))?;
                a.copy_advice(|| "", &mut region, config.b, 0)?;
                Ok(())
            },
        )
    }
}

fn keygen() -> VerifyingKey<Fq, KZGCommitmentScheme<Bls12>> {
    let params = ParamsKZG::<Bls12>::unsafe_setup(K, StdRng::seed_from_u64(0));
    keygen_vk_with_k::<_, KZGCommitmentScheme<Bls12>, _>(&params, &MyCircuit, K)
        .expect("vk should not fail")
}

#[test]
fn vk_round_trip() {
    for format in [
        SerdeFormat::Processed,
        SerdeFormat::RawBytes,
        SerdeFormat::RawBytesUnchecked,
    ] {
        let vk = keygen();
        let bytes = vk.to_bytes(format);
        assert_eq!(bytes.len(), vk.bytes_length(format));

        let read = VerifyingKey::<Fq, KZGCommitmentScheme<Bls12>>::from_bytes::<MyCircuit>(
            &bytes,
            format,
            #[cfg(feature = "circuit-params")]
            (),
        )
        .expect("vk should deserialize");

        assert_eq!(read.to_bytes(format), bytes);
        assert_eq!(read.transcript_repr(), vk.transcript_repr());
    }
}

#[test]
fn pk_round_trip() {
    for format in [
        SerdeFormat::Processed,
        SerdeFormat::RawBytes,
        SerdeFormat::RawBytesUnchecked,
    ] {
        let pk = keygen_pk(keygen(), &MyCircuit).expect("pk should not fail");
        let bytes = pk.to_bytes(format);
        assert_eq!(bytes.len(), pk.bytes_length(format));

        let read = ProvingKey::<Fq, KZGCommitmentScheme<Bls12>>::from_bytes::<MyCircuit>(
            &bytes,
            format,
            #[cfg(feature = "circuit-params")]
            (),
        )
        .expect("pk should deserialize");

        assert_eq!(read.to_bytes(format), bytes);
    }
}

#[test]
fn rejects_082_keys_and_proof_but_reads_compatible_processed_params() {
    // Produced by the signed betsudo 0.8.2 head 397b2424 with the same
    // circuit, k=5, and seeded synthetic parameters; see the fixture README.
    let vk = include_bytes!("fixtures/legacy_082/vk-082.bin");
    let pk = include_bytes!("fixtures/legacy_082/pk-082.bin");
    let params = include_bytes!("fixtures/legacy_082/params-082.bin");
    let proof = include_bytes!("fixtures/legacy_082/proof-082.bin");

    assert_eq!(vk[0], 0x03);
    assert_eq!(pk[0], 0x03);
    assert_eq!(keygen().to_bytes(SerdeFormat::Processed)[0], 0x04);
    let vk_error = match VerifyingKey::<Fq, KZGCommitmentScheme<Bls12>>::from_bytes::<MyCircuit>(
        vk,
        SerdeFormat::Processed,
        #[cfg(feature = "circuit-params")]
        (),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a 0.8.2 verifying key must not load as 0.8.3"),
    };
    assert_eq!(vk_error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(vk_error.to_string(), "unexpected version byte");

    let pk_error = match ProvingKey::<Fq, KZGCommitmentScheme<Bls12>>::from_bytes::<MyCircuit>(
        pk,
        SerdeFormat::Processed,
        #[cfg(feature = "circuit-params")]
        (),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a 0.8.2 proving key must not load as 0.8.3"),
    };
    assert_eq!(pk_error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(pk_error.to_string(), "unexpected version byte");

    let params_read = ParamsKZG::<Bls12>::read_custom(&mut &params[..], SerdeFormat::Processed)
        .expect("the ordinary processed parameter wire format is compatible for this fixture");
    let mut roundtrip = Vec::new();
    params_read.write_custom(&mut roundtrip, SerdeFormat::Processed).unwrap();
    assert_eq!(roundtrip, params);
    let current = ParamsKZG::<Bls12>::unsafe_setup(K, StdRng::seed_from_u64(0));
    let mut generated = Vec::new();
    current.write_custom(&mut generated, SerdeFormat::Processed).unwrap();
    assert_eq!(generated, params);

    let mut transcript = CircuitTranscript::<State>::init_from_bytes(proof);
    let invalid = match prepare(
        &keygen(),
        #[cfg(feature = "committed-instances")]
        &[],
        &[],
        &mut transcript,
    ) {
        Err(_) => true,
        Ok(guard) => guard.verify(&current.verifier_params()).is_err(),
    };
    assert!(invalid, "a 0.8.2 proof must not verify as 0.8.3");
}

#[test]
fn raw_082_keys_reject_and_params_round_trip() {
    let current = ParamsKZG::<Bls12>::unsafe_setup(K, StdRng::seed_from_u64(0));
    for (format, vk, pk, params) in [
        (
            SerdeFormat::RawBytes,
            &include_bytes!("fixtures/legacy_082/vk-082-raw.bin")[..],
            &include_bytes!("fixtures/legacy_082/pk-082-raw.bin")[..],
            &include_bytes!("fixtures/legacy_082/params-082-raw.bin")[..],
        ),
        (
            SerdeFormat::RawBytesUnchecked,
            &include_bytes!("fixtures/legacy_082/vk-082-raw.bin")[..],
            &include_bytes!("fixtures/legacy_082/pk-082-raw.bin")[..],
            &include_bytes!("fixtures/legacy_082/params-082-raw.bin")[..],
        ),
    ] {
        assert_eq!(vk[0], 0x03);
        assert_eq!(pk[0], 0x03);
        let vk_error = match VerifyingKey::<Fq, KZGCommitmentScheme<Bls12>>::from_bytes::<MyCircuit>(
            vk,
            format,
            #[cfg(feature = "circuit-params")]
            (),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a 0.8.2 verifying key must not load as 0.8.3"),
        };
        assert_eq!(vk_error.kind(), std::io::ErrorKind::InvalidData);
        let pk_error = match ProvingKey::<Fq, KZGCommitmentScheme<Bls12>>::from_bytes::<MyCircuit>(
            pk,
            format,
            #[cfg(feature = "circuit-params")]
            (),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a 0.8.2 proving key must not load as 0.8.3"),
        };
        assert_eq!(pk_error.kind(), std::io::ErrorKind::InvalidData);

        let parsed = ParamsKZG::<Bls12>::read_custom(&mut &params[..], format)
            .expect("ordinary parameter bytes should load for this fixture");
        let mut roundtrip = Vec::new();
        parsed.write_custom(&mut roundtrip, format).unwrap();
        assert_eq!(roundtrip, params);
        let mut generated = Vec::new();
        current.write_custom(&mut generated, format).unwrap();
        assert_eq!(generated, params);
    }
}
