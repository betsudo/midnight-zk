#![allow(clippy::many_single_char_names)]
#![allow(clippy::op_ref)]

use std::{hash::Hash, marker::PhantomData};

use assert_matches::assert_matches;
use blake2b_simd::State;
use ff::{FromUniformBytes, WithSmallOrderMulGroup};
use midnight_curves::serde::SerdeObject;
use midnight_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Fixed, ProvingKey,
        TableColumn, VerifyingKey, create_proof as create_plonk_proof, keygen_pk, keygen_vk,
        keygen_vk_with_k, prepare as prepare_plonk_proof,
    },
    poly::{
        Rotation,
        commitment::{Guard, PolynomialCommitmentScheme},
        fflonk::Fflonk,
        kzg::{KZGCommitmentScheme, params::ParamsKZG},
    },
    transcript::{CircuitTranscript, Hashable, Sampleable, Transcript},
    utils::{arithmetic::Field, rational::Rational},
};
#[cfg(feature = "disk-spill")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "disk-spill")]
use rand_core::SeedableRng;
use rand_core::{CryptoRng, OsRng, RngCore};

#[test]
#[cfg_attr(feature = "mmap", allow(unsafe_code))]
fn plonk_api() {
    const K: u32 = 5;

    #[derive(Clone)]
    struct PlonkConfig {
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        d: Column<Advice>,
        e: Column<Advice>,

        sa: Column<Fixed>,
        sb: Column<Fixed>,
        sc: Column<Fixed>,
        sm: Column<Fixed>,
        sp: Column<Fixed>,
        sl: TableColumn,
    }

    #[allow(clippy::type_complexity)]
    trait StandardCs<FF: Field> {
        fn raw_multiply<F>(
            &self,
            layouter: &mut impl Layouter<FF>,
            f: F,
        ) -> Result<(Cell, Cell, Cell), Error>
        where
            F: FnMut() -> Value<(Rational<FF>, Rational<FF>, Rational<FF>)>;
        fn raw_add<F>(
            &self,
            layouter: &mut impl Layouter<FF>,
            f: F,
        ) -> Result<(Cell, Cell, Cell), Error>
        where
            F: FnMut() -> Value<(Rational<FF>, Rational<FF>, Rational<FF>)>;
        fn copy(&self, layouter: &mut impl Layouter<FF>, a: Cell, b: Cell) -> Result<(), Error>;
        fn public_input<F>(&self, layouter: &mut impl Layouter<FF>, f: F) -> Result<Cell, Error>
        where
            F: FnMut() -> Value<FF>;
        fn lookup_table(
            &self,
            layouter: &mut impl Layouter<FF>,
            values: &[FF],
        ) -> Result<(), Error>;
    }

    #[derive(Clone)]
    struct MyCircuit<F: Field> {
        a: Value<F>,
        lookup_table: Vec<F>,
    }

    struct StandardPlonk<F: Field> {
        config: PlonkConfig,
        _marker: PhantomData<F>,
    }

    impl<FF: Field> StandardPlonk<FF> {
        fn new(config: PlonkConfig) -> Self {
            StandardPlonk {
                config,
                _marker: PhantomData,
            }
        }
    }

    impl<FF: Field> StandardCs<FF> for StandardPlonk<FF> {
        fn raw_multiply<F>(
            &self,
            layouter: &mut impl Layouter<FF>,
            mut f: F,
        ) -> Result<(Cell, Cell, Cell), Error>
        where
            F: FnMut() -> Value<(Rational<FF>, Rational<FF>, Rational<FF>)>,
        {
            layouter.assign_region(
                || "raw_multiply",
                |mut region| {
                    let mut value = None;
                    let lhs = region.assign_advice(
                        || "lhs",
                        self.config.a,
                        0,
                        || {
                            value = Some(f());
                            value.unwrap().map(|v| v.0)
                        },
                    )?;
                    region.assign_advice(
                        || "lhs^4",
                        self.config.d,
                        0,
                        || value.unwrap().map(|v| v.0).square().square(),
                    )?;
                    let rhs = region.assign_advice(
                        || "rhs",
                        self.config.b,
                        0,
                        || value.unwrap().map(|v| v.1),
                    )?;
                    region.assign_advice(
                        || "rhs^4",
                        self.config.e,
                        0,
                        || value.unwrap().map(|v| v.1).square().square(),
                    )?;
                    let out = region.assign_advice(
                        || "out",
                        self.config.c,
                        0,
                        || value.unwrap().map(|v| v.2),
                    )?;

                    region.assign_fixed(|| "a", self.config.sa, 0, || Value::known(FF::ZERO))?;
                    region.assign_fixed(|| "b", self.config.sb, 0, || Value::known(FF::ZERO))?;
                    region.assign_fixed(|| "c", self.config.sc, 0, || Value::known(FF::ONE))?;
                    region.assign_fixed(|| "a * b", self.config.sm, 0, || Value::known(FF::ONE))?;
                    Ok((lhs.cell(), rhs.cell(), out.cell()))
                },
            )
        }
        fn raw_add<F>(
            &self,
            layouter: &mut impl Layouter<FF>,
            mut f: F,
        ) -> Result<(Cell, Cell, Cell), Error>
        where
            F: FnMut() -> Value<(Rational<FF>, Rational<FF>, Rational<FF>)>,
        {
            layouter.assign_region(
                || "raw_add",
                |mut region| {
                    let mut value = None;
                    let lhs = region.assign_advice(
                        || "lhs",
                        self.config.a,
                        0,
                        || {
                            value = Some(f());
                            value.unwrap().map(|v| v.0)
                        },
                    )?;
                    region.assign_advice(
                        || "lhs^4",
                        self.config.d,
                        0,
                        || value.unwrap().map(|v| v.0).square().square(),
                    )?;
                    let rhs = region.assign_advice(
                        || "rhs",
                        self.config.b,
                        0,
                        || value.unwrap().map(|v| v.1),
                    )?;
                    region.assign_advice(
                        || "rhs^4",
                        self.config.e,
                        0,
                        || value.unwrap().map(|v| v.1).square().square(),
                    )?;
                    let out = region.assign_advice(
                        || "out",
                        self.config.c,
                        0,
                        || value.unwrap().map(|v| v.2),
                    )?;

                    region.assign_fixed(|| "a", self.config.sa, 0, || Value::known(FF::ONE))?;
                    region.assign_fixed(|| "b", self.config.sb, 0, || Value::known(FF::ONE))?;
                    region.assign_fixed(|| "c", self.config.sc, 0, || Value::known(FF::ONE))?;
                    region.assign_fixed(
                        || "a * b",
                        self.config.sm,
                        0,
                        || Value::known(FF::ZERO),
                    )?;
                    Ok((lhs.cell(), rhs.cell(), out.cell()))
                },
            )
        }
        fn copy(
            &self,
            layouter: &mut impl Layouter<FF>,
            left: Cell,
            right: Cell,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "copy",
                |mut region| {
                    region.constrain_equal(left, right)?;
                    region.constrain_equal(left, right)
                },
            )
        }
        fn public_input<F>(&self, layouter: &mut impl Layouter<FF>, mut f: F) -> Result<Cell, Error>
        where
            F: FnMut() -> Value<FF>,
        {
            layouter.assign_region(
                || "public_input",
                |mut region| {
                    let value = region.assign_advice(|| "value", self.config.a, 0, &mut f)?;
                    region.assign_fixed(
                        || "public",
                        self.config.sp,
                        0,
                        || Value::known(FF::ONE),
                    )?;

                    Ok(value.cell())
                },
            )
        }
        fn lookup_table(
            &self,
            layouter: &mut impl Layouter<FF>,
            values: &[FF],
        ) -> Result<(), Error> {
            layouter.assign_table(
                || "",
                |mut table| {
                    for (index, &value) in values.iter().enumerate() {
                        table.assign_cell(
                            || "table col",
                            self.config.sl,
                            index,
                            || Value::known(value),
                        )?;
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
        type Config = PlonkConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                a: Value::unknown(),
                lookup_table: self.lookup_table.clone(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> PlonkConfig {
            let e = meta.advice_column();
            let a = meta.advice_column();
            let b = meta.advice_column();
            let sf = meta.fixed_column();
            let c = meta.advice_column();
            let d = meta.advice_column();
            let p = meta.instance_column();

            meta.enable_equality(a);
            meta.enable_equality(b);
            meta.enable_equality(c);

            let sm = meta.fixed_column();
            let sa = meta.fixed_column();
            let sb = meta.fixed_column();
            let sc = meta.fixed_column();
            let sp = meta.fixed_column();
            let sl = meta.lookup_table_column();

            /*
             *   A         B      ...  sl
             * [
             *   instance  0      ...  0
             *   a         a      ...  0
             *   a         a^2    ...  0
             *   a         a      ...  0
             *   a         a^2    ...  0
             *   ...       ...    ...  ...
             *   ...       ...    ...  instance
             *   ...       ...    ...  a
             *   ...       ...    ...  a
             *   ...       ...    ...  0
             * ]
             */

            meta.lookup("lookup", None, |meta| {
                let a_ = meta.query_any(a, Rotation::cur());
                vec![(a_, sl)]
            });

            meta.create_gate("Combined add-mult", |meta| {
                let d = meta.query_advice(d, Rotation::next());
                let a = meta.query_advice(a, Rotation::cur());
                let sf = meta.query_fixed(sf, Rotation::cur());
                let e = meta.query_advice(e, Rotation::prev());
                let b = meta.query_advice(b, Rotation::cur());
                let c = meta.query_advice(c, Rotation::cur());

                let sa = meta.query_fixed(sa, Rotation::cur());
                let sb = meta.query_fixed(sb, Rotation::cur());
                let sc = meta.query_fixed(sc, Rotation::cur());
                let sm = meta.query_fixed(sm, Rotation::cur());
                Constraints::without_selector(vec![
                    &a * sa + &b * sb + a * b * sm - (c * sc) + sf * (d * e),
                ])
            });

            meta.create_gate("Public input", |meta| {
                let a = meta.query_advice(a, Rotation::cur());
                let p = meta.query_instance(p, Rotation::cur());
                let sp = meta.query_fixed(sp, Rotation::cur());

                Constraints::without_selector(vec![sp * (a - p)])
            });

            meta.enable_equality(sf);
            meta.enable_equality(e);
            meta.enable_equality(d);
            meta.enable_equality(p);
            meta.enable_equality(sm);
            meta.enable_equality(sa);
            meta.enable_equality(sb);
            meta.enable_equality(sc);
            meta.enable_equality(sp);

            PlonkConfig {
                a,
                b,
                c,
                d,
                e,
                sa,
                sb,
                sc,
                sm,
                sp,
                sl,
            }
        }

        fn synthesize(
            &self,
            config: PlonkConfig,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let cs = StandardPlonk::new(config);

            let _ = cs.public_input(&mut layouter, || Value::known(F::ONE + F::ONE))?;

            for _ in 0..10 {
                let a: Value<Rational<_>> = self.a.into();
                let mut a_squared = Value::unknown();
                let (a0, _, c0) = cs.raw_multiply(&mut layouter, || {
                    a_squared = a.square();
                    a.zip(a_squared).map(|(a, a_squared)| (a, a, a_squared))
                })?;
                let (a1, b1, _) = cs.raw_add(&mut layouter, || {
                    let fin = a_squared + a;
                    a.zip(a_squared).zip(fin).map(|((a, a_squared), fin)| (a, a_squared, fin))
                })?;
                cs.copy(&mut layouter, a0, a1)?;
                cs.copy(&mut layouter, b1, c0)?;
            }

            cs.lookup_table(&mut layouter, &self.lookup_table)?;

            Ok(())
        }
    }

    macro_rules! common {
        ($field:ident) => {{
            let a = $field::from(2834758237) * $field::ZETA;
            let instance = $field::ONE + $field::ONE;
            let lookup_table = vec![instance, a, a, $field::ZERO];
            (a, instance, lookup_table)
        }};
    }

    macro_rules! bad_keys {
        ($field: ident, $scheme:ty) => {{
            let (_, _, lookup_table) = common!($field);
            let empty_circuit: MyCircuit<$field> = MyCircuit {
                a: Value::unknown(),
                lookup_table: lookup_table.clone(),
            };

            // Check that we get an error if we try to initialize the proving key with a value of
            // k that is too small for the minimum required number of rows.
            let much_too_small_params= <$scheme as PolynomialCommitmentScheme<$field>>::gen_params(1);
            assert_matches!(
                keygen_vk_with_k::<_, $scheme, _>(&much_too_small_params, &empty_circuit, 1),
                Err(Error::NotEnoughRowsAvailable {
                    current_k: 1,
                })
            );

            // Check that we get an error if we try to initialize the proving key with a value of
            // k that is too small for the number of rows the circuit uses.
            let slightly_too_small_params = <$scheme as PolynomialCommitmentScheme<$field>>::gen_params(K-1);
            assert_matches!(
                keygen_vk_with_k::<_, $scheme, _>(&slightly_too_small_params, &empty_circuit, K - 1),
                Err(Error::NotEnoughRowsAvailable {
                    current_k,
                }) if current_k == K - 1
            );
        }};
    }

    fn keygen<F, Scheme: PolynomialCommitmentScheme<F>>(
        params: &mut Scheme::Parameters,
        explicit_k: Option<u32>,
    ) -> ProvingKey<F, Scheme>
    where
        F: FromUniformBytes<64> + WithSmallOrderMulGroup<3> + Ord,
    {
        let (_, _, lookup_table) = common!(F);
        let empty_circuit: MyCircuit<F> = MyCircuit {
            a: Value::unknown(),
            lookup_table,
        };

        // Initialize the proving key
        let vk = if let Some(k) = explicit_k {
            keygen_vk_with_k(params, &empty_circuit, k)
        } else {
            keygen_vk(params, &empty_circuit)
        }
        .expect("keygen_vk should not fail");

        keygen_pk(vk, &empty_circuit).expect("keygen_pk should not fail")
    }

    fn create_proof<
        F,
        Scheme: PolynomialCommitmentScheme<F>,
        T: Transcript,
        R: RngCore + CryptoRng,
    >(
        rng: R,
        params: &Scheme::Parameters,
        pk: &ProvingKey<F, Scheme>,
    ) -> Vec<u8>
    where
        F: Ord
            + WithSmallOrderMulGroup<3>
            + FromUniformBytes<64>
            + Sampleable<T::Hash>
            + Hashable<T::Hash>
            + Hash
            + SerdeObject,
        Scheme::Commitment: Hashable<T::Hash>,
    {
        let (a, instance, lookup_table) = common!(F);

        let circuit: MyCircuit<F> = MyCircuit {
            a: Value::known(a),
            lookup_table,
        };

        let mut transcript = T::init();

        create_plonk_proof::<F, Scheme, _, _>(
            params,
            pk,
            &circuit,
            #[cfg(feature = "committed-instances")]
            0,
            &[&[instance]],
            &mut transcript,
            rng,
        )
        .expect("proof generation should not fail");

        // Check this circuit is satisfied.
        let prover = match MockProver::run(&circuit, vec![vec![instance]]) {
            Ok(prover) => prover,
            Err(e) => panic!("{e:?}"),
        };
        assert_eq!(prover.verify(), Ok(()));

        transcript.finalize()
    }

    fn verify_proof<F, Scheme: PolynomialCommitmentScheme<F>, T: Transcript>(
        params_verifier: &Scheme::VerifierParameters,
        vk: &VerifyingKey<F, Scheme>,
        proof: &[u8],
    ) where
        F: Ord
            + WithSmallOrderMulGroup<3>
            + FromUniformBytes<64>
            + Sampleable<T::Hash>
            + Hashable<T::Hash>
            + Hash
            + SerdeObject,
        Scheme::Commitment: Hashable<T::Hash>,
    {
        let (_, instance, _) = common!(F);
        let pubinputs = [instance];

        let mut transcript = T::init_from_bytes(proof);

        let verifier = prepare_plonk_proof(
            vk,
            #[cfg(feature = "committed-instances")]
            &[],
            &[&pubinputs[..]],
            &mut transcript,
        )
        .unwrap();

        assert!(verifier.verify(params_verifier).is_ok());
    }

    use midnight_curves::{Bls12, Fq as Scalar};

    type Scheme = KZGCommitmentScheme<Bls12>;
    bad_keys!(Scalar, Scheme);

    let rng = OsRng;
    let full_ceremony_k = std::env::var_os("MIDNIGHT_PROOFS_TEST_CEREMONY_FULL_K").is_some();
    assert!(
        !full_ceremony_k || std::env::var_os("MIDNIGHT_PROOFS_TEST_CEREMONY_SRS").is_some(),
        "full-k gate requires a ceremony SRS file"
    );
    // Opt-in gate for a translated ceremony SRS. Keep the ordinary test
    // self-contained, but exercise exact Ledger9 parameter bytes when the
    // file is available locally.
    let mut params = if let Some(path) = std::env::var_os("MIDNIGHT_PROOFS_TEST_CEREMONY_SRS") {
        use std::io::Cursor;

        use midnight_proofs::utils::SerdeFormat;

        let bytes = std::fs::read(path).expect("read ceremony SRS");
        let mut params =
            ParamsKZG::<Bls12>::read_custom(&mut Cursor::new(&bytes), SerdeFormat::RawBytes)
                .expect("read ceremony SRS in the ordinary format");
        assert!(params.max_k() >= K);
        let mut roundtrip = Vec::new();
        params.write_custom(&mut roundtrip, SerdeFormat::RawBytes).unwrap();
        assert_eq!(roundtrip, bytes, "ordinary SRS bytes changed on round trip");

        // Ledger9's trusted-file loader uses this unchecked mode. Compare
        // its result to the checked file bytes before downsizing.
        let unchecked = ParamsKZG::<Bls12>::read_custom(
            &mut Cursor::new(&bytes),
            SerdeFormat::RawBytesUnchecked,
        )
        .expect("read ceremony SRS through the Ledger9 loader format");
        let mut unchecked_roundtrip = Vec::new();
        unchecked.write_custom(&mut unchecked_roundtrip, SerdeFormat::RawBytes).unwrap();
        assert_eq!(unchecked_roundtrip, bytes);

        let lazy =
            ParamsKZG::<Bls12>::read_custom_lazy(&mut Cursor::new(&bytes), SerdeFormat::RawBytes)
                .expect("read ceremony SRS with deferred Lagrange basis");
        let mut lazy_roundtrip = Vec::new();
        lazy.write_custom(&mut lazy_roundtrip, SerdeFormat::RawBytes).unwrap();
        assert_eq!(
            lazy_roundtrip, bytes,
            "lazy SRS basis differs from the file"
        );
        let lazy_unchecked = ParamsKZG::<Bls12>::read_custom_lazy(
            &mut Cursor::new(&bytes),
            SerdeFormat::RawBytesUnchecked,
        )
        .expect("read ceremony SRS through the Ledger9 lazy loader format");
        let mut lazy_unchecked_roundtrip = Vec::new();
        lazy_unchecked
            .write_custom(&mut lazy_unchecked_roundtrip, SerdeFormat::RawBytes)
            .unwrap();
        assert_eq!(lazy_unchecked_roundtrip, bytes);

        #[cfg(feature = "mmap")]
        {
            let mut companion = Vec::new();
            params.write_mmap_companion(&mut companion).unwrap();
            let mut mapping = memmap2::MmapMut::map_anon(companion.len()).unwrap();
            mapping[..companion.len()].copy_from_slice(&companion);
            // SAFETY: this test owns the immutable mapping until the mapped
            // parameters and their round trip are dropped.
            let mapped = unsafe {
                ParamsKZG::<Bls12>::read_mmap_arc(std::sync::Arc::new(
                    mapping.make_read_only().unwrap(),
                ))
            }
            .expect("read ceremony SRS companion");
            assert_eq!(mapped.max_k(), params.max_k());
            let mut mapped_roundtrip = Vec::new();
            mapped.write_custom(&mut mapped_roundtrip, SerdeFormat::RawBytes).unwrap();
            assert_eq!(mapped_roundtrip, bytes, "mapped SRS differs from the file");
        }

        if full_ceremony_k {
            assert_eq!(params.max_k(), 14, "full-k gate expects Ledger9's k=14 SRS");
        } else {
            params.downsize(K);
        }
        params
    } else {
        ParamsKZG::<Bls12>::unsafe_setup(K, rng)
    };

    let pk = keygen::<Scalar, Scheme>(&mut params, full_ceremony_k.then_some(14));
    if full_ceremony_k {
        assert_eq!(pk.get_vk().n(), 1 << 14);
    }

    let proof = create_proof::<Scalar, Scheme, CircuitTranscript<State>, _>(rng, &params, &pk);

    verify_proof::<_, _, CircuitTranscript<State>>(
        &params.verifier_params(),
        pk.get_vk(),
        &proof[..],
    );

    if full_ceremony_k {
        // Keep this opt-in gate to one heap proof and one mapped-parameter
        // proof. The ordinary test below covers the other storage policies
        // and FFLONK on its small synthetic circuit.
        #[cfg(feature = "mmap")]
        {
            let mut companion = Vec::new();
            params.write_mmap_companion(&mut companion).unwrap();
            let mut mapping = memmap2::MmapMut::map_anon(companion.len()).unwrap();
            mapping[..companion.len()].copy_from_slice(&companion);
            let mapping = std::sync::Arc::new(mapping.make_read_only().unwrap());
            // SAFETY: this test owns the immutable mapping until the mapped
            // parameters and proof have both been dropped.
            let mut mapped = unsafe { ParamsKZG::<Bls12>::read_mmap_arc(mapping) }.unwrap();
            assert_eq!(mapped.max_k(), 14);
            let mapped_pk = keygen::<Scalar, Scheme>(&mut mapped, Some(14));
            assert_eq!(mapped_pk.get_vk().n(), 1 << 14);
            let mapped_proof = create_proof::<Scalar, Scheme, CircuitTranscript<State>, _>(
                OsRng, &mapped, &mapped_pk,
            );
            verify_proof::<_, _, CircuitTranscript<State>>(
                &mapped.verifier_params(),
                mapped_pk.get_vk(),
                &mapped_proof,
            );
        }
        return;
    }

    #[cfg(feature = "disk-spill")]
    {
        use midnight_proofs::{
            config::ProverConfig,
            plonk::{create_proof_with, keygen_pk_with},
            utils::SerdeFormat,
        };

        let (a, instance, lookup_table) = common!(Scalar);
        let circuit = MyCircuit {
            a: Value::known(a),
            lookup_table,
        };
        let mut spill_policy = ProverConfig::mapped_key_and_cosets();
        spill_policy.coset_spill_floor_k = 0;
        let empty_circuit = MyCircuit {
            a: Value::unknown(),
            lookup_table: circuit.lookup_table.clone(),
        };
        let spill_vk = keygen_vk::<Scalar, Scheme, _>(&mut params, &empty_circuit).unwrap();
        let spill_pk = keygen_pk_with(spill_vk, &empty_circuit, &spill_policy).unwrap();
        let serialized_key = spill_pk.to_bytes(SerdeFormat::Processed);
        let loaded_pk = ProvingKey::<Scalar, Scheme>::read_with_policy::<_, MyCircuit<Scalar>>(
            &mut &serialized_key[..],
            SerdeFormat::Processed,
            #[cfg(feature = "circuit-params")]
            (),
            &spill_policy,
        )
        .expect("the mapped-key load policy should succeed");
        assert_eq!(loaded_pk.to_bytes(SerdeFormat::Processed), serialized_key);
        let heap_pk = ProvingKey::<Scalar, Scheme>::read_with_policy::<_, MyCircuit<Scalar>>(
            &mut &serialized_key[..],
            SerdeFormat::Processed,
            #[cfg(feature = "circuit-params")]
            (),
            &ProverConfig::process(),
        )
        .expect("the heap-key load policy should succeed");
        assert_eq!(heap_pk.to_bytes(SerdeFormat::Processed), serialized_key);
        let mapped_only_policy = ProverConfig::mapped_key();
        let mapped_only_vk = keygen_vk::<Scalar, Scheme, _>(&mut params, &empty_circuit).unwrap();
        let generated_mapped_only_pk =
            keygen_pk_with(mapped_only_vk, &empty_circuit, &mapped_only_policy).unwrap();
        assert_eq!(
            generated_mapped_only_pk.to_bytes(SerdeFormat::Processed),
            serialized_key
        );
        let mapped_only_pk =
            ProvingKey::<Scalar, Scheme>::read_with_policy::<_, MyCircuit<Scalar>>(
                &mut &serialized_key[..],
                SerdeFormat::Processed,
                #[cfg(feature = "circuit-params")]
                (),
                &mapped_only_policy,
            )
            .expect("the mapped-key policy without coset spill should succeed");
        assert_eq!(
            mapped_only_pk.to_bytes(SerdeFormat::Processed),
            serialized_key
        );
        let failing_policy = ProverConfig {
            spill_dir: Some("/nonexistent-midnight-spill-dir/for-this-test".into()),
            ..spill_policy.clone()
        };
        let failing_vk = keygen_vk::<Scalar, Scheme, _>(&mut params, &empty_circuit).unwrap();
        assert_matches!(
            keygen_pk_with(failing_vk, &empty_circuit, &failing_policy),
            Err(Error::KeyStorage(_))
        );
        assert!(
            ProvingKey::<Scalar, Scheme>::read_with_policy::<_, MyCircuit<Scalar>>(
                &mut &serialized_key[..],
                SerdeFormat::Processed,
                #[cfg(feature = "circuit-params")]
                (),
                &failing_policy,
            )
            .is_err(),
            "an opted-in key mapping failure must be returned to the caller"
        );
        let mut first_proof = None;
        for (key, policy) in [
            (&spill_pk, spill_policy.clone()),
            (&generated_mapped_only_pk, mapped_only_policy.clone()),
            (
                &loaded_pk,
                ProverConfig {
                    spill_dir: Some("/nonexistent-midnight-spill-dir/for-this-test".into()),
                    ..spill_policy
                },
            ),
            (&mapped_only_pk, mapped_only_policy),
            (&heap_pk, ProverConfig::process().clone()),
        ] {
            let mut transcript = CircuitTranscript::<State>::init();
            create_proof_with(
                &params,
                key,
                &policy,
                &circuit,
                #[cfg(feature = "committed-instances")]
                0,
                &[&[instance]],
                &mut transcript,
                ChaCha20Rng::from_seed([42; 32]),
            )
            .expect("mapped cosets and heap fallback must both prove");
            let proof = transcript.finalize();
            if let Some(first) = &first_proof {
                assert_eq!(
                    first, &proof,
                    "storage policy must not change a seeded proof"
                );
            } else {
                first_proof = Some(proof.clone());
            }
            verify_proof::<_, _, CircuitTranscript<State>>(
                &params.verifier_params(),
                key.get_vk(),
                &proof,
            );
            let wrong_inputs = [instance + Scalar::ONE];
            let mut wrong_transcript = CircuitTranscript::<State>::init_from_bytes(&proof);
            if let Ok(verifier) = prepare_plonk_proof(
                key.get_vk(),
                #[cfg(feature = "committed-instances")]
                &[],
                &[&wrong_inputs],
                &mut wrong_transcript,
            ) {
                assert!(verifier.verify(&params.verifier_params()).is_err());
            }
        }
    }

    #[cfg(feature = "mmap")]
    {
        let mut companion = Vec::new();
        params.write_mmap_companion(&mut companion).unwrap();
        let mut mapping = memmap2::MmapMut::map_anon(companion.len()).unwrap();
        mapping[..companion.len()].copy_from_slice(&companion);
        let mapping = std::sync::Arc::new(mapping.make_read_only().unwrap());
        // SAFETY: the test owns this immutable anonymous mapping until the
        // mapped parameters and proof are dropped.
        let mut mapped = unsafe { ParamsKZG::<Bls12>::read_mmap_arc(mapping) }.unwrap();
        let mapped_pk = keygen::<Scalar, Scheme>(&mut mapped, None);
        let mapped_proof =
            create_proof::<Scalar, Scheme, CircuitTranscript<State>, _>(OsRng, &mapped, &mapped_pk);
        verify_proof::<_, _, CircuitTranscript<State>>(
            &mapped.verifier_params(),
            mapped_pk.get_vk(),
            &mapped_proof,
        );
    }

    // fflonk combining up to 2 and up to 4 polynomials.
    fn fflonk_roundtrip<const LOG2_T_MAX: u32>() {
        bad_keys!(Scalar, Fflonk<Scheme, LOG2_T_MAX>);

        let mut params = Fflonk::<Scheme, LOG2_T_MAX>::gen_params(K);

        let pk = keygen::<Scalar, Fflonk<Scheme, LOG2_T_MAX>>(&mut params, None);

        let proof = create_proof::<Scalar, Fflonk<Scheme, LOG2_T_MAX>, CircuitTranscript<State>, _>(
            OsRng, &params, &pk,
        );

        verify_proof::<_, _, CircuitTranscript<State>>(
            &params.verifier_params(),
            pk.get_vk(),
            &proof[..],
        );

        #[cfg(feature = "disk-spill")]
        {
            use midnight_proofs::{config::ProverConfig, utils::SerdeFormat};

            let serialized = pk.to_bytes(SerdeFormat::Processed);
            let mapped_pk = ProvingKey::<Scalar, Fflonk<Scheme, LOG2_T_MAX>>::read_with_policy::<
                _,
                MyCircuit<Scalar>,
            >(
                &mut &serialized[..],
                SerdeFormat::Processed,
                #[cfg(feature = "circuit-params")]
                (),
                &ProverConfig::mapped_key(),
            )
            .expect("FFLONK mapped key should load");
            assert_eq!(mapped_pk.to_bytes(SerdeFormat::Processed), serialized);
            let mapped_proof =
                create_proof::<Scalar, Fflonk<Scheme, LOG2_T_MAX>, CircuitTranscript<State>, _>(
                    OsRng, &params, &mapped_pk,
                );
            verify_proof::<_, _, CircuitTranscript<State>>(
                &params.verifier_params(),
                mapped_pk.get_vk(),
                &mapped_proof,
            );
        }
    }
    fflonk_roundtrip::<1>();
    fflonk_roundtrip::<2>();
}
