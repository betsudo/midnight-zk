// This file is part of MIDNIGHT-ZK.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

//! Prove through the released stdlib 2.4 interface without a downloaded SRS.

use midnight_curves::{Bls12, Fq};
use midnight_proofs::{
    circuit::{Layouter, Value},
    config::{CancelToken, ProverConfig, ProverContext},
    plonk::{Error, ProveWithPolicyError},
    poly::kzg::params::ParamsKZG,
    utils::SerdeFormat,
};
use midnight_zk_stdlib::{ProveWithContextError, Relation, ZkStdLib};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone, Debug)]
struct EmptyRelation;

impl Relation for EmptyRelation {
    type Instance = ();
    type Witness = ();
    type Error = Error;

    fn format_instance(_: &()) -> Result<Vec<Fq>, Error> {
        Ok(Vec::new())
    }

    fn circuit(
        &self,
        _: &ZkStdLib,
        _: &mut impl Layouter<Fq>,
        _: Value<()>,
        _: Value<()>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn write_relation<W: std::io::Write>(&self, _: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_: &mut R) -> std::io::Result<Self> {
        Ok(Self)
    }
}

#[test]
fn released_stdlib_context_and_compatibility_proofs_verify() {
    let params = ParamsKZG::<Bls12>::unsafe_setup(10, StdRng::seed_from_u64(1));
    let relation = EmptyRelation;
    let vk = midnight_zk_stdlib::setup_vk(&params, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize proving key");
    let mut policy = ProverConfig::mapped_key_and_cosets();
    policy.coset_spill_floor_k = 0;
    #[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
    let loaded = midnight_zk_stdlib::MidnightPK::<EmptyRelation>::read_with_policy(
        &mut &pk_bytes[..],
        SerdeFormat::RawBytesUnchecked,
        &policy,
    )
    .expect("read proving key under explicit policy");
    #[cfg(not(all(feature = "native-memory", not(target_family = "wasm"))))]
    {
        let mut input = &pk_bytes[..];
        let original_len = input.len();
        let error = midnight_zk_stdlib::MidnightPK::<EmptyRelation>::read_with_policy(
            &mut input,
            SerdeFormat::RawBytesUnchecked,
            &policy,
        )
        .expect_err("unsupported mapped-key request must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(input.len(), original_len);
    }

    let token = CancelToken::new();
    token.cancel();
    let cancelled = ProverContext::new(ProverConfig::heap()).with_cancel(token);
    let error = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
        &cancelled,
        &params,
        &pk,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(2),
    )
    .expect_err("cancelled context should stop proving");
    assert!(matches!(
        error,
        ProveWithContextError::Prover(ProveWithPolicyError::Cancelled { .. })
    ));

    let live = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
        &ProverContext::new(ProverConfig::heap()),
        &params,
        &pk,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(3),
    )
    .expect("live context should prove");
    midnight_zk_stdlib::verify::<EmptyRelation, blake2b_simd::State>(
        &params.verifier_params(),
        &vk,
        &(),
        None,
        &live,
    )
    .expect("context proof should verify");

    #[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
    let reloaded = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
        &ProverContext::new(policy.clone()),
        &params,
        &loaded,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(5),
    )
    .expect("explicit-policy key should prove");
    #[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
    midnight_zk_stdlib::verify::<EmptyRelation, blake2b_simd::State>(
        &params.verifier_params(),
        &vk,
        &(),
        None,
        &reloaded,
    )
    .expect("explicit-policy key proof should verify");

    #[cfg(all(feature = "native-memory", not(target_family = "wasm")))]
    {
        let mut bad_policy = policy;
        bad_policy.spill_dir = Some(tempfile::tempdir().unwrap().path().join("missing-spill"));
        let error = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
            &ProverContext::new(bad_policy),
            &params,
            &loaded,
            &relation,
            &(),
            (),
            StdRng::seed_from_u64(6),
        )
        .expect_err("requested spill must fail explicitly");
        assert!(matches!(
            error,
            ProveWithContextError::Prover(ProveWithPolicyError::Storage(_))
        ));
    }

    let compatible = midnight_zk_stdlib::prove::<EmptyRelation, blake2b_simd::State>(
        &params,
        &pk,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(4),
    )
    .expect("original entry point should prove");
    midnight_zk_stdlib::verify::<EmptyRelation, blake2b_simd::State>(
        &params.verifier_params(),
        &vk,
        &(),
        None,
        &compatible,
    )
    .expect("compatibility proof should verify");
}
