// This file is part of MIDNIGHT-ZK.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

//! Prove through the released stdlib 2.4 interface without a downloaded SRS.

use midnight_curves::{Bls12, Fq};
use midnight_proofs::{
    circuit::{Layouter, Value},
    config::{CancelToken, ProverConfig, ProverContext, DISK_SPILL_AVAILABLE},
    plonk::Error,
    poly::kzg::params::ParamsKZG,
};
use midnight_zk_stdlib::{Relation, ZkStdLib};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn mapped_key_load_requires_disk_spill_capability() {
    if DISK_SPILL_AVAILABLE {
        return;
    }
    use std::io::ErrorKind;

    use midnight_proofs::utils::SerdeFormat;
    use midnight_zk_stdlib::MidnightPK;

    let error = MidnightPK::<EmptyRelation>::read_with_policy(
        &mut [10u8].as_slice(),
        SerdeFormat::RawBytes,
        &ProverConfig::mapped_key(),
    )
    .expect_err("mapped key policy must not silently load on the heap");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[cfg(feature = "disk-spill")]
#[test]
fn mapped_key_round_trip_proves_with_context() {
    use midnight_proofs::utils::SerdeFormat;
    use midnight_zk_stdlib::MidnightPK;

    let params = ParamsKZG::<Bls12>::unsafe_setup(10, StdRng::seed_from_u64(5));
    let relation = EmptyRelation;
    let vk = midnight_zk_stdlib::setup_vk(&params, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);
    let mut bytes = Vec::new();
    pk.write(&mut bytes, SerdeFormat::RawBytesUnchecked)
        .expect("serialize generated key");

    let policy = ProverConfig::mapped_key();
    let heap = MidnightPK::<EmptyRelation>::read_with_policy(
        &mut bytes.as_slice(),
        SerdeFormat::RawBytesUnchecked,
        &ProverConfig::heap(),
    )
    .expect("load heap key");
    let error = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
        &ProverContext::new(policy.clone()),
        &params,
        &heap,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(9),
    )
    .expect_err("mapped request must reject a heap-loaded key");
    assert!(matches!(error, Error::Synthesis(message) if message.contains("storage policy")));

    let mapped = MidnightPK::<EmptyRelation>::read_with_policy(
        &mut bytes.as_slice(),
        SerdeFormat::RawBytesUnchecked,
        &policy,
    )
    .expect("load key under mapped policy");
    let proof = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
        &ProverContext::new(policy),
        &params,
        &mapped,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(6),
    )
    .expect("mapped key should prove");
    midnight_zk_stdlib::verify::<EmptyRelation, blake2b_simd::State>(
        &params.verifier_params(),
        &vk,
        &(),
        None,
        &proof,
    )
    .expect("mapped-key proof should verify");
}

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

    if !DISK_SPILL_AVAILABLE {
        let error = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
            &ProverContext::new(ProverConfig::mapped_key()),
            &params,
            &pk,
            &relation,
            &(),
            (),
            StdRng::seed_from_u64(8),
        )
        .expect_err("requested mapped key must not silently use heap storage");
        assert!(matches!(error, Error::Synthesis(message) if message.contains("storage policy")));

        let policy = ProverConfig {
            spill_cosets: true,
            coset_spill_floor_k: 0,
            ..ProverConfig::heap()
        };
        let error = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State>(
            &ProverContext::new(policy),
            &params,
            &pk,
            &relation,
            &(),
            (),
            StdRng::seed_from_u64(7),
        )
        .expect_err("requested coset spill must not silently use heap storage");
        assert!(matches!(error, Error::Synthesis(message) if message.contains("disk-spill")));
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
    assert!(matches!(error, Error::Cancelled { .. }));

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
