// This file is part of MIDNIGHT-ZK.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

//! Prove through the released stdlib 2.4 interface without a downloaded SRS.

use midnight_curves::{Bls12, Fq};
use midnight_proofs::{
    circuit::{Layouter, Value},
    config::{CancelToken, ProverConfig, ProverContext},
    plonk::Error,
    poly::kzg::params::ParamsKZG,
};
use midnight_zk_stdlib::{Relation, ZkStdLib};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone)]
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
