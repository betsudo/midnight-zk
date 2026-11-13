// This file is part of MIDNIGHT-ZK.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

//! Exercise the stdlib's explicit context boundary without a downloaded SRS.

use midnight_curves::{Bls12, Fq};
use midnight_proofs::{
    circuit::{Layouter, Value},
    config::{CancelToken, ProverConfig, ProverContext},
    plonk::Error,
    poly::kzg::params::ParamsKZG,
};
use midnight_zk_stdlib::{KZG, Relation, ZkStdLib};
use rand::{SeedableRng, rngs::StdRng};

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
fn cancelled_context_stops_only_its_proof_and_live_context_verifies() {
    let params = ParamsKZG::<Bls12>::unsafe_setup(10, StdRng::seed_from_u64(1));
    let relation = EmptyRelation;
    let vk = midnight_zk_stdlib::setup_vk::<_, KZG>(&params, &relation);
    let pk = midnight_zk_stdlib::setup_pk(&relation, &vk);

    let token = CancelToken::new();
    token.cancel();
    let cancelled = ProverContext::new(ProverConfig::heap()).with_cancel(token);
    let error = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State, KZG>(
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
        Error::Cancelled {
            phase: "trace.start"
        }
    ));

    let proof = midnight_zk_stdlib::prove_with_context::<EmptyRelation, blake2b_simd::State, KZG>(
        &ProverContext::new(ProverConfig::heap()),
        &params,
        &pk,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(3),
    )
    .expect("a separate context should still prove");
    midnight_zk_stdlib::verify::<EmptyRelation, blake2b_simd::State, KZG>(
        &params.verifier_params(),
        &vk,
        &(),
        None,
        &proof,
    )
    .expect("proof from live context should verify");

    let legacy = midnight_zk_stdlib::prove::<EmptyRelation, blake2b_simd::State, KZG>(
        &params,
        &pk,
        &relation,
        &(),
        (),
        StdRng::seed_from_u64(4),
    )
    .expect("the compatibility entry point should still prove");
    midnight_zk_stdlib::verify::<EmptyRelation, blake2b_simd::State, KZG>(
        &params.verifier_params(),
        &vk,
        &(),
        None,
        &legacy,
    )
    .expect("proof from compatibility entry point should verify");
}
