// This file is part of midnight-zk.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: MIT OR Apache-2.0

use midnight_curves::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// The hash was generated from the published midnight-proofs 0.8.2 source
/// recorded by the crate (`f5e6e16d`), with the same seed and k. It guards
/// against a format change hidden by a new reader/writer round trip.
#[test]
fn published_082_srs_processed_encoding_is_stable() {
    let params = ParamsKZG::<Bls12>::unsafe_setup(4, ChaCha20Rng::from_seed([7; 32]));
    let mut bytes = Vec::new();
    params
        .write_custom(&mut bytes, SerdeFormat::Processed)
        .expect("serialize the seeded SRS");

    assert_eq!(bytes.len(), 1732);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "580745c91e98e293c08c1dd52a5359ebaa3dbdde3ebfa2f3217ab3712dfc479b"
    );

    let decoded = ParamsKZG::<Bls12>::read_custom(&mut bytes.as_slice(), SerdeFormat::Processed)
        .expect("published encoding decodes");
    let mut roundtrip = Vec::new();
    decoded
        .write_custom(&mut roundtrip, SerdeFormat::Processed)
        .expect("re-serialize the decoded SRS");
    assert_eq!(roundtrip, bytes);
}
