// This file is part of midnight-zk.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: MIT OR Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Per-proof extended-coset storage. The default preserves heap behavior;
//! native callers can explicitly request bounded, mapped spill storage.

use std::{io, path::PathBuf};

#[cfg(all(feature = "disk-spill", not(target_family = "wasm")))]
use super::mmap_pk::{spill_with_transform, MmappedPolys};
use crate::poly::{
    polynomial_views, Coeff, ExtendedLagrangeCoeff, Polynomial, PolynomialRead, PolynomialView,
};

/// How one proof stores its extended-domain cosets.
///
/// Spilling is opt-in and must be supported by the native `disk-spill` feature.
/// A failed spill returns an error rather than silently using unbounded heap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CosetStoragePolicy {
    /// Retain the released heap construction path.
    #[default]
    Heap,
    /// Spill each batch at or above `min_k` into an anonymous mapped file.
    Spill {
        /// Minimum circuit size for the spill; smaller proofs use the heap.
        min_k: u32,
        /// Optional spill volume; `None` uses the OS temporary directory.
        dir: Option<PathBuf>,
    },
}

impl CosetStoragePolicy {
    pub(crate) fn should_spill_at(&self, k: u32) -> bool {
        matches!(self, Self::Spill { min_k, .. } if k >= *min_k)
    }

    pub(crate) fn ensure_supported(&self) -> io::Result<()> {
        if matches!(self, Self::Spill { .. })
            && !cfg!(all(feature = "disk-spill", not(target_family = "wasm")))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "coset spilling requires native disk-spill support",
            ));
        }
        Ok(())
    }

    #[cfg(all(feature = "disk-spill", not(target_family = "wasm")))]
    fn spill_dir_at(&self, k: u32) -> Option<Option<&std::path::Path>> {
        match self {
            Self::Spill { min_k, dir } if k >= *min_k => Some(dir.as_deref()),
            _ => None,
        }
    }
}

/// Holds the backing until evaluation finishes and borrows it as typed views.
pub(crate) enum Cosets<F> {
    Heap(Vec<Polynomial<F, ExtendedLagrangeCoeff>>),
    #[cfg(all(feature = "disk-spill", not(target_family = "wasm")))]
    Spilled(MmappedPolys<F, ExtendedLagrangeCoeff>),
}

impl<F> Cosets<F> {
    pub(crate) fn views(&self) -> Vec<PolynomialView<'_, F, ExtendedLagrangeCoeff>> {
        match self {
            Self::Heap(polys) => polynomial_views(polys),
            #[cfg(all(feature = "disk-spill", not(target_family = "wasm")))]
            Self::Spilled(polys) => polys.views(),
        }
    }
}

pub(crate) fn build_cosets<F, P, T>(
    polys: &[P],
    k: u32,
    policy: &CosetStoragePolicy,
    to_extended: T,
) -> io::Result<Cosets<F>>
where
    F: Copy,
    P: PolynomialRead<F, Basis = Coeff>,
    T: for<'a> Fn(PolynomialView<'a, F, Coeff>) -> Polynomial<F, ExtendedLagrangeCoeff>,
{
    #[cfg(all(feature = "disk-spill", not(target_family = "wasm")))]
    if let Some(dir) = policy.spill_dir_at(k) {
        if !polys.is_empty() {
            return spill_with_transform(dir, polys, to_extended).map(Cosets::Spilled);
        }
    }
    #[cfg(not(all(feature = "disk-spill", not(target_family = "wasm"))))]
    let _ = (k, policy);

    Ok(Cosets::Heap(
        polys
            .iter()
            .map(|poly| to_extended(PolynomialView::new(poly.values())))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(all(feature = "disk-spill", not(target_family = "wasm"))))]
    fn unsupported_spill_policy_is_rejected() {
        let policy = CosetStoragePolicy::Spill {
            min_k: 0,
            dir: None,
        };
        assert_eq!(
            policy.ensure_supported().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    #[cfg(all(feature = "disk-spill", not(target_family = "wasm")))]
    fn spill_and_heap_values_agree_and_failure_is_explicit() {
        use midnight_curves::Fq;

        let source: Vec<Polynomial<Fq, Coeff>> = (0..3)
            .map(|i| Polynomial {
                values: (0..8).map(|j| Fq::from((i * 8 + j) as u64)).collect(),
                _marker: std::marker::PhantomData,
            })
            .collect();
        let transform = |view: PolynomialView<'_, Fq, Coeff>| {
            let Polynomial { values, .. } = view.materialise();
            Polynomial::<Fq, ExtendedLagrangeCoeff> {
                values,
                _marker: std::marker::PhantomData,
            }
        };

        let heap = build_cosets(&source, 5, &CosetStoragePolicy::Heap, transform).unwrap();
        let spilled = build_cosets(
            &source,
            5,
            &CosetStoragePolicy::Spill {
                min_k: 0,
                dir: None,
            },
            transform,
        )
        .unwrap();
        for (a, b) in heap.views().iter().zip(spilled.views()) {
            assert_eq!(&a[..], &b[..]);
        }

        let missing = tempfile::tempdir().unwrap().path().join("missing");
        let below_floor = build_cosets(
            &source,
            5,
            &CosetStoragePolicy::Spill {
                min_k: 6,
                dir: Some(missing.clone()),
            },
            transform,
        )
        .unwrap();
        assert!(matches!(below_floor, Cosets::Heap(_)));
        let error = build_cosets(
            &source,
            5,
            &CosetStoragePolicy::Spill {
                min_k: 0,
                dir: Some(missing),
            },
            transform,
        );
        assert!(error.is_err());
    }
}
