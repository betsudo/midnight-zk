use std::collections::BTreeMap;

use ff::{PrimeField, WithSmallOrderMulGroup};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

#[cfg(feature = "disk-spill")]
use crate::plonk::mmap_pk::{MmappedPolys, spill_iter_to_disk};
use crate::{
    plonk::{
        AbsorbedVk, ConstraintSystem, Error,
        argument::{self, Evaluation},
    },
    poly::{
        Coeff, EvaluationDomain, Polynomial, PolynomialLabel, PolynomialRepresentation,
        PolynomialView, ProverQuery, Rotation, commitment::PolynomialCommitmentScheme,
        polynomial_views,
    },
    transcript::{Hashable, Transcript},
    utils::arithmetic::eval_polynomial,
};

#[derive(Debug)]
enum CommittedPolys<F, B> {
    Owned(Vec<Polynomial<F, B>>),
    #[cfg(feature = "disk-spill")]
    Mapped(MmappedPolys<F, B>),
}

impl<F, B> CommittedPolys<F, B> {
    fn views(&self) -> Vec<PolynomialView<'_, F, B>> {
        match self {
            Self::Owned(polys) => polynomial_views(polys),
            #[cfg(feature = "disk-spill")]
            Self::Mapped(polys) => polys.views(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Committed<F: PrimeField, B: PolynomialRepresentation> {
    labels: Vec<PolynomialLabel>,
    polys: CommittedPolys<F, B>,
}

impl<F: PrimeField, B: PolynomialRepresentation> Committed<F, B> {
    fn from_map(polys_map: BTreeMap<PolynomialLabel, Polynomial<F, B>>) -> Self {
        let (labels, polys) = polys_map.into_iter().unzip();
        Committed {
            labels,
            polys: CommittedPolys::Owned(polys),
        }
    }

    /// The polynomial the group holds under `label`, if any.
    pub(crate) fn poly(&self, label: &PolynomialLabel) -> Option<&Polynomial<F, B>> {
        self.labels.binary_search(label).ok().map(|i| match &self.polys {
            CommittedPolys::Owned(polys) => &polys[i],
            #[cfg(feature = "disk-spill")]
            CommittedPolys::Mapped(_) => unreachable!("only phase-0 key polynomials may be mapped"),
        })
    }

    /// The polynomials the group holds under `labels`, as a slice in the same
    /// order.
    ///
    /// # Panics
    ///
    /// Panics if `labels` is not a run of consecutive labels of the group, in
    /// their `Ord` order.
    pub(crate) fn polys_of(&self, labels: &[PolynomialLabel]) -> &[Polynomial<F, B>] {
        let start = match labels.first() {
            Some(first) => self.labels.binary_search(first).unwrap_or(self.labels.len()),
            None => 0,
        };
        let end = start + labels.len();
        assert!(
            end <= self.labels.len() && self.labels[start..end] == *labels,
            "the labels are not a run of consecutive labels of the group"
        );
        match &self.polys {
            CommittedPolys::Owned(polys) => &polys[start..end],
            #[cfg(feature = "disk-spill")]
            CommittedPolys::Mapped(_) => unreachable!("use KeyGroup::views_of for mapped keys"),
        }
    }
}

impl<F: WithSmallOrderMulGroup<3>, B: PolynomialRepresentation> Committed<F, B> {
    pub fn into_coeff(self, domain: &EvaluationDomain<F>) -> Committed<F, Coeff> {
        Committed {
            labels: self.labels,
            polys: CommittedPolys::Owned(match self.polys {
                CommittedPolys::Owned(polys) => {
                    polys.into_par_iter().map(|p| B::self_to_coeff(domain, p)).collect()
                }
                #[cfg(feature = "disk-spill")]
                CommittedPolys::Mapped(_) => unreachable!("only coefficient keys may be mapped"),
            }),
        }
    }
}

impl<F: PrimeField, B: PolynomialRepresentation> Committed<F, B> {
    /// Commits to the polynomials of `polys_map` in the representation given by
    /// `encode`. The group keeps them as given.
    pub fn commit<CS, T, E>(
        params: &CS::Parameters,
        polys_map: BTreeMap<PolynomialLabel, Polynomial<F, B>>,
        encode: impl Fn(&Polynomial<F, B>) -> Polynomial<F, E> + Send + Sync,
        transcript: &mut T,
    ) -> Result<Self, Error>
    where
        CS: PolynomialCommitmentScheme<F>,
        CS::Commitment: Hashable<T::Hash>,
        T: Transcript,
        E: PolynomialRepresentation,
    {
        let group = Self::from_map(polys_map);
        let encoded: Vec<_> = match &group.polys {
            CommittedPolys::Owned(polys) => polys.par_iter().map(encode).collect(),
            #[cfg(feature = "disk-spill")]
            CommittedPolys::Mapped(_) => unreachable!("fresh commitments are owned"),
        };
        let commitment =
            CS::commit_many(params, &encoded.iter().collect::<Vec<_>>(), &group.labels);

        CS::write_commitment(transcript, &commitment)?;

        Ok(group)
    }
}

/// A group whose polynomials are committed to in the verifying key rather than
/// in the proof. It takes part in a proof, as a [`Committed`], only once that
/// verifying key has been absorbed into the transcript; see
/// [`Self::committed`].
#[derive(Debug)]
pub(crate) struct KeyGroup<F: PrimeField> {
    committed: Committed<F, Coeff>,
    /// The `transcript_repr` of the verifying key holding the group's
    /// commitment.
    vk_repr: F,
}

impl<F: PrimeField> KeyGroup<F> {
    /// Borrow a consecutive run without requiring allocator-owned storage.
    pub(crate) fn views_of(&self, labels: &[PolynomialLabel]) -> Vec<PolynomialView<'_, F, Coeff>> {
        let start = match labels.first() {
            Some(first) => self
                .committed
                .labels
                .binary_search(first)
                .unwrap_or(self.committed.labels.len()),
            None => 0,
        };
        let end = start + labels.len();
        assert!(end <= self.committed.labels.len() && self.committed.labels[start..end] == *labels);
        self.committed.polys.views()[start..end].to_vec()
    }

    #[cfg(feature = "disk-spill")]
    pub(crate) fn map_to_disk(self, spill_dir: Option<&std::path::Path>) -> std::io::Result<Self> {
        let Committed { labels, polys } = self.committed;
        let owned = match polys {
            CommittedPolys::Owned(polys) => polys,
            CommittedPolys::Mapped(polys) => {
                return Ok(Self {
                    committed: Committed {
                        labels,
                        polys: CommittedPolys::Mapped(polys),
                    },
                    vk_repr: self.vk_repr,
                });
            }
        };
        if owned.is_empty() {
            return Ok(Self {
                committed: Committed {
                    labels,
                    polys: CommittedPolys::Owned(owned),
                },
                vk_repr: self.vk_repr,
            });
        }
        let count = owned.len();
        let len = owned.first().map_or(0, |poly| poly.len());
        let mapped = spill_iter_to_disk(spill_dir, owned, count, len)?;
        Ok(Self {
            committed: Committed {
                labels,
                polys: CommittedPolys::Mapped(mapped),
            },
            vk_repr: self.vk_repr,
        })
    }

    #[cfg(feature = "disk-spill")]
    pub(crate) fn from_mapped(
        labels: Vec<PolynomialLabel>,
        polys: MmappedPolys<F, Coeff>,
        vk_repr: F,
    ) -> Self {
        assert!(labels.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(labels.len(), polys.len());
        Self {
            committed: Committed {
                labels,
                polys: CommittedPolys::Mapped(polys),
            },
            vk_repr,
        }
    }

    /// The group of `polys_map`, whose commitment is held by the verifying key
    /// of `transcript_repr` `vk_repr`.
    pub(crate) fn new(
        polys_map: BTreeMap<PolynomialLabel, Polynomial<F, Coeff>>,
        vk_repr: F,
    ) -> Self {
        KeyGroup {
            committed: Committed::from_map(polys_map),
            vk_repr,
        }
    }

    /// The group as a [`Committed`], given the witness that the verifying key
    /// holding its commitment has been absorbed.
    ///
    /// # Panics
    ///
    /// Panics if `vk` is the witness of a different verifying key.
    pub(crate) fn committed<CS: PolynomialCommitmentScheme<F>>(
        &self,
        vk: &AbsorbedVk<'_, F, CS>,
    ) -> &Committed<F, Coeff> {
        assert!(
            vk.transcript_repr() == self.vk_repr,
            "the absorbed verifying key does not hold the commitment to this group"
        );
        &self.committed
    }
}

pub(crate) struct Evaluated<'a, F: PrimeField> {
    committed: &'a Committed<F, Coeff>,
    pub(crate) evals_map: BTreeMap<PolynomialLabel, Vec<Evaluation<F>>>,
}

impl<F: PrimeField> Committed<F, Coeff> {
    /// Evaluates every polynomial of the group at each of its evaluation
    /// points and writes the evaluations to the proof, in the labels' `Ord`
    /// order.
    ///
    /// Borrows the group rather than consuming it.
    pub(crate) fn evaluate<T>(
        &self,
        cs: &ConstraintSystem<F>,
        x_rotations: &BTreeMap<Rotation, F>,
        transcript: &mut T,
    ) -> Result<Evaluated<'_, F>, Error>
    where
        F: Hashable<T::Hash> + WithSmallOrderMulGroup<3>,
        T: Transcript,
    {
        let evaluate = |poly: PolynomialView<'_, F, Coeff>, x: F| -> Evaluation<F> {
            Evaluation {
                point: x,
                eval: eval_polynomial(&poly, x),
            }
        };

        let evals_map: BTreeMap<PolynomialLabel, Vec<Evaluation<F>>> = self
            .labels
            .iter()
            .zip(self.polys.views())
            .map(|(label, poly)| {
                let eval_points = argument::eval_points(cs, label, x_rotations);
                (
                    label.clone(),
                    eval_points.into_iter().map(|point| evaluate(poly, point)).collect(),
                )
            })
            .collect();

        for evals in evals_map.values() {
            for evaluation in evals.iter() {
                transcript.write(&evaluation.eval)?;
            }
        }

        Ok(Evaluated {
            committed: self,
            evals_map,
        })
    }
}

impl<F: PrimeField> Evaluated<'_, F> {
    /// Adds the evaluation `eval` at `point` of the group's polynomial `label`,
    /// one the verifier derives rather than reads from the proof.
    pub(crate) fn insert(&mut self, label: PolynomialLabel, point: F, eval: F) {
        self.evals_map.insert(label, vec![Evaluation { point, eval }]);
    }

    pub(crate) fn open(&self) -> impl Iterator<Item = ProverQuery<'_, F>> + Clone {
        self.evals_map.iter().flat_map(|(label, evaluations)| {
            evaluations.iter().map(|evaluation| {
                ProverQuery::new_views(
                    &self.committed.labels,
                    self.committed.polys.views(),
                    evaluation.point,
                    label.clone(),
                )
            })
        })
    }
}
