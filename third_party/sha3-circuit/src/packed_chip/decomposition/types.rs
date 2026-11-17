//! Types for decomposing bits in dense and spread forms

use ff::PrimeField;

use super::rotation::{lane_limbs, limb_sizes};
use crate::{
    constants::KECCAK_LANE_SIZE,
    packed_chip::{
        utils::{AssignedSpreadBits, Bits, DenseBits, SpreadBits},
        NUM_FULL_LIMBS,
    },
};

/// struct representing a dense-decomposed lane
#[derive(Clone, Debug)]
struct DecomposedDense {
    _rot: usize,
    result: DenseBits,
    full_limbs: [DenseBits; NUM_FULL_LIMBS],
    // lo stands for leftover
    lo_limb: DenseBits,
    small_limb_1: DenseBits,
    small_limb_2: DenseBits,
}

impl DecomposedDense {
    /// Represents a lane (u64) as a [`DecomposedDense`] word
    /// in a way that it can be easily (right) rotated by rot
    fn new(v: u64, rot: usize) -> Self {
        // get the limb sizes based on the rotation and rotate them so full limbs
        // appear first
        let (mut limb_sizes, q) = limb_sizes(rot);
        limb_sizes.rotate_right(q);
        let limbs = lane_limbs(v, rot)
            .iter()
            .zip(limb_sizes)
            .map(|(&limb, limb_size)| Bits::try_from_u64(limb, limb_size).unwrap())
            .map(DenseBits::from)
            .collect::<Vec<_>>();

        // never panics since upper_bound is always 64
        let result: DenseBits = Bits::try_from_u64(v, KECCAK_LANE_SIZE).unwrap().into();
        let full_limbs = limbs[0..NUM_FULL_LIMBS].to_owned();
        let lo_limb = limbs[NUM_FULL_LIMBS].to_owned();
        let small_limb_1 = limbs[NUM_FULL_LIMBS + 1].to_owned();
        let small_limb_2 = limbs[NUM_FULL_LIMBS + 2].to_owned();

        DecomposedDense {
            _rot: rot,
            full_limbs: full_limbs.try_into().unwrap(),
            lo_limb,
            small_limb_1,
            small_limb_2,
            result,
        }
    }
}

/// struct representing a spread-decomposed lane.
///
/// This is the counterpart of [`DecomposedDense`] for spread bits
#[derive(Clone, Debug)]
pub(super) struct DecomposedSpread {
    _rot: usize,
    pub(super) result: SpreadBits,
    pub(super) full_limbs: [SpreadBits; NUM_FULL_LIMBS],
    // lo stands for leftover
    pub(super) lo_limb: SpreadBits,
    pub(super) small_limb_1: SpreadBits,
    pub(super) small_limb_2: SpreadBits,
}

impl DecomposedSpread {
    /// Represents a lane (u64) as a [`DecomposedSpread`] word
    /// in a way that it can be easily (right) rotated by rot
    pub(super) fn new(v: u64, rot: usize) -> Self {
        // get the dense form
        let dense = DecomposedDense::new(v, rot);

        // convert its parts to spread bits
        DecomposedSpread {
            _rot: rot,
            full_limbs: dense.full_limbs.map(|l| l.spread()),
            lo_limb: dense.lo_limb.spread(),
            small_limb_1: dense.small_limb_1.spread(),
            small_limb_2: dense.small_limb_2.spread(),
            result: dense.result.spread(),
        }
    }
}

/// struct representing the spreaded version of [[AssignedDecomposedDense]].
#[derive(Clone, Debug)]
pub(crate) struct AssignedDecomposedSpread<F: PrimeField> {
    pub(crate) _rot: usize,
    pub(crate) assigned_result: AssignedSpreadBits<F>,
    pub(crate) _assigned_full_limbs: [AssignedSpreadBits<F>; NUM_FULL_LIMBS],
    pub(crate) _assigned_lo_limb: AssignedSpreadBits<F>,
    pub(crate) _assigned_small_limb_1: AssignedSpreadBits<F>,
    pub(crate) _assigned_small_limb_2: AssignedSpreadBits<F>,
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use midnight_curves::Fq as Fp;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::{DecomposedDense, KECCAK_LANE_SIZE};
    use crate::packed_chip::decomposition::{
        rotation::{get_dense_limb_coefficients, get_spread_limb_coefficients},
        types::DecomposedSpread,
    };

    #[test]
    fn test_decomposed_from_lane() {
        let mut rng = ChaCha8Rng::from_entropy();

        let number_of_tests = 100;

        (0..number_of_tests).for_each(|_| {
            // sample a random u64 lane
            let v = rng.next_u64();
            // test for all possible rotations
            for rot in 0..KECCAK_LANE_SIZE {
                let dense = DecomposedDense::new(v, rot);
                let spread = DecomposedSpread::new(v, rot);

                // assert the result equals the initial value for the dense
                let result_dense: Fp = dense.result.to_field();
                let expected_dense: Fp = v.into();
                assert_eq!(result_dense, expected_dense);

                // assert the spreaded result equals the spreaded initial value
                let result_spread: Fp = spread.result.to_field();
                let expected_spread: Fp = dense.result.spread().to_field();
                assert_eq!(result_spread, expected_spread);

                // recompose the limbs and reconstruct the field element
                let mut dense_limbs = dense.full_limbs.to_vec();
                dense_limbs.push(dense.lo_limb);
                dense_limbs.push(dense.small_limb_1);
                dense_limbs.push(dense.small_limb_2);
                let result_dense = dense_limbs
                    .iter()
                    .map(|limb| limb.to_field::<Fp>())
                    .zip(get_dense_limb_coefficients::<Fp>(rot, false).iter())
                    .fold(Fp::ZERO, |acc, (l, c)| acc + l * c);
                assert_eq!(result_dense, expected_dense);

                // same for the spread limbs
                let mut spread_limbs = spread.full_limbs.to_vec();
                spread_limbs.push(spread.lo_limb);
                spread_limbs.push(spread.small_limb_1);
                spread_limbs.push(spread.small_limb_2);
                let result_spread = spread_limbs
                    .iter()
                    .map(|limb| limb.to_field::<Fp>())
                    .zip(get_spread_limb_coefficients::<Fp>(rot, false).iter())
                    .fold(Fp::ZERO, |acc, (l, c)| acc + l * c);
                assert_eq!(result_spread, expected_spread);
            }
        });
    }
}
