//! Computes the chi step in circuit.
//!
//! The chi step consists of computing the new state by
//! changing A[i][j] --> A[i][j] xor (not A[i+1][j] and A[i+2][j]).
//!
//! In spread forms, this corresponds to the *middle bit* of the computation
//!
//! changing A[i][j] --> 2 * A[i][j] + (spread(1..1) - A[i+1][j] + A[i+2][j]).
//! - spread(1..1) - A[i+1][j] --> to negation
//! - spread(1..1) - A[i+1][j] + A[i+2][j] --> add to get the AND on middle bits
//! - 2 * A[i][j] --> shift the value by one position to align with the AND
//!   result
//! - 2 * A[i][j] + (spread(1..1) - A[i+1][j] + A[i+2][j]) --> final result on
//!   middle bits
//!
//! If this is the last round, we optionally absorb messages for the next
//! permutation. Each permutation abosrbs 17 lanes by computing A[i][j] =
//! A[i][j] + M[i + 5*j]. The corresponding spread operation becomes
//!
//! A[i][j] --> 2 * (A[i][j] xor M[i + 5*j] + (spread(1..1) - A[i+1][j] +
//! A[i+2][j]).

use ff::PrimeField;
use midnight_proofs::{
    circuit::{Chip, Region},
    plonk::Error,
};

use super::{types::AssignedKeccakState, COMPUTE_CHI_OFFSET_START};
use crate::{
    constants::{KECCAK_ABSORB_LANES, KECCAK_NUM_LANES, KECCAK_NUM_ROUNDS, KECCAK_WIDTH},
    packed_chip::{
        bootstrap::assign_bootstrap::BPart,
        keccakf_operations::ROWS_PER_ROUND,
        utils::{AssignedSpreadBits, SpreadBits},
        PackedChip,
    },
};

impl<F: PrimeField> PackedChip<F> {
    /// Given as input a keccak state, it computes the state after applying the
    /// chi step.
    ///
    /// Concretely, it computes
    ///
    /// a[i][j] = a[i][j] xor (not a[i+1][j] and a[i+2][j])
    ///
    /// If there is a message to absorb *for the next block*, it also absorbs
    /// it by xoring it. The absorbed message consists of 17 lanes (1088) bits
    /// and the lane m_k is xored with a[k/5][k%5], i.e. we have the mapping:
    ///
    /// k     -> (k/5, k%5)
    /// (i,j) -> i + 5j
    ///
    ///
    /// Assigns the following values:
    ///
    /// | offset | dc_res  |  adv0   |  adv1    |  acc    |   limbs   |
    /// |--------|---------|---------|----------|---------|-----------|
    /// |   96   |  a0,0h  |   X     |    X     | acc0    |    ...    |
    /// |   97   |  a0,0m  |  a0,0   |   M/0    | acc1    |    ...    |
    /// |   98   |  a0,0l  |  a1,0   |  a2,0    | a0,0err |    ...    |
    /// |   99   |  a0,1h  |   X     |    X     | acc0    |    ...    |
    /// |  100   |  a0,1m  |  a0,1   |   M/0    | acc1    |    ...    |
    /// |  101   |  a0,1l  |  a1,1   |  a2,1    | a0,1err |    ...    |
    /// |        |   .     |    .    |    .     |  .      |     .     |
    /// |        |   .     |    .    |    .     |  .      |     .     |
    /// |        |   .     |    .    |    .     |  .      |     .     |
    /// |  168   |  a4,4h  |   X     |    X     | acc0    |    ...    |
    /// |  169   |  a4,4m  |  a4,4   |    0     | acc1    |    ...    |
    /// |  170   |  a4,4l  |  a0,4   |  a1,4    | a4,4err |    ...    |
    /// |--------|---------|---------|----------|---------|-----------|
    pub(super) fn compute_chi(
        &self,
        region: &mut Region<'_, F>,
        round: usize,
        assigned_state: &AssignedKeccakState<F>,
        ms: Option<&[AssignedSpreadBits<F>; KECCAK_ABSORB_LANES]>,
    ) -> Result<AssignedKeccakState<F>, Error> {
        // compute the region offset
        let chi_offset = round * ROWS_PER_ROUND + COMPUTE_CHI_OFFSET_START;

        let mut new_state_with_error = assigned_state.value().compute_chi_with_error();
        if let Some(ms) = ms {
            // sanity check: absorb on last round only!
            debug_assert!(round == KECCAK_NUM_ROUNDS - 1);
            let ms = ms.iter().map(|m| m.value().cloned()).collect::<Vec<_>>();
            new_state_with_error = new_state_with_error.absorb_with_error(&ms.try_into().unwrap())
        }

        // The layout looks like this:
        //
        // | dc_res  |  adv0   |  adv1    |  acc      |   limbs   |
        // |---------|---------|----------|-----------|-----------|
        // |  ai,jh  |   X     |    X     | acc0      |    ...    |
        // |  ai,jm  |  ai,j   |   M/0    | acc1      |    ...    |
        // |  ai,jl  | a_i+1,j | a_i+2,j  | a_i,j_err |    ...    |
        //
        // We need to:
        //  1. assign bootstrap a_i,j with error
        //  2. copy constraint the cells of adv0, adv1
        //  3. apply the q_chi gate to further constraint a_i,j_err

        let assigned_state_lanes = (0..KECCAK_NUM_LANES)
            .map(|k| {
                let (i, j) = (k / KECCAK_WIDTH, k % KECCAK_WIDTH);
                let lane = new_state_with_error.inner[i][j].clone();

                //  3. apply the q_chi gate to further constraint aij_err
                self.config().lc_subconfig.q_chi.enable(region, chi_offset + 3 * k + 1)?;

                //  1. assign bootstrap a_i,j with error
                self.assign_bootstrap3(region, chi_offset + 3 * k, &lane, 0, BPart::M)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        //  2. copy constraint the cells of adv0, adv1
        (0..KECCAK_NUM_LANES).try_for_each(|k| {
            let (i, j) = (k / KECCAK_WIDTH, k % KECCAK_WIDTH);
            assigned_state.inner[i][j].copy_advice(
                || format!("copy old state element {}, {}", i, j),
                region,
                self.config().lc_subconfig.advice[0],
                chi_offset + 3 * k + 1,
            )?;
            assigned_state.inner[(i + 1) % KECCAK_WIDTH][j].copy_advice(
                || {
                    format!(
                        "copy old state element for negation {}, {}",
                        (i + 1) % KECCAK_WIDTH,
                        j
                    )
                },
                region,
                self.config().lc_subconfig.advice[0],
                chi_offset + 3 * k + 2,
            )?;
            assigned_state.inner[(i + 2) % KECCAK_WIDTH][j].copy_advice(
                || {
                    format!(
                        "copy old state element for and op {}, {}",
                        (i + 2) % KECCAK_WIDTH,
                        j
                    )
                },
                region,
                self.config().lc_subconfig.advice[1],
                chi_offset + 3 * k + 2,
            )?;
            // absorbed message or zero
            if ms.is_some() && i + 5 * j < KECCAK_ABSORB_LANES {
                ms.unwrap()[i + 5 * j].copy_advice(
                    || format!("copy message {} for absorb", i + 5 * j),
                    region,
                    self.config().lc_subconfig.advice[1],
                    chi_offset + 3 * k + 1,
                )?;
            } else {
                region.assign_advice_from_constant(
                    || "assigning 0 in the absorbed message cell",
                    self.config().lc_subconfig.advice[1],
                    chi_offset + 3 * k + 1,
                    SpreadBits::zero(),
                )?;
            }
            Ok::<(), Error>(())
        })?;

        // create the state to return
        let assigned_state =
            AssignedKeccakState::from_lanes(&assigned_state_lanes.try_into().unwrap());

        Ok(assigned_state)
    }
}
