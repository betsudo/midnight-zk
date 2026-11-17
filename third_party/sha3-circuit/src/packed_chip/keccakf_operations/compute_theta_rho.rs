//! Computes the theta and rho step in circuit.
//!
//! The theta step consists of computing the new state by
//! changing A[i][j] to A[i][j] xor D[i] where D[i] = C[i-1] xor rotl(C[i+1],1)
//! and C[i] = xor_j A[i][j].
//!
//! In this step, we also compute the iota step of the previous round (if it is
//! not the first). This is done by computing A[0][0] = A[0][0] + RC[round]. We
//! do this by adding the RC[round]
//!
//! 1. in the computation of C: C[0] = xor_j A[0][j] xor RC[round].
//! 2. in the computation of A[0][0]: A[0][0] = A[0][0] xor D[0] xor RC[round].
//!
//! The rho step consists of taking rotations of the output of the theta step.
//! When computing the state after theta, we decompose in a way that computing
//! rotations is easy and we directly return the rotated new state.

// NOTE: Rotations are implemented by recomputing a (rotated) recomposition on
// a new row. This leads to ~30 rows per round. An alternative approach is by
// computing the rotation in the same row and assign the result in adv1 column.
// This can be done in two ways:
//
// 1. add more fixed columns (1 per limb) and do a new linear combination with
// the new coefficients.
// 2. add [`NUM_LIMBS`] new constraints, one for each of the possibles limb
// combinations. For any assignment, two of these can be used to compute both
// the normal and the rotated word.
//
// The reason these are not implemented is that it will require more fixed
// columns (in the second case this corresponds to selectors which *do not*
// implement compression).
//
// Finally, note that for these optimizations, the iota step would need to
// happen at the end of the round since we don't have the extra advice columns
// to assign the RC[round] value, leading to 2 more rows per round.

use ff::PrimeField;
use midnight_proofs::{
    circuit::{Chip, Region},
    plonk::Error,
};

use super::{
    types::{AssignedCs, AssignedKeccakState},
    COMPUTE_C_OFFSET_START,
};
use crate::{
    constants::{KECCAK_LANE_SIZE, KECCAK_NUM_LANES, KECCAK_WIDTH, RHO_ROTATAIONS, ROUND_CST},
    packed_chip::{
        bootstrap::assign_bootstrap::BPart,
        keccakf_operations::{COMPUTE_THETA_OFFSET_START, ROWS_PER_ROUND},
        utils::SpreadBits,
        PackedChip,
    },
};

impl<F: PrimeField> PackedChip<F> {
    /// Given as input a keccak state, it computes the state after applying the
    /// theta and rho steps.
    ///
    /// Concretely, it computes
    ///
    /// - c[0],...,c[4] and the corresponding 1-rotations
    /// - a[i][j] = a[i][j] xor c[i-1] xor rotl(c[i+1],1)
    ///
    /// It outputs the rotated state, that is, given
    /// a state the function outputs the assigned state
    /// rho(theta(state))
    ///
    /// It also does the previous round iota operation which corresponds to
    /// A[0][0] = A[0][0] xor RC[r].
    ///
    /// Assigns the following values:
    ///
    /// | offset | dc_res  |  adv0   |  adv1   |  acc   |   limbs   |
    /// |--------|---------|---------|---------|--------|-----------|
    /// |    0   |  c0h    | a[0,0]  |  a[0,1] | acc0   |    ...    |
    /// |    1   |  c0m    | a[0,2]  |  a[0,3] | acc1   |    ...    |
    /// |    2   |  c0l    | a[0,4]  |    RC   | c0_err |    ...    |
    /// |    3   |  rot    |    X    |    X    |  X     |     X     |
    /// |        |   .     |    .    |    .    |  .     |     .     |
    /// |        |   .     |    .    |    .    |  .     |     .     |
    /// |        |   .     |    .    |    .    |  .     |     .     |
    /// |   16   |  c4h    | a[4,0]  |  a[4,1] | acc0   |    ...    |
    /// |   17   |  c4m    | a[4,2]  |  a[4,3] | acc1   |    ...    |
    /// |   18   |  c4l    | a[4,4]  |    0    | c4_err |    ...    |
    /// |   19   |  rot    |    X    |    X    |  X     |    ...    |
    /// |--------|---------|---------|---------|--------|-----------|
    /// |   20   |  a0,0h  |    X    |    X    | acc0   |    ...    |
    /// |   21   |  a0,0m  | a0,0old |   c4    | acc1   |    ...    |
    /// |   22   |  a0,0l  |  rotc1  |   RC    | acc2   |    ...    |
    /// |   23   |  rota00 |    X    |    X    |  X     |    ...    |
    /// |   24   |  a0,1m  | a0,1old |   c4    | acc0   |    ...    |
    /// |   25   |  a0,1l  |  rotc1  |    0    | acc1   |    ...    |
    /// |   26   |  rota01 |    X    |    X    |  X     |    ...    |
    /// |        |   .     |    .    |    .    |  .     |     .     |
    /// |        |   .     |    .    |    .    |  .     |     .     |
    /// |        |   .     |    .    |    .    |  .     |     .     |
    /// |   93   |  a4,4m  | a0,1old |   c3    | acc0   |    ...    |
    /// |   94   |  a4,4l  |  rotc0  |    0    | acc1   |    ...    |
    /// |   95   |  rota44 |    X    |    X    |  X     |    ...    |
    /// |--------|---------|---------|---------|--------|-----------|
    // NOTE: this could be given as two separate functions but it seems clearer to
    // inspect them together
    pub(super) fn compute_theta_rho(
        &self,
        region: &mut Region<'_, F>,
        round: usize,
        state: &AssignedKeccakState<F>,
    ) -> Result<AssignedKeccakState<F>, Error> {
        // compute cs and their rotations using the helper function
        let assigned_cs = self.compute_c(region, round, state)?;

        // compute the region offset for theta
        let theta_offset = round * ROWS_PER_ROUND + COMPUTE_THETA_OFFSET_START;

        // Compute and spread the round constants added to a[i][j]. These are all zero
        // except possibly for A[0][0]. Recall that these constants are from the
        // previous round. It is important to assign either the round constant or the
        // zero constant since the constrain also adds the corresponding cell.
        let mut rcs = [[0; KECCAK_WIDTH]; KECCAK_WIDTH];
        if round != 0 {
            rcs[0][0] = ROUND_CST[round - 1];
        }
        let spread_rcs =
            rcs.map(|rcs| rcs.map(|rc| SpreadBits::try_from_u64(rc, KECCAK_LANE_SIZE).unwrap()));

        // compute the new state with error
        let mut new_state_with_error = state.value().compute_theta_with_error(assigned_cs.value());

        // add the round constant of the previous round if any
        new_state_with_error.inner[0][0] = new_state_with_error.inner[0][0]
            .clone()
            .map(|a_old| a_old.try_add(&spread_rcs[0][0]).unwrap());

        // The layout looks like this:
        //
        // | dc_res  |  adv0   |  adv1   |  acc        |   limbs   |
        // |---------|---------|---------|-------------|-----------|
        // | a_i,jm  |a_i,jold |  c_i-1  | acc0        |    ...    |
        // | a_i,jl  |rotc_i+1 |  RC/0   | a_i,j_error |    ...    |
        // | rotaij  |    X    |    X    |      X      |    ...    |
        //
        // We need to:
        //  1. assign bootstrap a_i,j_error terms
        //  2. copy constraint the cells of adv0, adv1
        //  3. apply the q_theta gate to further constraint a_i,j_error
        //  4. compute the appropriate rotated element in the third row
        //
        //  The first element a00 needs to be bootstraped *in three rows* since it
        //  has more accumulated error due to the added rc element
        let assigned_state_lanes = (0..KECCAK_NUM_LANES)
            .map(|k| {
                let (i, j) = (k / KECCAK_WIDTH, k % KECCAK_WIDTH);
                let lane = new_state_with_error.inner[i][j].clone();

                //  1. assign bootstrap a_i,j_error terms
                let a_low = if i == 0 && j == 0 {
                    // case a00 with more accumulated error
                    self.assign_bootstrap3(
                        region,
                        theta_offset,
                        &lane,
                        // we rotate left but we implement right rotations
                        // so we do a 64-rot rotation
                        (KECCAK_LANE_SIZE - RHO_ROTATAIONS[0][0]) % KECCAK_LANE_SIZE,
                        BPart::L,
                    )
                } else {
                    self.assign_bootstrap2(
                        region,
                        // 3 rows per a_i,j element except a_0,0 which needs 4.
                        // The 1 is due to the extra row needed for a[0][0].
                        theta_offset + 3 * k + 1,
                        &lane,
                        // we rotate left but we implement right rotations
                        // so we do a 64-rot rotation
                        (KECCAK_LANE_SIZE - RHO_ROTATAIONS[i][j]) % KECCAK_LANE_SIZE,
                        BPart::L,
                    )
                }?;

                //  2. copy constraint the cells of adv0, adv1
                state.inner[i][j].copy_advice(
                    || format!("copy old state element {}, {}", i, j),
                    region,
                    self.config().lc_subconfig.advice[0],
                    theta_offset + 3 * k + 1,
                )?;
                assigned_cs.cs[(i + KECCAK_WIDTH - 1) % KECCAK_WIDTH].copy_advice(
                    || format!("copy c {}", i - 1),
                    region,
                    self.config().lc_subconfig.advice[1],
                    theta_offset + 3 * k + 1,
                )?;
                assigned_cs.rot_cs[(i + 1) % KECCAK_WIDTH].copy_advice(
                    || format!("copy rotated c {}", i + 1),
                    region,
                    self.config().lc_subconfig.advice[0],
                    theta_offset + 3 * k + 2,
                )?;
                region.assign_advice_from_constant(
                    || "assigning rc",
                    self.config().lc_subconfig.advice[1],
                    theta_offset + 3 * k + 2,
                    // spread rcs correspond to RC[round] or 0
                    spread_rcs[i][j].clone(),
                )?;

                //  3. apply the q_theta gate to further constraint a_i,j_error
                self.config().lc_subconfig.q_theta.enable(region, theta_offset + 3 * k + 1)?;

                //  4. compute the appropriate rotated element in the third row
                self.assign_rotation_next_row(
                    region,
                    theta_offset + 3 * k + 2,
                    &a_low.value().map(|v| v.try_to_lane().unwrap()),
                    // we rotate left but we implement right rotations
                    // so we do a 64-rot rotation
                    (KECCAK_LANE_SIZE - RHO_ROTATAIONS[i][j]) % KECCAK_LANE_SIZE,
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // construct the new state corresponding to rho(theta(state))
        let assigned_state =
            AssignedKeccakState::from_lanes(&assigned_state_lanes.try_into().unwrap());

        Ok(assigned_state)
    }
}

impl<F: PrimeField> PackedChip<F> {
    /// Given as input a keccak state, compute [c0,...,c4] and the corresponding
    /// 1-rotations.
    ///
    /// Assigns the following values:
    ///
    /// | offset | dc_res  |  adv0   |  adv1  |  acc    |   limbs   |
    /// |--------|---------|---------|--------|---------|-----------|
    /// |   0    |  c0h    | a[0,0]  | a[0,1] | acc0    |    ...    |
    /// |   1    |  c0m    | a[0,2]  | a[0,3] | acc1    |    ...    |
    /// |   2    |  c0l    | a[0,4]  |   RC   | c0_err  |    ...    |
    /// |   3    |  rot    |    X    |   X    |   X     |    ...    |
    /// |        |   .     |    .    |   .    |   .     |     .     |
    /// |        |   .     |    .    |   .    |   .     |     .     |
    /// |        |   .     |    .    |   .    |   .     |     .     |
    /// |  16    |  c4h    | a[4,0]  | a[4,1] | acc0    |    ...    |
    /// |  17    |  c4m    | a[4,2]  | a[4,3] | acc1    |    ...    |
    /// |  18    |  c4l    | a[4,4]  |   0    | c4_err  |    ...    |
    /// |  19    |  rot    |    X    |   X    |   X     |    ...    |
    ///
    ///
    /// cih, cim, cil are the h, m and l bits of the value ci_err that contains
    /// the error term after the XOR operations.
    /// The following constraints are applied:
    ///     1. ci_err = sum_{j=0}^4 a[i,j] + RC/0
    ///     2. cil is the bootstrapped value of ci_err
    ///     3. the state values a[i,j], RC/0 are copy constrainted
    ///     4. rot is the 1 left rotation of the value represented in c4l
    fn compute_c(
        &self,
        region: &mut Region<'_, F>,
        round: usize,
        state: &AssignedKeccakState<F>,
    ) -> Result<AssignedCs<F>, Error> {
        // compute the region offset
        let c_offset = round * ROWS_PER_ROUND + COMPUTE_C_OFFSET_START;

        // compute the cs spread values (with error)
        let mut cs_with_error = state.value().compute_cs_with_error();

        // add the round constant to C[0] and fill with zeros for the copy constraints
        let rcs = if round != 0 {
            [ROUND_CST[round - 1], 0, 0, 0, 0]
        } else {
            [0; KECCAK_WIDTH]
        };
        let spread_rcs = rcs.map(|rc| SpreadBits::try_from_u64(rc, KECCAK_LANE_SIZE).unwrap());
        cs_with_error[0] = cs_with_error[0].clone().map(|c0| c0.try_add(&spread_rcs[0]).unwrap());

        // The layout looks like this:
        //
        // | offset | dc_res  |  adv0   |  adv1   |  adv3   | limbs |
        // |--------|---------|---------|---------|---------|-------|
        // |   4*i  |  ci_hi  | a[i,0]  | a[i,1]  | acc0    |  ...  |
        // |  4*i+1 |  ci_mid | a[i,2]  | a[i,3]  | acc1    |  ...  |
        // |  4*i+2 |  ci_lo  | a[i 4]  |  RC/0   | ci_err  |  ...  |
        // |  4*i+3 |  rotci  |   X     |   X     |   X     |   X   |
        //
        // We need to:
        //  1. assign bootstrap ci_err
        //  2. assign rotci
        //  3. copy constraint the cells of adv0, adv1 in the first 3 rows
        //  4. apply the q_c gate to further constraint ci_err

        //  1. assign bootstrap ci_err
        let cs = cs_with_error
            .iter()
            .enumerate()
            .map(|(i, c_err)| {
                // the unwrap does not panic since we call with rot != 0
                // we implement left rotations so we do KECCAK_LANE_SIZE - 1 for right rotations
                self.assign_bootstrap3(
                    region,
                    c_offset + 4 * i,
                    c_err,
                    // we rotate left but we implement right rotations
                    // so we do a 64-1 right rotation for a 1 left rotation
                    (KECCAK_LANE_SIZE - 1) % KECCAK_LANE_SIZE,
                    BPart::L,
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        //  2. assign rotci
        let rot_cs = (0..KECCAK_WIDTH)
            .map(|i| {
                self.assign_rotation_next_row(
                    region,
                    c_offset + 4 * i + 2,
                    &cs[i].value().map(|v| v.try_to_lane().unwrap()),
                    // we rotate left but we implement right rotations
                    // so we do a 64-1 right rotation for a 1 left rotation
                    (KECCAK_LANE_SIZE - 1) % KECCAK_LANE_SIZE,
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        //  3. copy constraint the cells of adv0, adv1 and the round constant in the
        //     first 3 rows
        state.inner.iter().enumerate().try_for_each(|(i, lanes)| {
            // copy the advices from a[i][0]...a[i][4] and the round constant
            lanes
                .iter()
                .enumerate()
                .map(|(j, a)| {
                    a.copy_advice(
                        || format!("Copy advice a_{},{}", i, j),
                        region,
                        self.config().lc_subconfig.advice[j % 2],
                        c_offset + 4 * i + j / 2,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            region.assign_advice_from_constant(
                || "assigning rc",
                self.config().lc_subconfig.advice[1],
                c_offset + 4 * i + 2,
                spread_rcs[i].clone(),
            )?;
            //  4. apply the q_c gate to further constrain ci_err
            self.config().lc_subconfig.q_c.enable(region, c_offset + 4 * i)?;
            Ok::<(), Error>(())
        })?;

        Ok(AssignedCs {
            cs: cs.try_into().unwrap(),
            rot_cs: rot_cs.try_into().unwrap(),
        })
    }
}
