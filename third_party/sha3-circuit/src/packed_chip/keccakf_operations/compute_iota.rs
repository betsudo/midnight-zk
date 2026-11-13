//! Computes the very last iota step in circuit. This consists of computing the
//! new state by changing A[0][0] to A[0][0] xor RC[24].
//!
//! This is done only in the very last round since the iota step is done
//! together with the theta step of the *next round*.

use ff::PrimeField;
use midnight_proofs::{
    circuit::{Chip, Region},
    plonk::Error,
};

use super::{types::AssignedKeccakState, LAST_IOTA_OFFSET};
use crate::{
    constants::{KECCAK_LANE_SIZE, KECCAK_NUM_ROUNDS, ROUND_CST},
    packed_chip::{bootstrap::assign_bootstrap::BPart, utils::SpreadBits, PackedChip},
};

impl<F: PrimeField> PackedChip<F> {
    /// Given a keccak state, it computes the iota operation which consists of
    /// computing a[0][0] = a[0][0] + RC[round].
    ///
    /// For efficiency reasons, this operation is done during the theta step of
    /// the next round, but we need to do it explicitly at the end of the last
    /// round.
    ///
    /// We use the q_iota gate which adds the elments in adv0 and adv1 spanned
    /// over two rows to constraint the bootstraped output.
    ///
    ///
    /// Assigns the following values:
    ///
    /// | offset | dc_res  |  adv0   |  adv1   |  acc   |   limbs   |
    /// |--------|---------|---------|---------|--------|-----------|
    /// |  4104  |  a00m   | a[0,0]  |  RC[24] | acc0   |    ...    |
    /// |  4105  |  a00l   |    0    |    0    | acc1   |    ...    |
    pub(super) fn compute_last_iota(
        &self,
        region: &mut Region<'_, F>,
        state: &AssignedKeccakState<F>,
    ) -> Result<AssignedKeccakState<F>, Error> {
        let mut new_state = state.clone();

        // compute the spread form of the last round constant
        let rc =
            SpreadBits::try_from_u64(ROUND_CST[KECCAK_NUM_ROUNDS - 1], KECCAK_LANE_SIZE).unwrap();

        // add the rc to the a[0][0] element
        let a00_new_with_error = state.inner[0][0].value().map(|a00| a00.try_add(&rc).unwrap());

        // bootstrap the value and enable the iota selector to add the values
        let a00_new =
            self.assign_bootstrap2(region, LAST_IOTA_OFFSET, &a00_new_with_error, 0, BPart::L)?;
        self.config().lc_subconfig.q_iota.enable(region, LAST_IOTA_OFFSET)?;

        new_state.inner[0][0] = a00_new;

        // copy constraint/assign fixed values for the advice columns
        state.inner[0][0].copy_advice(
            || "copy old a00 element for last iota step",
            region,
            self.config().lc_subconfig.advice[0],
            LAST_IOTA_OFFSET,
        )?;
        region.assign_advice_from_constant(
            || "assigning rc[24]",
            self.config().lc_subconfig.advice[1],
            LAST_IOTA_OFFSET,
            rc,
        )?;
        region.assign_advice_from_constant(
            || "assigning constant 0 for iota step col 0",
            self.config().lc_subconfig.advice[0],
            LAST_IOTA_OFFSET + 1,
            SpreadBits::zero(),
        )?;
        region.assign_advice_from_constant(
            || "assigning constant 0 for iota step col 1",
            self.config().lc_subconfig.advice[1],
            LAST_IOTA_OFFSET + 1,
            SpreadBits::zero(),
        )?;

        Ok(new_state)
    }
}
