use ff::PrimeField;
use midnight_proofs::{circuit::Region, plonk::Error};

use self::types::AssignedKeccakState;
use super::{utils::AssignedSpreadBits, PackedChip};
use crate::constants::{KECCAK_ABSORB_LANES, KECCAK_NUM_LANES, KECCAK_NUM_ROUNDS, KECCAK_WIDTH};

// mod compute_chi_iota;
mod compute_chi;
mod compute_iota;
mod compute_theta_rho;
pub(super) mod types;

#[cfg(test)]
mod tests;

// The relative row offset each steps takes place during a single round.
// Recall that each decomposition is done in a single row.

/// rows where cs are computed
const COMPUTE_C_OFFSET_START: usize = 0;

/// 4 rows per c[i] and their rotations
const COMPUTE_C_OFFSET_END: usize = COMPUTE_C_OFFSET_START + 4 * KECCAK_WIDTH;

/// rows where thetas are computed after having computed cs
const COMPUTE_THETA_OFFSET_START: usize = COMPUTE_C_OFFSET_END;

/// 2 rows per lane except A[0] which *needs three rows to be decomposed*
/// since we also add the round constant of the previous round.
///
/// # NOTES
///
/// We can save one row by ommitting the IV in the first
/// round but this seems too ugly relative to the gain
const COMPUTE_THETA_OFFSET_END: usize = COMPUTE_THETA_OFFSET_START + 3 * KECCAK_NUM_LANES + 1;

/// 3 rows per lane for computing chi
const COMPUTE_CHI_OFFSET_START: usize = COMPUTE_THETA_OFFSET_END;
const COMPUTE_CHI_OFFSET_END: usize = COMPUTE_CHI_OFFSET_START + 3 * KECCAK_NUM_LANES;

/// rows needed per keccak-f round
const ROWS_PER_ROUND: usize = COMPUTE_CHI_OFFSET_END;

/// rows where the last iota step is computed
const LAST_IOTA_OFFSET: usize = KECCAK_NUM_ROUNDS * ROWS_PER_ROUND;

/// the total rows needed for the permutation
pub(super) const KECCAK_ROWS_PER_PERMUTATION: usize = LAST_IOTA_OFFSET + 1;

impl<F: PrimeField> PackedChip<F> {
    /// given as input an assigned initial keccak state, it computes the state
    /// after applying one round of the keccak-f permutation. It optionally
    /// recieves message lanes to absorb *after* the final round.
    pub(super) fn keccakf_round(
        &self,
        region: &mut Region<'_, F>,
        round: usize,
        state: &AssignedKeccakState<F>,
        ms: Option<&[AssignedSpreadBits<F>; KECCAK_ABSORB_LANES]>,
    ) -> Result<AssignedKeccakState<F>, Error> {
        // apply the theta and rho steps and also the iota step of the previous round if
        // it is not the first round
        let state = self.compute_theta_rho(region, round, state)?;

        // apply the pi round which permutes the lanes. This performs no operation in
        // circuit.
        let state = state.compute_pi();

        // apply the chi step (with no absorbtion)
        let state = self.compute_chi(region, round, &state, ms)?;

        // if it is the last round, also compute the final iota step
        if round == KECCAK_NUM_ROUNDS - 1 {
            self.compute_last_iota(region, &state)
        } else {
            Ok(state)
        }
    }
}
