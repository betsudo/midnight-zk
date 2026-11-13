//! The module handle decomposition operations for packed bits. Specifically, it
//! allows the following in-circuit operations:
//!
//! 1. assign spread bits representing lanes (u64)
//! 2. assign rotated spread bits representing lanes (u64)

use ff::PrimeField;
use gates::{configure_decomposition_lc, configure_decomposition_lookup};
use midnight_proofs::plonk::ConstraintSystem;

use self::gates::configure_rotation_next_row;
use crate::packed_chip::DecompositionSubconfig;

mod decompose_spread;
mod gates;
mod rotation;
mod types;

#[cfg(test)]
mod tests;

#[allow(clippy::too_many_arguments)]
impl DecompositionSubconfig {
    /// configures the decomposition related gates
    pub(super) fn configure_decomposition_gates<F: PrimeField>(
        &self,
        meta: &mut ConstraintSystem<F>,
    ) {
        // Spread rangecheck. Uses the q_assign_spread selector and the t_spread table
        // column
        configure_decomposition_lookup(
            meta,
            self.q_assign_spread,
            self.tag_cols,
            self.dc_advice_cols,
            self.t_tag,
            self.t_spread,
        );
        // lc gates for decomposition
        configure_decomposition_lc(
            meta,
            self.q_dc,
            self.dc_fixed_cols,
            self.dc_advice_cols,
            self.dc_result_col,
        );
        // rotation on next row
        configure_rotation_next_row(
            meta,
            self.q_rotate_next,
            self.dc_fixed_cols,
            self.dc_advice_cols,
            self.dc_result_col,
        );
    }
}
