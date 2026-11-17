//! Module to "bootstrap" spread bits.
//!
//! When doing binary operations on spread bits, there are error terms that
//! correspond to carries. For example: a xor b  ==> res = a + b (in F) res has
//! errors: the lsb contains the xor result and the middle bit has possibly
//! carries.
//!
//! Bootstrapping allows to split res to two or three field elements (depending
//! on the accumulated error) and get clean spread bits that contain the result.
//!
//! In the above example res = res_lsb + 2 * res_middle
//! Crucially res_lsb, res_middle should be guaranteed to correspond to spread
//! bits. This is done by decomposing.

use ff::PrimeField;
use midnight_proofs::{
    plonk::{ConstraintSystem, Constraints, Expression},
    poly::Rotation,
};

use crate::packed_chip::BootstrapSubconfig;

pub(super) mod assign_bootstrap;

#[allow(clippy::too_many_arguments)]
impl BootstrapSubconfig {
    /// Applies the following constraint when q_bootstrap is enabled
    ///
    /// | res_col  |  acc_col
    /// |----------|----------
    /// |          |    acc
    /// |  p_next  | acc_next
    ///
    /// acc_next = 2 * acc + p_next
    ///
    /// This corresponds to the constraint:
    /// acc_col(omega X) = 2 * acc_col(X) + p(omega X)
    pub(crate) fn configure_bootstrap_gate<F: PrimeField>(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("bootstrap constraint", |meta| {
            let q = self.q_bootstrap;
            let acc = meta.query_advice(self.bootstrap_acc_col, Rotation::cur());
            let acc_next = meta.query_advice(self.bootstrap_acc_col, Rotation::next());
            let p_next = meta.query_advice(self.part_col, Rotation::next());
            let base = Expression::Constant(F::from(2));
            Constraints::with_selector(q, vec![acc_next - base * acc - p_next])
        });
    }
}

#[cfg(test)]
mod tests;
