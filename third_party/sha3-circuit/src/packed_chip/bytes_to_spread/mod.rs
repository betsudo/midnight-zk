//! Module to convert dense bytes to spread lane and vice versa.
//!
//! The conversion is done as: [b0...b7] <-> spread(b7b6...b0),
//! that is, the spread lane is mapped to little endian bytes.

use ff::PrimeField;
use midnight_proofs::{
    plonk::{ConstraintSystem, Constraints, Expression},
    poly::Rotation,
};

use crate::packed_chip::{BytesToSpreadSubconfig, MAX_BIT_LENGTH};

mod assign_bytes_to_spread;

#[allow(clippy::too_many_arguments)]
impl BytesToSpreadSubconfig {
    #[allow(clippy::doc_lazy_continuation)]
    /// Applies the following constraints:
    ///
    /// |recomposition | intermediate |   l0   | ... |   l3   |
    /// |--------------|--------------|--------|-----|--------|
    /// |      X       |       X      |   a3   | ... |   a0   |
    /// |     ~r       |     prev     |  ~a3   | ... |  ~a0   |
    /// |
    /// - (8, ai, ~ai) in Table => ai are bytes and ~ai their spread form
    /// - ~r = 8^32 prev + 8^24 a3 + 8^16 a2 + 8^8 a1 + a0
    ///
    /// To construct the spread lane using a0,...,a7 (little endian)
    ///
    /// 1. assign the constraint in row i with a4..a7 and prev = 0
    /// 2. assign the constraint in row i+2 with a0..a4 and prev being the
    /// spread form of 2^24 ~a7 + 2^16 ~a6 + 2^8 ~a5 + ~a4
    pub(super) fn configure_bytes_to_spread<F: PrimeField>(&self, meta: &mut ConstraintSystem<F>) {
        // configure the 4 lookups
        (0..4).for_each(|i| {
            meta.lookup(format!("spread byte lookup: limb {}", i), |meta| {
                let q = meta.query_selector(self.q_bytes_to_lane);
                // the dense value is on the current row
                let dense = meta.query_advice(self.limbs[i], Rotation::cur());
                // the spread value is on the next row
                let spread = meta.query_advice(self.limbs[i], Rotation::next());

                // in case we have an 8-bit lookup ignore the tag and look in the whole table
                if MAX_BIT_LENGTH == 8 {
                    vec![
                        (q.clone() * dense, self.t_dense),
                        (q.clone() * spread, self.t_spread),
                    ]
                } else {
                    // use tag=8 for looking up byte values
                    let tag = Expression::Constant(F::from(8));
                    vec![
                        (q.clone() * tag, self.t_tag),
                        (q.clone() * dense, self.t_dense),
                        (q * spread, self.t_spread),
                    ]
                }
            });
        });

        // configure the recomposition constraint:
        // res(omegaX) = 8^32 intermediate(omegaX) +
        //             + 8^24 l3(omegaX) + 8^16 l2(omegaX) +
        //             + 8^8 l1(omegaX) + l0(omegaX)
        meta.create_gate("byte to lane constraint", |meta| {
            // the selector
            let q = self.q_bytes_to_lane;

            // the previous result with its coefficient
            let prev_coef =
                Expression::Constant(F::from(1 << 32) * F::from(1 << 32) * F::from(1 << 32));
            let prev = meta.query_advice(self.intermediate, Rotation::next());

            // the limbs and their coefficients
            // the limbs are given from most to least significant byte
            let coeff = [1 << 24, 1 << 16, 1 << 8, 1 << 0]
                .map(|v| F::from(v) * F::from(v) * F::from(v))
                .map(|v| Expression::Constant(v));
            let limbs = (0..4).map(|i| meta.query_advice(self.limbs[i], Rotation::next()));

            let computed_res =
                coeff.into_iter().zip(limbs).fold(prev * prev_coef, |acc, (c, l)| acc + c * l);

            let res = meta.query_advice(self.recomposition, Rotation::next());
            Constraints::with_selector(q, vec![res - computed_res])
        });
    }
}

#[cfg(test)]
mod tests;
