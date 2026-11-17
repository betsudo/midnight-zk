//! Module for auxiliary linear combination
//!
//! This subconfig is used to apply the constraints:
//!
//! - C[i] = Sum_j A[i][j] + RC[r]
//! - A_theta[i][j] = (C[i-1] + rot(C[i+1],1) + A[i][j] + R[c]
//! - A_chi[i][j] = 2A[i][j] + (ones - A[i+1][j]) + A[i+2][j] + 2M[j + 5i]
//!
//! in the above
//!
//! - the R[c] is only used for C[0] and A_theta[0][0] and it applies the iota
//!   step of the *previous* round
//! - M[j + 5i] is the absorbed message (if it exists) and only applies for r=24

use ff::PrimeField;
use midnight_proofs::{
    plonk::{ConstraintSystem, Constraints, Expression},
    poly::Rotation,
};

use crate::packed_chip::{utils::SpreadBits, LCSubconfig};

#[allow(clippy::too_many_arguments)]
impl LCSubconfig {
    pub(super) fn configure_aux_lc_gates<F: PrimeField>(&self, meta: &mut ConstraintSystem<F>) {
        self.configure_c_gate(meta);
        self.configure_theta_gate(meta);
        self.configure_chi_gate(meta);
    }

    /// Applies the constraint for computing the C[i]
    /// and the iota step of the previous round:
    ///
    /// res - sum_row=0^2 aux_col0(omega^row X) + aux_col1(omega^row X)= 0
    ///
    /// The result is put in the acc_col which is the value that should be
    /// bootstrapped The layout looks like this:
    ///
    /// | q_c | aux_col0 | aux_col1 | acc_col |
    /// |-----|----------|----------|---------|
    /// |  1  |    a0    |    a1    |    X    |
    /// |  0  |    a2    |    a3    |    X    |
    /// |  0  |    a4    |    rc    |   res   |
    ///
    /// and the constraint is:
    /// res(omega^2 X) = aux_col0(X) + aux_col1(X)
    ///                + aux_col0(omega X) + aux_col1(omega X)
    ///                + aux_col0(omega^2 X) + aux_col1(omega^2 X)
    fn configure_c_gate<F: PrimeField>(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("compute c gate with error", |meta| {
            let q = self.q_c;
            let aux_cols = self.advice;

            // sum the six terms
            let sum = (0..6).fold(Expression::Constant(F::ZERO), |acc, i| {
                let (col, rot) = (i % 2, i / 2);
                acc + meta.query_advice(aux_cols[col], Rotation(rot as i32))
            });
            let res = meta.query_advice(aux_cols[2], Rotation(2));
            Constraints::with_selector(q, vec![res - sum])
        });
    }

    /// Applies the constraint for computing the theta step and the iota step of
    /// the previous round
    ///
    /// The result is put in the acc_col which is the value that should be
    /// bootstrapped. The layout looks like this:
    ///
    /// | q_theta | aux_col0 | aux_col1 | acc_col |
    /// |---------|----------|----------|---------|
    /// |    1    |     a    |    c     |    X    |
    /// |    0    |   rotc   |   RC     |   res   |
    ///
    /// and the constraint is:
    /// res(omega^2 X) = aux_col0(X) + aux_col1(X)
    ///                + aux_col0(omega X) + aux_col1(omega X)
    fn configure_theta_gate<F: PrimeField>(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("compute theta gate", |meta| {
            let q = self.q_theta;
            let aux_cols = self.advice;

            let sum = (0..4).fold(Expression::Constant(F::ZERO), |acc, i| {
                let (col, rot) = (i % 2, i / 2);
                acc + meta.query_advice(aux_cols[col], Rotation(rot as i32))
            });
            let res = meta.query_advice(aux_cols[2], Rotation(1));
            Constraints::with_selector(q, vec![res - sum])
        });
    }

    /// Applies the constraint for computing the chi step and the absorbion
    ///
    /// The result is put in the acc_col which is the value that should be
    /// bootstrapped The layout looks like this:
    ///
    /// | q_chi | aux_col0  | aux_col1  | acc_col |
    /// |-------|-----------|-----------|---------|
    /// |   1   |  a[i][j]  | M[j + 5i] |    X    |
    /// |   0   | a[i+1][j] | a[i+2][j] |   res   |
    ///
    /// and the constraint is:
    ///
    /// res(omega^2 X) = 2 * (aux_col0(X) + aux_col1(X)) + (ones -
    /// aux_col0(omega X)) + aux_col1(omega X)
    // - A_chi[i][j] = 2(A[i][j] + M[j + 5i]) + (ones - A[i+1][j]) + A[i+2][j]
    fn configure_chi_gate<F: PrimeField>(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("compute chi gate", |meta| {
            let q = self.q_chi;
            let aux_cols = self.advice;

            // constant values
            let one_spread =
                Expression::Constant(SpreadBits::try_from_u64(u64::MAX, 64).unwrap().to_field());
            let two = Expression::Constant(F::from(2));

            // 2(A[i][j] + M[j + 5i])
            let sum_1 = two
                * (meta.query_advice(aux_cols[0], Rotation::cur())
                    + meta.query_advice(aux_cols[1], Rotation::cur()));
            // (ones - A[i+1][j]) + A[i+2][j]
            let sum_2 = (one_spread - meta.query_advice(aux_cols[0], Rotation::next()))
                + meta.query_advice(aux_cols[1], Rotation::next());

            let sum = sum_1 + sum_2;
            let res = meta.query_advice(aux_cols[2], Rotation::next());

            Constraints::with_selector(q, vec![res - sum])
        });
    }
}

#[cfg(test)]
mod tests;
