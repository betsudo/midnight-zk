//! gates needed for limb decomposition

use ff::PrimeField;
use midnight_proofs::{
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Expression, Fixed, Selector, TableColumn,
    },
    poly::Rotation,
};

use crate::packed_chip::{
    LAST_FIXED_LIMB_LENGTH, MAX_BIT_LENGTH, NUM_FULL_LIMBS, NUM_LIMBS, TAG_COLS,
};

/// Configures a gate to decompose (in spread form) a lane into
/// appropriate limbs
pub(super) fn configure_decomposition_lookup<F: PrimeField>(
    meta: &mut ConstraintSystem<F>,
    q_spread: Selector,
    // two tags are given for the small limbs
    tag_cols: [Column<Fixed>; TAG_COLS],
    dc_advice_cols: [Column<Advice>; NUM_LIMBS],
    t_tag: TableColumn,
    t_spread: TableColumn,
) {
    // enable lookups for full size limbs
    for (i, adv_col) in dc_advice_cols.iter().take(NUM_FULL_LIMBS).enumerate() {
        meta.lookup(format!("decomposition lookup: limb {}", i), |meta| {
            // we use no tag here, we allow looking the whole table
            let q = meta.query_selector(q_spread);
            let limb = meta.query_advice(*adv_col, Rotation::cur());
            vec![(q * limb, t_spread)]
        });
    }
    // enable lookup for lo limbs
    meta.lookup(
        format!("decomposition lookup: limb {}", NUM_FULL_LIMBS),
        |meta| {
            let q = meta.query_selector(q_spread);
            // the tag in this case is fixed and equal to LAST_FIXED_LIMB_LENGTH. If it is a
            // full limb allow searching the whole table
            let lo_limb = meta.query_advice(dc_advice_cols[NUM_LIMBS - 3], Rotation::cur());
            if LAST_FIXED_LIMB_LENGTH == MAX_BIT_LENGTH {
                vec![(q * lo_limb, t_spread)]
            } else {
                let tag = Expression::Constant(F::from(LAST_FIXED_LIMB_LENGTH as u64));
                vec![(q.clone() * tag, t_tag), (q * lo_limb, t_spread)]
            }
        },
    );
    (0..=1).for_each(|i| {
        meta.lookup(
            format!("decomposition lookup: limb {}", NUM_FULL_LIMBS + 1 + i),
            |meta| {
                let q = meta.query_selector(q_spread);
                // the tag is explicit and depends on the rotation
                let tag_small = meta.query_fixed(tag_cols[i], Rotation::cur());
                let small_limb =
                    meta.query_advice(dc_advice_cols[NUM_LIMBS - 2 + i], Rotation::cur());
                vec![(q.clone() * tag_small, t_tag), (q * small_limb, t_spread)]
            },
        );
    });
}

/// Configures a gate to perform linear combination
pub(super) fn configure_decomposition_lc<F: PrimeField>(
    meta: &mut ConstraintSystem<F>,
    q_dc: Selector,
    // [`NUM_LIMBS`] columns to witness the limbs and the lc constants
    fixed_cols: [Column<Fixed>; NUM_LIMBS],
    dc_advice_cols: [Column<Advice>; NUM_LIMBS],
    // one advice column to witnesss the result
    result_col: Column<Advice>,
) {
    // linear combination constraint
    meta.create_gate("linear combination constraint", |meta| {
        let q = q_dc;
        let running_sum = dc_advice_cols.iter().zip(fixed_cols.iter()).fold(
            Expression::Constant(F::ZERO),
            |acc, (&limb_col, &coef_col)| {
                let coef = meta.query_fixed(coef_col, Rotation::cur());
                let limb = meta.query_advice(limb_col, Rotation::cur());
                acc + coef * limb
            },
        );
        let res = meta.query_advice(result_col, Rotation::cur());
        Constraints::with_selector(q, vec![res - running_sum])
    });
}

/// Configures a gate to perform the rotation of the current limbs in the next
/// row
pub(super) fn configure_rotation_next_row<F: PrimeField>(
    meta: &mut ConstraintSystem<F>,
    q_rotate: Selector,
    // [`NUM_LIMBS`] columns to witness the limbs and the lc constants
    fixed_cols: [Column<Fixed>; NUM_LIMBS],
    dc_advice_cols: [Column<Advice>; NUM_LIMBS],
    // one advice column to witnesss the result
    result_col: Column<Advice>,
) {
    // linear combination constraint on limbs on the next row
    meta.create_gate("rotation constraint", |meta| {
        let q = q_rotate;
        let running_sum = dc_advice_cols.iter().zip(fixed_cols.iter()).fold(
            Expression::Constant(F::ZERO),
            |acc, (&coef_col, &limb_col)| {
                let coef = meta.query_fixed(limb_col, Rotation::next());
                let limb = meta.query_advice(coef_col, Rotation::cur());
                acc + coef * limb
            },
        );
        let res = meta.query_advice(result_col, Rotation::next());
        Constraints::with_selector(q, vec![res - running_sum])
    });
}
