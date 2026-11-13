//! decomposes a (64bit) lane to limbs ammenable to rotations.

use ff::PrimeField;
use midnight_proofs::{
    circuit::{AssignedCell, Chip, Region, Value},
    plonk::Error,
};

use super::{
    rotation::{get_spread_limb_coefficients, limb_size_tags},
    types::{AssignedDecomposedSpread, DecomposedSpread},
};
use crate::packed_chip::{
    utils::{AssignedSpreadBits, SpreadBits},
    PackedChip, NUM_FULL_LIMBS, NUM_LIMBS,
};

impl<F: PrimeField> PackedChip<F> {
    /// Assigns constants *without enabling any constraint*.
    fn assign_dc_constants_helper(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        constants: &[F; NUM_LIMBS],
    ) -> Result<[AssignedCell<F, F>; NUM_LIMBS], Error> {
        constants
            .iter()
            .zip(self.config().decomposition_subconfig.dc_fixed_cols.iter())
            .map(|(&coefficient, &col)| {
                region.assign_fixed(
                    || format!("assign lc coefficient at col {:?}", col),
                    col,
                    offset,
                    || Value::known(coefficient),
                )
            })
            .collect::<Result<Vec<_>, Error>>()
            .map(|c| c.try_into().unwrap())
    }

    /// Assigns constants *without enabling the lookup constraint*.
    /// The constraint is enabled during the spread rangecheck.
    // we make it public in super only to be able to access it for testing
    pub(super) fn assign_dc_constants(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        constants: &[F; NUM_LIMBS],
    ) -> Result<[AssignedCell<F, F>; NUM_LIMBS], Error> {
        // enable the linear combination constraint
        self.config().decomposition_subconfig.q_dc.enable(region, offset)?;
        // assign the constants
        self.assign_dc_constants_helper(region, offset, constants)
    }

    /// Helper function that assigns *without constraining* an
    /// [`AssignedDecomposedSpread`] when given as input a u64 lane. The
    /// function assings in a single row:
    ///
    /// |   F   |   F   |  A  |   A   | ... |   A   |
    /// ---------------------------------------------
    /// | tag_1 | tag_2 | res | limb1 | ... | limbk |
    ///
    /// The decomposition structure (limb sizes) is defined by the rotation.
    fn assign_spread_limbs_helper(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: &Value<u64>,
        rot: usize,
    ) -> Result<AssignedDecomposedSpread<F>, Error> {
        // get the needed values
        // computes the limbs of the spread form of the value determined by the rotation
        let decomposed = value.map(|v| DecomposedSpread::new(v, rot));

        let tags = limb_size_tags(rot).map(|t| F::from(t as u64));

        // assign the tags for the rangecheck
        tags.iter()
            .enumerate()
            .map(|(i, &tag)| {
                region.assign_fixed(
                    || format!("assign tag {} for rangecheck", NUM_FULL_LIMBS + i),
                    self.config().decomposition_subconfig.tag_cols[i],
                    offset,
                    || Value::known(tag),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // assign the full-size limbs
        let assigned_limbs = (0..NUM_FULL_LIMBS)
            .map(|i| {
                let limb = decomposed.clone().map(|d| d.full_limbs[i].clone());
                region.assign_advice(
                    || format!("assign spread limb {}", i),
                    self.config().decomposition_subconfig.dc_advice_cols[i],
                    offset,
                    || limb.clone(),
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // convert to an array. should never panic since we always get 4 elements
        let _assigned_full_limbs: [AssignedSpreadBits<F>; NUM_FULL_LIMBS] =
            assigned_limbs.try_into().unwrap();

        // assign the lo limb
        let _assigned_lo_limb = region.assign_advice(
            || "assign lo limb",
            self.config().decomposition_subconfig.dc_advice_cols[NUM_LIMBS - 3],
            offset,
            || decomposed.clone().map(|d| d.lo_limb),
        )?;

        // similarly assign the small limbs
        let _assigned_small_limb_1 = region.assign_advice(
            || "assign small limb 1",
            self.config().decomposition_subconfig.dc_advice_cols[NUM_LIMBS - 2],
            offset,
            || decomposed.clone().map(|d| d.small_limb_1),
        )?;
        let _assigned_small_limb_2 = region.assign_advice(
            || "assign small limb 2",
            self.config().decomposition_subconfig.dc_advice_cols[NUM_LIMBS - 1],
            offset,
            || decomposed.clone().map(|d| d.small_limb_2),
        )?;

        // assign the result
        let assigned_result = region.assign_advice(
            || "assign decomosition result",
            self.config().decomposition_subconfig.dc_result_col,
            offset,
            || decomposed.clone().map(|d| d.result),
        )?;

        Ok(AssignedDecomposedSpread {
            _rot: rot,
            assigned_result,
            _assigned_full_limbs,
            _assigned_lo_limb,
            _assigned_small_limb_1,
            _assigned_small_limb_2,
        })
    }

    /// Assigns limbs of a lane (u64) to be decomposed in spread form.
    /// The decomposition structure (limb sizes) is defined by the rotation.
    ///
    /// # NOTE
    ///
    /// This call does *only constrains* the limbs to be in the correct range
    /// and should never be used. Use
    /// [`PackedChip::assign_spread_decomposition`] to also make the limbs
    /// consistent with the result.
    ///
    /// We make it public in super only to be able to access it for testing.
    pub(super) fn assign_spread_limbs(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: &Value<u64>,
        rot: usize,
    ) -> Result<AssignedDecomposedSpread<F>, Error> {
        // enable spread lookup selector
        self.config().decomposition_subconfig.q_assign_spread.enable(region, offset)?;

        self.assign_spread_limbs_helper(region, offset, value, rot)
    }

    /// Assigns a lane (u64) to be decomposed in spread form.
    /// The decomposition structure (limb sizes) is defined by the rotation.
    /// If `rotate` is true, the rotated word is constraint.
    /// | tag_1 | tag_2 | res | limb_1 | ... | limb_6 | c_1  | ... | c_6  |
    /// |-------|-------|-----|--------|-----|--------|------|-----|------|
    /// |  t_1  |  t_2  |  r  |   l_1  | ... |  l_6   | c_1  | ... | c_6  |
    pub(crate) fn assign_spread_decomposition(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: &Value<u64>,
        rot: usize,
    ) -> Result<AssignedDecomposedSpread<F>, Error> {
        // assign lc coefficients
        let constants = get_spread_limb_coefficients(rot, false);
        self.assign_dc_constants(region, offset, &constants)?;

        // assign the spread limbs. The constraint selector for the lookup and
        // the lc is enabled here
        self.assign_spread_limbs(region, offset, value, rot)
    }

    /// Assigns the rotation of a decomposed lane (u64) on the next row.
    /// | tag_1 | tag_2 | res | limb_1 | ... | limb_6 | c_1  | ... | c_6  |
    /// |-------|-------|-----|--------|-----|--------|------|-----|------|
    /// |   X   |   X   |  X  |   X    | ... |   X    |  X   | ... |  X   |
    /// |   X   |   X   | rot |   X    | ... |   X    | c_1' | ... | c_6' |
    ///
    /// Precondition: the first row is already assigned with
    /// decomposition of the initial word.
    pub(crate) fn assign_rotation_next_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: &Value<u64>,
        rot: usize,
    ) -> Result<AssignedSpreadBits<F>, Error> {
        // convert to spread
        let value_spread = value.map(|v| SpreadBits::try_from_u64(v, 64).unwrap());

        // enable the linear combination constraint
        self.config().decomposition_subconfig.q_rotate_next.enable(region, offset)?;
        // assign the constants
        let constants = get_spread_limb_coefficients(rot, true);
        self.assign_dc_constants_helper(region, offset + 1, &constants)?;

        region.assign_advice(
            || "assign decomosition result on next row",
            self.config().decomposition_subconfig.dc_result_col,
            offset + 1,
            || value_spread.clone().map(|v| v.rotate_right(rot)),
        )
    }
}
