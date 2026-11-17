//! Module to assign values for bootstraping  spread bits of the form
//! w = a_1b_1c_1 a_2b_2c_2 ..... a_mb_mc_m

use ff::PrimeField;
use midnight_proofs::{
    circuit::{Chip, Region, Value},
    plonk::Error,
};

use crate::packed_chip::{
    utils::{AssignedSpreadBits, SpreadBits},
    PackedChip, SPREAD_BASE_BITS,
};

#[repr(usize)]
/// Representation of the result of the bootstraping.
/// Depending on the binary operations, we might want to return the low or
/// middle bits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BPart {
    // we never need the high bits
    H = 0,
    M = 1,
    L = 2,
}

// NOTE: the next functions can be merged but it seems cleaner to repeat some
// code
impl<F: PrimeField> PackedChip<F> {
    /// Given as input spread bits with small error (msbs are 0)
    /// w = 0b_1c_1 0b_2c_2 ..... 0b_mc_m
    /// it decomposes the word into clean spread bits
    /// b = 00b_1_00b_2_.....00b_m (middle bits).
    /// c = 00c_1_00c_2_.....00c_m (low bits).
    /// depending on the [`BPart`] given as output along with its rotation
    ///
    /// The layout is as follows:
    /// | res |  acc   |     limbs       |
    /// |-----|--------|-----------------|
    /// |  b  |  acc0  |  ...limbs_b...  |
    /// |  c  |  acc1  |  ...limbs_c...  |
    ///
    /// The following constraints are applied:
    ///
    /// 1. b is a valid spread word (via limb decomposition of limbs_b)
    /// 2. c is a valid spread word (via limb decomposition of limbs_c)
    /// 3. acc0 = b (equality constraint)
    /// 4. acc1 = c + 2acc0 (should equal the input w)
    ///
    /// The output is either b or c and is defined by `output`
    /// (in this case it should always be [`BPart::L`])
    ///
    /// # Note
    ///
    /// The acc1 cell is *not copy constraint from some previous value* but
    /// rather directly assigned. Additional constraints are used to further
    /// constraint the result in place.
    ///
    /// For example, to compute C = A1 xor ... xor A5 we need to imopose an
    /// additional constraint *on the same cell* s.t. spreadC = sum Ai.
    /// This is equivalent to first computing spreadC as a spreadword with error
    /// and then bootstraping it.
    pub(crate) fn assign_bootstrap2(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        w: &Value<SpreadBits>,
        rot: usize,
        output: BPart,
    ) -> Result<AssignedSpreadBits<F>, Error> {
        // sanity check: this is not called with high/middle bits
        debug_assert_eq!(output, BPart::L);

        // get the middle and low spread bits
        let parts = w.clone().map(|bits| bits.spread_parts()).transpose_vec(SPREAD_BASE_BITS);

        // never errors: parts have by construction only the least significant bits
        // non-zero
        let middle = parts[BPart::M as usize].clone().map(|v| v.try_to_lane().unwrap());
        let low = parts[BPart::L as usize].clone().map(|v| v.try_to_lane().unwrap());

        // assign the spread limb decomposition
        // this handles constraints 1, 2
        let decomposed = [
            self.assign_spread_decomposition(region, offset, &middle, rot)?,
            self.assign_spread_decomposition(region, offset + 1, &low, rot)?,
        ];

        // constrain the initial accumulator
        // this handles constraint 3 (b = acc0)
        let acc_col = self.config().bootstrap_subconfig.bootstrap_acc_col;
        decomposed[0].assigned_result.copy_advice(
            || "copy constraint initial accumulator for bootstraping",
            region,
            acc_col,
            offset,
        )?;

        // assign acc1
        let acc1 = decomposed[0]
            .assigned_result
            .value()
            .zip(decomposed[1].assigned_result.value())
            .map(|(m, l)| F::from(2) * m.to_field::<F>() + l.to_field::<F>());
        region.assign_advice(|| "assign accumulator", acc_col, offset + 1, || acc1)?;

        // enable the bootstrap_constraint
        // this handles constraint 4 (acc1 = c + 2acc0 <==> w = c + 2b)
        self.config().bootstrap_subconfig.q_bootstrap.enable(region, offset)?;

        let output = match output {
            // should never need to use the high bits
            BPart::H => return Err(Error::InvalidInstances),
            BPart::M => decomposed[0].clone(),
            BPart::L => decomposed[1].clone(),
        };
        Ok(output.assigned_result)
    }

    /// This is exactly like [`PackedChip::assign_bootstrap2`] but handles the
    /// general case of up to two "corrupted" bits
    ///
    /// The input is
    /// w = a_1b_1c_1 a_2b_2c_2 ..... a_mb_mc_m
    /// and is decomposed to
    ///
    /// a = 00a_1_00a_2_.....00a_m (high bits).
    /// b = 00b_1_00b_2_.....00b_m (middle bits).
    /// c = 00c_1_00c_2_.....00c_m (low bits).
    /// The output is one of the values with (possibly) the rotation
    ///
    /// The layout is as follows:
    /// | res |  acc   |     limbs       |
    /// |-----|--------|-----------------|
    /// |  a  |  acc0  |  ...limbs_a...  |
    /// |  b  |  acc1  |  ...limbs_b...  |
    /// |  c  |  acc2  |  ...limbs_c...  |
    ///
    /// The following constraints are applied:
    ///
    /// 1. a is a valid spread word (via limb decomposition of limbs_a)
    /// 2. b, is a valid spread word (via limb decomposition of limbs_b)
    /// 3. c, is a valid spread word (via limb decomposition of limbs_c)
    /// 4. acc1 = b + 2 acc0 (b + 2a)
    /// 5. acc2 = c + 2 acc1 (c + 2b + 4acc0 = c + 2b + 4a)
    /// 6. acc0 = a (equality constraint)
    ///
    /// Recall that the input *is not equality constrained* and should be
    /// further constraint.
    pub(crate) fn assign_bootstrap3(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        w: &Value<SpreadBits>,
        rot: usize,
        output: BPart,
    ) -> Result<AssignedSpreadBits<F>, Error> {
        // get the spread parts
        let parts = w.clone().map(|bits| bits.spread_parts()).transpose_vec(SPREAD_BASE_BITS);

        // do not panic since they are parts which have only the least significant bits
        // non-zero
        let high = parts[BPart::H as usize].clone().map(|v| v.try_to_lane().unwrap());
        let middle = parts[BPart::M as usize].clone().map(|v| v.try_to_lane().unwrap());
        let low = parts[BPart::L as usize].clone().map(|v| v.try_to_lane().unwrap());

        // assign the spread limb decomposition
        // this handles constraints 1, 2, 3
        let decomposed = [
            self.assign_spread_decomposition(region, offset, &high, rot)?,
            self.assign_spread_decomposition(region, offset + 1, &middle, rot)?,
            self.assign_spread_decomposition(region, offset + 2, &low, rot)?,
        ];

        // constrain the initial accumulator
        // this handles constraint 6 (a = acc0)
        let acc_col = self.config().bootstrap_subconfig.bootstrap_acc_col;
        decomposed[0].assigned_result.copy_advice(
            || "copy constraint initial accumulator for bootstraping",
            region,
            acc_col,
            offset,
        )?;

        // assign acc1
        let acc1 = decomposed[0]
            .assigned_result
            .value()
            .zip(decomposed[1].assigned_result.value())
            .map(|(h, m)| F::from(2) * h.to_field::<F>() + m.to_field::<F>());
        region.assign_advice(|| "assign accumulator 1", acc_col, offset + 1, || acc1)?;
        // assign acc2
        let acc2 = acc1
            .zip(decomposed[2].assigned_result.value())
            .map(|(acc1, l)| F::from(2) * acc1 + l.to_field::<F>());
        region.assign_advice(|| "assign accumulator 2", acc_col, offset + 2, || acc2)?;

        // assign the bootstrap_constraint
        // constraint 4: acc1 = b + acc0
        self.config().bootstrap_subconfig.q_bootstrap.enable(region, offset)?;

        // constraint 5: acc2 = c + 2acc1 = c + 2b + 4acc0 = c + 2b + 4a
        self.config().bootstrap_subconfig.q_bootstrap.enable(region, offset + 1)?;

        // get the part and its rotation based on output
        let result = decomposed[output as usize].clone();
        Ok(result.assigned_result)
    }
}
