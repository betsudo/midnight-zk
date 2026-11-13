//! Module to assign a spread lane by 8 assigned (dense) bytes.

use ff::PrimeField;
use midnight_proofs::{
    circuit::{Chip, Region, Value},
    plonk::Error,
};

use crate::{
    constants::KECCAK_BYTES_PER_LANE,
    packed_chip::{
        utils::{AssignedDenseBits, AssignedSpreadBits, DenseBits, SpreadBits},
        PackedChip,
    },
};

impl<F: PrimeField> PackedChip<F> {
    /// Helper function that takes as input 8 (dense) bytes [b0..b7] and the
    /// combined spread word (spread(b7b6..b0)) and applies the constraints
    /// to assert they are consistent.
    ///
    /// On input b0,...,b7 and denoting the spread values ~bi,
    /// the layout is as follows:
    ///
    /// |offset| recomposition | intermediate |   l0   | ... |   l3   |
    /// |------|---------------|--------------|--------|-----|--------|
    /// |   0  |      X        |       X      |   b7   | ... |   b4   |
    /// |   1  |     ~r1       |       0      |  ~b7   | ... |  ~b4   |
    /// |   2  |      X        |       X      |   b3   | ... |   b0   |
    /// |   3  |     ~r2       |     ~r1      |  ~b3   | ... |  ~b0   |
    ///
    /// The following constraints are applied:
    /// 1. (8, bi, ~bi) in table
    /// 2. intermediate at offset 1 is 0
    /// 3. intermediate at offset 3 = recomposition at offset 1
    /// 4. 8^32 * 0 + 8^24 * b7 + 8^16 * b6 + 8^8 * b5 + 8^0 * b4 = ~r1
    /// 5. 8^32 * ~r1 + 8^24 * b3 + 8^16 * b2 + 8^8 * b1 + 8^0 * b0 = ~r2
    ///
    ///
    /// The function returns:
    /// 1. the assigned result (~r2).
    /// 2. the assigned dense bytes ([b0, ..., b7])
    pub(crate) fn assign_bytes_and_spread(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        bytes: &[Value<DenseBits>; KECCAK_BYTES_PER_LANE],
        lane: &Value<SpreadBits>,
    ) -> Result<
        (
            AssignedSpreadBits<F>,
            [AssignedDenseBits<F>; KECCAK_BYTES_PER_LANE],
        ),
        Error,
    > {
        // assign the given dense limbs corresponding to bytes
        let assigned_dense: [AssignedDenseBits<F>; KECCAK_BYTES_PER_LANE] = bytes
            .iter()
            // we reverse to start from the msbs
            .rev()
            .enumerate()
            .map(|(i, b)|
                // we assign msb first 
                region.assign_advice(
                    || "assign bytes to be looked-up",
                    self.config().bytes_to_spread_subconfig.limbs[i % 4],
                    offset + 2 * (i / 4),
                    || b.clone()
                ))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        // spread the limbs "vertically" in the next row
        let _assigned_spread = assigned_dense
            .iter()
            .enumerate()
            .map(|(i, b)| {
                region.assign_advice(
                    || "assign spread bytes for lookup",
                    self.config().bytes_to_spread_subconfig.limbs[i % 4],
                    offset + 2 * (i / 4) + 1,
                    || b.value().map(|d| d.spread()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // assign the intermediate result in the recomposition column
        let intermediate_lane = bytes
            .iter()
            // we need the 4 most significant bits
            .skip(4)
            // we reverse to take the msb first
            .rev()
            .fold(Value::known(0u64), |acc, v| {
                acc.zip(v.clone().map(|v| v.to_lane())).map(|(acc, v)| acc * 256 + v)
            })
            .map(|lane|
                // the unwrap never happens since lane is the combination of 4 bytes
                SpreadBits::try_from_u64(lane, 32).unwrap());

        let assigned_intermediate = region.assign_advice(
            || "assign zero as the intermediate result",
            self.config().bytes_to_spread_subconfig.recomposition,
            offset + 1,
            || intermediate_lane.clone(),
        )?;

        // 2. intermediate at offset 1 is 0
        region.assign_advice_from_constant(
            || "assign intermediate result for hi bytes to 0",
            self.config().bytes_to_spread_subconfig.intermediate,
            offset + 1,
            F::ZERO,
        )?;

        // 3. intermediate at offset 3 = recomposition at offset 1
        assigned_intermediate.copy_advice(
            || "copy intermediate result for lo bytes",
            region,
            self.config().bytes_to_spread_subconfig.intermediate,
            offset + 3,
        )?;

        // assign the spread lane (computation result)
        let assigned_lane = region.assign_advice(
            || "assign spread lane",
            self.config().bytes_to_spread_subconfig.recomposition,
            offset + 3,
            || lane.clone(),
        )?;

        // enable the q_bytes_to_lane selector to handle the remaining constraints:
        // 1. (8, bi, ~bi) in table
        // 4. 2^32 * 0 + 2^24 * b7 + 2^16 * b6 + 2^8 * b5 + 2^0 * b4 = ~r1
        // 5. 2^32 * ~r1 + 2^24 * b3 + 2^16 * b2 + 2^8 * b1 + 2^0 * b0 = ~r2
        self.config().bytes_to_spread_subconfig.q_bytes_to_lane.enable(region, offset)?;
        self.config()
            .bytes_to_spread_subconfig
            .q_bytes_to_lane
            .enable(region, offset + 2)?;

        // reverse the dense byte to have them in le form
        let assigned_dense =
            assigned_dense.into_iter().rev().collect::<Vec<_>>().try_into().unwrap();

        Ok((assigned_lane, assigned_dense))
    }

    /// Takes as input a spread lane and converts it to dense bytes.
    ///
    /// It simply calls [`Self::assign_bytes_and_spread_helper`]
    /// to assigned the dense bytes and apply the constraints, and
    /// copy constraints the result w.r.t. the given input.
    ///
    /// It assumes the spread bits have no accumulated error.
    pub(crate) fn convert_spread_lane_to_bytes(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        input_lane: &AssignedSpreadBits<F>,
    ) -> Result<[AssignedDenseBits<F>; KECCAK_BYTES_PER_LANE], Error> {
        // extract the byte values
        let byte_values = input_lane
            .value()
            .map(|v|
            // never panics in the honest case since v is derived from a u64 word
            v.try_to_le_bytes().unwrap()
                .map(|v| DenseBits::try_from_u64(v, 64).unwrap()))
            .transpose_vec(KECCAK_BYTES_PER_LANE);

        // apply the constraints for the conversion
        let (computed_lane, computed_bytes) = self.assign_bytes_and_spread(
            region,
            offset,
            &byte_values.try_into().unwrap(),
            &input_lane.value().cloned(),
        )?;

        // the computed_lane must be equal to the input_lane to assert the
        // computed_bytes corresponds to the dense bytes form of the input_lane
        region.constrain_equal(computed_lane.cell(), input_lane.cell())?;

        Ok(computed_bytes)
    }
}
