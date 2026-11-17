use super::*;
use crate::base_operations::types::blake2b_word::AssignedBlake2bWord;
use crate::base_operations::types::byte::AssignedByte;
use crate::base_operations::types::row::AssignedRow;
use ff::PrimeField;
use midnight_proofs::circuit::Value;

/// This gate rotates the limbs of a number to the right and uses copy constrains to ensure that
/// the rotation is correct. It's used in our circuit to implement 16-bit, 24-bit and 32-bit rotations.
#[derive(Clone, Debug)]
pub(crate) struct LimbRotation {
    q_decompose: Selector,
}

impl LimbRotation {
    pub(crate) fn configure(q_decompose: Selector) -> Self {
        Self { q_decompose }
    }

    /// This method receives a row of cells, and rotates the limbs to the right by the number
    /// specified in the limbs_to_rotate_to_the_right parameter. It then constrains the output
    /// to be the correct rotation of the input.
    /// For this method to work, the input_row must be the last row of the trace at the moment
    /// the method is called
    pub(crate) fn generate_rotation_rows_from_input_row<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        input_row: AssignedRow<F>,
        limbs_to_rotate_to_the_right: usize,
        full_number_u64_column: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        let result_value =
            Self::right_rotation_value(input_row.full_number.value(), limbs_to_rotate_to_the_right);

        let result_cell = region
            .assign_advice(
                || "Full number rotation output",
                full_number_u64_column,
                *offset,
                || result_value,
            )?
            .into();

        self.q_decompose.enable(region, *offset)?;

        for i in 0..8 {
            // We must subtract limb_rotations_right because if a number is expressed bitwise
            // as x = l1|l2|...|l7|l8, the limbs are stored as [l8, l7, ..., l2, l1]
            let top_assigned_cell = input_row.limbs[i].clone();
            let out_limb_index = (8 + i - limbs_to_rotate_to_the_right) % 8;
            AssignedByte::copy_advice_byte(
                region,
                "Limb rotation output",
                limbs[out_limb_index],
                *offset,
                top_assigned_cell,
            )?;
        }

        *offset += 1;
        Ok(result_cell)
    }

    /// Computes the actual value of the rotation of the number
    fn right_rotation_value(
        value: Value<Blake2bWord>,
        limbs_to_rotate: usize,
    ) -> Value<Blake2bWord> {
        value.map(|input| {
            let bits_to_rotate = limbs_to_rotate * 8;
            rotate_right_field_element(input, bits_to_rotate)
        })
    }
}
