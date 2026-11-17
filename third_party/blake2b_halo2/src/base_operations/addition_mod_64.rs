use midnight_proofs::plonk::Constraints;
use super::*;
use crate::base_operations::types::bit::AssignedBit;
use crate::base_operations::types::blake2b_word::{AssignedBlake2bWord, Blake2bWord};
use crate::base_operations::types::row::AssignedRow;

/// Config used to constrain addition mod 64-bits. It generates
/// a decomposed result in limbs, which will be used in one of the optimizations.
#[derive(Clone, Debug)]
pub(crate) struct AdditionMod64Config {
    carry: Column<Advice>,
    pub(crate) q_add: Selector,
    q_decompose: Selector,
    q_range: Selector,
}

impl AdditionMod64Config {
    /// Creates the necessary gate for the operation to be constrained
    /// The gate that will be used to check the sum of two numbers mod 2^64
    /// The gate is defined as:
    ///     sum mod 2 ^ 64 = full_number_result - full_number_x - full_number_y
    ///                     + carry * (1 << 64)
    ///    carry = carry * (1 - carry)
    ///
    /// Note that the full number is range checked to be a 64-bit number because we
    /// are using 8-bit limbs and the q_decompose and q_range selectors below.
    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        carry: Column<Advice>,
        q_decompose: Selector,
        q_range: Selector,
    ) -> Self {
        let q_add = meta.complex_selector();

        meta.create_gate("sum mod 2 ^ 64", |meta| {
            let q_add = meta.query_selector(q_add);
            let full_number_x = meta.query_advice(full_number_u64, Rotation(0));
            let full_number_y = meta.query_advice(full_number_u64, Rotation(1));
            let full_number_result = meta.query_advice(full_number_u64, Rotation(2));
            let carry = meta.query_advice(carry, Rotation(1));

            let constraints = vec![
                q_add.clone()
                    * (full_number_result - full_number_x - full_number_y
                        + carry.clone() * (Expression::Constant(F::from_u128(1u128 << 64)))),
                q_add * carry.clone() * (Expression::Constant(F::from_u128(1u128)) - carry),
            ];

            Constraints::without_selector(constraints)
        });

        Self {
            carry,
            q_add,
            q_decompose,
            q_range,
        }
    }

    /// This method receives two cells, copies the values of the cells to the trace and then
    /// calculates the result and carry of the addition and write it in a third row.
    ///
    /// When one of the addition parameters (previous_cell)
    /// is the last cell that was generated in the circuit, by setting the [use_last_cell_as_first_operand]
    /// to [true] we can avoid copying the value of previous_cell again, and just copy the cell_to_copy.
    /// This saves one row per addition.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generate_addition_rows_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        previous_cell: &AssignedBlake2bWord<F>,
        cell_to_copy: &AssignedBlake2bWord<F>,
        use_last_cell_as_first_operand: bool,
        full_number_u64_column: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Result<(AssignedRow<F>, AssignedBit<F>), Error> {
        let (result_value, carry_value) =
            Self::calculate_result_and_carry(previous_cell.value(), cell_to_copy.value());
        let offset_to_enable = *offset - if use_last_cell_as_first_operand { 1 } else { 0 };
        self.q_add.enable(region, offset_to_enable)?;

        if !use_last_cell_as_first_operand {
            AssignedBlake2bWord::copy_advice_word(
                previous_cell,
                region,
                full_number_u64_column,
                *offset,
                "Sum first operand",
            )?;
            *offset += 1;
        }
        AssignedBlake2bWord::copy_advice_word(
            cell_to_copy,
            region,
            full_number_u64_column,
            *offset,
            "Sum second operand",
        )?;

        let carry_cell =
            AssignedBit::assign_advice_bit(region, "carry", self.carry, *offset, carry_value)?;
        *offset += 1;

        self.q_decompose.enable(region, *offset)?;
        self.q_range.enable(region, *offset)?;
        let result_row = generate_row_from_word_value(
            region,
            result_value,
            *offset,
            full_number_u64_column,
            limbs,
        )?;
        *offset += 1;

        Ok((result_row, carry_cell))
    }

    /// Given 2 operand values, known at proof generation time, returns the values holding the
    /// result of that sum mod 2^64 and the carry value, which must be 0 or 1. Both ranges will be
    /// constrained by this gate.
    fn calculate_result_and_carry<F: PrimeField>(
        lhs: Value<Blake2bWord>,
        rhs: Value<Blake2bWord>,
    ) -> (Value<Blake2bWord>, Value<F>) {
        let result_value = lhs.and_then(|l| rhs.and_then(|r| Value::known(Self::sum_mod_64(l, r))));
        let carry_value =
            lhs.and_then(|l| rhs.and_then(|r| Value::known(Self::carry_mod_64(l, r))));
        (result_value, carry_value)
    }

    fn sum_mod_64(a: Blake2bWord, b: Blake2bWord) -> Blake2bWord {
        (((a.0 as u128 + b.0 as u128) % (1u128 << 64)) as u64).into()
    }

    fn carry_mod_64<F: PrimeField>(a: Blake2bWord, b: Blake2bWord) -> F {
        let carry = (a.0 as u128 + b.0 as u128) / (1u128 << 64);
        F::from(carry as u64)
    }
}
