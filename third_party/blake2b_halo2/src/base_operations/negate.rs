use midnight_proofs::plonk::Constraints;
use crate::base_operations::types::blake2b_word::AssignedBlake2bWord;
use super::*;

/// This config handles the bitwise negation of a 64-bit number.
///
/// This gate assumes that the input
/// will already be range checked in the circuit. This is true in the context of Blake2b usage, and
/// allows us to avoid making duplicate constraints over both input and result.
#[derive(Clone, Debug)]
pub(crate) struct NegateConfig {
    q_negate: Selector,
}

impl NegateConfig {
    /// The gate that will be used to negate a number
    /// The gate is defined as:
    ///    negate = (1 << 64) - 1 - value - not_value
    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
    ) -> Self {
        let q_negate = meta.complex_selector();

        meta.create_gate("negate", |meta| {
            let q_negate = meta.query_selector(q_negate);
            let value = meta.query_advice(full_number_u64, Rotation(0));
            let not_value = meta.query_advice(full_number_u64, Rotation(1));

            let constraints = vec![
                q_negate
                    * (Expression::Constant(F::from_u128((1u128 << 64) - 1)) - value - not_value),
            ];
            Constraints::without_selector(constraints)
        });

        Self { q_negate }
    }

    /// This method receives a [AssignedBlake2bWord] and a [full_number_column] where it will be
    /// copied. In the same column, the result is placed in the next row. The gate constrains the
    /// result.
    pub(crate) fn generate_rows_from_cell<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        input: &AssignedBlake2bWord<F>,
        full_number_column: Column<Advice>,
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.q_negate.enable(region, *offset)?;
        AssignedBlake2bWord::copy_advice_word(
            input,
            region,
            full_number_column,
            *offset,
            "Negation input",
        )?;
        *offset += 1;

        let result_value: Value<Blake2bWord> =
            input.value().map(|input| Blake2bWord(u64::MAX) - input);

        let result_cell = region
            .assign_advice(|| "Negation output", full_number_column, *offset, || result_value)?
            .into();

        *offset += 1;
        Ok(result_cell)
    }
}
