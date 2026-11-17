use midnight_proofs::plonk::Constraints;
use super::*;
use num_bigint::BigUint;
use crate::base_operations::types::blake2b_word::AssignedBlake2bWord;

/// This config handles the 63-right-bit rotation of a 64-bit number, which is the same as the
/// 1-bit rotation to the left.
///
/// For the gate of this config to be sound, it is necessary that the modulus of the field is
/// greater than 2^65.
///
/// This gate assumes that the input will already be range checked in the circuit and this allows us
/// to avoid making duplicate constraints. This condition holds in the context of Blake2b usage,
/// because every time a rot63 operation appears is after a xor operation, and rot63 reuses the
/// last row from the xor, which is the result, and therefore is range checked by the xor operation.
#[derive(Clone, Debug)]
pub(crate) struct Rotate63Config {
    pub q_rot63: Selector,
    q_decompose: Selector,
    q_range: Selector,
}

impl Rotate63Config {
    /// The gate that will be used to rotate a number 63 bits to the right
    /// The gate is defined as:
    ///    0 = 2 * input_full_number - output_full_number
    ///                      * (2 * input_full_number - output_full_number - (1 << 64 - 1))
    pub(crate) fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        full_number_u64: Column<Advice>,
        q_decompose: Selector,
        q_range: Selector,
    ) -> Self {
        Self::enforce_modulus_size::<F>();

        let q_rot63 = meta.complex_selector();

        meta.create_gate("rotate right 63", |meta| {
            let q_rot63 = meta.query_selector(q_rot63);
            let input_full_number = meta.query_advice(full_number_u64, Rotation(-1));
            let output_full_number = meta.query_advice(full_number_u64, Rotation(0));
            let constraints = vec![
                q_rot63
                    * (Expression::Constant(F::from(2)) * input_full_number.clone()
                        - output_full_number.clone())
                    * (Expression::Constant(F::from(2)) * input_full_number
                        - output_full_number
                        - Expression::Constant(F::from(((1u128 << 64) - 1) as u64))),
            ];
            Constraints::without_selector(constraints)
        });

        Self {
            q_rot63,
            q_decompose,
            q_range,
        }
    }

    /// This method receives a [AssignedBlake2bWord] and a [full_number_u64] column where it will be
    /// copied. In the same column, the result is placed in the next row. The gate constrains the
    /// result.
    pub(crate) fn generate_64_bit_rotation_from_cells<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        input: &AssignedBlake2bWord<F>,
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Result<AssignedBlake2bWord<F>, Error> {
        self.q_rot63.enable(region, *offset)?;
        let result_value = input.value().map(|input| rotate_right_field_element(input, 63));

        self.q_decompose.enable(region, *offset)?;
        self.q_range.enable(region, *offset)?;
        let result_row =
            generate_row_from_word_value(region, result_value, *offset, full_number_u64, limbs)?;
        *offset += 1;
        Ok(result_row.full_number)
    }

    /// Enforces the field's modulus to be greater than 2^65. This is necessary to preserve the
    /// soundness of a circuit that uses this operation.
    pub(crate) fn enforce_modulus_size<F: PrimeField>() {
        let modulus_bytes: Vec<u8> = hex::decode(F::MODULUS.trim_start_matches("0x"))
            .expect("Modulus is not a valid hex number");
        let modulus = BigUint::from_bytes_be(&modulus_bytes);
        let two_pow_65 = BigUint::from(1u128 << 65);
        assert!(modulus > two_pow_65, "Field modulus must be greater than 2^65");
    }
}
