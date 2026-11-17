//! Basic types for the blake2b chip.

/// This module holds types that exist across our code to explicitly state that a value is in a
/// given range. Everytime you see an AssignedBit, AssignedByte, AssignedBlake2bWord or AssignedRow,
/// you can be certain that all their values were range checked (both in the synthesize and in the
/// circuit constraints).
///
/// All these types are created in a context where its value has been constrained by a circuit
/// restriction to be in range.
use ff::PrimeField;
use midnight_proofs::circuit::AssignedCell;
use num_bigint::BigUint;

/// Native type for an [AssignedCell] that hasn't been constrained yet
pub type AssignedNative<F> = AssignedCell<F, F>;

/// Module for assigned bits.
pub mod bit;
/// Module for assigned bytes.
pub mod byte;
/// Module for assigned blake2b words.
pub mod blake2b_word;
/// Module for assigned blake2b rows.
pub mod row;

/// Given a field element and a limb index in little endian form, this function checks that the
/// field element is in range [0, 2^64-1]. If it's not, it will fail.
/// We assume that the internal representation of the field is in little endian form. If it's
/// not, the result is undefined and probably incorrect.
/// Finally, it returns a [BigUint] holding the field element value.
fn get_word_biguint_from_le_field<F: PrimeField>(fe: F) -> BigUint {
    let field_internal_representation = fe.to_repr(); // Should be in little-endian
    let (bytes, zeros) = field_internal_representation.as_ref().split_at(8);

    let field_is_out_of_range = zeros.iter().any(|&el| el != 0u8);

    if field_is_out_of_range {
        panic!("Arguments to the function are incorrect")
    } else {
        BigUint::from_bytes_le(bytes)
    }
}
