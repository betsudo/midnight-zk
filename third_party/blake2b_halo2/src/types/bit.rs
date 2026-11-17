use super::*;
use ff::PrimeField;
use midnight_proofs::circuit::{Region, Value};
use midnight_proofs::plonk::{Advice, Column, Error};
use midnight_proofs::utils::rational::Rational;

/// The inner type of AssignedBit. A wrapper around `bool`
#[derive(Copy, Clone, Debug)]
struct Bit(bool);

impl Bit {
    /// Creates a new [Bit] element. When the byte is created, it is constrained to be in the
    /// range [0, 1] and its internal member is a boolean.
    fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v == BigUint::from(0u8) || bi_v == BigUint::from(1u8));
        let bit = bi_v.to_bytes_le().first().copied().unwrap();
        Bit(bit == 1)
    }
}

/// Allows us to call the .assign_advice() method of the region with a Bit as its value
impl<F: PrimeField> From<&Bit> for Rational<F> {
    fn from(value: &Bit) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}

/// This wrapper type on `AssignedNative<F>` is designed to enforce type safety
/// on assigned bits. It is used in the addition chip to enforce that the
/// carry value is 0 or 1
#[must_use]
pub(crate) struct AssignedBit<F: PrimeField>(#[allow(dead_code)] AssignedCell<Bit, F>);

impl<F: PrimeField> AssignedBit<F> {
    /// This method assigns a bit in the trace. The bit is range-checked both in
    /// synthesize time and constrained in the circuit. The idea is that only the base operations
    /// can create an [AssignedBit] from a Field value, since they're responsible to activate the
    /// constraints over the cells in the trace. In this case, the AdditionMod64 gate is the
    /// responsible to create constraints over the carry bit, which will be represented by an
    /// [AssignedBit].
    pub(crate) fn assign_advice_bit(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        value: Value<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let bit_value = value.map(|v| Bit::new_from_field(v));
        // Create AssignedCell with the same value but different type
        let assigned_bit =
            Self(region.assign_advice(|| annotation, column, offset, || bit_value)?);
        Ok(assigned_bit)
    }
}

#[cfg(test)]
use midnight_proofs::circuit::Cell;
#[cfg(test)]
impl<F: PrimeField> AssignedBit<F> {
    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }
}
