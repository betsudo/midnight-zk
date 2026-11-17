use std::ops::BitXor;
use ff::PrimeField;
use midnight_proofs::circuit::{Cell, Region, Value};
use midnight_proofs::plonk::{Advice, Column, Error};
use midnight_proofs::utils::rational::Rational;
use super::*;

/// The inner type of AssignedByte. A wrapper around `u8`
#[derive(Copy, Clone, Debug)]
pub struct Byte(pub u8);

impl Byte {
    /// Creates a new [Byte] element. When the byte is created, it is constrained to be in the
    /// range [0, 255].
    pub(crate) fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from(255u8)); //[zhiyong]: no need to check in CPU, since it will be constrained in the circuit anyway
        Byte(bi_v.to_bytes_le().first().copied().unwrap())
    }
}

impl BitXor for Byte {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Allows us to call the .assign_advice() method of the region with a Byte as its value
impl<F: PrimeField> From<&Byte> for Rational<F> {
    fn from(value: &Byte) -> Self {
        Self::Trivial(F::from(value.0 as u64))
    }
}

/// This wrapper type on `AssignedCell<Byte, F>` is designed to enforce type safety
/// on assigned bytes. It prevents the user from creating an `AssignedByte`
/// without using the designated entry points, which guarantee (with
/// constraints) that the assigned value is indeed in the range [0, 256).
#[derive(Clone, Debug)]
pub struct AssignedByte<F: PrimeField>(AssignedCell<Byte, F>);

impl<F: PrimeField> AssignedByte<F> {
    /// This method takes an [AssignedNative], copies it to another cell in the circuit as an
    /// [AssignedByte]. The range-check is performed in synthesize time, but
    /// WARNING: the caller of this method should allways constrain the value to be a byte in the
    /// circuit. That's why only the base operations can create an [AssignedByte] from a Field value,
    /// since they're responsible to activate the constraints over the cells in the trace.
    pub(crate) fn copy_advice_byte_from_native(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        cell_to_copy: AssignedNative<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = cell_to_copy.value().map(|v| Byte::new_from_field(*v));
        // Create AssignedCell with the same value but different type
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        // Constrain cells have equal values
        region.constrain_equal(cell_to_copy.cell(), assigned_byte.cell())?;

        Ok(assigned_byte)
    }

    /// This method takes an [AssignedByte], and copies it to another cell in the circuit.
    /// The range-check is not needed here, since we're copying a cell that should already have
    /// been constrained.
    pub(crate) fn copy_advice_byte(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        cell_to_copy: AssignedByte<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let byte_value = cell_to_copy.0.value().map(|v| Byte(v.0));
        // Create AssignedCell with the same value but different type
        let assigned_byte =
            Self(region.assign_advice(|| annotation, column, offset, || byte_value)?);
        // Constrain cells have equal values
        region.constrain_equal(cell_to_copy.cell(), assigned_byte.cell())?;

        Ok(assigned_byte)
    }

    /// Given a Byte value, it creates an [AssignedBlake2bWord] with its value.
    /// WARNING: this method is only available to the base operations because they should make sure
    /// that constrains over the byte values of these cells are enforced.
    pub(crate) fn assign_advice_byte(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        byte_value: Value<Byte>,
    ) -> Result<AssignedByte<F>, Error> {
        Ok(Self(region.assign_advice(|| annotation, column, offset, || byte_value)?))
    }

    /// Gets the inner cell of an assigned byte.
    pub fn cell(&self) -> Cell {
        self.0.cell()
    }

    /// Gets the inner value of an assigned byte.
    pub fn value(&self) -> Value<Byte> {
        self.0.value().cloned()
    }
}

impl<F: PrimeField> From<AssignedByte<F>> for AssignedCell<Byte, F> {
    fn from(value: AssignedByte<F>) -> Self {
        value.0
    }
}
