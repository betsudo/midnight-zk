use super::*;
use ff::PrimeField;
use midnight_proofs::circuit::{AssignedCell, Cell, Region, Value};
use midnight_proofs::plonk::{Advice, Column, Error};
use midnight_proofs::utils::rational::Rational;
use std::ops::{BitXor, Sub};

/// The inner type of AssignedBlake2bWord. A wrapper around `u64`
#[derive(Copy, Clone, Debug)]
pub(crate) struct Blake2bWord(pub u64);

impl Blake2bWord {
    /// Creates a new [Blake2bWord] element. When the Blake2bWord is created, it is constrained to be in the
    /// range [0, 2^64 - 1].
    pub(crate) fn new_from_field<F: PrimeField>(field: F) -> Self {
        let bi_v = get_word_biguint_from_le_field(field);
        #[cfg(not(test))]
        assert!(bi_v <= BigUint::from((1u128 << 64) - 1));
        let mut bytes = bi_v.to_bytes_le();
        bytes.resize(8, 0);
        u64::from_le_bytes(bytes.try_into().unwrap()).into()
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl BitXor for Blake2bWord {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for Blake2bWord {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl From<u64> for Blake2bWord {
    /// An u64 has a trivial conversion into a [Blake2bWord]
    fn from(value: u64) -> Self {
        Blake2bWord(value)
    }
}

impl<F: PrimeField> From<AssignedCell<Blake2bWord, F>> for AssignedBlake2bWord<F> {
    fn from(value: AssignedCell<Blake2bWord, F>) -> Self {
        Self(value)
    }
}

/// Allows us to call the .assign_advice() method of the region with an Blake2bWord as its value
impl<F: PrimeField> From<&Blake2bWord> for Rational<F> {
    fn from(value: &Blake2bWord) -> Self {
        Self::Trivial(F::from(value.0))
    }
}

/// This wrapper type on `AssignedCell<Blake2bWord, F>` is designed to enforce type safety
/// on assigned Blake2bWords. It prevents the user from creating an [AssignedWord]
/// without using the designated entry points, which guarantee (with constraints) that the
/// assigned value is indeed in the range [0, 2^64 - 1].
#[derive(Clone, Debug)]
pub(crate) struct AssignedBlake2bWord<F: PrimeField>(AssignedCell<Blake2bWord, F>);

impl<F: PrimeField> AssignedBlake2bWord<F> {
    /// Method that copies an [AssignedBlake2bWord] in the trace into another cell.
    pub(crate) fn copy_advice_word(
        &self,
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        offset: usize,
        annotation: &str,
    ) -> Result<Self, Error> {
        let result = self.0.copy_advice(|| annotation, region, column, offset)?;
        Ok(Self(result))
    }

    /// Method that assigns a fixed word in the trace. It's safe to use because it's a constant,
    /// therefore it's constrained to a fixed value known by everyone.
    pub(crate) fn assign_fixed_word(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        word_value: Blake2bWord,
    ) -> Result<Self, Error> {
        let result =
            region.assign_advice_from_constant(|| annotation, column, offset, word_value)?;
        Ok(Self(result))
    }

    /// Given a value that contains a field element, this method converts it into a Blake2bWord and
    /// assigns the value into a cell. The word is range-checked both in circuit-building
    /// time (synthesize) and constrained in the circuit. The idea is that only the base operations
    /// can create an [AssignedBlake2bWord] from a Field value, since they're responsible to
    /// activate the constraints over the cells in the trace. In this case, the [Decompose8] gate
    /// is the responsible to create them.
    pub(crate) fn assign_advice_word_from_field(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        value: Value<F>,
    ) -> Result<Self, Error> {
        // Check value is in range
        let word_value = value.map(|v| Blake2bWord::new_from_field(v));
        // Create AssignedCell with the same value but different type
        Self::assign_advice_word(region, annotation, column, offset, word_value)
    }

    /// Given a value that contains a Blake2bWord, this method assigns the value into a cell
    pub(crate) fn assign_advice_word(
        region: &mut Region<'_, F>,
        annotation: &str,
        column: Column<Advice>,
        offset: usize,
        word_value: Value<Blake2bWord>,
    ) -> Result<Self, Error> {
        Ok(Self(region.assign_advice(|| annotation, column, offset, || word_value)?))
    }

    pub(crate) fn value(&self) -> Value<Blake2bWord> {
        self.0.value().cloned()
    }

    pub(crate) fn cell(&self) -> Cell {
        self.0.cell()
    }
}
