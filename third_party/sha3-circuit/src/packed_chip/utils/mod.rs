//! Utilitis and types for handling bits and their dense and spread forms.

use std::fmt::Debug;

use ff::PrimeField;
use midnight_proofs::{circuit::AssignedCell, plonk::Error, utils::rational::Rational};
#[cfg(test)]
use num_bigint::BigUint;

use crate::packed_chip::SPREAD_BASE_BITS;

#[cfg(test)]
/// Decompose the given field element into big-endian bits.
fn fe_to_be_bits<F: PrimeField>(v: &F) -> Vec<bool> {
    let bi = BigUint::from_bytes_le(v.to_repr().as_ref());
    (0..F::NUM_BITS as u64).map(|i| bi.bit(i)).rev().collect()
}

#[cfg(test)]
/// Convert bool slices to field element.
///
/// Returns [`Error::InvalidInstances`] if the input slice contains more bit
/// that what can fit on a field element
fn try_be_bits_to_fe<F: PrimeField>(bits: &[bool]) -> Result<F, Error> {
    if bits.len() as u32 > F::NUM_BITS {
        return Err(Error::InvalidInstances);
    }

    let mut repr = F::from(0).to_repr();
    let view = repr.as_mut();

    let rev_bits = bits.iter().copied().rev().collect::<Vec<_>>();
    let bytes = rev_bits.chunks(8).map(|bits| {
        bits.iter()
            .enumerate()
            .fold(0u8, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
    });
    for (byte, repr) in bytes.zip(view.iter_mut()) {
        *repr = byte
    }

    Ok(F::from_repr(repr).unwrap())
}

/// Struct representing numbers in the set [0, 2^upper_bound) as bit vectors.
/// The invariant inner.len() == upper_bound should *always* be preserved.
///     
/// We always consider big endianness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Bits {
    inner: Vec<bool>,
    upper_bound: usize,
}

impl TryFrom<Bits> for Vec<bool> {
    type Error = Error;

    /// # Errors
    ///
    /// Returns [`Error::InvalidInstances`] if the inner slice's length is not
    /// equal to the bound.
    fn try_from(value: Bits) -> Result<Self, Self::Error> {
        if value.inner.len() != value.upper_bound {
            return Err(Error::InvalidInstances);
        }
        Ok(value.inner)
    }
}

impl From<&[bool]> for Bits {
    fn from(value: &[bool]) -> Self {
        let upper_bound = value.len();
        Bits {
            inner: value.to_owned(),
            upper_bound,
        }
    }
}

impl Bits {
    /// Creates [`Bits`] from a u64 v in [0, 2^bound).
    ///     
    /// # Errors
    ///
    /// Returns [`Error::InvalidInstances`] if the bit represent a bigger number
    /// than 2^upper_bound or upper_bound is 0
    pub(super) fn try_from_u64(value: u64, upper_bound: usize) -> Result<Self, Error> {
        let mut inner = vec![false; upper_bound];

        // When bound < 64 then 1 << bound does not overflow
        // When bound == 64 we short-circuit so it never overflows
        if (upper_bound < 64 && value >= (1 << upper_bound)) || upper_bound == 0 {
            return Err(Error::InvalidInstances);
        } else {
            for (i, b) in inner.iter_mut().rev().enumerate() {
                *b = (value >> i) & 1 == 1
            }
        }
        Ok(Bits { inner, upper_bound })
    }

    #[cfg(test)]
    /// Creates [`Bits`] from a field element v in [0, 2^bound).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInstances`] if value represents a number greater
    /// than 2^upper_bound
    pub(super) fn try_from_f<F: PrimeField>(value: F, upper_bound: usize) -> Result<Self, Error> {
        // Check that the element respects the bound
        let bi = BigUint::from_bytes_le(value.to_repr().as_ref());
        if bi >= BigUint::from(1u32) << upper_bound {
            return Err(Error::InvalidInstances);
        }

        let inner = fe_to_be_bits(&value).iter().rev().take(upper_bound).rev().copied().collect();

        // keep only the last upper_bound bits
        Ok(Bits { inner, upper_bound })
    }

    /// coverts a number represented in bits to a field element
    pub(super) fn to_field<F: PrimeField>(&self) -> F {
        self.inner.iter().fold(F::ZERO, |acc, &bit| {
            acc * F::from(2u64) + F::from(bit as u64)
        })
    }
}

/// Wrapper type representing dense bits (base 2)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenseBits(Bits);

impl From<u8> for DenseBits {
    fn from(byte: u8) -> DenseBits {
        let bits = Bits::try_from_u64(byte as u64, 8).unwrap();
        DenseBits(bits)
    }
}

impl From<&Bits> for DenseBits {
    fn from(bits: &Bits) -> DenseBits {
        DenseBits(bits.to_owned())
    }
}

impl From<Bits> for DenseBits {
    fn from(bits: Bits) -> DenseBits {
        DenseBits(bits)
    }
}

impl DenseBits {
    /// creates the zero [`DenseBits`] representation
    fn zero() -> Self {
        let bits = Bits::try_from_u64(0, 64).unwrap();
        DenseBits::from(bits)
    }

    /// creates [`DenseBits`] from a u64 v in [0, 2^bound)
    pub(super) fn try_from_u64(value: u64, upper_bound: usize) -> Result<Self, Error> {
        let bits = Bits::try_from_u64(value, upper_bound)?;
        Ok(DenseBits::from(bits))
    }

    /// coverts a number represented in bits to a field element
    pub(super) fn to_field<F: PrimeField>(&self) -> F {
        self.0.to_field()
    }

    /// Creates a spread representation of a value
    pub(super) fn spread(&self) -> SpreadBits {
        let dense_upper_bound = self.0.upper_bound;
        let spread_upper_bound = SPREAD_BASE_BITS * self.0.upper_bound;
        let mut bits = Bits {
            inner: vec![false; spread_upper_bound],
            upper_bound: spread_upper_bound,
        };
        for i in 0..dense_upper_bound {
            bits.inner[SPREAD_BASE_BITS * i + (SPREAD_BASE_BITS - 1)] = self.0.inner[i];
        }
        SpreadBits(bits)
    }

    /// converts dense bits to a u64 representing a lane
    pub fn to_lane(&self) -> u64 {
        let bits: Vec<bool> = self.0.clone().try_into().unwrap();
        bits.iter().fold(0u64, |acc, &b| if b { 2 * acc + 1 } else { 2 * acc })
    }
}

/// Wrapper type representing spread bits (base 2)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpreadBits(Bits);

impl From<&Bits> for SpreadBits {
    fn from(bits: &Bits) -> SpreadBits {
        SpreadBits(bits.to_owned())
    }
}

impl From<Bits> for SpreadBits {
    fn from(bits: Bits) -> SpreadBits {
        SpreadBits(bits)
    }
}

impl SpreadBits {
    /// creates [`SpreadBits`] from a u64 v in [0, 2^bound)
    pub(super) fn try_from_u64(value: u64, upper_bound: usize) -> Result<Self, Error> {
        DenseBits::try_from_u64(value, upper_bound).map(|d| d.spread())
    }

    /// creates the zero [`SpreadBits`] representation
    pub(super) fn zero() -> Self {
        DenseBits::zero().spread()
    }

    /// creates the zero [`SpreadBits`] representation
    pub(super) fn rotate_right(&self, rot: usize) -> Self {
        let mut inner = self.0.inner.clone();
        inner.rotate_right(SPREAD_BASE_BITS * rot);
        SpreadBits(Bits {
            inner: inner.clone(),
            upper_bound: inner.len(),
        })
    }

    /// Convertes a spread word (with no errors) to little endian bytes.
    /// The bytes are represented as u64 values
    pub(super) fn try_to_le_bytes(&self) -> Result<[u64; 8], Error> {
        let lane = self.try_to_lane()?;
        Ok(lane.to_le_bytes().map(|v| v as u64))
    }

    /// Given the spread form that is possibly "noisy", it creates a vector
    /// of [`DenseBits`] where the i-th element contains the
    /// bits in positions i + k * SPREAD_BASE_BITS
    fn dense_parts(&self) -> Vec<DenseBits> {
        // sanity check
        debug_assert_eq!(self.0.upper_bound % SPREAD_BASE_BITS, 0);

        // the bound for the resulting dense words
        let upper_bound = self.0.upper_bound / SPREAD_BASE_BITS;
        let mut parts = Vec::with_capacity(SPREAD_BASE_BITS);

        for i in 0..SPREAD_BASE_BITS {
            let inner = self
                .0
                .inner
                .iter()
                .skip(i)
                .step_by(SPREAD_BASE_BITS)
                .copied()
                .collect::<Vec<_>>();
            parts.push(Bits { inner, upper_bound });
        }
        parts.into_iter().map(DenseBits).collect()
    }

    /// Given the spread form that is possibly "noisy", it creates a vector
    /// of [`SpreadBits`] where the i-th element contains the
    /// bits in positions i + k * SPREAD_BASE_BITS
    ///
    /// This is the spread representation of the output of
    /// [`SpreadBits::dense_parts`].
    pub(super) fn spread_parts(&self) -> Vec<SpreadBits> {
        self.dense_parts().iter().map(|v| v.spread()).collect()
    }

    /// coverts a number represented in bits to a field element
    pub(super) fn to_field<F: PrimeField>(&self) -> F {
        self.0.to_field()
    }

    /// Converts spread bits to a u64 representing a lane.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInstances`] if the spread bits have error, i.e.
    /// if any bit group apart from the rightmost are non-zero.
    pub(super) fn try_to_lane(&self) -> Result<u64, Error> {
        let parts = self.dense_parts();
        for part in parts.iter().take(SPREAD_BASE_BITS - 1) {
            if part.to_lane() != 0 {
                return Err(Error::InvalidInstances);
            }
        }
        Ok(parts[SPREAD_BASE_BITS - 1].to_lane())
    }

    /// Bitwise add two [`SpreadBits`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInstances`] if the inputs are of different
    /// lengths.
    ///
    /// # Notes
    ///
    /// The accumulated error *is not checked*. The caller should be cautious to
    /// only call when the operation can be done without introducing too much
    /// error that will lose information.
    pub(super) fn try_add(&self, other: &SpreadBits) -> Result<SpreadBits, Error> {
        let a_bits: Vec<bool> = self.0.clone().try_into()?;
        let b_bits: Vec<bool> = other.0.clone().try_into()?;

        // sanity check. Only same length values should be added
        if a_bits.len() != b_bits.len() {
            return Err(Error::InvalidInstances);
        }

        let mut result = Vec::with_capacity(a_bits.len());
        let mut carry = 0u8;

        for i in (0..a_bits.len()).rev() {
            let sum = a_bits[i] as u8 + b_bits[i] as u8 + carry;
            result.push(sum % 2 == 1);
            carry = if sum > 1 { 1 } else { 0 };
        }
        result.reverse();
        let bits = Bits {
            inner: result,
            upper_bound: a_bits.len(),
        };

        Ok(SpreadBits::from(bits))
    }

    /// Multiply by two [`SpreadBits`]. This shifts the bits.
    ///
    /// # Notes
    ///
    /// The accumulated error *is not checked*. The caller should be cautious to
    /// only call when the operation can be done without introducing too much
    /// error that will lose information.
    pub(super) fn mul2(&self) -> Result<SpreadBits, Error> {
        let other = self.clone();
        self.try_add(&other)
    }

    /// Negate [`SpreadBits`]. The lsbs of the input are inverted.
    ///
    /// # Notes
    ///
    /// The accumulated error *is not checked*. The caller should be cautious to
    /// only call when the operation can be done without introducing too much
    /// error that will lose information.
    pub(super) fn negate(&self) -> Result<SpreadBits, Error> {
        let bits: Vec<bool> = self.clone().0.try_into()?;
        let result = bits
            .iter()
            .enumerate()
            .map(|(i, x)| {
                if i % SPREAD_BASE_BITS == SPREAD_BASE_BITS - 1 {
                    !x
                } else {
                    *x
                }
            })
            .collect::<Vec<_>>();
        let bits = Bits {
            inner: result,
            upper_bound: bits.len(),
        };
        Ok(SpreadBits::from(bits))
    }
}

/// Type alias for the assigned version of [`SpreadBits`]
/// Type alias for the assigned version of [`DenseBits`]
pub(super) type AssignedDenseBits<F> = AssignedCell<DenseBits, F>;

/// Type alias for the assigned version of [`SpreadBits`]
pub(super) type AssignedSpreadBits<F> = AssignedCell<SpreadBits, F>;

impl<F: PrimeField> From<&DenseBits> for Rational<F> {
    fn from(bits: &DenseBits) -> Rational<F> {
        bits.0.to_field::<F>().into()
    }
}

impl<F: PrimeField> From<DenseBits> for Rational<F> {
    fn from(bits: DenseBits) -> Rational<F> {
        bits.0.to_field::<F>().into()
    }
}

impl<F: PrimeField> From<&SpreadBits> for Rational<F> {
    fn from(bits: &SpreadBits) -> Rational<F> {
        bits.0.to_field::<F>().into()
    }
}

impl<F: PrimeField> From<SpreadBits> for Rational<F> {
    fn from(bits: SpreadBits) -> Rational<F> {
        bits.0.to_field::<F>().into()
    }
}

#[cfg(test)]
mod tests;
