use super::*;
use midnight_curves::bls12_381::Fq;
use ff::Field;
use std::marker::PhantomData;
use crate::base_operations::{
    create_limb_decomposition_gate, create_range_check_gate, generate_row_from_word_and_keep_row,
    populate_lookup_table,
};
use crate::types::AssignedNative;
use crate::types::blake2b_word::Blake2bWord;
use crate::types::row::AssignedRow;

mod test_blake2b;
mod test_negate;
mod tests_addition;
mod tests_rotation;
mod tests_xor;

pub(crate) fn one() -> Value<Fq> {
    Value::known(Fq::ONE)
}
pub(crate) fn zero() -> Value<Fq> {
    Value::known(Fq::ZERO)
}

pub(crate) fn blake2b_value_for(number: u64) -> Value<Blake2bWord> {
    Value::known(number.into())
}

pub(crate) fn value_for<T, F>(number: T) -> Value<F>
where
    T: Into<u128>,
    F: PrimeField,
{
    Value::known(F::from_u128(number.into()))
}

pub(crate) fn generate_row_8bits<T, F>(number: T) -> [Value<F>; 9]
where
    F: PrimeField,
    T: Into<u128>,
{
    let mut number: u128 = number.into();
    let mut ans = [Value::unknown(); 9];
    ans[0] = value_for(number);
    for ans_item in ans.iter_mut().take(9).skip(1) {
        *ans_item = value_for(number % 256);
        number /= 256;
    }
    ans
}

/// This config handles the decomposition of 64-bit numbers into 8-bit limbs in the trace,
/// where each limbs is range checked regarding the designated limb size.
/// T is the amount of limbs that the number will be decomposed into.
/// Little endian representation is used for the limbs.
/// We also expect F::Repr to be little endian in all usages of this trait.
#[derive(Clone, Debug)]
struct Decompose8Config {
    /// The full number and the limbs are not owned by the config.
    full_number_u64: Column<Advice>,
    /// There are 8 limbs of 8 bits each
    limbs: [Column<Advice>; 8],

    /// Selector that turns on the gate that defines if the limbs should add up to the full number
    q_decompose: Selector,

    /// Selector that turns on the gate that defines if the limbs should be range-checked
    q_range: Selector,

    /// Table of [0, 2^8) to check if the limb is in the correct range
    t_range: TableColumn,
}

impl Decompose8Config {
    /// Creates the corresponding gates and lookups to constrain range-checks and 8-limb
    /// decomposition of 64-bit numbers.
    fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        // The full number and the limbs are not owned by the config.
        full_number_u64: Column<Advice>,
        limbs: [Column<Advice>; 8],
    ) -> Self {
        let q_range = meta.complex_selector();
        let t_range = meta.lookup_table_column();
        let q_decompose = meta.complex_selector();

        // Gate that checks if the decomposition is correct
        create_limb_decomposition_gate(meta, q_decompose, full_number_u64, limbs);

        // Range checks for all the limbs (range [0,255])
        create_range_check_gate(meta, t_range, q_range, limbs);

        Self {
            full_number_u64,
            limbs,
            q_decompose,
            t_range,
            q_range,
        }
    }

    /// Fills the [t_range] table with values in the range [0,255]
    fn populate_lookup_table<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        populate_lookup_table(layouter, self.t_range)
    }
    /// Given an explicit vector of values, it assigns the full number and the limbs in a row of the trace
    /// row size is T + 1
    /// row[0] is the full number
    /// row[1..T] are the limbs representation of row[0]
    fn populate_row_from_values<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        row: &[Value<F>],
        offset: usize,
        check_decomposition: bool,
    ) -> Result<Vec<AssignedNative<F>>, Error> {
        if check_decomposition {
            self.q_decompose.enable(region, offset)?;
            self.q_range.enable(region, offset)?;
        }
        let full_number =
            region.assign_advice(|| "full number", self.full_number_u64, offset, || row[0])?;

        let limbs = (0..8)
            .map(|i| {
                region.assign_advice(|| format!("limb{}", i), self.limbs[i], offset, || row[i + 1])
            })
            .collect::<Result<Vec<_>, _>>()?;

        //return the full number and the limbs
        Ok(std::iter::once(full_number).chain(limbs).collect())
    }

    /// Method for generating a row from a value and keeping the full row.
    /// Given a Value, we might want to use it as an operand in the circuit, and sometimes we need
    /// to establish constraints over the result's limbs. That's why we need a way to retrieve the
    /// full row that was created from that value.
    fn generate_row_from_word_and_keep_row<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        value: Value<Blake2bWord>,
        offset: usize,
    ) -> Result<AssignedRow<F>, Error> {
        self.q_range.enable(region, offset)?;
        generate_row_from_word_and_keep_row(region, value, offset, self.full_number_u64, self.limbs)
    }
}
