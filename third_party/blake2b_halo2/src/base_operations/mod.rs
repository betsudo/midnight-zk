use midnight_proofs::plonk::Constraints;
use super::*;
use crate::base_operations::types::blake2b_word::AssignedBlake2bWord;
use crate::base_operations::types::byte::{AssignedByte, Byte};
use crate::base_operations::types::row::AssignedRow;
use crate::base_operations::types::AssignedNative;
use types::blake2b_word::Blake2bWord;

pub mod addition_mod_64;
pub mod negate;
pub mod xor;

pub mod generic_limb_rotation;
pub mod rotate_63;

/// Given a [Blake2bWord], it returns another [Blake2bWord] with the original word rotated to the
/// right by 'rotation_degree' bits.
fn rotate_right_field_element(value_to_rotate: Blake2bWord, rotation_degree: usize) -> Blake2bWord {
    let value_to_rotate = value_to_rotate.0;
    let rotation_degree = rotation_degree % 64;
    let rotated_value = ((value_to_rotate as u128) >> rotation_degree)
        | ((value_to_rotate as u128) << (64 - rotation_degree));
    (rotated_value as u64).into()
}

/// Given an array of [AssignedNative] byte-values, it puts in the circuit a full row with those
/// bytes in the limbs and the resulting full number in the first column.
/// WARNING: this method doesn't set any constraints. That's the responsibility of the caller.
pub(crate) fn generate_row_from_assigned_bytes<F: PrimeField>(
    region: &mut Region<'_, F>,
    bytes: &[AssignedNative<F>; 8],
    offset: usize,
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
) -> Result<AssignedRow<F>, Error> {
    // Compute the full number from the limbs
    let full_number_cell = AssignedBlake2bWord::assign_advice_word_from_field(
        region,
        "full number",
        full_number_u64,
        offset,
        compute_full_value_u64_from_bytes(bytes),
    )?;

    let mut assigned_limbs = vec![];

    // Fill the row with copies of the limbs
    for (index, byte_cell) in bytes.iter().enumerate() {
        let assigned_byte = AssignedByte::copy_advice_byte_from_native(
            region,
            "Copied input byte",
            limbs[index],
            offset,
            byte_cell.clone(),
        )?;
        assigned_limbs.push(assigned_byte)
    }

    Ok(AssignedRow::new(full_number_cell, assigned_limbs.try_into().unwrap()))
}

/// Given a list of limb values, it returns the full number value that the limbs build up to.
fn compute_full_value_u64_from_bytes<F: PrimeField>(bytes: &[AssignedNative<F>; 8]) -> Value<F> {
    let mut full_number = F::ZERO;
    // We process the limbs from the most significant to the least significant
    for byte_cell in bytes.iter().rev() {
        byte_cell.value().and_then(|v| {
            full_number *= F::from(256u64);
            full_number += *v;
            Value::<F>::unknown()
        });
    }
    Value::known(full_number)
}

/// Given a cell with a 64-bit value, it creates a new row with the copied full number and the
/// decomposition in 8-bit limbs.
/// WARNING: this method doesn't set any constraints. That's the responsibility of the caller.
fn generate_row_from_cell<F: PrimeField>(
    region: &mut Region<'_, F>,
    cell: &AssignedBlake2bWord<F>,
    offset: usize,
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
) -> Result<AssignedRow<F>, Error> {
    let value = cell.value();
    let new_cells =
        generate_row_from_word_and_keep_row(region, value, offset, full_number_u64, limbs)?;
    region.constrain_equal(cell.cell(), new_cells.full_number.cell())?;
    Ok(new_cells)
}

/// Given a value of 64 bits, it generates a row with the assigned cells for the full number
/// and the limbs, and returns the full number
/// WARNING: this method doesn't set any constraints. That's the responsibility of the caller.
pub(crate) fn generate_row_from_word_value<F: PrimeField>(
    region: &mut Region<'_, F>,
    value: Value<Blake2bWord>,
    offset: usize,
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
) -> Result<AssignedRow<F>, Error> {
    generate_row_from_word_and_keep_row(region, value, offset, full_number_u64, limbs)
}

/// Method for generating a row from a value and returning the full row.
/// Given a Value, we might want to use it as an operand in the circuit, and sometimes we need
/// to establish constraints over the result's limbs. That's why we need a way to retrieve the
/// full row that was created from that value.
/// WARNING: this method doesn't set any constraints. That's the responsibility of the caller.
pub(crate) fn generate_row_from_word_and_keep_row<F: PrimeField>(
    region: &mut Region<'_, F>,
    value: Value<Blake2bWord>,
    offset: usize,
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
) -> Result<AssignedRow<F>, Error> {
    let limb_values: [Value<Byte>; 8] =
        (0..8).map(|i| get_limb_from(value, i)).collect::<Vec<_>>().try_into().unwrap();
    create_row_with_word_and_limbs(region, value, limb_values, offset, full_number_u64, limbs)
}

/// Given a value and a limb index, it returns the value of the limb
fn get_limb_from(value: Value<Blake2bWord>, limb_number: usize) -> Value<Byte> {
    value.map(|v| {
        let number = v.to_le_bytes()[limb_number];
        Byte(number)
    })
}

/// Given a full number and the values of the limbs. It creates a new row with these values.
/// WARNING: this method doesn't set any constraints. That's the responsibility of the caller.
pub(crate) fn create_row_with_word_and_limbs<F: PrimeField>(
    region: &mut Region<'_, F>,
    full_value: Value<Blake2bWord>,
    limb_values: [Value<Byte>; 8],
    offset: usize,
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
) -> Result<AssignedRow<F>, Error> {
    let full_number_cell = AssignedBlake2bWord::assign_advice_word(
        region,
        "full number",
        full_number_u64,
        offset,
        full_value,
    )?;

    let assigned_limbs: Vec<AssignedByte<F>> = limb_values
        .iter()
        .enumerate()
        .map(|(i, limb)| {
            AssignedByte::assign_advice_byte(region, "limb", limbs[i], offset, *limb).unwrap()
        })
        .collect::<Vec<_>>();

    Ok(AssignedRow::new(full_number_cell, assigned_limbs.try_into().unwrap()))
}

/// Creates a gate that constraints that a given 64-bit word decomposition is correct.
/// The equation that should hold is:
/// full_number - (sum [i=0..7] -> limbs[i] * (1 << (8*i)) ) == 0
pub(crate) fn create_limb_decomposition_gate<F: PrimeField>(
    meta: &mut ConstraintSystem<F>,
    q_decompose: Selector,
    full_number_u64: Column<Advice>,
    limbs: [Column<Advice>; 8],
) {
    meta.create_gate("decompose in 8 bit words", |meta| {
        let q_decompose = meta.query_selector(q_decompose);
        let full_number = meta.query_advice(full_number_u64, Rotation::cur());
        let limbs: Vec<Expression<F>> =
            limbs.iter().map(|column| meta.query_advice(*column, Rotation::cur())).collect();
        let constraints = vec![
            q_decompose
                * (full_number
                    - limbs[0].clone()
                    - limbs[1].clone() * Expression::Constant(F::from(1 << 8))
                    - limbs[2].clone() * Expression::Constant(F::from(1 << 16))
                    - limbs[3].clone() * Expression::Constant(F::from(1 << 24))
                    - limbs[4].clone() * Expression::Constant(F::from(1 << 32))
                    - limbs[5].clone() * Expression::Constant(F::from(1 << 40))
                    - limbs[6].clone() * Expression::Constant(F::from(1 << 48))
                    - limbs[7].clone() * Expression::Constant(F::from(1 << 56))),
        ];
        Constraints::without_selector(constraints)
    })
}

/// Creates the necessary lookups to constrain that all the limbs in a given row are in the
/// range [0, 255].
pub(crate) fn create_range_check_gate<F: PrimeField>(
    meta: &mut ConstraintSystem<F>,
    t_range: TableColumn,
    q_range: Selector,
    limbs: [Column<Advice>; 8],
) {
    for limb in limbs {
        range_check_for_limb(meta, &limb, &q_range, &t_range);
    }
}

/// Creates the lookup of an 8-bit limb. It uses the [t-range] table, which is filled in the
/// [populate_lookup_table()] method, and the [q_range], which is turned on whenever needed
fn range_check_for_limb<F: PrimeField>(
    meta: &mut ConstraintSystem<F>,
    limb: &Column<Advice>,
    q_range: &Selector,
    t_range: &TableColumn,
) {
    meta.lookup(format!("lookup limb {limb:?}"), |meta| {
        let limb: Expression<F> = meta.query_advice(*limb, Rotation::cur());
        let q_range = meta.query_selector(*q_range);
        vec![(q_range * limb, *t_range)]
    });
}

/// Fills the [t_range] table with values in the range [0,255]
pub(crate) fn populate_lookup_table<F: PrimeField>(
    layouter: &mut impl Layouter<F>,
    t_range: TableColumn,
) -> Result<(), Error> {
    const LIMB_SIZE_IN_BITS: usize = 8;
    layouter.assign_table(
        || format!("range {LIMB_SIZE_IN_BITS}-bit check table"),
        |mut table| {
            for i in 0..1 << LIMB_SIZE_IN_BITS {
                table.assign_cell(|| "value", t_range, i, || Value::known(F::from(i as u64)))?;
            }
            Ok(())
        },
    )
}
