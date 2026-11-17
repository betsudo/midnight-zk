use ff::PrimeField;
use crate::types::blake2b_word::AssignedBlake2bWord;
use crate::types::byte::AssignedByte;

/// We use this type to model the Row we generally use along this circuit. This row has the
/// following shape:
/// full_number | limb_0 | limb_1 | limb_2 | limb_3 | limb_4 | limb_5 | limb_6 | limb_7
///
/// Where full_number is a Blake2bWord (64 bits) and the limbs constitute the little endian repr
/// of the full_number (each limb is an AssignedByte)
#[derive(Debug)]
pub(crate) struct AssignedRow<F: PrimeField> {
    pub(crate) full_number: AssignedBlake2bWord<F>,
    pub(crate) limbs: [AssignedByte<F>; 8],
}

impl<F: PrimeField> AssignedRow<F> {
    pub(crate) fn new(full_number: AssignedBlake2bWord<F>, limbs: [AssignedByte<F>; 8]) -> Self {
        Self { full_number, limbs }
    }
}
