use super::*;
use crate::tests::Decompose8Config;
use crate::base_operations::generic_limb_rotation::LimbRotation;
use ff::PrimeField;
use midnight_proofs::circuit::SimpleFloorPlanner;
use midnight_proofs::plonk::Circuit;
use std::array;

#[derive(Clone)]
pub(crate) struct LimbRotationCircuit<F: PrimeField, const T: usize> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 2],
}

impl<F: PrimeField, const T: usize> LimbRotationCircuit<F, T> {
    pub(crate) fn new_for_trace(trace: [[Value<F>; 9]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField, const T: usize> Circuit<F> for LimbRotationCircuit<F, T> {
    type Config = LimbRotationCircuitConfig<F>;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: [[Value::unknown(); 9]; 2],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| {
            let column = meta.advice_column();
            meta.enable_equality(column);
            column
        });

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);

        Self::Config {
            _ph: PhantomData,
            decompose_8_config: decompose_8_config.clone(),
            limb_rotation_config: LimbRotation::configure(decompose_8_config.q_decompose),
        }
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let limbs_to_rotate_to_the_right = match T {
            32 => 4,
            24 => 3,
            16 => 2,
            _ => panic!("Unexpected Rotation"),
        };

        config.decompose_8_config.populate_lookup_table(&mut layouter)?;
        config.limb_rotation_config.populate_rotation_rows(
            &mut layouter,
            &mut config.decompose_8_config,
            self.trace,
            limbs_to_rotate_to_the_right,
        )
    }
}

impl LimbRotation {
    /// This method is meant to receive a valid rotation_trace, and populate the circuit with it
    /// The rotation trace is a 2x9 matrix. The rows represent the input and output of the rotation,
    /// and the columns represent the limbs of each number.
    /// In the end of the method, the circuit will have the correct constraints to ensure that
    /// the output is the input rotated to the right by the number of limbs specified in the
    /// limb_rotations_right parameter.
    /// This method is not used in the actual circuit, but it is useful for testing if you want to
    /// write a test where the values are incorrect and check that the contstaints fail.
    fn populate_rotation_rows<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        decompose_config: &mut Decompose8Config,
        trace: [[Value<F>; 9]; 2],
        limb_rotations_right: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || format!("rotate {}", limb_rotations_right),
            |mut region| {
                let first_row = decompose_config.populate_row_from_values(
                    &mut region,
                    trace[0].as_ref(),
                    0,
                    true,
                )?;
                let second_row = decompose_config.populate_row_from_values(
                    &mut region,
                    trace[1].as_ref(),
                    1,
                    true,
                )?;

                for i in 0..8 {
                    // We must subtract limb_rotations_right because if a number is expressed bitwise
                    // as x = l1|l2|...|l7|l8, the limbs are stored as [l8, l7, ..., l2, l1]
                    let top_cell = first_row[i + 1].cell();
                    let bottom_cell = second_row[((8 + i - limb_rotations_right) % 8) + 1].cell();
                    region.constrain_equal(top_cell, bottom_cell)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
