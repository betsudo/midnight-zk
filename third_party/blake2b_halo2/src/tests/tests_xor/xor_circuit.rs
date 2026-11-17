use super::*;
use crate::tests::Decompose8Config;
use crate::base_operations::xor::XorConfig;
use midnight_proofs::circuit::SimpleFloorPlanner;
use midnight_proofs::plonk::Circuit;
use std::array;
use std::marker::PhantomData;

#[derive(Clone)]
pub(crate) struct XorCircuitConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    xor_config: XorConfig,
    decompose_8_config: Decompose8Config,
}

pub(crate) struct XorCircuit<F: PrimeField> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 3],
}

impl<F: PrimeField> XorCircuit<F> {
    pub(crate) fn new_for_trace(trace: [[Value<F>; 9]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for XorCircuit<F> {
    type Config = XorCircuitConfig<F>;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: [[Value::unknown(); 9]; 3],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);
        let xor_config = XorConfig::configure(
            meta,
            limbs,
            full_number_u64,
            limbs,
            decompose_8_config.q_decompose,
        );

        Self::Config {
            _ph: PhantomData,
            xor_config,
            decompose_8_config,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_config.populate_lookup_table(&mut layouter)?;

        config.xor_config.populate_xor_lookup_table(&mut layouter)?;
        config.xor_config.populate_xor_region(
            &mut layouter,
            self.trace,
            &mut config.decompose_8_config,
        )
    }
}

impl XorConfig {
    /// Given 3 explicit rows of values, it assigns the full number and the limbs of the operands
    /// and the result in the trace
    fn populate_xor_region<F: PrimeField>(
        &self,
        layouter: &mut impl Layouter<F>,
        xor_trace: [[Value<F>; 9]; 3],
        decompose_8_config: &mut Decompose8Config,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "xor",
            |mut region| {
                self.q_xor.enable(&mut region, 0)?;

                let first_row = xor_trace[0].to_vec();
                let second_row = xor_trace[1].to_vec();
                let third_row = xor_trace[2].to_vec();

                decompose_8_config.populate_row_from_values(&mut region, &first_row, 0, true)?;
                decompose_8_config.populate_row_from_values(&mut region, &second_row, 1, true)?;
                decompose_8_config.populate_row_from_values(&mut region, &third_row, 2, true)?;

                Ok(())
            },
        )?;
        Ok(())
    }
}
