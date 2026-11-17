use crate::tests::Decompose8Config;
use crate::base_operations::negate::NegateConfig;
use crate::types::blake2b_word::Blake2bWord;
use ff::PrimeField;
use midnight_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use midnight_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed};
use std::array;
use std::marker::PhantomData;

pub(crate) struct NegateCircuit<F: PrimeField> {
    _ph: PhantomData<F>,
    value: Value<Blake2bWord>,
    expected_result: Value<Blake2bWord>,
}

#[derive(Clone)]
pub(crate) struct NegateCircuitConfig<F: PrimeField> {
    _ph: PhantomData<F>,
    negate_config: NegateConfig,
    decompose_8_config: Decompose8Config,
    fixed_result: Column<Fixed>,
    full_number_u64: Column<Advice>,
}

impl<F: PrimeField> Circuit<F> for NegateCircuit<F> {
    type Config = NegateCircuitConfig<F>;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            value: Value::unknown(),
            expected_result: Value::unknown(),
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);
        let negate_config = NegateConfig::configure(meta, full_number_u64);

        let fixed_result = meta.fixed_column();
        meta.enable_equality(full_number_u64);
        meta.enable_equality(fixed_result);

        Self::Config {
            _ph: PhantomData,
            negate_config,
            decompose_8_config,
            fixed_result,
            full_number_u64,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_config.populate_lookup_table(&mut layouter)?;

        layouter.assign_region(
            || "negate",
            |mut region| {
                let mut offset = 0;
                let cell = config
                    .decompose_8_config
                    .generate_row_from_word_and_keep_row(&mut region, self.value, offset)?
                    .full_number;
                offset += 1;

                let result = config.negate_config.generate_rows_from_cell(
                    &mut region,
                    &mut offset,
                    &cell,
                    config.full_number_u64,
                )?;
                let fixed_cell = region.assign_fixed(
                    || "assign fixed",
                    config.fixed_result,
                    0,
                    || self.expected_result,
                )?;
                region.constrain_equal(result.cell(), fixed_cell.cell())?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: PrimeField> NegateCircuit<F> {
    pub(crate) fn new_for(value: Value<Blake2bWord>, expected_result: Value<Blake2bWord>) -> Self {
        Self {
            _ph: PhantomData,
            value,
            expected_result,
        }
    }
}
