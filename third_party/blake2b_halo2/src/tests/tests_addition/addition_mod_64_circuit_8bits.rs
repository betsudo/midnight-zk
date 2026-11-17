use super::*;
use crate::tests::Decompose8Config;
use midnight_proofs::circuit::SimpleFloorPlanner;
use midnight_proofs::plonk::Circuit;
use std::array;

pub(crate) struct AdditionMod64Circuit8Bits<F: PrimeField> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 3],
}

#[derive(Clone, Debug)]
pub(crate) struct AdditionMod64Config8Bits<F: PrimeField + Clone> {
    sum_8bits_config: AdditionMod64Config,
    decompose_8_config: Decompose8Config,
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for AdditionMod64Circuit8Bits<F> {
    type Config = AdditionMod64Config8Bits<F>;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            _ph: PhantomData,
            trace: [[Value::unknown(); 9]; 3],
        }
    }

    #[allow(unused_variables)]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let full_number_u64 = meta.advice_column();
        let limbs: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs);

        let sum_8bits_config = AdditionMod64Config::configure(
            meta,
            full_number_u64,
            limbs[0],
            decompose_8_config.q_decompose,
            decompose_8_config.q_range,
        );

        Self::Config {
            _ph: PhantomData,
            decompose_8_config,
            sum_8bits_config,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_config.populate_lookup_table(&mut layouter)?;
        config.sum_8bits_config.populate_addition_rows(
            &mut layouter,
            self.trace,
            config.decompose_8_config.clone(),
        )?;
        Ok(())
    }
}

impl<F: PrimeField> AdditionMod64Circuit8Bits<F> {
    pub(crate) fn new_for_trace(trace: [[Value<F>; 9]; 3]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}
