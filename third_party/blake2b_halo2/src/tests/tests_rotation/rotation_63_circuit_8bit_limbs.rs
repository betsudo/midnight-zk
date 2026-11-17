use super::*;
use crate::tests::Decompose8Config;
use crate::base_operations::rotate_63::Rotate63Config;
use midnight_proofs::circuit::SimpleFloorPlanner;
use midnight_proofs::plonk::Circuit;
use std::array;
use std::marker::PhantomData;

pub(crate) struct Rotation63Circuit8bitLimbs<F: PrimeField> {
    _ph: PhantomData<F>,
    trace: [[Value<F>; 9]; 2],
}

impl<F: PrimeField> Rotation63Circuit8bitLimbs<F> {
    pub(crate) fn new_for_trace(trace: [[Value<F>; 9]; 2]) -> Self {
        Self {
            _ph: PhantomData,
            trace,
        }
    }
}

impl<F: PrimeField> Circuit<F> for Rotation63Circuit8bitLimbs<F> {
    type Config = Rotation63Config8bitLimbs<F>;
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
        let limbs_8_bits: [Column<Advice>; 8] = array::from_fn(|_| meta.advice_column());

        let decompose_8_config = Decompose8Config::configure(meta, full_number_u64, limbs_8_bits);
        let rotation_63_config = Rotate63Config::configure(
            meta,
            full_number_u64,
            decompose_8_config.q_decompose,
            decompose_8_config.q_range,
        );

        Self::Config {
            _ph: PhantomData,
            decompose_8_config,
            rotation_63_config,
        }
    }

    #[allow(unused_variables)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.decompose_8_config.populate_lookup_table(&mut layouter)?;
        config.rotation_63_config.populate_rotation_rows(
            &mut layouter,
            &mut config.decompose_8_config.clone(),
            self.trace,
        )
    }
}
