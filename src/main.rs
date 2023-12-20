use std::{collections::BTreeSet, marker::PhantomData};

use halo2_proofs::{
    circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::ff::PrimeField, plonk::Circuit,
};
use regex::{DFADef, RegexCircuitConfig};

use crate::constants::MAX_STATE;

pub(crate) mod constants;
pub mod dfa;
mod regex;

#[derive(Default)]
pub(crate) struct RegexCircuit<F> {
    pub(crate) dfa: DFADef,
    pub(crate) traces: Vec<(u16, u8, u64)>,
    pub(crate) _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for RegexCircuit<F> {
    type Config = RegexCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        Self::Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        config.load(&self.dfa, &self.traces, &mut layouter)?;
        Ok(())
    }
}

fn main() {
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut state_lookup = BTreeSet::new();
    state_lookup.insert((1, 0, 1));
    state_lookup.insert((2, 1, 2));
    state_lookup.insert((3, 2, 0));

    let circuit = RegexCircuit::<Fr> {
        dfa: DFADef {
            state_lookup,
            first_state_val: 0,
            accepted_state_val: 2,
        },
        traces: vec![(9, 1, 0), (9, 2, 1), (9, 3, 2)],
        _marker: PhantomData,
    };
    let prover = MockProver::run(4, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}
