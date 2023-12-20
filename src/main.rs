use std::marker::PhantomData;

use halo2_proofs::{
    circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::ff::PrimeField, plonk::Circuit,
};
use regex::{DFADef, RegexCircuitConfig};

use crate::dfa::{gen_regex_dfa_def, gen_traces};

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

    let regex = "[a-z]+";
    let input = b"auidsafddsavbjhsaoefd";

    let dfa = gen_regex_dfa_def(regex);
    let traces = gen_traces(regex, input);

    let circuit = RegexCircuit::<Fr> {
        dfa,
        traces,
        _marker: PhantomData,
    };
    let prover = MockProver::run(8, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}
