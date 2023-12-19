use std::{
    collections::{BTreeSet, HashMap, HashSet},
    marker::PhantomData,
};

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Expression, Selector, TableColumn},
    poly::Rotation,
};

use crate::constants::MAX_STATE;

pub trait Expr<F> {
    fn expr(&self) -> Expression<F>;
}

impl<F, T> Expr<F> for T
where
    F: From<T>,
    T: Copy,
{
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self))
    }
}

#[derive(Default)]
pub struct DFADef {
    /// A set from (character, current state id in DFA, next state id in DFA).
    pub state_lookup: BTreeSet<(u8, u64, u64)>,
    /// The first state id.
    pub first_state_val: u64,
    /// The id of the accepted state.
    /// It supports only one accepted state.
    pub accepted_state_val: u64,
}

#[derive(Clone)]
pub struct DFATable<F> {
    pub character: TableColumn,
    pub state: TableColumn,
    pub next_state: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> DFATable<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let character = meta.lookup_table_column();
        let state = meta.lookup_table_column();
        let next_state = meta.lookup_table_column();
        meta.annotate_lookup_column(character, || "character");
        meta.annotate_lookup_column(state, || "state");
        meta.annotate_lookup_column(next_state, || "next_state");
        Self {
            character,
            state,
            next_state,
            _marker: PhantomData,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        def: &DFADef,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        layouter.assign_table(
            || "assign transition table",
            |mut table| {
                let mut offset = 0;
                let mut assign_row = |char: u8,
                                      cur_state: u64,
                                      next_state: u64|
                 -> Result<(), halo2_proofs::plonk::Error> {
                    table.assign_cell(
                        || format!("character at {}", offset),
                        self.character,
                        offset,
                        || Value::known(F::from(char as u64)),
                    )?;
                    table.assign_cell(
                        || format!("cur_state at {}", offset),
                        self.state,
                        offset,
                        || Value::known(F::from(cur_state)),
                    )?;
                    table.assign_cell(
                        || format!("next_state at {}", offset),
                        self.next_state,
                        offset,
                        || Value::known(F::from(next_state)),
                    )?;
                    offset += 1;
                    Ok(())
                };
                assign_row(0, MAX_STATE, MAX_STATE)?;
                for (character, state, next_state) in def.state_lookup.iter() {
                    assign_row(*character, *state, *next_state)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Table layout
/// | character | state | q_state_check | q_enable |

#[derive(Clone)]
pub struct RegexCircuitConfig<F> {
    q_state_check: Selector,
    state: Column<Advice>,
    character: Column<Advice>,
    expected_state: Column<Advice>,
    q_enable: Selector,
    dfa_table: DFATable<F>,
}

impl<F: PrimeField> RegexCircuitConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let q_state_check = meta.selector();
        let q_enable = meta.complex_selector();

        let state = meta.advice_column();
        let expected_state = meta.advice_column();
        let character = meta.advice_column();

        let dfa_table = DFATable::configure(meta);

        meta.create_gate("The current state must be expected", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let q_state_check = meta.query_selector(q_state_check);
            let state = meta.query_advice(state, Rotation::cur());
            let expected_state = meta.query_advice(expected_state, Rotation::cur());
            vec![q_enable * q_state_check * (state - expected_state)]
        });

        meta.lookup("Transition must be valid", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let cur_state = meta.query_advice(state, Rotation::cur());
            let next_state = meta.query_advice(state, Rotation::next());
            let character = meta.query_advice(character, Rotation::cur());
            let dummy_state = MAX_STATE.expr();

            vec![
                (q_enable.clone() * character.clone(), dfa_table.character),
                (
                    q_enable.clone() * cur_state.clone()
                        + (1.expr() - q_enable.clone()) * dummy_state.clone(),
                    dfa_table.state,
                ),
                (
                    q_enable.clone() * next_state.clone()
                        + (1.expr() - q_enable.clone()) * dummy_state.clone(),
                    dfa_table.next_state,
                ),
            ]
        });

        Self {
            q_enable,
            q_state_check,
            state,
            expected_state,
            character,
            dfa_table,
        }
    }

    pub fn load(
        &self,
        dfa_def: &DFADef,
        traces: &[(u8, u64)],
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.dfa_table.assign(layouter, dfa_def)?;

        layouter.assign_region(
            || "assign traces",
            |mut region| {
                let mut offset = 0;
                let mut traces = traces.iter().peekable();

                while let Some((character, state)) = traces.next() {
                    self.q_enable.enable(&mut region, offset)?;
                    // enable init state check
                    let expected_state = if offset == 0 {
                        dfa_def.first_state_val
                    } else if traces.peek().is_none() {
                        dfa_def.accepted_state_val
                    } else {
                        0
                    };
                    if offset == 0 || traces.peek().is_none() {
                        self.q_state_check.enable(&mut region, offset)?;
                    }
                    region.assign_advice(
                        || "assign init state",
                        self.expected_state,
                        offset,
                        || Value::known(F::from(expected_state)),
                    )?;
                    self.q_enable.enable(&mut region, offset)?;

                    region.assign_advice(
                        || "assign character",
                        self.character,
                        offset,
                        || Value::known(F::from(*character as u64)),
                    )?;
                    region.assign_advice(
                        || "assign state",
                        self.state,
                        offset,
                        || Value::known(F::from(*state)),
                    )?;
                    offset += 1;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
