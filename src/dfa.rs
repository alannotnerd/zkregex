use std::collections::BTreeSet;

use regex_automata::{
    dfa::{
        dense::{Builder, Config},
        Automaton, StartKind,
    },
    Input,
};

use crate::regex::DFADef;

pub fn gen_regex_dfa_def(regex: &str) -> DFADef {
    let dfa = Builder::new()
        .configure(
            Config::new()
                .minimize(true)
                .start_kind(StartKind::Unanchored)
                .starts_for_each_pattern(false)
                .specialize_start_states(true)
                .match_kind(regex_automata::MatchKind::LeftmostFirst),
        )
        .build(regex)
        .and_then(|dense| dense.to_sparse())
        .unwrap();

    let mut state_lookup = BTreeSet::new();

    for state in dfa.states() {
        for (lower, upper) in state.ranges().into_iter() {
            let next_state = state.next(lower as u8);
            for class_id in lower..=upper {
                state_lookup.insert((class_id, state.id().as_u64(), next_state.as_u64()));
            }
        }
    }

    let first_state_val = dfa.special().min_start.as_u64();
    let accepted_state_val = dfa.special().min_match.as_u64();

    // Handle last transition
    state_lookup.insert((0, accepted_state_val, 0u64));

    DFADef {
        state_lookup,
        first_state_val,
        accepted_state_val,
    }
}

pub fn gen_traces(regex: &str, input: &[u8]) -> Vec<(u16, u8, u64)> {
    let dfa = Builder::new()
        .configure(
            Config::new()
                .minimize(true)
                .start_kind(StartKind::Unanchored)
                .starts_for_each_pattern(false)
                .specialize_start_states(true)
                .match_kind(regex_automata::MatchKind::LeftmostFirst),
        )
        .build(regex)
        .and_then(|dense| dense.to_sparse())
        .unwrap();

    let mut traces = vec![];
    let mut state = dfa.start_state_forward(&Input::new(input)).unwrap();
    for &b in input.iter() {
        let class_id = dfa.class(b);
        traces.push((b as u16, class_id, state.as_u64()));
        state = dfa.next_state(state, b);
    }
    traces.push((0, 0, state.as_u64()));
    state = dfa.next_eoi_state(state);
    traces.push((0, 0, state.as_u64()));
    
    traces
}

#[cfg(test)]
mod tests {
    use super::{gen_regex_dfa_def, gen_traces};

    #[test]
    fn test_regex_gen() {
        let regex = r"[0-9]+[a-z]+o";
        let input = b"0ao";
        let def = gen_regex_dfa_def(regex);
        let traces = gen_traces(regex, input);
        println!("def: {:?}", def);
        println!("traces: {:?}", traces);
    }
}
