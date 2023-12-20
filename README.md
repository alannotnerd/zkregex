# zkregex(WIP)

## Overview
This repository showcases a Proof of Concept (POC) demonstrating the use of halo2 for validating regular expression (regex) matching processes. By transforming regex into Deterministic Finite Automata (DFA) using the regex_automata crate, this project demonstrates an innovative approach to regex matching verification.

## Limitation
This crate is WIP, and has some limitations:

- Support only ASCII code
- `Unanchored` mode only
- Only support full text matching

## Getting Start
### Prerequisites
- rustc (only tested in latest nightly version)

### Installation
1. Clone the repository
```bash
git clone https://github.com/alannotnerd/zkregex
```

2. Navigate to the project directory
```bash
cd zkregex
```

3. Build the project
```bash
cargo run --release
```
Note: This runs with `MockProver` which doen't create a real proof.


