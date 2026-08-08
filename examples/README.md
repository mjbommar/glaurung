# Glaurung examples

> **Status: maintained example index.** Examples use checked-in fixtures or an
> explicit user-supplied path. Model-backed, solver-backed, and driver-specific
> programs are labeled separately from offline examples.

Run commands from the repository root after `uv sync --locked --dev`.

## Python

- `python_triage_examples.py` exercises triage and deterministic JSON using a
  caller-supplied binary.
- `analyze_with_ioc_validation.py` lists byte-derived IOC candidates offline;
  `--validate` adds a model-backed, candidate-bound judgement.
- `demo_ioc_validation.py` uses the checked-in native C2 demo and only invokes
  a model when `--validate` is explicit.
- `test_no_hallucination.py` demonstrates the value-free V2 decision schema on
  candidates extracted from the checked-in native C2 demo. It does not claim
  the model's security judgement is correct.
- `iterative_analysis.py` is model-backed and requires configured credentials.

Offline smoke commands:

```bash
uv run python examples/python_triage_examples.py \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2
uv run python examples/analyze_with_ioc_validation.py \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O0/c2_demo-gcc-O0
uv run python examples/demo_ioc_validation.py
uv run python examples/test_no_hallucination.py
```

These examples consume the bounded IOC samples returned by triage. Candidate
order and count can vary with that sampler.

The result is not a complete IOC inventory. Treat every row as an observation
to investigate, including ordinary loader paths and library hostnames.

## Rust

Default-feature examples can be checked together:

```bash
cargo check --examples
```

Symbolic examples declare required features in `Cargo.toml`. `ioctl_scan` and
`ioctlance` require `symbolic`; several real-driver and benchmark examples
require `solver-axeyum`, and Axeyum comparisons also require `solver-z3`.
Those programs may require external driver fixtures, Z3/libclang, or explicit
environment controls documented in `docs/axeyum-integration/`.

The current `solver-axeyum` gate at Glaurung `fcca960b` does not compile because
the translator has not yet added `LogicalAnd`/`LogicalOr`. See the
[Axeyum integration index](../docs/axeyum-integration/README.md). Do not present
Axeyum example output as current until that gate is repaired and rerun.

Examples such as `ioctlance` are research/validation harnesses, not stable CLI
interfaces. Read their module documentation and `--help` or source before using
them against a new corpus.
