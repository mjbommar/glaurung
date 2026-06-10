# Architecture Decision Records

The load-bearing choices, each with context, the decision, rejected alternatives,
and consequences. Format: lightweight ADR.

| ADR | Decision | Status |
|---|---|---|
| [0001](adr-0001-single-domain-core.md) | One interpreter parameterized by a `Domain` trait (concrete + symbolic share `step()`) | Accepted |
| [0002](adr-0002-executable-ir-vs-new-tier.md) | Harden the existing LLIR in place (vs a new lower IR tier) | Accepted |
| [0003](adr-0003-interpreter-not-jit.md) | Cached IR interpreter for v1 (vs JIT) | Accepted |
| [0004](adr-0004-memory-model-concretize-threshold.md) | Symbolic memory = BV + flat + concretize-with-threshold (1024 B) | Accepted |
| [0005](adr-0005-smt-pipe-then-native-optional.md) | `Solver` trait; **native `z3` crate first (in-process), pipe as fallback**; feature-gated (revised from the original pipe-first) | Accepted (revised) |
| [0006](adr-0006-concolic-default.md) | Directed concolic as the default mode (vs pure symbolic) | Accepted |

All six are mutually reinforcing: a single typed IR (0002) feeds one
domain-generic interpreter (0001) run as a deterministic interpreter (0003); the
symbolic instantiation defaults to concolic (0006) with a concretizing memory
model (0004) and a native, in-process solver (0005). Each is grounded in
[`../01-research/`](../01-research/).
