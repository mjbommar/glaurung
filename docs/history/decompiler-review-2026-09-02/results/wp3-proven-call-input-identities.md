# WP3 proven call-input identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `00a652e7` removes a remaining production signature-inference dependency
on value-numbered display spelling. A non-exact call contract distinguishes
the ABI-wide `args` may-use set from its `proven_args` subset. The shared
predicate used to strip `#version` and compare the resulting register names,
so two misleading names could fabricate a proven source parameter even when
their authoritative SSA identities occupied different machine storage.

`use_is_proven_input_with_identities` now compares the unambiguous physical
storage carried by `ValueIdentities`. The value-numbered architectural-read
and live-in parameter scans use that form. Raw type-recovery callers retain
the spelling-compatible entry point because they run before an identity
sidecar exists. Missing or ambiguous identity evidence fails closed.

## RED/GREEN evidence

The adversarial contract gives `rdi#looks_proven` an exact `rax` identity and
`edi#also_looks_proven` an exact `rsi` identity. The old display-name rule
accepted the input; after the repair it is rejected:

```text
ir::use_def::tests::proven_call_input_rejects_matching_display_names_with_different_identities
```

Focused debug validation:

```text
cargo test --features python-ext --lib ir::use_def::tests::
16 passed; 0 failed; 4,758 filtered out

cargo test --features python-ext --lib ir::value_number::tests::
65 passed; 0 failed; 4,709 filtered out
```

The latter slice includes positive non-exact call-input, phi-plumbing, live-in,
subregister, and misleading-spelling controls; the change does not merely
reject every call input.

## Exact release fixture evidence

A clean detached worktree at `00a652e7178ded08d2c773523d103dc10fadab3f`
was built with `uv run maturin develop --release`. `tools/build_guard.py`
reported `fresh`; the native SHA-256 was
`1b08be50a745a1d572d760e27c63403decf6b014e754f93587f858e785f82d7e`.

```text
uv run --no-sync python tools/dectest.py @calls
SCOPED: 8 lanes of 838 (1%) - no regressions in scope

uv run --no-sync pytest -q <six symbols/PIE GCC O0/O2 Hello nodes>
6 passed
```

The Hello nodes cover x86-64, AArch64, and ARMv7 at O0 and O2. No broad Rust
or Python suite, complete fixture matrix, DecBench, or Joern run was made.

The focused test-census gate is presently non-authoritative in the shared
checkout: unrelated concurrent work raises the declared count from 5,198 to
5,311. The generator's temporary baseline rewrite was reversed rather than
pinning those in-flight tests in this increment.

## Next boundary

Continue the production semantic-name audit. Keep raw/pre-sidecar and explicit
no-sidecar compatibility parsers separate from consumers that already own
`ValueIdentities`; migrate only the latter, with an adversarial identity test
and a directly affected fixture slice.
