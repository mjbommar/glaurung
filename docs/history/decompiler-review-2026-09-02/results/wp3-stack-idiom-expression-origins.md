# WP3 stack-idiom expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `4c19cb2e` preserves exact value provenance when the stack-idiom pass
rematerializes a lifted decrement/store pair as `Stmt::Push`.

The pushed expression retains any owner it already carried and additionally
owns the store that supplied the pushed value. The synthesized push statement
continues to own the union of the stack decrement and store. This keeps the
value-producing instruction distinct from stack-motion bookkeeping while
preserving the existing semantic collapse.

Pop targets are storage identities rather than expressions and need no
analogous expression carrier. Recognition and refusal rules are unchanged.
This bounded migration does not complete universal expression attribution or
WP3.

## Focused verification

The existing attributed-push test was strengthened with three distinct facts:
an existing source-expression owner, a stack-decrement owner, and a value-store
owner. It was observed red because the pushed expression retained only its
existing owner and lost the store owner.

After repair:

```text
cargo test --features python-ext \
  attributed_push_pair_unions_instruction_origins --lib
1 passed; 0 failed

cargo test --features python-ext 'ir::stack_idiom::tests::' --lib
11 passed; 0 failed; 4,349 filtered out
```

The focused real-binary canary is
`208_flag_register_roundtrip::single_argument_survives`, which executes an
x86 `pushfq`/`popfq` sequence. Parent and isolated tip release builds both
report:

```text
clang O0 pass; clang O2 pass; gcc O0 pass; gcc O2 pass
4 lanes; no scoped regressions
```

The tip build guard reports fresh at exact commit `4c19cb2e`, with native
SHA-256 `2e4a5a7959beccb71d82f78308dc890de7d29edcd4a61dcdea99c10feeb81686`.
No full Rust, Python, fixture, architecture, or DecBench suite was run.

## Next boundary

Continue the production-constructor audit outside call recovery. Prioritize
rewrites that synthesize a returned, stored, or control expression from an
attributed definition and prove exact owner composition before migrating the
next pass.
