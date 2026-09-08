# WP3 tail-call origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `849c5a5b` makes direct, resolved GOT-indirect, and relocation-proven
vtable tail-call recovery transparent to statement origins. Attributed setup
statements and local labels now participate in the same proofs as raw
statements; nested `try`/`catch` bodies are traversed; and a transfer expanded
into `Call` plus `Return` gives both synthesized statements the transfer's
owner. Existing argument setup owners remain unchanged.

This is a bounded WP3 consumer migration. It does not weaken external-target,
GOT, vtable-layout, alignment, or argument-slot proofs, add expression origins,
or complete the remaining argument-recovery audit.

## Evidence

Three new ownership tests were observed red before the production change: an
attributed GOT tail was skipped, an attributed direct tail inside a catch was
skipped, and an attributed vtable transfer was skipped. A fourth refusal test
keeps an attributed jump to an in-function label as a `Goto`. The complete
focused module is green:

```text
cargo test --features python-ext call_args::tail_calls::tests -- --nocapture
13 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

The complete JSON map is byte-for-byte identical to the preceding
function-table boundary. The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,278 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole Python suite improved by one normalized node with no
addition:

```text
216 failed; 4,589 passed; 77 skipped; 128 deselected; 876 xfailed
0 added failure nodes; 1 removed failure node
```

The removed node is
`test_exported_rust_i32_return_uses_exact_c_width[O2]`. A controlled release
A/B reversed only `849c5a5b`: the parent retained an `unrecovered indirect
jump` through the trait vtable, while the restored tip recovered the terminal
indirect tail call and passed. The source hash matched after restoration and
the tip release extension was rebuilt.

The separately reported `stack_3` / `local_c` declaration regression came from
an older 2026-09-05 run. The current release-built eight-cell invariant remains
green:

```text
uv run pytest python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared -q
8 passed
```

## Next ordered increment

Continue the enabled wildcard audit through argument reconstruction. The raw
setup/removal paths in `src/ir/call_args.rs`, `src/ir/call_args/cdecl32.rs`, and
`src/ir/call_args/aapcs.rs` can still skip attributed assignments/stores or
remove their carriers without transferring exact consumed-origin unions.
Migrate one proof family at a time, beginning with the convention-generic
recovered-layout folds, before the architecture-specific outgoing-stack
helpers and before expression ownership.
