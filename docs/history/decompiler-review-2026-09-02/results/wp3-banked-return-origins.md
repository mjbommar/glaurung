# WP3 banked-return origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `6068a59c` migrates `src/ir/callee_return_bank.rs`, the first complex
result-composition consumer, to the explicit fold/hoist/duplication ownership
contract. Origin wrappers no longer hide stack-object stores, local forwarding,
register-bank definitions, calls, returns, joins, or nested structured bodies.

Register-resident aggregate returns deliberately produce more than one
source-level statement from one machine contributor. The original assignment
or call and its synthesized bank-object store therefore receive independent
copies of the exact same origin set. A return-projected store and the rewritten
whole-object return likewise share the complete return owner; the set is never
partitioned. In-place stack-object return rewrites retain the return's existing
owner.

This closes a concrete one-to-many statement-transformation policy and prevents
the origin carrier from disabling SysV split-bank, SysV SSE-pair, and AAPCS64
HFA return composition.

## Focused TDD

Both new cases were observed red before the migration:

```text
attributed_stack_bank_return_is_composed_without_losing_its_owner
attributed_register_result_duplicates_exact_owners_onto_materialization
```

The completed module is green:

```text
cargo test --features python-ext ir::callee_return_bank::tests --lib -- --nocapture
20 passed; 0 failed
```

The release extension was rebuilt after the final Rust edit. The exact
aggregate-return lanes this consumer owns remain execution-correct:

```text
uv run python tools/dectest.py \
  '195_by_value_aggregates:*:*:bv195_make_mixed' \
  '197_homogeneous_float_aggregates:*:*:hfa197_make_trio3f' \
  --jobs 4 --full
8 passed; 0 regressions; GCC/Clang O0/O2
```

The complete stripped/debug comparison reports 102 known regressions, 16
improvements, and zero infrastructure problems. That absolute map is useful
current-tip evidence, but concurrent source-semantics work changed the shared
checkout after the preceding stored map, so it is not claimed as an isolated
parent/tip identity proof.

The complete required Rust gate is green at the exact source commit:

```text
cargo test --features python-ext
library: 4,318 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all integration and documentation targets passed
```

A whole-Python run was started because this repository historically required
one after every `src/` commit, but it spent its tail rebuilding unrelated
Docker fixture cells. At the user's explicit request to keep validation scoped,
it was interrupted at 98% and therefore has no terminal pass/fail totals and is
not evidence. Future development increments use affected modules and functions;
the full Python gate is paid only at a coherent integration boundary.

## Boundary and next action

This commit proves duplication for statement-level owners; it does not expose
structured line mappings to Python or give expressions independent owners.
Continue the wildcard audit through the related call-result composition
surface, then start expression ownership only after all statement consumers
are transparent.
