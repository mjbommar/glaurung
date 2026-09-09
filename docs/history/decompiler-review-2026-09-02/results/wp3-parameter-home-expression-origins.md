# WP3 parameter-home expression origins

Date: 2026-09-08

Commit: `e8d09ce4`

## Defect and repair

The cdecl32 stack-local rewrite recognizes stores into incoming stack argument
slots and converts a full-width home store such as `[rbp + 8] = eax` into an
assignment to the recovered ABI parameter. It previously inspected only a
literal `Expr::Lea`. An origin carrier around the address made the same store
look unrelated to the parameter slot, so the store survived unpromoted.

`src/ir/stack_locals/rewrite.rs` now classifies and rewrites the semantic
address beneath the carrier. When the store becomes an assignment, the single
surviving statement receives the union of the store owner and address owner;
it does not create nested statement-origin wrappers. Existing width and
argument-slot refusal rules remain in force.

## Focused validation

The contract
`attributed_cdecl32_argument_home_store_preserves_all_owners` was observed red
before the repair: the attributed input remained a `Store`. It passes after the
repair. The complete owning module also passes:

```text
running 118 tests
test result: ok. 118 passed; 0 failed; 4561 filtered out
```

No repository-wide Rust or Python suite ran.

Fixture validation used a detached clean worktree with only the owned patch, a
separate virtual environment, and cache-backed build directories:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-origin-release-target
uv run maturin develop --release
uv run python tools/dectest.py \
  03_loop_shapes:i386:O0:cond_side_effect --show
```

Result:

```text
SCOPED: 1 lane of 3304 (0%) - no regressions in scope
```

This is focused evidence for the i386 cdecl path only. It does not close the
remaining WP3 semantic-expression consumers or universal production
attribution.
