# WP3 coalesced values project unanimous type facts

Status: bounded WP3 semantic-reader migration landed at `1f48af39` on
`master`.

## Result

Value-keyed type recovery no longer drops a rendered value merely because it
represents multiple stable `ValueId`s. When every represented value has the
same `TypeHint`, that unanimous fact now refines the rendered value. This
preserves narrow widths and pointer/scalar class through legal phi/copy
coalescing.

The projection remains fail-closed. An empty set, any missing value-keyed fact,
or any disagreement in class, signedness, or width declines the refinement.
The older operation-level analysis is then left unchanged, and authoritative
locked declarations still outrank both paths.

## Focused evidence

The unanimous two-value regression was observed red before implementation:

```text
coalesced_numbered_use_accepts_unanimous_value_keyed_type ... FAILED
left: Some(Int { signed: true, width: 8 })
right: Some(Int { signed: true, width: 4 })
```

After implementation, that case and the existing partial-fact refusal pass as
part of the full focused module:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext ir::types_recover::tests --lib
92 passed; 0 failed; 4,680 filtered out; finished in 0.15s
```

An exact detached release build of `1f48af39` produced native SHA-256
`4a946a8291f69ef1b0f5f2307adb73e854e8e2b018ac7859016fe68010d2c889`.
The build guard reported it fresh. All four GCC/Clang O0/O2 lanes of fixture
`02_integer_widths` passed without a scoped regression, and the periodic
symbols/PIE Hello checkpoint passed x86-64, AArch64, and ARMv7 at O0 and O2.

## Measurement boundary

Only the 92 type-recovery tests, four integer-width fixture lanes, and six
Hello cells ran. No broad Rust or Python suite, complete fixture matrix,
cross-corpus sweep, DecBench, Joern, GED, or performance run was used. This
closes one identity consumer; WP3 remains open.
