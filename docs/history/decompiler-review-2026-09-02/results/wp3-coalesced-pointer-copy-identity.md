# WP3 pointer-copy recovery accepts coalesced identities

Status: bounded WP3 semantic-reader migration landed at `07b900ce` on
`master`.

## Result

Pointer-origin recovery no longer requires a trusted copy source to represent
exactly one SSA candidate. Legal phi/copy coalescing may combine multiple SSA
versions while preserving pipeline ownership; those values can now carry an
authoritative callee pointer contract back to the source parameter.

This reader asks only whether a copy source is pipeline-attributed. The
separate recursive definition proof still rejects conflicting definitions,
cycles, unsafe integer uses, and incompatible pointer widths. Unattributed
`varN`/`argN` display spellings remain untrusted.

## Focused evidence

The existing diffutils `lf_skip`-shaped contract was strengthened from one
exact `rax` version to two coalesced versions. It was observed red before the
reader migration:

```text
recovered_callee_pointer_flows_back_through_a_coalesced_parameter_copy ... FAILED
left: None
right: Some(8)
```

After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext ir::high_variables::tests --lib
37 passed; 0 failed; 4,733 filtered out; finished in 0.20s
```

An exact detached release build of `07b900ce` produced native SHA-256
`e9e69dfc47d91fa29a433ec72032b4c5539ee6118c91cd60faa06392b6ee4664`.
The build guard reported it fresh. `tools/dectest.py @calls --full` passed all
eight selected fixture lanes without a scoped regression, and the periodic
symbols/PIE Hello checkpoint passed x86-64, AArch64, and ARMv7 at O0 and O2.

## Measurement boundary

Only the 37 high-variable tests, eight call fixture lanes, and six Hello cells
ran. The DecBench `lf_skip` specimen that motivated the original contract was
not run because DecBench was not requested. No broad Rust or Python suite,
complete fixture matrix, cross-corpus sweep, Joern, GED, or performance run was
used. This closes one identity consumer; WP3 remains open.
