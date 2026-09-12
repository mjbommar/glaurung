# WP3 float live-ins follow SSA paths

Status: bounded WP3 semantic-reader migration landed at `de12aebe` on
`master`.

## Result

Float-argument discovery no longer treats a register definition anywhere in
the function as if it killed the incoming value everywhere in the CFG. Both
the general float-bank scan and x86 binary64-width evidence now consult the
authoritative `SsaInfo` snapshot and accept only exact version-zero uses.

The old whole-function `defined` set depended on block-vector order. If one
branch assigned `s0` before a sibling branch read the incoming `s0`, the read
was discarded and the source parameter disappeared. SSA versions express the
actual path semantics: the sibling read remains `s0` version zero, while reads
reached by the assignment use a later version.

Observed register spelling remains separate from identity. It still selects
the source view (`s0` versus `d0`, or an x86 lane versus the whole `xmm`
register), while SSA identity decides whether the value entered the function.

## Focused evidence

The branch-sensitive regression was observed red before implementation:

```text
float_live_in_on_one_branch_survives_a_sibling_definition ... FAILED
left: []
right: [(0, "s0")]
```

After implementation:

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext ir::types_recover::tests --lib
90 passed; 0 failed; 4,678 filtered out; finished in 0.19s
```

An exact detached release build of `de12aebe` produced native SHA-256
`054c568ab488a05e57ac83fe00ffadf3487194fe6db18f521dc74d9adbcff777`.
The build guard reported the detached native extension fresh.

The directly relevant real fixture retained its correct source signature:

```text
tools/dectest.py 172_float_double_widths:gcc:O0:double_precision_horner \
  --show --full

double double_precision_horner(double x, double a, double b)
SCOPED: 1 lane of 838 (0%) — no regressions in scope
```

That cell remains a known failure because the body returns the wrong SSA value;
this increment fixes parameter discovery, not call-result preservation. The
periodic symbols/PIE Hello checkpoint passed all six selected cells: x86-64,
AArch64, and ARMv7 at O0 and O2.

## Measurement boundary

Only the observed-red regression, the 90-test type-recovery module, one real
float fixture cell, and six Hello cells ran. No broad Rust or Python suite,
fixture matrix, cross-corpus sweep, DecBench, Joern, GED, or performance run
was used. This closes one path-sensitive SSA consumer; WP3 remains open.
