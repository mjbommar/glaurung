# WP6/WP9 cdecl32 wide source parameters — 2026-09-06

> **Kind:** record · **Date:** 2026-09-06

Behavior commit `fcd9bd2d`, architecture-baseline commit `9b307e0b`, and census
commit `d1bf72a7` close one bounded i386 parameter-identity defect. They do not
complete WP6's general constraint solver, WP9's target model, or WP3's stable
source-value identity.

## Defect and contract

The supported i386 cdecl boundary passes an eight-byte integer parameter in two
adjacent incoming stack words. Stack promotion previously named the low word
`arg0`, but presented the high word as an unrelated `stack_0` local. Wide
selectors could therefore lose their upper half even when an authoritative
prototype declared the source parameter as `uint64_t`.

`RecoveredPrototype` now records the exact low/high incoming stack offsets of
each authoritatively declared eight-byte integer parameter. The existing
32-bit wide-parameter materializer consumes that fact after stack promotion.
It maps the separate high stack word to `(argN >> 32)` while retaining the
promoted `argN` low coordinate as the whole source value. Both entry-SP and
frame-pointer coordinates are supported with their cdecl return-address and
saved-frame-pointer displacement.

The rule is deliberately fail closed. It applies only to 32-bit x86 cdecl,
uses declaration-derived scalar layout, and stops when a preceding parameter
has an unknown or unsupported size. It does not infer a prototype from display
names and does not generalize stack-coordinate equality into source-value
identity.

An earlier prototype rewrote the promoted low `argN` coordinate to a 32-bit
projection as well. The full i386 comparison exposed three new regressions in
`173_widen_long_to_double`, `193_mc193_scaled_constant`, and
`208_single_argument_survives`. That interpretation was rejected. The final
rule recognizes that the promoted `argN` role already denotes the complete
source argument and rewrites only a separately represented high word; all
three controls return to their parent verdicts.

## Measured movement

Across the complete 410-lane i386 O0/O2 parent/tip comparison, the final
implementation adds nine execution-correct cells and introduces no regression
attributable to this increment:

- fixture 215, O0: `wide_selector_dense`, `wide_selector_high_labels`, and
  `wide_selector_mixed`;
- fixture 215, O2: `wide_selector_dense` and
  `wide_selector_high_labels`; and
- fixture 202, O0 and O2: both `clz64` and `ctz64`.

The four baseline regressions present in the final comparison reproduce at the
exact parent. Signed wide selectors remain WP6/WP7 expression-semantics work.
The i386 O2 mixed selector remains WP5 indirect-target/switch work rather than
an ABI-carrier defect.

## Verification

- Unit contracts cover i386 stack-pair materialization, preservation of the
  whole promoted argument role, and refusal after an unknown preceding
  parameter.
- The release-built i386 fixture-215 execution regression passes at O0 and O2.
- The exact 410-lane parent/tip i386 comparison reports the same four
  pre-existing regressions at both revisions and four additional improvements
  after accounting for fixture-215 baseline updates; together with the five
  newly ratcheted fixture-215 cells, the increment contributes nine
  improvements and zero attributable regressions.
- The generated census at `d1bf72a7` records 4,643 declared tests, an IR
  subtotal of 2,123, and zero tests that are never executed; the focused census
  suite passes.
- The required exact-clean-checkout `cargo test --features python-ext` gate at
  `d1bf72a7` exits zero: its library target reports 4,126 passed, zero failed,
  and five ignored; every integration and documentation target also passes.
  The longest identity-retrieval target reports 44 passed, zero failed, and
  ten ignored in 525.61 seconds.
- One immediate library-only recount transiently reported 52 failures without
  a source change. Two subsequent identical recounts are green at 4,126/0/5.
  This does not invalidate the independently green full gate, but remains test-
  harness stability debt rather than being silently discarded.

The next carrier increment should be selected from a measured failing ABI cell
and should continue to use authoritative declaration and target facts. Stable
joining of frame aliases and source values remains WP3 work; the rejected A32
frame-alias experiment demonstrates why architecture-wide spelling equivalence
is not an acceptable substitute.
