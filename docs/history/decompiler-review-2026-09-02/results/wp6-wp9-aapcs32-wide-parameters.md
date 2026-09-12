# WP6/WP9 AAPCS32 wide source parameters — 2026-09-06

> **Kind:** record · **Date:** 2026-09-06

Behavior commit `62a4ab72`, architecture-baseline commit `342df62c`, and census
commit `056c694a` close one bounded ARM32 parameter-identity defect in
`215_switch_on_wide_selector`. They do not complete WP6's general constraint
solver or WP9's target model.

## Defect and contract

AAPCS32 passes an aligned `uint64_t` parameter in two core registers. For the
fixture's first parameter those are `r0:r1` on the supported little-endian ARM
targets. Prototype recovery previously retained only `r0` as `arg0`. The upper
word in `r1` was consequently rendered as an unrelated, undefined-looking
local, so high switch labels could not be reconstructed or executed correctly.

`RecoveredPrototype` now carries the exact low/high entry values for an
authoritatively declared eight-byte integer parameter. A dedicated AST pass,
run after storage-value splitting and before role naming, materializes both
reads as projections of the same source argument:

```c
(unsigned int)(op)
(unsigned int)(((unsigned long long)(op)) >> 32)
```

This is target and evidence bounded. The fact is produced only for locked
AAPCS `Arm` or `ArmHardFloat` declarations whose type is an eight-byte integer.
The pass rewrites source reads rather than destinations, so later scratch
register definitions keep their own identity. Big-endian ARM declines until a
target-owned word-order contract is implemented. No renderer-name heuristic is
used.

The batch differential helper also now preserves requested odd Thumb symbol
addresses as lookup aliases when native decompilation returns the canonical
even code address. A focused unit test prevents the execution harness from
mistaking that representation difference for a missing decompilation.

## Measured movement

Across the complete 60-cell fixture-215 architecture slice, this increment
makes four new O2 cells execution-correct:

- ARMv7 `wide_selector_dense` and `wide_selector_high_labels`;
- ARMv7 A32 `wide_selector_dense` and `wide_selector_high_labels`.

ARMv7 O0 `wide_selector_dense` also executes correctly, restoring its existing
baseline expectation. The two reported A32 O0 regressions reproduce at exact
parent `9e2e4dce`; the two x86-64 O2 improvements came from the preceding wide-
selector work. Neither movement is attributable to this increment. Remaining
signed, mixed, O0, and i386 wide-selector failures stay explicitly red.

## Verification

- Focused Rust contracts: two wide-parameter tests and the adjacent locked-
  AAPCS parameter test pass.
- Release-built real-binary tests: both ARMv7 Thumb and ARMv7 A32 O2 builds
  retain `unsigned long long op`, consume `op >> 32`, and pass native
  differential execution for both targeted functions.
- Exact committed fixture-215 matrix: 60 function cells across AArch64, ARMv7,
  ARMv7 A32, i386, x86-64 Clang, and x86-64 GCC 15; no attributable regression.
- Exact clean-checkout Rust gate at `056c694a`: 4,124 library tests passed,
  zero failed, five ignored; every integration and documentation target also
  passed. The long identity-retrieval target passed 44 tests and ignored 10.
- Generated census: 4,641 declared tests, IR subtotal 2,121, zero never
  executed. The six-test census suite passes.

The next architecture work should address the residual A32 O0 frame/storage
identity failures and the i386 two-word parameter carrier. General source-value
identity still belongs in WP3; this bounded authoritative ABI fact must not
grow into a parallel name-based type system.

## Source-identity presentation follow-on

Behavior commits `c27bb0a2` and `e4b370c2` close the later presentation
regression exposed by the same ARM32 O2 cells. Wide-parameter materialization had correctly replaced
the two machine words with one `arg0` source identity, but role naming did not
receive that newly synthesized, prototype-owned identity. The pre-structuring
type map also retained the superseded high machine word and therefore inflated
the rendered signature back to two parameters.

The pipeline now publishes a synthetic source-argument role only when the
prototype-directed wide-parameter pass actually materializes it. The renderer
accepts an authoritative source arity when every argument referenced by the
body fits that declaration, while continuing to reject the declaration if the
body genuinely references an additional argument. On ILP32, declaration-
redundant integer casts are compared using the target-width spelling, removing
the stale `(unsigned long)(op)` truncation around the high-word shift. The
fixture now renders the intended boundary and projection:

```c
int wide_selector_dense(unsigned long long op) {
    /* ... */
    op >> 32
}
```

The regression was observed red in a focused renderer contract. The two arity
contracts, the ILP32 cast contract, all nine adjacent renderer identity tests,
the authoritative naming contract, and all seven pipeline request/order tests
pass. The post-source Python gate exposed and the follow-on commit corrected an
overbroad first version that could enlarge a two-parameter body to a
three-parameter analyst declaration. Both wrong-arity controls now pass. After
a release extension rebuild, the exact ARMv7, ARMv7 A32, i386, and two host
semantic controls pass (six pytest cells total). This is a bounded
WP3 identity-carrier and WP6/WP9 presentation repair; it does not close the
general type solver, big-endian ordering, or residual A32 O0 storage work.
The required post-source whole-Python fail-fast run passes the corrected
analyst-prototype boundary and reaches the same existing 17% AArch64 O2
`call_chain_in_loop` execution failure (`return 0 != 22176384` on `[0, 0]`);
it reports no earlier failure.

## Rejected A32 O0 follow-on

The two residual A32 O0 failures expose mixed aliases after lifting: frame
establishment is spelled `fp = sp`, while memory operands retain versioned
`r11` coordinates. Treating every such `fp`/`r11` pair as one active stack base
made both target functions pass, but the required full 410-lane A32 O0/O2 run
rejected it with 188 pass-to-fail movements, concentrated in frame-pointer-
omitted O2 code. That prototype was removed without commit or baseline change.
A future repair must join the exact established SSA frame value to its aliases
and stop at later `r11` definitions; architecture-level spelling equivalence is
not sufficient evidence.
