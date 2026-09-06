# WP4 raw-loop source-level continue — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `c9483542` replaces transfers from a locally owned raw-loop block to
that exact loop header with source-level `continue`. The production ARMv7 A32
O2 `206_aarch64_wide_dispatch::dispatch_in_loop` output previously contained
six copies of:

```c
if (var6 != var7) {
    goto L_4f4;
}
```

It now emits six copies of:

```c
if (var6 != var7) {
    continue;
}
```

and the unused `L_4f4` header label disappears.

## Safety boundary

`Region::RawLoop` already owns every block and backedge in its dominator-proven
natural-loop body. During AST lowering, the existing recursive multi-exit
transfer materializer now receives that raw loop's exact header and converts
only gotos to that address. It descends through conditionals and switches but
does not cross nested loops. Transfers to case handlers and loop exits remain
explicit, while a terminal fallthrough to the header remains C's implicit
continue.

The reduced AST test uses a conditional latch, verifies that its header edge is
`Continue`, and verifies that no explicit goto to the raw-loop header survives.
The real architecture test requires `continue;` in production output in
addition to its existing no-undefined-`var1` and native-execution checks.

## Evidence

- Real ARMv7 A32 O2 production output retains the recovered `switch`, cases
  `0..6`, all case effects, and correct native execution.
- `GLAURUNG_ACCOUNT_STRUCTURE=1` remains silent for the real function.
- `cargo test --features python-ext` is green, beginning with 4,116 library
  tests and ending with green integration and documentation tests.
- The complete 410-lane ARMv7 A32 O0/O2 comparison has no attributable status
  change. Its only parent/tip map difference is `tail_countdown`, an unrelated
  row that passed three immediate exact-tip retries and later flipped again on
  the unchanged code.
- Exact host parent `0e29ffc4` and tip `c9483542` comparisons each cover 824 of
  838 object lanes and 3,346 function verdicts: 2,913 pass, 312 fail, and 121
  structural. The normalized status maps and raw status logs are identical, so
  the change causes zero host execution or structural-category movement. This
  host gate does not claim identical pseudocode; the asserted output movement
  is the separately checked A32 function.

This increment removes loop-backedge gotos only. The switch still targets
separately labelled case-handler bodies. Inlining those handlers requires a
separate proof of exclusive entry and join ownership; this change deliberately
does not infer it from textual proximity.
