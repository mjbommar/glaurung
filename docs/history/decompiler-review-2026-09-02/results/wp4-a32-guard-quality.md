# WP4 ARMv7 pre-loop guard quality — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Two follow-on commits close the remaining definedness and structural-accounting
defects in production output for GCC ARMv7 A32 O2
`206_aarch64_wide_dispatch::dispatch_in_loop`.

## Dominated ARM select arms

Commit `28b3bc5b` folds the exact predication identity

```text
C ? (C ? x : unreachable_prior) : z  ->  C ? x : z
```

and its symmetric false-arm form. The real instructions are `cmp r1, #64`,
`movls r3, #0`, and `movhi r3, #1`: LLIR correctly retained incoming `r3` for
each predicated write, but nesting the two selects left that undefined incoming
value visible in an unreachable expression arm.

The fold requires byte-identical, repeatable conditions composed only from
registers, constants, arithmetic/comparisons, unary operations, and casts.
Calls, loads, nested selects, symbolic addresses, and unknown expressions are
refused because removing their second evaluation could be observable. Tests
cover both identities and an effectful-call refusal. The real fixture now emits

```c
var2 = ((unsigned long)count <= 64 ? 0 : 1);
```

instead of declaring and reading an undefined `var1` in the impossible arm.

Exact parent `e5ca2152` and tip `28b3bc5b` host measurements each cover 824 of
838 object lanes and exactly 3,346 function verdicts: 2,913 pass, 312 fail, and
121 structural. The normalized maps and complete raw logs are byte-identical,
so the generic AST rule causes zero host status movement. The complete 410-lane
ARMv7 A32 comparison also has no attributable status decline; its one apparent
`tail_countdown` decline passes on three immediate exact-tip retries.

## Private prefix and shared terminal

Commit `0e29ffc4` removes the remaining
`EdgeViaGoto { from: 1, to: 5, kind: Taken }`. This is the `count == 0`
pre-loop guard, not the switch range guard. Its return-value setup block is
private to the guard, while the final machine return is shared with a switch
arm.

The structurer now accepts this path only inside the already-proved adapter
whose other arm reaches a raw dispatch loop. It requires a bounded acyclic
single-successor prefix, owns only blocks with the exact preceding owner, and
represents a shared final machine return as a borrowed predecessor-sensitive
view. Shared non-terminal suffixes, branches, cycles, and non-returning paths
retain the explicit goto. A reduced CFG test pins clean block/edge accounting
with a shared terminal.

On the real fixture, `GLAURUNG_ACCOUNT_STRUCTURE=1` is silent, cases `0..6`
remain present, the undefined `var1` is absent, and native ARM execution passes.
The exact post-change A32 matrix differs from the preceding map only in three
known unstable functions (`loop_break`, `tail_countdown`, and `bst_search`), all
of which flip toward pass in this run and none of which has the guarded raw
dispatch shape. No status change is attributed to the structural-quality edit.

## Gates

- `cargo test --features python-ext` after the select fold: green, beginning
  with 4,115 library tests.
- `cargo test --features python-ext` after private-tail ownership: green,
  beginning with 4,116 library tests.
- real ARMv7 A32 O2 production round-trip: pass.
- generated census at `0e29ffc4`: 4,633 declared tests and zero never-executed
  entries.

These commits close the concrete precondition and outer-guard defects. They do
not make the raw loop source-like: case-specific labels/gotos and the missing
high-level `for` induction variable remain WP4/WP7 readability work.
