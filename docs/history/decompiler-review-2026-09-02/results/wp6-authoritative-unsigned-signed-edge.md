# WP6 authoritative unsigned boundary with signed machine edge — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Behavior commits `a88edd9a` and `8ab39b50`, fixture-baseline commit
`275c8350`, and census commit `71290304` close one bounded per-use signedness
defect in Clang O2's `215_switch_on_wide_selector::wide_selector_high_labels`.
They do not complete WP6's general constraint solver.

## Defect and contract

The source parameter is authoritatively declared `uint64_t`. Clang partitions
the optimized comparison tree with a signed `jg` against `0x100000000`, then
tests `UINT64_MAX` on the lower branch. Before this increment the renderer kept
the correct unsigned signature but printed the signed machine edge as a direct
C comparison:

```c
int wide_selector_high_labels(unsigned long long op) {
    long var0 = 0x100000000;
    if (op <= 0x100000000) {
        if (op == -1) return 23;
        /* ... */
    }
}
```

C's usual conversions make that edge unsigned. `UINT64_MAX` therefore bypassed
the inner equality and returned `-1` instead of `23`. The machine comparison
operator is exact per-use evidence, while DWARF remains authoritative for the
function boundary. The accepted output states both facts:

```c
int wide_selector_high_labels(unsigned long long op) {
    long var0;
    var0 = 0x100000000;
    if ((long)(op) <= 0x100000000) {
        if (op == -1) return 23;
        if (op != var0) return -1;
        return 20;
    }
    if (op == 0x200000000) return 22;
    if (op != 0x100000001) return -1;
    return 21;
}
```

`DeclarationPlan` now records which integer parameters came from an
authoritative prototype. For a signed machine relation only, the renderer casts
a directly used parameter that has an authoritative unsigned declaration to
the signed C type of the same width. It does not change the signature, infer a
new global type, cast recovered/inferred declarations, or rewrite composite
expressions.

The first implementation applied the cast to every unsigned declaration. The
structural census showed that boundary was needlessly broad, so it was rejected
and narrowed in `8ab39b50`. A unit refusal check now proves that an otherwise
identical recovered (non-authoritative) prototype does not receive the
exception.

## Verification

- Exact-tip AST renderer gate: 217 passed, zero failed.
- Pinned Clang-O2 real-binary regression: the unsigned signature and signed
  per-use cast are both present; native differential execution passes,
  including `UINT64_MAX` and the other manifest boundary values.
- Exact final fixture harness: 838 fixture lanes, 3,449 function results;
  2,955 pass, 373 known fail, and 121 structural-only. It matches the updated
  baseline, and all five fixture-215 Clang-O2 functions pass.
- Exact parent `9e2e4dce` and tip `8ab39b50` def-use diagnostics are
  byte-identical after normalization (171 lines). Their structural diagnostics
  are also byte-identical (142 lines). Both corpus gates remain red only on the
  same pre-existing baseline debt; this increment adds no finding.
- Exact-tip complete Rust gate: 4,122 passed, zero failed, five ignored; every
  integration and documentation target passes. Runtime was approximately 10
  minutes 25 seconds, dominated by identity retrieval.
- Generated census: 4,639 declared tests, IR subtotal 2,119, zero never
  executed. The focused census and real-binary suite pass eight of eight tests.

Open work remains deliberately larger: carry authoritative/per-use facts by
stable WP3 value identity, solve conflicting signedness constraints generally,
and extend the compiler/architecture matrix without turning this exact source-
declaration exception into a heuristic over inferred locals.
