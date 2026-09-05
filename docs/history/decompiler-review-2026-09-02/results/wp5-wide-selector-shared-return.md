# WP5 wide-selector shared-return switch — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Behavior commit `9333881e` recovers the real Clang and GCC O2
`215_switch_on_wide_selector::wide_selector_mixed` jump table in the production
structurer. Hardening commit `98a0d2d3` then narrows the predicate provenance
and cyclic-ownership contracts after the complete def-use census caught a
regression in the already-green fixture-206 loop switch. Census commit
`94d56bfa` records the additional reduced Rust test; baseline commit
`766b100c` accepts only the two execution-verified fixture-215 movements.

This is a bounded WP5/WP4 increment. It is not a claim that wide selectors,
shared returns, or cyclic switch ownership are complete across the compiler and
architecture matrix.

## Defects and contracts

The fixture-215 machine CFG already had six typed table targets. Production v1
still emitted an `unrecovered indirect jump` for two independent reasons:

1. Clang materialises x86 `ja` as an equality test over `CF | ZF`. The CFG's
   range proof only recognised a comparison consumed directly by the branch.
2. Case zero enters a bare return block also reached from the out-of-range
   default path. The arm-ownership check treated that external predecessor as
   a reason to discard the complete switch.

The implementation now traces unsigned comparison provenance through copies,
boolean `and`/`or`/`xor`/`not`, and equality/inequality tests against boolean
zero or one. It deliberately stops at arithmetic, loads, extensions, and the
ordinary data operands of a comparison. A new reduced test was RED before this
restriction and proves that arithmetic ancestry cannot masquerade as boolean
range evidence.

For an acyclic guarded switch, a case may borrow a bounded return chain only
when the typed formal default can reach that exact chain. The default remains
the structural owner. Cyclic reachability is explicitly excluded: a default
inside a loop can reach a case through the next iteration, which is not proof
of shared-return ownership. Dense guard folding inside a loop therefore retains
the narrower direct-comparison contract until raw-loop verification can prove
general predicate-DAG ownership.

## Real output

Before `9333881e`, `wide_selector_mixed` retained the range conditional but
discarded all six typed arms:

```c
int wide_selector_mixed(unsigned long long op) {
    if ((unsigned long)(op) <= (unsigned long)(5)) {
        /* unrecovered indirect jump through ... */
    }
    if (op == (-0x7fffffffffffffffLL - 1LL)) return 37;
    if (op != 0x100000000) return -1;
    return 36;
}
```

The production result is now deterministic, parseable C:

```c
int wide_selector_mixed(unsigned long long op) {
    switch (op) {
        case 0: return 30;
        case 1: return 31;
        case 2: return 32;
        case 3: return 33;
        case 4: return 34;
        case 5: return 35;
        default:
            if (op == (-0x7fffffffffffffffLL - 1LL)) return 37;
            if (op == 0x100000000) return 36;
            return -1;
    }
}
```

## Regression found and repaired

The first exact-tip def-use census changed Clang O2's aggregate improvement
from `288 -> 187` undefined reads to `288 -> 188` and dropped the existing
resolved finding for
`206_aarch64_wide_dispatch:clang:O2:dispatch_in_loop`. Direct inspection
confirmed a real regression: the output lost its loop switch, regained an
unrecovered indirect jump, and read `var10` without defining it.

That result was not accepted as baseline movement. The reduced arithmetic-
ancestry test, a new pinned-toolchain host Clang O2 fixture-206 regression, and
the existing ARMv7 A32 production round trip now jointly hold the boundary.
After `98a0d2d3`, fixture 206 again contains its structured loop switch, has no
`var10`, and passes 42 native differential cases, while fixture 215 retains its
new switch.

## Verification

The focused release-built checks pass:

```bash
cargo test --features python-ext 'ir::structure::tests::' -- --nocapture
uv run --no-sync pytest \
  python/tests/test_decompiler_control_flow_semantics.py::test_wide_selector_switch_borrows_default_shared_return \
  python/tests/test_decompiler_control_flow_semantics.py::test_transitive_wide_guard_does_not_steal_a_loop_switch \
  python/tests/test_decompiler_arch_roundtrip.py::test_a32_o2_loop_byte_switch_round_trips_in_v1 -q
```

- All 61 production-structurer unit tests pass.
- Both fixture-215 O2 cells move from `fail` to `pass`; no other fixture-215
  host cell regresses.
- The new fixture-206 host check passes 42 execution cases, and the existing
  ARMv7 A32 v1 execution test remains green.
- The test census moves from 4,637 to 4,638 declared tests, IR from 2,117 to
  2,118, and keeps the never-executed pool at zero.
- An exact clean checkout at `94d56bfa` passes the complete
  `cargo test --features python-ext` gate. Its library target reports 4,121
  passed, zero failed, and five ignored; every integration and documentation
  target also passes. The 531.41-second identity-retrieval target dominates the
  approximately ten-and-a-half-minute gate rather than the decompiler tests.
- The complete def-use census finishes four of six tests. Its two red tests are
  the pre-existing two-sided baseline ratchets. After removing pytest wrapper
  lines and deduplicating display lines, all 169 findings are byte-identical to
  the pre-increment report: fixture 206's resolved `var10` finding and the
  Clang-O2 aggregate `288 -> 187` are restored.
- The exact clean structural gate finishes 25 of 27 tests in 648.14 seconds.
  Its two red tests are likewise the existing regression and improvement
  ratchets; all 16 normalized findings are byte-identical to the exact
  `1ce1a80b` pre-increment report. In particular, the transient fixture-206
  `goto_free` movement seen at unhardened `6348000d` is absent rather than
  accepted as a misleading improvement.
- The exact clean def-use replay finishes four of six tests in 53.49 seconds
  and reproduces the same 169 normalized findings described above.

The complete 838-lane fixture harness exposed 38 older unrecorded movements,
including the independently known `rust_slice_get` regression. That wholesale
rewrite was rejected. Only the two attributable `wide_selector_mixed` O2 rows
were changed in `tests/decompiler_fixtures/baseline.json`.

The exact clean-checkout whole-Python result for the hardened tip must still be
recorded before this increment can support a release claim. Cross-architecture
wide-selector cells, GED, structure-axis movement, RSS, and output-size budgets
remain open WP5/WP4 obligations.
