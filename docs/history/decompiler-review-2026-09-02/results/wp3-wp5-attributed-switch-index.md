# WP3/WP5 attributed switch-index recovery

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `144211a0` restores the i386 O2 GOT-relative switch cells after WP3
statement-origin attribution exposed a semantic-transparency omission in AST
lowering. The jump-table analysis and case edges remained correct, but the
fallback that recovered the table index matched only a bare `Stmt::Assign`.
Once that assignment was carried inside an origin wrapper, lowering missed its
scaled index and rendered a fresh, undeclared switch discriminant.

Switch-index recovery now reads each prefix statement through
`Stmt::semantic()`. Origin metadata is therefore preserved without becoming a
semantic barrier. The change is deliberately local: it does not weaken the
jump-table proof, infer new case targets, or accept an unproved table.

## Evidence

- The focused Rust regression wraps a scaled dispatch-table load in an
  `OriginSet` and proves that its index remains recoverable.
- A release extension rebuild completed successfully.
- Both exact previously failing fixture functions pass:
  `206_aarch64_wide_dispatch:i386:O2:dense_dispatch` and
  `206_aarch64_wide_dispatch:i386:O2:dispatch_in_loop`.
- The owning `test_i386_o2_got_relative_switches_round_trip` pytest passes.

This closes one concrete WP3 consumer migration and restores the associated
WP5 output capability. It does not complete the remaining semantic-consumer
audit or the broader switch matrix. No DecBench run or upstream interaction
was performed.
