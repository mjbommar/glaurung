# WP3 readonly expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `e72a8d77` makes readonly scalar and bounded-table folding transparent to
expression provenance. Attributed dereferences, addresses, casts, constants,
indices, scaled addresses, and range guards now retain the same proof as plain
expressions. Synthesized constants and select trees receive the deterministic
union of every consumed expression owner, flattened into one carrier.

All existing bounds remain mandatory: complete readonly bytes, exact widths,
safe unsigned or independently nonnegative signed guards, bounded table size,
and mutation barriers still fail closed.

## Focused TDD

Two contracts were strengthened with expression owners. Before repair, the
direct scalar remained an absolute dereference and the proven table remained a
non-portable image load. After repair:

```text
direct_readonly_scalar_load_becomes_a_portable_constant: pass
terminating_upper_bound_guard_materialises_the_fallthrough_lookup: pass
ir::readonly_fold: 10 passed, 4,686 filtered out
```

The scalar contract additionally proves that the dereference and address
owners are unioned onto the replacement constant.

## Release real-binary evidence

After a clean detached release build at `e72a8d77`, the directly owning
AArch64 optimized readonly-switch round trip passes. The two AMD64 GCC
symbols/non-PIE Hello O0/O2 cells remain red with `0x402004` instead of the
string literal. That separate direct-address/reference-resolution debt is not
fixed or hidden by this dereference/table migration.

No broad Rust, Python, fixture, DecBench, or Joern run was performed.

## Scope

This closes the readonly-fold expression consumer and ownership-transfer
surface. Universal expression attribution, the remaining wildcard audit, and
the non-PIE direct-address Hello defect remain open.
