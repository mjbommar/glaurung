# WP3 guarded-switch identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `5389ca0a` makes range-guarded switch cleanup identity-required in every
production path. Its untyped and typed spelling-only entry points are now
test-only, while both shipped entry points require the pipeline's
`ValueIdentities` snapshot. The recursive engine carries a closed authority
whose legacy promoted-local spelling variant does not exist in non-test
builds.

This prevents a future production caller from treating a pointer store through
a value merely named `local_*` as a lossless promoted-object discriminator
copy. A stack-backed switch discriminator qualifies only when the identity
sidecar owns it as a promoted stack object.

## Focused evidence

```text
cargo test --features python-ext ir::guarded_switch::tests:: -- --test-threads=1
20 passed; 0 failed

cargo check --features python-ext --lib
pass
```

The slice covers the identity-owned positive case, the misleading unowned
`local_*` refusal, width-preserving and narrowing casts, case-range and default
semantics, trapping expressions, control-flow shapes, read counts, and origin
composition.

A fresh debug extension passes `tools/build_guard.py`. The required
whole-Python fail-fast gate passes the repaired 11% ARM region and again
reaches 17%, where the committed `arch_baseline.json` and `baseline.json`
control rows disagree. This commit changes neither ledger.

This closes one WP3 authority seam that supports WP5 switch quality. It is not
an output-change claim; the production pipeline already selected the exact
entry points. Remaining optional identity engines, invalidation, and origin
tracking stay open.
