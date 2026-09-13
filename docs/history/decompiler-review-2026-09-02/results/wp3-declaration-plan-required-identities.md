# WP3 declaration planning requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `b1bce1a1` removes `varN` display spelling from declaration-plan identity
eligibility when the pipeline provides `ValueIdentities`. Recovered pointer,
integer, width, and local declaration facts now require an authoritative
parameter role, promoted stack object, or unambiguous physical-storage identity.
Generated-temporary spelling remains available only to explicit render calls
that have no sidecar.

This prevents an unowned name such as `var99` from injecting a narrow, unsigned,
or pointer declaration into the rendered C merely because it resembles an
internal generated value.

## Red and green evidence

The new focused contract was observed red before the condition changed:

```text
generated_temporary_spelling_is_not_identity_when_sidecar_is_installed
assertion failed: !is_identity_value("var99", Some(&identities))
```

After the repair:

```text
ir::ast::declaration_plan: 8 passed, 0 failed
decbench_ render filter:   86 passed, 0 failed
```

A fresh release build completed and `tools/build_guard.py` reported `fresh`
with native SHA-256
`7730bbb6686b07886fad685690d22424b35349087fefeb47c9f4bd9a1b8d93f5`.
The periodic canonical Hello sample passed all six symbols/PIE GCC cells: O0
and O2 on x86-64, AArch64, and ARMv7.

The census advances by the one owned Rust test (`total_declared` 5,352 to
5,353; `ir` 2,618 to 2,619). Other edits in the shared worktree were not staged.
No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

This closes declaration planning's generated-temporary spelling authority. It
does not complete the remaining WP3 semantic-reader audit, universal origin
attribution, or removal of `tag_phys` inside value numbering.
