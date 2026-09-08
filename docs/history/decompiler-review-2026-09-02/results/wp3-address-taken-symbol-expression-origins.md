# WP3 address-taken symbol expression origins

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `5dcd837c` makes the address-taken named-symbol inventory recurse through
expression-origin carriers. A named callback or other function address used as
a value therefore remains a declaration candidate after provenance is
attached.

The existing fail-closed authority rule is unchanged. Merely taking a symbol's
address contributes an empty observation list and does not invent a function
prototype. A declaration is emitted only when the program-level symbol
environment independently supplies the callee's signature.

## Focused TDD

The new contract wraps a named callback value in an `OriginSet` and invokes the
private inventory boundary directly. Before the repair, the candidate was
missing:

```text
left: None
right: Some([])
```

After adding the missing origin recursion, the complete named-call module
passes:

```text
cargo test --features python-ext --lib ir::ast::named_calls::tests -- --nocapture
4 passed; 0 failed; 4,672 filtered out
```

The adjacent tests retain exact observed prototypes, deterministic variadic
common-prefix recovery, and machine-word fallback for conflicting returns.

## Release evidence and scope

`uv run maturin develop --release` completed successfully. No committed
decompiler fixture currently exercises an attributed named function address as
a callback value, so no fixture result is claimed and no broad corpus sweep was
substituted for that missing witness.

This is one bounded WP3 expression-inventory consumer. It does not weaken the
symbol-environment authority rule, infer callback types, or complete universal
expression attribution.
