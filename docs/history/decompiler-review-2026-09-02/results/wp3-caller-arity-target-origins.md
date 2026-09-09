# WP3 caller-arity target origins

Commit `ed4e1eee` closes a bounded expression-origin hole in caller-derived
fixed-arity recovery. `stack_proven_direct_call_arities_with_identities` now
classifies the semantic payload of a direct call target, so an `OriginSet`
carrier cannot hide an otherwise requested literal or named target.

The strengthened test first reproduced the defect: the attributed call target
caused the complete balanced-stack proof to return no candidate rather than the
expected eight-argument candidate. The repair changes only target recognition;
the SysV AMD64 restriction, requested-target filter, balanced outgoing-stack
proof, exact cleanup requirement, and environment agreement policy are
unchanged.

Focused validation:

```text
cargo test --features python-ext --lib ir::caller_arity::tests:: --quiet
4 passed; 0 failed

pytest -q python/tests/test_decompiler_caller_arity.py
1 passed
```

The Python check used a clean release build of exact commit `ed4e1eee`; the
native build guard reported `fresh`. No broad suite was run. The periodic Hello
checkpoint was not repeated because the immediately preceding WP3 checkpoint
already passed its x86-64, AArch64, and ARMv7 GCC-O2 cells, and this change is
confined to requested direct targets with stack-proven arity.

This is not WP3 completion. The remaining enabled expression consumers and
universal production attribution stay open.
