# WP3 tail-call expression origins

Commit `7e65572a` closes the expression-ownership layer deliberately left open
by the earlier statement-origin tail-call migration.

Resolved GOT-indirect and proven Rust vtable tail-call recovery now inspect
semantic expressions through provenance carriers. This covers the indirect
transfer target, GOT dereference and named slot, vtable load and address,
terminal target register, direct prototype-bearing callee, constant slot
offset, and recursively nested high-word extraction. The recovery proofs are
unchanged: unresolved computed jumps, unaligned/non-method vtable slots,
scalar-returning callees, overwritten high result words, and ambiguous
identities still refuse.

When a provenance-wrapped GOT dereference becomes a call, its slot-load and
named-target contributors are unioned on the surviving callee expression.
Vtable target expressions and the enclosing transfer owner likewise survive
the rewrite.

Two strengthened ownership contracts were observed red before the repair: the
attributed GOT target remained an `IndirectGoto`, and the attributed vtable
target failed to become the terminal call. After the repair:

```text
cargo test --features python-ext --lib ir::call_args::tail_calls::tests --quiet
15 passed
```

An exact detached release build of `7e65572a` was fresh. The focused fixture
slice requested only tail-position functions:

```text
06_calling_conventions:{gcc,clang}:O2:{forward_sum6,tailcall_to_sum4}
4 requested cells passed

08_indirect_dispatch:{gcc,clang}:O2:tail_dispatch
2 requested cells passed

167_rust_trait_objects:rustc:O2:rust_dyn_apply
known baseline fail; no regression; terminal vtable call remains recovered
```

Direct inspection of `rust_dyn_apply` confirms the final expression is still a
call through the method pointer loaded from vtable offset 24. Its extra
parameter and source-type/readability debt predate this increment and remain
WP6/WP9 work.

The periodic canonical Hello checkpoint passed exactly six GCC symbols/PIE
cells: O0 and O2 on x86-64, AArch64, and ARMv7. No broad Rust, Python, fixture,
DecBench, or Joern suite ran.

This closes one bounded tail-call expression-consumer family, not WP3.
Universal production attribution, explicit invalidation, and the remaining
enabled expression-consumer audit stay open.
