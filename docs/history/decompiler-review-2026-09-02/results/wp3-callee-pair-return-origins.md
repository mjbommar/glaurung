# WP3 callee pair-return origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `8989cecc` migrates `src/ir/callee_return_pair.rs` to the statement-origin
carrier. Integer-pair return recognition now sees attributed assignments and
returns, mutates the semantic return in place, and therefore retains the
return statement's exact owner. The same slice adds a conservative bank
boundary: an explicit floating-point low result cannot be reinterpreted as an
integer pair merely because another return lane is present.

This is an ownership and soundness migration, not a claim that general
multi-register return recovery is complete. In particular, the separate
SplitBanks path remains responsible for heterogeneous aggregate returns.

## Evidence

Both focused tests were observed red before their production changes. The
complete module then passed:

```text
cargo test --features python-ext ir::callee_return_pair::tests --lib
9 passed; 0 failed
```

The release-built focused Python gate covered the call/return invariants and
the declaration regression previously reported as undeclared `stack_3` or
`local_c`:

```text
30 passed
```

The complete stripped/debug JSON is byte-identical to the preceding accepted
canary boundary:

```text
102 regressions; 18 improvements; 0 infrastructure problems
```

The complete Rust gate is green:

```text
library: 4,291 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory whole-Python run retained the exact 211 accepted semantic
failure nodes. It also reported the build-fingerprint guard because the next
source batch was edited while the already-running suite was in progress; that
mechanical node is not a decompiler-result change:

```text
212 failed; 4,592 passed; 78 skipped; 128 deselected; 876 xfailed
semantic failure-set delta: 0 added; 0 removed
transient added node: test_build_guard_reports_the_native_binary_fingerprint
```

A narrow release A/B also established that all four current
`bv195_make_mixed` fixture regressions occur with this file restored to its
parent version and produce identical C. Pass dumping locates that defect in
the separate SplitBanks `compose_bank_returns` path, so it is neither caused
nor concealed by this increment.

## Next ordered increment

Continue the enabled WP3 consumer audit. Batch closely related call-analysis
readers behind focused carrier tests, then pay the broad gates once for the
coherent batch rather than once per reader.
