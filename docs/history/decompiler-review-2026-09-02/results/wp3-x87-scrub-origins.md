# WP3 x87 scrub origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `8bfadfa9` makes the hardened x86-64 return scrub recognizer transparent
to statement origin carriers. It retains the existing fail-closed proof: only
an exact suffix of eight `fldz` operations followed by eight `fstp` operations
immediately before a return is removed. Any incomplete or differently ordered
x87 sequence remains visible.

The replacement epilogue comment receives the exact union of every consumed
x87 instruction and any contiguous positive stack adjustments proven to be
part of the same teardown. The surviving return retains its independent owner.

## Focused evidence

The attributed scrub test was observed red before repair: all 16 wrapped x87
operations remained in the body. After repair they collapse to one comment
with the exact address set `0x1000..0x103c`, followed by the independently
owned return.

```text
cargo test --features python-ext \
  ir::x86_prologue::tests::attributed_x87_scrub_unions_exact_machine_owners_on_the_comment \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::x86_prologue::tests
35 passed; 0 failed; finished in 0.21s
```

A fresh release extension was built in 34.83 seconds. No checked-in fixture
currently compiles with `-fzero-call-used-regs=all`; the historical real target
is in upstream DecBench, which was not run under the repository's autonomous
interaction boundary. No broad Rust, Python, architecture, or fixture sweep
was run.

## Next action

Continue the bounded audit of `collapse_epilogue`. Its remaining raw matches
cover ordinary `leave`/`pop rbp` spellings and should be migrated as one
transaction that assigns exact consumed origins to each replacement comment.
