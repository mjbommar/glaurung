# WP3 vector-copy identities

Status: bounded production consumer migration landed at `9e43b52b` on
`agent/wp5-next-switch`.

## Result

Packed-vector copy recovery now resolves each XMM lane and synthesized wide
view through the pipeline-owned `ValueIdentities` sidecar. Production no longer
decides that `xmmN_dM#version` values belong together by parsing their rendered
names. Missing, ambiguous, or contradictory identities decline the transform.

The compatibility entry point retains spelling parsing for legacy callers that
have no identity sidecar. A focused negative test maps a value spelled
`xmm0_d0#9` to exact `rax` identity and proves that it cannot impersonate an
XMM lane. The same test maps an opaque spelling to exact `xmm3_d2` version 7
and proves recovery uses the semantic identity.

## Focused evidence

Build fingerprint: commit `9e43b52b`, debug Cargo/maturin profile, CPython
3.14, `python-ext` enabled.

```text
/usr/bin/time -v cargo test --lib --features python-ext \
  ir::vector_copy::tests -- --nocapture
9 passed; 0 failed; 4,457 filtered out
elapsed 11.27 s; maximum RSS 2,792,788 KiB

uv run maturin develop
completed in 16.9 s

/usr/bin/time -v uv run python tools/dectest.py \
  188_vector_transport:gcc:O2 --show
SCOPED: 1 lane of 838 -- no regressions in scope
elapsed 4.89 s; maximum RSS 93,424 KiB
```

The first un-timed run and the post-format replay were also green at 9/9. The
new exact-identity test was introduced with the implementation; its negative
case is the previous spelling behavior expressed as an explicit refusal.

## Measurement boundary

This is intended as an identity-authority migration, not an output-changing
feature. The one directly owning C fixture lane is unchanged and green. No Rust
fixture was in scope, so C counts are one unchanged lane and Rust counts are
zero evaluated lanes. Gotos, switches, breaks, output bytes, GED, types, and
Union are unchanged for the evaluated lane; the scoped harness reports no
execution regression. No full Rust/Python suite, fixture matrix, DecBench, or
Joern run was used for this bounded increment.

## Remaining scope

This removes the packed-vector production `#version` parser from the WP3
semantic-reader inventory. It does not remove value-numbering tags, migrate the
remaining call/type readers, establish expression ownership, or complete WP3.
