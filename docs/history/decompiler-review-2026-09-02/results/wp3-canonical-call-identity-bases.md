# WP3 canonical call identity bases

Commit `2a33f6a5` stops two call-recovery readers from reparsing authoritative
identity bases as display names.

The shared recovered-layout storage predicate now compares an identity's base
exactly with the requested architectural storage. The System V SSE-pair
forwarder likewise recognizes only exact `xmm0`/`xmm1` or exact declared lane
identities after the sidecar has resolved a value. The explicit no-sidecar
compatibility paths still accept value-numbered `#version` display spellings.

Two adversarial cases were observed red before the production change: an
identity whose malformed base was `rdi#not_canonical` impersonated `rdi`, and
one whose malformed base was `xmm1#not_canonical` incorrectly blocked
forwarding of a proven SSE-pair result.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::storage_match_does_not_reparse_an_authoritative_identity_base \
  -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::sysv_sse_pair_clobber_uses_exact_identity_not_display_spelling \
  -- --exact
cargo test --features python-ext --lib \
  ir::call_args::tests::recovered_layout_setup_uses_exact_identity_not_display_spelling \
  -- --exact
# 1 passed in each command; 4,493 filtered out in each

uv run maturin develop
uv run python tools/build_guard.py
# fresh; native SHA-256
# 39e990680aef57dd9f8d912ad30966c09eb5898007714e623a849b78305c387b

uv run python tools/dectest.py \
  197_homogeneous_float_aggregates:gcc:O2:hfa197_tagged_control
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used.

