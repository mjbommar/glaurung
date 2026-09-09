# WP3 coalesced call-result identity

Commit `81c33138` migrates call-result attribution from exact-single-candidate
SSA lookup to the identity sidecar's unambiguous physical-storage fact. A
rendered value may legitimately represent several non-interfering SSA versions
after phi-copy coalescing. When every candidate comes from the ABI return
register, a read of that value still proves the call result is consumed and the
call must retain its destination.

The rule remains fail-closed. A value whose candidates contain different
physical bases does not match the return register, and production paths with an
identity sidecar never parse the rendered `name#version` spelling. The legacy
spelling fallback remains only for callers that supply no identity artifact.

## Focused evidence

```text
cargo test --features python-ext --lib \
  call_args::return_attribution::tests::
3 passed; 4,751 filtered out
```

The tests cover an incorrectly spelled value with a non-result identity, an
opaque exact result, two coalesced `rax` versions, and a mixed `rax`/`rdi`
candidate set. The mixed set is rejected by the storage predicate while the
outer scan retains its established conservative lexical-fallthrough policy.

An exact detached release build of `81c33138` produced native SHA-256
`8b190c51b08d85552c50582444120aae70e788023c3a1e3fed6334ced26260ab`.
The GCC O0/O2 `11_call_shapes:call_result_drives_branch` controls both pass and
their rendered SHA-256 values are byte-identical to the exact parent:

```text
O0  fc693ac00b9883ac51ece77786c44cfcf96dea9d61e2617a0d415bf48fc6e9e5
O2  093047e6b64cae041fc909dcfa57f670c200a624f444c153874b1851cc3ef501
```

No checked-in control in that pair requires the newly accepted coalesced
identity, so this is a capability migration rather than an attributed output
improvement on those binaries. The periodic six-cell Hello checkpoint passed
on the preceding output-changing increment and was not repeated. No broad Rust,
Python, fixture, architecture, DecBench, or Joern suite ran.
