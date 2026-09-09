# WP3 return-role naming identities

Commit `b6e1f92d` moves production return-role naming off value-numbered
register spelling and onto `ValueIdentities`' producer-owned physical-storage
fact.

Previously, `apply_role_names` recognized a directly returned value by passing
its rendered name to `abi::is_return_register`. That compatibility predicate
strips `#version`, so the production path still treated presentation text as
semantic evidence. The new identity-aware entry point recognizes opaque and
coalesced values when their sidecar has one unambiguous result-register base,
and declines misleading `rax#...` text whose identity belongs to other storage.
The identity-free public wrappers retain their compatibility behavior.

This is one bounded step toward keeping naming at the presentation boundary. It
does not remove `tag_phys`: value numbering still encodes identity in internal
names, and the wider naming rewrite remains a WP3 exit criterion.

## Focused evidence

The owning module was tested without running the repository-wide Rust suite:

```text
cargo test --features python-ext --lib ir::naming::tests:: --quiet
22 passed; 0 failed; 4695 filtered out
```

The new adversarial contract covers both directions: an opaque value with an
exact `rax` storage identity becomes `ret`, while a value merely spelled
`rax#looks_like_a_result` with an `rdi` identity becomes an ordinary `var0`.

A clean detached worktree at `b6e1f92d` supplied the release extension. One
directly owning canonical x86-64 Hello slice then remained green:

```text
python -m pytest -q --tb=short \
  python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical \
  -k 'gcc and O2 and pie and symbols'
2 passed
```

The selector intentionally covers both PIE and non-PIE symbol-bearing GCC O2
cells (`pie` is also a substring of `nonpie`). No broad Python suite, fixture
corpus, DecBench run, or redundant 72-cell Hello matrix was run for this small
identity-only increment.

## Read-only role-map boundary

Follow-on commit `358e0408` separates the calculation from its legacy AST
rewrite. `role_names_with_identities` now accepts an immutable `Function` and
returns the complete deterministic presentation map. The independently named
`apply_role_name_mapping` operation performs the rewrite explicitly. The
production pipeline calls these in sequence for byte-compatible output today;
future WP3 increments can migrate downstream semantic consumers before moving
or deleting that second call.

The adversarial return-role test now snapshots the complete `Function`, computes
the map, and proves the semantic AST is byte-for-byte structurally unchanged
before applying the map. Focused evidence remains:

```text
cargo test --features python-ext --lib ir::naming::tests:: --quiet
22 passed; 0 failed; 4695 filtered out
```

A release build from a clean detached worktree at `358e0408` retained both
selected symbol-bearing GCC O2 x86-64 Hello cells:

```text
python -m pytest -q --tb=short \
  python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical \
  -k 'gcc and O2 and pie and symbols'
2 passed
```

No broader suite or corpus was run for this behavior-neutral separation.

## Semantic cleanup before presentation mutation

Commit `0be1594d` moves the explicit role-name rewrite to the end of the common
AST pass sequence. Dead-store elimination, canary/frame cleanup, stack-idiom
rematerialization, and label pruning now run while the AST still carries its
machine/value identities. They receive the projected sidecar, which contains
both original identities and the future presentation aliases. Only after those
semantic passes finish does the pipeline mutate names for its current renderers.

The pass-order contract now rejects any attempt to put dead-store elimination
back behind presentation naming. Focused validation was:

```text
cargo test --features python-ext --lib ir::naming::tests:: --quiet
22 passed; 0 failed; 4695 filtered out

cargo test --features python-ext --lib ast_pass_order_ --quiet
2 passed; 0 failed; 4715 filtered out

cargo test --features python-ext --lib ir::dead_stores::tests:: --quiet
49 passed; 0 failed; 4668 filtered out
```

A clean detached worktree at `0be1594d` produced the release extension. Running
from that exact worktree (so its package, rather than the shared checkout, was
first on `sys.path`) proved both selected GCC O2 x86-64 Hello cells green and
the exact effect-only-call lane regression-free:

```text
python -m pytest -q --tb=short \
  python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical \
  -k 'gcc and O2 and pie and symbols'
2 passed

python tools/dectest.py 11_call_shapes:gcc:O2:call_result_unused --show
SCOPED: 1 lane of 838 - no regressions in scope
```

The initial main-checkout invocation was rejected as stale by `build_guard.py`
and is not evidence. No broad suite, corpus, or DecBench run was performed.
