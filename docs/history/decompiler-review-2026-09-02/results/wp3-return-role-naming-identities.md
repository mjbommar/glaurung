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

## Naming after AST finalization

Commit `5555d85d` moves the remaining mutation out of `run_ast_passes` and to
the end of `finalize_prepared_ast`. Exception recovery, architecture-specific
frame cleanup, DWARF local merging, and PDB field annotation now all operate on
the unrenamed semantic AST with the projected identity sidecar. The mutation is
still required by the current renderers, but no semantic AST pass precedes it
in the shared pipeline anymore.

Focused Rust checks retained the read-only mapping and revised order contracts:

```text
cargo test --features python-ext --lib ast_pass_order_ --quiet
2 passed; 0 failed; 4715 filtered out

cargo test --features python-ext --lib ir::naming::tests:: --quiet
22 passed; 0 failed; 4695 filtered out
```

The release extension came from a clean detached worktree at `5555d85d`.
`build_guard.py` reported that exact worktree extension fresh, with SHA-256
`42bf4fe42b4da3eb943396b467eef40538784f09a0ef832247234fafb2ed956c`.
Targeted output checks were:

```text
# GCC O2, x86-64, symbol-bearing PIE and non-PIE
2 passed

# GCC O2, ARMv7 and AArch64, symbol-bearing PIE and non-PIE
4 passed

python tools/dectest.py \
  11_call_shapes:gcc:O2:call_result_unused \
  10_cpp_runtime_shapes:clang:O2:cpp_exception --show
SCOPED: 2 lanes of 838 - no regressions in scope
```

No full Hello matrix, broad suite, fixture corpus, or DecBench run was needed
for this bounded ordering change.

## Immutable semantic AST at the renderer boundary

Commit `a15e92a7` completes the production-side separation. Finalization no
longer applies the role map. The one shared renderer creates a cloned
`role_named_render_view`, applies `argN`/`ret`/`varN` presentation aliases only
to that view, and passes the view consistently to typed DecBench, typed C,
plain C, and diagnostic rendering. `PreparedAst.function` remains in the
semantic value-identity space before, during, and after rendering.

The naming contract now proves both stages are non-mutating: calculating the
map preserves the source `Function`, and building the named render view also
preserves it. The compatibility `apply_role_names*` APIs still mutate their
explicit caller-owned function, so their eventual deletion remains paired with
the final `tag_phys` migration.

Focused Rust evidence:

```text
cargo test --features python-ext --lib ir::naming::tests:: --quiet
22 passed; 0 failed; 4695 filtered out

cargo test --features python-ext --lib ast_pass_order_ --quiet
2 passed; 0 failed; 4715 filtered out
```

A clean detached worktree at `a15e92a7` produced a fresh release extension
with SHA-256
`824aae1650659f8a37e491c156a41ec02ab73a1e61ffe885a767163f44fdcca2`.
The same six selected O2 Hello cells across x86-64, ARMv7, and AArch64 passed,
and the effect-only-call plus C++ exception lanes remained regression-free.
The deterministic structured line-mapping test also passed with the exact
worktree package forced first on `PYTHONPATH` while using the main checkout's
generated fixture directory.

The first line-mapping invocation inside the detached worktree failed because
its generated `01_conditional_polarity-gcc-O0.so` fixture was absent. That is an
infrastructure result and is not counted as product evidence. No broad suite,
full fixture corpus, full Hello matrix, or DecBench run was performed.
