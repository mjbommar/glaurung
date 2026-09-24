# WP3: remove machine identity from numbered value keys

> **Kind:** record · **Date:** 2026-09-12

Code commit: `8f5285b9`

## Result

Production value numbering no longer serializes semantic identity as
`reg#version`, and `tag_phys` no longer exists under `src/`.

Each ordinary physical-register definition/use now receives the deterministic
opaque key owned by the authoritative SSA snapshot's `ValueId`. The sidecar
continues to carry the exact `SsaValue`, physical storage, width, parameter,
result, and promoted-object facts. Semantic consumers therefore cannot recover
machine meaning by inspecting the internal key. Version-zero live-ins,
structural frame registers, and deliberately kept-bare result values retain
their canonical spelling because those are explicit pipeline roles, not
encoded SSA identities.

Definitions now receive their complete SSA value from the indexed snapshot,
matching the already-typed use path. This was required by the ARM64 Hello
canary: the first implementation reconstructed a value from a raw destination
alias and panicked when that spelling differed from the snapshot's canonical
base. Passing the owned `SsaValue` fixes the boundary without an
architecture-specific exception.

## Red/green evidence

The strengthened
`ir::value_number::tests::opaque_ssa_identity_survives_llir_to_ast_lowering`
contract was observed red against the old implementation:

```text
numbered value keys must be opaque, not encoded machine identity: rax#1
```

After the cutover:

```text
cargo test --features python-ext --lib ir::value_number:: -- --test-threads=1
68 passed; 0 failed

cargo test --features python-ext --lib ir::naming::tests:: -- --test-threads=1
23 passed; 0 failed

cargo test --features python-ext --lib python_bindings::ir::tests:: -- --test-threads=1
20 passed; 0 failed

uv run python tools/dectest.py @smoke
SCOPED: 4 lanes of 838 (0%) — no regressions in scope
```

After `uv run maturin develop --release`, four focused Hello integration tests
passed:

```text
python/tests/test_cli_decompile.py::test_decompile_entry_prints_pseudocode
python/tests/test_cli_decompile.py::test_decompile_arm64_main_shows_prologue_and_epilogue
python/tests/test_cli_decompile.py::test_decompile_arm32_thumb_recovers_main
python/tests/test_cli_decompile.py::test_decompile_x86_o0_main_shows_prologue_and_epilogue
4 passed
```

Direct DecBench-style decompilation of the x86-64 O2 `_start`, AArch64 `main`,
and ARM32 sample function completed, and a search over all three outputs found
zero `value[0-9]+` or `#[0-9]+` leaks. The fresh release extension SHA-256 was
`d3614579c70fb4e9956a65e90f3758e67e74b44a119c8c5980ac7bc43c32f94c`.
Because the checkout contained unrelated concurrent source edits, this is
fresh-tree runtime evidence, not an exact-clean-build provenance claim.

The ARM32 sample still emitted its existing one-undefined-read health warning;
this change neither introduced nor concealed that separate correctness debt.

## Deliberate limits

No broad Rust/Python suite, corpus matrix, DecBench, or Joern run was performed.
An attempted focused output-canary file had three setup errors because the
concurrent checkout's `src/lib.rs` no longer exposed its expected `scratch`
module; the separate determinism tests in the same command passed. That setup
failure is outside this commit's owned diff and is not counted green.

Compatibility-only parsers for hand-written identity-free tests remain where
their APIs explicitly receive no sidecar. The next WP3 audit should decide
whether to delete those compatibility entry points with their legacy mutating
naming surface; it must not restore machine semantics to the new opaque keys.
