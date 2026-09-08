# WP3 promoted-store type identities

Commit `84c33d9e` migrates two coupled presentation-name readers in typed output
cleanup to producer-owned promoted-stack identity.

`typed_simplify` removes an outer machine-width zero extension when a recovered
narrow integer destination proves those high bits unobservable. A bare-register
`Stmt::Store` represents either a promoted scalar assignment or an indirect
pointer write. Previously the pass decided between them by `local_*` spelling.
That missed an owned object after an opaque rename and trusted an unowned value
whose name merely looked local.

The first observed-red regression proves an opaque `frame_object` marked as a
promoted stack object consumes the redundant extension. The second proves an
unowned `local_looks_promoted` retains it. Following the positive failure also
identified the same spelling dependency in `declared_int_type_with_identities`:
the shared width query described promoted slots in its contract but returned a
machine-wide declaration for an opaque owned slot. Both consumers now use the
identity sidecar whenever present and reserve the old spelling rule for the
identity-free compatibility API.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::typed_simplify::tests::identity_ -- --test-threads=1
2 passed; 4646 filtered out

cargo test --features python-ext --lib ir::typed_simplify::tests:: -- --test-threads=4
5 passed; 4643 filtered out

cargo test --features python-ext --lib ir::ast::return_ctype::tests:: -- --test-threads=4
5 passed; 4643 filtered out

uv run maturin develop
success

uv run python tools/dectest.py 194_narrow_return_widths:clang:O0:nrw194_u8_value_control --show --allow-stale
1 scoped lane; no regressions

uv run pytest \
  python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-clang] \
  python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-clang] \
  python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-aarch64] \
  python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-aarch64] -q
4 passed
```

The narrow-local fixture required `--allow-stale` only because the concurrent,
untracked `src/disasm/native_aarch64.rs` was touched after this extension was
built. `tools/build_guard.py` named that as the sole freshness offender. The
extension was rebuilt after both files in this commit changed, so the result is
valid for this WP3 slice but is not evidence that the complete dirty checkout
was globally fresh.

The isolated committed-tree census records 5,180 declared Rust tests, 2,475 in
IR, and zero outside every gate. This increment improves typed expression
readability and declaration fidelity, but does not complete WP3's remaining
semantic-reader audit, expression ownership, or universal identity lifecycle.
