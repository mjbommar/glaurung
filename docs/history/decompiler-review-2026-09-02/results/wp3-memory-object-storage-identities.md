# WP3 memory-object storage identities

Commit `925bf81f` moves promoted-store classification in the prepared-AST
memory-object adapter from display spelling to pipeline-owned identities.

`high_variables` uses this model to decide whether an apparent pointer value is
a conflict-free aggregate cursor. It already received `ValueIdentities`, but
discarded them when calling `infer_from_ast`. The adapter then interpreted a
bare-register `Stmt::Store` as a scalar definition solely when the destination
began with `local_*` or `stack_*`. An opaque renamed cursor could become a fake
indirect access, while a suggestively named unowned pointer store could become
a scalar definition and acquire object semantics.

`infer_from_ast` remains the identity-free compatibility API. The new
`infer_from_ast_with_identities` carries one optional sidecar through every
nested body, and production high-variable refinement passes through the
authority it already owns. The positive contract proves an opaque promoted
cursor retains its 64-byte stride and two ordered access paths. The negative
contract proves an unowned `local_*` store remains an offset-zero pointer
write.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::memory_objects::tests::opaque_promoted_cursor_recovers_object_by_identity -- --exact --test-threads=1
1 passed; 4653 filtered out

cargo test --features python-ext --lib ir::memory_objects::tests::unowned_local_spelling_is_observed_as_a_pointer_store -- --exact --test-threads=1
1 passed; 4653 filtered out

cargo test --features python-ext --lib ir::memory_objects::tests:: -- --test-threads=4
11 passed; 4643 filtered out

cargo test --features python-ext --lib ir::high_variables::tests:: -- --test-threads=4
35 passed; 4619 filtered out; test execution 0.22s

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_memory_objects.py::test_stripped_aggregate_cursor_preserves_byte_stride_and_execution -q
1 passed
```

The compiled check initially rejected improved initialized output
`char * local_8 = ...;` because its regex required an uninitialized declaration
ending immediately after the identifier. The matcher now extracts the cursor
from either form; its following stride, no-wrong-stride, generated-C compile,
and runtime-equivalence assertions are unchanged.

The isolated committed-tree census records 5,186 declared Rust tests, 2,481 in
IR, and zero outside every gate. This closes the memory-object adapter's
storage-name reader; it does not complete WP3's remaining semantic-reader
audit, expression ownership, or universal identity lifecycle.
