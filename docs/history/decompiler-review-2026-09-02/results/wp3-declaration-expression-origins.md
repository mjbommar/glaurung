# WP3 declaration expression origins

Commit `79bcb911` closes two output-facing expression-origin holes in the shared
identifier census.

- A 16-byte dereference retains wide-vector declaration evidence when the load
  expression carries an `OriginSet`.
- A literal or named absolute address retains portable global-storage evidence
  when the address expression carries an `OriginSet`.

Both strengthened contracts were observed red. The wide load was classified
as an ordinary scalar local. The global load lost its backing declaration and
rendered as the raw process address `*(int *)(0x4024)`. The repair makes only
the two classifiers semantic-expression aware; it preserves all provenance and
does not widen the accepted address or load shapes.

Focused Rust validation:

```text
attributed_wide_load_keeps_vector_declaration_evidence: 1 passed
decbench_portable_static_storage: 2 passed
three adjacent scalar/global rendering contracts: 3 passed
```

An exact detached release build of `79bcb911` was fresh. The dedicated writable
global fixture passed all four GCC/Clang O0/O2 round-trip lanes and emitted no
raw process address. Its final spelling assertion exposed an independent stale
test assumption: the test allowed only byte-array storage although stronger
current recovery emits `static int g_counter;`. Commit `82fb7456` updates that
assertion to accept either a byte array or a proven integer scalar while still
requiring named static storage and rejecting raw addresses. The exact focused
Python test then passed.

No broad suite ran. The periodic six-cell Hello checkpoint was not repeated
because it passed immediately before this increment on x86-64, AArch64, and
ARMv7 at O0/O2.

This closes one bounded declaration-consumer family, not WP3. Remaining enabled
expression consumers and universal production attribution stay open.
