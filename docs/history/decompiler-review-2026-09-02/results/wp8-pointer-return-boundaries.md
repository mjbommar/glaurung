# WP8 pointer-return boundary evidence

Date: 2026-09-04

## Defect

The real optimized linked-list fixture recovered the source return type and
the returned local as `node *`, but retained a pointer-width integer transport
cast in the AST. The scored renderer therefore emitted:

```c
return (node *)((long)var0);
```

That text is noisier than the declarations justify and obscures that the
returned value is already a pointer. Clang's equivalent fixture used the local
name `ret` and had the same representation boundary.

## Change

Implementation commit: `7c747d820ffaab2ca90ec28af147d42ae79bdc53`.
Base revision: `eac1661715f0213a1d8f7d271f1d279b89ef92ed`.

`src/ir/ast/dec_render.rs` now treats the declaration plan as the authority
for whether a physical-register value has pointer representation. At a
pointer-typed assignment or return boundary it removes exactly one
pointer-width integer cast when the inner register is already declared as a
pointer. It emits the register directly for the same type or a `void *`
compatibility boundary, but retains a pointer-to-pointer cast when two
concrete pointee types differ.

This is deliberately a render-boundary repair. It does not infer a pointer
from an integer carrier, remove narrowing casts, or make incompatible pointer
types silently interchangeable.

`src/ir/ast.rs` contains the focused contract test: a `char *` parameter
transported through a machine-word cast returns directly from a `char *`
function, while returning it from an `int *` function still emits `(int *)`.
The generated census moved by exactly one declaration: total
`4274 -> 4275`, Rust IR `2031 -> 2032`.

## RED and GREEN evidence

Before the production change, the real GCC fixture reached the new semantic
assertion and failed with:

```c
return (node *)((long)var0);
```

After rebuilding the extension with `uv run maturin develop`:

```text
uv run --no-sync pytest \
  python/tests/test_decompiler_control_flow_semantics.py::test_o2_pointer_return_keeps_declared_dwarf_kind \
  -q --tb=short
2 passed
```

GCC now emits `return var0;`; Clang emits `return ret;`. Both generated
programs compile and execute equivalently. The test continues to require typed
aggregate fields, pre-dereference null checks, canonical loops, and no `goto`.

The unit-level boundary contract and adjacent pointer surface also pass:

```text
cargo test --features python-ext \
  pointer_return_strips_integer_transport_but_keeps_real_pointer_conversion \
  --lib
1 passed

cargo test --features python-ext pointer --lib -q
156 passed
```

The prior declared-call repair remains green, as do the census and smoke
lanes:

```text
uv run --no-sync pytest \
  python/tests/test_libc_pointer_roundtrip.py \
  python/tests/test_test_census.py -q --tb=short
9 passed

uv run --no-sync python tools/dectest.py @smoke
4 scoped lanes of 838; no scoped regressions
```

## Broad gates and limitations

The complete Rust/Python-extension gate passed:

```text
cargo test --features python-ext
3,787 library tests passed; 4 ignored; all ordinary integration targets passed;
2 doc tests passed; 1 ignored
```

The required post-commit whole Python command completed rather than hanging:

```text
uv run pytest python/tests/ -q --tb=short
completed at 100 percent; red
```

Pytest's completed-run `lastfailed` cache contained 441 entries. Of those, 319
were the existing `test_known_decompiler_failures.py` recovery ratchet; other
large groups were variadic ABI (14), build-configuration invariants (11),
decompiler emission (10), ARM32 semantics (10), and fixture structural (9).
The output also included stale exact-format assertions that reject improved
inline initializers and pointer spacing. This broad gate is not claimed green,
and its failures were not mass-refreshed or hidden.

The broader control-flow file alone has three such stale assertions: it
expects separate `int i;` declarations where output now uses
`for (int i = 0; ...)`, and double parentheses around a canonical `while`.
The pointer-return test itself and all three libc execution fixtures are green
against the freshly rebuilt extension.

GED, type-match, byte-match, Union, and full DecBench metrics were not run for
this bounded readability repair, so no benchmark score movement is claimed.
