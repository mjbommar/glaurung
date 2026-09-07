# WP3 structured line mappings

Commit `db2e7735` exposes the statement instruction origins already carried by
the production AST as structured, one-based line mappings.

## Contract

- `decompile_many` and `decompile_all` retain their five-field result by
  default. `include_line_mappings=True` appends ordered
  `{"line_number": n, "addresses": [...]}` records.
- JSON and JSONL CLI output request and name the field `line_mappings`.
- Mapping happens while the DecBench renderer writes each attributed statement;
  no rendered-text parsing or nearest-address guessing is involved.
- Addresses are sorted and deduplicated. Several addresses may own one line,
  and one address may own several output lines.
- Scored pseudocode is unchanged. Non-DecBench render styles return no line
  mappings until they have an equivalent explicit provenance contract.

## Focused evidence

The exact Rust contract test executed one test and passed:

```text
cargo test --features python-ext --lib \
  decbench_render_exposes_deterministic_statement_line_mappings -- --nocapture

1 passed; 0 failed; 4345 filtered out
```

The required release extension rebuild completed in 34.92 seconds:

```text
uv run maturin develop --release
```

The exact real-binary public API test passed:

```text
uv run pytest python/tests/test_decompiler_line_mappings.py -q

1 passed
```

It decompiles only GCC O0 `01_conditional_polarity::classify` and proves the
legacy and opt-in tuple shapes, valid line indices, canonical non-contiguous
address sets, one-to-many ownership, and repeated-call determinism.

The exact CLI probe returned five mappings. Its first mapping was source line 3
to six instruction addresses:

```text
5 {'line_number': 3, 'addresses': [4817, 4821, 4822, 4825, 4828, 4837]}
```

The generated native stub is current and Ruff passes for the new test and
touched CLI module. No fixture matrix, corpus sweep, DecBench run, or broad
Python suite was run for this bounded increment.

## Remaining WP3 boundary

This closes structured statement-level Python exposure. It does not claim
expression ownership, completion of the remaining raw-statement consumer
audit, elimination of display-name semantic parsing, or universal origin
survival through every enabled pass.
