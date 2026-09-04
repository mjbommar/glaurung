# WP8 annotated declaration-conflict evidence

Date: 2026-09-04

## Defect

Declaration/recovery disagreements were retained as structured
`PrototypeConflict` records and were queryable through
`glaurung.ir.take_render_verification()`, but the analyst-facing decompile
command had no explicit way to show them with the affected function. The only
text modes were scored/default renderings, where adding diagnostics would
break determinism and contaminate benchmark input.

## Change

Implementation commit: `b4a130ee`.
Base revision: `a542c3bf52ea28218ed4f72b245c1b40de4a5a2d`.

`glaurung decompile --style decbench --annotate-conflicts` now inserts a
deterministic C line comment immediately before each affected signature. The
comment includes both prototype shapes, both provenance labels, and the exact
disagreement fields. For example:

```c
// glaurung: tail_dispatch @ 0x1200
// glaurung: declaration conflict: dwarf `int (int, int, int)` vs inferred `int (unsigned int, unsigned int, int)`; differs: parameter_types
int tail_dispatch(int tag, int a, int b) {
```

The option is explicit and is rejected unless the selected style is
`decbench`. Without it, CLI and native scored text are byte-for-byte on the
existing path and contain no conflict comment. Newlines and C comment closers
inside analyst-controlled type text are neutralized before annotation.

Single-address, explicit-range, `--vas` batch, and `--all` routes use the same
formatter. JSON retains its existing schema and places the requested comment
inside the `pseudocode` value. Single-function annotated mode bypasses the
persistent text cache: conflict metadata is produced by a live render and is
drained separately, so replaying cached C would otherwise manufacture the
false claim that no conflict existed.

The generated CLI reference was refreshed from the real parser. No Rust or
native-binding code changed in this increment.

## RED and GREEN evidence

The real `tail_dispatch` fixture first failed because argparse rejected the
new contract:

```text
glaurung: error: unrecognized arguments: --annotate-conflicts
```

After implementation, the real-binary regression exercises default, single,
range, batch JSON, and whole-image modes. It proves the comment is absent by
default, appears between prelude and signature only on request, and contains
the exact DWARF/inferred disagreement. The cache regression proves two
annotated requests both render live and create no text-cache entry.

```text
uv run --no-sync pytest \
  python/tests/test_decompiler_declaration_authority.py \
  python/tests/test_cli_cache.py \
  python/tests/test_gen_cli_reference.py \
  python/tests/test_test_census.py -q --tb=short
36 passed

uv run --no-sync pytest \
  python/tests/test_cli_decompile.py::test_decompile_style_decbench_is_valid_c_shape \
  python/tests/test_cli_decompile.py::test_decompile_vas_batch_emits_named_json \
  python/tests/test_cli_decompile.py::test_requested_va_budget_counts_unique_targets_only \
  python/tests/test_cli_decompile.py::test_decbench_output_parses_with_gcc \
  -q --tb=short
4 passed

uv run --no-sync python tools/gen_cli_reference.py --check
passed

uvx ruff check python/glaurung/cli/commands/decompile.py \
  python/tests/test_decompiler_declaration_authority.py \
  python/tests/test_cli_cache.py
passed

uvx ty check python/glaurung/cli/commands/decompile.py
passed
```

## Broader gate state

The complete `python/tests/test_cli_decompile.py` module ran. It retained five
current-master failures already present in the immediately preceding full
Python run: two assertions reject improved inline local initializers, one
expects obsolete pointer spacing, and two ARM stripped/requested-VA cases have
existing discovery/name differences. None exercises conflict annotation or
argument routing. The remaining DecBench-style CLI tests pass, including GCC
syntax parsing.

`python/tests/test_decompiler_render_styles.py` retains one adjacent stale
spelling assertion: the authoritative signature uses source-level `int`, while
the test requires the equivalent `int32_t`. It is not attributed to this
Python-only annotation layer.

The full Python suite was not repeated after this Python-only increment. The
immediately preceding run at base revision completed with 441 failures, chiefly
the known-decompiler recovery inventory; this report does not claim that broad
gate green. No fixture or known-failure baseline was changed.
