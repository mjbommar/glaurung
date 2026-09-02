# Decompiler output format

> **Kind:** reference · **Status:** maintained

What `glaurung decompile` emits, and what the deliberate absences mean. For how
the output is produced, see
[`../architecture/decompiler-pipeline.md`](../architecture/decompiler-pipeline.md).

## The command

```
glaurung decompile <path> [--format plain|rich|json|jsonl] [--json]
```

`--format` and `--json` come from the shared CLI base
(`python/glaurung/cli/commands/base.py`); the rest are
`decompile`'s own (`python/glaurung/cli/commands/decompile.py`):

| flag | effect |
|---|---|
| `--func VA\|name` | one function. Hex, decimal, or a name resolved against analysis. Stripped binaries only have `sub_<VA>` names, so a VA is preferred. Default: the detected entry point |
| `--all` | up to `--limit` discovered functions |
| `--vas VAS\|@FILE\|-` | exactly these entry VAs, in one analysis pass. Inline list, a file, or stdin; `#` comments allowed. Emits a JSON list. Intended for batch harnesses that already know their targets — `@FILE` and `-` carry no argv length bound |
| `--limit N` | max functions for `--all` (default 8) |
| `--no-types` | disable the type-annotation pass |
| `--timeout-ms`, `--max-blocks`, `--max-instructions` | per-function budgets; default to the analysis config |
| `--range-start VA`, `--range-end VA` | explicit `[start, end)` range-seeded decompile |
| `--style plain\|c\|decbench` | see below |
| `--pdb-cache DIR` | Microsoft-style PDB cache for PE/PDB public function names |
| `--cache-dir DIR` | persistent cache for single-function output, keyed by (version, sha256, VA, flags). Falls back to `$GLAURUNG_CACHE_DIR`. Append-only |
| `--db FILE` | a `.glaurung` project. Names recorded there (analyst rename, DWARF, FLIRT) are applied at the definition **and** at every call site. Without it this command is blind to the project, so a renamed function still prints as `sub_<hex>` |
| `--analysis-config FILE` | Windows analysis config YAML/JSON. Defaults to `.glaurung/windows-analysis.yaml` or `$GLAURUNG_WINDOWS_ANALYSIS_CONFIG` |

There is no engine selection flag. Glaurung has one decompiler.

### Styles

| `--style` | output |
|---|---|
| `plain` (default) | register-level detail, `%`-prefixed names, type annotations |
| `c` | `%` prefixes and annotations stripped — a closer-to-C view |
| `decbench` | parseable C: a real `long name(long arg0, …)` signature with declared locals, for external tooling that parses the output as C |

`decbench` is a behaviour fork, not a formatting switch: it is the only style
that turns on DWARF output contracts, the DWARF type environment, the program
environment, and semantic prototype recovery.

## Structured JSON

`--format json` (or `--json`). One object per function:

```json
{
  "name": "x87_accumulate",
  "entry_va": 4345,
  "size": 125,
  "pseudocode": "int x87_accumulate(int arg0) { ... }",
  "variables": [
    {"name": "arg0", "type": "int", "kind": "arg",
     "arg_index": 0, "stack_offset": null, "size": null, "addresses": []},
    {"name": "i", "type": "int32_t", "kind": "stack",
     "arg_index": null, "stack_offset": -20, "size": 4,
     "addresses": [4390, 4418, 4422]}
  ]
}
```

`variables` is the recovered inventory (`src/ir/recovered_variables.rs`),
reported only for names the render actually emitted — a variable is never
invented from the C. Ordering is deterministic (parameters by ABI slot, then
locals by name) so two identical decompilations cannot disagree.

| field | meaning |
|---|---|
| `name` | the identifier as it appears in the rendered C |
| `type` | the declared C type, or `"long"` when only the width is known (`RecoveredVariable::ctype`) |
| `kind` | `"arg"` for an ABI parameter, `"stack"` for a promoted frame slot |
| `arg_index` | zero-based ABI parameter position; `null` for a stack local |
| `stack_offset` | signed frame displacement the slot was minted from, in the frame's own coordinate space; `null` for a parameter, and `null` for a local whose coordinate was withheld as ambiguous |
| `size` | access width in bytes, when the promotion pass proved one |
| `addresses` | machine addresses the slot is read or written at, ascending and deduplicated |

Top-level `size` and `variables` are additive: every previously emitted key keeps
its name and meaning. Single-function mode (`--func` without `--vas`) goes
through `decompile_at`, which does not return the inventory, so it emits
`"size": null` and `"variables": []` — absent rather than claiming the function
has no variables.

### `addresses`: empty means UNCLAIMED, never "there are none"

Three consequences, all deliberate. The rules and the measurements are in the
module doc of `src/ir/variable_addresses.rs`.

- **A parameter carries none.** A register's live range is not a storage
  coordinate, and deriving one needs liveness this join deliberately does not do.
- **A slot is silent wherever the published coordinate is not the coordinate the
  machine uses.** Two configurations do this today: x86-64 at `-O2`, where gcc
  omits the frame pointer and coordinates are `entry_rsp`-based while the machine
  only ever names `rsp`; and ARM32, where locals sit at positive displacements
  from `r7` while the published coordinates are entry-relative and negative.
  Silence, never a wrong address — a plausible wrong address is worse than none,
  because it is a real instruction start inside the function and so passes a
  consumer's validator while mis-attributing the evidence.
- **An address can fall outside `[entry_va, entry_va + size)`.** A function is not
  always contiguous: `cpp_exception.cold` sits below its hot part. Those
  addresses are correct — 2 of 6,726 over 250 fixture binaries — and a consumer
  that clamps to the contiguous extent will drop them.

Every emitted address has been validated against an external disassembler as a
real instruction start whose instruction accesses that displacement: **8,441
addresses, zero wrong**, across ELF, PE and Mach-O on x86-64, i386 and aarch64,
by both `objdump` and `llvm-objdump`. The per-corpus breakdown and the per-slot
coverage rates are the table in `src/ir/variable_addresses.rs` (measured
2026-08-29).

### There is deliberately no line map

No `{line → address}`. That needs AST-node-to-instruction lineage, which lowering
discards: `lower_block` (`src/ir/ast/lower_conds.rs:280`) passes only `&ins.op`
onward and drops `ins.va`, and `ast::Function` keeps `name`, `entry_va` and
`body`.

Per-variable addresses are a *different* problem and need no node identity at
all — the join is on the frame coordinate, which both `stack_locals` and the LLIR
still hold. Conflating the two is why the capability went unbuilt for as long as
it did. dewolf and Reko emit this same shape, and DecBench's ingest supports it:
variable addresses are filtered independently of line mappings and survive with
none.

## Stderr

`glaurung decompile` names on stderr any function that failed the pre-render
definition-before-use check; stdout stays exactly the payload. `GLAURUNG_VERIFY_DEFS=1`
additionally splices per-violation `// glaurung-verify:` comments into the body.
It is opt-in because the decbench render is an artifact external tooling parses
and scores. See
[`../architecture/register-model.md`](../architecture/register-model.md).

A discovery budget that fired produces a rendered incompleteness note ahead of
the body, so truncation is visible in the output rather than silent.
