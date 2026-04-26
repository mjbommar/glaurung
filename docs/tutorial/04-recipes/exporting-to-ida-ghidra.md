# §U — Recipe: exporting to IDA / Binary Ninja / Ghidra

`glaurung export` emits your `.glaurung` project as a script that
applies your renames, comments, data labels, types, and stack
vars **inside the target tool**. Use case: Glaurung is your
fast-iterate engine; the polished tool gets the result.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/04-export/`](../_fixtures/04-export/).

## The output formats

```bash
$ glaurung export tutorial.glaurung --output-format markdown   # human report
$ glaurung export tutorial.glaurung --output-format json       # round-trippable KB
$ glaurung export tutorial.glaurung --output-format header     # compilable C .h
$ glaurung export tutorial.glaurung --output-format ida        # IDAPython
$ glaurung export tutorial.glaurung --output-format binja      # Binary Ninja Python
$ glaurung export tutorial.glaurung --output-format ghidra     # Ghidra Jython
```

## Markdown report (head)

```bash
$ glaurung export tutorial.glaurung --output-format markdown | head -30
```

```markdown
# Glaurung KB export

- function_names: **9**
- prototypes: **192**
- comments: **0**
- data_labels: **0**
- stack_vars: **36**
- types: **112**
- evidence rows: **1**

## Functions (first 32)

| entry | name | demangled | set_by |
|---|---|---|---|
| `0x1060` | `_start` | — | analyzer |
| `0x1090` | `deregister_tm_clones` | — | analyzer |
| `0x10c0` | `register_tm_clones` | — | analyzer |
| `0x1100` | `__do_global_dtors_aux` | — | analyzer |
| `0x1140` | `frame_dummy` | — | analyzer |
| `0x1150` | `main` | — | analyzer |
| `0x117b` | `sub_117b` | — | analyzer |
| `0x11d0` | `print_sum` | — | analyzer |
| `0x1200` | `static_function` | — | analyzer |

## Types (first 16)

- `ATOM` (typedef, set_by=stdlib, confidence=0.99)
- `BOOL` (typedef, set_by=stdlib, confidence=0.99)
- `BOOLEAN` (typedef, set_by=stdlib, confidence=0.99)
- `BYTE` (typedef, set_by=stdlib, confidence=0.99)
```

(Captured: [`_fixtures/04-export/export-markdown-head.out`](../_fixtures/04-export/export-markdown-head.out).)

## JSON shape

```bash
$ glaurung export tutorial.glaurung --output-format json | python -c \
    'import json,sys; d=json.load(sys.stdin); \
     print("schema_version:", d["schema_version"]); \
     print("keys:", sorted(d.keys()))'
```

```text
schema_version: 1
keys: ['comments', 'data_labels', 'evidence_log', 'function_names',
       'function_prototypes', 'schema_version', 'stack_frame_vars',
       'summary', 'types']
```

(Captured: [`_fixtures/04-export/export-json-summary.out`](../_fixtures/04-export/export-json-summary.out).)

The top-level keys are the round-trippable tables — every analyst
write Glaurung tracks ends up in one of those buckets.

## IDAPython script (head)

```bash
$ glaurung export tutorial.glaurung --output-format ida | head -20
```

```python
# Glaurung → IDAPython export (#165 / #190)
# Paste into IDA's scripting console (File > Script file)
# or run via `idat -A -S<this.py> <target.idb>`.

import idaapi
import idc
import ida_name
import ida_bytes
import ida_funcs

def _apply():
    summary = {
        "renamed_functions": 0,
        "comments_set": 0,
        "data_labels_set": 0,
        "stack_vars_set": 0,
    }

    # Function renames (preferring demangled when present).
    if ida_name.set_name(0x1060, "_start", ida_name.SN_FORCE):
```

(Captured: [`_fixtures/04-export/export-ida-head.out`](../_fixtures/04-export/export-ida-head.out).)

## Binary Ninja script (head)

```bash
$ glaurung export tutorial.glaurung --output-format binja | head -20
```

```python
# Glaurung → Binary Ninja export (#190)
# Run via the BN scripting console (bv is in scope) or:
#   binaryninja.load("<binary>").execute_script("<this.py>")

def _apply(bv):
    summary = {
        "renamed_functions": 0,
        "comments_set": 0,
        "data_labels_set": 0,
    }

    # Function renames — uses bv.get_function_at(va).set_user_symbol
    from binaryninja import Symbol, SymbolType
    f = bv.get_function_at(0x1060)
    if f is not None:
        bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, 0x1060, '_start'))
        summary["renamed_functions"] += 1
```

(Captured: [`_fixtures/04-export/export-binja-head.out`](../_fixtures/04-export/export-binja-head.out).)

## Ghidra script (head)

```bash
$ glaurung export tutorial.glaurung --output-format ghidra | head -20
```

```python
# Glaurung → Ghidra export (#190)
# Run via Window > Script Manager. Targets the active program.

# @category Glaurung
# @runtime Jython

from ghidra.program.model.symbol import SourceType

def _apply():
    summary = {'renamed_functions': 0, 'comments_set': 0, 'data_labels_set': 0}
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    af = currentProgram.getAddressFactory().getDefaultAddressSpace()
    def addr(va): return af.getAddress(va)

    fn = fm.getFunctionAt(addr(0x1060))
    if fn is not None:
        fn.setName("_start", SourceType.USER_DEFINED)
        summary['renamed_functions'] += 1
```

(Captured: [`_fixtures/04-export/export-ghidra-head.out`](../_fixtures/04-export/export-ghidra-head.out).)

## How the IDA / Binja / Ghidra scripts work

Each script is a self-contained Python file. The IDA flavour, for
example, calls `ida_name.set_name`, `idc.set_cmt`, `parse_decls`,
etc. for every annotation in your KB:

```python
# excerpt of an IDA export
import idaapi, ida_name, idc

ida_name.set_name(0x1140, "parse_packet", ida_name.SN_FORCE)
idc.set_cmt(0x1144, "TODO: bounds check this", 0)
ida_name.set_name(0x4040, "g_secret_key", ida_name.SN_FORCE)
parse_decls("struct exported_struct { int a; void *b; };", 0)
# ...
```

Run it inside IDA via `File > Script File...` (or
`Edit > Plugins > Python` and `exec(open('apply_in_ida.py').read())`).

Same shape for Binary Ninja (`binaryninja.user.script`) and
Ghidra's PyDev / Jython console.

## Use case: Glaurung as your fast-iterate engine

A typical workflow:

```bash
# 1. Triage in Glaurung — sub-second feedback loop.
glaurung kickoff target.elf --db work.glaurung

# 2. Annotate aggressively in the REPL (renames, retypes, comments,
#    stack-frame edits). Use undo freely.
glaurung repl target.elf --db work.glaurung
>>> n parse_packet
>>> y char[256]
>>> ...
>>> save
>>> q

# 3. Export to your preferred polished tool.
glaurung export work.glaurung --output-format ida > apply.py

# 4. Open the binary in IDA and run apply.py.
```

The opposite direction (IDA → Glaurung) isn't shipped in v0 — for
now Glaurung is one-way to IDA / BinaryNinja / Ghidra. JSON
round-trip exists for tool-to-tool migrations between Glaurung
projects.

## C-header export

```bash
glaurung export work.glaurung --output-format header > types.h
```

Emits every struct / enum / typedef in `type_db` as a compilable
header. Useful for:

- Re-importing into a new analysis project.
- Producing a header for a recovered-source `recover_source.py`
  rebuild.
- Sharing recovered types with a teammate who's working in a
  different tool.

## JSON round-trip

```bash
# Export.
glaurung export work.glaurung --output-format json > backup.json

# Inspect.
jq '.summary' backup.json
jq '.function_names | length' backup.json
jq '.function_names[] | select(.set_by == "manual")' backup.json
```

The JSON is round-trippable: future tooling will accept it as
input to recreate a `.glaurung` from the saved state. For now,
treat it as a backup format.

## Markdown report

```bash
glaurung export work.glaurung --output-format markdown > report.md
```

A human-readable summary with sections per table. Drop into the
project's docs as a snapshot of "what we knew at this point in
the analysis."

## See also

- [`reference/cli-cheatsheet.md`](../reference/cli-cheatsheet.md) —
  full export-flag list.
- [#190 export trio](../../architecture/IDA_GHIDRA_PARITY.md) —
  implementation notes.
