# §U — Recipe: exporting to IDA / Binary Ninja / Ghidra

`glaurung export` emits your `.glaurung` project as a script that
applies your renames, comments, data labels, types, and stack
vars **inside the target tool**. Use case: Glaurung is your
fast-iterate engine; the polished tool gets the result.

## The four output formats

```bash
# Markdown — human-readable report.
glaurung export tutorial.glaurung --output-format markdown

# JSON — round-trippable.
glaurung export tutorial.glaurung --output-format json > kb.json

# C header — every type as a compilable .h.
glaurung export tutorial.glaurung --output-format header > kb.h

# IDAPython script — apply your KB inside IDA Pro.
glaurung export tutorial.glaurung --output-format ida > apply_in_ida.py

# Binary Ninja Python script.
glaurung export tutorial.glaurung --output-format binja > apply_in_binja.py

# Ghidra Python script (Jython 2.7 syntax).
glaurung export tutorial.glaurung --output-format ghidra > apply_in_ghidra.py
```

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
