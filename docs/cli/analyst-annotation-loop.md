# The annotation loop: edit the project, see it in the output

An analyst's two most common actions are renaming and annotating — 14 of the 16
professional reverse engineers observed in [Votipka et al., USENIX Security
2020](https://www.usenix.org/conference/usenixsecurity20/presentation/votipka-observational)
did each. Until 2026-08-28 Glaurung could record both and show neither: the
`.glaurung` project was **write-only with respect to the decompiler**.

This page is the loop as it now works, and — just as important — where it still
stops.

## The shape of the problem

`glaurung decompile` imported no `kb` module and had no `--db` flag. A function
renamed in the project still printed as `sub_1140` forever. Two secondary
surfaces (`view`, `repl`) papered over it with `render_decompile_with_names`, a
regex substitution over the decompiler's *output string* — which cannot follow a
call through a PLT stub, and will happily rewrite a matching substring inside a
string literal.

Writing was no better. `rename`, `comment`, `label` and `proto` existed only
inside the interactive REPL, so no analyst workflow could be scripted, replayed
in CI, driven from an editor, or handed to an agent.

## The loop

```bash
# 1. Analyse once. The project file is the durable artifact.
uv run glaurung kickoff ./target.so --db target.glaurung

# 2. Annotate, non-interactively. An address argument also accepts a function
#    name already in the project, so you rarely need to look one up.
#    (`kickoff` imports the binary's own names, so `validate` resolves here.)
uv run glaurung rename  target.glaurung validate parse_packet_hdr
uv run glaurung comment target.glaurung parse_packet_hdr \
    "Bounds-checks before indexing. Returns -1 on a null pointer."
uv run glaurung label   target.glaurung 0x4000 g_opcode_table --type "int[16]"
uv run glaurung proto   target.glaurung parse_packet_hdr int "p:const uint8_t *" "n:int"

# 3. Locals: a rename needs a type. See "Why a rename needs a type" below.
uv run glaurung frame target.glaurung 0x1119 retype -12 "unsigned int"
uv run glaurung frame target.glaurung 0x1119 rename -12 running_total

# 4. Read it back. Every surface below now agrees with the project.
uv run glaurung decompile target.so --func parse_packet_hdr --db target.glaurung
uv run glaurung disasm    target.so --db target.glaurung --function parse_packet_hdr
uv run glaurung graph     target.so callgraph --db target.glaurung

# 5. Undo is per-write and covers deletions.
uv run glaurung undo target.glaurung --list
uv run glaurung undo target.glaurung
```

## What `--db` changes, per surface

| Surface | Function names | Locals | Comments | Call targets |
|---|---|---|---|---|
| `decompile --db` | definition **and** every call site | name + type in the body | function comment above the signature; interior notes listed by address | via the address map |
| `disasm --db` | header and `-> name` annotations | — | — | direct, PLT, IAT |
| `graph callgraph --db` | node labels | — | — | edge labels, including `@plt` |
| `view`, `repl` | regex post-processor (unchanged) | comment prelude only | — | — |

## Three rules worth knowing

### Renames follow a function's aliases

A call inside a shared object does not target the callee — it targets the
callee's **PLT stub**, at a different address. An overlay that rewrote only the
renamed address renamed the header and left every call site reading the old
name. So a rename also rewrites the `@`-qualified spellings of the name it
replaced: `validate@plt` becomes `parse_packet_hdr@plt`. The qualifier is kept
deliberately — it tells you the call goes through a stub. Only `@`-qualified
spellings are followed, so two `static` helpers that merely share a name are
left alone.

### Why a rename needs a type

`glaurung frame … rename` on an untyped slot prints a note, and the rename does
not appear in `decompile --db` until you also set a type. That is not
bureaucracy. Measured on a stripped `-O0` build, renaming the surviving local at
`rbp-0xc` with no type attached turned

```c
int local_c;   local_c = 0;   ...   return (unsigned int)(local_c);
```

into

```c
long running_total;   *(int *)(running_total) = 0;
```

— a pointer store synthesised from a scalar assignment, because the local lost
its recovered width along with its `local_` identity. Declining the rename is
the correct answer; emitting that is not.

With a type, the retype genuinely propagates: `return (unsigned int)(local_c)`
becomes `return running_total`, the cast gone because the declared type now
matches. And naming a slot the optimiser had copy-propagated away *recovers* it
— `limit = n; for (i = 0; i < limit; i++)` — which is closer to the source than
the propagated form.

A slot whose frame coordinate the promotion pass withheld as ambiguous cannot be
named at all. An offset reachable from two different bases is not one variable,
and attaching your name to whichever slot was iterated last is worse than
leaving it `local_18`.

### Comments are anchored, not placed

A comment on the **function** renders above the signature, where nothing can
orphan it. Comments at other addresses are **listed with their addresses**:

```c
// glaurung: parse_packet_hdr @ 0x1030
// Bounds-checks before indexing. Returns -1 on a null pointer.
//
// analyst notes at addresses inside this function:
//   0x1045: the length check happens here
int parse_packet_hdr(const uint8_t * arg0, int arg1) {
```

Placing an interior comment on a *line* needs an instruction-to-line map the AST
cannot currently supply — `lower_block` calls `lower_op(&ins.op, ..)` and drops
`ins.va`. A plausible **wrong** placement is worse than an honest list, because
it reads as fact and silently mis-attributes your note to unrelated code.

This split is not an invention. Hex-Rays says of its own position-anchored
pseudocode comments that they "can move around or even end up as orphan comments
when the pseudocode changes", and ships a *Delete orphan comments* action for the
consequences; its function comments have no such problem.

## Provenance

Every writable fact carries `set_by`, and precedence is by **rank**
(`glaurung.llm.kb.provenance`), not by a `manual`-or-not test:

```
manual 100 > dwarf = pdb = gopclntab 80 > stdlib 60 > flirt = cil 50
       > ported 40 > propagated 30 > auto = analyzer = borrowed 20
```

Equal rank replaces, so a later pass may improve on an earlier one and you can
correct your own edit. An unknown `set_by` ranks at `auto` — lowest would let a
typo be outranked forever, highest would let a typo clobber DWARF.

`--by` on every annotation command exists so a tool driving them can record
something other than an analyst decision. Mislabelling automation as `manual`
would let it overwrite real analyst edits, which is the failure the rank exists
to prevent. A refused write is **reported**, with exit code 5.

## What still does not work

Named honestly, because a tool that models half a problem and stays quiet about
it produces confidently-wrong output:

- **No line map.** There is no `{line → address}` for decompiled output, so
  nothing can jump from a pseudocode line to its address, and interior comments
  are listed rather than placed. `lower_block` drops `ins.va`; `Expr`/`Stmt`
  derive `PartialEq`/`Eq` and have no node identity, so origin cannot simply be
  attached. This is the largest remaining gap and the one the incumbents treat
  as table stakes.
- **A KB prototype does not change recovery.** `glaurung proto` records a
  signature; it does not force arity or parameter types into the decompiler, so
  call sites are not re-rendered against it.
- **A user-defined `struct` reaches no render path.** Setting a stack var's
  `c_type` to `struct request *` stores a string; nothing resolves it to the
  `types` table, and there is no `base->field` rendering.
- **`decompile --all` / `--vas` carry no local overlay.** The overlay is per
  function; only single-function mode loads one.
- **No code labels.** `data_labels` is globals-only; a named jump target inside
  a function has nowhere to live.
- **Prototypes are keyed by name, with no rename cascade.** Renaming a function
  orphans its prototype row, and a later function that happens to take the old
  name inherits it.
- **Sessions do not scope annotations.** Only `kb_nodes`/`kb_edges` are
  session-keyed; renames are binary-wide.
- **`view` and `repl` still use the regex post-processor.** They were not
  migrated to the address-map overlay, so they keep its limits: a call through
  a PLT stub is not followed, and a matching substring inside a string literal
  can be rewritten.
- **No concurrency safety.** Two `glaurung` processes writing one project is
  undefined; there is no `busy_timeout` and no advisory lock.

## Where the tests are

| Behaviour | Test |
|---|---|
| Rename reaches definition and call sites | `python/tests/test_analyst_rename_reaches_decompile.py` |
| Locals reach the body; untyped rename declined | `python/tests/test_analyst_locals_reach_decompile.py` |
| Comments reach the output | `python/tests/test_analyst_comments_reach_decompile.py` |
| The CLI write surface | `python/tests/test_cli_annotate.py` |
| Callgraph names and PLT labels | `python/tests/test_cli_graph_names.py` |
| KB-aware disassembly | `python/tests/test_kb_disasm_symbols.py` |
| Provenance ranking | `python/tests/test_kb_provenance_rank.py` |
| Stack-var writes preserve unsupplied facts | `python/tests/test_kb_stack_var_preserves.py` |
