# Provenance: the `set_by` ladder

Every named entity in a `.glaurung` project file (function names,
data labels, comments, stack vars, types, function prototypes) carries
a `set_by` tag recording **where the name came from**. Glaurung uses
this tag to decide whether a later analysis pass is allowed to
overwrite an earlier write.

This is a Glaurung-specific edge over IDA / Ghidra. Both of those
tools maintain provenance internally for some name kinds, but neither
exposes it cleanly to the analyst. In Glaurung, `set_by` is a column
in the SQLite tables — visible to every CLI surface, queryable via
`glaurung find --kind ... | grep set_by`, and surfaced in the
typed-locals prelude in `render_decompile_with_names` output.

## The precedence ladder

```
manual  >  dwarf  >  flirt  >  borrowed  >  cil  ≡  gopclntab  >  propagated  >  auto  >  analyzer  >  stdlib
```

A higher tier always wins over a lower tier. Same-tier writes are
last-writer-wins.

### Manual (always wins)

- **Source:** the analyst typed it (REPL `n`/`y`/`c`, `glaurung
  bookmark`, etc., or any setter called with `set_by="manual"`).
- **Recorded in undo log:** yes (#228).
- **Re-running indexing won't clobber it:** by design — `index_callgraph`
  and the per-pass setters all check `set_by == "manual"` before
  writing and refuse to overwrite.

### DWARF

- **Source:** debug info embedded by gcc/clang at build time when
  `-g` is set (#157, #178).
- **Includes:** function names, parameter names, struct/enum/typedef
  bodies, line numbers, source-file paths.
- **Defers to:** manual.

### FLIRT

- **Source:** signature match against `data/sigs/*.flirt.json` (#158).
- **Includes:** function names recovered from compiler-stdlib pattern
  matches (e.g. `__libc_start_main`, `__cxa_finalize`).
- **Defers to:** manual, dwarf.

### Borrowed (cross-binary symbol borrow)

- **Source:** sibling-debug binary used as a name donor via
  `glaurung repl > borrow <other.glaurung>` (#170).
- **Includes:** function names matched by prologue.
- **Defers to:** manual, dwarf, flirt.

### CIL / gopclntab (managed-runtime recovery)

- **Sources:** ECMA-335 metadata table walker (.NET PEs, #210),
  Go pclntab parser (stripped Go binaries, #212).
- **Includes:** fully-qualified method / function names
  (e.g. `Hello::Main`, `runtime.gopanic`).
- **Defers to:** manual, dwarf.
- **Same tier:** they don't overlap on a single binary so precedence
  between them is moot.

### Propagated (call-site type matching)

- **Source:** type-propagation pass (#172, #195) — when a stack slot
  flows into `recv(int sockfd, ...)`, the slot's c_type becomes
  `int`.
- **Includes:** stack-var c_types, sometimes data-label c_types.
- **Defers to:** manual, dwarf, flirt, borrowed.

### Auto (heuristic)

- **Source:** auto-struct recovery (#163) — `[reg+0x10]` access
  patterns produce candidate field declarations.
- **Includes:** synthesized struct types and field names.
- **Defers to:** manual, dwarf, flirt, borrowed, cil/gopclntab,
  propagated.

### Analyzer (default)

- **Source:** the bare-minimum name the function discoverer assigned
  before any name pass (`sub_1140`, `var_8`, `arg_10`).
- **Defers to:** everything above.
- **In practice:** the only rows tagged `analyzer` are the ones no
  later pass touched.

### Stdlib (lowest)

- **Source:** library-bundle types loaded by `auto_load_stdlib` (libc,
  POSIX, Win32 — #180, #198).
- **Includes:** type definitions only (`size_t`, `FILE`, `HANDLE`).
- **Defers to:** everything — these are the most generic shapes.

## What the undo log captures

Only `set_by == "manual"` writes enter the undo log (#228). The
reasoning:

- Auto / dwarf / flirt / propagated / cil / gopclntab writes can be
  re-derived by re-running the analysis pass. Undoing them is
  meaningless — the next index would just put them back.
- Manual writes encode analyst intent that nothing else can recover.
  If they're lost, they're lost. So `glaurung undo` is the analyst's
  safety net.

## Reading the tag

Every CLI surface that lists named entities prints the `set_by` tag:

```
$ glaurung find tutorial.glaurung parse --kind function
kind        location        snippet
----------  --------------  --------
function    0x1140          parse_packet  (set_by=manual)
function    0x1180          parse_header  (set_by=propagated)
```

In the REPL:

```
>>> functions
0x1080  printf@plt           (flirt)
0x1140  parse_packet         (manual)
0x1180  sub_1180             (analyzer)
```

In `glaurung view`'s typed-locals prelude (#194):

```
// ── locals (from KB) ───────────────────────────────────
    int counter;          // -0x10  set_by=propagated
    char *msg_buf;        // -0x20  set_by=manual
    int loop_index;       // -0x30  set_by=auto (TODO refine)
// ─────────────────────────────────────────────────────────
```

## Analyst tip

Aggressive renames are safe because:

1. Manual writes can't be clobbered by any later pass.
2. `glaurung undo` reverses any manual write at any time.
3. The provenance tag tells you at a glance whether a name is
   trustworthy (DWARF: very) vs guessed (auto: skim and refine).

When in doubt, rename → look at the rerendered decompile → if you
don't like it, `glaurung undo`.

## See also

- [`cli-cheatsheet.md`](cli-cheatsheet.md)
- [`repl-keymap.md`](repl-keymap.md)
- Tier 2 §E `naming-and-types.md` — applies this in practice
- Tier 2 §K `undo-redo.md` — full undo workflow
