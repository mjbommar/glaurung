# §X — Agent: one-shot kickoff (deterministic)

`glaurung kickoff` is the deterministic-only first-touch pipeline.
No LLM, no tokens, no API key — just the deterministic analysis
surface composed into one command. The agent's first turn in any
chat-driven workflow uses this same data, so understanding what
kickoff produces (and what it doesn't) is the foundation for the
rest of Tier 5.

## What kickoff does

```bash
glaurung kickoff <binary> --db <project>.glaurung
```

In ~300ms on a small binary, this runs:

1. **`detect_packer`** — UPX / Themida / VMProtect / etc. fingerprint
   match plus generic high-entropy fallback. If packed, the deeper
   passes short-circuit (see §R).
2. **Triage** — format / arch / language / IOC string scan. Same
   primitive `glaurung triage <binary>` runs.
3. **`analyze_functions_path`** — function discovery + bounded
   callgraph via the Rust analyzer.
4. **`index_callgraph`** — write functions and call edges into
   the SQLite project file. **Then** the format-specific
   recoveries fire:
   - **gopclntab** (#212) for stripped Go binaries
   - **CIL metadata** (#210) for managed .NET PEs
   - **DWARF type ingestion** (#178) when debug info is present
5. **Auto-load stdlib bundles** — 192 libc / WinAPI prototypes
   into `function_prototypes`.
6. **`demangle_function_names`** — every persisted name gets its
   `display` form (Itanium / Rust / MSVC manglings).
7. **Per-function lift (capped)** — for the first N functions:
   - `discover_stack_vars` — auto-populate stack frame slots.
   - `propagate_types_at_callsites` — type stack vars from libc
     call sites.
   - `recover_struct_candidates` — heuristic struct field
     discovery.

## What kickoff produces

A single `.glaurung` SQLite file with these tables populated:

| Table | What's in it after kickoff |
|---|---|
| `function_names` | Every analyzer-discovered function + format-specific recoveries (gopclntab/cil/dwarf names) |
| `xrefs` | Every callgraph edge as a `call` xref |
| `function_prototypes` | The 192-entry stdlib bundle |
| `types` | Bundle types + DWARF types |
| `stack_frame_vars` | Auto-discovered slots for the first N functions |
| `evidence_log` | One row per kickoff invocation citing the summary |

Crucially, **everything is `set_by="analyzer"` / `"gopclntab"` /
`"cil"` / `"dwarf"` / `"propagated"` / `"auto"` / `"stdlib"`** —
zero rows are `set_by="manual"`. That's important for two reasons:

1. **Re-running kickoff is safe.** Subsequent runs respect any
   manual writes (rename / retype / comment) you make later — the
   set_by precedence rules ensure manual always wins.
2. **The agent can build its first turn from kickoff alone.**
   Every fact in the kickoff summary is grounded in a specific KB
   row, queryable via deterministic tools — no hallucination
   surface.

## Read the markdown summary aloud

```bash
glaurung kickoff samples/.../c2_demo-clang-O0 --db demo.glaurung
```

Every line of the summary maps to a specific KB query:

```
- format: ELF, arch: x86_64                  ← triage.verdicts[0]
- entry: 0x1070                              ← triage.entry_va
- discovered: 6, named: 6                    ← list_function_names(kb)
- callgraph edges: 1                         ← count(xrefs WHERE kind='call')
- name sources: analyzer=6                   ← group_by(set_by)
- stdlib prototypes loaded: 192              ← list_function_prototypes(kb)
- DWARF types imported: 0                    ← list_types(kb, set_by='dwarf')
- stack slots discovered: 90                 ← count(stack_frame_vars)
- types propagated: 18                       ← count(stack_frame_vars WHERE set_by='propagated')
- IOCs: 4 ipv4 / 3 domain / 2 url / 1 email  ← triage.ioc_summary
```

The agent's first turn in a chat workflow is essentially "run
kickoff, render the summary, point at the IOCs." Every claim is
deterministically backed.

## Kickoff is also a memory tool

The agent has `kickoff_analysis` registered as one of its 50+
deterministic memory tools (#206). When the agent calls it:

- Inputs: binary path, optional db_path, optional skip_if_packed.
- Outputs: the same `KickoffSummary` shape the CLI prints, plus a
  `cite_id` referencing an evidence_log row.
- Side effects: the `.glaurung` file is created/updated.

The agent's response can then say "I ran kickoff_analysis (cite 47)
and found..." — citing the row in evidence_log so the user can
inspect what the tool actually did.

## When kickoff isn't enough

Kickoff is intentionally **bounded** — it's the fast first-touch
pipeline. It doesn't do:

- Per-function decompilation across the whole binary (only a
  capped sample).
- Cross-binary symbol borrowing (#170) — that's a manual REPL step.
- Auto-struct recovery v2 (heuristic struct merging) — also
  manual.
- Anything LLM-driven.

For deeper analysis, you graduate to the daily-basics floor (Tier 2)
— the kickoff state is the foundation those commands build on.

## What's next

- [§Y `chat-driven-triage.md`](chat-driven-triage.md) — what the
  agent does *on top of* kickoff state.
- [§Z `evidence-and-citations.md`](evidence-and-citations.md) —
  reading evidence_log directly.

→ [§Y `chat-driven-triage.md`](chat-driven-triage.md)
