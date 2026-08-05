# Glaurung tutorial track

Welcome. This track teaches you how to use Glaurung the way a working
reverse engineer uses IDA Pro or Ghidra — but with the Glaurung-
specific edges (persistent KB with explicit provenance, end-to-end
undo, agent integration) called out as you go.

## Who this is for

You should be comfortable on the command line and have a vague idea
what "reverse engineering a binary" means. You **do not** need:

- Prior IDA / Ghidra experience (we'll point at analogous concepts).
- Assembly-language fluency (the decompiler renders pseudocode first;
  raw disassembly is optional).
- An LLM API key (Tiers 1-4 are deterministic only; Tier 5 is opt-in).

## Track shape

Five tiers, plus a reference. Each tier stands alone — you can stop
after any tier and have done productive work. Each subsequent tier
deepens the toolkit without requiring earlier tiers verbatim.

### [Tier 1: Getting started](01-getting-started/) (~30 min)

Clean install → loaded binary in under five minutes.

- §A `install.md`
- §B `first-binary.md`
- §C `cli-tour.md`
- §D `repl-tour.md`

### [Tier 2: Daily basics](02-daily-basics/) (~2 hours)

The eight keystroke loops an analyst hits in an hour of real work.

- §E `naming-and-types.md` — rename + retype with auto-rerender (#220)
- §F `cross-references.md` — the xrefs panel (#219)
- §G `stack-frames.md` — the frame editor (#221)
- §H `strings-and-data.md` — the strings panel + data labels (#222 / #181)
- §I `searching.md` — `glaurung find` across every table (#225)
- §J `bookmarks-and-journal.md` — analyst notes (#226)
- §K `undo-redo.md` — the trust floor (#228)
- §L `patch-and-verify.md` — patch shorthands + re-disasm verify (#224)

### [Tier 3: Walkthroughs](03-walkthroughs/) (~5 hours total)

Seven CTF-shape transcripts on real samples shipped in this repo.

| # | Sample | Demonstrates |
|---|---|---|
| §M | `hello-clang-debug` | The full kickoff → annotate loop on a tiny C ELF |
| §N | stripped Go binary | gopclntab recovery (#212): 0 → 1801 named functions |
| §O | Mono PE | CIL metadata recovery (#210): `Hello::Main` from a managed PE |
| §P | Java classfile + JAR | JVM bytecode triage (#209) |
| §Q | vulnparse | Vulnerability hunting (CTF buffer-overflow analog) |
| §R | UPX-packed | Anti-analysis: detect → punt to upx → re-analyze |
| §S | c2_demo | Full malware-triage flagship (Demo 1, agent-aware) |

### [Tier 4: Recipes](04-recipes/) (~30 min each)

Short, copy-paste-driven recipes for specific tasks.

- §T `diffing-two-binaries.md`
- §U `exporting-to-ida-ghidra.md`
- §V `typed-locals-from-libc.md`
- §W `bench-harness-as-ci.md`

### [Tier 5: Agent workflows](05-agent-workflows/) (optional, requires LLM)

How the deterministic backbone supports an LLM-driven analyst loop.

- §X `one-shot-kickoff.md`
- §Y `chat-driven-triage.md`
- §Z `evidence-and-citations.md`

### [Reference](reference/)

Lookup material kept here so chapters can cross-link to it.

- [`cli-cheatsheet.md`](reference/cli-cheatsheet.md) — every `glaurung` subcommand
- [`repl-keymap.md`](reference/repl-keymap.md) — every REPL keystroke
- [`set-by-precedence.md`](reference/set-by-precedence.md) — the provenance
  ladder (manual > dwarf > flirt > ... > stdlib)
- [`sample-corpus.md`](reference/sample-corpus.md) — every binary in
  `samples/binaries/` and the chapter that uses it

## Conventions

- **Environment.** Chapters after §A show the shorter `glaurung ...` form and
  assume you ran `source .venv/bin/activate` from the repository root. If the
  environment is not activated, prepend `uv run` to every Glaurung or Python
  command.
- **Copy-paste-driven.** Every step is a one-line shell command or
  REPL keystroke. No screenshots; no "right-click this button".
- **Sample binaries ship in this repo.** Every walkthrough names a
  path under `samples/binaries/...` so a fresh clone is enough.
- **Provenance is visible.** When the docs show a renamed function,
  the `set_by` tag is shown too — so you know whether a name came
  from DWARF (very trustworthy), the analyzer (placeholder), or you
  (manual, undo-able).
- **Status notes.** Anything that's a current limitation (a parser
  we haven't shipped yet, a CLI flag in flight) is flagged inline
  with a → link to the parity tracker.

## How to read this

Linear is fine — each tier builds on the previous. But if you have a
specific question, jump straight in:

- **"How do I just open a binary?"** → §B `first-binary.md`
- **"How do I rename a function?"** → §E `naming-and-types.md`
- **"How do I find every caller of `recv`?"** → §F `cross-references.md`
- **"How do I analyze a stripped Go binary?"** → §N walkthrough
- **"How do I patch out a license check?"** → §L `patch-and-verify.md`
- **"What's `set_by="cil"` mean?"** → reference/`set-by-precedence.md`

## See also

- [`PLAN.md`](PLAN.md) — the structural plan / functionality
  requirements for this whole track. Useful if you want to know
  what's coming next or contribute a chapter.
- `../architecture/IDA_GHIDRA_PARITY.md` — the engineering tracker
  for "what Glaurung has, what's still missing."
- `../demos/` — the three canonical chat-UI demos referenced by
  Tier 5.
