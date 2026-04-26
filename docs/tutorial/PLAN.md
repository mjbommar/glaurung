# Glaurung tutorial track — top-down plan

This document is the structural plan for `docs/tutorial/`. Every step
in every chapter doubles as a **functionality requirement**: the CLI
or REPL surface named must work end-to-end, on a sample binary that
ships in this repo, with no LLM dependency unless explicitly
flagged. Anything not yet shipped is called out as a **GAP** and
becomes a candidate task in the parity tracker.

## Design principles

- **Decompiler-first ordering.** Modern RE tutorials lead with
  pseudocode, not assembly. We do the same — `glaurung kickoff`
  and `glaurung view` come before any disassembly deep-dive.
- **Every step is a one-line shell command.** No "click this menu
  in the GUI" — readers can copy-paste and follow along.
- **Sample binaries ship in this repo.** Every tutorial points at
  a path under `samples/binaries/...` so a fresh clone is enough.
- **CTF walkthrough shape.** Real-binary chapters follow the
  universal 6-step template:
  triage → load → function-id → string/logic trace → verify → solve.
- **Provenance is visible.** Every annotation surfaced in a tutorial
  shows its `set_by` tag (manual / dwarf / flirt / propagated /
  gopclntab / cil / auto / borrowed). This is a Glaurung-specific
  edge over IDA/Ghidra and the docs should call it out.
- **Undo as a teaching aid.** Tutorials encourage readers to
  experiment freely with rename/retype because `glaurung undo`
  reverses any analyst write.

## Track structure

```
docs/tutorial/
  README.md                      # entry point + prerequisites + nav
  PLAN.md                        # this file (kept after the track lands)
  01-getting-started/
    install.md                   # § A
    first-binary.md              # § B
    cli-tour.md                  # § C
    repl-tour.md                 # § D
  02-daily-basics/
    naming-and-types.md          # § E
    cross-references.md          # § F
    stack-frames.md              # § G
    strings-and-data.md          # § H
    searching.md                 # § I
    bookmarks-and-journal.md     # § J
    undo-redo.md                 # § K
    patch-and-verify.md          # § L
  03-walkthroughs/
    01-hello-c-clang.md          # § M (binary ladder rung 1)
    02-stripped-go-binary.md     # § N (binary ladder rung 2)
    03-managed-dotnet-pe.md      # § O (binary ladder rung 3)
    04-jvm-classfile.md          # § P (binary ladder rung 4)
    05-vulnerable-parser.md      # § Q (vulnerability hunting CTF shape)
    06-upx-packed-binary.md      # § R (anti-analysis)
    07-malware-c2-demo.md        # § S (full flagship demo, agent-aware)
  04-recipes/
    diffing-two-binaries.md      # § T
    exporting-to-ida-ghidra.md   # § U
    typed-locals-from-libc.md    # § V
    bench-harness-as-ci.md       # § W
  05-agent-workflows/
    one-shot-kickoff.md          # § X (deterministic only)
    chat-driven-triage.md        # § Y (LLM, optional)
    evidence-and-citations.md    # § Z
  reference/
    cli-cheatsheet.md            # § AA
    repl-keymap.md               # § BB
    set-by-precedence.md         # § CC
    sample-corpus.md             # § DD
```

The track has five tiers. A reader can stop at the end of any tier
and have done productive work; each subsequent tier deepens the
toolkit without requiring earlier tiers verbatim (we cross-link).

---

## Tier 1: Getting started (§A-§D)

Goal: from clean install to a binary loaded in under five minutes.
Everything in this tier is **deterministic only** — no LLM calls.

### § A — `install.md`

**Requirements (glaurung must expose):**

- `pip install` (or `uv pip install -e .`) succeeds on a fresh
  Linux x86_64 / macOS arm64 / WSL Ubuntu environment.
- `glaurung --version` prints a semver string.
- `glaurung --help` lists every subcommand documented in this track.
- The binary corpus under `samples/binaries/` is reachable from the
  repo root (no external download required).

**Sections to write:**

1. Prerequisites (Python ≥ 3.11, Rust toolchain only if building from source).
2. `pip install glaurung` (PyPI) and `git clone + uv sync` (source).
3. Sanity check: `glaurung kickoff samples/binaries/.../hello-clang-debug`
   completes in under a second and prints a triage summary.
4. Optional: enable LLM features (env vars / config file).

**GAPs:** PyPI publishing pipeline isn't shipped (we publish the
wheel locally only). **Future task:** add `release-pypi.yml` GitHub
Action.

---

### § B — `first-binary.md`

**Requirements:**

- `glaurung kickoff <binary>` completes in <1s on a small ELF.
- Prints: format, arch, language, function count, named-vs-unnamed
  ratio, packer verdict, IOC count summary.
- Subsequent commands can read the same `.glaurung` project file.

**Sections:**

1. Pick a binary: `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug`.
2. Run `glaurung kickoff <binary> --db tutorial.glaurung`.
3. Read the markdown summary aloud: what each line means.
4. Open `tutorial.glaurung` in a SQLite viewer to demystify it
   (it's just rows in a few tables).
5. Pointer forward: "every command in Tier 2 reads/writes this same DB."

**GAPs:** none. `kickoff_analysis` already exposes everything.

---

### § C — `cli-tour.md`

**Requirements:** every CLI subcommand listed must run successfully
against `tutorial.glaurung`:

| Subcommand | Status |
|---|---|
| `glaurung triage <binary>` | ✅ |
| `glaurung kickoff <binary>` | ✅ |
| `glaurung disasm <binary> <va>` | ✅ |
| `glaurung decompile <binary> <va>` | ✅ |
| `glaurung view <db> <va>` (#223) | ✅ |
| `glaurung xrefs <db> <va>` (#219) | ✅ |
| `glaurung frame <db> <fn-va>` (#221) | ✅ |
| `glaurung find <db> <query>` (#225) | ✅ |
| `glaurung strings-xrefs <db>` (#222) | ✅ |
| `glaurung bookmark <db>` (#226) | ✅ |
| `glaurung journal <db>` (#226) | ✅ |
| `glaurung undo <db>` / `redo` (#228) | ✅ |
| `glaurung patch in out --va N --nop` (#224) | ✅ |
| `glaurung diff a b` | ✅ |
| `glaurung detect-packer <binary>` | ✅ |
| `glaurung graph <binary> callgraph` | ✅ |
| `glaurung export <db> --output-format json` | ✅ |
| `glaurung classfile <path>` (#209) | ✅ |
| `glaurung luac <path>` (#211) | ✅ |
| `glaurung verify-recovery <recovered-dir>` | ✅ |
| `glaurung repl <binary>` | ✅ |
| `glaurung name-func <binary> <va>` (LLM) | ✅ |
| `glaurung ask "<question>"` (LLM) | ✅ |

**Sections:**

1. Group commands by purpose (load / inspect / annotate / patch /
   export / agent).
2. Show a one-liner for each.
3. Cross-link to the tier-2 chapters that go deep on each one.

**GAPs:** none. This is summary-only; each command has its own
chapter.

---

### § D — `repl-tour.md`

**Requirements:** Every keystroke documented in the cheatsheet must
work on `tutorial.glaurung`.

| Keystroke | Action | Status |
|---|---|---|
| `g <addr>` | Goto address | ✅ |
| `b` / `f` | Back / forward | ✅ |
| `n <name>` | Rename function at cursor (auto-rerender) | ✅ |
| `y <c-type>` | Retype data label at cursor | ✅ |
| `c <text>` | Comment at cursor | ✅ |
| `x` | Cross-references at cursor | ✅ |
| `d` | Decompile enclosing function | ✅ |
| `l` / `locals` | List/edit stack frame slots | ✅ |
| `label <addr> <name>` | Set data label | ✅ |
| `borrow <other.glaurung>` | Cross-binary symbol borrow | ✅ |
| `proto <name> <c-type>` | Set function prototype | ✅ |
| `propagate` | Run cross-function type propagation | ✅ |
| `recover-structs` | Run auto-struct recovery | ✅ |
| `ask "<question>"` | LLM agent with full KB context | ✅ |
| `save` | Persist KB to disk | ✅ |
| `q` / `quit` | Exit | ✅ |

**Sections:**

1. Launch the REPL: `glaurung repl <binary> --db tutorial.glaurung`.
2. The cursor model: `goto`, history, `back`/`forward`.
3. Each keystroke demoed with output.
4. Cross-link to `02-daily-basics/` for deeper coverage of each.

**GAPs:** none.

---

## Tier 2: Daily basics (§E-§L)

Goal: master the 10-keystroke loop an analyst hits in an hour. Each
chapter is a self-contained walkthrough using `tutorial.glaurung` from
Tier 1.

### § E — `naming-and-types.md` (rename + retype)

**Requirements:** #220 keystroke flow + #228 undo end-to-end.

**Sections:**

1. Rename a function: `n parse_packet` at the cursor (auto-rerender
   shows callers updating).
2. Retype a data label: `y char[32]` at a global VA.
3. Provenance: read back via `glaurung find <db> parse_packet`.
4. **Undo as safety net:** `glaurung undo <db>` reverses the rename.
5. Round-trip: rename → re-render → undo → re-render.

**Reader exit state:** confidence to rename aggressively without
fear, knowing undo is there.

**GAPs:** none.

---

### § F — `cross-references.md`

**Requirements:** #219 xrefs panel + #227 prototype hints.

**Sections:**

1. From any call line: `x` (REPL) or `glaurung xrefs <db> <va>`.
2. Filter by kind: `--kind call` vs `--kind data_read`.
3. Read the snippet column — what's the calling instruction?
4. Walk callees: `--direction from` from inside `main`.
5. Prototype hints in decompile output: `// proto: ...` annotations.

**Reader exit state:** can navigate from any call site to its caller
or callee in one keystroke.

---

### § G — `stack-frames.md`

**Requirements:** #221 frame editor + #191 stack-frame slots.

**Sections:**

1. `glaurung frame <db> <fn-va>` — read the slot table.
2. `glaurung frame ... discover` to populate slots.
3. Inline retype: `frame ... retype -0x10 char[256]`.
4. Confirm via decompile: `glaurung view <db> <fn-va>` shows the
   slot named in the body.
5. Provenance: which slots came from auto-discovery vs the analyst?

**GAPs:** the frame editor doesn't yet show "size" beyond the
gap-to-next-slot heuristic. **Future task:** track explicit
slot sizes when a c_type is set with known width.

---

### § H — `strings-and-data.md`

**Requirements:** #222 strings panel + data labels (#181).

**Sections:**

1. `glaurung strings-xrefs <db>` — every string with its use sites.
2. Filter to interesting strings: `--used-only --min-len 8`.
3. Add a data label at a global: REPL `label 0x4000 g_secret_key --type "char[32]"`.
4. Re-render: the secret_key shows up by name in callers.
5. **CTF tip**: scan for URLs/IPs/paths in the strings panel.

**GAPs:** the strings panel doesn't yet group by section
(.rodata vs .data). **Future task:** add `--section` filter once
section-of-VA is exposed in the Python API.

---

### § I — `searching.md`

**Requirements:** #225 unified search.

**Sections:**

1. `glaurung find <db> parse` — sweep across functions / comments /
   labels / types / stack vars / strings / disassembly.
2. Filter by kind: `--kind disasm` for raw mnemonic search.
3. Regex: `--regex '^parse_'`.
4. Case sensitivity: `--case-sensitive`.
5. Use case: "find every TODO comment" — `find <db> TODO --kind comment`.

---

### § J — `bookmarks-and-journal.md`

**Requirements:** #226 bookmarks + journal.

**Sections:**

1. Bookmark a VA: `glaurung bookmark <db> add 0x1234 "weird branch"`.
2. List bookmarks: `bookmark <db> list`.
3. Journal entry: `journal <db> add "today: traced C2 protocol"`.
4. Workflow: bookmark while exploring, journal when you change state.
5. Difference from comments: bookmarks index by id (multiple per VA)
   and survive multiple revisions.

---

### § K — `undo-redo.md`

**Requirements:** #228 undo log.

**Sections:**

1. Mutations covered: rename, retype, comment, data label, stack var.
2. `glaurung undo <db>` reverts the last analyst write.
3. `glaurung undo <db> --list` prints history without mutating.
4. `glaurung redo <db>` re-applies what undo just reverted.
5. Why auto / dwarf / flirt / propagated writes don't enter the log
   (they re-derive on next pass).
6. **Set_by precedence diagram** — see also `reference/set-by-precedence.md`.

---

### § L — `patch-and-verify.md`

**Requirements:** #224 patch shorthands + #185 byte-level patch.

**Sections:**

1. NOP an instruction: `glaurung patch in out --va 0x1140 --nop --verify`.
2. Force a branch: `--force-branch true|false`.
3. Redirect: `--jmp 0x1200`.
4. Raw bytes: `--bytes "90 90 90"`.
5. The `--verify` step re-disassembles the patched VA so you can
   confirm the encoding decodes as intended.
6. **Caveat**: patches don't currently enter the undo log. **Future
   task:** wire `patch_at_va` into `_record_undo` so a single
   `glaurung undo <db>` reverses both KB writes AND byte-level
   patches.

**GAPs:** patches not yet undo-able. Filed as a follow-up; this
chapter explicitly calls it out.

---

## Tier 3: Walkthroughs (§M-§S)

Each walkthrough follows the universal CTF shape:

```
1. Triage          — what is this thing? (format, arch, language)
2. Load            — kickoff into a fresh .glaurung project
3. Function ID     — find main / entry / interesting logic
4. String/logic trace — what does it do?
5. Verify          — confirm via decompile + xrefs
6. Solve / annotate — extract IOC, write report, or rename for clarity
```

Each walkthrough is a real `glaurung` session transcript with
copy-pasteable commands and expected output. Total runtime per
walkthrough: 5-30 minutes.

### § M — `01-hello-c-clang.md` (rung 1: tiny C ELF)

Sample: `samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug`

The "Hello World" ladder rung. Teaches the full kickoff →
xrefs → rename → undo loop on a binary so simple the reader
already knows what it does.

### § N — `02-stripped-go-binary.md` (rung 2: stripped managed)

Sample: `samples/binaries/platforms/linux/amd64/export/go/hello-go`

Demonstrates **#212 Go gopclntab walker**. Reader sees:
- 0 named functions before pclntab walk
- 1801 named functions after `index_callgraph` runs
- `main.main`, `runtime.gopanic`, `internal/abi.Kind.String` all present
- `glaurung find <db> main.` lists every user function

This chapter is the strongest "Glaurung does what IDA can't out of
the box" demo we have today.

### § O — `03-managed-dotnet-pe.md` (rung 3: managed PE)

Sample: `samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe`

Demonstrates **#210 .NET CIL metadata parser**. Reader sees:
- ECMA-335 metadata-table walker recovering `Hello::Main` and
  `Hello::.ctor` from a managed PE
- `set_by="cil"` provenance tag
- VAs computed as image_base + RVA

### § P — `04-jvm-classfile.md` (rung 4: bytecode)

Sample: `samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class`
and the matching `.jar`.

Demonstrates **#209 JVM classfile parser**. Reader sees:
- `glaurung classfile HelloWorld.class` printing class +
  super + interfaces + fields + methods with JVM descriptors
- `glaurung classfile HelloWorld.jar` walking every class entry
- The differences from native binaries: no VAs, file IS the function
  container

**GAP:** JVM bytecode doesn't yet wire into the KB function_names
table the way Go / .NET do, because there's no VA model. **Future
task:** design a `bytecode_methods` table for non-VA function
recovery so `glaurung xrefs` can work on a .class file.

### § Q — `05-vulnerable-parser.md` (CTF shape: vuln hunting)

Sample: `samples/binaries/platforms/linux/amd64/export/native/gcc/O0/vulnparse-c-gcc-O0`

Already shipped as Demo 2 (#207). The walkthrough mirrors the
existing transcript but in the canonical 6-step CTF shape:
triage → load → find `parse` → trace user input flow → verify
buffer-overflow site → annotate.

### § R — `06-upx-packed-binary.md` (anti-analysis)

Sample: `samples/packed/hello-go.upx9`

Demonstrates **#187 packer detection** + the bench harness's
**#213 packed-matrix tier**. Reader sees:
- `glaurung detect-packer` flags UPX with confidence ≥ 0.9
- `kickoff_analysis` short-circuits on packed input (the body is
  unreachable until unpacked)
- `python -m glaurung.bench --packed-matrix` produces a regression-
  trackable scorecard ("Packed binaries: 10 (UPX×10)")
- **Caveat**: glaurung doesn't unpack. The walkthrough covers
  **detect → punt to upx → re-analyse the unpacked binary** as
  the canonical workflow.

**GAP:** `glaurung unpack` is not shipped. **Future task** (likely
filed as #229): wire `upx -d` as an optional unpack step gated on
the packer verdict, returning a new `.glaurung` for the unpacked
binary.

### § S — `07-malware-c2-demo.md` (flagship)

Sample: `samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0`

The flagship demo (#205 Demo 1). Full malware-triage walkthrough:
- Triage → kickoff
- IOCs surface in the kickoff summary (URLs, IPs, paths)
- `glaurung strings-xrefs` shows where each IOC is referenced
- Type propagation lights up libc args (`recv(int sockfd, ...)`)
- Auto-struct recovery on the C2 message buffer
- Agent-driven: the reader runs `glaurung ask "what does this binary do?"`
  and the agent builds its case from the citable evidence_log

This is the longest chapter (~30 min reader time) and the one we'd
link from a marketing page.

---

## Tier 4: Recipes (§T-§W)

Short, focused, copy-paste-driven. Each <300 words.

### § T — `diffing-two-binaries.md`

`glaurung diff a.elf b.elf` — function-level diff with same /
changed / added / removed status. Use case: "what did the patch
change?" Sample: `switchy-c-gcc-O2` vs `switchy-c-gcc-O2-v2`
(Demo 3, #205).

### § U — `exporting-to-ida-ghidra.md`

`glaurung export <db> --output-format ida|binja|ghidra` — emit a
script that applies your KB inside the target tool. Use case:
"Glaurung is my fast-iterate engine; ship the result to IDA for the
team." Each format covered: IDAPython, Binary Ninja, Ghidra Python.

### § V — `typed-locals-from-libc.md`

The propagation pipeline: stdlib bundle (#180) loads → DWARF /
auto types stack into type_db → call-site propagation (#195)
fills stack-var c_types from libc args → render_decompile_with_names
shows them as real C declarations (#194). Demonstrate on
`c2_demo-clang-O0`'s `recv()` call.

### § W — `bench-harness-as-ci.md`

`python -m glaurung.bench --ci-matrix --output baseline.json`. Use
case: "I'm refactoring the structurer — did anything regress?"
Cover the JSON shape, the markdown summary, and `--packed-matrix`
for packer-detection regressions.

---

## Tier 5: Agent workflows (§X-§Z)

Optional tier — only relevant if the reader has LLM credentials
configured.

### § X — `one-shot-kickoff.md`

`glaurung kickoff <binary>` is the deterministic-only first-touch
pipeline. **Zero LLM**. The agent's first turn in a chat UI uses
this same data. Reader exit state: understands which fields are
KB-driven and which are LLM-driven.

### § Y — `chat-driven-triage.md`

`glaurung repl + ask` or the (planned) web UI. Reader sees:
- Agent has 50+ memory tools
- Each tool call records to evidence_log with a citation id
- The agent's answer cites those evidence rows by id
- Manual rename mid-conversation — agent picks up the new name

**GAPs:**
- Web chat UI (#203/#204) not shipped.
- Streaming agent output not shipped.

### § Z — `evidence-and-citations.md`

The evidence_log table (#200) — every memory-tool call records its
inputs/outputs/summary with a `cite_id`. The agent can render its
case as "I claim X because evidence_log row 47 shows Y." Reader
walks through reading the log directly via SQLite.

---

## Reference (§AA-§DD)

### § AA — `cli-cheatsheet.md`

One-page table of every CLI subcommand with a one-line description
and a typical invocation. Generated by walking `glaurung --help`
output; kept in sync via a CI check.

**GAP:** no CI check yet. **Future task:** snapshot test that
diffs `glaurung --help` against `cli-cheatsheet.md`.

### § BB — `repl-keymap.md`

Same shape for the REPL.

### § CC — `set-by-precedence.md`

The provenance ladder: `manual > dwarf > flirt > borrowed > cil > gopclntab > propagated > auto > analyzer > stdlib`.
Why writes from each source can or can't clobber writes from
another. The undo log only captures `manual` writes.

### § DD — `sample-corpus.md`

The full inventory of `samples/binaries/` with a one-line
description per binary, the canonical workflow it demonstrates,
and the chapter number that uses it. This is also the input to
`bench --ci-matrix`.

---

## Functionality requirements summary (the gap list)

This whole plan is a requirements document. Anything labeled **GAP**
above feeds the parity tracker. Aggregated:

| GAP | Owner chapter | Suggested task |
|---|---|---|
| PyPI release pipeline | § A install | `release-pypi.yml` GitHub Action |
| Frame editor: explicit slot sizes | § G stack-frames | Track size when c_type has known width |
| Strings panel: section filter | § H strings-and-data | Expose section-of-VA + add `--section` flag |
| Patches enter undo log | § L patch-and-verify | Wire `patch_at_va` into `_record_undo` |
| JVM bytecode → KB | § P jvm-classfile | Design `bytecode_methods` table for non-VA recovery |
| `glaurung unpack` for UPX | § R upx-packed | Optional `upx -d` flow returning a fresh .glaurung |
| Web chat UI | § Y chat-driven-triage | #203 (already filed) |
| Streaming agent output | § Y chat-driven-triage | #204 (already filed) |
| CLI cheatsheet snapshot test | § AA cli-cheatsheet | Pytest that diffs `--help` output |

These gaps are **not blockers** for shipping the tutorial track.
Each chapter that mentions a gap makes the gap explicit to the
reader (which is itself useful — it sets expectations and points
to the roadmap).

---

## Order of operations for shipping the track

1. **Land this plan as `PLAN.md`.** Acts as the contract between
   docs and engineering.
2. **Land the reference tier first** (§AA-§DD). It's mostly
   table-of-contents-shaped material we can derive from existing
   docstrings + the parity tracker. Cheap to ship, immediately
   useful.
3. **Land Tier 1** (§A-§D) next. Validates the install →
   first-binary path against a fresh clone.
4. **Land Tier 2** (§E-§L) one chapter at a time, each as its own
   commit. Each chapter is roughly 200-400 lines and cross-links
   to siblings.
5. **Land Tier 3 walkthroughs** (§M-§S) in order of "Glaurung
   superpower" — start with §N stripped-Go (the strongest
   differentiator), §S c2_demo flagship last.
6. **Land Tier 4 recipes** (§T-§W) in parallel with Tier 3 —
   they're short and self-contained.
7. **Tier 5 agent workflows** (§X-§Z) last, gated on the LLM
   chapters' samples being reproducible.

A reasonable cadence is 2-3 chapters per session; the full track
fits in roughly two weeks of focused work assuming no unexpected
gaps.

---

## What this gets us beyond docs

Writing every chapter against shipped CLI surfaces is the most
realistic functional test we can run on the daily-basics floor.
Every "copy this command" line in this plan is one more assertion
that the surface still works. As tutorials land, broken commands
become commit-blockers — the docs become a second tier of
regression coverage on top of the bench harness and the 85-test
adversarial matrix (#214).
