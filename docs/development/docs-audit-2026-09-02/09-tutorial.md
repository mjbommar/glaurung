# Audit: docs/tutorial/ (chapters, reference, _fixtures)

## Executive summary

`docs/tutorial/` is in genuinely good shape and should be the backbone of the
rewrite: 22 of 24 fixture-backed chapters are byte-verified against real CLI
output by `scripts/verify_tutorial.py` + `python/tests/test_verify_tutorial.py`,
and every chapter I checked matches the current CLI registry, argparse flags,
and sample-corpus paths. The verifier does **not** parse markdown fences — it
hardcodes each chapter's commands separately in Python and links to the
resulting `.out` fixtures from hand-written prose, so markdown and Python can
silently diverge; this is exactly what happened. Two concrete, high-confidence
defects: (1) `reference/set-by-precedence.md` documents a `set_by` precedence
ladder that does not match `python/glaurung/llm/kb/provenance.py`'s
`SET_BY_PRIORITY` table (rewritten 2026-08-28) — wrong on `stdlib`,
`gopclntab`, `borrowed`, and missing `pdb`/`ported` entirely; the same wrong
ladder is echoed a third way in `PLAN.md` and a fourth way in root
`CLAUDE.md`. (2) `reference/cli-cheatsheet.md` is missing the four
`rename`/`comment`/`label`/`proto` top-level commands added 2026-08-28
(commit `881e01ba`) — the registry has 40 commands, the cheatsheet lists 36 —
and `PLAN.md`'s own open GAP ("no CI check diffing `--help` against the
cheatsheet") explains exactly why nothing caught it: the harness only
fixture-checks the first 3 lines of `--help`, not the cheatsheet prose. A
third finding, `03-walkthroughs/05-vulnerable-parser.md`'s
`disasm --function parse_record` command, silently disassembles the entry
point instead (KB-aware mode requires `--db`, which the line omits) — nothing
catches it because that exact command is not in the verifier's recipe.
Everything else — 21 chapters, `sample-corpus.md`, all fixture links, all
sample paths — checked out clean.

## Per-file table

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---|---|---|---|---|---|
| `01-getting-started/install.md` | 111 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_install` recipe exactly; `--version` string `0.1.0` matches `main.py:131`; `git clone` URL matches `git remote -v`; both sample paths exist. | keep |
| `01-getting-started/first-binary.md` | 112 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_first_binary` recipe exactly; all 6 fixture links resolve; `set_by` sentence ("both landmarks are currently analyzer-provided") matches `sqlite-fnames.out`. | keep |
| `01-getting-started/cli-tour.md` | 146 | `0ec35a2e` 2026-08-07 | user-guide | mostly-current | Verified subset (triage/strings/disasm/cfg/kickoff/find/view/xrefs/strings-xrefs/frame/undo) matches `chapter_cli_tour` exactly. But `symbols`, `decompile`, `graph`, `diff`, `export`, `patch --help`, `ask`, `bookmark --help`, `journal --help` shown in prose are never executed by the harness (unverified prose). Missing any mention of the `rename`/`comment`/`label`/`proto` non-interactive CLI verbs added 2026-08-28 (`881e01ba`) — this chapter's own "Work interactively and preserve history" section is the natural home for them and doesn't cover them. | revise: add a scriptable-annotation section (`rename`/`comment`/`label`/`proto`); note which command families are prose-only |
| `01-getting-started/repl-tour.md` | 144 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_repl_tour` recipe exactly (help/navigate/inspect/decomp/functions/annotate/locals-rename/proto/undo-list). Does not itself quote a stale tool count (see cross-cutting finding on `repl.py`'s "51 tools" string, which only shows up in the fixture, not this prose). | keep |
| `02-daily-basics/naming-and-types.md` | 110 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_naming_and_types` recipe exactly; `set_by=cil`/manual claims consistent with code. | keep |
| `02-daily-basics/cross-references.md` | 87 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_xrefs_demo` recipe exactly; all 6 fixture links resolve. | keep |
| `02-daily-basics/stack-frames.md` | 75 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_stack_frames` recipe exactly (list/discover/rename/retype/json). | keep |
| `02-daily-basics/strings-and-data.md` | 78 | `0ec35a2e` 2026-08-07 | user-guide | mostly-current | Matches `chapter_strings_and_data` recipe exactly for commands run, but the second `find "$DB" server --kind data` example is only backed by the link to `find-label.out`, not its actual fixture `find-data-prefix.out` (unreferenced in the doc). Cosmetic citation slip, not a functional bug. | revise: fix the `find-data-prefix.out` citation |
| `02-daily-basics/searching.md` | 87 | `0ec35a2e` 2026-08-07 | user-guide | mostly-current | `find` examples match `chapter_searching` recipe exactly. The closing "Pivot to evidence" `view`/`xrefs` commands are not in that chapter's recipe (unverified here specifically, though the same binary/address combo is verified in `cross-references.md`). | revise (optional): fold the pivot commands into the harness, or note they're illustrative |
| `02-daily-basics/bookmarks-and-journal.md` | 75 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_bookmarks` recipe exactly (add/list/filter/journal/delete/json). | keep |
| `02-daily-basics/undo-redo.md` | 74 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_undo_redo` recipe exactly. | keep |
| `02-daily-basics/patch-and-verify.md` | 67 | `0ec35a2e` 2026-08-07 | user-guide | mostly-current | Matches `chapter_patch` recipe's commands/flags exactly (`--nop`/`--bytes`/`--verify`/`--force`/`--format json`), but every example writes output under `/tmp/...`, and the verifier's own `TMP = Path("/tmp/tutorial-fixtures")` (`scripts/verify_tutorial.py:43`) does the same — both contradict CLAUDE.md's explicit "nothing this project does may write to `/tmp`; export `TMPDIR` first" rule. | revise: point examples at `$TMPDIR` or a repo-local scratch dir, and fix the harness's own `TMP` constant to match |
| `03-walkthroughs/01-hello-c-clang.md` | 67 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_hello_c_clang` recipe exactly; addresses (`0x1150`/`0x11d0`/`0x1200`) and xref sources (`0x11bd`/`0x11c2`) match fixtures. | keep |
| `03-walkthroughs/02-stripped-go-binary.md` | 61 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_stripped_go` recipe exactly (regex anchoring, namespace query, runtime pivots). | keep |
| `03-walkthroughs/03-managed-dotnet-pe.md` | 41 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_dotnet_pe` recipe exactly; `find-hello.out` literally shows `Hello::.ctor (set_by=cil)` / `Hello::Main (set_by=cil)`, confirming the doc's provenance claim. | keep |
| `03-walkthroughs/04-jvm-classfile.md` | 43 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_jvm` recipe exactly; `java triage`/`security`/`recovery` subparsers confirmed in `python/glaurung/cli/commands/java.py:27-33`. | keep |
| `03-walkthroughs/05-vulnerable-parser.md` | 70 | `0ec35a2e` 2026-08-07 | user-guide | mostly-current | `kickoff`/`view`/`xrefs` steps match `chapter_vulnparse` recipe exactly. But `uv run glaurung disasm "$BIN" --function parse_record --max-instructions 160` is broken as written: `disasm.py:173` only takes the KB-aware `--function` path when **both** `args.db` and `args.function` are set; with no `--db` in this line, `--function` is silently ignored and the command disassembles from the binary's entry point instead of `parse_record`. This exact command is absent from `chapter_vulnparse`'s recipe, so the harness cannot catch the drift. | revise: add `--db "$DB"` to the command, or replace it with the already-recovered `--addr 0x11e9` |
| `03-walkthroughs/06-upx-packed-binary.md` | 50 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_upx_packed` recipe exactly; exit-code table (0/1/2) matches `EXPECTED_RETURN_CODES[("03-upx-packed","detect-packer")] = {1}`. | keep |
| `03-walkthroughs/07-malware-c2-demo.md` | 62 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_c2_demo` recipe exactly. | keep |
| `04-recipes/diffing-two-binaries.md` | 33 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_diff` recipe exactly; exit-1-on-difference matches `EXPECTED_RETURN_CODES[("04-diff","diff")] = {1}`. | keep |
| `04-recipes/exporting-to-ida-ghidra.md` | 47 | `0ec35a2e` 2026-08-07 | user-guide | mostly-current | `markdown`/`json`/`ida`/`binja`/`ghidra` formats match `chapter_export` recipe and `export.py`'s `--output-format` choices exactly. Doesn't cover the `header` (C header) or `bundle` (+`--bodies`) formats that also exist in `export.py:22`. Not wrong, just incomplete relative to the live surface. | revise (optional): add `header`/`bundle` coverage |
| `04-recipes/typed-locals-from-libc.md` | 50 | `0ec35a2e` 2026-08-07 | user-guide | current | Matches `chapter_typed_locals` recipe exactly; SQL query, column names, and `set_by='propagated'` filter match `stack_frame_vars` schema. | keep |
| `04-recipes/bench-harness-as-ci.md` | 52 | `0ec35a2e` 2026-08-07 | user-guide | current | `--ci-matrix`/`--packed-matrix`/`--output`/`--quiet` all confirmed in `python/glaurung/bench/__main__.py`. | keep |
| `05-agent-workflows/one-shot-kickoff.md` | 95 | `0ec35a2e` 2026-08-07 | user-guide | current | `--max-functions`, `--analyze-packed`, `--no-pdb`, `--no-fetch-pdb` all confirmed in `kickoff.py`; `evidence_log` columns match the schema fixture exactly. | keep |
| `05-agent-workflows/chat-driven-triage.md` | 141 | `0ec35a2e` 2026-08-07 | user-guide | current | `--route`/`--show-routing`/`--show-tools`/`--all-tools`/`--max-cost-usd`/`--usage-log` all confirmed in `ask.py`; "~163 tools" / "5-30" routed subset confirmed consistent with `memory_agent.py:595`, `tool_routing.py`, `llm/tools/base.py:60`, `test_tool_routing.py:147`; default usage-log path `~/.cache/glaurung/usage/<session>.jsonl` confirmed in `usage_tracker.py:291` and `ask.py:220`. Verification here is **assertion-based** (`test_verify_tutorial.py::test_agent_workflow_docs_use_current_safe_cli_contract`), not execution-based — reasonable, since `ask` is a live LLM call, but worth stating explicitly for the rewrite. | keep |
| `05-agent-workflows/evidence-and-citations.md` | 173 | `0ec35a2e` 2026-08-07 | user-guide | current | `evidence_log` column table (cite_id/binary_id/tool/args_json/summary/va_start/va_end/file_offset/output_json/created_at) matches `xref_db.py:186-197`'s `CREATE TABLE` verbatim, and matches the checked-in `evidence-log-schema.out` fixture byte-for-byte. | keep |
| `PLAN.md` | 629 | `fcca960b` 2026-08-05 | roadmap/plan | historical (self-declared "kept after the track lands") | Track-structure tree matches the shipped file tree exactly. Several GAPs remain true today: no PyPI workflow (`ls .github/workflows/` has none), `patch.py` never calls `_record_undo`/`undo_log` (grep count 0), §AA's "no CI check" diffing `--help` against `cli-cheatsheet.md` is still true. But: §CC's inline precedence ladder (`manual > dwarf > flirt > borrowed > cil > gopclntab > propagated > auto > analyzer > stdlib`, line 557) is wrong the same way `set-by-precedence.md` is wrong (see below) — a third distinct variant of an already-inconsistent claim. Line 427's sample path `samples/binaries/platforms/linux/amd64/export/native/gcc/O0/vulnparse-c-gcc-O0` does not exist (the real, correctly-used path elsewhere is `.../synthetic/vulnparse-c-gcc-O0`). | keep as historical record per its own note; revise §CC and the line-427 path when touched, but do not treat as a live reference |
| `README.md` (tutorial) | 98 | `0ec35a2e` 2026-08-07 | index | current | Learning-path list matches the actual directory/file names 1:1 (verified by listing `docs/tutorial/`); both `verify_tutorial.py` invocations shown work; links to `PLAN.md` and `../development/setup.md` resolve. | keep |
| `reference/cli-cheatsheet.md` | 136 | `0ec35a2e` 2026-08-07 | reference | **stale** | `python/glaurung/cli/main.py`'s `_REGISTRY` has 40 top-level commands (confirmed via `_fixtures/01-install/help-head.out`, the literal `--help` usage line). The cheatsheet documents 36 — missing `rename`, `comment`, `label`, `proto`, added by commit `881e01ba` ("cli: the analyst write surface existed only inside the REPL", 2026-08-28), which touched zero files under `docs/tutorial/`. `PLAN.md` §AA's own long-open GAP ("no CI check... snapshot test that diffs `glaurung --help` against `cli-cheatsheet.md`") is why nothing caught this: the harness only fixture-checks the first 3 lines of `--help` (the usage/subcommand-list line, refreshed in `342925a1`), never the cheatsheet's hand-written table. | revise: add the 4 missing commands; consider finally closing the PLAN.md §AA GAP with a real assertion (`_REGISTRY` keys ⊆ cheatsheet command column) |
| `reference/repl-keymap.md` | 100 | `32e0155a` 2026-04-26 | reference | mostly-current | Every entry in the doc's tables (g/b/f/n/y/c/x/d/l/s/q/`?`/label/borrow/proto/propagate/recover-structs/functions/types/struct/show/ask, plus long forms) is present with a matching key in `repl.py`'s `commands = {...}` dict (lines 750-787). Gap: doesn't mention that `rename`/`comment`/`label`/`proto` now *also* exist as non-interactive top-level CLI commands (same `881e01ba` addition as above) — a reader would not learn they can script annotations outside the REPL. | revise: cross-link to the new non-interactive CLI verbs from the "Annotation" table |
| `reference/set-by-precedence.md` | 157 | `32e0155a` 2026-04-26 | reference | **stale / superseded** | The documented ladder `manual > dwarf > flirt > borrowed > cil ≡ gopclntab > propagated > auto > analyzer > stdlib` does not match `python/glaurung/llm/kb/provenance.py`'s `SET_BY_PRIORITY` (introduced `2d3c3977`, "kb: the provenance ladder had two rungs, not seven", 2026-08-28): `manual(100) > dwarf≡pdb≡gopclntab(80) > stdlib(60) > flirt≡cil(50) > ported(40) > propagated(30) > auto≡analyzer≡borrowed(20)`. Concretely wrong: `stdlib` is placed dead-last in the doc but ranks *above* `flirt`/`cil` in code; `gopclntab` is tied with `dwarf` at the very top in code but tied with `cil` far lower in the doc; `borrowed` gets its own mid-ladder rung in the doc but is at parity with `auto`/`analyzer` (the bottom rung) in code; `pdb` and `ported` are entirely absent from the doc. `provenance.py`'s own module docstring states the *prior* implementation "was not implemented at all below the top rung" — i.e. even the old code only ever enforced manual-vs-everything-else, so this doc's detailed ladder was never accurate, before or after the rewrite. See cross-cutting findings for the third and fourth copies of this same wrong information. | rewrite entirely from `SET_BY_PRIORITY` in `provenance.py`; this is the single highest-priority fix in this scope |
| `reference/sample-corpus.md` | 149 | `0ec35a2e` 2026-08-07 | reference | current | All ~24 referenced `samples/...` paths in the mapping tables exist (checked programmatically); `samples/README.md`, `samples/adversarial/README.md`, `python/tests/test_adversarial_coverage.py`, `python/glaurung/bench/__main__.py` all exist. | keep |

## `_fixtures/` inventory

24 fixture directories, 157 `.out` files total, matching `verify_tutorial.py`'s
`CHAPTERS` dict **1:1** (every fixture directory has exactly one chapter
recipe and vice versa — no orphaned directories, no recipe with a missing
directory). All ~128 fixture links found in the chapter markdown resolve to
real files; the remaining ~29 `.out` files (mostly `kickoff.out` per chapter,
plus a handful like `xrefs-from-main.out`, `undo-list-after-redo.out`,
`find-case-sensitive.out`, `find-data-prefix.out`) exist and are exercised by
the harness but are not individually hyperlinked from prose — expected, since
`kickoff.out` in particular is long and the README explicitly avoids
hard-coding volatile counts in prose.

Git history of the whole `_fixtures/` tree is short and mostly `--capture`
maintenance, not organic drift:

| date | commit | trigger |
|---|---|---|
| 2026-04-26 | `14c92690` | harness + fixtures created (§B, §M) |
| 2026-04-26 | `797c2854` | Tier 1-5 chapters rewritten against real captured fixtures |
| 2026-08-07 | `0ec35a2e` | docs mass-overhaul (touched nearly everything) |
| 2026-08-10 | `fc1dea23` | decompiler change ("recover plt.got tail-call contracts") moved output |
| 2026-08-13 | `60271f29` | cross-arch lane measurement moved output |
| 2026-08-28 | `342925a1` | `--help` usage line refreshed for the 4 new CLI verbs |

This is a good signal for brittleness: fixtures move only when the CLI or
analyzer output genuinely changes, not on every commit — the harness is doing
its job. The one miss (`342925a1`) is instructive: it refreshed the *fixture*
correctly but did not (and structurally could not, per its own commit
message) touch the *prose* cheatsheet, which is the `cli-cheatsheet.md` gap
above.

## Directory-level summary

**`docs/tutorial/` top level** (`README.md`, `PLAN.md`): a working index plus
an intentionally-retained planning document. `README.md` is the real entry
point and is accurate. `PLAN.md` should survive the rewrite as a dated design
record (it says so itself), not as a maintained reference — its precedence
one-liner and one sample path need a one-time fix, but nothing more.

**`01-getting-started/` through `05-agent-workflows/`**: this is the live,
almost entirely fixture-verified backbone of the user-facing docs. 21 of 26
chapter files are fully current with no findings; the other 5 have small,
independent, easily-fixed issues (a broken example command, two citation
slips, one `/tmp` convention violation, one missing feature section). No
chapter references a deleted command, a renamed flag, or a nonexistent
sample. A clean structure here is close to the existing one — the tier
grouping (getting-started → daily-basics → walkthroughs → recipes →
agent-workflows) is sound and should be kept.

**`reference/`**: two of four files (`cli-cheatsheet.md`,
`set-by-precedence.md`) are stale specifically because they were *not*
touched by the 2026-08-07 mass edit or, for `set-by-precedence.md`, by the
2026-08-28 provenance rewrite either. `sample-corpus.md` and `repl-keymap.md`
are in good shape. This directory is exactly where a rewrite needs the
strongest tie to a single source of truth (the `_REGISTRY` dict and the
`SET_BY_PRIORITY` table) rather than hand-maintained prose tables, given it
has drifted twice already in under a year.

**`_fixtures/`**: purely generated evidence, never hand-edited (verified: no
`.out` file content contradicts what its recipe would produce, based on
spot-checks above). Treat as build output that happens to be checked in for
review-friendliness; it should not appear in a "docs I might delete/archive"
conversation — deleting it would silently disable the entire verification
mechanism.

## Cross-cutting findings

1. **The verifier does not parse markdown.** `scripts/verify_tutorial.py`
   hardcodes each chapter's commands as Python argv lists in a `CHAPTERS`
   dict; the markdown prose is hand-written separately and links to the
   resulting `.out` files. There is no mechanism that checks the *code fence
   text* in a `.md` file against what the harness actually ran — only that
   linked fixture files exist and that certain literal strings appear
   (`test_verify_tutorial.py`'s per-doc assertions, e.g. `test_ask_reference_tracks_current_cli_contract`).
   A rewrite that wants stronger guarantees should either (a) accept this
   two-track model and add a lint that fences in markdown are a subset of a
   chapter's recipe argv, or (b) invert it: generate the fenced examples from
   the recipe so they cannot diverge. Right now divergence is caught only
   when a human notices, which is exactly how `cli-cheatsheet.md` went stale.

2. **The `set_by` precedence ladder is wrong in four independent places**,
   each slightly differently: `docs/tutorial/reference/set-by-precedence.md`
   (`manual > dwarf > flirt > borrowed > cil≡gopclntab > propagated > auto >
   analyzer > stdlib`), `docs/tutorial/PLAN.md:557` (`manual > dwarf > flirt >
   borrowed > cil > gopclntab > propagated > auto > analyzer > stdlib` — cil
   and gopclntab split into two tiers here, unlike the reference doc), and
   root `CLAUDE.md` ("manual/dwarf/stdlib/flirt/propagated/auto/borrowed" —
   a *fifth*, shorter variant that at least gets `stdlib` above `flirt`,
   unlike the two tutorial docs). The actual code
   (`python/glaurung/llm/kb/provenance.py:59-102`, `SET_BY_PRIORITY`) is none
   of these: `manual(100) > {dwarf,pdb,gopclntab}(80) > stdlib(60) >
   {flirt,cil}(50) > ported(40) > propagated(30) > {auto,analyzer,borrowed}(20)`.
   This module was written 2026-08-28 specifically to *fix* a bug where the
   ladder wasn't implemented at all below `manual`; none of the three docs
   that describe a ladder were updated to match the fix. **This is the
   single most load-bearing piece of ground truth in this audit** — get the
   rewrite's provenance page from `provenance.py`, not from any existing doc.

3. **`cli-cheatsheet.md` and `repl-keymap.md` both missed the same commit**
   (`881e01ba`, 2026-08-28, adding non-interactive `rename`/`comment`/`label`/
   `proto`). The cheatsheet is missing the commands outright; the keymap
   documents their REPL forms but not that they now also exist standalone.
   Both gaps stem from the same cause as finding 1: the commit that changed
   the CLI touched zero files under `docs/tutorial/`.

4. **A verified fixture can still carry wrong information if the tool being
   verified is itself wrong.** `python/glaurung/cli/commands/repl.py` prints
   "(loaded memory agent — 51 tools available)" (line 741) and "run the
   memory agent (51 tools)" in its help text (line 935) — both dating from
   commit `12f884fd` (2026-04-25, the REPL's original implementation). The
   actual registered tool count has been documented elsewhere in the same
   codebase as **~163** since `05a05db5` (2026-05-22,
   `python/glaurung/llm/tool_routing.py`) and is corroborated by
   `memory_agent.py:595`, `llm/tools/base.py:60`, and
   `test_tool_routing.py:147`. `docs/tutorial/_fixtures/01-repl-tour/repl-help.out`
   faithfully captures the stale "51 tools" string, so `verify_tutorial.py`'s
   fixture-diff mechanism reports this chapter as fully verified even though
   the number it verifies is >3x stale. This is worth stating explicitly to
   whoever writes the rewrite plan: fixture-verification proves the doc
   matches the CLI's *current output*, not that the CLI's current output is
   itself accurate. (Fix belongs in `repl.py`, not in the tutorial — flagging
   here because it silently undermines confidence in the verification
   mechanism this scope depends on.)

5. **`/tmp` usage contradicts CLAUDE.md in the tutorial's own tooling.**
   `docs/tutorial/02-daily-basics/patch-and-verify.md`'s examples write to
   `/tmp/hello-c-clang-debug.nop` etc., and `scripts/verify_tutorial.py:43`
   hardcodes `TMP = Path("/tmp/tutorial-fixtures")` for the same purpose —
   both violate CLAUDE.md's "nothing this project does may write to `/tmp`;
   export `TMPDIR` first" rule (justified there by a shared, per-user-quota'd
   tmpfs that has caused real failures). This is arguably lower-stakes for a
   reader's own shell than for CI, but the harness itself should follow the
   project's own convention.

6. **`docs/demos/`** (out of my scope but directly downstream) reuses this
   scope's fixtures directly rather than duplicating narrative — `demo-1
   -malware-triage.md`, `demo-2-vulnerability-hunting.md`, and
   `demo-3-patch-analysis.md` all link straight into
   `../tutorial/_fixtures/03-c2-demo/`, `03-vulnparse/`, and `04-diff/`. This
   is the right pattern (single evidence source, two narrative framings —
   analyst walkthrough vs. marketing-style demo) and should be preserved,
   not merged. `docs/cli/ASK_COMMAND.md` and `docs/cli/analyst-ergonomics.md`
   overlap topically with `05-agent-workflows/chat-driven-triage.md` and
   `01-getting-started/cli-tour.md` respectively — worth a cross-scope
   reconciliation pass by whoever owns `docs/cli/`, since I did not audit
   that tree in depth.

7. **Root docs already treat the tutorial as the primary onboarding path.**
   `docs/README.md` sends new users straight into `tutorial/01-getting-started/`
   and links `tutorial/reference/cli-cheatsheet.md` / `set-by-precedence.md`
   as *the* CLI and provenance references for the whole documentation tree —
   so the two stale reference files found here are not a tutorial-only
   problem; they're the canonical answer the rest of `docs/` points at.

## Proposed new structure

The existing tier structure is sound; the rewrite should mostly be "fix
findings in place" plus two additions, not a reshuffle:

```
docs/tutorial/
  README.md                          rewrite of README.md — same nav, same tiers (current structure is good)
  PLAN.md                            archived — keep as dated historical record; fix §CC ladder + one path when next touched
  01-getting-started/
    install.md                       keep (current)
    first-binary.md                  keep (current)
    cli-tour.md                      rewrite of cli-tour.md — add scriptable-annotation section (rename/comment/label/proto)
    repl-tour.md                     keep (current)
  02-daily-basics/
    naming-and-types.md              keep
    cross-references.md              keep
    stack-frames.md                  keep
    strings-and-data.md              rewrite of strings-and-data.md — fix find-data-prefix.out citation
    searching.md                     keep (minor: note unverified pivot commands)
    bookmarks-and-journal.md         keep
    undo-redo.md                     keep
    patch-and-verify.md              rewrite of patch-and-verify.md — use $TMPDIR-based paths
  03-walkthroughs/  (all 7 files)    keep, except:
    05-vulnerable-parser.md          rewrite of 05-vulnerable-parser.md — fix the broken --function example
  04-recipes/  (all 4 files)         keep, except:
    exporting-to-ida-ghidra.md       revise: add header/bundle format coverage
  05-agent-workflows/  (all 3 files) keep
  reference/
    cli-cheatsheet.md                rewrite of cli-cheatsheet.md — add rename/comment/label/proto; generate from _REGISTRY where possible
    repl-keymap.md                   revise: cross-link the new non-interactive verbs
    set-by-precedence.md             rewrite of set-by-precedence.md — from provenance.py's SET_BY_PRIORITY, not from any existing doc
    sample-corpus.md                 keep (current)
  reference/cli-verb-drift-check.md  new — a lint doc/script proposal: assert _REGISTRY keys ⊆ cli-cheatsheet.md command list, closing PLAN.md's long-open §AA GAP
```

`_fixtures/` and `scripts/verify_tutorial.py` are infrastructure, not docs —
keep the mechanism as-is; the one code fix worth making alongside the rewrite
is `TMP = Path("/tmp/tutorial-fixtures")` → `$TMPDIR`-based, for consistency
with CLAUDE.md.

## Ground truth established

- **Actual CLI subcommand list (40 commands)**, from
  `python/glaurung/cli/main.py`'s `_REGISTRY` and confirmed verbatim in
  `docs/tutorial/_fixtures/01-install/help-head.out`: `triage, strings,
  symbols, disasm, cfg, ask, decompile, explain, name-func, repl, graph,
  detect-packer, diff, kickoff, patch, verify-recovery, export, undo, redo,
  xrefs, frame, strings-xrefs, view, find, bookmark, rename, comment, label,
  proto, journal, classfile, java, java-recovery-report, luac, pe,
  windows-risk, types, windows, locks, group`. (A stale code comment at
  `main.py:16` still says "importing all 35 eagerly" — also wrong, out of
  scope to fix here but worth flagging.)
- **`reference/cli-cheatsheet.md` documents 36 of these 40** — missing
  `rename`, `comment`, `label`, `proto`.
- **The real `set_by` provenance ranking** (`python/glaurung/llm/kb/provenance.py:59-102`):
  `manual(100) > {dwarf, pdb, gopclntab}(80) > stdlib(60) > {flirt, cil}(50)
  > ported(40) > propagated(30) > {auto, analyzer, borrowed}(20, and any
  unrecognized string)`. Equal rank is last-writer-wins
  (`outranks()` uses `>=`). No existing doc in `docs/tutorial/` (or
  `CLAUDE.md`) states this correctly.
- **Fixture-directory-to-recipe mapping is exact 1:1** — 24 `_fixtures/`
  directories, 24 `CHAPTERS` entries in `verify_tutorial.py`, 157 total
  `.out` files. Tier 5's `chat-driven-triage.md` and `one-shot-kickoff.md`
  are backed by string-assertion checks in `test_verify_tutorial.py`, not
  execution-based fixture diffing (only `evidence-and-citations.md`'s
  `kickoff`/SQL steps are, via the shared `05-kickoff-anatomy` fixture
  directory) — deliberate, since `ask` makes live, billable LLM calls.
- **`disasm --function` requires `--db` to take effect**
  (`python/glaurung/cli/commands/disasm.py:172-174`); without `--db` it is
  silently ignored and the command falls back to entry-point (or `--addr`)
  disassembly. `03-walkthroughs/05-vulnerable-parser.md` has exactly this
  bug in its `--function parse_record` example.
- **`rename`/`comment`/`label`/`proto` became non-interactive CLI commands
  on 2026-08-28** (`881e01ba`), living in `python/glaurung/cli/commands/annotate.py`.
  Shapes: `glaurung rename <db> <VA|name> <new-name> [--binary] [--by]`,
  `glaurung comment <db> <VA|name> [text...] [--binary] [--by]`,
  `glaurung label <db> <VA> [name] [--type] [--size] [--delete] [--binary]
  [--by]`, `glaurung proto <db> <name> ...`. `--by` exists so automation
  doesn't mislabel its writes as `manual` and outrank real analyst edits.
