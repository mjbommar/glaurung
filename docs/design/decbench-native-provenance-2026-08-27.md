# DecBench native line/variable provenance — the audit, and what answering it costs

**Date:** 2026-08-27
**Status:** evidence and options. Nothing here is a work queue; see
[`decompiler-roadmap.md`](decompiler-roadmap.md) if any of it is adopted.

**Pinned refs**

| thing | ref |
|---|---|
| Glaurung HEAD at analysis time | `5e16879802d4f1594bf9e8c8286ae420cf3ae869` |
| Glaurung revision DecBench audited | `fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4` (2026-08-13; 242 commits behind HEAD) |
| DecBench `main` | `429b07554a` (2026-08-26) |
| DecBench PR [#48](https://github.com/Noelo-Lab/decbench/pull/48) branch head (`experiment/local-variable-edit-distance`) | `d59567c2b90215087113ac52b34898ba4448594c` |
| Kuna PR [#310](https://github.com/Noelo-Lab/kuna/pull/310) (the reference producer implementation) | merged `ef520f84557ca2bd73a333c4bc1f29ba87769370` |

Throughout, `LVED:` marks a path as it exists on the PR #48 branch and `MAIN:`
as it exists on DecBench `main`. The distinction is load-bearing — see §1.

---

## 0. The question this answers

The document under review is `docs/decompilers.md` at `d59567c2b9`, and
specifically its section **"Glaurung and Manifold: final-AST lineage blockers"**
(lines 327–400 at that commit). It is an audit of Glaurung's IR written by the
DecBench maintainers — not by us — which states that our AST discards
machine-instruction lineage, and prescribes a four-step fix plus a JSON schema
extension for us to adopt.

Two questions were asked: how much of that document is ours, and whether and how
we could address what it asks for.

---

## 1. Where the audit lives, and who wrote the file

### 1a. The audit is on an unmerged draft branch

`docs/decompilers.md` on DecBench **`main`** is 763 lines and contains **only our
two operational blocks** (the `raw/glaurung_raw.py` bullet at `:33-38`, and the
"Glaurung follows the same explicit-build contract" section at `:334-353`).

The 1,015-line version — the one carrying the entire native-provenance
apparatus, the `Glaurung and Manifold: final-AST lineage blockers` section, and
the prescribed JSON schema — exists **only** at `d59567c2b9`, which is the head
of PR #48. That PR is **still a draft**, opened 2026-07-27, last updated
2026-08-25, and gated behind other backends' replays. Its own body says the full
rescore is in progress and "not candidates for canonical promotion".

**Consequence:** none of this is currently a published requirement. There is no
open issue asking us for anything (`gh issue list --search glaurung` returns only
an unrelated Fission submission).

### 1b. Authorship of the file

`git blame -w`, surviving non-blank lines:

| | on `main` (763 lines, 635 non-blank) | on PR #48 (1,015 lines, 868 non-blank) |
|---|---:|---:|
| Zion Basque / `mahaloz` (same person, two identities) | 606 (95.4%) | 841 (96.9%) |
| **Michael Bommarito (us)** | **22 (3.5%)** | **21 (2.4%)** |
| Chang Liu (manifold backend) | 7 | 6 |

Our entire contribution is PR [#56](https://github.com/Noelo-Lab/decbench/pull/56)
(`08f891581e`), which added 26 lines; 24 survive verbatim. Two of our sentences
were later extended by them (`f5f81bd3` added the "the *published* `glaurung`
column … is an external submission" clarification; `b8157659` added the container
UID/GID paragraph).

The single largest chunk of the file is `c2c942315b`, *"docs: improve AGENTS.md,
fixup the README, condense the docs (#49)"* — **552 non-blank lines, 64% of the
PR-#48 version** — carrying `Co-authored-by: Claude Fable 5`. Two further commits
carry `Co-Authored-By: Claude Opus 5 (1M context)` with `Claude-Session:` links,
and `325046f` carries both `Claude Opus 5` and `mahaloz <claude@ekahi.simplelogin.com>`.
The ~30 remaining `mahaloz` commits carry no trailers, but sit alongside PRs the
repository itself titles `[AUTOMATED]`.

So: **we wrote the two "how to run the backend" blocks and nothing else.** Every
analytical statement about Glaurung in that document — including the claim about
`ins.va` and the schema they want us to emit — is theirs, and the document's
spine is a Claude-co-authored condensation pass.

---

## 2. The claims, verified against current master

Their audit was written against `fb4ee6ba` (2026-08-13). We are 242 commits past
it. Verified against `5e168798`:

| Claim | Verdict | Evidence |
|---|---|---|
| "Glaurung stores a machine VA on `LlirInstr`" | **TRUE** | `src/ir/types.rs:508-516` — `pub struct LlirInstr { pub va: u64, pub op: Op }` |
| "`ir/ast.rs::lower_block` calls `lower_op(&ins.op, ...)` and drops `ins.va`" | **TRUE**, file has moved | `src/ir/ast/lower_conds.rs:280-286`. `lower_op` is `src/ir/ast/lower_ops.rs:598`, taking `&Op` — the VA is not merely unused, it is **not in scope**. `:283` is the single discard point in product code. |
| "Its `Expr` and `Stmt` nodes have no origin field" | **TRUE** | `Expr` at `src/ir/ast.rs:204-357` (20 variants), `Stmt` at `:487-617` (20 variants). No `span`/`origin`/`id`/`source_va` on any variant. |
| "…after which expression reconstruction, copy propagation, DCE, condition folding, and the DecBench preparation passes rewrite the tree" | **TRUE, and understated** | 77 pass entry points matching `fn …(&mut Function)` across 37 files; `run_ast_passes` (`src/python_bindings/ir/pipeline.rs:83-289`) is 20 numbered steps, `prepare_for_decbench_with_output_and_protected_locals` (`src/ir/ast/prepare.rs:121-259`) is 19 more. ~41,000 LOC across the touched passes. |
| "The JSON command emits only `name`, `entry_va`, and `pseudocode`" | **TRUE** | Verified by running it — see §6. Emission sites: `python/glaurung/cli/commands/decompile.py:264-269` (`--vas`), `:284-289` (`--all`), `:367-374` (single). |

### Two refinements they did not state

1. **A coarse VA does survive to the output text.** `Stmt::Label(u64)` and
   `Stmt::Goto { target: u64 }` carry basic-block start VAs (assigned at
   `src/ir/ast/lower_region.rs:182, 384, 407, 547`) and render as `L_<va>:` /
   `goto L_<va>;` (`src/ir/ast/dec_render/stmt.rs:348-351`). This is
   block-granular, only appears when the structurer failed to produce structured
   control flow, and `label_prune::prune_unreferenced_labels`
   (`pipeline.rs:297`) deletes most of it. It is not usable as occurrence
   evidence, but it is not *nothing*, and their "no origin reaches the output"
   framing is slightly too absolute.
2. **`Function` keeps `entry_va`.** `src/ir/ast/lower_region.rs:745-749`. It is
   the only address that crosses the lowering boundary intact, and it is what
   `entry_va` in the JSON already reports.

---

## 3. The contract, precisely

### 3a. What they want emitted

`LVED:docs/decompilers.md:378-400`, additive on our existing per-function record:

```json
{
  "name": "target",
  "entry_va": 4198400,
  "size": 64,
  "pseudocode": "long target(long arg0) { ... }",
  "line_mappings": [ {"line_number": 2, "addresses": [4198404]} ],
  "variables": [
    {"variable_id": "v3", "name": "count", "type": "long", "kind": "stack",
     "arg_index": null, "stack_offset": null,
     "line_numbers": [2], "addresses": [4198404]}
  ]
}
```

`variable_id` is **producer-side only** — it appears nowhere in DecBench's models
and is never consumed. It is a requirement that *we* maintain a stable identity,
not a field they read.

### 3b. Their four-step design

From `LVED:docs/decompilers.md:361-374`, paraphrased:

1. Seed every lowered statement/expression with its set of real machine
   instruction VAs; give every variable a stable identity independent of its
   printed name.
2. Preserve identities and origin sets through every rewrite. Move/clone
   preserves origin; combining unions proven origins; deletion drops them;
   coalescing creates one identity with the union. Synthetic or ambiguous nodes
   get no mapping.
3. During the *same* render that produces the measured C, record the 1-based
   output line for each proven statement and variable occurrence. **Never
   recover occurrences afterward by matching identifier text.**
4. Emit only instruction starts inside the function, normalized to linked ELF/PE
   space. Invalid, out-of-range, duplicate-identity, or stale-render evidence is
   omitted rather than repaired.

### 3c. What is actually validated

Three layers, all on the PR #48 branch.

**Producer-side sanitizer** — `LVED:decbench/decompilers/provenance.py`, schema
`decbench-native-provenance-sanitizer-v2`. Runs at
`LVED:decbench/pipeline/decompile.py:60-64`, `LVED:scripts/run_benchmark.py:563`
(against the **unstripped** original after DWARF relabeling),
`reeval_typematch.py:227`, `sanitize_native_checkpoints.py:120`.

`_filter_addresses` (`:130-168`) drops an address when it is:

| condition | drop reason |
|---|---|
| `bool`, non-`int`, or `< 0` | `not_exact_instruction_start` |
| not in `code.instruction_starts` (exact Capstone start inside the function's DWARF ranges) | `not_exact_instruction_start` |
| a duplicate after canonicalization | `duplicate` / `duplicate_after_normalization` |
| no `FunctionCode` resolvable | `no_address_provenance` / `binary_validation_unavailable` / `function_validation_unavailable` |

ARM Thumb: `addr & 1` is accepted **only** when the function is Thumb and
`addr & ~1` is a real start; it is then rewritten to `addr & ~1`.

Row-level rules (`_sanitize_function`, `:171-224`):

- a `LineMapping` whose `addresses` empties is **deleted** (`:189-192`);
- **variable `addresses` are filtered independently and survive with no line map
  at all** (`:202-212`) — this is the dewolf/Reko lane and the crux of §7 Route B;
- variable `line_numbers` are wiped entirely if no mapped row survived
  (`:213-214`);
- code and `VariableInfo` records themselves are never discarded, only their
  address/line evidence.

**Address resolution** — `LVED:decbench/utils/native_code.py`. Formats
`{elf, pe}`, architectures `{x86, x86-64, arm, aarch64}`. Hard-fails on
unrecognized format (`:193`), unsupported arch (`:195`), no readable DWARF
(`:198`), no DWARF match for `(name, addr)` (`:305`), ambiguous match (`:308`),
a DWARF range not wholly inside one file-backed executable region (`:174`), or an
entry that is not itself a decoded instruction start (`:322-323`). Capstone runs
with `skipdata=True` and only `instruction.id != 0` addresses count as starts
(`:178-182`). ARM state comes from an odd entry, an exact `.symtab` `STT_FUNC`
symbol, a unique name match, the M-profile attribute, or the PE machine type —
conflicting or missing evidence **raises** rather than defaulting to A32.

**There is no PIE/image-base normalization in the sanitizer.** Rebasing into
ELF-file space is entirely the backend's job
(`raw/common.py:96-122 elf_min_vaddr`, PE `_pe_image_base` `:61-93`).

**Independent auditor** — `LVED:decbench/auditing/native_provenance.py`
(`decbench-native-provenance-audit-v1`), driven by
`scripts/audit_native_provenance.py`. Read-only; exit 0 valid / 1 findings / 2
malformed. Finding codes: `malformed_decompiled_code`,
`malformed_provenance_fields`, `line_number_out_of_bounds`,
`duplicate_line_mapping`, `malformed_address_list`, `duplicate_address`,
`noninstruction_address`, `empty_line_mapping`, `malformed_line_number_list`,
`duplicate_variable_line`, `variable_lines_without_map`,
`variable_line_address_disagreement`. It tracks
`functions_with_direct_only_addresses` as a first-class statistic — again, the
no-line-map lane is explicitly supported.

### 3d. What consumes it

Only **`type_match`**. GED reads CFGs; `byte_match` recompiles the C. Neither
touches these fields.

`LVED:decbench/metrics/variable_match.py:371-696 match_variables`, default mode
`address+usage` (`auto` resolves to it, `type_match.py:938`):

1. **`"argument"`** (`:484-500`) — unique `arg_index` on both sides. Available to
   everyone today.
2. **`"stack"`** (`:502-560`) — calibrated `stack_offset` shift, 1:1 neighbour
   pair. Guard at `:554-559`: if both sides have addresses and they do **not**
   intersect, the stack pair is *rejected* — addresses can veto a bad offset match.
3. Edge scoring for the remainder (`:574-623`): both address+usage → `"fused"`
   (`0.5·address + 0.5·usage`, threshold 0.2); address only → `"address-only"`
   (threshold `min_overlap = 0.1`); neither → `"usage-fallback"` (threshold 0.15).
4. Mutual-best greedy acceptance with ambiguity margins (`:631-684`).
   `usage_ambiguity_margin` and `combined_ambiguity_margin` default to `0.0` with
   a `gap <= margin` test, so **any exact tie abstains**.

Address score is weighted Dice over shared instruction addresses (`:271-285`),
weighted `1 / max(source_degree, decompiled_degree)` (`:288-303`) so a
many-variable address is worth less.

**Two facts that determine our options:**

- With `mode != "usage"`, variables that DecBench *inferred* by parsing our C
  (because `FunctionDecompilation.variables` was empty) get their evidence
  **stripped**: `addresses=frozenset(), lines=(), live_ranges=()`
  (`variable_match.py:414-420`), and in address-only mode an inferred variable is
  dropped entirely unless it has an `arg_index` or a `stack_offset` (`:421-422`).
- `extract_decompiler_evidence` (`:1389-1393`) derives variable addresses from
  the line map when `VariableInfo.addresses` is empty. So `line_mappings` +
  named variables gives address evidence for free — **but direct
  `VariableInfo.addresses` is strictly stronger and bypasses the line map
  entirely.**

Evidence classification (`type_match.py:1160-1173`):
`native_stages = {argument, stack, overlap, address-only}`,
`fallback_stages = {usage, usage-fallback}`, and `"fused"` counts as **both** —
so any fused match forces `"mixed"`. Result is `None | "native" | "mixed" |
"fallback_only"`, recorded as `variable_match_evidence` and surfaced by
`LVED:decbench/rendering/assets/app.js:446-457` as a Type-score caveat tooltip.

`linemap_present` is derived, not stored: true iff at least one `LineMapping`
survives sanitization **with a non-empty `addresses` list**
(`type_match.py:1058-1063`).

`type_match`'s `cache_version` moves `"5"` → `"10"`, invalidating every cached
value.

---

## 4. What it is worth

From PR #48's own A/B tables, Glaurung's rows:

| Scope | Address | Usage | Stacked | Δ | Coverage |
|---|---:|---:|---:|---:|---:|
| Full corpus (86,671) | 5.124% | 3.820% | **6.905%** | +1.781 pp | 86,660 measured — **the best coverage of any backend** |
| Frozen sample (235) | 6.809% | 5.532% | **11.064%** | +4.255 pp | 235/235 |

### 4a. Read the two scopes separately — they disagree

**Frozen sample (235 functions), stacked exact counts.** Glaurung is first among
deterministic backends:

| backend | exact / 235 | % |
|---|---:|---:|
| **Glaurung** | **26** | **11.064%** |
| Binary Ninja 5.3 | 19 | 8.085% |
| IDA DecLib | 19 | 8.085% |
| angr | 18 | 7.660% |
| angr DecLib, Phoenix | 16 | 6.809% |
| Ghidra 10.4–12.1 (all five versions), IDA 9.2, Binary Ninja DecLib | 15 | 6.383% |
| Kuna, dewolf, Manifold, Ghidra DecLib | 14 | 5.957% |
| RetDec | 12 | 5.106% |
| r2dec | 4 | 1.884% |
| Reko | 0 | 0% |

(Codex 16.170% and Claude Code 11.489% are LLM rows, sample-only.)

**Full corpus (86,671 functions), stacked.** Glaurung is fifth of nine:

| backend | % | measured |
|---|---:|---:|
| Binary Ninja 5.3 | 9.227% | 76,295 |
| angr | 8.526% | 84,151 |
| Ghidra 12.1 | 7.794% | 80,005 |
| IDA 9.2 | 7.527% | 82,581 |
| **Glaurung** | **6.905%** | **86,660** |
| Kuna | 6.131% | 86,662 |
| Phoenix | 4.530% | 44,481 |
| r2dec | 1.884% | 60,274 |
| Reko | 0.264% | 22,419 |

**Do not report the sample row as "best deterministic decompiler."** Four things
qualify it:

1. **One metric.** This is `type_match` correspondence only. The leaderboard
   headline is a Union perfect-rate across GED, type, and byte; GED and
   `byte_match` are untouched by any of this work, and our own
   [`decbench-submission-readiness.md`](decbench-submission-readiness.md) records
   where we lose those (clang/O0 GED, O2 type recovery, no aggregate recovery).
2. **Small n.** 26 vs 19 out of 235. The full corpus, 369× larger, ranks us
   fifth — which is the figure to quote if only one is quoted.
3. **Unmerged and self-flagged.** PR #48 is a draft whose own body says these
   rows "are not candidates for canonical promotion until a fail-closed cache-v11
   replay" completes.
4. **Every row carries the `*`.** Including ours, and ours is
   `fallback_only` — the weakest evidence class in the table.

What *is* unambiguously ours to claim: **the highest measured coverage of any
backend**, 86,660/86,671 with 11 zero-filled misses, ahead of Kuna (9 misses but
86,662 measured), angr (2,520), IDA (4,090), Ghidra (6,666) and Binary Ninja
(10,376). We decompile essentially everything they ask for.

### 4a-bis. Scored, 2026-08-27: the mean-distance axis moved

Everything in §4 is read from the published board, whose `glaurung` column is
pinned at `git-fb4ee6b`. That is not the only thing available: the materialized
sample-set tree carries 221 pre-extracted source CFGs, so DecBench's own metric
code can score a fresh decompilation with **no Joern**. Procedure in
`docs/development/decompiler-testing.md`, "A real DecBench score, without Joern";
tool at `tools/decbench_redecompile_tree.py`.

Re-decompiled with `d8665dd` and scored against the same CFGs by the same metric
code, alongside the `24b3826` column stored in the tree from 2026-07-29:

| metric | `24b3826` | `d8665dd` | change |
|---|---|---|---|
| Union | 48/250 · 19.2% | **65/241 · 27.0%** | **+7.8 pp** |
| GED perfect | 47/239 · 19.7% | **64/231 · 27.7%** | **+8.0 pp** |
| **GED mean distance** | **41.55** | **28.98** | **-30%** |
| **GED median distance** | **14.0** | **10.0** | **-29%** |
| byte_match perfect | 2/250 · 0.8% | **10/241 · 4.1%** | **5x** |
| byte_match mean | 0.0423 | **0.2186** | **5.2x** |

**Read the mean, not the perfect count.** §4b below establishes that our
published profile is best perfect-count of any deterministic backend and *worst
mean GED distance of any real backend* — the signature of catastrophic rather
than incremental failure, and the axis no gate in this repository measures. Mean
fell 30% and median 29%. That is the first direct evidence that the axis is
movable and is moving.

Three qualifications, none of which touch the mean:

* `type_match` is absent — `evaluate-tree` cannot compute it from stored
  artifacts, which carry no recovered variables. This is 2 of 3 metrics.
* The denominator moved 250 -> 241 (nine functions had no resolvable symbol),
  so the perfect-count percentages are on a smaller base and are slightly
  flattered. Mean and median are unaffected.
* This is roughly a month of work, not one day's. Almost none of the ARM
  dispatch work of 2026-08-27 shows here, because the sample-set contains
  almost no ARM table dispatch — which is precisely the finding of
  `decbench-defect-reproductions-2026-08-27.md` §10a.

### 4b. The margin over the backends we lead — and why one of them is illusory

DecBench's headline uses a **fixed 86,671 denominator with zero-filled misses**,
so a backend that fails to produce output is penalised exactly like one that
produces wrong output. That is a defensible headline choice, but it makes the
margin over low-coverage backends partly a coverage margin, not an accuracy one.
Both framings, full corpus, stacked:

| backend | exact | fixed-denominator | measured | conditional on measured | our lead (exact) | pp | ratio |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Glaurung** | **5,985** | **6.905%** | 86,660 | **6.906%** | — | — | — |
| Kuna `ef520f` | 5,314 | 6.131% | 86,662 | 6.132% | +671 | +0.774 | 1.13× |
| Phoenix | 3,926 | 4.530% | 44,481 | **8.826%** | +2,059 | +2.376 | 1.52× |
| r2dec | 1,633 | 1.884% | 60,274 | 2.709% | +4,352 | +5.021 | 3.67× |
| Reko | 229 | 0.264% | 22,419 | 1.021% | +5,756 | +6.641 | 26.14× |

Frozen sample (235), stacked exact: Glaurung 26, Phoenix 16, Kuna 14, r2dec 4,
Reko 0.

Read those four separately:

- **Kuna is the only genuine peer here, and the comparison flatters us.** Its
  6.131% is measured at pinned merge commit `ef520f84`, i.e. **with** the native
  line/variable provenance of Kuna PR #310 already in place. We are 0.774 pp
  ahead of a provenance-bearing backend while running on fallback evidence only.
  That is the single most useful number in this table, and it is also the reason
  not to panic about the `*`.
- **Phoenix's margin is an artifact and reverses under the fair comparison.** It
  measures 44,481 of 86,671 functions (51%); conditional on what it does measure
  it scores **8.826% against our 6.906%**. It is also a **retired backend** —
  fully deprecated in PR #35 (merged 2026-07-23), deleted from the harness and
  hidden from the site — carried in PR #48 only as a control. It is not a
  competitor and should not be counted as one.
- **r2dec is a real 3.67× lead** that survives the adjustment (2.709% conditional),
  and it is the one backend where fusion actively *hurt*: zero exact gains and
  two losses versus address mode.
- **Reko's number is known-broken.** Its full control ran on an old image whose
  ARM/Thumb loader decodes stripped Cortex-M images as A32, so DecBench correctly
  refuses to bind the addresses and it measures 49 of 31,913 ARM functions —
  22,419 of 86,671 overall. An independently reviewed loader fix is pending a
  fresh all-803 run. Expect this gap to close substantially; even conditionally
  we are 6.8× ahead today, but that figure is measured against a crippled
  configuration.

All of the above is `type_match` only, from an unmerged draft PR whose own body
declines to promote these rows.

Their own commentary: *"Glaurung is the full-corpus fallback stress test … it
gains 1,544 exact matches, loses none, improves 20,459 partial functions, and
regresses zero … Every row is starred because all 86,660 measured functions lack
native variable provenance."*

**What native provenance would buy:** our address-mode figure (5.124%) is
generated almost entirely by ABI argument anchors parsed out of our C signature.
The backends that carry real occurrence evidence sit at 7.4–8.9% in the same
mode. A plausible target is +1 to +2.5 pp on address mode, plus removal of the
`*`.

**What it does not buy:** there is **no hard gate**. No score is withheld, and
`union_leaders` (`LVED:decbench/rendering/aggregate.py:72-105`) reads only the
Union perfect-rate pair and never looks at the evidence field. The `*` is a
tooltip, and right now *every* backend in the table carries one.

---

## 5. The structural catch: the eval kit cannot carry provenance

The published `glaurung` column is an **external sample-set submission** at
`git-fb4ee6b`, flagged `external_submission` in its metadata
(`LVED:docs/decompilers.md:53-56`; confirmed in `LVED:site/data/aggregates.json`).

The eval-kit submission format is **identical on `main` and on PR #48**, and it
is exhaustively:

```json
{"decompiler": {"name": "…", "version": "…"},
 "results": {"bin_000.c": {"binary": "bin_000.elf",
                           "functions": {"sub_1234": "0x1234"}}}}
```

`decbench/evalkit/templates.py:129-149`. There is **no slot** for
`line_mappings`, `variables`, `line_numbers`, types, or offsets. The ingest side
confirms it: `evalkit/ingest.py:403-409` constructs `FunctionDecompilation` with
`name`, `address`, `decompiled_code`, `line_count`, `metadata` — and never sets
`variables` or `line_mappings`.

**An external submission is structurally incapable of scoring `native` evidence.**
It will always be `fallback_only` with `linemap_present=false` and
`decompiler_address_variables=0`.

Therefore the *only* path that pays off is the in-tree `glaurung_raw.py`
backend — which they **do** run: PR #48's Glaurung rows are a full-corpus
in-tree-backend run (86,660 functions). That adapter is sitting ready:

```python
# LVED:decbench/decompilers/raw/glaurung_raw.py:549-564
return FunctionDecompilation(
    name=name, address=file_addr,
    decompiled_code=code, line_count=code.count("\n") + 1,
    line_mappings=[],        # :561
    variables=[],            # :562
    metadata=common.extract_metrics(code),
)
```

with a module docstring (`:35-42`) naming the blocker and pointing at
`docs/decompilers.md` for "the producer-side contract needed to unlock native
evidence."

Its pinned revision is `_DEFAULT_REF = "fb4ee6ba…"` (`glaurung_raw.py:86`,
`docker/glaurung.Dockerfile:33-34`) — i.e. **any producer change requires them to
bump the ref and re-run**, because "a reeval can only use what the checkpoint
recorded" (`LVED:docs/benchmarking.md`).

---

## 6. Where our value actually is — measured

The CLI DecBench calls, verified on `5e168798` with a fresh build
(`tools/build_guard.py` → `fresh`):

```
glaurung decompile <binary> --vas 0x…,0x… --style decbench --format json --timeout-ms N
→ [ {"name": …, "entry_va": …, "pseudocode": …} ]     # exactly three keys
```

**Local-variable census.** 40 binaries from the frozen DecBench sample-set kit
(`~/projects/personal/decbench-evalkit-sample-set`), 49 functions recovered,
declared body locals classified by name:

| class | count | share |
|---|---:|---:|
| register-derived `varN` | 1,272 | **84.7%** |
| stack slot `local_*` / `stack_*` | 168 | 11.2% |
| temp `tN` | 19 | 1.3% |
| return reg `ret` | 16 | 1.1% |
| raw regs / flags (`rbp`, `rsp`, `df_1`, …) | 14 | 0.9% |
| **total** | **1,502** | |

Separately, 120 signature parameters across those 49 functions — those already
reach DecBench through its C-signature parse and already feed the `"argument"`
stage.

**This is the number that drives the plan.** The stack-slot path — where our
existing machinery is closest to ready — covers roughly **one eighth** of our
locals. The register path carries **85%** of the available credit.

> Measurement note: the first pass of this census reported 1,804 locals and a
> "18.3% other" bucket. The regex was matching `goto L_4011a0;` as
> `<type> <name>;`. This is the identical trap fixed in our own HEAD commit
> `5e168798` ("extbench: every `goto` was counted as a declaration, and 31% of
> the figure was that"). Corrected figures are the ones above.

---

## 7. Four routes, costed

### Route A — build what they prescribed (origin-carrying AST). Not recommended.

Their step 1–2 wants an origin set on every node, preserved through every
rewrite. Measured blast radius on `src/`:

| metric | `Expr` | `Stmt` |
|---|---:|---:|
| total `X::` occurrences | 7,213 | 5,701 |
| files mentioning it | 110 | 88 |
| likely construction sites (struct variants) | 2,449 | 3,639 |
| tuple-variant constructors (no `..` escape) | 3,755 | 461 |
| struct patterns binding fields with **no** `..` (hard compile breaks) | — | **506** |

Heaviest files: `src/ir/ast.rs` (1,133), `call_args.rs` (929), `stack_locals.rs`
(760), `copy_prop.rs` (716), `loop_form.rs` (589), `const_fold.rs` (473).

And a trap: `src/ir/ast/prepare.rs:143-149` runs a bounded fixpoint whose
termination test is `if owned == before { break; }` — whole-`Function` structural
equality — with a second at `:216-219`. A naively added origin field changes that
loop's behaviour. Origin would have to be excluded from `Eq` by a custom impl.

Passes that a preservation rule must handle: **merging** (`vector_copy` 4→1,
`expr_reconstruct` inline-and-delete, `const_fold` subtree→literal, `call_args`
moves argument setup into `Stmt::Call.args`), **splitting**
(`call_result_split`, `value_split`), **deleting** (`dce`, `dead_stores`,
`label_prune`, `recognise_machine_frame`), **renaming in place** (`naming`), and
**duplicating** (`label_prune::inline_terminal_goto_tails`, `prepare.rs:214`,
the one pass that makes origin one-to-many in the output direction).

This is a multi-month rewrite of the pass layer for a tooltip.

### Route B — direct variable addresses, no line map. **Recommended as the real target.**

Their own sanitizer supports it (`provenance.py:202-212`), their auditor counts
it (`functions_with_direct_only_addresses`), and dewolf and Reko ship exactly
this shape: direct `VariableInfo.addresses`, no `line_mappings`, because neither
renderer exposes a stable token-to-line map.

Crucially, this needs **no changes to `Expr`/`Stmt`**, because the identity chain
already exists as *name lineage* rather than node lineage:

- **Stack locals.** `StackLocalFacts.frame_coordinates: HashMap<String,(String,i64)>`
  (`src/ir/stack_locals.rs:151-171`) already maps each promoted local name to its
  `(base, disp)` frame coordinate — and its doc comment states it already
  **withholds** any name reachable from two coordinates. That is precisely
  DecBench's fail-closed rule, already implemented, for exactly the right reason
  (`rbp-0x18` and `entry_rsp-0x18` are different storage). `sizes`,
  `source_types`, and `source_names` are in the same struct.
- **The name reaches the C verbatim.** `src/ir/naming.rs:160-163` deliberately
  does **not** rewrite `local_*` / `stack_*` to `varN` ("Names already allocated
  by the stack-slot promotion pass … are meaningful"), and `parse_arg_index`
  names are likewise preserved (`:169-171`).
- **Register locals have a rename map.** `apply_role_names_with_parameter_roles`
  **returns** `HashMap<String,String>` (old → `varN`), already threaded out of
  `run_ast_passes` (`src/python_bindings/ir/pipeline.rs:96-100`, bound as
  `role_names` at `:275`).
- **LLIR has the addresses.** `InstrAddr { block_idx, instr_idx }`
  (`src/ir/use_def.rs:66-69`) indexes straight into
  `LlirFunction.blocks[b].instrs[i].va`.

The work is therefore a **name-lineage tracker**: seed a `variable_id → {VAs}`
table from LLIR use-def at lowering, and maintain it across the handful of passes
that mint, split, merge, or rename names — `stack_locals`, `naming`,
`value_split`, `call_result_split`, `copy_prop`, `expr_reconstruct` — abstaining
wherever lineage is not 1:1. That is a bounded audit of six passes, not a rewrite
of forty-one thousand lines.

This is **not** the "match identifier text afterwards" approach their step 3
forbids: it tracks a recorded rename map and a recorded storage coordinate, both
of which are real identity, not spelling.

**Open risk to resolve before committing:** whether every pass that mutates a
`VReg` name routes through a recorded map. Any that does not is a silent break in
the chain and must either be fixed or made to abstain. This audit is the first
task, and it is cheap.

### Route C — structured `variables[]` with no addresses. **Do this first, regardless.**

Today DecBench regex-parses our C to invent variables, and under PR #48 those
inferred variables have their evidence stripped (`variable_match.py:414-420`) and
are dropped entirely in address-only mode unless they carry an `arg_index` or a
`stack_offset` (`:421-422`).

Emitting `name` / `type` / `kind` / `arg_index` / `stack_offset` / `size` — from
data we already compute (`StackLocalFacts`, the `DeclarationPlan` at
`src/ir/ast/declaration_plan.rs`) — properly unlocks the `"argument"` and
`"stack"` stages instead of leaving them to a text parse. Also add `size` to the
function record: the Kuna-shaped adapter uses it to clamp evidence addresses to
`[entry_va, entry_va + size)`.

Strictly additive, self-contained, days not weeks.

### Route D — line maps. Defer.

The renderer half is genuinely cheap. `LVED`-required "same render that produced
the measured C" is satisfied by construction: `decbench_render.rs:673-675` is a
single loop into a single `String` via one recursive
`write_stmt_dec` (`src/ir/ast/dec_render/stmt.rs:138`), so a 1-based line number
per statement is a newline count sampled at entry — roughly 20–40 lines, plus a
`DEC_LINE_MAP` thread-local alongside the eight already installed and cleared at
`decbench_render.rs:686-693`.

But statement → **address** still requires Route A's plumbing. And since direct
variable addresses bypass line maps entirely, Route D adds nothing until B lands.

---

## 8. Recommendation

1. **Route C now.** Structured `variables[]` plus `size` in the per-function
   JSON. Additive, no behaviour change to the emitted C, no baseline movement
   expected. Verify against `tests/decompiler_fixtures/`; this touches the JSON
   surface only, so the four baselines should be untouched — confirm rather than
   assume.
2. **Audit the six name-mutating passes** for unrecorded `VReg` renames. Cheap,
   and it decides whether Route B is a two-week or a two-month job.
3. **Route B as a scoped project**, with the **register path as the primary
   target**. A stack-only implementation delivers ~1/8 of the value (§6) and
   would be easy to mistake for completion.
4. **Skip Route D** until B lands, and **skip Route A** entirely. Their
   prescribed design assumes a Ghidra-shaped decompiler whose printer already
   holds IR handles. Kuna's producer PR was only +689/−40 across 13 files
   precisely because its `Atom` tokens already carried `op_key(op)`; the change
   was adding `vn_key(vn)` beside it. We have no equivalent, and manufacturing
   one is the whole cost.
5. **Do not treat this as urgent.** PR #48 has been an open draft for a month, no
   issue asks us for anything, and no published score is gated on it.

Two PRs and a re-run are required for any of this to show up: a producer change
here, an adapter change in `glaurung_raw.py:549-564` (a near-verbatim copy of
`LVED:kuna_raw.py:298-396`), and a full-corpus re-run by them with
`_DEFAULT_REF` bumped. Kuna is the precedent: producer PR upstream, then
re-benchmark at the pinned merge commit.

---

## 9. Risks and traps

- **Every address must be an exact Capstone instruction start inside the
  function's DWARF ranges**, in ELF-file space, Thumb-normalized. Anything else
  is silently dropped by the sanitizer and loudly flagged `noninstruction_address`
  by the auditor. Our own emission must therefore be conservative: abstain, never
  approximate.
- **`line_number` is 1-based within `FunctionDecompilation.decompiled_code`**,
  not within any aggregate `.c`, and text and mappings must come from the *same*
  render pass.
- **`type_match` is type-blind, so provenance exposes our types.** Matching more
  variables converts misses into matches that are then graded. Our O2 type
  recovery is 0.404–0.523. Their data has a real counterexample: RetDec's fusion
  *lost* an exact function (−0.426 pp). Our empirical record is favourable
  (+1,544 exact, −0 on full corpus) but that was the fallback path, not this
  change.
- **The PyO3 boundary is tuple-shaped.** `decompile_many` / `decompile_all`
  return `(name, entry_va, pseudocode)` triples
  (`src/python_bindings/ir.rs:868-885`, `:1104-1119`, declared in
  `python/glaurung/ir.pyi:21-24`). Extending it is a breaking signature change
  across four functions plus the three dict literals in `decompile.py`; prefer
  returning a dict/struct over a widening tuple.
- **Any binding change requires `uv run python tools/gen_native_stub.py`** and
  `cargo test --features python-ext` — a plain `cargo test` does not compile
  `src/python_bindings/` at all.
- **Fixture binaries embed their build path**, so any census like §6 must be run
  in the main checkout, not a worktree.

---

## 10. Roadmap calibration — read the published board, not the experiment

Everything above §9 is about `type_match` correspondence in an unmerged draft.
For calibrating the roadmap, the **published** board is the better input. Source:
`decbench/site/data/aggregates.json` at DecBench `main` `429b07554a`,
`generated_at 2026-08-19`, our column pinned at `git-fb4ee6b` — **242 commits
behind our HEAD**. Denominator rules are `docs/site.md` §"Denominator semantics":
`overall` is **Union** (perfect on ≥1 measurable metric), a measurable function a
decompiler failed on stays in its denominator as a miss, and `normalize=1`
restricts to functions **every rendered decompiler** decompiled.

### 10a. We are the leading deterministic decompiler on the published board

Sample-set preset, normalize off (the default view), 250 functions / 224 binaries:

| decompiler | Union | GED | Type | Byte |
|---|---:|---:|---:|---:|
| codex *(LLM)* | 143/250 57.2% | 130/246 52.8% | 29/235 12.3% | 32/238 13.4% |
| claude-code *(LLM)* | 141/250 56.4% | 134/246 54.5% | 23/235 9.8% | 19/238 8.0% |
| **glaurung** | **82/250 32.8%** | **69/246 28.0%** | **22/235 9.4%** | **5/238 2.1%** |
| ida | 73/250 29.2% | 65/246 26.4% | 11/235 4.7% | 2/238 0.8% |
| angr | 72/250 28.8% | 60/246 24.4% | 15/235 6.4% | 1/238 0.4% |
| kuna | 71/250 28.4% | 64/246 26.0% | 12/235 5.1% | 4/238 1.7% |
| binja | 64/250 25.6% | 54/246 22.0% | 19/235 8.1% | 0/238 0.0% |
| ghidra | 58/250 23.2% | 51/246 20.7% | 12/235 5.1% | 0/238 0.0% |
| fission | 56/250 22.4% | 51/246 20.7% | 9/235 3.8% | 2/238 0.8% |
| r2dec | 45/250 18.0% | 45/246 18.3% | 1/235 0.4% | 0/238 0.0% |
| manifold | 22/250 8.8% | 21/246 8.5% | 2/235 0.9% | 5/238 2.1% |
| dewolf | 13/250 5.2% | 13/246 5.3% | 0/235 0.0% | 0/238 0.0% |

**First among deterministic backends on Union and on all three metrics
individually**, +9 functions over IDA and +10 over angr. Also `errors` =
`[0, 250]` — the only deterministic backend with zero failures over 250 attempts
(angr 30, binja 29, dewolf 74, r2dec 46, ghidra 16, ida 16, kuna 15).

On the normalize=1 slice (91 functions every rendered decompiler handled) we are
still first deterministic at 24/91 (26.4%) against angr 19, ida 19, binja 18,
kuna 15, ghidra 11.

### 10b. The profile is bimodal, and it is not a coverage artifact

Perfect counts are only half the picture. From the same payload's `distance`
block (`at0` = perfect count, median/mean = edit distance, lower better), on the
**normalized 91-function slice** — so coverage differences cannot explain it:

| metric | our `at0` | rank | our median | field median | our mean | field mean |
|---|---:|---|---:|---|---:|---|
| GED | **17** | tied 1st deterministic (ida 17, angr 15, kuna 14, binja 14, ghidra 9) | **15.0** | angr/ida/kuna 13, binja/ghidra 15 | **36.68** | **worst of any real backend** (kuna 29.5, angr 31.0, ghidra 31.9, ida 32.3, binja 32.5) |
| Type | **11** | **1st of ALL rows, LLMs included** (codex 9, claude 8, binja 7, angr 6, ghidra/ida 5, kuna 3) | 7.0 | angr/binja 5, codex/ghidra/ida 6 | 10.94 | mid-pack |
| Byte | 2 | mid | **106.0** | **worst of all** (angr 49, ida 64, kuna 70, fission 72, ghidra 81) | **348.84** | worst but manifold |

**Glaurung is simultaneously the most likely to be exactly right and the most
likely to be badly wrong.** That is the signature of catastrophic, not
incremental, failure — and it maps exactly onto the three defects the roadmap
already names:

- `detect_if_shape` tries shapes in fixed order against a `visited` set, so once
  a ladder arm returns, the immediate post-dominator is the function exit and the
  loop body ends at the first case — the rest is **stranded**
  (`statemachine` gcc/O0: GED 36 vs angr 25). The roadmap's own conclusion, "the
  answer is a region analysis, not a third predicate", is correct.
- `discover_jump_tables` does not recognise clang's 4-byte **relative** form, so
  thirty instructions of a state machine **never enter the CFG at all**.
- `Op::Unknown { mnemonic }` and `Op::opaque` **declare no register write**, so
  an unmodelled instruction is invisible to dataflow and a stale value flows on
  (`SILENT_REGISTER_WRITERS`: 28 mnemonics / 1,130 occurrences, down from
  35 / 1,372).

Each of those produces one catastrophically wrong function, not many slightly
wrong ones. The mean-distance column is where they show up, and nothing in our
gate currently measures it.

### 10c. What this implies for the plan

1. **The current queue is aimed at the right metric.** `byte_match` is our one
   genuine quality deficit — median 106 against a 49–81 field — and it is *not* a
   compilability problem: our Compiles rate is 158/158 (100%), the top of that
   table. We emit C that always builds and still lands furthest from the original
   bytes. That is exact semantics — widths, constants, flags, ABI — which is
   precisely what the open items (imul CF/OF poison, `direct_output::RETURN_REGS`,
   float↔bits reinterpretation, `SILENT_REGISTER_WRITERS`) attack. **Validation,
   not redirection.**
2. **The success criterion is mis-specified.** The fixture ratchet counts cells
   `fail -> pass` and the def-use census counts violations; both are
   perfect-count-shaped. Neither can see "how wrong when wrong", which is the
   axis we are worst on and the axis a human analyst actually experiences.
   **Consider adding a distance gate** — median and mean GED/byte distance over a
   fixed corpus, ratcheted like the rest — or we will keep optimising the metric
   that already flatters us.
3. **Rank the provenance work (§7) LOW.** It moves `type_match` correspondence:
   the metric where we are already first *including the LLMs* (11/85 perfect on
   the normalized slice), in an unmerged experiment, with no hard gate. Take
   Route C (days, additive) and leave Route B behind the structuring work.
4. **The cheapest high-ROI action is not engineering — it is a resubmission.**
   The published column is `git-fb4ee6b` (2026-08-13). Since then: the imul CF/OF
   poison fix (6 cells), `abi::result_register_candidates` returning `None` for
   AArch64, the `movlpd`/`movhpd`/`movlps`/`movhps` family, `RETURN_REGS` missing
   `xmm0`, float→bits reinterpretation (26 cells), the C++ landing-pad CFG fix
   (2,080 undefined reads), the 10 MB truncation, the MSVC prologue rule. A rerun
   plus a submission costs no engineering and is very likely to move the row.
5. **We are `sample_set_only`.** The full-corpus presets carry us at 49/34,312,
   18/34,465, 15/25,490 and 0/1,987 — artifacts of scoring a sample-only
   submission against a full denominator, which is why those rows are hidden. Yet
   PR #48's in-tree run shows we already handle the full corpus with the best
   coverage of any backend (86,660/86,671). **Converting to a full-corpus entry is
   an infrastructure task, not a decompiler-quality one**, and it is the single
   largest change available to our published standing.
6. **Do not calibrate against the LLM rows.** They lead on every metric
   (normalized GED median 3.0/4.0 against our 15.0), but DecBench's own sample-set
   description warns that "results from LLMs can be biased since this dataset is
   open-source and some LLMs have shown capability for perfect recall on
   assembly-only samples", and issue
   [#43 "Potential LLM Bias"](https://github.com/Noelo-Lab/decbench/issues/43) is
   open. The published `compile` table also lists codex at `0/155` and
   claude-code at `0/154` while both post the highest `byte_match` — a
   contradiction under `docs/site.md`'s stated definition of that column that this
   analysis could not reconcile. Treat the deterministic field as our comparison
   set.

### 10d. One number to carry

If a single figure has to represent our standing: **82/250 Union on the published
sample-set, first among deterministic decompilers, at a revision 242 commits
old** — paired with the honest qualifier that our mean GED distance (36.68
normalized) is the worst of any real backend on the board.

---

## Appendix A — Glaurung file:line index (at `5e168798`)

| what | where |
|---|---|
| `LlirInstr { va, op }` | `src/ir/types.rs:508-516` |
| `LlirBlock { start_va, end_va, succs }` | `src/ir/types.rs:520-527` |
| `VReg` variants | `src/ir/types.rs:107-121` |
| `is_promoted_local_name` (prefix test) | `src/ir/types.rs:126-133` |
| `InstrAddr { block_idx, instr_idx }` | `src/ir/use_def.rs:66-69` |
| SSA versioning (`reg#version` into the name) | `src/ir/value_number.rs:1-21` |
| **the discard point** — `lower_block` | `src/ir/ast/lower_conds.rs:280-286` |
| `lower_op(&Op, bool)` | `src/ir/ast/lower_ops.rs:598` |
| `Function { name, entry_va, body }` construction | `src/ir/ast/lower_region.rs:745-749` |
| block-start VAs for labels/gotos | `src/ir/ast/lower_region.rs:182, 384, 407, 547` |
| `Expr` (20 variants) | `src/ir/ast.rs:204-357` |
| `Stmt` (20 variants) | `src/ir/ast.rs:487-617` |
| `run_ast_passes` (20 steps) | `src/python_bindings/ir/pipeline.rs:83-289` |
| role rename map returned | `src/python_bindings/ir/pipeline.rs:96-100`, `:275` |
| `prepare_for_decbench…` (19 steps) | `src/ir/ast/prepare.rs:121-259` |
| the `PartialEq` fixpoints | `src/ir/ast/prepare.rs:143-149`, `:216-219` |
| `StackLocalFacts.frame_coordinates` | `src/ir/stack_locals.rs:151-171` |
| naming pass; promoted locals **not** renamed | `src/ir/naming.rs:150-185` |
| `apply_authoritative_local_names` | `src/ir/naming.rs:196` |
| render entry / body loop | `src/ir/ast/decbench_render.rs:673-675` |
| `write_stmt_dec` | `src/ir/ast/dec_render/stmt.rs:138` |
| render-scoped thread-locals (cleared) | `src/ir/ast/decbench_render.rs:686-693` |
| `L_<va>:` emission | `src/ir/ast/dec_render/stmt.rs:348-351` |
| function header comment | `src/ir/ast/decbench_render.rs:289` |
| JSON emission (3 sites) | `python/glaurung/cli/commands/decompile.py:264-269, 284-289, 367-374` |
| native `decompile_many` / `decompile_all` | `src/python_bindings/ir.rs:1104-1119`, `:868-885` |

**Free side benefit if Route D ever happens:**
`python/glaurung/cli/commands/view.py:89-92` documents that the pseudocode pane
"highlights any line whose leading address matches the target"; the
implementation at `:154-155` is `lines = text.splitlines(); return lines[:max_lines]`.
There is no address on any pseudocode line to match. That docstring is currently
false and a line map would make it true.

## Appendix B — DecBench file:line index

`MAIN:` = `429b07554a`; `LVED:` = `d59567c2b9` (PR #48).

| what | where |
|---|---|
| `LineMapping`, `VariableInfo`, `FunctionDecompilation` | `MAIN:decbench/models/decompilation.py:11-75` |
| `VariableInfo.line_numbers` / `.addresses` (added) | `LVED:decbench/models/decompilation.py:41-48` |
| `VARIABLE_MATCH_EVIDENCE`, `FunctionRecord.metric_evidence` | `LVED:decbench/models/function_data.py:15, :30-34` |
| sanitizer | `LVED:decbench/decompilers/provenance.py:130-168, :171-224` |
| instruction-start resolution / ARM state | `LVED:decbench/utils/native_code.py:143-183, :252-281, :301-332` |
| auditor findings | `LVED:decbench/auditing/native_provenance.py:668-863` |
| `match_variables` stages | `LVED:decbench/metrics/variable_match.py:371-696` |
| inferred-variable evidence stripping | `LVED:decbench/metrics/variable_match.py:414-422` |
| line-map → variable-address derivation | `LVED:decbench/metrics/variable_match.py:1382-1393` |
| `linemap_present` derivation | `LVED:decbench/metrics/type_match.py:1058-1063` |
| evidence classification | `LVED:decbench/metrics/type_match.py:1160-1173` |
| site caveat rendering | `LVED:decbench/rendering/assets/app.js:446-457` |
| **the reference producer adapter** | `LVED:decbench/decompilers/raw/kuna_raw.py:298-396` |
| our adapter, both fields empty | `LVED:decbench/decompilers/raw/glaurung_raw.py:549-564` |
| pinned Glaurung ref | `LVED:decbench/decompilers/raw/glaurung_raw.py:86`, `LVED:docker/glaurung.Dockerfile:33-34` |
| eval-kit submission schema (no provenance slot) | `decbench/evalkit/templates.py:129-149` |
| eval-kit ingest (never sets the fields) | `decbench/evalkit/ingest.py:403-409` |
| the audit of us | `LVED:docs/decompilers.md:327-400` |

## Appendix C — how §6 was measured

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
tools/build_guard.py            # must print "fresh"
# for each of the first 40 binaries in the frozen sample-set kit:
glaurung decompile <kit>/binaries/<bin> \
  --vas <comma-separated hex targets from functions.json -> public> \
  --style decbench --format json --timeout-ms 15000
```

Declared body locals were counted with a `<type> <name>;` regex anchored to
indented lines, **excluding lines beginning `goto`/`extern`/`return`/
`break`/`continue`** — without that exclusion `goto L_4011a0;` parses as a
declaration and inflates the count by 20% (see the note in §6). 40/40 binaries
succeeded, 0 failures, 49 functions.
