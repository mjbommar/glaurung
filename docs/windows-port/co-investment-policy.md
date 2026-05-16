# Co-investment policy (mirrors asb ADR 0023)

> How the `agentic-security-bot` (asb) windows-port campaign and
> Glaurung collaborate. This doc mirrors asb's ADR 0023; if the
> two ever drift, asb's ADR is the source of truth and we update
> here.

asb ADR 0023 lives at
`/nas4/data/workspace-infosec/agentic-security-bot/projects/windows-port/workstreams/01-decisions-and-wiring.md`
sec "ADR 0023 -- Glaurung co-investment relationship".

## Context

asb chose Glaurung as its static-analysis substrate for Windows
binaries (asb ADR 0021). That choice implies sustained working
contact: feature work flows from asb campaign needs into
Glaurung upstream PRs; bench results flow back. The contract
below is what keeps both sides honest.

## Decisions

### 1. No vendoring

Glaurung stays at `/nas4/data/workspace-infosec/glaurung/` as a
sibling repo. asb's `bot/kg_pe/` calls into Glaurung's Python
bindings; no source duplication. The only asb artifacts that
land in Glaurung are:

- the docs under this `docs/windows-port/` tree (design
  artifacts, not code)
- the per-tool Rust + Python files this campaign drives
  upstream via PRs (`glaurung/llm/tools/find_*.py` etc.)
- test fixtures + manifest in `tests/fixtures/msvc-pdb/`

The reverse direction (Glaurung -> asb) is read-only: asb
consumes Glaurung's Python bindings, CLI, and bench output.

### 2. Issue-tracked contributions

Every asb-side feature need that requires a Glaurung change
opens a Glaurung GitHub issue first. The issue describes the
use case in campaign-agnostic terms so it benefits future
Glaurung users, not just the asb windows-port campaign.

The four roadmap items already on the Glaurung board (#179,
#197, #199, #186) satisfy this clause for the initial wave;
each is described in
`docs/architecture/IDA_GHIDRA_PARITY.md` without asb-specific
framing. New features asb identifies during the campaign get
the same treatment.

### 3. Upstream PR before downstream consume

asb does not depend on un-merged Glaurung branches in
production wheel activities. The dev loop may use a working
branch (asb's `tools/kg-pe/bridge.py` may import from a
local-checkout Glaurung with a feature branch); the wheel
only fires against merged Glaurung commits.

Practical implication: the asb wheel activity
`windows-pe-rule-hunt` checks Glaurung's installed version at
startup and refuses to run if a feature it depends on is not
merged. This prevents silent fork.

### 4. Atomic-tool authoring policy

The 12-15 Windows-specific atomic tools live in
`glaurung/llm/tools/` as part of Glaurung, not under asb's
`bot/kg_pe/`. (Detailed list in `atomic-tools.md`.) Tool
implementations reference asb's
`data/kg/pe-{sources,gates}.yaml` via a configurable path so
the YAMLs can be updated without a Glaurung release.

Why: tools are reusable across consumers (memory_agent,
interactive `glaurung ask`, bench). YAMLs are campaign-specific
data. Code goes where reuse happens; data goes where the
campaign owns it.

### 5. Calibration cross-pull

Glaurung's `python -m glaurung.bench` output is ingested into
asb's `data/calibration/` via a thin adapter
(`tools/calibration/glaurung_bench_to_jsonl.py`, asb-side) so
asb's calibration history covers Windows binaries.

Glaurung's bench gains Windows binaries in the `--ci-matrix`
as part of the #197 / #199 work; the matrix expansion is the
upstream-side analog of the asb-side adapter.

### 6. Failure mode (escape hatch)

If Glaurung's roadmap velocity becomes a campaign blocker, the
escape hatch is to fork onto a long-running
`agentic-windows-port` branch, rebase weekly, with the explicit
intent of returning. The escape is documented in this doc and
in asb ADR 0023; we do not silently fork.

Tripwire: if asb's wheel is blocked on a Glaurung PR for >2
weeks, file the fork issue. If we hit a fork, the rebase log
lives at `docs/windows-port/fork-rebase-log.md` (not yet
created; only on actual fork).

## Consequences

- Glaurung repository sees increased issue + PR traffic
  specific to Windows binaries; expected to be net positive
  for Glaurung's broader Windows-research value.
- asb's wheel can be blocked on a Glaurung merge; mitigated
  by the fork escape hatch.
- The line between "Glaurung capability" and "asb Windows
  campaign" stays clear at the YAML-config boundary:
  `pe-sources.yaml` / `pe-gates.yaml` live in asb; tools that
  consume them live here.
- asb's wheel activity `windows-pe-rule-hunt` (asb ADR 0022)
  calls Glaurung CLI directly via `subprocess` or via Python
  bindings; either is acceptable, choice is per-activity.

## Alternatives considered

- "Vendor Glaurung into asb" -- rejected per asb ADR 0021.
- "Use Glaurung as a black box, no upstream contribution" --
  rejected; the missing features (#179 PDB, #199 PE
  hardening) are blockers asb cannot defer to other
  contributors.
- "Fork Glaurung permanently" -- rejected; doubles
  maintenance cost, loses bench harness alignment.

## Authoring conventions

### Commit trailer

Every Glaurung commit asb drives carries:

```
Assisted-by: Claude:claude-opus-4-7
```

Per the kernel coding-assistants doc (which Glaurung adopts as
the cross-project convention). Do NOT use any of:

- `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`
  (the chat-UI default; wrong shape for assistant attribution)
- `Co-Authored-By: Claude <noreply@anthropic.com>` (same)
- any `Name <email>` form generally

The `Assisted-by:` trailer is what kernel maintainers expect
for assistant-touched patches; Glaurung uses the same form so
the asb workflow doesn't need to learn two conventions.

If a Glaurung CI hook complains about the trailer format, the
fix is to teach the hook the new trailer kind, not to switch
to the `Name <email>` form. See asb's `feedback_assisted_by_format`
memory rule for the operator-facing rationale.

### ASCII purity

All docs in this tree and all Glaurung commits driven by the
asb campaign are ASCII-only. asb has an `ascii-scrub` skill
that catches em-dash / curly-quote / smart-punct / NBSP /
arrows / ellipsis; Glaurung's pre-commit grep gate does the
same on the Glaurung side.

Source patterns to never use, in either docs or code:

- em-dash, en-dash (use `--` or `,` or parens in prose; never
  use `--` as a literal in code outside CLI flags)
- curly single / double quotes
- ellipsis character (use three ASCII dots)
- NBSP (use regular space)
- unicode arrows in markdown tables (use `->`)

Verification:

```
grep -rnP '[^\x00-\x7F]' docs/windows-port/
```

should return empty.

### Doc style alignment

The docs in this tree match Glaurung's existing tone:

- Markdown tables for status + comparison
- Code blocks for actual Rust signatures, Python decorator
  patterns, SQL schemas
- Per-doc "Cross-refs" section at the end pointing at
  Glaurung + asb files
- Length ceiling ~500 lines per doc; split if exceeded

Reference for tone: `docs/llm/ROADMAP.md`,
`docs/architecture/PERSISTENT_PROJECT.md`.

## Operating cadence

- asb session that touches Windows campaign work re-reads
  `docs/windows-port/README.md` first to refresh the roadmap
  status table.
- When a Glaurung issue from this set lands, update both:
  - `docs/architecture/IDA_GHIDRA_PARITY.md` row status
    (Glaurung-side)
  - `docs/windows-port/README.md` roadmap status table
    (this tree)
- When a new tool ships under `glaurung/llm/tools/<name>.py`,
  add a row to `atomic-tools.md` table if not already there.

## Cross-refs

- Source ADR (truth):
  `agentic-security-bot/projects/windows-port/workstreams/01-decisions-and-wiring.md`
  sec "ADR 0023 -- Glaurung co-investment relationship"
- asb ADR 0021 (the substrate-choice ADR that ADR 0023 follows from):
  same file, sec "ADR 0021"
- Glaurung roadmap board:
  `docs/architecture/IDA_GHIDRA_PARITY.md`
- asb operator habit on commit-trailer format:
  asb memory rule `feedback_assisted_by_format`
- asb ASCII-purity skill:
  asb skill `ascii-scrub`
- Per-feature docs:
  `roadmap.md`, `atomic-tools.md`, `pdb-ingestion-design.md`,
  `pe-hardening-design.md`, `bsim-similarity-design.md`
