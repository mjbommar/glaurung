# Glaurung Windows-port working tree

> Living docs for the Windows / PE / PDB readiness sprint driven
> by the sibling `agentic-security-bot` (asb) repo's `windows-port`
> campaign.

## Status

Implementation is active. #197 and #199 have shipped, and #179 now
has the PE/PDB type-ingestion path needed by the comparison-02
contract: cached PDBs produce persisted struct, union, and
function-prototype type records with provenance. Public PDB
function names and direct PE code-to-data xrefs now persist into
the `.glaurung` KB, which unblocks IDA-style string/use-site
queries for direct `.rdata` references. The remaining windows-port
work is UTF-16 / indirect string-reference coverage, the broader
PDB follow-up surface, BSim-style similarity, and the
Windows-specific atomic tools.

## Why this exists in Glaurung (not in asb)

asb chose Glaurung over a Ghidra-headless wrapper as its static-
analysis substrate for Windows binaries (asb ADR 0021). The four
roadmap items below are the gap between today's Glaurung and what
asb needs to ship Windows CVEs:

- `#197` MSVC + .pdb sample fixtures
- `#179` PDB ingestion (mirrors gimli DWARF path)
- `#199` PE format hardening (delay imports, manifest, version
  info, TLS callbacks)
- `#186` BSim-equivalent function similarity

asb commits to driving these features upstream rather than
forking; the contract is asb ADR 0023 (mirrored here as
`co-investment-policy.md`).

## What you can do without leaving this tree

- Read `roadmap.md` for the four roadmap items + per-item scope,
  motivation, design sketch, dependencies, and effort.
- Read `atomic-tools.md` for the 12-15 Windows-specific atomic
  tools the campaign wants registered with `memory_agent`.
  Authoring template included.
- Read `pdb-ingestion-design.md` for the design plan against
  the Rust `pdb` crate, with the llvm-pdbutil JSON fallback.
- Read `pe-hardening-design.md` for the four PE directories
  `#199` lights up, each with a CVE-class rationale.
- Read `bsim-similarity-design.md` for the Patch-Tuesday-diff
  use case and three competing approaches (4-gram-LSH,
  CodeT5+ embeddings, hybrid).
- Read `co-investment-policy.md` for the issue-first /
  upstream-first contract with asb. This is also where the
  `Assisted-by: Claude:claude-opus-4-7` trailer convention is
  recorded.

## Cross-refs

- asb campaign root:
  `/nas4/data/workspace-infosec/agentic-security-bot/projects/windows-port/`
- asb workstream 02 (the substrate sprint):
  `projects/windows-port/workstreams/02-kg-pe-substrate.md`
- asb workstream 03 (the rules layer that consumes the tools):
  `projects/windows-port/workstreams/03-rules-and-master-data.md`
- asb bug-class invariants (the 13 tier-1 patterns the atomic
  tools encode):
  `projects/windows-port/reference/bug-class-invariants.md`
- Glaurung roadmap board:
  `docs/architecture/IDA_GHIDRA_PARITY.md` (issues #197 / #179 /
  #199 / #186 surface there with one-line status)
- Glaurung pydantic-ai integration:
  `docs/llm/ROADMAP.md` + `docs/llm/TOOLS.md`
- Glaurung persistent KB schema:
  `docs/architecture/PERSISTENT_PROJECT.md`

## Roadmap-item status table

| issue | scope | blocker for | per-doc | status |
|-------|-------|-------------|---------|--------|
| #197  | MSVC + .pdb sample fixtures                | #179 PDB ingest test cases | `roadmap.md` sec 1, `pdb-ingestion-design.md` sec "Test fixtures" | shipped |
| #179  | PDB ingestion (`src/symbols/pdb.rs`)       | every kg-pe rule that needs PDB-derived types | `pdb-ingestion-design.md` | type path + public function-name binding shipped; alias summaries remain |
| #199  | PE hardening: delay-import / manifest / VersionInfo / TLS callbacks | grounded malware triage, driver TLS-callback bug class | `pe-hardening-design.md` | shipped |
| xrefs | PE direct code-to-data refs                | strings-xrefs and data-use queries over Windows binaries | `IDA_GHIDRA_PARITY.md` #154/#222 | direct `data_read` rows shipped for PE functions; UTF-16 and one-hop pointer refs remain |
| #186  | BSim-equivalent function similarity         | Patch Tuesday cross-build diff for n-day | `bsim-similarity-design.md` | not started |
| tools | 12-15 Windows-specific `llm/tools/` files   | rule-as-tool encoding for tier-1 bug classes | `atomic-tools.md` | not started |

## Authoring conventions

- ASCII only; no em-dashes, smart quotes, ellipsis, NBSP, arrows.
  These docs and any Glaurung commits they motivate get scrubbed
  before merge (asb has an `ascii-scrub` skill; Glaurung side
  uses `pre-commit` + a similar grep gate).
- Every Glaurung commit asb drives carries the
  `Assisted-by: Claude:claude-opus-4-7` trailer per the kernel
  coding-assistants doc. Do NOT use the
  `Name <email>` form; bot/co-author trailers are the wrong
  shape for assistant attribution.
- Each per-feature doc is 200-500 lines and self-contained: a
  reader landing on `pdb-ingestion-design.md` should not have
  to read `roadmap.md` to understand scope.
