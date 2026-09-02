# DecBench failure remediation plan — 2026-08-31

> **Kind:** plan · **Status:** proposed

This is the implementation plan for the proven classes in the
[full-run taxonomy](../../history/design/campaigns/decbench-full-failure-taxonomy-2026-08-31.md).
It deliberately separates Glaurung product defects, Glaurung evaluation-harness
defects, and DecBench dataset/evaluator inconsistencies.

## Progress update — 2026-09-01

Increment B's F1a core landed in `0d6b30d1`: a collision-safe resolver, real
PE32 fixture, and six-clause contract cover the 33 predicted stdcall rows.
Increment D's product-side core now distinguishes an import from an absent
symbol. The scoring/dataset disposition for all 63 F1b rows remains open, as
do F1c, F1d, and F2a. No fresh full DecBench rerun has confirmed row movement,
so the predicted 33 recoveries are not yet observed submission data.

## Contracts and ownership

| class | count | owner | desired terminal state |
|---|---:|---|---|
| F1a: i386 stdcall name decoration | 33 | Glaurung DecBench adapter | Local body requested by unambiguous decorated symbol address. |
| F1b: import-only identity | 63 | Adapter plus DecBench scoring contract | Explicit external/import disposition; never pretend an IAT entry is a local body. |
| F1c: manifest-only identity | 88 | Dataset validation | Excluded or supplied with a valid source/binary identity path. |
| F1d: gzip source-CFG-only wrapper | 2 | Dataset/build provenance | Proven eliminated/renamed wrapper or corrected binary identity. |
| F2a: ARM32 Cortex-M system register | 31 | Glaurung ARM32 lifter | Body returned with explicit conservative MRS/MSR semantics. |
| E1: original PE bytes unavailable | 13 | DecBench evaluator | Compile evidence produced or row explicitly excluded from compile denominator. |

These counts are occurrences in the pinned run, not promises about the next
dataset revision. Every implementation must be guarded by independent fixtures
before a held-out rerun measures impact.

## Increment A — Make the taxonomy reproducible

### Artifact

Add `tools/decbench_failure_taxonomy.py RUN_ROOT --out DIR` producing:

* `failure-taxonomy.json`: one row per manifest function without a returned
  body, with immutable `(opt, project, binary, function)` key;
* `failure-taxonomy-summary.json`: counts by class, format, architecture,
  project, and optimization;
* `failure-taxonomy.md`: generated ledger and summaries;
* nonzero exit if row count or evidence relationships are inconsistent.

Required row fields:

```text
key, binary_sha256, format, arch,
checkpoint_status, returncode, parse_error, conversion_error,
requested, returned, unresolved,
source_cfg_present, source_cfg_nodes, source_cfg_edges,
symbol_matches, import_matches, canonical_name,
class, reason, evidence_paths
```

### Tests

Create `python/tests/test_decbench_failure_taxonomy.py` with real tiny ELF and
PE fixtures where possible and minimal on-disk checkpoint/source-CFG records.
Synthetic checkpoint JSON is permitted only for testing the taxonomy parser,
not as decompiler evidence; label it as parser fixture data.

Cases:

* terminal successful checkpoint with returned body is omitted;
* unresolved decorated symbol becomes F1a;
* import without local symbol becomes F1b;
* manifest name absent from source CFG and binary becomes F1c;
* source CFG without binary identity becomes F1d;
* requested address without return becomes F2;
* decompile failure, parse failure, conversion failure, duplicate address, and
  outside return remain distinct fatal taxonomy classes;
* all summary totals reconcile to the row set.

Acceptance on the pinned root: exactly 217 rows partitioned as
`33 + 63 + 88 + 2 + 31`, plus thirteen separate E1 records.

## Increment B — F1a stdcall resolution

### RED

Refactor the import-unsafe resolver in `tools/decbench_redecompile_tree.py` into
pure helpers that tests can import without starting a run. Add a real PE32
fixture or compile one with the pinned clang-cl/mingw fixture toolchain having:

* `_worker@4`, `_entry@12`, and `_handler@16` function symbols;
* undecorated `worker` and `_worker` collision controls;
* a data symbol named like a function;
* duplicate canonical names at distinct addresses.

Tests first assert the current resolver misses `_worker@4`. The new contract:

1. exact name wins;
2. existing cdecl `_name` fallback remains;
3. `_name@N` is accepted only for i386 PE function symbols;
4. more than one matching code address is an explicit ambiguity, never
   first-entry-wins;
5. data/import symbols cannot satisfy a local-function request;
6. decoration and chosen raw symbol are recorded in the checkpoint.

### GREEN and verification

Implement the smallest resolver change, then run:

```bash
uv run pytest python/tests/test_decbench_failure_taxonomy.py -xvs
uv run pytest python/tests/test_decbench_redecompile_tree.py -xvs
uv run pytest python/tests/test_decompile_vas_sources.py -xvs
```

Re-run only the affected Dexter, Mydoom, and x0r-usb binaries first. Expected
movement is 33 F1a rows into requested addresses, not necessarily 33 successful
bodies. Classify any new no-body result rather than hiding it.

## Increment C — F2a ARM32 MRS/MSR semantics

### Semantics

Cortex-M special registers are machine state, not ordinary memory. Model them
as typed, non-memory intrinsics so def-use remains honest:

* `mrs Rd, SYS` → `arm32.mrs.<sys>` with one W32 output `Rd`;
* `msr SYS, Rn` → `arm32.msr.<sys>` with one explicit W32 input;
* `BASEPRI_MAX` remains distinct from `BASEPRI` because its update semantics
  are conditional;
* known registers: `BASEPRI`, `BASEPRI_MAX`, `IPSR`, and `PSP` first;
* unknown system-register encodings become a named conservative intrinsic,
  never an empty lift and never an ordinary memory operation.

This is intentionally an intrinsic first, not fabricated high-level C. It
keeps the body and data dependencies while allowing later refinement for
execution/symbolic semantics.

### RED at three layers

1. **Packet tests in `src/ir/lift_arm32.rs`.** Use real instruction bytes from
   independently assembled Cortex-M code. Assert mnemonic-specific intrinsic,
   inputs/outputs, W32 width, and `reads_mem=false/writes_mem=false`.
2. **Function lift.** A byte window beginning with each MRS/MSR form must not
   produce `NoLiftableBlocks` or a maximally opaque memory-clobbering unknown.
3. **Fixture lane.** Add one numbered Cortex-M source/assembly fixture containing
   ordinary helpers plus SVC/PendSV/SysTick vector handlers. Assert every
   normalized Thumb VA is discovered and returns a body.

The fixture must cover these observed prefixes:

```text
mrs rN, BASEPRI
msr BASEPRI, rN
msr BASEPRI_MAX, rN
mrs rN, IPSR
mrs rN, PSP
msr PSP, rN
```

### Downstream checks

Run focused Rust tests, `cargo test --features python-ext`, then the architecture
fixture lane and all four behavioral baselines. Inspect undefined-read changes:
MRS outputs should remove false undefined reads; MSR inputs must retain their
real dependencies.

Re-run one Betaflight, one NuttX, and one RTOS image before the full set.
Expected movement: all 31 F2a rows return bodies or expose a narrower next
failure. The metric result is secondary to complete body accounting.

## Increment D — F1b external/import contract

Do not resolve an imported function name to its IAT slot and pass that address
to the decompiler. The slot is data; a PLT/import thunk, when present, is a
different object from the external implementation.

Define an adapter record:

```json
{
  "kind": "external_import",
  "name": "Process32First",
  "library": "KERNEL32.dll",
  "import_name": "Process32First",
  "ordinal": null,
  "iat_va": "0x...",
  "thunk_va": "0x... or null",
  "local_body": false
}
```

Then determine with DecBench whether these rows should be removed from its
local-function universe or represented as explicit declarations. Until that
contract exists, report 63 “not locally body-bearing,” not 63 Glaurung
decompilation failures.

Tests require a real PE importing by name and ordinal, plus a delay import and
forwarded export when the PE fixture lane supports them.

## Increment E — F1c/F1d dataset consistency

Add a read-only validator, usable against any materialized tree, enforcing one
of these paths for each binary manifest function:

1. source CFG plus local function identity/address;
2. explicit external/import identity;
3. explicit optimizer-eliminated/source-only disposition;
4. explicit alias to another immutable function key.

A bare name with none of those paths is invalid. On the pinned tree it must
report exactly 88 F1c rows and two F1d rows.

For gzip `__printf__`, obtain the exact source revision and preprocessed unit.
Compare source definition, compiler symbols before/after link, and final binary.
Do not guess between macro wrapper, inline elimination, alias, or extraction
artifact from the one-node CFG.

## Increment F — E1 compile evidence

For the thirteen O2 Dexter rows, record original address/range provenance and
why DecBench byte extraction failed. Acceptance is one of:

* original bytes extracted and all thirteen acquire compile facts;
* function range is proven unavailable/ambiguous and the evaluator excludes
  the rows from the compile denominator with an explicit reason.

This lane must not change Glaurung output to satisfy evaluator byte extraction.

## Increment G — Ratchet and held-out rerun

The final gate records:

| invariant | target |
|---|---:|
| command/parse/conversion/address-integrity failures | 0 |
| unexplained manifest-only identities | 0 |
| requested addresses with no body or structured refusal | 0 |
| ambiguous name resolutions silently chosen | 0 |
| compile facts absent without evaluator reason | 0 |

Run order:

1. independent fixtures and focused unit tests;
2. affected project/optimization shards;
3. full local fixture/architecture/structural/def-use gates;
4. fresh release-build full DecBench run at a newly pinned revision;
5. regenerate taxonomy and compare class transitions by immutable key.

Never overwrite the 2026-08-31 evidence. A new run gets a new root and report.

## Sequencing and stop conditions

`A → B → C` are the first three increments. B and C fix proven, bounded
Glaurung-owned causes. D–F can proceed after A and do not block the independent
fixtures.

Stop and reclassify when:

* stdcall normalization yields multiple addresses;
* an F2 function still fails after MRS/MSR becomes explicit;
* a manifest-only name gains an address only through heuristic nearest-symbol
  snapping;
* an import is mistaken for a local code body;
* a metric improves while function accounting becomes less complete.

Those are evidence of a new class, not permission to broaden a heuristic.
