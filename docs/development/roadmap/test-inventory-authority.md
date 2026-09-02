# Test-inventory authority plan — 2026-08-31

> **Kind:** plan · **Status:** proposed

This implements R0 of the
[real-binary roadmap](real-binary-decompiler.md) and refines
test-estate Phase 1. The current inventory is valuable but not reproducible or
internally atomic enough to serve as live authority.

## Measured current state

The machine-readable files currently say:

* `index.json`: commit `78ad620e`, 984 entries, 6,282 tests, 77 unreachable;
* `index.yaml`: the same commit and counts;
* `unreachable.json`: commit `78ad620e`, 77 entries;
* `coverage.md`: commit `2ce51f9d`, 986 entries, 89 unreachable.

This is not merely a stale comment. `coverage.md` also retains old kind/domain
counts while `index.json` reflects deleted assets/scripts and reachability
repairs.

The generator explains the drift:

1. it writes only `index.json`, `index.yaml`, and `unreachable.json`;
2. it never writes `coverage.md` or README summary counts;
3. its required five input `*.jsonl` survey fragments are not committed;
4. no test or CI workflow invokes it;
5. it has no `--check` mode or schema version;
6. it validates path existence and domain vocabulary, but not the rest of the
   advertised entry schema.

Therefore the command documented in the README cannot reproduce the committed
inventory from a fresh checkout. A generated artifact without its source
inputs is a snapshot, not a renewable control.

## Authority model

Choose one explicit model. The recommended model is **committed canonical
records plus generated views**:

```text
docs/test-inventory/records/*.jsonl   canonical reviewed records
                 │
                 ▼
tools/build_test_inventory.py        validation + deterministic render
                 │
                 ├── index.json
                 ├── index.yaml
                 ├── unreachable.json
                 └── coverage.md
```

README prose remains hand-maintained and may cite generated counts only through
a clearly delimited generated block. Do not generate human judgement in
`findings.md`; it is a dated interpretation, not a view.

An alternative is full live discovery from repository source. That is a much
larger tool: subject, notes, and runner semantics are human judgements and
cannot be inferred reliably. Do not pretend a scanner can regenerate them.

## I0 — Recover and commit canonical inputs

Reconstruct five territory files from the current `index.json`, dropping only
the derived `reach` field and preserving every reviewed field. The transform is
mechanical because every entry retains its `territory`.

Files:

```text
docs/test-inventory/records/assets.jsonl
docs/test-inventory/records/fixtures.jsonl
docs/test-inventory/records/python-tests.jsonl
docs/test-inventory/records/rust-tests.jsonl
docs/test-inventory/records/tooling.jsonl
```

Validation before accepting them:

* rebuilding produces byte-equivalent semantic records to current
  `index.json` after ignoring commit/order metadata;
* 984 unique IDs and 984 unique `(kind, path)` identities unless an explicit
  multi-entry reason is present;
* every path exists;
* territory counts are exactly Python 445, Rust 371, tooling 110, fixtures 32,
  assets 26 at the pinned snapshot.

This recovery does not claim the records are current; it restores the missing
source of truth so subsequent updates are reviewable.

## I1 — Versioned strict schema

Add a typed entry model or explicit validator with `schema_version = 2`.

Required existing fields:

```text
id, kind, path, title, subject, domain, size_bytes,
runs_by, consumes, gated_by, notes, markers, features,
count, count_of, territory
```

`count` and `count_of` are nullable together for non-test/non-countable entries;
the present 108 null pairs are valid only under that rule.

Add optional structured fields while retaining human prose:

```text
oracle: [execution, source-cfg, source-types, dwarf, pdb, structural,
         differential, parser, static-assertion, none]
formats: [elf, pe, macho, wasm, dex, class, archive, container, raw]
architectures: [x86, x86_64, armv7, arm64, riscv64, ...]
languages: [c, cpp, rust, go, ...]
compilers: [{name, version, optimization, flags_hash}]
transformations: [stripped, packed, obfuscated, lto, inlined, malformed]
size_class: [micro, small, medium, large, pathological]
asset_class: [construct, generated, production, benign, malicious,
              suspicious-behavior, adversarial-parser]
ground_truth_strength: [behavioral, source, debug-info, differential,
                        structural-only, none]
provenance: {source_url, revision, license, build_recipe, sha256}
runtime: {class, last_measured_seconds, measured_at_commit}
```

Use arrays where one entry spans multiple formats/architectures. Reject unknown
enum values. Do not require detailed dimensions retroactively in one giant
rewrite: represent absence as `unknown`, report it, and ratchet domain by
domain.

## I2 — Deterministic complete rendering

The generator writes all four derived files into a temporary directory, parses
its own JSON/YAML, verifies cross-file counts, then atomically replaces the
destination set.

`coverage.md` is generated from the same counters and includes:

* schema version and inventory commit;
* total entries/test functions;
* reach/kind/domain/territory tables;
* unreachable by kind and domain;
* oracle/format/architecture/language/asset-class coverage;
* missing-dimension table;
* no hand-entered numeric claims.

Stable ordering is part of the contract. Generation twice at the same commit
must be byte-identical.

Avoid embedding wall-clock generation time because it defeats deterministic
`--check`; record the Git commit and schema version.

## I3 — `--check` and CI

`--check` renders into a temporary directory and byte-compares every generated
file. It reports each stale path and a compact diff, writes nothing, and exits
nonzero.

TDD cases:

* missing canonical record directory;
* malformed JSON line with file/line diagnostic;
* missing/unknown required field;
* stale path;
* duplicate ID and duplicate unexplained identity;
* unknown enum;
* `count`/`count_of` mismatch;
* stale one-of-four output;
* generator determinism;
* YAML round trip;
* exact cross-view totals.

Wire the check into the ordinary Python CI job because it is filesystem-only
and cheap. Add the command to `CLAUDE.md` only after it exists.

## I4 — Reachability becomes structured

Current `reach()` infers authority from substring search over `gated_by`:
“manual,” “gate,” and “decbench” become opt-in; “workflow” becomes CI. This is
useful for the snapshot but too fragile for a ratchet.

Replace inference with:

```text
reach: default-suite | ci | opt-in | unreachable | documentation-only
runners:
  - kind: pytest | cargo-test | cargo-fuzz | script | workflow | external
    command: ...
    caller: path or null
    condition: marker/feature/env or null
```

During migration, compare explicit reach to legacy inference and report
disagreements. Remove inference only when every entry has an explicit runner
path or a reasoned non-running class.

“CI” means a tracked workflow transitively invokes the command, not that the
entry text contains the word.

## I5 — Coverage queries that guide the roadmap

Add a small query/report interface over `index.json`, not a second database.
It must answer:

* source-grounded PE O2 functions by runner/reach;
* ARM32 Cortex-M MRS/MSR fixtures and their oracle;
* large/pathological functions with execution and resource telemetry;
* stripped/packed/obfuscated matched pairs;
* malicious or suspicious-behavior assets with redistribution provenance;
* files/modules with no reachable behavioral oracle;
* tests whose last measured runtime exceeds their declared class.

Saved queries for R1–R7 become tests: when a roadmap milestone claims coverage,
the corresponding query must prove it.

## Sequencing

1. I0 canonical input recovery.
2. I1 schema v2 with legacy fields and tests.
3. I2 generate all views, including `coverage.md`.
4. I3 `--check` and CI.
5. I4 explicit reach/runner migration.
6. I5 new dimensions, populated first for decompiler fixtures and assets.

Do not start by manually changing `coverage.md` from 89 to 77. That repairs one
number while preserving the mechanism that let it drift.

## Definition of done

* a fresh checkout contains canonical inputs;
* one documented command reproduces all generated files;
* two runs are byte-identical;
* `--check` passes on `master` and fails after perturbing any generated view;
* CI runs `--check`;
* schema and cross-view totals are tested;
* reachability has explicit runners rather than substring authority;
* decompiler fixtures/assets have enough dimensions to prove R1–R7 coverage;
* zero numeric summary in generated views can drift independently.
