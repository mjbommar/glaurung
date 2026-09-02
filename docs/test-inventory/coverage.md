# Coverage tables

> **Kind:** reference · **Status:** maintained

**This file is a frozen snapshot, not a live view.** It was written by hand at
commit `2ce51f9d` from that commit's `docs/test-inventory/index.json` and has
not been regenerated since. `tools/build_test_inventory.py` — the only tool
that writes into `docs/test-inventory/` — produces `index.json`, `index.yaml`,
and `unreachable.json` only; it does not write this file, and its own five
`*.jsonl` survey-fragment inputs are not committed (see the
[test-inventory authority plan](../development/roadmap/test-inventory-authority.md)).
`index.json` has since moved past the counts below — check its own `commit`
and `counts` fields for the current numbers. Do not quote the tables here as
current; read `index.json` directly, or `unreachable.json` for the reachability
detail.

**986 entries, 6,282 test functions, at `2ce51f9d`.**

## Reach — what runs each thing

| reach | entries | |
|---|---:|---|
| default-suite | 771 | runs when someone types the ordinary command |
| unreachable | 89 | **nothing runs it** |
| ci | 79 | a GitHub workflow runs it |
| opt-in | 36 | a marker, a feature flag, or a gate script |
| other | 11 | unclassified |

## Kind

| kind | entries |
|---|---:|
| `python-test` | 445 |
| `rust-unit-test` | 303 |
| `tool` | 56 |
| `rust-integration-test` | 41 |
| `example` | 30 |
| `binary-asset` | 29 |
| `bench` | 20 |
| `script` | 18 |
| `fixture-corpus` | 15 |
| `baseline` | 12 |
| `ci-workflow` | 7 |
| `docs` | 5 |
| `fuzz-target` | 5 |

## Domain

Entries may carry several domains, so the total exceeds the entry count.

| domain | entries |
|---|---:|
| `llm` | 228 |
| `decompiler` | 185 |
| `windows` | 165 |
| `ir` | 137 |
| `analysis` | 81 |
| `infra` | 78 |
| `triage` | 76 |
| `formats` | 67 |
| `java` | 60 |
| `symbolic` | 47 |
| `decbench` | 45 |
| `kb` | 26 |
| `disasm` | 21 |
| `symbols` | 21 |
| `cli` | 21 |
| `strings` | 18 |
| `packers` | 11 |
| `docker` | 9 |
| `entropy` | 8 |
| `similarity` | 8 |
| `docs` | 7 |
| `flirt` | 4 |
| `containers` | 4 |
| `demangle` | 3 |

## Unreachable, by kind

| kind | entries |
|---|---:|
| `example` | 24 |
| `rust-unit-test` | 15 |
| `rust-integration-test` | 11 |
| `bench` | 10 |
| `script` | 9 |
| `fuzz-target` | 5 |
| `tool` | 5 |
| `fixture-corpus` | 3 |
| `python-test` | 3 |
| `binary-asset` | 2 |
| `baseline` | 1 |
| `docs` | 1 |

The full list with reasons is in `unreachable.json`.

