# Source front ends: the measurement harness

> **Kind:** plan · **Status:** proposed

How the parsing substrate and the front ends on top of it are measured: four
axes rather than one, the corpora they run against, the targets and where each
one comes from, the ratchet, and the reporting rules.

The substrate being measured is [`substrate.md`](substrate.md); the case for it
is [`README.md`](README.md); its first consumer is
[`static-c-analysis/`](../static-c-analysis/README.md).

Nothing here is built.

## 1. Why four axes

The usual parser benchmark measures throughput and stops. That is the wrong
instrument for this component, because the property that decides whether it is
usable is **coverage**, not speed: a lexer twenty percent faster that loses one
more function is a regression, and nothing in a throughput number says so.

| axis | question it answers | failure it catches |
|---|---|---|
| **throughput** | how fast per byte | a hot-path regression |
| **latency** | how fast per translation unit, at the tail | a pathological input class that the mean hides |
| **coverage** | how much does it parse, and how much does it lose | the regression that matters most and shows up in no timing |
| **determinism** | is the output a function of the input alone | the failure that makes every other gate meaningless, because every gate here is a diff |

Coverage is ranked **above** throughput. A change that improves throughput and
loses a function is rejected.

## 2. The corpora

Three, all present today, all with different jobs.

| corpus | size | provenance | job |
|---|---|---|---|
| **fixture C** | 196 files under `tests/decompiler_fixtures/src/`, 14 under `tests/decbench_corpus/src/`, 21,296 lines total | ours, clean, single-construct by design | correctness floor: **zero** parse errors permitted |
| **decompiled C** | 1,606 `.c` artifacts, ~200 MB, in the materialized DecBench tree | real output from every decompiler column | robustness and throughput: adversarial, ill-formed, and the input that actually matters |
| **preprocessed C** | `.i` output from the fixture corpus via `gcc -E` | generated on demand, not committed | the source-side dialect, with GNU extensions and line markers intact |

Counts reproduce with:

```bash
ls tests/decompiler_fixtures/src/*.c | wc -l          # 196
ls tests/decbench_corpus/src/*.c | wc -l              # 14
cat tests/decompiler_fixtures/src/*.c tests/decbench_corpus/src/*.c | wc -l   # 21296
find ~/.cache/glaurung/decbench-full/tree -name '*.c' -path '*/decompiled/*' | wc -l
```

at `935b7db1`. The decompiled corpus lives outside the repository, so every lane
that uses it degrades to a skip rather than a failure when the tree is absent —
the same discipline the DecBench lanes already follow.

## 3. What is measured

### 3.1 Throughput — `benches/source_parse.rs`

Two tiers, following the convention `benches/ir_lift.rs` established: a **micro**
tier that isolates one shape per benchmark, and a **realistic** tier that runs
the thing the pipeline actually calls. Throughput is declared wherever a size is
meaningful, so criterion reports MiB/s rather than bare latencies.

| lane | input | reports |
|---|---|---|
| `source_parse/lex/<shape>` | hand-written windows: dense identifiers, dense numeric literals, string-heavy, comment-heavy, deeply nested parentheses | MiB/s, ns/token |
| `source_parse/lex/corpus` | the ten largest decompiled artifacts | MiB/s |
| `source_parse/parse/<shape>` | expression-heavy, statement-heavy, declaration-heavy | MiB/s |
| `source_parse/parse/corpus` | the same ten artifacts | MiB/s |
| `source_parse/cfg/corpus` | events → CFG, parse excluded from the timing | functions/s |

Windows are cut from real corpus files, never synthesized. The repository's
existing rule applies: the input is the format the component actually takes, not
a stand-in for it.

### 3.2 Memory and allocation

Reported alongside throughput because the substrate's data-structure choices are
justified on memory grounds and an unmeasured justification is a guess.

* bytes of arena per KLOC — tokens, nodes and `extra` separately;
* allocation count per file;
* peak RSS over the whole 200 MB corpus in one process.

The struct-of-arrays token buffer and node arena in
[`substrate.md`](substrate.md) §2 exist to reduce the first of these. **The
array-of-structs control must be measured once**, on the same corpus, so the
choice is evidence rather than received wisdom — the published Zig figure of
37.5% for a specific four-field struct is their measurement of their shape, not
ours.

### 3.3 Latency

Per translation unit, over the whole decompiled corpus: p50, p90, p99, max, and
the identity of the worst ten files. The tail is the interesting part — a
pathological input class shows up at p99 and vanishes in a mean.

### 3.4 Coverage — `tools/source_parse_census.py`

The lane that outranks the others. For each corpus it reports:

| number | meaning |
|---|---|
| files parsed / total | a file is "parsed" if it produced any function |
| functions found | the substrate's answer |
| functions Joern found that we did not | a **loss** |
| functions we found that Joern did not | a **gain** |
| diagnostics per KLOC | recovery pressure, not a pass/fail |
| files with zero functions | the whole-file voiding mode, which must stay at zero |

Losses and gains are computable without running Joern, because the published
source CFGs and the stored per-function GED cells name exactly which functions
Joern produced — the same offline oracle
[`static-c-analysis/parity-plan.md`](../static-c-analysis/parity-plan.md) §1
inventories.

### 3.5 Determinism

Parse the whole corpus twice in one process and once in a fresh process; diff
the serialized output bytes. Any difference is a failure, not a warning. This
lane is cheap and it is the one that protects every other gate, because all of
them are diffs.

## 4. Targets, and where each comes from

| target | value | source |
|---|---|---|
| fixture corpus parse errors | **0** | it is clean C that we own |
| files with zero functions | **0** | the failure mode being removed — `joern-behavior.md` §5 |
| source-side function loss | **≤ 5.01%** | Joern's own published rate over 94,575 functions |
| decompiled-side function loss | **≤ 0.04%** | the best rate any decompiler currently gets from Joern (ghidra; kuna is 0.00%) |
| median TU parse | **< 10 ms** | `REQ-PERF-1` |
| 56 cells of CFG extraction | **< 1 min** | against ~37 minutes today, one JVM per cell |
| determinism | byte-identical | `REQ-SYN-5` |

Throughput has deliberately **no absolute target**. Publishing one against
another project's numbers would be comparing different corpora, different
machines and different work; the ratchet in §5 is the honest instrument.

## 5. The ratchet

Commit a baseline JSON under `tests/` holding, per corpus: files parsed,
functions found, losses, gains, zero-function files, and p50/p99 latency. A test
in `python/tests/` fails on any **coverage** decrease and on any latency
regression beyond a stated tolerance. Timing tolerance is wide, because the
machine is not controlled; coverage tolerance is **zero**, because it is a
property of the code alone.

This follows the four baselines the fixture estate already uses, and inherits
their operating rule: baselines are regenerated on a quiet machine and the
regenerated diff is read, never accepted blind.

## 6. Fuzzing

A ninth target beside the existing eight in `fuzz/fuzz_targets/`:
`source_parse.rs`, seeded from the corpus by `fuzz/seed_corpus.py`.

Per the seed-class rule carried from the sibling `axeyum` workspace — where a
wrong `unsat` shipped because the differential fuzz structurally could not
generate the degenerate argument — the seed corpus must **deliberately** contain
each degenerate case, since a sweep over real files will not produce them:

* nesting deep enough to exhaust a recursive parser (`REQ-SYN-3`);
* an unterminated string, comment, or brace at end of file;
* a raw control byte inside a string literal;
* an identifier at the interner's boundary conditions;
* a file that is entirely comments, or entirely one token;
* a truncated multibyte UTF-8 sequence;
* inline `asm` with unbalanced quotes in its constraint string.

The properties the target asserts: no panic, no abort, no unbounded time, and a
diagnostic list whose spans all lie inside the input.

## 7. Reporting rules

Carried from `development/contributing-docs.md`, and they are the reason this
document exists rather than a spreadsheet:

* **the command and the commit go next to the number**, or the number does not
  get written down;
* **say which build** — `maturin develop` is debug, and a debug parser number is
  not the one that ships;
* a number produced on a loaded machine is not evidence. The arch gate has
  recorded false failures under load, and a parser benchmark is more sensitive,
  not less;
* coverage and throughput are reported **together**, always. A throughput
  improvement quoted without its coverage number is not a result.
