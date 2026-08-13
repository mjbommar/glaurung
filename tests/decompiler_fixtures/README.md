# Decompiler fixture gate

A **fail-closed, deterministic, ratcheting** semantic-fidelity gate for the
decompiler. The DecBench-style metrics (type_match / GED / byte_match) reward
plausible-looking output; this corpus instead checks that the decompilation is
*behaviourally faithful* — that it computes the same thing the original binary
does, and that structural facts an analyst relies on survive lowering.

## Layout

| path | role |
|------|------|
| `src/` | numbered C, C++, Rust, Go, and assembly reference programs: focused bug-class fixtures, the 66-project curriculum (`15_*` through `80_*`), language/runtime fixtures, and coverage-directed regressions |
| `manifest.py` | declarative oracle: required (exported) functions, pointer buffer sizes, length-arg clamping, exact boundary/switch/packet vectors, `skip_exec`, and per-function `STRUCTURAL` assertions |
| `sets.toml` | named, validated `dectest` selections, including the complete curriculum and its subject-area subsets |
| `curriculum_oracle.c` | independently checks canonical examples for the original curriculum tranche (`15_*` through `30_*`) before those programs serve as differential references |
| `baseline.json` | committed per-function status for applicable `{fixture}:{compiler}:{opt}` lanes, plus the `__toolchain__` fingerprint that produced it |
| `structural_baseline.json` | committed structural map (closure per style, effect predicates, fabricated-name flags, def-before-use violations) |
| `arch_baseline.json` | committed execution-differential results for the required x86-64, x86-32, AArch64, and ARMv7 architecture lanes |
| `structural.py` | structural report implementation shared by the structural test and baseline generator |
| `toolchain/Dockerfile` | the fingerprinted compile toolchain (see below) |
| `../../tools/diff_decompile.py` | the execution-differential worker: recompile decompiled C, call original vs. recompiled with identical inputs in an isolated subprocess, diff full-width return + every mutable buffer |
| `../../tools/fixture_harness.py` | compiles the matrix, runs the gate, writes/validates baselines |
| `../../tools/fixture_toolchain.py` | runs every compile inside the pinned toolchain; fingerprints it |
| `../../tools/gen_structural_baseline.py` | regenerates `structural_baseline.json` |
| `../../tools/arch_roundtrip.py` | runs and ratchets the cross-architecture execution differential |

The local execution matrix currently applies GCC/Clang at O0/O2 to C and C++
fixtures and rustc at O0/O2 to Rust fixtures. `fixture_harness._fixture_sources`
does not currently include the Go sources. The hand-written assembly source is
used by a focused Rust CFG regression rather than by the Python matrix. Keeping
those boundaries explicit matters: merely living in `src/` does not prove that a
source participates in every gate. The manifest and tests, rather than a prose
count here, are authoritative when the corpus grows.

## Curriculum corpus

`manifest.CURRICULUM_PROJECTS` is the authoritative catalog. It currently names
66 recognizable programs:

| fixtures | subject area |
|----------|--------------|
| `15_*`–`19_*` | trees, open-address hashing, heaps, and disjoint sets |
| `20_*`–`23_*` | BFS, DFS, Dijkstra, and topological sorting |
| `24_*`–`30_*` | merge sort, KMP, sparse matrices, iteration, polynomials, and stencils |
| `31_*`–`35_*` | dynamic programming |
| `36_*`–`40_*` | sorting and selection |
| `41_*`–`45_*` | tokenization, stack evaluation, codecs, and string algorithms |
| `46_*`–`50_*` | bitsets, Huffman coding, Gray code, CRC/checksums, and varints |
| `51_*`–`54_*` | stream/hash/PRNG/SHA-256 kernels |
| `55_*`–`64_*` | number theory, exact arithmetic, matrices, and numerical methods |
| `65_*`–`70_*` | physics and chemistry kernels |
| `71_*`–`76_*` | finance and market kernels |
| `77_*`–`80_*` | LRU cache, ring buffer, segment tree, and trie |

These fixtures test behavior, not source-text similarity. The tree and graph
programs use bounded flat representations so seeded and malformed inputs remain
terminating and memory-safe. Pointer-indexing functions declare their safe input
domains in `manifest.py`; an absent contract is a test failure.

See [the curriculum corpus guide](../../docs/development/decompiler-curriculum-corpus.md)
for the original `15_*`–`30_*` tranche's representations, stressors, and
revision-bound capability map. Use the manifest and `sets.toml` for the complete
current catalog and selectors.

## Tests

- `python/tests/test_decompiler_fixture_harness.py` — fail-closed **unit** tests
  (portability, determinism, exact ABI, infra-status handling). Fast; every PR.
- `python/tests/test_decompiler_fixture_compile.py` — strict compile gate
  (`-Wall -Wextra -Werror`, every applicable C/C++ fixture × gcc/clang × O0/O2).
  Fast; every PR.
- `python/tests/test_decompiler_fixture_toolchain.py` — fingerprinted toolchain
  and compiler-provisioning contracts.
- `python/tests/test_decompiler_curriculum_corpus.py` — exact checks for the
  original tranche plus complete-catalog/source/contract checks for all current
  curriculum entries.
- `python/tests/test_decompiler_curriculum_reference.py` — compiles and executes
  independent known-answer checks from `curriculum_oracle.c` for the original
  16 curriculum projects (`15_*`–`30_*`).
- `python/tests/test_decompiler_fixture_matrix.py` — the execution-differential
  **matrix** vs. `baseline.json`. Marked `slow`.
- `python/tests/test_decompiler_fixture_structural.py` — the **structural lane**
  vs. `structural_baseline.json`. Marked `slow`.
- `python/tests/test_decompiler_arch_roundtrip.py` — fail-closed and ratcheting
  contracts for the cross-architecture differential.
- `python/tests/test_dectest_selection.py` and `test_dectest_equivalence.py` —
  named-set/selector integrity and equivalence between scoped and full verdicts.
- `python/tests/test_local_gate_fails_closed.py` — the heavy local gate may not
  report green when a required lane is absent.

Run tests through the locked project environment. Focused examples:

```bash
uv run pytest python/tests/test_decompiler_fixture_harness.py
uv run pytest python/tests/test_decompiler_curriculum_reference.py
uv run pytest -m slow python/tests/test_decompiler_fixture_matrix.py
uv run pytest -m slow python/tests/test_decompiler_fixture_structural.py
```

**For iterating, don't run the matrix.** `tools/dectest.py` runs this same
harness over a selection, with the same compilers, seeded vectors, and baseline
comparison. Named sets live in `sets.toml`; selection tests require every set to
have a description and resolve to at least one lane. See
[docs/development/decompiler-testing.md](../../docs/development/decompiler-testing.md).

```bash
tools/dectest.py 13_loop_early_exit:gcc:O0:sum_positive --show
tools/dectest.py @loops
tools/dectest.py @curriculum --full
tools/dectest.py @curriculum-sorting --show
tools/dectest.py --list-sets
```

Selectors have the form `fixture[:compiler[:opt[:function]]]` and accept globs.
A selector that matches nothing is an error. Scoped runs intentionally cannot
write a baseline.

## Cross-architecture gate

The ordinary fixture matrix is a host x86-64 gate even when its sources are
portable. `tools/arch_roundtrip.py` separately cross-compiles fixtures and runs
the same isolated behavioral differential over the required architecture and
optimization matrix recorded in `arch_baseline.json`. Its x86-64 control lanes
must agree with `baseline.json`; missing compilers, empty lanes, build failures,
unknown statuses, and control disagreements fail closed.

```bash
tools/arch_roundtrip.py --check
tools/arch_roundtrip.py --arch aarch64 --opt O0 03_loop_shapes
```

The exact required targets are defined by `arch_roundtrip.REQUIRED_ARCHES` and
may grow. See the maintained decompiler testing guide for target-specific gaps
and the distinction between host-width round trips and target-width rebuilds.

## Per-function statuses

`pass` / `fail` are decompiler results (a known `fail` stays visible in the
baseline). `structural` means not execution-differential (a callback, a
void-no-buffer effect, a pointer return) — the structural lane must carry an
assertion for it. `missing` (a required export absent), `nocases` (no vectors
generated) and `timeout` (the worker exceeded its wall clock) are
**infrastructure** failures: they fail CI and `--write-baseline` refuses to record
them.

`timeout` is deliberately NOT `fail`: exceeding a wall clock is not evidence that
a decompilation is wrong, and recording it as a semantic verdict bakes machine
speed into the baseline. This is not hypothetical — `guarded_spin`'s `spin` guard
was driven nonzero by the boundary sweep, so every such vector ran a `volatile`
increment loop to 32-bit wraparound (~0.9s per vector, per binary). It passed on a
24-core workstation and timed out on a 4-vCPU CI runner. A parameter guarding an
unbounded path must be pinned with the manifest's `arg_values`, so the verdict
depends on the decompilation and not on the hardware.

## Ratchet: refreshing a baseline

The gate fails on **regressions** (a `pass` that now fails) *and* on unrecorded
**improvements** (a baseline `fail` that now passes) — so the baseline can never
silently drift. After you land a real decompiler improvement and have
**independently verified the behavioural differential**, refresh:

```bash
# Host execution matrix; refuses infrastructure failures.
uv run python tools/fixture_harness.py --write-baseline

# Structural map; refuses unasserted structural gaps.
uv run python tools/gen_structural_baseline.py

# Required cross-architecture matrix; requires a clean control lane.
tools/arch_roundtrip.py --write-baseline
```

Both share `manifest.FIXTURE_FUZZ` so the committed baseline and the gate
exercise identical (stable-seeded) vectors.

## The fingerprinted compile toolchain

Two different compilers decide a verdict: the one that builds the fixture (its
codegen idioms are what the decompiler must recover) and the one that rebuilds our
decompiled C (gcc ≥ 14 turns several diagnostics gcc 11 only warns about into hard
errors, so "decompiled C failed to compile" is a function of the compiler). Against
whatever a developer's host ships, the per-function baseline is a snapshot of one
machine and cannot reproduce in CI.

So **every** compile the primary host fixture gate performs — fixture builds,
the strict compile lane, the recompile of our own output, and the structural
lane's builds — runs inside the image built from `toolchain/Dockerfile` (Ubuntu
22.04: gcc/g++ 11.4, clang/clang++ 14, glibc 2.35, plus the fingerprinted Rust
compiler). Only compilation is containerised; the objects execute natively,
which is safe because the image's glibc floor is older than any host we build
on. The architecture gate uses target cross-compilers for its foreign fixture
builds and the pinned toolchain for the host rebuild side; its baseline records
both identities.

The image is not bit-reproducible: its base is pinned by digest, but the compiler
packages come from the live Ubuntu archive. The guarantee is the **fingerprint**,
not the image — see below.

`baseline.json` records the observed compiler versions under `__toolchain__`, and
the gate asserts they match before comparing any verdict — a mismatch fails loudly
with a refresh instruction instead of reporting phantom regressions. Because the
image provisions clang++'s C++ runtime, no lane is `env-missing` any more; a lane
whose environment availability changes in either direction is a hard failure
(`fixture_harness.env_lane_problems`), so a lane can never silently drop out of the
comparison.

`GLAURUNG_FIXTURE_TOOLCHAIN=host` runs the host compilers instead. It is never
silent: the fingerprint records `mode: host`, so such a run cannot be compared
against the pinned baseline.

## Relationship to DecBench and the heavy gate

This directory owns the repository-native semantic fixture corpus. External
DecBench programs and metric baselines are separate: GED, `type_match`, and
`byte_match` do not substitute for this corpus's execution differential.
`scripts/decbench-local-gate.sh` composes the Rust tests, this host fixture
matrix, the cross-architecture matrix, external behavioral round trips, and the
external metric ratchet. Required external inputs fail closed unless the script
documents and reports an explicit waiver.

```bash
scripts/decbench-local-gate.sh
```

## Definition-before-use

`src/ir/verify_defs.rs` checks the AST that is actually printed (the output of
`ast::prepare_for_decbench`, after which renderers are formatting-only) for reads
of values the decompiler never defined — the emitted C reading an uninitialised
variable, which recompiles to garbage and is invisible to type_match / GED /
byte_match. Violations are emitted as `// glaurung-verify:` comments (comments, so
the compiled C is unchanged) and recorded per function in
`structural_baseline.json`: known ones stay visible, a new one fails the gate.

## Portability and speed

Scratch space resolves `GLAURUNG_FIXTURE_TMPDIR` → `TMPDIR` → system tempfile —
no machine-specific path. Lanes run concurrently (`--jobs`, default cores−1 capped
at 8, or `GLAURUNG_FIXTURE_JOBS`): lanes are independent and per-function fuzz
seeds are stable, so concurrency changes wall-clock, not verdicts.
