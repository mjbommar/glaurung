# Decompiler fixture gate

A **fail-closed, deterministic, ratcheting** semantic-fidelity gate for the
decompiler. The DecBench-style metrics (type_match / GED / byte_match) reward
plausible-looking output; this corpus instead checks that the decompilation is
*behaviourally faithful* — that it computes the same thing the original binary
does, and that structural facts an analyst relies on survive lowering.

## Layout

| path | role |
|------|------|
| `src/NN_*.c`, `src/10_*.cpp` | 10 fixtures, each targeting one bug class (conditional polarity, integer widths, loops, switches, cleanup/FSM, calling conventions, packet parsing, indirect dispatch, memory effects, C++ runtime shapes) |
| `manifest.py` | declarative oracle: required (exported) functions, pointer buffer sizes, length-arg clamping, exact boundary/switch/packet vectors, `skip_exec`, and per-function `STRUCTURAL` assertions |
| `baseline.json` | committed per-function status for every `{fixture}:{cc}:{opt}` lane, plus the `__toolchain__` fingerprint that produced it |
| `structural_baseline.json` | committed structural map (closure per style, effect predicates, fabricated-name flags, def-before-use violations) |
| `toolchain/Dockerfile` | the fingerprinted compile toolchain (see below) |
| `../../tools/diff_decompile.py` | the execution-differential worker: recompile decompiled C, call original vs. recompiled with identical inputs in an isolated subprocess, diff full-width return + every mutable buffer |
| `../../tools/fixture_harness.py` | compiles the matrix, runs the gate, writes/validates baselines |
| `../../tools/fixture_toolchain.py` | runs every compile inside the pinned toolchain; fingerprints it |
| `../../tools/gen_structural_baseline.py` | regenerates `structural_baseline.json` |

## Tests

- `python/tests/test_decompiler_fixture_harness.py` — fail-closed **unit** tests
  (portability, determinism, exact ABI, infra-status handling). Fast; every PR.
- `python/tests/test_decompiler_fixture_compile.py` — strict compile gate
  (`-Wall -Wextra -Werror`, all 10 × gcc/clang × O0/O2). Fast; every PR.
- `python/tests/test_decompiler_fixture_matrix.py` — the execution-differential
  **matrix** vs. `baseline.json`. Marked `slow`.
- `python/tests/test_decompiler_fixture_structural.py` — the **structural lane**
  vs. `structural_baseline.json`. Marked `slow`.

Run the slow lanes with `-m slow` (they build + decompile the whole corpus).

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
# execution matrix (4 lanes, ~15 min):
python tools/fixture_harness.py --write-baseline        # refuses infra failures
# structural map:
python tools/gen_structural_baseline.py
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

So **every** compile the gate performs — fixture builds, the strict compile lane,
the recompile of our own output, and the structural lane's builds — runs inside the
image built from `toolchain/Dockerfile` (Ubuntu 22.04: gcc/g++ 11.4, clang/clang++
14, glibc 2.35). Only compilation is containerised; the objects execute natively,
which is safe because the image's glibc floor is older than any host we build on.

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
