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
| `baseline.json` | committed per-function status for every `{fixture}:{cc}:{opt}` lane |
| `structural_baseline.json` | committed structural map (closure per style, effect predicates, fabricated-name flags) |
| `../../tools/diff_decompile.py` | the execution-differential worker: recompile decompiled C, call original vs. recompiled with identical inputs in an isolated subprocess, diff full-width return + every mutable buffer |
| `../../tools/fixture_harness.py` | compiles the matrix, runs the gate, writes/validates baselines |
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
assertion for it. `missing` (a required export absent) and `nocases` (no vectors
generated) are **infrastructure** failures: they fail CI and `--write-baseline`
refuses to record them.

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

## Portability

Scratch space resolves `GLAURUNG_FIXTURE_TMPDIR` → `TMPDIR` → system tempfile —
no machine-specific path. A clang C++ lane on a host without the C++ runtime is a
*probed, declared* env gap (never a silent skip); CI provisions the runtime so
those lanes run.
