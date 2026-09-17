# Full-sample loss investigation and regression repairs

> **Kind:** record · **Date:** 2026-09-17

This record wraps the regression work on source commit `e7fb91b3f0c33ed87ca9aa648a888303296a455c`, based on `8b02bd4bb36953edbf97408520f353e3e6a3c759`. The fixes are committed and applied in the original shared checkout. Final whole Python validation is still running; this is not an all-green release or a new leaderboard result.

## Findings

The supplied comparison contains 7,077 Union losses and 5,096 gains, net −1,981 function entries. ARM accounts for 6,635 losses, and 5,608 previously passed only type matching. Separate binaries and optimisation settings count as separate entries.

Previous replay preparation could silently retain debug information when stripping failed, choose a binary by ambiguous prefix, and mask legitimate odd x86 addresses. Exact lookup, fail-closed stripping, section checks, input hashes and architecture-aware address handling now make those comparisons reproducible. Matched stripped/debug controls support debug-assisted type recovery as an important cause of the ARM score difference; they do not explain every loss.

Ten expanded loss controls match or exceed prior correctly stripped type scores. BL_ReadBuf improves from 0 to 0.3333. A7105Config recovers from 0 to 0.25, matching its prior correctly stripped result; the debug-assisted perfect score is not restored. No full DecBench rerun or new Union score is claimed.

## Repairs

- CFG walking checks executable membership at each linear step and bounds decoder input. U-Boot __div0 no longer decodes following read-only data; its actual hang call survives.
- Fully versioned incoming argument evidence prevents compatibility return names from erasing ARM input identity. Betaflight A7105Config uses its pointer argument instead of an uninitialised return variable.
- Paired-result recovery requires both callee outputs and bounded caller consumption. It follows full-width spills across CFG edges, invalidates overlapping writes, excludes padding, self-zeroing and later calls, and uses actual stack reads from uniquely resolved local receivers. OpenSSH sys_tun_outfilter retains scalar ssh_err, while genuine wide results survive register/spill/partial-read controls. Two fix-induced Rust undefined reads were removed.
- ARM64 MRS preserves its actual 64-bit destination through a typed opaque intrinsic with an encoded register selector. This removes phantom x0 arguments in flag helpers. It preserves read effects, without claiming a complete symbolic system-register model; privileged SP_EL0 has compile/lift coverage rather than claimed runtime execution.
- PLT receiver lookups reuse an index extracted during the existing ProgramImage parse. A real compiled shared-library test proves zero additional parses for repeated warmed lookups.
- Exact argument analysis repeats only when compatibility return-register names overlap physical argument slots. ARM/AArch64 overlap retains the proof; unrelated return registers avoid redundant value numbering.

The compiled reproducers live in [the CFG fixtures](../../../tests/fixtures/cfg/). Reusable replay preparation is [tools/decbench_inputs.py](../../../tools/decbench_inputs.py), covered by [real-input preparation tests](../../../python/tests/test_decbench_replay_inputs.py).

Topic commits: `1ff3f584` (initial repairs), `db7274dc` (return provenance), `69792b05` (MRS effects), and `e7fb91b3` (PLT indexing and argument-analysis cost).

## Validation

All measurements below use the isolated source above. Both mandated `uv run maturin develop` and `uv run maturin develop --release` builds succeeded; measurements used the release extension. Compiler-produced fixtures and actual target/reference execution supply controls, without invented binary inputs.

| Command or control | Result |
| --- | --- |
| `cargo test --features python-ext -- --test-threads=1` | 5,113 passed, 17 ignored, zero failures across 35 library/integration/doc groups |
| `cargo test --features python-ext` | Initial parallel run failed two discovery deadline comparisons; no claim that those failures reproduced on baseline |
| `cargo test --features python-ext --lib ir::value_number::tests` | 66 passed |
| `uv run pytest python/tests/test_pipeline_profile_report.py -q` | 7 passed |
| Original matched-input, Rust undefined-read and compiled return controls | 8 groups passed; recovered C matches verified predecessors where required |
| Actual ARM64 flag round trips | 4 functions, 94 execution cases passed |
| `uv run python tools/arch_roundtrip.py --check --jobs 4` | Exit1; 205 stored regression keys versus untouched 209; one new non-reproducible candidate described below |
| `uv run python tools/perf_gate.py` | Exit1 against stored thresholds; all three final minima within 5% of the live untouched baseline |
| `bash scripts/feature-build-gate.sh` | Fuzz passes; 11 root configurations fail only the two baseline obsolete recover_types benchmark calls |
| `uvx ruff check python/` / explicit-file `rustfmt --check` / `uv run python tools/gen_native_stub.py --check` | Pass |
| `uvx ty check python/` / `uvx ruff format --check python/` | Same baseline 386 diagnostics / 8 unformatted files |
| `uv run pytest python/tests/` after e7fb source commit | Running at wrap-up; terminal failure attribution remains pending |

The architecture candidate is `112_recursion_shapes:armv7_a32:O2:tail_countdown`. Detailed final and baseline executions each pass all four fixture exports, 22 cases per function. Four concurrent final repeats also pass, and baseline/final emit identical tail_countdown C on one identical compiled binary. The raw full-run failure remains disclosed; no changed product semantics were reproduced.

Both discovery deadline tests pass in serial focused runs on final and baseline; focused parallel baseline also passes. The full serial Rust run passes without weakened assertions. Per-function timing sensitivity is plausible but the original parallel failure cause is unproven.

The older frozen `69792b05` whole Python suite finished with 111 failed, 4,748 passed, 102 skipped, 128 deselected and 860 xfailed. Its only new failure candidate is the parse-budget test fixed by e7fb and passing in the final focused run. Nine aggregate failure sections match untouched assertions, except one fewer Rust undefined read. This older run cannot substitute for the running final suite. Pytest heading parsing was corrected to recognise short underscore headings; ten structural-improvement warnings are unchanged, superseding an earlier report that they disappeared.

## Performance

`tools/perf_gate.py` measures retired user instructions, minimum of three runs, on identical input binaries and verified release extensions. Stored thresholds already fail on untouched 8b02; their large excess is not attributed to these repairs.

| Reference | Untouched 8b02 | Final e7fb | Final delta |
| --- | ---: | ---: | ---: |
| Rust release | 3,384,497,847,376 | 3,234,750,496,130 | −4.42% |
| Go | 667,537,961,525 | 700,702,084,678 | +4.97% |
| Rust debug | 2,630,368,099,085 | 2,600,351,365,091 | −1.14% |

Go is 27.42% below the pre-optimization repair's 965,411,945,298 instructions. Final spreads are 8.1%, 9.2% and 31.9% respectively; untouched spreads are 5.7%, 20.7% and 20.3%. Differences within that variation do not establish robust performance improvement over untouched. The older stored performance baseline is not restored.

## Delivery and remaining work

The shared checkout's final debug/release builds and original/ABI/undefined-read/profile/flag controls pass. Applying the latest five-file patch preserved 119 unrelated dirty paths. A read-only final audit covers 21 owned paths: 18 exactly match the isolated source; the other three retain existing solver-description, DWARF-initializer and runtime-image helper edits. Concurrent work is excluded from this topic's commits.

Complete the already-running final Python suite, compare actual assertion contents against untouched baseline, and resolve any newly confirmed regression before declaring overall completion. Local evidence and resume state are under `$HOME/.cache/glaurung/regression-review/2026-09-17T14-19-43-0400/`, with `state.json`, `completion-audit.json`, logs and per-control receipts. Session 77923 tracks the current Python run; process handles are machine-local and require live verification.

The accompanying [validation snapshot](validation.json) records tested source identity, terminal measurements and pending status. No autonomous DecBench upstream issues, comments or pull requests were created.
