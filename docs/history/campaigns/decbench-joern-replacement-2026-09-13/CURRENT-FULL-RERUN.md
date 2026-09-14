# Current-code full DecBench rerun

> **Kind:** completed internal measurement record · **Run:** 2026-09-13–14 · **Status:** complete and independently audited

## Plain-English result

The full rerun completed successfully on the newest clean, committed Glaurung
revision available when the run was frozen. It generated artifacts for all 803
manifest binaries, emitted 94,485 unique function identities, evaluated every
emitted identity, and exited with status 0.

When merged locally with the published DecBench comparison universe, this
column ranks first on GED, type match, byte match, and Union. This is an
**internal ranking calculation**, not an official DecBench publication or
submission. No issue, comment, pull request, result, or other material was
posted upstream.

| Metric | Perfect | Shared denominator | Audited rate | Prior rate | Change |
|---|---:|---:|---:|---:|---:|
| GED | 34,512 | 91,288 | **37.806%** | 32.275% | **+5.530 pp** |
| Type match | 20,124 | 86,671 | **23.219%** | 21.812% | **+1.406 pp** |
| Byte match | 6,375 | 94,487 | **6.747%** | 5.893% | **+0.854 pp** |
| **Union** | **43,547** | **94,487** | **46.088%** | 41.553% | **+4.534 pp** |

The exact perfect-count gains over the clean `229fbb1` run are +5,049 GED,
+1,219 type, +812 byte, and +4,311 Union. Denominators changed because the new
column makes more functions measurable; percentages above use the newly
audited shared universe, not the smaller historical denominator.

## Why this is not every byte in the shared worktree

The run used `e170a2b4a8946b84808890fd5a09d46ce7cf6a66`, the newest clean,
committed revision available when preparation finished. At freeze time:

- `master` and `origin/master` pointed to
  `0892552157be6bd9267007231419ff6606a2dd38`;
- the campaign branch and clean run worktree pointed to the newer `e170a2b4`;
- the shared `master` worktree contained 16 modified source files owned by
  concurrent work;
- those uncommitted files had no stable identity and could change during a
  multi-hour run.

Building the shared dirty tree would have mixed incomplete work from multiple
agents and made the result irreproducible. This result therefore means
"latest clean committed code at run freeze," not "whatever happened to be in
the shared checkout at some later instant." Any subsequently committed source
changes require a separately named rerun.

## Frozen provenance

| Input | Identity |
|---|---|
| Glaurung source | `e170a2b4a8946b84808890fd5a09d46ce7cf6a66` |
| Clean run worktree | `~/.cache/glaurung/decbench-latest-e170a2b4` |
| Release CLI SHA-256 | `9bf526586196dff807dd4e5b1529b68f80ed03b20e9a8e6487c7d0a3d49bdec5` |
| Native extension SHA-256 | `5015721795bdf67c4272c6f71c540f1d72c61301c5f38017cd3a5484134b8110` |
| Final run-only driver SHA-256 | `988f701f35c4dbc6e8ba28f6b60a4b7b111a1d60fc162248c510f5e995e4d2ac` |
| DecBench | `f76dae075d4d82004fb21132b3f15e43b680e179` |
| Dataset | `e5eb576d66ee36793b800a4dd45e291e0add4472` (`full`) |
| Dataset population | 803 binaries / 94,575 manifest functions |
| Output column | `glaurung-e170a2b4-exact-adapter` |

The run-only driver changed measurement orchestration only: exact current
adapter routing, deterministic sharding, bounded recovery, project exclusion,
and an include-key file. It did not change the Glaurung executable. The final
driver hash differs from the earlier live snapshot because bounded recovery
controls were added before the three timed-out binaries were rerun.

## Adapter policy

For each manifest binary, the driver resolved requested function addresses and
followed DecBench's current Glaurung adapter policy:

- at most 400 resolved addresses: one narrow `--vas` invocation;
- more than 400: one `--all --limit 30000` invocation, then narrow returned
  functions to manifest addresses;
- per-function internal timeout: 20,000 ms;
- first-pass outer timeout: 600 seconds per binary;
- recovery outer timeout: 3,600 seconds for only the missing binary keys;
- one C artifact and one metadata TOML per completed binary.

This loads each binary once per invocation and does not decompile a function a
second time merely to recover its signature.

## Generation coverage and timing

The first pass produced 800/803 binary artifacts. The three 600-second misses
were recovered individually with the longer bounded timeout:

| Recovery binary | Manifest functions | Wall time | Peak RSS |
|---|---:|---:|---:|
| O0 Betaflight STM32F405 | 4,018 | 12m16s | 1,803,044 KiB |
| O2 Betaflight STM32F405 | 4,008 | 12m23s | 1,804,132 KiB |
| O2 Bash | 1,557 | 14m38s | 1,563,380 KiB |

First-pass lanes were intentionally concurrent:

| Lane | Binary artifacts | Manifest functions | Wall time | Peak RSS |
|---|---:|---:|---:|---:|
| Coreutils | 327/327 | 7,022 | 34m04s | 1,757,256 KiB |
| Non-Coreutils shard 0 | 118/119 | 19,311 | 29m08s | 1,797,440 KiB |
| Non-Coreutils shard 1 | 119/119 | 23,473 | 39m48s | 1,379,412 KiB |
| Non-Coreutils shard 2 | 118/119 | 18,559 | 46m43s | 1,801,580 KiB |
| Non-Coreutils shard 3 | 118/119 | 16,537 | 42m29s | 5,110,640 KiB |

Final artifact coverage is 803 C files and 803 TOMLs. Identity reconciliation
found:

- 94,575 manifest identities;
- 94,485 emitted marker/TOML identities;
- 90 unresolved identities across 16 binaries;
- zero duplicate identities, extra identities, or recorded failed functions.

The 90 unresolved names are principally entry/start/TLS aliases, U-Boot
start/jump aliases, and `__printf__` in two gzip optimization cells. They are
an explicit 0.095% identity-coverage gap, not silently discarded successes.
Coverage improved from 94,358 scored functions in the prior run to 94,485,
adding 127 scored identities and reducing the unscored manifest gap from 217
to 90.

## Evaluation timing and direct verification

Pinned `evaluate-tree` ran with 12 workers and exited 0:

| Measurement | Value |
|---|---:|
| Wall time | 4h00m04s |
| Aggregate user CPU | 61,132.63s |
| Aggregate system CPU | 3,172.85s |
| Average CPU utilization | 446% |
| Peak RSS | 7,672,756 KiB |
| Swap | 0 |
| Binaries | 803 |
| Unique evaluated identities | 94,485 |

A direct recount of the generated `function_results.json` independently found
803 groups, 94,485 rows, 94,485 unique identities, and 94,485 `decompiled=true`
flags. It reproduced the self-column counts exactly:

| Metric | Finite self values | Perfect |
|---|---:|---:|
| GED | 89,009 | 34,512 |
| Type match | 86,669 | 20,124 |
| Byte match | 94,485 | 6,375 |
| Union | 94,485 emitted identities | 43,547 |

These self denominators explain the rounded 38.8%, 23.2%, 6.7%, and 46.1%
shown by the one-column local scoreboard. They are not the denominators used
for cross-decompiler ranking. The independent audit merged the new fragments
with the pinned published per-function data and derived shared denominators of
91,288 GED, 86,671 type, and 94,487 byte/Union, producing the rates in the
opening table.

## Local rank interpretation

Against the columns in the pinned published DecBench data, the new column is
locally first on all four measures:

| Measure | Glaurung | Next published column | Margin in perfect functions |
|---|---:|---:|---:|
| GED | 34,512 | Kuna, 33,146 | +1,366 |
| Type match | 20,124 | angr, 6,367 | +13,757 |
| Byte match | 6,375 | Kuna, 3,061 | +3,314 |
| Union | 43,547 | Kuna, 36,348 | +7,199 |

This is not an official rank until a human follows DecBench's contribution
rules and the maintainers accept and recompute the data. It also describes the
pinned full corpus and these metrics, not arbitrary real-world binaries.

## Cell-level comparison with `229fbb1`

Exact-identity comparison covered 94,389 identities common to the old and new
stored result sets, plus 96 identities present only in the new set. The old
set contained no identities absent from the new set. Thirty-one old identities
had rows but no finite metric, which is why the increase in scored coverage is
127 rather than 96.

| Metric | Non-perfect/missing to perfect | Perfect to non-perfect | Net common-identity gain | New-only perfect |
|---|---:|---:|---:|---:|
| GED | 5,676 | 632 | +5,044 | 5 |
| Type match | 1,585 | 366 | +1,219 | 0 |
| Byte match | 1,246 | 434 | +812 | 0 |
| Union | 5,041 | 735 | +4,306 | 5 |

The improvement is broad rather than fixture-local. The largest Union gain
clusters are OpenSSH (+1,369), Betaflight (+794), Crazyflie (+562), Bash
(+493), Cleanflight (+406), Coreutils (+203), and tar (+167). The largest
regression clusters are OpenSSH (302), Crazyflie (142), Betaflight (65), Bash
(33), Cleanflight (24), ChibiOS (23), and U-Boot (21). These regressions are
real follow-up inventory, but they do not overturn the large net gains.

The regression distribution also argues against benchmark gaming: changes are
spread across hosted utilities, cryptographic/network applications, embedded
firmware, libraries, and bootloader code, and hundreds of formerly perfect
cells moved backward while thousands moved forward. The benchmark records the
net effect of general decompiler changes; it was not made monotonic by special
casing DecBench functions.

## Artifact locations and hashes

Large generated data remains outside Git:

| Artifact | Location | SHA-256 |
|---|---|---|
| Preserved function results | `~/.cache/glaurung/decbench-current-e170a2b4/function_results-e170a2b4.json` | `c1439af9a575fef649e612ce10c06fd7a3e4dcd69552a74e82c173323fab89d4` |
| Preserved local scoreboard | `~/.cache/glaurung/decbench-current-e170a2b4/scoreboard-e170a2b4.toml` | `fd9a4fdb6df87650093629efd0aa26904bb29b52410de79559b778a42f04577c` |
| Independent merged audit | `~/.cache/glaurung/decbench-current-e170a2b4/audited-score-e170a2b4.json` | `b3549cfce21f75a40b6414e2287d94f6591164b35a5da129b3726d58bba2db58` |
| Evaluation stdout | `~/.cache/glaurung/decbench-current-e170a2b4/evaluate-tree.stdout` | recorded locally |
| Evaluation resource record | `~/.cache/glaurung/decbench-current-e170a2b4/evaluate-tree.time.stderr` | recorded locally |
| Historical audited baseline | `~/.cache/glaurung/decbench-full/audited-score-clean-229fbb1.json` | recorded locally |

The preserved copies hash-identically to the final files in the materialized
tree. The audit reads the pinned manifest, published per-function dataset, and
raw `evaluated/*.toml` fragments; it does not trust the generated scoreboard.

## Completion audit

| Gate | Evidence | Result |
|---|---|---|
| Reconcile 803 binary keys | 803 C + 803 TOML artifacts | Pass |
| Investigate first-pass failures | Three exact keys isolated and recovered with a 3,600s bound | Pass |
| Audit identities | 94,485 unique emitted; 90 named-resolution gaps; no duplicates/extras | Pass with explicit gap |
| Run all metrics | Pinned `evaluate-tree`, 803 stored artifacts, exit 0 | Pass |
| Verify raw counts | Direct JSON recount matches scoreboard perfect counts | Pass |
| Use shared comparison universe | Independent merge audit; denominators 91,288 / 86,671 / 94,487 | Pass |
| Compare old/new cells | 94,389 common identities plus new-only coverage classified | Pass |
| Reproduce independent audit | Fresh rerun is byte-identical, SHA-256 `b3549cfce21f75a40b6414e2287d94f6591164b35a5da129b3726d58bba2db58` | Pass |
| Preserve timing and hashes | This record and external artifacts | Pass |
| Respect upstream boundary | No DecBench post, issue, comment, PR, or repository mutation | Pass |

The exact recheck commands, direct counts, shared-universe arithmetic, and all
90 unresolved names are recorded in
[RESULT-VERIFICATION.md](RESULT-VERIFICATION.md).

The full rerun objective is complete. Any submission remains a separate,
human-only action under DecBench's rules.
