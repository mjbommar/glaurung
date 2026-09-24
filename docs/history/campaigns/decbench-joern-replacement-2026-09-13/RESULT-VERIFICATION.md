# Full-rerun result verification

> **Kind:** record · **Date:** 2026-09-14 · **Scope:** `glaurung-e170a2b4-exact-adapter`

## Verdict

The completed full-corpus result is internally consistent and reproducible
from its preserved inputs. Four separate checks agree on coverage and perfect
counts:

1. direct inspection of all stored C and metadata artifacts;
2. a direct recount of the generated `function_results.json`;
3. a fresh rerun of `tools/decbench_audit_full.py` against the pinned manifest,
   raw evaluated fragments, and published comparison data;
4. a separate direct union of the published and new result JSONs by exact
   identity, recomputing every denominator, perfect count, rate, and rank
   without the scoreboard or audit helper.

The fresh merged audit was byte-identical to the first audit:

```text
b3549cfce21f75a40b6414e2287d94f6591164b35a5da129b3726d58bba2db58
```

This verifies the local result. It is not an official DecBench submission or
rank, and no upstream action was taken.

## Artifact-level check

The materialized tree contains:

| Check | Result |
|---|---:|
| Glaurung C artifacts | 803 |
| Glaurung metadata TOMLs | 803 |
| Matching C/TOML path pairs | 803/803 |
| Parseable TOMLs | 803/803 |
| TOMLs with `timeout=true` | 0 |
| Non-empty `failed_functions` lists | 0 |
| Function markers across C artifacts | 94,485 |

This check is independent of the generated scoreboard. It scans the stored
artifacts directly.

## Manifest reconciliation

Joining exact `(project, optimization, binary, function)` identities gives:

| Population | Count |
|---|---:|
| Manifest rows | 94,575 |
| Unique manifest identities | 94,575 |
| Generated result rows | 94,485 |
| Unique generated identities | 94,485 |
| Missing manifest identities | 90 |
| Out-of-manifest identities | 0 |
| Affected binary/optimization cells | 16 |

Every unresolved identity is listed below:

| Project | Opt | Binary | Count | Names |
|---|---|---|---:|---|
| crazyflie | O0 | `CMSIS_DAP` | 1 | `start` |
| crazyflie | O2 | `CMSIS_DAP` | 1 | `start` |
| crazyflie | O2-noinline | `CMSIS_DAP` | 1 | `start` |
| dexter | O0 | `dexter` | 7 | `TlsCallback_0`, `TlsCallback_1`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `tls_callback_0`, `tls_callback_1` |
| dexter | O2 | `dexter` | 7 | `TlsCallback_0`, `TlsCallback_1`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `tls_callback_0`, `tls_callback_1` |
| dexter | O2-noinline | `dexter` | 7 | `TlsCallback_0`, `TlsCallback_1`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `tls_callback_0`, `tls_callback_1` |
| gzip | O2 | `gzip` | 1 | `__printf__` |
| gzip | O2-noinline | `gzip` | 1 | `__printf__` |
| minipig | O0 | `minipig` | 9 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| minipig | O2 | `minipig` | 9 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| minipig | O2-noinline | `minipig` | 9 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| mydoom | O0 | `mydoom` | 9 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| mydoom | O2 | `mydoom` | 9 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| mydoom | O2-noinline | `mydoom` | 9 | `TlsCallback_0`, `TlsCallback_1`, `TopLevelExceptionFilter`, `_TLS_Entry_0`, `_TLS_Entry_1`, `entry`, `start`, `tls_callback_0`, `tls_callback_1` |
| u-boot | O2 | `u-boot` | 5 | `j_j_j_sub_608002ec`, `j_j_sub_608002ec`, `j_sub_608002ec`, `j_sub_60802a44`, `start` |
| u-boot | O2-noinline | `u-boot` | 5 | `j_j_j_sub_608002ec`, `j_j_sub_608002ec`, `j_sub_608002ec`, `j_sub_60802af4`, `start` |

The total is `3 + 21 + 2 + 27 + 27 + 10 = 90`. The concentration in PE
entry/TLS aliases, start symbols, gzip's `__printf__`, and U-Boot jump aliases
supports the classification as identity-resolution coverage rather than 90
ordinary decompilation crashes. It remains a real gap.

## Direct result-data recount

Reading the preserved result JSON without consulting `scoreboard.toml` found:

- 803 binary groups;
- 94,485 rows and 94,485 unique identities;
- 94,485 rows marked decompiled;
- no duplicate identities.

Perfectness was recomputed from each finite value and the declared perfect
value, then compared with each stored `perfects` flag. Counts agreed exactly:

| Metric | Finite values | Recomputed perfect | Stored perfect flags |
|---|---:|---:|---:|
| GED | 89,009 | 34,512 | 34,512 |
| Type match | 86,669 | 20,124 | 20,124 |
| Byte match | 94,485 | 6,375 | 6,375 |
| Union | 94,485 emitted identities | 43,547 | 43,547 |

These are the self-column populations. Cross-decompiler percentages require
the shared measurable population below.

## Shared-universe audit and ranking

The independent audit merged the new raw fragments with the pinned published
per-function dataset. It did not read the generated scoreboard. The merged
universe contains 94,487 functions measurable by at least one column: 94,267
from the published universe, 220 measurable only after adding the new column,
and two published-measurable functions not measurable by the new column.

| Metric | Perfect | Shared denominator | Rate | Next published column | Local rank |
|---|---:|---:|---:|---|---:|
| GED | 34,512 | 91,288 | 37.805626% | Kuna: 33,146/91,288 | 1 |
| Type match | 20,124 | 86,671 | 23.218839% | angr: 6,367/86,671 | 1 |
| Byte match | 6,375 | 94,487 | 6.746960% | Kuna: 3,061/94,487 | 1 |
| Union | 43,547 | 94,487 | 46.087822% | Kuna: 36,348/94,487 | 1 |

The rank calculation sorts exact perfect rates over one shared denominator per
metric. Because the denominator is shared, the same ordering follows directly
from perfect counts. This avoids comparing percentages computed over different
populations.

The fourth direct-union calculation independently reproduced all four rows,
including the runners-up: Kuna for GED, byte, and Union, and angr for type.

## Baseline delta check

Against the independently audited clean `229fbb1` baseline:

| Metric | New perfect | Old perfect | Perfect-count change | Percentage-point change |
|---|---:|---:|---:|---:|
| GED | 34,512 | 29,463 | +5,049 | +5.530494 |
| Type match | 20,124 | 18,905 | +1,219 | +1.406468 |
| Byte match | 6,375 | 5,563 | +812 | +0.854264 |
| Union | 43,547 | 39,236 | +4,311 | +4.534387 |

The old and new denominators differ for GED, byte, and Union, so the
percentage-point changes were calculated from each run's exact audited
numerator and denominator. They were not inferred from rounded display values.

## Preserved verification inputs

| Input | Location |
|---|---|
| Result JSON | `~/.cache/glaurung/decbench-current-e170a2b4/function_results-e170a2b4.json` |
| Local scoreboard | `~/.cache/glaurung/decbench-current-e170a2b4/scoreboard-e170a2b4.toml` |
| First merged audit | `~/.cache/glaurung/decbench-current-e170a2b4/audited-score-e170a2b4.json` |
| Fresh verification audit | `~/.cache/glaurung/decbench-current-e170a2b4/audited-score-e170a2b4-recheck.json` |
| Pinned manifest | `~/.cache/glaurung/decbench-full/tree/sample_set_manifest.json` |
| Raw evaluated fragments | `~/.cache/glaurung/decbench-full/tree/*/*/evaluated/*.toml` |
| Published comparison data | `~/.cache/glaurung/decbench-full/published_function_results.json` |

The two audit JSON files have the same SHA-256 shown above. The preserved
result JSON and scoreboard retain the hashes recorded in
[CURRENT-FULL-RERUN.md](CURRENT-FULL-RERUN.md).
