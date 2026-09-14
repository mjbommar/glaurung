# Current-code full DecBench rerun

> **Kind:** live measurement record · **Started:** 2026-09-13 · **Status:** in progress

## Plain-English answer

The historical `41.553%` Union result is not based on today's decompiler. It
was generated from Glaurung `229fbb1d` on 2026-08-30 and was deliberately
reused as frozen input for the September Joern-replacement experiment.

A new full-corpus run **is now executing** against the newest reproducible
Glaurung revision available when the run was prepared:
`e170a2b4a8946b84808890fd5a09d46ce7cf6a66`. This revision includes the final
source-CFG compatibility change at `f9a5cbaa` and all commits through the
campaign documentation commit at `e170a2b4`.

This is “today's latest committed code,” not “every byte currently visible in
the shared main worktree.” The distinction is required for reproducibility:

- `master` and `origin/master` currently point to `0892552157be6bd9267007231419ff6606a2dd38`;
- the campaign branch and clean run worktree point to the newer `e170a2b4`;
- the shared `master` worktree currently has 16 modified source files owned by
  concurrent work;
- those uncommitted files have no stable commit identity and can change while
  a multi-hour run is executing.

Building the shared dirty tree would make the result impossible to reproduce
or attribute. It could also mix half-finished changes from several agents.
The correct unit for a leaderboard-quality run is therefore the newest clean,
committed revision, with executable hashes recorded below. If the outstanding
source edits are later reviewed and committed, they require a separately named
rerun; they cannot be silently included in or projected onto this result.

## Frozen provenance

| Input | Identity |
|---|---|
| Glaurung source | `e170a2b4a8946b84808890fd5a09d46ce7cf6a66` |
| Clean run worktree | `~/.cache/glaurung/decbench-latest-e170a2b4` |
| Release CLI SHA-256 | `9bf526586196dff807dd4e5b1529b68f80ed03b20e9a8e6487c7d0a3d49bdec5` |
| Native extension SHA-256 | `5015721795bdf67c4272c6f71c540f1d72c61301c5f38017cd3a5484134b8110` |
| Run-only driver SHA-256 | `92bd57b399623db7d89318aaf3e5432e478f8e3adeb7a33eb406eaa3b148ba79` |
| DecBench | `f76dae075d4d82004fb21132b3f15e43b680e179` |
| Dataset | `e5eb576d66ee36793b800a4dd45e291e0add4472` (`full`) |
| Dataset population | 803 binaries / 94,575 manifest functions |
| Output column | `glaurung-e170a2b4-exact-adapter` |

The run-only driver differs from the committed source only in measurement
orchestration: deterministic sharding, exclusion of the separately completed
Coreutils lane, and exact current-adapter routing. It does not change the
Glaurung executable. Its hash is recorded separately so the orchestration is
auditable rather than being mistaken for part of the source revision.

## Exact adapter policy

For each manifest binary, the driver resolves the requested function
addresses and follows DecBench's current Glaurung adapter policy:

- at most 400 resolved addresses: one narrow `--vas` invocation;
- more than 400: one `--all --limit 30000` invocation, then narrow returned
  functions to the manifest addresses;
- per-function internal timeout: 20,000 ms;
- first-pass outer timeout: 600 seconds per binary;
- one output C file and one metadata TOML per completed binary.

This removes the qualification on the August all-`--vas` run. It also avoids
starting a process or loading the same binary once per function.

## Live progress snapshot

Snapshot taken during the run on 2026-09-13:

| Lane | State | Last reported progress |
|---|---|---:|
| Coreutils | complete | 327/327 binaries, 7,022 functions |
| Non-Coreutils shard 0 | complete | 118/119 binaries, 19,311 functions; one timeout |
| Non-Coreutils shard 1 | running | at least 75/119 binaries, 10,985 functions |
| Non-Coreutils shard 2 | running | at least 75/119 binaries, 11,687 functions |
| Non-Coreutils shard 3 | running | at least 25/119 binaries, 6,349 functions |
| Materialized artifacts | running total | **647/803 C and 647/803 TOML** |

The artifact count is the authoritative coverage checkpoint because progress
logs print only every 25 successful binaries. At the snapshot, three child
decompilers were CPU-bound on real binaries and their three parent shard
drivers remained alive. No final score is claimed while generation is still
in progress.

The completed Coreutils lane took 2,044 seconds (34m04s), emitted 7,022
functions, exited successfully, and peaked at 1,757,256 KiB RSS. Non-Coreutils
shard 0 completed in 1,748 seconds with 118 successful binaries and one
600-second binary timeout. The timeout is a coverage failure to recover, not a
zero score and not permission to reduce the denominator.

## Artifact locations

| Artifact | Location |
|---|---|
| Generated tree | `~/.cache/glaurung/decbench-full/tree` |
| Run logs and timing | `~/.cache/glaurung/decbench-current-e170a2b4` |
| Coreutils log | `smoke-coreutils.stdout` |
| Coreutils resource record | `smoke-coreutils.time.stderr` |
| Shard logs | `full-shard-{0,1,2,3}.stdout` |
| Shard resource records | `full-shard-{0,1,2,3}.time.stderr` |
| Historical audited baseline | `~/.cache/glaurung/decbench-full/audited-score-clean-229fbb1.json` |

These large generated artifacts remain outside Git. This document is the
durable map to them and records the identities needed to interpret them.

## Completion and scoring protocol

The run is not complete merely because the four first-pass processes exit.
Completion requires all of the following:

1. join the manifest's 803 binary keys against generated C and TOML artifacts;
2. enumerate every timeout, nonzero exit, empty output, duplicate identity,
   missing identity, and out-of-manifest identity;
3. rerun missing binary keys with a longer bounded outer timeout without
   overwriting completed outputs;
4. reach 803/803 binary artifacts or preserve an explicit, investigated gap;
5. run pinned DecBench `evaluate-tree` for GED, type match, and byte match on
   only `glaurung-e170a2b4-exact-adapter`;
6. recompute GED, type, byte, and Union counts from raw per-function TOMLs;
7. merge the new column into the shared comparison universe rather than reuse
   the August denominator;
8. compare every changed perfect/non-perfect cell with the clean `229fbb1`
   baseline and inspect unexpected regressions;
9. save final wall time, peak RSS, tool hashes, coverage, score, and rank
   interpretation in this campaign folder.

Until those gates pass, `41.553%` remains the historical baseline and the new
run has no honest current-code ranking. Nothing in this process is posted to
DecBench; any eventual upstream submission or communication is human-only.
