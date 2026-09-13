# Joern versus Glaurung performance

> **Kind:** record · **Date:** 2026-09-13

## Measured results

| Workload | Java Joern/pyjoern | Glaurung | Observed ratio |
|---|---:|---:|---:|
| Strict 785-binary, 85,645-cell pass | 11,716.9 s summed shard wall | 59.74 s wall | 196.1x lower time for Glaurung |
| Peak RSS during strict pass | 9,255,808 KiB | 339,952 KiB | 27.2x lower for Glaurung |
| Unscored 18-file, 4,380-definition tail | 356.10 s | 0.60 s | 593.5x lower time for Glaurung |
| Peak RSS on 18-file tail | 2,690,784 KiB | 121,492 KiB | 22.1x lower for Glaurung |

The final Glaurung timing belongs to the accepted ternary-loop build whose
CPython 3.12 extension SHA-256 is
`1dc2682a9f80520e7d72213f2b2700c592cd67ae38a45cc4c6f00b063879615e`.
The Java environment was OpenJDK 25.0.4, pyjoern 4.0.150.4, and Joern 4.0.150.

## How the runs differ

The Glaurung scored measurement is one complete provider invocation over the
785-binary universe. Java was deliberately divided into 79 resumable shards of
ten binaries each because a single monolithic Joern run was operationally
risky. The Java number is the sum of each shard's wall time, not the elapsed
clock time of an overlapping parallel batch. The peak Java RSS is the largest
individual recorded shard RSS, not a sum across concurrent processes.

Consequently, `196.1x` is a useful workload-cost comparison for these recorded
invocations, not a universal latency claim. It must not be read as a controlled
single-process microbenchmark or projected to unrelated corpora.

## Why Java costs more here

The pyjoern route starts and manages a JVM-backed parsing pipeline and emits a
much wider set of parser entities. Across the full 803 files, Java returned
78,902 names beyond stored definition markers. Every such graph was a one-node,
zero-edge declaration/prototype graph. Glaurung's definition-oriented frontend
returned none of this noise. The experiment did not attempt to isolate how much
Java time came from startup, parsing, graph construction, serialization, or
those additional declarations.

## Resource controls

Java shards recorded JSON summaries, per-function JSONL, stderr/progress, exit
status, `/usr/bin/time` measurements, and peak RSS. Completed shards were
checkpointed and never silently recomputed. `JAVA_TOOL_OPTIONS` set
`-Djava.io.tmpdir=$TMPDIR`; an earlier attempt that did not redirect every JVM
temporary file was rejected and is not part of the final measurement.

Glaurung used a release-mode native extension built in the clean comparison
worktree. The final scored output and timing record are retained under the
artifact directory named in [METHODOLOGY.md](METHODOLOGY.md).

## Practical conclusion

For DecBench's source-CFG extraction workload, the native Glaurung path is
materially cheaper in both time and memory while providing complete definition
coverage. The exact speed ratio should remain pinned to this environment and
execution design; the qualitative operational advantage is large enough that
reasonable measurement overhead cannot reverse it.
