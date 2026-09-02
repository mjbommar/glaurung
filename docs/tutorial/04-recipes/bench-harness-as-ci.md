# §W — Benchmark harness as CI evidence

> **Kind:** guide · **Status:** maintained

Goal: run the checked-in matrices, retain machine-readable output, and avoid
turning revision-specific score totals into permanent guarantees.

## Inspect options first

```bash
uv run python -m glaurung.bench --help
```

The benchmark is a Python module, not a top-level `glaurung bench` command.

## Run the native CI matrix

```bash
uv run python -m glaurung.bench \
  --ci-matrix \
  --output bench-ci.json \
  --quiet
```

The runner also writes a Markdown report beside the JSON file. The current
aggregate header is
[`ci-matrix-md-head.out`](../_fixtures/04-bench/ci-matrix-md-head.out).
Function discovery, naming rate, decompiler coverage, and timings can move when
analysis changes or the host differs. Compare against a pinned baseline rather
than hard-coding the values in prose.

## Run the packed matrix

```bash
uv run python -m glaurung.bench \
  --packed-matrix \
  --output bench-packed.json \
  --quiet
```

The packed matrix should retain packer-family detection across the checked-in
UPX fixtures. See
[`packed-matrix-md-head.out`](../_fixtures/04-bench/packed-matrix-md-head.out).

## Use results responsibly

- Retain the Glaurung revision, sample hashes, host/toolchain, JSON, Markdown,
  and process exit status.
- Compare like-for-like matrices and configuration.
- Treat successful completion separately from metric improvement.
- Investigate unexpected function-count jumps, failures, or detector changes
  before accepting a refreshed baseline.

Continue to [§X — One-shot kickoff](../05-agent-workflows/one-shot-kickoff.md).
