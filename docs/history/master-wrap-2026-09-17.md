# Outstanding-work integration on master

> **Kind:** record · **Date:** 2026-09-17

The user authorised review, documentation, staging, commit and push of all
outstanding work in the canonical checkout, and confirmed `master` as the
destination. This is a delivery record, not an all-green release claim.

## Review and integration

The initial checkout was `master` at `0c6f1d5e`, one commit ahead and 47 behind
the fetched `origin/master` at `ca5768ba`. Nineteen outstanding file paths
covered executable-section CFG boundaries, ARM incoming argument identity,
paired-return provenance and receiver consumption, AArch64 system-register
reads, PLT indexing, checked replay inputs and compiler-produced fixtures.

Every outstanding file except the relocation helper and dependency-boundary
allowlist matched the fetched remote byte-for-byte (`git hash-object` compared
with `git rev-parse origin/master:<path>`). The local runtime-foundation commit
also had a newer integrated counterpart, `165ff4ed`, on the remote.

Commit `6f9486c3` preserved all outstanding paths before integration. Merge
`fa448ebf` retained both histories without rebasing or force-pushing. Conflicts
kept the remote's newer dependency pins, canonical-cache accounting and
documentation. The duplicate solver-authority decision at the old ADR-032
path was removed during reconciliation; the retained ADR-037 contains the
same authority decision and is indexed by the remote documentation.

The resulting product difference from fetched `ca5768ba` is
`RelocationTable::build_plt_map_from_first`: `.plt.sec` has no reserved resolver
entry, so its first relocation maps to the section start. The remote ELF
parser already calls this helper; the outstanding implementation completes
that call. Traditional `.plt` continues to skip its reserved first entry.
Cargo also normalised dependency ordering in `Cargo.lock`; no dependency
version changed in that normalisation. The environment-allowlist removal
merged with the remote's newer entries without dropping them.

## Validation on the integrated checkout

All scratch files and logs use `/home/mjbommar/.cache/glaurung/tmp`, not `/tmp`.
Commands below were run after merge `fa448ebf`, with only Cargo's lockfile
ordering normalisation subsequently dirty. No DecBench or Joern evaluation,
or upstream interaction, was performed.

| Command | Observed result |
| --- | --- |
| `uv sync --locked --dev` | Passed |
| `uv run maturin develop` | Debug extension rebuilt and installed successfully |
| `uv run python tools/gen_native_stub.py --check` | Passed |
| `uv run pytest python/tests/test_decbench_replay_inputs.py python/tests/test_src_dependency_boundaries.py python/tests/test_cli_decompile.py -k 'replay or dependency or plt_got' -q` | 18 selected controls passed |
| `uvx ruff check python/` | Passed |
| `rustfmt --edition 2021 --check src/formats/elf/relocations.rs` | Passed |
| `uvx ty check python/` | Failed: 411 diagnostics |
| `uvx ruff format --check python/` | Failed: 13 files require formatting |
| Focused documentation, dependency-boundary and replay-input pytest run | Five documentation tests failed; other selected tests passed |
| `cargo test --features python-ext -- --test-threads=1` | Test compilation failed: E0063, missing `stable_terms` in the test-only constructor at `src/symbolic/solver/axeyum_backend.rs:443` |
| `uv run pytest python/tests/` | Started after the source commit and native rebuild; terminal result pending at documentation time |

The Rust failure implementation is identical to fetched `origin/master`;
`git log -S 'stable_terms' -- src/symbolic/solver/axeyum_backend.rs` attributes
the field addition to `165ff4ed`. The documentation failures include the
missing banner in `runtime-stack-writes.md`, historical record/index gaps,
and links to embedded source-analysis files removed by the Cindergraph
extraction. Python and documentation source files are unchanged from fetched
`origin/master`; these failures were observed, not repaired or waived here.
No full feature, performance, architecture or fixture-matrix pass is claimed.

## Resume evidence

Logs in the scratch directory have prefix `master-wrap-` and suffix
`-20260917.log`: `rust`, `python`, `controls`, `focused`, `ruff`, `ty` and
`format`. The whole Python run uses the canonical checkout's virtualenv;
another pre-existing whole Python run belongs to the regression integration
worktree and must not be confused with this run or terminated.

Finish reading the terminal Python result before claiming whole-suite
validation. Fix the inherited test constructor, documentation estate,
formatting and type diagnostics in a separately scoped follow-up. Delivery
is verified by comparing local `HEAD` with `git ls-remote origin
refs/heads/master`; remote CI is a separate, unverified fact.
