# Terminal branch kinds and stable one-arm structuring

Date: 2026-07-30

Source checkpoint: `6175a19d38264af9a5618c952ede6dcc2067262b`

## Verdict

Glaurung now distinguishes an explicit-return terminal block from a
successor-free block ending in a non-returning call, trap, or tail transfer
when both arms of a conditional terminate. A unique non-returning terminal is
rendered as the one-arm guard; equal terminal kinds are ordered by the
conditional's semantic taken edge. Successor-vector insertion order no longer
decides condition polarity or which terminal arm becomes the trailing path.

This closes one concrete structuring defect and improves the blinded DecBench
sample without a measured byte-match loss. It does **not** establish overall
parity with Ghidra, angr, or Kuna: fresh full-corpus GED and type evidence are
still unavailable in the retained sample tree, and the remaining architectural
backlog is larger than this control-flow tie-breaker.

## Root cause and reference designs

`detect_if_shape` previously tried `(successor[0], successor[1])` before the
reverse pair. When both successors had no outgoing edges, the first vector
entry became the one-arm `if` body even though the CFG already retained the
conditional's exact taken target. On GCC's `copyFileName` layout, that produced
the inverse presentation:

```c
if (size <= 1024) {
    strncpy(...);
    return;
}
exit(...);
```

The original machine code branches over the lexical `exit` fallthrough to the
normal copy path. The corrected presentation is therefore:

```c
if (size > 1024) {
    exit(...);
}
strncpy(...);
return;
```

The design comparison was made against primary implementations:

- [Ghidra's deferred `ruleBlockIfNoExit`](https://github.com/NationalSecurityAgency/ghidra/blob/a14dad67f369affeffc1cd4d584b6b717cd9c3f5/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc#L1376-L1407)
  chooses an exact output-edge slot and negates the condition when the selected
  clause is on the false edge. It does not infer truth from container order.
- [angr's Phoenix terminal-arm rule](https://github.com/angr/angr/blob/61bac8ffd0338cdc43788276aa14eee6d50f995d/angr/analyses/decompiler/structuring/phoenix.py#L2269-L2292)
  swaps terminal arms deliberately and then recovers the exact edge condition.
  A static angr 9.3.1 run on the same blinded function selected the prior
  success-first layout and also inferred a spurious non-void return; Glaurung's
  corrected output preserves the original void boundary and machine layout.
- [Kuna's `rule_block_if_no_exit`](https://github.com/Noelo-Lab/kuna/blob/d09f21ce73627f6bddfcb41c436d3235b114b945/decompiler/crates/kuna-decomp/src/p8_structure/blockaction.rs#L2149-L2194)
  faithfully ports Ghidra's edge-slot selection and condition negation. Kuna is
  retained as a first-class decompiler reference alongside Ghidra and angr.

## Real TDD and collateral-loss control

The RED witness compiles and strips a real `-O0` shared ELF containing a bounded
copy guarded by `exit(7)`, decompiles the exported address through the installed
Rust extension, verifies that `exit` remains inside the guard before `strncpy`,
and recompiles the recovered C with GCC and `-Werror`.

Two Rust topology tests separately cover:

1. a non-returning fallthrough paired with an explicit-return taken target; and
2. two ordinary return arms, which must use the semantic taken edge as the
   stable tie-breaker.

The first implementation used fallthrough for every pair of terminal arms. A
full 250-function score rejected that broad rule: it gained three functions but
lost `gzip:flush_outbuf` and `bash:save_builtin`, reducing the mean to
`0.16067781957090946`. Inspecting both generated functions showed that their
arms were ordinary returns, not non-returning guards. Retaining terminal kind
in the CFG restored both functions exactly while preserving all three gains.

## Blinded DecBench evidence

The blinded binaries were statically analyzed only. They were never executed,
emulated, or made executable.

| function | `6ddf4ce` | `6175a19` | changed-line distance |
|---|---:|---:|---:|
| `bzip2:copyFileName` | 0.218750000 | 0.350877193 | 50 to 37 |
| `gnutls:nstrftime` | 0.117647059 | 0.136363636 | 60 to 57 |
| `dpkg-query:searchfiles` | 0.162849873 | 0.163265306 | 329 to 328 |

Across the frozen 250-function sample, 3 functions improve, 0 decline, and 247
are unchanged. Mean official `ByteMatchMetric` rises from
`0.16146020536865263` to `0.16206524218413854`; all 250 functions remain
compilable.

Immutable artifact:

- path:
  `/home/mjbommar/projects/personal/decbench-evalkit-sample-set/glaurung-results-6175a19.zip`;
- SHA-256:
  `1ec86a6eb8e10aeca6044f8309a2ef18a0512a1f4c7a0c9a40c8a191bd1056a8`;
- size: 286,927 bytes;
- coverage: 224/224 binaries and 250/250 target functions;
- embedded version: `6175a19`.

## Gates

- Rust library: 1,300 passed, zero failed.
- Real compiled decompiler fixture file: 50 passed, zero failed.
- Behavioral differential: 56/56 lanes, no regressions, with the three retained
  `call_fold_wide_result` improvements.
- Release extension build: passed with the repository's 19-warning baseline.
- Clippy: exit 0 with the repository's existing warning backlog.
- Ruff on the owned Python fixture file: passed.
- Narrow `ty`: unchanged at two pre-existing `pytest.raises` stub diagnostics.
- `cargo fmt --check` and `git diff --check`: passed.
