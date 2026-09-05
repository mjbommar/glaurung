# WP5 typed switch evidence through raw loops — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `460259fa` extends the shared WP5 case/default transport through the
WP4 `RawLoop` ownership boundary. A raw dispatch loop now retains the canonical
`SwitchEvidence` built from typed CFG edges. AST lowering consumes that object
instead of reconstructing case values from successor positions or requiring a
guard default to appear among the dispatch successors.

This is a representation and correctness increment, not handler inlining.
Case bodies still target their separately owned labelled blocks. The next WP4
slice must prove exclusive handler prefixes and a unique shared join before it
can move those statements into the switch arms.

## Safety boundary

- Ordinary multi-latch raw loops carry no switch evidence.
- Incomplete evidence remains attached for diagnosis but is not consumed for
  source-level cases; lowering falls back to the prior lossless CFG form.
- Typed evidence is used only at its exact dispatch block.
- Case target indices and the default target are resolved through the same
  `LlirFunction` block table; missing targets fail closed instead of fabricating
  an address.
- Raw-loop ownership, exits, labels, and backedge-to-`continue` handling are
  otherwise unchanged.

## Output evidence

Release build command:

```bash
TMPDIR="$HOME/.cache/glaurung/tmp" uv run maturin develop --release
```

On the real ARMv7 A32 O2
`206_aarch64_wide_dispatch::dispatch_in_loop`, the previous seven cases
`0..6`, handler effects, and six source-level `continue` statements remain.
The CFG-proven out-of-range target now also appears as:

```c
default:
    goto L_580;
```

The earlier heuristic omitted that default because `L_580` is reached by the
range guard and is not a successor of the indirect-dispatch block. The output
therefore moves from zero to one explicit default arm. Handler inlining remains
open, so the local goto count moves from seven to eight by faithfully exposing
that previously dropped edge.

The real v1 architecture round trip remains green:

```bash
TMPDIR="$HOME/.cache/glaurung/tmp" uv run pytest \
  python/tests/test_decompiler_arch_roundtrip.py \
  -k 'loop_byte_switch_round_trips_in_v1' -xvs
# 1 passed, 99 deselected in 1.30s
```

The reduced AST test uses non-positional case values `10`, `12`, and `42`, plus
a guard-only default absent from the dispatch successor list. It proves that
lowering follows typed evidence rather than rediscovering either fact.

## Gates and current limitations

- `cargo test --features python-ext` at `460259fa`: 4,116 library tests passed,
  zero failed, five ignored; every integration and documentation target passed.
- The exact clean `c9483542` structural gate stopped after 632.42 seconds on an
  unrelated stale assertion for `tail_dispatch`: the test searched for an
  intermediate call assignment, while production now emits the better direct
  `return ops[tag](a, b)` form. Eight preceding tests passed.
- The exact clean `c9483542` def-use gate stopped after 64.43 seconds on 27
  baseline mismatches across unrelated C++, Rust, float, and control-flow
  functions. The changed `dispatch_in_loop` cell is not among them.
- A current-tip complete architecture/host matrix, GED comparison, RSS, and
  whole Python suite have not yet run. This result must not be described as a
  release-wide green claim.
