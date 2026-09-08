# WP4 raw-loop switch-guard folding — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

Commit `88e6584c` absorbs a range guard into a raw loop's typed switch when the
production structurer proves the same contract already required by ordinary
guarded-switch recovery: complete shared switch evidence, an exact typed
guard/default/dispatch relationship, a single guard predecessor for the
dispatch, and an SSA condition that transitively consumes an unsigned
comparison.

This is not a textual AST pattern. `Region::RawLoop` records the exact guard
block only after CFG/SSA verification. Lowering rechecks the guard's two exact
successors and terminal conditional before removing that conditional; the
typed switch's formal default then owns the out-of-range behavior.

## Real output movement

The ARMv7 A32 O2 `206_aarch64_wide_dispatch::dispatch_in_loop` output changes
from:

```c
var12 = ((unsigned long)((unsigned int)(var11)) & 7);
if ((unsigned long)(6) < (unsigned long)(var12)) {
    goto L_580;
}
switch (var12) {
```

to:

```c
switch ((var11 & 7)) {
```

The existing cases `0..6` and the typed `default: goto L_580` remain. The
temporary `var12`, its declaration, the redundant range-check `if`, and one
goto disappear. The function retains six source-level `continue` statements;
its goto count returns from eight to seven while preserving the default edge
that the pre-transport output had omitted.

## Evidence and limits

- Release extension rebuilt with
  `TMPDIR="$HOME/.cache/glaurung/tmp" uv run maturin develop --release`.
- The reduced typed-evidence test proves non-positional case values, a
  guard-only default, and removal of the now-redundant guard conditional.
- The real A32 test requires no `var12`, one formal default, and exactly one
  remaining transfer to `L_580`; native round trip passes all generated cases.
- `GLAURUNG_ACCOUNT_STRUCTURE=1` is silent for the real function.
- `cargo test --features python-ext`: 4,116 library tests passed, zero failed,
  five ignored; every integration and documentation target passed.
- Full current-tip structural, def-use, architecture, host, GED, RSS, and whole
  Python comparisons remain open. No release-wide green claim is made.

The remaining seven gotos target separately owned handler/join blocks. Their
removal requires the planned verified presentation partition; this increment
does not infer handler ownership from lexical proximity.
