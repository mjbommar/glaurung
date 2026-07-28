# The always-hoist recovery: a measured trade, both sides

> ## STRICTLY EXPERIMENTAL — do not merge or cherry-pick the AST code
>
> The measurements in this document stand. **The code does not.**
>
> Besides the always-hoist flag, branch `recover-ged-cells` carries a
> `drop_dead_preamble` helper whose liveness is computed from the loop condition and
> body only. It never examines statements after the loop, so a preamble destination
> read only by a later `return` is treated as dead and dropped. That is a correctness
> bug independent of the hoisting question.
>
> Use this document as historical evidence for what the loop fallback costs, and
> nothing else. The unsafe code was deliberately not integrated.

**Experimental branch:** `recover-ged-cells` at `2bde5a8`  
**Baseline:** `a1a8a87` · **Compared master:** `d6144a7`+ · measured 2026-07-26

## What it buys

Restoring the pre-`a6d6da0` always-hoist behaviour removes the
`while (1) { pre; if (!cond) break; }` fallback, which was the largest single GED cost
in the measured corpus.

| | total GED over baseline | cells |
|---|---:|---:|
| master | **+108.32** | 18 |
| always-hoist | **+58.00** | 14 |
| **recovered** | **50.32 points (46%)** | |

Every `-O0` GED cell returned to baseline—ten cells:

`matrix:gcc:O0` 15.0 → **3.0** · `matrix:clang:O0` 11.0 → **3.0** ·
`sort:gcc:O0` 10.0 → **3.5** · `strops:gcc:O0` 6.0 → **2.0** ·
`strops:clang:O0` 5.0 → **2.33** · `loops:gcc:O0` and `loops:clang:O0`
3.33 → **0.67** · `statemachine:gcc:O0` 39.0 → **36.0** · `sort:gcc:O2` ·
`linkedlist:gcc:O2`.

Six `-O2` cells became slightly worse (`arrays`, `checksum`, `fixedpoint`,
`linkedlist`), which is included in the +58.

## What it costs

Four functions across six cells returned wrong answers:

| function | lanes |
|---|---|
| `03_loop_shapes:while_prefix` | gcc:O2 |
| `12_loop_rotation:find_first_set` | gcc:O2 |
| `13_loop_early_exit:classify_run` | clang:O2, gcc:O2 |
| `14_flag_effects:countdown` | clang:O0, gcc:O0 |

No cases timed out. `str_len` was not affected.

The initial description—two functions, with `str_len` hanging—was wrong. It was
inferred from textual metrics and an earlier experiment instead of the execution
differential. The eight-minute differential produced the table above. GED,
`type_match`, and `byte_match` do not execute the decompiled code, so they cannot
establish behavioral safety.

## Reading the trade

On the submission metric this experiment gains 50.32 GED points; on actual decompiler
quality it introduces four behavioral regressions. The correct resolution is
verify-after-fold, which should retain the readability recovery without accepting the
wrong answers. See `value-model-root-cause-and-plan.md` §0.4.

The surviving +58 was entirely `-O2`. That matches the attribution: the loop fallback
was an `-O0`-shaped cost, while the `-O2` excess belonged to out-of-SSA copies
(`b367f3a`) and flag statements (`12dcd5e`). Those require the value/flag architecture,
not unsafe loop lowering.
