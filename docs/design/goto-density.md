# Goto density: what was measured, and why the sinking pass was removed

> **Kind:** design · **Status:** proposed

*Recorded 2026-08-12, when `src/ir/goto_sink.rs` was deleted. The code was 0%
covered with no production caller; this file keeps the part of it that was
actually expensive to produce — the measurement and the conclusion.*

## The gap

Goto density is the second-largest readability gap after declaration count,
measured function-weighted over 93 ground-truth functions:

| Decompiler | gotos per 100 lines |
| ---------- | ------------------- |
| Glaurung   | 8.63                |
| Ghidra     | 3.18                |
| angr       | 1.99                |

## The structure of our gotos

Over the 409 gotos in that corpus:

```
316  (77.3%)  target a label reached by exactly ONE goto
102  of those also have NO fallthrough into the label
  0  are at the same nesting level as their goto
```

That last line is the load-bearing one. Every one of the 102 fully-sinkable
cases has its `goto` nested *deeper* than the label: the label sits at function
level and the jump comes from inside an `if`. **A same-level inliner fires on
nothing at all** — which rules out the obvious cheap fix and is why the pass
that was written *sank* the block to the jump rather than inlining it upward.

## Why sinking is sound

When exactly one `goto` targets a label and nothing falls into it, that goto is
the block's only predecessor: the block executes exactly when the goto is taken,
and never otherwise. Moving it to the goto site preserves the execution set
wherever that site is nested — including inside a loop, because "when the goto
fires" is the same condition either way.

The one thing that must not be lost is the block's own exit. A block that ended
by falling through into the *next* label depended on its position, so a sound
pass may only move a block that ends in an unconditional transfer, which is
self-contained by construction. Appending a synthetic `goto next` would widen
the pass's applicability, but it would also manufacture a jump the reader did
not have, which is the opposite of the goal.

## Why it was not kept

The pass was correct and did what it claimed: **it removed 11% of emitted
gotos.** It still lost.

Wiring it in cost `statemachine:gcc:O0` a GED of 10 -> 35, plus five `byte_match`
cells. Fewer gotos is not the same as a control-flow graph closer to the
source's, and this is the counterexample: moving a block to its jump site
changes where that block sits in the region tree, which is exactly what GED
measures.

## What would have to change first

Do not reintroduce sinking without a metric that says goto density is worth
paying GED for. The honest ordering is:

1. Decide what readability metric the project optimises alongside GED, and
   whether goto density is in it at a weight that can beat a 25-point GED
   regression on a single function.
2. Only then reconstruct the pass; the analysis above is the expensive part and
   it stays true, but the implementation was ~330 lines of routine tree surgery.
