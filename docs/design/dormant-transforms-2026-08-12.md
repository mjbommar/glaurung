# The two transforms that never fire — measured, 2026-08-12

Two structural recovery passes were suspected of never firing on real input.
"Never fires" and "fires and changes nothing" produce identical output, so the
question could not be answered by reading the corpus — it needed an instrument.
`src/ir/pass_stats.rs` is that instrument: opt-in via `GLAURUNG_PASS_STATS`, one
relaxed atomic load per call when off.

    for so in tests/decompiler_fixtures/build/*.so; do
      GLAURUNG_PASS_STATS=1 glaurung decompile "$so" --all --style decbench \
        --format json >/dev/null
    done 2>&1 | sort | uniq -c | sort -rn

## What the corpus says

| pass | attempts | fires | rate |
| ---- | -------: | ----: | ---- |
| `recover_guarded_do_whiles`       | 11390 | 1 | 0.009% |
| `recover_owned_pretested_do_while`| (same walk) | 13 | — |
| `recover_sentinel_search_loops`   |  5695 | **0** | 0% |

(`recover_guarded_do_whiles` is offered twice per function and
`recover_sentinel_search_loops` once, which is why the attempt counts differ by
exactly 2x. Counted over every function of every built fixture object, not only
the functions the behavioural gate scores.)

## `recover_sentinel_search_loops` is NOT dead code

It is correct, and it is narrow. Probing it directly with the source shape its
own doc comment describes:

```c
struct node { struct node *next; int key; };

__attribute__((noinline)) struct node *find_node(struct node *head, int key) {
    struct node *p = head;
    while (p != 0) {
        if (p->key == key) return p;
        p = p->next;
    }
    return 0;
}
```

| build | fires |
| ----- | ----: |
| clang -O1 | **1** |
| clang -O2 | **1** |
| clang -O0 | 0 |
| gcc -O0/-O1/-O2 | 0 |

So the pass fires exactly where it was designed to, and the corpus simply
contains nothing of that shape.

### What does NOT trigger it, and why that matters

Three near-misses were tried, and all three are instructive because they are the
shapes a fixture author would reach for first:

* **pointer INCREMENT** (`const char *cursor; ... cursor += 1;`) — 0 fires at
  every level and both compilers. The matcher requires the loop body to be
  exactly `result = advance(current); current = result; if (result == sentinel)
  return sentinel;`, and a pointer chase produces that because the advance is a
  LOAD. An increment does not.
* **index walk** over a caller-owned array (what `183_sentinel_list_search`
  does) — 0 fires. The exit test is a bound, not a sentinel, so the compiler
  rotates it into a different form entirely.
* **linked walk over a `static` pool built in the same function** — 0 fires.
  The head is then a known constant and the builder loop perturbs the shape.

The single trigger is: **the list head arrives as a PARAMETER, and the advance
is a pointer chase through a struct field, under clang -O1 or above.**

### Why there is still no fixture for it

The harness constructs arguments from caller-owned integer buffers. A parameter
of type `struct node *` whose `next` fields are real addresses into that buffer
is not something `tools/diff_decompile.py` can synthesise today. Giving this
pass standing coverage therefore needs a harness feature (a declared
"linked-structure" argument kind that the worker builds and relocates), not just
another `.c` file — which is why `183_sentinel_list_search` covers the sentinel
SHAPES it can drive and this one is recorded here instead of being faked.

## `recover_guarded_do_whiles` fires once in 1984

One fire is not zero, so the pass is reachable — but a 0.05% rate over the whole
corpus means its behaviour is effectively unmeasured: any edit to it would be
validated by a single lane. The same instrument now makes that visible, and the
same fix applies as above — find the shape, or retire the pass.

## Recommendation

Neither pass should be deleted on this evidence. `recover_sentinel_search_loops`
demonstrably works on the input it was written for; the gap is in the CORPUS and
in what the harness can construct, not in the pass. Record the trigger (above),
and treat "add linked-structure arguments to the differential harness" as the
prerequisite for closing this out.
