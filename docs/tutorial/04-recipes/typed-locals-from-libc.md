# §V — Recipe: typed locals from libc

How Glaurung's call-site type propagation (#172 / #195) lights up
stack-variable types automatically when the function calls a
typed library function. No analyst input needed — the propagation
happens at `kickoff` time.

This recipe explains *why* the typed-locals prelude in
`glaurung view` output sometimes fills in for free, and *how* to
get the same effect on calls into types Glaurung doesn't yet know
about (your own libraries, custom protocols, etc).

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/04-typed-locals/`](../_fixtures/04-typed-locals/).

## The free-lunch case

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
$ glaurung kickoff $BIN --db demo.glaurung
```

```markdown
## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **0**
- stack slots discovered: **90**
- types propagated: **18**
- auto-struct candidates: **0**
```

(Captured: [`_fixtures/04-typed-locals/kickoff.out`](../_fixtures/04-typed-locals/kickoff.out).)

The line that matters: **`types propagated: 18`**. That happened
during kickoff — no analyst input.

```bash
$ glaurung view demo.glaurung 0x1160 --binary $BIN \
    --pane pseudo --pseudo-lines 8
```

```text
── pseudocode (enclosing function) ──
fn main {
    // ── locals (from KB) ─────────────────────────────────
    void *var_1b0;  // -0x1b0  set_by=propagated
    void *var_140;  // -0x140  set_by=propagated
    char *var_110;  // -0x110  set_by=propagated
    // ─────────────────────────────────────────────────

    // x86-64 prologue: save rbp, frame 432 bytes
```

(Captured: [`_fixtures/04-typed-locals/view-typed-locals.out`](../_fixtures/04-typed-locals/view-typed-locals.out).)

The locals are typed `void *` and `char *` even though the source
binary has no DWARF type info. Where did the types come from?

- **Stdlib bundle** — auto-loaded at kickoff time. Includes 192
  libc prototypes (printf, snprintf, recv, memcpy, …) plus the
  Win32 API surface.
- **Propagation pass** (#172 / #195) — when `var_110` is passed
  as the first argument to `snprintf(char *, size_t, const
  char *, ...)`, the propagator infers `var_110: char *` and
  writes it to the KB with `set_by="propagated"`.

The output's `set_by=propagated` tag is deliberate — you can tell
this isn't ground truth, it's an inference from a libc-call site.

## Re-running propagation explicitly

`propagate` operates on the cursor's enclosing function:

```text
─── stdin (keystrokes piped to glaurung repl) ───
g 0x1160
propagate
save
q
─── glaurung repl stdout ───
>   0x1160  main  (set_by=analyzer)
0x1160>   refined types on 3 stack slot(s) in fn@0x1160
0x1160> saved.
0x1160>
saving and exiting…
```

(Captured: [`_fixtures/04-typed-locals/repl-propagate.out`](../_fixtures/04-typed-locals/repl-propagate.out).)

> **Note.** `propagate` requires a cursor — without `g <addr>`
> first the REPL says `(set position with goto first)`. Use
> `g <function-entry-va>` to scope it to one function.

## What types are loaded

```bash
$ glaurung find demo.glaurung "" --kind type | head -10
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
type        ATOM            typedef  (set_by=stdlib)
type        BOOL            typedef  (set_by=stdlib)
type        BOOLEAN         typedef  (set_by=stdlib)
type        BYTE            typedef  (set_by=stdlib)
type        CHAR            typedef  (set_by=stdlib)
type        DIR             typedef  (set_by=stdlib)
type        DWORD           typedef  (set_by=stdlib)
type        DWORD_PTR       typedef  (set_by=stdlib)
```

(Captured: [`_fixtures/04-typed-locals/find-types-head.out`](../_fixtures/04-typed-locals/find-types-head.out).)

`set_by=stdlib` rows came from the auto-loaded type bundle. DWARF
types would show `set_by=dwarf`. Analyst-defined types show
`set_by=manual`.

## Manually setting a prototype, then propagating

For your own functions, set a prototype:

```text
>>> proto set handle_request int char *,size_t
  handle_request  int(char *, size_t)
>>> g 0x<caller-va>
>>> propagate
  refined types on N stack slot(s) in fn@0x<caller-va>
```

Now any caller of `handle_request` will type its first-arg slot
as `char *` and second-arg slot as `size_t` — and those types
flow into `glaurung view`'s locals prelude.

## When propagation doesn't fire

Three common reasons:

1. **No prototype known.** If the caller calls `do_thing()` and
   `do_thing` has no entry in `function_prototypes`, the
   propagator has nothing to apply. Set the prototype with REPL
   `proto set`.
2. **Indirect call.** Propagation only fires on direct call
   instructions where the target is statically resolvable to a
   named function.
3. **Slot already manually typed.** The propagator never
   overwrites `set_by="manual"` slots. If you've set a type by
   hand, that wins.

## How it composes with the daily-basics flow

```text
1. kickoff                      # auto-load stdlib + run propagation
   ↓
2. propagated slots typed       # var_110: char *  (from snprintf)
   ↓
3. typed-locals prelude         # `glaurung view` shows real C declarations
   ↓
4. analyst rename + retype      # promote `var_110` → `c2_url_buffer: char *`
   ↓
5. set_by=manual wins           # subsequent re-runs respect the rename
```

Steps 1-3 are free. Step 4 is where analyst intent enters the
record. Step 5 is the safety guarantee.

## See also

- [`reference/set-by-precedence.md`](../reference/set-by-precedence.md) —
  why propagated never beats manual.
- [§G `stack-frames.md`](../02-daily-basics/stack-frames.md) —
  the daily-basics frame editor.
- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  end-to-end use of typed locals.
