# §V — Recipe: typed locals from libc

How Glaurung's call-site type propagation (#172 / #195) lights up
stack-variable types automatically when the function calls a
typed library function. No analyst input needed — the propagation
happens at `kickoff` time.

This recipe explains *why* the typed-locals prelude in
`glaurung view` output sometimes fills in for free, and *how* to
get the same effect on calls into types Glaurung doesn't yet know
about (your own libraries, custom protocols, etc).

## The free-lunch case

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
glaurung kickoff $BIN --db demo.glaurung
glaurung view demo.glaurung 0x1160 --binary $BIN --pane pseudo --pseudo-lines 6
```

```
fn main {
    // ── locals (from KB) ───────────────────────────────────
    void *var_1b0;       // -0x1b0  set_by=propagated
    void *var_140;       // -0x140  set_by=propagated
    char *var_110;       // -0x110  set_by=propagated
    // ───────────────────────────────────────────────────────

    snprintf@plt(&var_110, 256, "http://%s:8080%s", ...);
    ...
}
```

The locals are typed `void *` and `char *` even though the source
binary is stripped of DWARF type info. Where did the types come
from?

- **Stdlib bundle** — auto-loaded at kickoff time. Includes 192
  libc prototypes (printf, snprintf, recv, memcpy, ...) plus the
  Win32 API surface.
- **Propagation pass** (#172 / #195) — when `var_110` is passed
  as the first argument to `snprintf(char *, size_t, const
  char *, ...)`, the propagator infers `var_110: char *` and
  writes it to the KB with `set_by="propagated"`.

The output's `set_by=propagated` tag is deliberate — you can tell
this isn't ground truth, it's an inference from a libc-call site.

## Manually: set a function prototype, then propagate

For your own functions, set a prototype:

```bash
glaurung repl $BIN --db demo.glaurung
>>> proto handle_request "int" "char *,size_t"
  handle_request  int(char *, size_t)
>>> propagate
  propagated types into 4 stack slots across 2 functions
```

Now any caller of `handle_request` will type its first-arg slot
as `char *` and second-arg slot as `size_t` — and those types
flow into `glaurung view`'s locals prelude.

## Look at what's known

```bash
glaurung find demo.glaurung "" --kind type | head
```

The full list of types in `type_db` — stdlib bundle types
(`size_t`, `FILE`, `ssize_t`, `sockaddr`, `HANDLE`) plus anything
DWARF imported plus anything you've defined.

## When propagation doesn't fire

Three common reasons:

1. **No prototype known.** If the caller calls `do_thing()` and
   `do_thing` has no entry in `function_prototypes`, the
   propagator has nothing to apply. Set the prototype with REPL
   `proto`.
2. **Indirect call.** Propagation only fires on direct call
   instructions where the target is statically resolvable to a
   named function.
3. **Slot already manually typed.** The propagator never
   overwrites `set_by="manual"` slots. If you've set a type by
   hand, that wins.

## Reading the propagation output

```bash
glaurung repl $BIN --db demo.glaurung
>>> propagate
  propagated types into 18 stack slots across 1 functions
>>> save
```

The "18 stack slots across 1 functions" means: 18 `(function_va,
offset)` rows now have a `c_type` set. Confirm:

```bash
glaurung find demo.glaurung "" --kind stack_var | grep "set_by=propagated" | head
```

Each `set_by=propagated` row is a slot whose type the propagator
inferred. They're never authoritative — DWARF types beat
propagated, manual beats both.

## How it composes with the daily-basics flow

```
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
