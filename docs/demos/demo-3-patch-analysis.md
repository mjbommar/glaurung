# Demo 3 — Patch analysis

**Samples:**
- `samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2` (v1)
- `samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2`

`switchy.c` is a tiny dispatcher with an 8-way switch over an integer
opcode. v1 has no input validation; v2 adds an `if (op < 0 || op > 7)
return -1;` bounds check at the top of `dispatch`.

This is the canonical "patch analysis" use case: a customer says
*"version 2.3.1 fixed a bug we had in 2.3.0 — what changed?"* The
agent should identify which function moved, characterize the change,
and recover enough source to explain whether the change is a security
fix.

## The conversation

### User turn 1: "What changed between v1 and v2?"

```bash
$ glaurung diff \
    samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2 \
    samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2
```

Output (~200ms):

```markdown
# Binary diff — switchy-c-gcc-O2 ↔ switchy-c-gcc-O2-v2

1 same / 6 changed / 0 added / 0 removed (a=7 b=7)

## Changed functions

| function | a hash | b hash | a size | b size |
|---|---|---|---:|---:|
| `__do_global_dtors_aux` | `7fd4526f20430951` | `c8015d10c2ed71a5` | 57 | 57 |
| `_start` | `ea7906078022b002` | `655a8c389e85d4a0` | 89 | 89 |
| `deregister_tm_clones` | `6057d1ade1a998f4` | `318941da3c2929c8` | 41 | 41 |
| `dispatch` | `b9016d60df22f19d` | `6a818a145f5bf746` | 47 | 151 |
| `main` | `f8c58af674c873ca` | `e0e57fc75dfc574b` | 39 | 39 |
| `register_tm_clones` | `dc6edb3b026d7f42` | `bb1d6b3058d50a55` | 57 | 57 |
```

The agent's interpretation:

> **One function genuinely changed:** `dispatch` grew from 47 bytes to
> 151 bytes (a 3.2× expansion). That's far too much to be a relocation
> shift — real new code was added.
>
> The other 5 "changed" functions all kept their byte counts but their
> hashes changed. That's the diff tool's v1 limitation: it sees
> relocation-shifted call offsets as different bytes. Once we filter
> for size deltas, only `dispatch` is interesting.

### User turn 2: "Decompile both versions of `dispatch` and show me the difference."

```bash
$ glaurung decompile samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2 --va dispatch
$ glaurung decompile samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2 --va dispatch
```

The agent (after running both) produces a side-by-side diff:

```diff
  int dispatch(int op, int a, int b) {
+     if (op < 0 || op > 7)
+         return -1;
      switch (op) {
          case 0: return a + b;
          ...
      }
  }
```

> **The patch adds a bounds check on `op` before dispatching.** v1
> indexed into the jump table without validating that `op` was within
> [0, 7], which means an attacker-controlled `op` could read arbitrary
> code addresses from the table neighborhood and jump to them. v2's
> bounds check eliminates that vector.

### User turn 3: "Was this a security fix?"

> **Yes — high-confidence.** The pattern matches CWE-129 (improper
> validation of array index). The pre-patch behavior is exploitable
> when:
> - `op` originates from untrusted input (e.g. parsed from a packet,
>   read from a config file, or supplied by another process)
> - the jump table at `0x4020` is followed by code addresses or
>   function pointers that an attacker could mis-jump into
>
> Both conditions hold for `dispatch` in this binary's call shape:
> `main` invokes `dispatch(i, ...)` in a loop where `i` is bounded,
> but the function's exposed prototype doesn't guarantee that.
>
> **Recommendation:** treat any v1.x deployment as latently vulnerable
> until upgraded.

## Why this works today

- `glaurung diff` (#184) does the function-level pairing in 200ms.
- The `decomp` REPL command renders both versions side-by-side via
  `render_decompile_with_names` (#196).
- The case-body discovery in v1 vs v2 is symmetric thanks to the
  jump-table walker (#177) — without it, neither side would see the
  switch's case bodies as discoverable functions.

## Limitations to fix in v2 of the diff tool

The "6 functions changed" noise on a 1-function-actually-changed
binary is the most visible v1 wart. v2 of `binary_diff` will mask
address-relative immediates from the body hash before comparison;
this filter would correctly show `1 changed / 0 added / 0 removed`
on this exact pair. Filed as a follow-up under #184.
