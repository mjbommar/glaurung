# §T — Recipe: diffing two binaries

`glaurung diff` does function-level binary diff, BinDiff-style.
Use case: "what did the patch change?" — comparing a CVE-fixed
release to its predecessor, or a patched malware variant to the
original.

> **Verified output.** Captured by `scripts/verify_tutorial.py`
> and stored at
> [`_fixtures/04-diff/diff.out`](../_fixtures/04-diff/diff.out).

## The one-liner

```bash
$ glaurung diff samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2 \
                samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2
```

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

The `dispatch` function grew from 47 to 151 bytes — that's where
the patch lives. Five other functions show different hashes but
same size, which is normal: small layout shifts ripple through
CRT functions because their `lea` offsets to the data section
move when the data section grows.

## What "changed" means

Each row's `a hash` / `b hash` are content hashes of the
disassembled instruction stream. Same hash = identical
instructions; different hash = at least one byte differs.

Same-size + different-hash rows are usually one of:

- A literal address moved (RIP-relative offset shift).
- A constant value changed (`mov eax, 0x10` → `mov eax, 0x20`).
- An instruction was substituted for one of the same length
  (`mov` → `lea`).

Different-size rows are real logic changes — that's what
`dispatch` shows here.

## Drill into the changed function

```bash
glaurung kickoff samples/.../switchy-c-gcc-O2 --db v1.glaurung
glaurung kickoff samples/.../switchy-c-gcc-O2-v2 --db v2.glaurung
glaurung view v1.glaurung 0x<dispatch_va_in_v1> --binary <v1>
glaurung view v2.glaurung 0x<dispatch_va_in_v2> --binary <v2>
```

Eyeball the two pseudocode dumps side by side. The structurer
(#192/#193) recovers if-then-else and switch shapes, so a
code-flow change shows up as different control structure rather
than a wall of `goto L_<hex>` labels.

## JSON output for scripting

```bash
glaurung diff a.elf b.elf --format json | jq '.changed[] | select(.a_size != .b_size)'
```

```json
{
  "name": "dispatch",
  "a_hash": "b9016d60df22f19d",
  "b_hash": "6a818a145f5bf746",
  "a_size": 47,
  "b_size": 151
}
```

Pipeline-friendly. Use this as a CI gate: "fail the build if any
function in the public API grew by more than 50%."

## When to reach for it

- **Patch analysis** — what did this CVE fix actually change?
- **Variant correlation** — is this new malware sample structurally
  related to the one I triaged last week?
- **Build reproducibility** — should two compiles of the same
  source produce identical binaries? (Usually not, due to BuildID
  / timestamps; `diff` shows you which functions are NOT identical
  and why.)

## Limitations

- The diff is at function granularity, not instruction granularity
  — for instruction-level diff, decompile each side and `diff`
  the pseudocode.
- Function identity is by name (or by entry-VA when names disagree
  across binaries). Renamed functions show as add/remove pairs;
  consider running `--match-by hash` (planned) or borrow names
  via `glaurung repl > borrow` first.

## See also

- [§S `07-malware-c2-demo.md`](../03-walkthroughs/07-malware-c2-demo.md) —
  uses diff for variant analysis.
- [`reference/cli-cheatsheet.md`](../reference/cli-cheatsheet.md) —
  full diff-flag list.
