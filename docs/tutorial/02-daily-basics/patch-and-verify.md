# §L — Patch and verify

The byte-level editor with mnemonic shorthands. Reversers patch
dozens of times a day — license checks, anti-debug stubs, infinite
loops, integer overflows. Glaurung's `patch` command supports the
common shapes and verifies the result.

## Setup

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug
```

(We'll use `hello-clang-debug` because it's small enough to inspect
the patched binary by hand.)

## The general shape

```bash
glaurung patch <input> <output> --va <addr> <action> [--verify] [--force]
```

Where `<action>` is exactly one of:

| Flag | What it does |
|---|---|
| `--bytes "<hex>"` | Raw byte patch (legacy form) |
| `--nop` | NOP-out the instruction at `<addr>`, size-preserving |
| `--jmp <target>` | Replace with `jmp <target>`, NOP-padded if shorter |
| `--force-branch true` | Replace conditional with `jmp <original-target>` (always-taken) |
| `--force-branch false` | Replace conditional with NOPs (never-taken) |

`--verify` re-disassembles the patched VA in the output binary so
you can confirm the encoding.

`--force` overwrites the output file if it already exists.

## NOP-out an instruction

Find an instruction:

```bash
glaurung disasm $BIN 0x11e0 --max-instructions 4
```

```
0x11e0  f30f1efa   Endbr64
0x11e4  31ed       xor ebp, ebp
0x11e6  4989d1     mov r9, rdx
0x11e9  5e         pop rsi
```

Patch out `xor ebp, ebp`:

```bash
glaurung patch $BIN /tmp/hello-patched --va 0x11e4 --nop --verify --force
```

```
# Patch applied
- input:  `samples/.../hello-clang-debug`
- output: `/tmp/hello-patched`
- VA: `0x11e4` (file offset `0x11e4`)
- before: `31ed`
- after:  `9090`

_patched 2 bytes at VA 0x11e4 (file offset 0x11e4)_
_verify: nop_
```

The verify line confirms the patched bytes decode as `nop`.

## Force a branch

Conditional jumps decode as `jcc` (e.g. `jne`, `jz`). To force the
condition always taken:

```bash
glaurung patch $BIN /tmp/forced --va 0x1140 --force-branch true --verify --force
```

This rewrites the `jcc <target>` as `jmp <target>` (size-preserving,
NOP-padded if `jmp` is shorter than the original `jcc`).

To force never-taken (equivalent to NOP-ing the jcc):

```bash
glaurung patch $BIN /tmp/forced --va 0x1140 --force-branch false --verify --force
```

## Redirect to a different VA

```bash
glaurung patch $BIN /tmp/redirected --va 0x1140 --jmp 0x1200 --verify --force
```

Replaces the instruction at `0x1140` with `jmp 0x1200`. The patcher
picks the shortest near-relative encoding that fits in the
original instruction's size, NOP-padding any leftover bytes.

## Raw byte patch (legacy)

If you've decided exactly what bytes you want:

```bash
glaurung patch $BIN /tmp/raw --va 0x11e4 --bytes "90 90 90" --verify --force
```

Spaces are tolerated; case doesn't matter. The byte length must
match the original instruction's size for code patches (otherwise
you'll desync the surrounding instruction stream).

## JSON output

```bash
glaurung patch $BIN /tmp/p --va 0x11e4 --nop --verify --force --format json | jq
```

```json
{
  "output_path": "/tmp/p",
  "va": 4580,
  "file_offset": 4580,
  "original_hex": "31ed",
  "patched_hex": "9090",
  "notes": ["patched 2 bytes at VA 0x11e4 (file offset 0x11e4)"],
  "verify": "verify: nop"
}
```

Pipeline-friendly for batch patching.

## Common patterns

**"Bypass a license check"**

```bash
# Disasm the check, find the conditional jump.
glaurung disasm <binary> <addr_of_check>

# Force the branch always-taken (or never-taken, depending on logic).
glaurung patch <input> <output> --va <jcc_addr> --force-branch true --verify
```

**"NOP-out an anti-debug call"**

```bash
glaurung patch <input> <output> --va <call_va> --nop --verify
```

A 5-byte `call` becomes 5×`0x90` NOPs.

**"Skip a region of code"**

```bash
glaurung patch <input> <output> --va <start> --jmp <end> --verify
```

## Caveats

- Patches don't enter the KB undo log today —
  [#235 GAP](../../architecture/IDA_GHIDRA_PARITY.md). Workaround:
  the original input is untouched, so to "undo" a patch, just
  re-run `patch` from the original.
- Mnemonic shorthands (`--nop`, `--jmp`, `--force-branch`) are
  x86_64 only in v0. Other architectures will surface a clear
  `NotImplementedError`.
- The patcher refuses to extend past EOF or to overwrite output
  without `--force`.
- For `--force-branch true`, only the common `jcc` family
  (`jo/jno/jb/jnb/jz/jnz/jbe/ja/js/jns/jp/jnp/jl/jnl/jle/jg`,
  both rel8 and rel32) is recognized. Other conditional jumps
  surface "instruction at <va> is not a recognized conditional
  branch."

## Patch + re-analyze workflow

```bash
# 1. Patch.
glaurung patch in.elf out.elf --va 0x1140 --force-branch true --verify --force

# 2. Re-analyze the output.
glaurung kickoff out.elf --db patched.glaurung

# 3. Confirm the change.
glaurung view patched.glaurung 0x1140 --binary out.elf --pane disasm
```

This is the canonical workflow for "patched-binary triage" — run
the same analysis pipeline on the patched output to confirm your
patch actually changed what you thought it did.

## What's next

- [§K `undo-redo.md`](undo-redo.md) — KB-level undo (note that
  [#235](../../architecture/IDA_GHIDRA_PARITY.md) is the gap for
  unifying KB undo with patch undo)
- [Tier 4 §T `diffing-two-binaries.md`](../04-recipes/diffing-two-binaries.md) —
  compare your patched output to the original

→ End of Tier 2. Continue to [Tier 3 walkthroughs](../03-walkthroughs/).
