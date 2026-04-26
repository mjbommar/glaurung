# §L — Patch and verify

The byte-level editor with mnemonic shorthands. Reversers patch
dozens of times a day — license checks, anti-debug stubs, infinite
loops, integer overflows. Glaurung's `patch` command supports the
common shapes and verifies the result.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/02-patch/`](../_fixtures/02-patch/).

## Setup

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
```

(Same `hello-c-clang-debug` we used in §B / §M / §F. Small enough
to inspect by hand.)

## The general shape

```bash
glaurung patch <input> <output> --va <addr> <action> [--verify] [--force]
```

Where `<action>` is exactly one of:

| Flag                    | What it does                                                    |
|-------------------------|-----------------------------------------------------------------|
| `--bytes "<hex>"`       | Raw byte patch (legacy form)                                    |
| `--nop`                 | NOP-out the instruction at `<addr>`, size-preserving            |
| `--jmp <target>`        | Replace with `jmp <target>`, NOP-padded if shorter              |
| `--force-branch true`   | Replace conditional with `jmp <original-target>` (always-taken) |
| `--force-branch false`  | Replace conditional with NOPs (never-taken)                     |

`--verify` re-disassembles the patched VA in the output binary so
you can confirm the encoding.

`--force` overwrites the output file if it already exists.

## Find a target instruction

```bash
$ glaurung disasm $BIN --addr 0x11e0 --max-instructions 4
```

```text
engine: iced-x86 arch: x86_64
0x11e0: 3d350e0000           cmp eax, 0xe35
0x11e5: b000                 mov al, 0x0
0x11e7: e854feffff           call 0x1040
0x11ec: 4883c410             add rsp

note: truncated preview output.
- Read only first 256 bytes of file
- Stopped after 4 instructions
```

(Captured: [`_fixtures/02-patch/disasm-target.out`](../_fixtures/02-patch/disasm-target.out).)

We've got a 5-byte `cmp eax, 0xe35` at `0x11e0` and a 2-byte
`mov al, 0x0` at `0x11e5`. Both are clean instruction-boundary
targets to patch.

## NOP-out an instruction

Patch out the `cmp eax, 0xe35` at `0x11e0`:

```bash
$ glaurung patch $BIN /tmp/patched-nop.bin \
    --va 0x11e0 --nop --verify --force
```

```text
# Patch applied

- input:  `samples/.../hello-c-clang-debug`
- output: `/tmp/patched-nop.bin`
- VA: `0x11e0` (file offset `0x11e0`)

  before: `3d350e0000`
  after:  `9090909090`

_patched 5 bytes at VA 0x11e0 (file offset 0x11e0)_
_verify: Nop_
```

(Captured: [`_fixtures/02-patch/patch-nop.out`](../_fixtures/02-patch/patch-nop.out).)

The 5-byte `cmp` was replaced with five `0x90` NOPs. The
`_verify: Nop_` line confirms the first patched instruction
decodes as `nop` in the output binary.

## Raw byte patch

If you've decided exactly what bytes you want — say, NOP-out only
the 2-byte `mov al, 0x0` at `0x11e5`:

```bash
$ glaurung patch $BIN /tmp/patched-bytes.bin \
    --va 0x11e5 --bytes "90 90" --verify --force
```

```text
# Patch applied

- input:  `samples/.../hello-c-clang-debug`
- output: `/tmp/patched-bytes.bin`
- VA: `0x11e5` (file offset `0x11e5`)

  before: `b000`
  after:  `9090`

_patched 2 bytes at VA 0x11e5 (file offset 0x11e5)_
_verify: Nop_
```

(Captured: [`_fixtures/02-patch/patch-bytes.out`](../_fixtures/02-patch/patch-bytes.out).)

Spaces in the hex string are tolerated; case doesn't matter. The
byte length must match the original instruction's size for code
patches (otherwise you'll desync the surrounding instruction
stream).

## JSON output

```bash
$ glaurung patch $BIN /tmp/patched-json.bin \
    --va 0x11e0 --nop --verify --force --format json
```

```json
{
  "output_path":"/tmp/patched-json.bin",
  "va":4576,
  "file_offset":4576,
  "original_hex":"3d350e0000",
  "patched_hex":"9090909090",
  "notes":["patched 5 bytes at VA 0x11e0 (file offset 0x11e0)"],
  "verify":"verify: Nop"
}
```

(Captured: [`_fixtures/02-patch/patch-json.out`](../_fixtures/02-patch/patch-json.out).)

`va: 4576` is `0x11e0` decoded. Pipeline-friendly for batch
patching:

```bash
$ glaurung patch in.elf out.elf --va 0x1140 --nop --verify --force \
    --format json | jq -r '.notes[]'
patched 5 bytes at VA 0x1140 (file offset 0x1140)
```

## Force a branch (`--force-branch`)

Conditional jumps decode as `jcc` (e.g. `jne`, `jz`). To force the
condition always taken:

```bash
$ glaurung patch in.elf out.elf --va 0x1140 \
    --force-branch true --verify --force
```

This rewrites the `jcc <target>` as `jmp <target>` (size-preserving,
NOP-padded if `jmp` is shorter than the original `jcc`).

To force never-taken (equivalent to NOP-ing the jcc):

```bash
$ glaurung patch in.elf out.elf --va 0x1140 \
    --force-branch false --verify --force
```

## Redirect to a different VA (`--jmp`)

```bash
$ glaurung patch in.elf out.elf --va 0x1140 \
    --jmp 0x1200 --verify --force
```

Replaces the instruction at `0x1140` with `jmp 0x1200`. The patcher
picks the shortest near-relative encoding that fits in the
original instruction's size, NOP-padding any leftover bytes.

## Common patterns

| Need                                | Command                                                                  |
|-------------------------------------|--------------------------------------------------------------------------|
| Bypass a license check              | `glaurung patch <in> <out> --va <jcc> --force-branch true --verify`      |
| NOP-out an anti-debug call          | `glaurung patch <in> <out> --va <call-va> --nop --verify`                |
| Skip a region of code               | `glaurung patch <in> <out> --va <start> --jmp <end> --verify`            |
| Apply a hand-crafted byte sequence  | `glaurung patch <in> <out> --va <addr> --bytes "<hex>" --verify`         |

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
$ glaurung patch in.elf out.elf --va 0x1140 \
    --force-branch true --verify --force

# 2. Re-analyze the output.
$ glaurung kickoff out.elf --db patched.glaurung

# 3. Confirm the change.
$ glaurung view patched.glaurung 0x1140 \
    --binary out.elf --pane disasm
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
