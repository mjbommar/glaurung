# §L — Patch and verify

> **Kind:** guide · **Status:** maintained

Goal: inspect an exact instruction, write a size-preserving patch to a separate
file, and understand the limit of byte-level verification.

## Inspect the target first

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
uv run glaurung disasm "$BIN" --addr 0x11e0 --max-instructions 4
```

The checked instruction window is
[`disasm-target.out`](../_fixtures/02-patch/disasm-target.out). Addresses and
instruction lengths are build-specific; never transfer this patch to a binary
without confirming its identity and bytes.

Nothing in this project writes to `/tmp` — it is a shared, per-user-quota'd
tmpfs on the reference machine. Write patched output under `$TMPDIR` (or the
same fallback the harness uses, `~/.cache/glaurung/tmp`) instead:

```bash
SCRATCH="${TMPDIR:-$HOME/.cache/glaurung/tmp}"
mkdir -p "$SCRATCH"
```

## NOP one instruction into a new output

```bash
OUT="$SCRATCH/hello-c-clang-debug.nop"
uv run glaurung patch "$BIN" "$OUT" \
  --va 0x11e0 --nop --verify --force
```

`--nop` determines the decoded instruction length and replaces those bytes with
NOPs. `--verify` re-reads and decodes the output. `--force` allows replacing the
explicit output path; omit it when accidental overwrite protection matters.
See [`patch-nop.out`](../_fixtures/02-patch/patch-nop.out) — its checked-in
`output:` line shows `/tmp/tutorial-fixtures/patched-nop.bin` because
`scripts/verify_tutorial.py` normalizes its own `$TMPDIR`-derived scratch
directory to that fixed token so fixtures compare identically across
machines; it is a display convention in the checked-in evidence, not a
real write to `/tmp`.

## Write explicit bytes only when length is known

```bash
OUT="$SCRATCH/hello-c-clang-debug.bytes"
uv run glaurung patch "$BIN" "$OUT" \
  --va 0x11e5 --bytes '90 90' --verify --force
```

Raw bytes bypass instruction-intent safeguards. Confirm the original span,
instruction boundaries, file-to-VA mapping, and architecture first. The checked
result is [`patch-bytes.out`](../_fixtures/02-patch/patch-bytes.out).

## Machine-readable result

```bash
uv run glaurung patch "$BIN" "$SCRATCH/hello-c-clang-debug.json-patch" \
  --va 0x11e0 --nop --verify --force --format json
```

See [`patch-json.out`](../_fixtures/02-patch/patch-json.out) for the current
schema.

## What verification proves

Patch verification proves that Glaurung wrote the intended byte sequence at the
resolved file offset and could decode the result. It does **not** prove:

- control-flow or calling-convention correctness;
- program equivalence or exploitability changes;
- signature, checksum, loader, or relocation validity;
- safe runtime behavior.

Keep the input immutable, record its hash, diff the output, and execute patched
programs only in an appropriately isolated environment. Project undo history
does not revert files written by `patch`.

Continue to [§M — Native C walkthrough](../03-walkthroughs/01-hello-c-clang.md).
