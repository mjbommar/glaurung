# §M — Native C with debug information

> **Kind:** guide · **Status:** maintained

Goal: walk a small ELF from file identity through function search, pseudocode,
and exact callsite xrefs without treating decompiler text as source truth.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=hello-c.glaurung
file "$BIN"
uv run glaurung kickoff "$BIN" --db "$DB"
```

The sample is a debug-rich x86-64 PIE. Current `file` and kickoff results are
[`file.out`](../_fixtures/03-hello-c-clang/file.out) and
[`kickoff.out`](../_fixtures/03-hello-c-clang/kickoff.out). Function and type
counts are measured output, not stable promises.

## Find the user-facing functions

```bash
uv run glaurung find "$DB" main --kind function
uv run glaurung find "$DB" "" --kind function
```

The shipped build currently places `main`, `print_sum`, and `static_function`
at `0x1150`, `0x11d0`, and `0x1200`. Obtain these addresses from your project;
do not transfer them to a rebuilt sample. See
[`find-main.out`](../_fixtures/03-hello-c-clang/find-main.out) and
[`find-all.out`](../_fixtures/03-hello-c-clang/find-all.out).

## Inspect pseudocode as a hypothesis

```bash
uv run glaurung view "$DB" 0x1150 --binary "$BIN" \
  --pane pseudo --pseudo-lines 25
uv run glaurung view "$DB" 0x11d0 --binary "$BIN" \
  --pane pseudo --pseudo-lines 8
```

The current decompiler exposes loop and flag mechanics that older tutorial
text incorrectly simplified. Read the live results in
[`view-main.out`](../_fixtures/03-hello-c-clang/view-main.out) and
[`view-print-sum.out`](../_fixtures/03-hello-c-clang/view-print-sum.out).
Validate branches, arguments, and stack operations against disassembly before
assigning semantics.

## Verify the direct callsites

```bash
uv run glaurung xrefs "$DB" 0x11d0 --binary "$BIN" --direction to
uv run glaurung xrefs "$DB" 0x1200 --binary "$BIN" --direction to
```

The current index records calls at `0x11bd` and `0x11c2`, both inside `main`.
The source address is the exact call instruction, not the function entry. See
[`xrefs-print-sum.out`](../_fixtures/03-hello-c-clang/xrefs-print-sum.out) and
[`xrefs-static-fn.out`](../_fixtures/03-hello-c-clang/xrefs-static-fn.out).

## Result

This workflow established file identity, recovered landmarks, inspected a
fallible higher-level rendering, and confirmed two direct call edges. That is a
stronger conclusion than copying old pseudocode or counting functions alone.

Continue to [§N — Stripped Go](02-stripped-go-binary.md).
