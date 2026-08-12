# §G — Stack frames

Goal: inspect recovered stack slots, refine one supported name and type, and
verify the manual provenance.

## Set up and list the frame

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung frame "$DB" 0x1160 list --binary "$BIN"
```

Frame offsets are relative to the recovered function frame. The current slot
inventory is
[`frame-list-before.out`](../_fixtures/02-stack-frames/frame-list-before.out).
Never transfer an offset unchanged to another build.

## Re-run bounded discovery

```bash
uv run glaurung frame "$DB" 0x1160 discover --binary "$BIN"
uv run glaurung frame "$DB" 0x1160 list --binary "$BIN"
```

`discover` refreshes analyzer-provided slots; it is not a substitute for
checking uses. See
[`frame-discover.out`](../_fixtures/02-stack-frames/frame-discover.out) and
[`frame-list-after.out`](../_fixtures/02-stack-frames/frame-list-after.out).

## Rename and retype a supported slot

Disassembly and pseudocode for this sample show that `-0x1b0` receives a
37-byte systemd service-path string in a region extending to the next recovered
slot. Use a bounded 48-byte array rather than the old, unsupported 256-byte
guess:

```bash
uv run glaurung frame "$DB" 0x1160 rename \
  -0x1b0 service_path --binary "$BIN"
uv run glaurung frame "$DB" 0x1160 retype \
  -0x1b0 'char[48]' --binary "$BIN"
uv run glaurung frame "$DB" 0x1160 list --binary "$BIN"
```

The writes are captured in
[`frame-rename.out`](../_fixtures/02-stack-frames/frame-rename.out),
[`frame-retype.out`](../_fixtures/02-stack-frames/frame-retype.out), and
[`frame-list-final.out`](../_fixtures/02-stack-frames/frame-list-final.out).

The array size remains an analyst model derived from this build's layout. If
the evidence only establishes “pointer-like” or “buffer-like,” use a
conservative type and record the uncertainty.

## JSON output

```bash
uv run glaurung frame "$DB" 0x1160 list \
  --binary "$BIN" \
  --format json
```

The checked schema is
[`frame-list-json.out`](../_fixtures/02-stack-frames/frame-list-json.out).

## Safety rules

- Inspect all recorded uses before assigning semantic meaning.
- Keep analyzer recovery separate from manual interpretation.
- Re-render the function and verify that the type improves rather than distorts
  memory operations.
- Use undo history when a manual frame edit proves wrong.

Continue to [§H — Strings and data](strings-and-data.md).
