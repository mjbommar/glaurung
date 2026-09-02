# §R — UPX-packed binary

> **Kind:** guide · **Status:** maintained

Goal: detect a packed input, interpret the command's shell status correctly,
and avoid presenting stub analysis as analysis of the unpacked program.

## Identify the input

```bash
BIN=samples/packed/hello-go.upx9
file "$BIN"
```

The checked file is an x86-64 ELF without a section header. That alone does not
identify UPX; use packer-specific evidence. See
[`file.out`](../_fixtures/03-upx-packed/file.out).

## Run packer detection

```bash
status=0
uv run glaurung detect-packer "$BIN" || status=$?
test "$status" -eq 1
```

In plain output mode, `detect-packer` intentionally returns:

- `0` when the verdict is not packed;
- `1` when the verdict is packed;
- `2` for invalid input.

Therefore exit 1 is the expected positive signal for this fixture, not a tool
failure. JSON modes return zero and encode the verdict in data. The current
UPX evidence is [`detect-packer.out`](../_fixtures/03-upx-packed/detect-packer.out).

## Observe kickoff's fail-safe behavior

```bash
uv run glaurung kickoff "$BIN" --db packed.glaurung
```

By default, kickoff detects the packer and avoids pretending that analysis of
the packing stub represents the original Go program. See
[`kickoff.out`](../_fixtures/03-upx-packed/kickoff.out).

If deeper work is required, unpack only in an isolated environment with a
trusted tool, retain hashes for both artifacts, and restart analysis on the
unpacked output. Packer detection confidence and entropy are measured values,
not permanent constants.

Continue to [§S — Malware-style C2 sample](07-malware-c2-demo.md).
