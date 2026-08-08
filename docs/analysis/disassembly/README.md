# Disassembly

`glaurung disasm` decodes a bounded window of native instructions without
executing the target and without using an LLM. It can start at the detected
entry point, a supplied virtual address, or the beginning of the file.

Disassembly is not proof that bytes are reachable code. Data, padding,
overlapping instructions, an incorrect architecture, or a bad start address can
all produce plausible-looking instructions.

## Quick start

From the repository root:

```bash
BIN="samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"

uv run glaurung disasm "$BIN" \
  --max-instructions 40 \
  --window-bytes 512

uv run glaurung disasm "$BIN" \
  --max-instructions 40 \
  --window-bytes 512 \
  --json
```

The default start is the detected binary entry point. JSON is the appropriate
format for automation; plain and rich output are presentations for analysts.

## Start-address selection

- The default, or explicit `--entry`, asks the format analysis for an entry VA.
- `--addr 0x...` starts at that virtual address when it maps into the file.
- `--no-entry` starts at VA/file offset zero unless `--addr` is also supplied.

The current command is fail-soft: if a supplied or detected VA cannot be mapped,
it falls back to decoding from the start of the file and can still return zero.
Check `metadata.start_address` and the first instruction address in JSON instead
of assuming the requested address was honored.

For a known function in an existing project database:

```bash
uv run glaurung disasm "$BIN" \
  --db analysis.glaurung \
  --function main \
  --max-instructions 200
```

`--db` and `--function` must be supplied together for KB-aware function mode.
That mode uses stored function identity and CFG-derived bounds and includes a
coverage footer.

## Architectures and engines

With `--engine auto`, the current backend registry uses:

- iced-x86 for x86 and x86-64; and
- Capstone for ARM, AArch64, MIPS, MIPS64, PPC, PPC64, RISC-V, and RISC-V64.

The CLI accepts `auto`, `iced`, or `capstone`. Explicit `iced` is valid only for
x86/x86-64. Backend availability for Capstone architectures depends on the
compiled extension.

There is an important current wiring limit: `--engine` and `--arch` do not
control the mapped-VA path used for a valid entry point or `--addr`. That path
selects from the binary automatically. The two flags affect only the fail-soft
file-start fallback. Do not describe them as reliable overrides until the
mapped-window API accepts them.

The JSON `engine` field currently reports `iced-x86` for `auto` even when the
registry selected Capstone. Do not use that field as backend provenance until
the formatter is wired to the selected backend.

## Resource bounds

Current defaults are:

- `--window-bytes 8192`;
- `--max-instructions 2048`; and
- `--max-time-ms 5000`.

Tighten all three for untrusted or batch inputs. JSON metadata records byte- and
instruction-limit truncation, but the time limit is enforced in the backend and
is not currently exposed as a distinct truncation field.

## Output contract and limitations

Each JSON instruction contains an address, raw bytes, mnemonic, operands, and
length. Metadata contains the chosen start address and requested bounds.

`--comments` currently does not add annotations: its hook returns no comment.
Use KB-aware function mode or later xref/string workflows when annotated call
targets and data references matter.

An empty instruction list can still exit zero when architecture selection or
backend construction fails. Treat empty output as inconclusive and inspect
triage, the architecture override, and the requested VA.

## Exit status

- `0`: the command completed, including fail-soft or empty results;
- `2`: the input path is invalid, or KB-aware function selection failed; and
- an uncaught backend/format error can terminate the process nonzero.

Do not use exit zero alone as proof that meaningful code was decoded.

## Related workflows

- Use [`glaurung cfg`](../README.md) for function discovery and control-flow
  analysis.
- Use the [decompiler documentation](../decompiler/) for pseudocode and the
  LLIR/SSA/AST pipeline.
- Use the [triage guide](../../triage/) to establish format and architecture
  before overriding either.

Run `uv run glaurung disasm --help` for the current accepted values.
