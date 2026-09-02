# §T — Diff two binaries

> **Kind:** guide · **Status:** maintained

Goal: identify changed recovered functions between two related binaries and
interpret the command's shell status correctly.

```bash
OLD=samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2
NEW=samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2
status=0
uv run glaurung diff "$OLD" "$NEW" || status=$?
test "$status" -eq 1
```

Plain `diff` returns zero when no differences are found and one when the inputs
differ. This checked pair is intentionally different, so exit 1 is the expected
positive result. Input errors remain failures.

The current report identifies `dispatch` as changed and gives structural hashes,
sizes, and a similarity score. See
[`diff.out`](../_fixtures/04-diff/diff.out). These are recovered-analysis
signals, not a proof of semantic equivalence for functions listed as “same.”

## Follow up

1. Confirm both input hashes and build provenance.
2. Inspect the changed function in each binary with `disasm` and `decompile`.
3. Compare exact callsites, constants, and control-flow edges.
4. Run behavior-level tests when source or a safe execution harness exists.

Use `--format json` for automation and test the schema on the pinned Glaurung
revision before making it a release gate.

Continue to [§U — Exporting projects](exporting-to-ida-ghidra.md).
