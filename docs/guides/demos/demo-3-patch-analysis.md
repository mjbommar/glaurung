# Demo 3 — Patch analysis

> **Kind:** guide · **Status:** maintained

This demo compares two related checked-in binaries:

```text
old: samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2
new: samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2
```

The goal is to identify a changed recovered function and define the follow-up
evidence needed before calling the change a security fix.

## 1. Run the structural diff

```bash
OLD=samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2
NEW=samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2

status=0
uv run glaurung diff "$OLD" "$NEW" || status=$?
test "$status" -eq 1
```

For `diff`, exit 0 means no reported difference and exit 1 means differences
were found. The checked pair is intentionally different, so the verifier
requires exit 1. Input or execution errors are not accepted as positive diff
signals.

The current [`diff.out`](../../tutorial/_fixtures/04-diff/diff.out) reports one
changed recovered function, `dispatch`, with its structural hashes, sizes, and
similarity. The other recovered functions are classified as unchanged. These
are analysis signals, not semantic-equivalence proofs.

## 2. Inspect both sides

```bash
OLD_DB=switchy-old.glaurung
NEW_DB=switchy-new.glaurung

uv run glaurung kickoff "$OLD" --db "$OLD_DB"
uv run glaurung kickoff "$NEW" --db "$NEW_DB"

uv run glaurung disasm "$OLD" --db "$OLD_DB" --function dispatch \
  --max-instructions 200 > dispatch-old.asm
uv run glaurung disasm "$NEW" --db "$NEW_DB" --function dispatch \
  --max-instructions 200 > dispatch-new.asm

uv run glaurung decompile "$OLD" --func dispatch --style c \
  > dispatch-old.c
uv run glaurung decompile "$NEW" --func dispatch --style c \
  > dispatch-new.c

diff -u dispatch-old.asm dispatch-new.asm || true
diff -u dispatch-old.c dispatch-new.c || true
```

The `|| true` applies only to the final display diffs, whose expected status is
1 when text differs. Do not apply it to the Glaurung commands; a failed analysis
must remain a failure.

Review exact comparisons, branches, constants, indirect targets, and callers.
Pseudocode can make the delta easier to read, but disassembly and behavior are
the stronger evidence surfaces.

## 3. Bound the conclusion

The deterministic report supports “`dispatch` changed structurally between
these two artifacts.” It does not, by itself, establish:

- which source edit produced the change;
- whether the edit fixes a defect;
- whether any pre-change behavior was reachable from untrusted input;
- whether the two complete programs are behaviorally equivalent elsewhere; or
- the severity or exploitability of a suspected security issue.

To classify a security fix, add build provenance, exact control/data-flow
analysis, caller input constraints, source or symbol evidence where available,
and behavior-level tests in a safe harness.

The verified recipe is
[Diff two binaries](../../tutorial/04-recipes/diffing-two-binaries.md).
