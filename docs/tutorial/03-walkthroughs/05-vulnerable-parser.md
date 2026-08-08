# §Q — Vulnerable parser

Goal: use Glaurung to navigate a deliberately unsafe parser while keeping the
vulnerability claim grounded in shipped source and instruction-level evidence,
not pseudocode appearance alone.

## Known fixture truth

The source at `samples/source/c/vulnparse.c` deliberately copies a caller-
controlled one-byte length into a 64-byte stack buffer after checking only the
source length. Values above 63 can overflow `buf`, and the subsequent NUL write
can also exceed it. This known source is the oracle for the tutorial fixture.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0
DB=vulnparse.glaurung
file "$BIN"
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung find "$DB" "" --kind function
```

The current build places `parse_record` at `0x11e9` and `main` at `0x12ae`.
Resolve those addresses from the current project. See
[`file.out`](../_fixtures/03-vulnparse/file.out),
[`kickoff.out`](../_fixtures/03-vulnparse/kickoff.out), and
[`find-all-funcs.out`](../_fixtures/03-vulnparse/find-all-funcs.out).

## Trace input into the parser

```bash
uv run glaurung view "$DB" 0x12ae --binary "$BIN" \
  --pane pseudo --pseudo-lines 30
uv run glaurung xrefs "$DB" 0x11e9 --binary "$BIN" --direction to
```

The xref index currently records the direct call at `0x1324` inside `main`.
See [`view-main.out`](../_fixtures/03-vulnparse/view-main.out) and
[`xrefs-parse-record.out`](../_fixtures/03-vulnparse/xrefs-parse-record.out).

## Inspect the vulnerable body

```bash
uv run glaurung view "$DB" 0x11e9 --binary "$BIN" \
  --pane pseudo --pseudo-lines 30
uv run glaurung disasm "$BIN" --function parse_record \
  --max-instructions 160
```

The current pseudocode is intentionally linked rather than quoted in prose:
[`view-parse-record.out`](../_fixtures/03-vulnparse/view-parse-record.out).
It helps locate the length comparison and copy region, but decompiler output
alone is insufficient to prove buffer capacity, integer range, or overwrite
reach. Confirm:

1. the declared length originates from the input byte;
2. the check bounds reads against `total_len`, not writes against 64;
3. the destination is the fixed stack buffer;
4. the copy length can exceed its capacity;
5. the following terminator write uses the same unchecked index.

## Safety

The checked-in input is a purpose-built educational fixture. Do not turn this
chapter into an exploit recipe for unrelated software, and do not claim a
vulnerability in another binary without reproducing all relevant bounds and
control conditions.

Continue to [§R — UPX-packed binary](06-upx-packed-binary.md).
