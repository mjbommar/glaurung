# §F — Cross-references

Goal: distinguish references *to* an address from references *from* an exact
source address, and pivot from a callsite into deeper analysis.

## Set up and locate the function

```bash
BIN=samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
DB=demo.glaurung
uv run glaurung kickoff "$BIN" --db "$DB"
uv run glaurung find "$DB" print_sum --kind function
```

The current project places `print_sum` at `0x11d0`. See
[`find-print-sum.out`](../_fixtures/02-cross-references/find-print-sum.out).

## Find references to `print_sum`

```bash
uv run glaurung xrefs "$DB" 0x11d0 \
  --binary "$BIN" \
  --direction to
```

The current index records one call at `0x11bd`, inside `main`. `src_va` is the
call instruction, not the start of its containing function. The verified row is
[`xrefs-to-print-sum.out`](../_fixtures/02-cross-references/xrefs-to-print-sum.out).

Columns mean:

- `dir`: relationship relative to the queried address;
- `src_va`: exact source instruction address;
- `kind`: `call`, `jump`, `data_read`, `data_write`, or `struct_field`;
- `function`: containing source function when recovered;
- `snippet`: disassembly at the source site.

## Follow the callsite forward

`--direction from` is exact-address based. Query the callsite returned above:

```bash
uv run glaurung xrefs "$DB" 0x11bd \
  --binary "$BIN" \
  --direction from \
  --kind call
```

Querying `0x1150`, the entry of `main`, does not mean “aggregate every outgoing
edge in this function”; it asks for edges whose source is exactly `0x1150`.
This distinction was previously obscured by stale tutorial output. See
[`xrefs-from-main-call.out`](../_fixtures/02-cross-references/xrefs-from-main-call.out).

## Use JSON for both endpoints

```bash
uv run glaurung xrefs "$DB" 0x11d0 \
  --binary "$BIN" \
  --direction to \
  --format json
```

JSON includes numeric `src_va` and `dst_va` fields for scripting. The checked
payload is [`xrefs-json.out`](../_fixtures/02-cross-references/xrefs-json.out).

## Inspect both directions in the REPL

```text
g 0x11d0
x
```

The REPL reports recorded edges to and from the cursor. Zero outgoing edges
means the current index has none at that exact address; it is not proof that the
function performs no indirect calls or runtime data access. See
[`repl-x.out`](../_fixtures/02-cross-references/repl-x.out).

## Coverage limits

Xrefs are recovered evidence. Indirect calls, incomplete function discovery,
format-specific gaps, or missing data indexing can produce false negatives.
Cross-check important relationships in disassembly and, when possible, dynamic
analysis. Use `--direction both` only when the exact-address semantics match
your question; its current result is
[`xrefs-both.out`](../_fixtures/02-cross-references/xrefs-both.out).

Continue to [§G — Stack frames](stack-frames.md).
