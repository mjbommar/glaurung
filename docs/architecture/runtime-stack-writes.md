# Runtime stack-write relations

> **Kind:** architecture · **Status:** maintained

`glaurung-runtime-stack-write-report-v1` relates an observed input write to an
authoritative static stack-object contract without copying runtime state into
`ProgramImage` or the decompiler AST.

## Evidence chain

The first provider-neutral chain is:

1. a selected `read` event records the destination, returned length, input
   source, and exact LLIR call occurrence;
2. the owned fixture execution stops cooperatively immediately before and
   after the read;
3. the capsule retains exact executable mappings, observed RIP/RSP, a bounded
   hash-verified stack page, and two separately hash-bound 64-byte destination
   windows from that same execution;
4. the analyzer scans only that captured page for x86-64 frame records and
   accepts a `main` frame only when its return address resolves through an
   exact-image runtime/static relation;
5. the frame base is interpreted through the function's DWARF contract;
6. the resulting runtime interval is joined to one DWARF stack object and one
   field layout; and
7. the observed write interval is compared with both field and whole-object
   bounds; and
8. the before/after windows are joined to the realized fields and reduced to
   exact changed intervals; and
9. the input source range is intersected with the LLIR call effect and mapped
   onto every exactly covered DWARF field interval.

Each stage is typed as inferred or unknown. Missing stack bytes, a different
image, ambiguous frames, unsupported registers, missing DWARF, ambiguous
objects, and missing field layouts stop the chain instead of selecting a likely
answer.

The report now also compares the realized stack object itself. Object-level
changes are separate from field changes, so a bare DWARF array remains a real
stack object rather than being disguised as a synthetic struct field. A
missing field layout therefore blocks field conclusions without erasing an
independently proved whole-object interval.

## First real result

`memory_read_overflow` passes the 16-cell good/bad matrix across GCC and Clang,
`-O0` and `-O2`, and PIE and non-PIE builds with frame pointers. Every lane
describes the same 12-byte `struct box b`, but its location ranges from GCC's
`DW_OP_call_frame_cfa - 36`/`-52` to Clang's `rbp - 28`/`-48`. The relation
resolves each contract to the concrete destination and identifies the
eight-byte `dst` field.

The good execution writes eight bytes and reports `within_field`. The bad
execution writes twelve bytes and reports `crosses_field_boundary` with four
bytes beyond `dst`; it remains within the enclosing 12-byte object. The report
also retains the exact LLIR `call` occurrence that introduced those bytes.
Its typed `input_field_effects` relation maps source bytes `0..8` onto `dst`;
in the bad run it additionally maps source bytes `8..12` onto `canary`.
Runtime addresses, enclosing-object offsets, and field offsets remain separate
coordinates in the relation.
The field comparison reports `dst` changing from eight zero bytes to
`abcdefgh` in both runs. In the good run the adjacent little-endian `canary`
remains `0x1234abcd`; in the bad run its four bytes change from `cdab3412` to
`ijkl`. The harness projects these results, without loading the oracle, into
the expected changed-interval and unchanged-field facts. The bad run also
produces `memory / stack_object:box.dst / bounds_violation` with value
`read:length=12:declared_length=8`. All facts satisfy the independent semantic
oracle in the 16-cell matrix, and mutating the expected write length fails the
gate.

The negative controls are deliberately layered. Removing the stack page makes
frame and object realization unknown. Removing only the before-snapshot
payload preserves the frame and object relation but makes field changes
unknown. Supplying a different image makes the static relation unknown. The
analyzer never substitutes file bytes, zeroes, or a neighboring process's
mapping for missing runtime evidence.
Removing the event's input-source record specifically makes
`input_field_effects` unknown while leaving independently supported frame,
object, field, bounds, and snapshot conclusions intact.

## Integer conversion to write

The report also contains typed `integer_conversion_writes` relations. A
relation is emitted only when one executed store has all of the following:

1. a bounded static stored-value expression that reduces a wider frame load by
   an explicit truncation, low-bit extraction, or contiguous low-bit mask;
2. occurrence-time registers that resolve that load to exactly one earlier
   realized DWARF scalar object;
3. a narrower realized DWARF destination object whose observed value equals
   the stated reduction of the observed source value; and
4. exactly one subsequent, exact `memset` operation occurrence with a realized
   destination field and write bound.

This keeps static reduction semantics, runtime scalar values, source-variable
contracts, and the later memory effect as separate evidence joined by one
relation. In particular, CFA and machine-register offsets are never compared
as if they shared a coordinate system: their expressions must resolve to the
same runtime address in the observed frame.

`memory_integer_truncation` proves this chain across GCC and Clang, PIE and
non-PIE, for good and bad executions. The bad relation reports a 64-bit
`requested=265`, eight-bit `narrowed=9`, twelve-byte write, and eight-byte
`dst`. The good relation reports `8`, `8`, eight, and eight. The semantic
projection emits a bounds violation only for the bad relation.

## Deliberate limits

This first slice requires Linux x86-64, an owned cooperative child, two
fixture-timed stops, a bounded captured stack, a recoverable frame-pointer
chain, exact main-image identity, and authoritative DWARF stack-object and
field layouts. The stop helper controls acquisition timing only: the analyzer
consumes ordinary capsule events, registers, mappings, snapshots, payloads,
and static image bytes. It does not infer a stack object from a source fixture
name, decompiler rendering, or a nearby canary. It does not mutate static
variables with runtime addresses.

Optimized location lists, omitted frame pointers, non-DWARF binaries,
additional architectures, general control-dependence proofs, and arbitrary
machine-write completeness remain later work. Unsupported evidence produces
`unknown`.
