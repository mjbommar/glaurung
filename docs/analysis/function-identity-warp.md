# WARP function GUIDs

**Status: implemented for x86 and x86-64.** `src/identity/warp.rs`, exposed as
`glaurung.analysis.warp_function_guids_path`, stored under the
`function_identity` scheme `warp-function-guid-v1`.

WARP is Vector 35's interchange format for function information
([github.com/Vector35/warp](https://github.com/Vector35/warp), Apache-2.0). Its
identity primitive is a UUIDv5 over relocation-masked instruction bytes. It is
the **L0** rung of the identity ladder in
[`docs/research/program-measures-2026-09-02.md`](../research/program-measures-2026-09-02.md):
the cheapest, most exact answer to "is this exactly a known build of a known
function?", looked up by equality in O(1).

It is a *stronger FLIRT*, not a similarity metric. It is invariant to address
and relocation and to nothing else. Two builds of the same source at `-O0` and
`-O2` never share a GUID, and neither do two compilers. That is a property of
the scheme, not a defect: cross-variant matching is what the CFR rung exists
for.

## The spec, as implemented

### Namespaces

| Object | Namespace |
|---|---|
| Basic block | `0192a178-7a5f-7936-8653-3cbaa7d6afe7` |
| Function | `0192a179-61ac-7cef-88ed-012296e9492f` |
| Constraint | `019701f3-e89c-7afa-9181-371a5e98a576` |

Taken verbatim from the WARP README and from
`rust/src/signature/{basic_block,function,constraint}.rs`.

### Basic-block GUID

UUIDv5 over the block's instruction bytes in execution order, after three
transforms applied per instruction:

1. **Zero every relocatable instruction.** Contribute its length in zero bytes.
2. **Drop NOPs.** Contribute nothing.
3. **Drop effectively-NOP self-moves.** `mov reg, reg`, which compilers emit as
   hot-patch space.

### Function GUID

UUIDv5 over the concatenated 16-byte block GUIDs, blocks sorted by start
address **highest to lowest**.

### Constraint GUID

UUIDv5 over a function GUID's 16 bytes, a symbol name's UTF-8 bytes, or a
`u64`'s little-endian bytes. A constraint pairs that GUID with an optional
signed offset. We emit three kinds:

| Kind | Offset |
|---|---|
| `callee` | The call site's offset from this function's entry. Positive or negative; WARP's own `(GUID, 48)` example. |
| `caller` | `None`. A caller's call site is an offset into the *caller*, and no distance between the two entries survives a rebase, so there is nothing honest to record. WARP spells this `i64::MAX`; we spell it `None` and convert only at a serialization boundary. |
| `adjacent` | The neighbour's entry minus this entry, for the function immediately before and after by address. |

Constraints are sorted by `(kind, guid, offset)` and deduplicated, so the list
is a function of the binary and not of iteration order.

## The masking rules, with the arch caveat

An instruction is **relocatable** when an operand is a constant pointer into a
mapped region, or computes one with a constant offset. On x86 that is four
shapes, checked with iced-x86:

1. A direct `call`/`jmp` with a `rel8`/`rel16`/`rel32` displacement whose
   resolved target is mapped. The README's own `e8b55b0100` example.
2. A RIP/EIP-relative memory operand. Always relocation-bearing: the
   displacement is a distance the linker chose.
3. An absolute memory operand (no base, no index) whose displacement is mapped.
   Non-PIE data references.
4. A 32- or 64-bit immediate that is itself a mapped address.

**"Mapped" carries a floor of one page** (`MIN_PLAUSIBLE_POINTER = 0x1000`).
Without it, a PIE's first `LOAD` starts at virtual address 0 and every small
integer in the program reads as a pointer -- in the PIE build only. That was
not hypothetical: `mathlib_version_major` is ten bytes, `endbr64; mov eax, 1;
ret`, byte-for-byte identical in the two relink fixtures, and it produced two
different GUIDs until the floor existed, because `mov eax, 1` was masked in the
PIE image and kept in the non-PIE one. The floor is a **syntactic
approximation** of WARP's semantic rule ("an operand *used as* a constant
pointer"), and it is wrong for a firmware image whose code genuinely lives in
the first page.

### The `mov edi, edi` distinction

On x86-64, writing a 32-bit register zero-extends into the full 64-bit
register, so `mov edi, edi` **changes** `rdi` and is kept. Every other width,
and every width in 32-bit mode, leaves the architectural state unchanged and is
dropped. This is the case the WARP README calls out by name; it is
`is_effective_nop_self_move` in `src/identity/warp.rs` and is tested both ways
round.

### Architectures

x86 and x86-64 only. AArch64 and ARM32 are a documented **TODO**:
`warp_functions_from_bytes` returns `WarpError::UnsupportedArchitecture` rather
than emitting a value that would not be a WARP GUID. The work is not a port of
the x86 predicate -- on those ISAs a pointer is materialised across two or more
instructions (`adrp` + `add`, the README's own `add x1, x1, #0xf10` example),
so the rule needs a small constant propagation over the block rather than a
per-instruction test.

## Verification

The `warp` crate is Apache-2.0 but is **not on crates.io** -- the crates.io
`warp` is Sean McArthur's HTTP framework -- so using it would mean a git
dependency in a shipped crate. It also could not do the whole job:
`BasicBlockGUID::from(&[u8])` hashes bytes that are *already* masked, and the
masking itself lives in Binary Ninja's closed core rather than in the open
crate. So there is no crate cross-check. Instead, `src/identity/warp.rs`
asserts upstream's own published vectors directly, which is the stronger test
of the two:

| Test | Vector | Source |
|---|---|---|
| `matches_the_warp_readme_worked_example` | three block GUIDs -> `7a55be03-76b7-5cb5-bae9-4edcf47795ac` | WARP README |
| `matches_the_warp_crate_unit_test_vector` | three block GUIDs -> `1bef6187-74d9-5ebe-a0eb-4dbe6a97e578` | `warp` `rust/tests/signature.rs` |

**One rule could not be verified against source.** The block sort direction is
stated in the README ("sorted highest to lowest start address") and read the
same way by the survey, but the sort itself happens in Binary Ninja's closed
core -- the open `FunctionGUID::from_basic_blocks` takes an already-ordered
slice. It is therefore documented prose, not read code.
`sort_blocks_for_function_guid` is the single place that decision lives, so a
correction is a one-line change with a name to search for.

## What the KB writes

`python/glaurung/llm/kb/function_identity.py`:

```python
from glaurung.llm.kb import function_identity as fid

fid.index_function_identities(kb, path, scheme=fid.WARP_FUNCTION_GUID_V1)
```

One row per function in `function_identity(binary_id, entry_va, scheme,
identity, n_blocks)`:

- `scheme` = `"warp-function-guid-v1"`, the same string
  `glaurung.analysis.warp_scheme()` returns. Two spellings would split the
  table in half, so a test asserts they agree.
- `identity` = the GUID as a lowercase hyphenated UUID string.
- `n_blocks` = how many basic blocks went into it. This is the honest
  denominator for "how much evidence is behind this identity": a one-block
  GUID is exact but cheap to collide with.

This is a **new scheme value in the existing column**, not a schema change, not
a migration and not a second table -- exactly what that module's docstring
anticipated. `glaurung-structural-v1` is untouched, and a function may carry
both at once. `compute_identities`, `set_function_identity`,
`index_function_identities`, `is_indexed`, `find_by_identity`,
`resolve_entry_va` and `port_annotations` all already took a `scheme`
parameter; they now all work under either.

**Constraints are not stored.** `function_identity` holds one string per
`(binary, entry_va, scheme)`, and a constraint set is a relation rather than a
scalar. They are available through the binding
(`WarpFunction.constraints`); persisting them belongs with the
`function_reference` table the survey proposes, not with the identity column.

## Python API

```python
import glaurung as g

for fn in g.analysis.warp_function_guids_path("/bin/ls"):
    print(fn.guid, hex(fn.entry_va), fn.name, len(fn.block_guids))
    for c in fn.constraints:
        print("   ", c.kind, c.guid, c.offset)
```

`WarpFunction` carries `guid`, `entry_va`, `name`, `block_guids` (in hashing
order, highest address first) and `constraints`. `WarpConstraint` carries
`guid`, `offset`, `kind` and `label`. The label is the name the constraint was
derived from and is **never** part of the GUID -- a stripped build has to agree
with a symbolised one.

Raises `OSError` if the file cannot be read and `ValueError` if it is not a
parseable object or its architecture is unsupported.

## Measured

`python/tests/test_warp_function_guids.py`, 2026-09-02, on the two fixtures in
`tests/fixtures/flirt/` that link the same `libmathlib.a` as a PIE and as a
non-PIE with different amounts of driver code ahead of it:

- **22 of 22** `mathlib_*` functions present in both images keep the same
  function GUID across the relink.
- Before the pointer floor was added, 4 of those 22 changed.

## Notes and limits

- `entry_va` is a **label**, not part of the identity. WARP's per-block
  construction tolerates non-contiguous functions and multiple entry points;
  a byte-range prologue signature does not.
- WARP deliberately never prunes colliding functions, so one GUID may name
  several. `port_annotations` refuses to carry an annotation across an
  ambiguous identity, which is the right behaviour here as it is for the
  structural scheme.
- The GUID depends on the CFG our discovery recovers. Two tools that split
  blocks differently will not agree, and neither will we with ourselves if
  discovery changes. That is inherent to the scheme -- upstream says so:
  "the algorithm must be carefully upgraded to ensure that previously
  generated UUIDs are no longer valid."
