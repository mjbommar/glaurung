# FLIRT-style signature libraries

> **Kind:** reference · **Status:** maintained

**Implemented.** `src/flirt/`, built by
`python -m glaurung.tools.build_flirt_library`, shipped in `data/sigs/`.
See [`data/sigs/README.md`](../../data/sigs/README.md) for what the shipped
library contains and how to rebuild it.

This page is about the mechanism. It covers what changed on 2026-09-02, why
`lancelot-flirt` was priced and declined, and what the matcher does now.

## The defect

Before this change the library was **30 exact 32-byte prologues harvested from
linked sample binaries**, compared with byte equality and no mask.

A linked image is the contaminated input. The linker has already resolved every
`call rel32` and every RIP-relative displacement to a value it chose for *that*
link, and it kept no record of which bytes those were. A prologue harvested
from one therefore records the layout, not the function.

The number, measured on the one real archive this repository ships
(`samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a`):
**19 of 20** functions have a relocation inside their 32-byte window. Those
signatures could not have matched the same function in any other build.

FLIRT, Ghidra FunctionID, Binary Ninja SigKit and WARP's `WARP\Process` all
take `.a` archives for the same reason. SigKit states it plainly: the linker
"basically copy-pastes it byte-for-byte... The only bytes that change are the
relocation bytes."

## The decision: not `lancelot-flirt`

`lancelot-flirt` 0.10.0 (Apache-2.0, released 2026-07-09, ~61k downloads,
`github.com/williballenthin/lancelot`) parses and matches real IDA `.pat` and
`.sig` files, and open signature sets exist for it (`fireeye/siglib`,
`Maktm/FLIRTDB`). It was priced first, as the survey asked. **Declined**, for
three reasons in descending weight:

1. **It does not do the half that was broken.** It parses and matches; it does
   not *build* signatures from an archive. Deriving variant-byte masks from
   `.o` relocation tables -- the actual fix -- would still have been ours to
   write, and we would additionally have had to emit IDA `.pat` format to hand
   it over.
2. **Its dependency tree is CLI-shaped and non-optional.** Thirteen direct
   dependencies, none behind a feature: `anyhow`, `better-panic`, `bitflags 1`,
   `bitvec`, `chrono`, `clap 3`, `fern`, `inflate`, `log`, `nom 7`, `regex`,
   `smallvec`, `thiserror`. Three of those are EOL major versions and
   `clap 3`, `fern` and `better-panic` are binary-shaped concerns in a library
   crate. That is a large permanent addition to a shipped crate in exchange for
   a masked-compare core that is under a hundred lines.
3. **The match model would need an adapter anyway.** Our hits flow into
   `Function` renaming and into the KB at `set_by=flirt`, which outranks
   `auto`; the ambiguity policy ("no name beats a wrong name") is ours and has
   to be enforced at our boundary regardless of who does the comparing.

**It remains the right answer to a different question.** The day we want to
*consume* third-party `.sig`/`.pat` libraries -- which is the only way to get
libc and MSVC coverage without building those toolchains ourselves -- that is
the crate, and it should go behind an optional feature so the dependency cost
falls only on people who ask for it. Nothing in this change forecloses that:
the on-disk schema is a superset of what a `.pat` line carries.

## What the format holds now

Schema version `"2"`. Every field added after v1 is `#[serde(default)]` and
every default is the v1 behaviour, so an old file still loads and still matches
exactly.

```jsonc
{
  "schema_version": "2",
  "arch": "x86_64",
  "prologue_len": 32,
  "library": {"name": "mathlib", "version": "1.0.0",
              "variant": "gcc-15.2.0-O2", "arch": "x86_64"},
  "entries": [{
    "name": "mathlib_add",
    "prologue_hex": "f30f1efa8305...",   // the pattern
    "mask_hex":     "ffffffffffff00000000ffff...", // ff = fixed, 00 = variant
    "crc16": 46863, "crc_len": 28,       // over bytes [32, 32+28)
    "function_len": 60,
    "refs": [{"offset": 14, "name": ".LC0"}],
    "source_binary": "mathlib.o!mathlib_add"
  }]
}
```

Variant bytes hold whatever the builder happened to see and are never compared.
Do not read them as library content; FLIRT splits pattern from mask
deliberately so a signature set is not a copy of the library it describes.

### Where each field comes from

| Field | Source |
|---|---|
| `mask_hex` | The `.o`'s relocation table: `[offset, offset + size/8)` for each relocation, clamped to the pattern. **Plus** every byte at or beyond `function_len`, because a short symbol's 32-byte window runs into whatever the linker placed next and that is a different neighbour in every link. |
| `crc16` / `crc_len` | IDA's exact CRC16 (`src/flirt/crc16.rs`), over the bytes following the pattern, stopping at the first variant byte, the end of the function, or 255 bytes -- whichever comes first. |
| `refs` | Every relocation inside the function that names a symbol other than the function itself, at its offset from the entry. |
| `library` | Given on the command line. |

### Why the CRC is not a generic CRC-16

`flair/crc16.cpp` is reflected CCITT (`0x8408`) with `0xFFFF` seeding, a final
complement, **a byte swap of the result**, and `0` defined for empty input.
All four details change the value. `src/flirt/crc16.rs` reproduces a published
vector -- `lancelot-flirt`'s README signature for `__EH_prolog3_catch_align`
records CRC `6562` over `0x20` bytes, and the 103 bytes of `utcutil.dll` it
matches are in the README too, so bytes `[32, 64)` of that buffer must hash to
`0x6562`. They do.

## Matching

`FlirtLibrary::match_at(data)` returns `None`, `Unique(name)` or
`Ambiguous(names)`. Three filters, in FLIRT's order:

1. **Masked pattern compare**, bucketed by the first pattern byte for
   signatures whose first byte is fixed.
2. **CRC16** over the recorded range. A candidate whose CRC range runs past the
   readable bytes is a **non-match**, not a free pass -- unverifiable is not
   verified.
3. **Referenced names**, via `match_at_with_refs(data, resolver)`. The resolver
   answers "what is the name of the thing this function references `offset`
   bytes in?". `None` means unknown and never eliminates a candidate; a name
   that disagrees with a candidate's recorded reference does. Survivors are
   ranked by how many references were positively confirmed.

`Ambiguous` is never collapsed to a name. A FLIRT hit is written at
`set_by=flirt`, which `provenance.py` ranks at 50, above `auto` and
`propagated` -- a false positive here does not degrade an answer, it *outranks*
the correct one. The builder applies the same rule at build time: two functions
whose **masked** patterns, masks and CRCs all agree but whose names differ are
both dropped.

### Signatures the builder declines to make

- Symbols smaller than `min_function_len` (default 8 bytes).
- Signatures with fewer than `min_fixed_bytes` (default 16) *fixed* pattern
  bytes. Stating the rule about surviving bytes rather than about length is
  what actually bounds the false-positive rate, because the mask decides how
  much of the window is compared.

**The floor of 16 was measured, not chosen.** At 8, the shipped library kept
four signatures with 10 or 11 fixed bytes, no CRC and no references --
`mathlib_version_major` is `endbr64; mov eax, 1; ret`, ten bytes -- and those
four named `zext_u32_to_u64` and two C++ methods in the fixture corpus: four
false positives out of 2,801 functions. A ten-byte function that returns a
constant is not identifiable by its bytes at any pattern length, and the only
honest thing to do with it is decline. Raising the floor to 16 drops exactly
those four plus one other (nothing in this archive sits between 11 and 17
fixed bytes) and takes the false-positive count to zero. FLIRT's answer to the
same problem is to match such functions only as *referenced* names from a
caller, never standalone; that is available here through
`match_at_with_refs` once a resolver is wired in.

## Keying

A library is `(name, version, variant, arch)`. **No exact or masked scheme
crosses an optimisation level** -- FLIRT, FunctionID, SigKit and WARP all say
so -- and a corpus spanning gcc and clang across `-O0` to `-O3` is not one
library but N libraries sharing a name. The variant is part of the identity,
not metadata about it. Cross-variant matching is the CFR rung's job; see
[`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md).

## Measured

`tests/flirt_signature_matching.rs`, 2026-09-02, against two images that link
the same `libmathlib.a` (`tests/fixtures/flirt/`, PIE and non-PIE, different
drivers):

| Measurement | Result |
|---|---|
| Signed functions with identical 32-byte windows in both links | **0 of 16** -- the exact matcher's ceiling |
| Named in both links by the shipped masked library | **16 of 16** |
| Named in both links by the same library with masks and CRC stripped | **0 of 16** |
| Names assigned in 767 functions across 60 unrelated sample binaries | **0** |
| Names assigned in 2,801 functions of the decompiler fixture corpus | **0** |
| `mathlib_*` recovered from a stripped image | **16** |

Rows two and three are the point: same pipeline, same bytes, masks removed.

## Not done here

- **Consuming third-party `.sig`/`.pat`.** See the `lancelot-flirt` decision
  above. This is the path to libc and MSVC coverage.
- **A `siglib` provenance table and `function_match` evidence rows.** The
  library file carries its key, but a match does not yet record *which* library
  and *which* level resolved it. That is item 7 in the research plan.
- **Referenced-name resolution wired into the analysis pass.**
  `match_at_with_refs` exists and is tested, but `apply_flirt_overrides` calls
  `match_at`: the pass has no resolver to hand it yet, because that needs the
  PLT and symbol maps threaded through. Until then a tie stays a tie and
  nothing is named, which is the safe direction.
- **A BinaryFuse8 membership gate.** Item 3 in the research plan; the shipped
  library is 16 signatures, so there is nothing to gate yet.
