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

## COFF archives (MinGW-w64 `.a`, MSVC `.lib`)

Added 2026-09-03. Before that, `glaurung.analysis.flirt_signatures_from_archive_path`
returned **`raw=0`** for every COFF archive on the box --
`/usr/x86_64-w64-mingw32/lib/libmingwex.a`, `libmingw32.a` and
`/usr/lib/gcc/x86_64-w64-mingw32/13-win32/libgcc.a` -- while
`/usr/lib/x86_64-linux-gnu/libc.a` returned 4,375. It was not a parse failure:
`object` reads COFF, the archive walked, the members parsed.

### The diagnosis

Four things were checked against a real member
(`lib64_libmingwex_a-cacos.o`), and only the first was broken.

1. **A COFF symbol record has no size.** ELF's `STT_FUNC` carries `st_size`;
   COFF has nothing equivalent. The MS aux *function definition* record has a
   `TotalSize` field, but GCC writes it as zero, so `object` reports
   `size() == 0` for **every** function symbol in the archive -- asserted in
   `archive::tests::every_coff_function_symbol_reports_no_size`. The builder's
   `sym.size() < min_function_len` guard therefore rejected all of them. That
   one line was the whole of the failure.
2. **Symbol kinds were already right.** `object` maps
   `IMAGE_SYM_DTYPE_FUNCTION` to `SymbolKind::Text` for both
   `IMAGE_SYM_CLASS_EXTERNAL` and `IMAGE_SYM_CLASS_STATIC`, so published and
   file-local functions both arrive, and section definition symbols (`.text`,
   `.rdata`) arrive as `SymbolKind::Section` and are excluded.
3. **Section identity was never assumed.** The builder keys on the symbol's own
   section index, so MSVC's `/Gy` COMDAT `.text$mn` sections -- one function per
   section -- and GCC's `-ffunction-sections` need nothing special. `.drectve`
   and `.debug*` are skipped by requiring `SectionKind::Text`.
4. **Relocation widths were already right.** `object` reports COFF relocations
   in bits: 32 for `IMAGE_REL_AMD64_REL32`, `ADDR32`, `ADDR32NB` and `SECREL`,
   64 for `ADDR64`; i386's `REL32` and `DIR32` are both 32. So the generic
   `[offset, offset + size/8)` span is correct as written. **No COFF relocation
   is linker-relaxable** -- there is no COFF analogue of ELF's `R_386_GOT32X`,
   whose contract lets the linker rewrite the two opcode bytes before the field
   -- so no span is widened. An unrecognised relocation type reports size 0 and
   falls back to the architecture's pointer width, which over-masks by four
   bytes rather than missing the field.

### The rules

| Rule | Why |
|---|---|
| **Extent = next symbol in the section, or the section end.** | The only rule available with no size field. FLIRT's own `pcf` does the same. Strictly-greater, so two aliases at one address do not each derive an extent of zero. Applied to *any* format that reports `size() == 0`, so ELF assembly functions with no `.size` directive are picked up too; ELF output is otherwise byte-identical, verified by rebuilding the shipped library to a zero-line diff. |
| **Trailing alignment padding (`0x00`, `0x90`, `0xcc`) is trimmed off a derived extent, unless a relocation covers it.** | See below -- this is the rule that keeps the false-positive count at zero. The relocation guard is for an unlinked `jmp rel32` tail call, which really does end in four zero bytes. |
| **Section symbols are not references.** | A COFF relocation against a constant pool targets the `.rdata` *section* symbol. Recording `.rdata` as a referenced name would make the L4 disambiguator fire on a name that every COFF object contains and no resolver over a linked image can confirm -- so a resolver reporting the real symbol would *eliminate* the correct candidate. MinGW's `.refptr.<name>` COMDAT stubs are ordinary symbols, not section symbols, and are kept. |
| **i386 COFF loses exactly one leading underscore.** | `_cacos` is the cdecl decoration of `cacos`; `___mingw_vfprintf` is `__mingw_vfprintf`. Inside an `__imp_` prefix the underscore comes off the tail, so `__imp__GetLastError` becomes `__imp_GetLastError` -- the import indirection is real and stays named as such rather than being rewritten to the target. x86-64, ARM and AArch64 COFF are undecorated and untouched. |
| **Non-object members are skipped, not errors.** | An MSVC `.lib` has a *first* and a *second* linker member (both named `/`) then `//` for long names, where a GNU `.a` has one `/`; `object`'s archive reader walks past all of them. A short-import member (`IMPORT_OBJECT_HDR_SIG2`, magic `00 00 ff ff`) is `FileKind::CoffImport`, which `object::File::parse` declines -- so an import-only library yields an empty list rather than an error. |

### Alignment padding was the whole false-positive story

`libmingwex.a`'s `alarm` is `xor eax,eax; ret` -- three bytes, alone in a
16-byte-aligned section. With the extent running to the section end, it signs as
**sixteen fixed bytes, thirteen of them `0x90`**. It clears the
`min_fixed_bytes` floor of 16 on padding alone, and padding is identical in
every object ever compiled. Measured on a MinGW `hello.exe` before the trim was
added: `alarm` was applied to `_setargv` and `__tlregdtor`, and `libgcc.a`'s
one-byte `__clear_cache` to `__gcc_deregister_frame` -- five wrong names at
`set_by=flirt` rank across two link layouts. With the trim, `alarm` is three
bytes, falls below `min_function_len`, and is correctly never signed; the wrong
names go to **zero**.

This is the same lesson `min_fixed_bytes` records one section up, arriving by a
different road: what bounds the false-positive rate is how many bytes are
*compared and specific to the function*, and a derived extent can inflate that
count without inflating the information.

### Measured

Release build, this box, best of three runs. "raw" is what the extractor
returns, "unique" what survives the builder's ambiguity rule.

| archive | MB | raw | unique | ambiguous | masked | with CRC | with refs | build |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `libmingwex.a` | 2.0 | 474 | 391 | 23 | 129 | 352 | 235 | 4 ms |
| `libmingw32.a` | 0.2 | 31 | 31 | 0 | 24 | 24 | 26 | <1 ms |
| `libgcc.a` (mingw) | 2.9 | 446 | 390 | 16 | 127 | 343 | 298 | 4 ms |
| `libmsvcrt.a` (mingw) | 2.2 | 278 | 162 | 26 | 159 | 136 | 100 | 3 ms |
| `libkernel32.a` (mingw) | 1.6 | 31 | 23 | 1 | 31 | 0 | 0 | 2 ms |
| `mingw_crt_subset.a` (fixture) | 0.1 | 62 | 62 | 0 | 25 | 57 | 44 | <1 ms |
| `import_only.msvc.lib` (fixture) | 0.0 | 0 | 0 | 0 | 0 | 0 | 0 | <1 ms |
| `libc.a` (ELF control) | 6.2 | 4375 | 2690 | 137 | 1953 | 2233 | 2189 | 39 ms |
| `libmathlib.a` (ELF, shipped) | 0.0 | 16 | 16 | 0 | 16 | 14 | 1 | <1 ms |

The two ELF rows are the control, and it was run as an A/B rather than asserted:
the change was reverted with `git apply -R`, the extension **rebuilt**, and
`libc.a` measured again. All 2,690 entries are identical in name, pattern, mask,
CRC and length across the two builds -- 0 added, 0 removed. Rebuilding
`data/sigs/glaurung-base.x86_64.flirt.json` likewise produces a zero-line diff.
Nothing about the ELF path moved. The same A/B on the reverted build gives
**0** signatures for `libmingwex.a`, `libmingw32.a`, `libgcc.a` and the fixture,
which is the "before" column of the table above.

### The relink measurement

`samples/source/c/hello.c` built twice with `x86_64-w64-mingw32-gcc -O2`: link A
plain, link B with three filler functions ahead of it and
`-Wl,--image-base,0x180000000`. Both stripped. The library is
`tests/fixtures/flirt/coff/mingw_crt_subset.a` -- the 27 CRT objects the link
map says `hello.exe` actually pulls. Ground truth is `x86_64-w64-mingw32-nm` on
the unstripped images (`tests/flirt_signature_matching.rs`,
`one_mingw_archive_linked_two_ways_is_named_in_both`).

| Measurement | Result |
|---|---|
| Signatures from the archive (before this change) | **0** |
| Signatures from the archive (after) | **62** |
| Named in link A / link B | **62 / 62** |
| Correct against the `nm` truth | **124 of 124** |
| Wrong | **0** |
| Ambiguous | **0** |
| Named in **both** links | **62** |
| ...of those, at a **different** address in the two links | **62 of 62** |
| Named in both with `mask_hex` and the CRC stripped | **37** -- the exact matcher's ceiling |

The last row is the control the ELF fixture has too: same archive, same
discovery, same matcher, masks removed. Here it does not fall to zero the way
`mathlib`'s does, because 37 of these 62 CRT functions have no relocation
anywhere in their 32-byte window; the 25 that do are exactly the 25 an
exact-byte library loses on every relink.

### Not covered

**No MSVC-built `.lib` was available to test.** There is no Microsoft toolchain
on this machine and no `.lib` under the Windows corpora on `/nas4`
(`windows-corpus`, `windows-packages`, `windows-seeds` -- searched, zero hits),
so the MSVC-specific claims above are supported by the archive *layout*
(`llvm-lib`, byte-for-byte the same first/second-linker-member structure MSVC's
`lib.exe` writes) and by the short-import member format, but not by MSVC's own
code generation. `.text$mn` COMDAT handling in particular is argued from the
code path -- the builder never looks at a section's name -- rather than
measured. That is the first thing to check the day a real `.lib` is to hand.

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

## Provenance and the membership gate

Item 7 of the research plan
([`docs/history/program-measures-2026-09-02.md`](../history/program-measures-2026-09-02.md)):
a BinaryFuse8 membership gate over known identities, and the four KB tables
that let a match say which library it came from and which level resolved it
(`03-schema.sql` sections 1, 2, 7, 8: `siglib`, `siglib_function`,
`identity_filter`, `function_match`).

### The gate

`src/identity/gate.rs` builds a `xorf::BinaryFuse8` over the identity strings
of one `(scheme, architecture)`. `xorf` 0.13.0 (MIT) with
`default-features = false, features = ["binary-fuse", "serde"]`: the crate's
defaults include `uniform-random`, which fills unused fingerprint slots from
`rand::thread_rng()` and makes two builds over identical keys produce
different bytes -- measured in the survey, and re-verified here
(`two_builds_over_the_same_keys_are_byte_identical`). With defaults off, the
fill is deterministic zero and the whole filter is a pure function of its key
set. Identity strings hash to the filter's `u64` keys via BLAKE3 (first 8
bytes), not `std::hash`'s `SipHash`, because the standard hasher is
process-seeded by default -- the same determinism trap one level up.

Serialization is xorf's `DmaSerializable`/`FilterRef` split: an 8-byte key
count plus a 20-byte descriptor are copied, and the fingerprint bytes -- the
part that scales with key count -- are read back with `BinaryFuse8Ref`
straight out of the `identity_filter.filter` BLOB, no copy. Python:
`glaurung.analysis.identity_gate_build(identities) -> bytes`,
`identity_gate_contains(blob, identity) -> bool`,
`identity_gate_n_keys(blob) -> int`.

**Measured.** `src/identity/gate.rs`'s own tests, over 150,000 synthetic keys,
release-equivalent debug build: **9.393 bits/key, 0.385% false-positive rate**
(xorf's own published figures at that scale are ~9.04 bits/key and ~0.39%).
`tests/identity_gate.rs` runs the gate over every WARP function GUID this
repository's native sample corpus produces (83 binaries under
`samples/binaries/platforms/linux/amd64/export/native/`): **3,255 identities,
249 distinct, 12.337 bits/key, zero false negatives** -- the higher bits/key
than the synthetic run is the same fixed-overhead effect small key sets show
in the KB measurements below, not a defect. The same file's second test is
the deliverable's stated negative control: a gate built from `mathlib`'s WARP
identities (read from one `tests/fixtures/flirt/` relink layout) accepts every
`mathlib_*` function read from the *other* relink layout and rejects every
non-library function in both that fixture and an entirely unrelated sample
binary (`hello-clang-debug`). Probe cost is not independently rebenchmarked
in this lane; xorf's own published figure is ~3 ns.

At the tiny scale this repository's own libraries reach today, the fixed
per-filter overhead dominates: the shipped FLIRT library's 16 masked-pattern
identities measure **38.0 bits/key**, and `mathlib`'s 22 WARP identities (21
distinct -- see below) measure **28.95 bits/key**
(`python/tests/test_kb_siglib.py`). Neither is a useful storage figure by
itself; they are recorded because a bits/key number is not a measurement
without the corpus size next to it, and this repository's own libraries are
this small today.

### The four tables

`python/glaurung/llm/kb/siglib.py` implements `03-schema.sql` sections 1, 2,
7 and 8 verbatim, following `function_structural.py`'s pattern (its own
`_SCHEMA`/`_ensure`, not joined into `xref_db`'s schema script). `siglib` is
keyed `(name, version, variant, architecture, platform)`; `siglib_function`
is deduplicated on `(siglib_id, scheme, identity, name)` with `occurrences`
bumped on re-ingest (BSim's `vectable.count`, Lumina's popularity);
`identity_filter` holds one gate BLOB per `(scheme, architecture)`;
`function_match` records `score`, `confidence`, `rank`, `ambiguous` and
`evidence`. `base_name` is `siglib.base_name_of`: the demangled name
(`glaurung.strings.demangle_text`) with its `::`-namespace and a parameter
list dropped and leading underscores stripped -- FunctionID's grouping key.

`siglib.ingest_flirt_library` records the rebuilt library's provenance:
`data/sigs/glaurung-base.x86_64.flirt.json` inserts a `siglib` row keyed
**`(mathlib, 1.0.0, gcc-15.2.0-O2, x86_64)`** and one `siglib_function` row
per signature, under a new scheme, **`flirt-masked-pattern-v1`**
(`src/flirt::MASKED_PATTERN_SCHEME`) -- the masked pattern hex, *not* a
`function_identity` scheme, because a masked pattern is gate/provenance input
rather than an equality key (see [Matching](#matching) above). The identity
is computed by `FlirtLibrary::masked_pattern_identities` /
`FlirtSignature::masked_pattern_hex` on the Rust side and by
`siglib._masked_pattern_hex` on the Python side -- the same equivalence
`build_flirt_library.py::_masked_pattern` already uses to decide which
signatures collide, implemented three times because none of the three call
sites has a compiled library object the other two could borrow.

### Evidence: which level resolved a match

`FlirtLibrary::match_at_with_evidence` and the free function
`match_functions_with_evidence` are the evidence-carrying counterparts of
`match_at` and `apply_flirt_overrides`: same escalation, but the return value
names which level resolved a `Unique` verdict.

| Evidence | What ran |
|---|---|
| `flirt-L1` | Masked pattern compare only; no surviving candidate records a CRC. |
| `flirt-L2` | At least one surviving candidate's CRC was checked. |
| `flirt-L3` | *Not implemented.* Schema-reserved (`siglib_flirt.tail_offset`/`tail_byte`); this matcher has no tail-byte discriminator. |
| `flirt-L4` | Pattern and CRC left more than one name; a referenced name broke the tie. |
| `warp-guid` | Exact WARP GUID equality against a `siglib_function` row. |
| `warp-constraint` | *Not implemented this lane.* WARP GUID collisions are reported ambiguous (below), not resolved by constraint proof. |

`ambiguous = 1` rows carry `evidence = NULL` and no name is applied -- "no
name beats a wrong name" reaches this table too. It is not a hypothetical:
`mathlib_get_global_seed` and `mathlib_set_global_seed` produce the **same**
WARP GUID in both relink layouts (two trivial one-block accessors whose
masked bytes happen to coincide), so ingesting `mathlib`'s 22 named WARP
functions yields 21 *distinct* identities, and `siglib.match_warp_library`
correctly reports both as ambiguous, one `function_match` row per candidate,
rather than guessing (`python/tests/test_kb_siglib.py::test_ingest_and_match_warp_library_across_a_relink`).

`siglib.match_flirt_library` and `siglib.match_warp_library` are the two
match paths. WARP's is the gate's real pre-lookup role: a candidate's GUID is
directly comparable to a library identity with no masking step in between, so
a gate negative skips the `siglib_function` lookup entirely and is counted in
`MatchSummary.gate_stats` (mirroring `crate::identity::gate::GateStats`).
FLIRT's masking has to run first to know which bytes even count, so its gate
check is necessarily post-hoc -- a positive-control verification that the
matched candidate's own masked-pattern identity is, as it must be by
construction, a member.

### Not done here

- **Consuming third-party `.sig`/`.pat`.** See the `lancelot-flirt` decision
  above. This is the path to libc and MSVC coverage.
- **Referenced-name resolution wired into the analysis pass.**
  `match_at_with_refs` exists and is tested, but `apply_flirt_overrides` calls
  `match_at`: the pass has no resolver to hand it yet, because that needs the
  PLT and symbol maps threaded through. Until then a tie stays a tie and
  nothing is named, which is the safe direction.
- **FLIRT's L3 tail-byte discriminator and WARP constraint-based
  disambiguation.** Both are schema-reserved (`siglib_flirt.tail_offset`/
  `tail_byte`, `siglib_reference`) but not implemented by either matcher; a
  collision at either level is reported ambiguous rather than resolved.
- **`siglib_flirt` and `siglib_reference` (schema sections 3)** are not
  populated: the shipped matcher works directly off the JSON library file,
  not off a SQL-indexed masked-prefix table. Building that index is future
  work once a library is large enough that a linear in-memory scan stops
  being the cheaper option (see the schema survey's "flat scan until 1e5"
  guidance).
