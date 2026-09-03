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

## Sources: where the archives come from

The `--archive` input is not this repository's own corpus. Until 2026-09-03 the
only `.a` this builder had ever been pointed at was
`samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a` --
twenty functions of fixture C, which is enough to prove the mechanism and
nothing else. A library that names anything an analyst will meet has to come
from the distribution's own static archives, and those already exist inside the
`samples/docker` build images along with the `dpkg` database that says where
each one came from.

`samples/docker/harvest_system_archives.py` exports them with exactly the
provenance the key `(name, version, variant, arch)` needs: the **owning
package** and its version become the library name and version, the image's
distribution and compiler driver become the variant, and the target triplet
fixes the arch. `tools/build_signature_set.py` then drives one
`build_flirt_library --archive` per archive and records what each produced.

Read [the sample corpus page](sample-corpus.md), section "System archives", for
the allowlist, the manifest schema, the licence position -- the archives are
distribution packages under their own licences and are never checked in, only
the derived signatures are redistributable -- and the measured table.

**The first real set, 2026-09-03.** Three build images (`linux/amd64`,
`windows/amd64`, and `linux/arm64` under qemu) yielded **419 archives,
508.6 MB, across 11 distinct target triplets and 37 distinct Debian
packages**. `libcrypto.a` alone contributes 6,042 unique signatures and
glibc's `libc.a` 2,563, against the 16 this repository's own `libmathlib.a`
produces.

**Re-measured against `5e882019`, "flirt: build signatures from COFF
archives."** The number above was first taken against an extension built from
`935b7db1`, where `src/flirt/archive.rs` read ELF and Mach-O relocations only,
so all 120 MinGW-w64 rows (the `i686-w64-mingw32` and `x86_64-w64-mingw32`
triplets, present in every one of the three images) scored zero. Rebuilding
against `5e882019` and re-running `tools/build_signature_set.py` over the same
419 archives (39.5 s, 0 failures) gives **147,733 unique signatures** from
235,043 raw, with 11,696 dropped as ambiguous -- **299 of 419 archives** now
produce at least one signature, up from 203, entirely the 120 MinGW-w64 rows
(each triplet: 16 of 20 archives sign; the remaining four -- `libdelayimp.a`,
`libm.a`, `libmoldname.a`, `libssp_nonshared.a` -- are empty or import-only by
construction). The nine non-MinGW `(image, triplet)` groups also gained a
handful of raw signatures each, because the same size-derivation fix ("extent
= next symbol in the section, or the section end") applies to any format
reporting `size() == 0`, not only COFF, and a few ELF assembly symbols with no
`.size` directive newly qualify. See the [sample corpus
page](sample-corpus.md), section "System archives", for the full re-measured
table.

None of these libraries is shipped in `data/sigs/` yet; keying,
deduplication across variants and a shipping policy for a set this size are
the next question, not this lane's.

**The other axis: the network harvest, 2026-09-03.** The Docker harvest above
gives breadth of *build image*; it does not give breadth of *distro release*,
because one image is one build point. `python/glaurung/tools/harvest_sources.py`
fetches the `base` matrix directly from Debian (`snapshot.debian.org`), Ubuntu
(Launchpad) and Alpine (APKINDEX + CDN) without a container at all, and writes
into the same `index.json` this section describes. See
[Signature sources: the `base` matrix](signature-sources.md) for the fetch
mechanics, the network manners, the licence position, and the measured
cross-release overlap table -- including the two rows where the network and
Docker harvesters reach the same package versions by different paths and agree
on every signature byte for byte.

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

---

## Windows: WARP libraries from PE + PDB

Everything above is about FLIRT, which wants an `ar` archive of unlinked `.o`
members because their relocation tables say which bytes the linker will
rewrite. **For Windows system code that input does not exist.** Microsoft ships
no `.lib` or `.obj` for `ntdll` or `ntoskrnl` -- not in the SDK, not in the WDK,
not on the symbol server -- and there is none anywhere in the corpus. What
Microsoft does publish is the linked image and a PDB full of names for it.

That pair is exactly WARP's input. Its GUID is a UUIDv5 over
relocation-*masked* instruction bytes, and the masking is derived by decoding
the image rather than by reading a relocation table, so a linked PE is a
first-class input rather than the contaminated one
([`function-identity-warp.md`](function-identity-warp.md)). So on Windows the
scheme is WARP and the ladder starts at L0, not at FLIRT.

`python/glaurung/tools/build_warp_library.py` builds them;
`siglib.ingest_warp_library_file` records one in the KB so `function_match`
provenance works, and the builder's `--kb` does both in one command;
`python/tests/test_warp_windows_libraries.py` pins every number below.

### The key

`(name, version, variant, arch, platform)`, read off the PE itself rather than
off the path it was found at:

| Field | Source | Example |
|---|---|---|
| `name` | The module file name, lowercased | `ntdll.dll` |
| `version` | `VS_FIXEDFILEINFO`'s `FileVersion`, from the `RT_VERSION` resource -- the field Microsoft increments per servicing build. Falls back to `cv-<GUID+age>` when a module has no version resource | `10.0.22621.2428` |
| `variant` | Optional-header linker version + the Rich header's toolset build id | `msvc-14.30-b30795` |
| `arch` | COFF machine | `x86_64` |
| `platform` | Constant | `windows` |

The Rich header's build id is taken as *the build number appearing in the most
`(product, build, count)` triples*: a Visual Studio release stamps the same
number from its compiler, assembler, CVTRES and linker, while a stale object
linked in from an older toolset contributes one lonely triple with an older
one. **The `msvc-` prefix is claimed only when a Rich header is present**,
because the Rich header is written by the Microsoft linker and by nothing else;
a MinGW or `lld` image gets `link-<major>.<minor>`, which does not assert a
compiler that never touched it.

### ICF and the ambiguity rule

The MSVC linker folds identical functions (`/OPT:ICF`) and Windows system DLLs
are full of the result, and WARP deliberately never prunes a colliding GUID
either. The builder therefore emits **one entry per `(guid, name)` pair** --
exactly what `siglib_function`'s `UNIQUE (siglib_id, scheme, identity, name)`
stores -- and flags every entry whose GUID carries more than one name
`ambiguous`. It never picks one, `ingest_warp_library_file` never drops one
(dropping would leave the GUID looking unique to the next library that claimed
it), and `match_warp_library` applies no name to one. Across the 82 libraries
below, **2.13%** of GUIDs are ambiguous (7,169 of 336,864).

### The evidence floor, measured

A WARP GUID over a very short function is exact and worthless. The extreme case
is `jmp qword [rip+disp32]`, the import thunk: six bytes, of which WARP masks
four, so **every import thunk in every PE ever linked carries one GUID**. That
is not a hash collision, it is the scheme correctly reporting that six masked
bytes are six masked bytes.

Measured against 48 MinGW-built PEs in `samples/binaries/platforms/windows/`
(6,368 functions, sharing no code at all with Windows) using a union library of
226,346 GUIDs from all 82 libraries, so every hit is a false positive:

| `min_bytes` | False positives | Recall, `ntoskrnl.exe` PT pair |
|---|---|---|
| 0 | 2,396 | 0.905 |
| 8 | 130 | 0.900 |
| 16 | **4** | 0.890 |
| 24 | 2 | 0.872 |
| 48 | 0 | 0.797 |

2,070 of the 2,396 unfloored hits are six-byte functions. 16 is where the curve
turns -- it removes 99.8% of the false positives for about one point of recall,
where 48 buys the last four for eleven -- and it is
`build_warp_library.MIN_EVIDENCE_BYTES`. It is applied at *match* time, to both
sides, rather than at build time: the library records `byte_len` per entry, so
a consumer can always raise the bar, whereas a builder that dropped small
entries would have destroyed the evidence needed to lower it again. The number
landing on FLIRT's own measured `min_fixed_bytes` floor is two different
mechanisms arriving at the same place, not one rule.

### Built, 2026-09-03

83 inputs -- every Microsoft-authored module in `windows-8-pro-x64`,
`windows-10-x64`, `windows-11-x64` and `patch-tuesday` whose PDB is in the
cache (see [`../development/corpora.md`](../development/corpora.md)) -- across
40 distinct modules, producing **82 libraries**: `ndfltr.sys` is byte-identical
and identically versioned in the Windows 10 and Windows 11 trees, so the key
correctly collapses the two into one. 411,124 functions discovered, 368,870
entries, 336,864 GUIDs, 142 MB of JSON, **152 seconds** total, release build.
Ingesting all 82 into one KB adds 368,870 `siglib_function` rows in 225 s and
164 MB of SQLite. A representative slice of the Windows 11 lane:

| Module | Version | Functions | Entries | Unique GUIDs | Ambiguous | PDB-resolved | Build | JSON |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `ntoskrnl.exe` | 10.0.22621.2428 | 28,970 | 27,240 | 25,297 | 383 | 0.940 | 16.3 s | 9.1 MB |
| `KernelBase.dll` | 10.0.22621.2428 | 17,107 | 7,172 | 3,846 | 205 | **0.419** | 2.0 s | 3.5 MB |
| `combase.dll` | 10.0.22621.2215 | 15,735 | 15,109 | 12,141 | 587 | 0.960 | 3.8 s | 8.6 MB |
| `win32kfull.sys` | 10.0.22621.2428 | 9,119 | 8,030 | 7,567 | 105 | 0.881 | 2.4 s | 2.9 MB |
| `win32kbase.sys` | 10.0.22621.2428 | 8,362 | 7,699 | 6,864 | 172 | 0.921 | 2.0 s | 3.2 MB |
| `ole32.dll` | 10.0.22621.2428 | 5,878 | 5,565 | 4,371 | 208 | 0.947 | 1.0 s | 2.6 MB |
| `tcpip.sys` | 10.0.22621.2428 | 5,778 | 5,497 | 5,226 | 91 | 0.951 | 1.6 s | 1.7 MB |
| `ntdll.dll` | 10.0.22621.2428 | 4,558 | 4,100 | 3,794 | 77 | 0.898 | 0.8 s | 1.3 MB |
| `http.sys` | 10.0.22621.2428 | 3,521 | 3,424 | 3,344 | 30 | 0.972 | 0.9 s | 1.0 MB |
| `rpcrt4.dll` | 10.0.22621.2428 | 3,373 | 3,152 | 2,741 | 78 | 0.934 | 0.9 s | 1.3 MB |
| `ucrtbase_clr0400.dll` | 14.32.31326.0 | 2,698 | 2,128 | 1,372 | 210 | 0.789 | 0.6 s | 1.2 MB |
| `kernel32.dll` | 10.0.22621.2428 | 2,622 | 2,407 | 1,357 | 61 | 0.918 | 0.5 s | 1.0 MB |
| `msvcp140_clr0400.dll` | 14.32.31326.0 | 1,675 | 1,507 | 755 | 217 | 0.900 | 0.7 s | 1.2 MB |
| `win32u.dll` | 10.0.22621.2428 | 1,481 | 1,481 | 1,461 | 2 | 0.999 | 0.3 s | 0.4 MB |
| `afd.sys` | 10.0.22621.2215 | 1,177 | 1,035 | 1,011 | 11 | 0.879 | 0.3 s | 0.3 MB |
| `vcruntime140_clr0400.dll` | 14.32.31326.0 | 332 | 272 | 238 | 12 | 0.819 | 0.3 s | 0.1 MB |

PDB-resolved fraction is `functions whose entry VA the PDB names / functions
discovered`; the median across all 82 libraries is **0.920**.
`KernelBase.dll`'s 0.419 is the low outlier and is not a defect in the PDB:
that module is mostly forwarders and API-set thunks that discovery finds and
the PDB's public stream does not name.

**The PDB cache is the binding constraint, not the corpus.** Of 4,212 / 5,273 /
5,408 PEs in the three build trees, only **30 / 117 / 169** resolve a PDB in
the 7.3 GB cache, and only 30 modules resolve one in all three -- of which just
ten are Microsoft-authored (`afd`, `clfs`, `dxgkrnl`, `fltMgr`, `mrxsmb`,
`ntfs`, `ntoskrnl`, `srvnet`, `tcpip`, `win32k`); the rest are third-party IHV
drivers. `ntdll`, `kernel32`, `KernelBase`, `combase`, `ole32` and `rpcrt4`
have a PDB for the Windows 11 build only, and `advapi32`, `user32`, `gdi32`,
`msvcrt`, `ucrtbase`, `ws2_32`, `crypt32`, `bcrypt`, `shell32` and `oleaut32`
have none for any of the three. Widening this needs `glaurung.pdb_fetch`
pointed at `msdl.microsoft.com`, not more binaries.

### Cross-build recall

The measurement: build the library from build A, run the GUID matcher over
build B **without consulting B's PDB**, then read B's PDB afterwards purely to
grade what the library said. `scored` is the population B's PDB names, which is
the only population on which correct and wrong can be told apart. Ambiguous
hits apply no name and are therefore neither. `GUID-shared` is the fraction of
*all* of B's functions whose GUID also occurs in A -- how much of the module is
byte-identical after masking.

**One servicing build to the next** (`patch-tuesday`, one Patch Tuesday apart):

| Module | From -> to | Scored | Correct | Wrong | Ambiguous | Unmatched | Recall | GUID-shared |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `afd.sys` | .8328 -> .8457 | 1,118 | 1,023 | 3 | 44 | 23 | **0.915** | 0.845 |
| `afd.sys` | .8521 -> .8655 | 1,130 | 1,031 | 0 | 58 | 16 | **0.912** | 0.851 |
| `tcpip.sys` | .8328 -> .8457 | 5,828 | 5,263 | 0 | 308 | 92 | **0.903** | 0.906 |
| `tcpip.sys` | .8521 -> .8655 | 5,832 | 5,313 | 0 | 310 | 44 | **0.911** | 0.914 |
| `clfs.sys` | .8328 -> .8457 | 1,265 | 1,047 | 0 | 63 | 30 | 0.828 | 0.680 |
| `cldflt.sys` | .8328 -> .8457 | 1,047 | 889 | 3 | 54 | 60 | 0.849 | 0.847 |
| `ntoskrnl.exe` | .8328 -> .8457 | 29,499 | 26,245 | 0 | 1,937 | 285 | **0.890** | 0.900 |
| `win32kfull.sys` | .8328 -> .8457 | 8,989 | 8,212 | 3 | 476 | 80 | **0.914** | 0.868 |
| `http.sys` | .8521 -> .8655 | 3,843 | 3,612 | 0 | 63 | 121 | **0.940** | 0.877 |
| `dhcpcore.dll` | .8521 -> .8655 | 1,041 | 859 | 0 | 110 | 7 | 0.825 | 0.848 |
| `dwmcore.dll` | .8521 -> .8655 | 11,317 | 9,204 | 0 | 984 | 21 | 0.813 | 0.852 |

**One Windows release to the next** (10.0.19041 -> 10.0.22621), two years
apart. Same code, same measurement:

| Module | Scored | Correct | Wrong | Ambiguous | Recall | GUID-shared |
|---|---:|---:|---:|---:|---:|---:|
| `srvnet.sys` | 859 | 318 | 5 | 19 | 0.370 | 0.382 |
| `mrxsmb.sys` | 1,019 | 343 | 0 | 10 | 0.337 | 0.321 |
| `fltMgr.sys` | 1,025 | 337 | 3 | 59 | 0.329 | 0.375 |
| `afd.sys` | 1,035 | 321 | 3 | 14 | 0.310 | 0.287 |
| `clfs.sys` | 938 | 280 | 3 | 31 | 0.299 | 0.255 |
| `tcpip.sys` | 5,497 | 1,483 | 21 | 155 | 0.270 | 0.287 |
| `ntoskrnl.exe` | 27,237 | 6,263 | 80 | 1,081 | 0.230 | 0.256 |
| `ntfs.sys` | 2,816 | 457 | 3 | 11 | 0.162 | 0.111 |
| `dxgkrnl.sys` | 7,074 | 817 | 50 | 301 | 0.115 | 0.146 |
| `win32k.sys` | 4,629 | 197 | **1,199** | 1,327 | 0.043 | 0.588 |

**Windows 8 to Windows 10** (6.2.9200 -> 10.0.19041), for the shape of the
curve: `afd.sys` 0.012, `clfs.sys` 0.015, `tcpip.sys` 0.012, `ntoskrnl.exe`
0.013, `ntfs.sys` 0.003, `srvnet.sys` 0.006, `win32k.sys` 0.000. Eight years is
a different program.

**Read the three together.** WARP carries ~90% of a Windows module across a
Patch Tuesday, ~30% across a release, and ~1% across eight years, and that is
the scheme working as specified rather than failing: it is invariant to address
and relocation and to nothing else. A library is worth building per servicing
build, and a library from the wrong release is nearly worthless. The `wrong`
column is the reassuring one -- 0 or 3 almost everywhere, because a GUID that
does not match simply does not match.

### `win32k.sys`: the failure mode a floor cannot fix

The one exception, worth stating plainly because it is the limit of exact
matching. `win32k.sys` on Windows 10/11 is the syscall shim layer: 1,316 of its
functions (1,456 in the Windows 11 build) are 165-byte `_stub_*` bodies that
differ **only in a syscall index**. An index is an immediate, not a pointer
into a mapped region, so WARP correctly keeps it -- and the GUID therefore ends
up keyed on the *index* rather than on the function. Windows reassigns those
indices between releases, and the reassignment is a reshuffle rather than a
shift (at best 202 of 1,316 names stay in order at any single offset), so the
library hands out **1,199 confidently wrong names**.

Neither available mitigation touches it:

- The **evidence floor** does nothing: the bodies are 165 bytes, ten times the
  floor. At `min_bytes=64` the wrong count is still 1,199.
- **WARP constraints** do nothing either, measured rather than assumed: of the
  2,397 GUID-level wrong verdicts, requiring the callee-constraint set to agree
  rescues **0** and rejects **0**, because the stubs' callee sets are identical
  too. That is a real result for the schema-reserved `warp-constraint` level --
  it is not the answer to this case.

The honest reading is that "identical bytes" and "identical function" come
apart wherever code is generated from a table, and no equality scheme can tell
the difference. Detecting *that a module is table-generated* -- a large
population of same-size, same-block-count functions -- and declining to name it
is the cheap guard, and is not implemented.

### False positives

The union of all 82 libraries -- 252,702 `(guid, name)` pairs over 226,346
GUIDs -- against the 48 MinGW-built PEs in
`samples/binaries/platforms/windows/`, which share no code with Windows at all:

| Measurement | Result |
|---|---|
| Functions examined | 6,368 |
| GUID hits at `min_bytes=16` | **4** |
| Of those, unambiguous | **0** |
| **Names applied** | **0** |
| GUID hits at `min_bytes=0` | 2,396 |

All four surviving hits are in `hello-cpp-mingw64-O1.exe` and all four are
ambiguous, so the ambiguity rule alone would have refused them even without the
floor. Names applied to unrelated code: zero.

### Third-party binaries with a statically linked CRT

`/nas4/data/binary-analysis/windows-drivers.sqfs` **was not mounted** and this
lane does not mount it, so the intended vendor-driver sample was replaced by 20
vendor binaries drawn (seeded, `random.Random(20260903)`) from the 4,400-file
`binaries/windows-update` tree -- AMD, Intel, Realtek, Synaptics, ASUS and
Kaspersky driver packages. Against the union of the `ucrtbase`, `vcruntime140`,
`msvcp140`, `msvcp120` and `msvcr120` libraries:

| Measurement | Result |
|---|---|
| Binaries | 20 |
| Functions | 68,105 |
| GUID hits | 7,791 |
| Unambiguously named | **5,338** (7.8%) |
| Ambiguous | 2,453 |

Spot-checked, the names are real CRT and STL code -- `__acrt_thread_detach`,
`_strtoi64_l`, `__crt_stdio_output::type_case_integer<>` instantiations,
`std::exception` vtable deleting destructors -- and the distribution is what
the premise predicts. Per binary, as `hits (named) / functions`:

| Binary | Hits | Named | Functions |
|---|---:|---:|---:|
| `RsDMFT64.dll` | 1,804 | 1,219 | 15,826 |
| `IntelIhvRouter08.dll` | 1,662 | 1,127 | 8,648 |
| `SynCOM.dll` | 1,189 | 886 | 4,337 |
| `MonoSeparationEnrollDll.dll` | 263 | 207 | 1,759 |
| `Dptf.dll` | 136 | 90 | 13,986 |
| `klflt.sys` | 5 | 5 | 1,317 |
| `ibtusb.sys` | 3 | 3 | 525 |
| `AsusPTPFilter.sys` | 2 | 2 | 519 |
| `klwtp.sys` | 2 | 2 | 1,006 |
| `AdbWinApi.dll` | 0 | 0 | 345 |

The user-mode DLLs statically link a large chunk of the CRT; the `.sys` drivers
link essentially none of it, because a kernel driver does not use the user-mode
CRT. (The sampled 20 files are 16 distinct names -- `IntelIhvRouter08.dll`
appears in three vendor packages and `klwtp.sys` and `ibtusb.sys` in two each,
at different versions. That is the corpus, not a sampling bug, and the repeats
were kept rather than deduplicated because a redistributed DLL appearing many
times is exactly what a signature library meets in the field.) Just under a
third of the hits are ambiguous and name nothing, which is the ICF rule doing
its job on a runtime full of one-line template instantiations.

### Licence

A library file holds **GUIDs, names, sizes and constraint GUIDs -- no Microsoft
bytes**. Not a prologue, not a mask, not a pattern; unlike a FLIRT signature it
does not even carry variant bytes. That is the property that makes a
FLIRT-family signature set redistributable, and it is asserted rather than
merely claimed: `test_entries_are_deterministic_and_carry_no_bytes` pins the
exact key set an entry may have. The *names* are Microsoft's and are reproduced
from public PDBs the symbol server serves without restriction. The libraries
themselves are written to `$HOME/.cache/glaurung/system-libs/warp/` and are not
committed, because 142 MB of derived data is not repository content.

### Not done here, for Windows

- **No PDB fetching.** The measurement is bounded by a 7.3 GB local cache, not
  by the corpus. `glaurung.pdb_fetch.ensure_pdb_cached` already speaks the
  symbol-server protocol; pointing it at `msdl.microsoft.com` for the ~5,000
  cache misses is the single highest-value follow-up.
- **No membership gate over these libraries.** `identity_gate_build` would take
  337,257 GUIDs to roughly 380 KB, and `match_warp_library` already consults a
  gate when one exists; none is built here.
- **Constraint-based disambiguation** is measured to be useless for the one
  case that motivates it (above), and remains unimplemented.
- **x86-32 and ARM64 Windows.** `warp_functions_from_bytes` raises
  `UnsupportedArchitecture` for AArch64, so the ARM64 Windows images in the
  corpus produce nothing.

## Cortex-M (bare metal)

Measured 2026-09-03 against the ARM GNU Toolchain 13.2.Rel1
(`arm-none-eabi-gcc 13.2.1 20231009`, newlib `4.3.0`), on
`/nas4/data/binary-analysis/armtc/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/`
(read-only; never copied). This is the same builder and matcher documented
above, aimed at bare-metal ARM (Cortex-M) instead of a hosted libc: no ELF
dynamic section, no PLT, one statically linked image per firmware, Thumb-2
throughout.

### Source and harvest

`tools/harvest_armtc.py` inventories the toolchain's static archives by NAS
path plus sha256 -- it does not copy them, the same "unit of distribution is
a blob plus provenance" policy the design doc states for the wider program.
Output: `$HOME/.cache/glaurung/system-libs/armtc-13.2.1/manifest.json`, one
entry per `.a` under `arm-none-eabi/lib/{arm,thumb}/**` and
`lib/gcc/arm-none-eabi/13.2.1/**`, keyed by `multilib_path` (e.g.
`thumb/v7e-m+fp/hard`) and `lib_root`. Measured: **780 of 780** archives on
the box inventoried (39 multilibs x 20 archive basenames each), 752,307,272
bytes, in well under a second (hashing dominates). Licence: newlib/libgloss
is BSD-style (Red Hat/Cygnus plus a University of California, Berkeley
notice; the toolchain's `license.txt` lines 8721-10644); libgcc, libstdc++
and libsupc++ carry GPLv3 plus the GCC Runtime Library Exception, which
permits linking without imposing the GPL on the linked program -- the same
legal position as the rest of this page applies here unchanged: only masked
patterns, CRCs and names are ever redistributed, never archive or object
bytes.

### Keying and multilibs built

`tools/build_armtc_signatures.py` drives `build_flirt_library.py --archive`
once per `(multilib, component)` pair for the six multilibs bare-metal
firmware actually links (`thumb/v6-m/nofp`, `thumb/v7-m/nofp`,
`thumb/v7e-m/nofp`, `thumb/v7e-m+fp/hard`, `thumb/v7e-m+dp/hard`,
`thumb/v8-m.main/nofp`) and eight components each (`newlib`, `newlib-nano`,
`newlib-libm`, `libgcc`, `libstdc++`, `libstdc++-nano`, `libsupc++`,
`libnosys`). Keyed `(name, version, variant, arch)` exactly as the rest of
this page: `variant = arm-gnu-<gcc-version>-<multilib-with-dashes>` (e.g.
`newlib/4.3.0/arm-gnu-13.2.1-thumb-v7e-m+fp-hard/armv7`) -- no masked scheme
crosses a multilib any more than it crosses an optimisation level, because
the ABI, FPU and instruction-set variant all change the code the compiler
emits. `--arch armv7` throughout: `object`'s `Architecture` enum does not
distinguish M-profile sub-variants, so `src/flirt/archive.rs::arch_tag` maps
every 32-bit ARM object to `"armv7"` regardless of Thumb-1/Thumb-2/v6-M/v8-M
-- the profile lives in the *variant* string, which is why it has to be part
of the key. (The task brief's illustrative key used `newlib/4.4.0/...`; the
toolchain's actual newlib is measured at `4.3.0`, used throughout.)

**All 48 libraries yielded signatures -- zero archives yielded nothing.**
32,812 unique signatures total, 63,210 raw, 5,109 dropped ambiguous, built in
3.2 seconds, 36.3 MB of JSON. Per-multilib totals are nearly identical (the
six multilibs disagree only in FPU/architecture-dependent codegen, not in
which symbols exist), so one representative row (`thumb/v7e-m+fp/hard`, the
STM32F4 multilib both validations below actually exercise) stands for all
six; the full 48-row table is `tools/build_armtc_signatures.py`'s own
`index.json` output.

| component | raw | unique | ambiguous | masked | with CRC | with refs | JSON bytes | build |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `newlib` | 825 | 588 | 59 | 482 | 451 | 467 | 498,669 | 63 ms |
| `newlib-nano` | 723 | 563 | 36 | 500 | 385 | 440 | 403,293 | 60 ms |
| `newlib-libm` | 298 | 212 | 39 | 171 | 164 | 173 | 288,080 | 52 ms |
| `libgcc` | 562 | 337 | 75 | 311 | 176 | 113 | 172,781 | 51 ms |
| `libstdc++` | 4,220 | 1,984 | 313 | 2,737 | 1,601 | 1,798 | 2,641,613 | 98 ms |
| `libstdc++-nano` | 3,798 | 1,657 | 334 | 3,063 | 1,151 | 1,438 | 1,809,132 | 92 ms |
| `libsupc++` | 160 | 141 | 3 | 99 | 104 | 120 | 121,437 | 48 ms |
| `libnosys` | 1 | 1 | 0 | 1 | 0 | 1 | 1,065 | 53 ms |

**`libnosys` yielding 1 of 23 candidate symbols is correct, not a defect.**
Every syscall stub (`_read`, `_write`, `_close`, `_lseek`, `_fstat`,
`_isatty`, `_kill`, `_getpid`, `_open`, `_link`, ...) is 16 bytes with only
12 fixed after masking -- boilerplate "set `errno`, return -1" identical in
shape across every stub, correctly declined by the same `min_fixed_bytes=16`
floor documented above (measured directly: re-running the extractor with
both floors at 0 recovers all 23, all but `_sbrk` at 12 fixed bytes).
`_sbrk` alone (28 bytes, 20 fixed) clears the floor and is the one signature
kept.

### Validation: `rt-libopencm3` (20 STM32F4 firmwares, three optimisation levels)

`/nas4/data/binary-analysis/rt-libopencm3/` -- built with this exact
toolchain (`GCC: (15:13.2.rel1-2) 13.2.1 20231009`, confirmed from each
firmware's own `.comment` section), `addr2name.json` ground truth (decimal
VA, some carrying the Thumb bit -- cleared with `addr & ~1` on both the
truth and the matcher's `entry_va` before comparing). Every firmware in the
corpus reports `Tag_CPU_arch: v7E-M`, `Tag_FP_arch: VFPv4-D16`,
`Tag_ABI_HardFP_use: SP only` in its own `.ARM.attributes` -- i.e. all 20 are
`thumb/v7e-m+fp/hard`, read off the binary rather than inferred from a board
name (`tools/validate_cortex_m_signatures.py::infer_multilib`). Matched with
`glaurung.analysis.flirt_match_functions_with_evidence_path` against the
`newlib` + `libgcc` + `libstdc++` + `libsupc++` + `libnosys` components
merged (the non-nano set: this corpus's DWARF producer strings carry no
`--specs=nano.specs`, and its `printf` pulls the full `_dtoa_r` double
formatter, which newlib-nano does not build by default) -- **function
discovery on a stripped, statically linked, bare-metal Thumb-2 ELF works
with no changes**, which was the open risk item this measurement was meant
to settle.

| firmware | opt | in truth | named | correct | wrong | ambiguous |
|---|---|--:|--:|--:|--:|--:|
| adc-dac-printf | O0 | 167 | 34 | 34 | 0 | 0 |
| lcd-dma | O0 | 192 | 36 | 36 | 0 | 0 |
| lcd-serial | O0 | 115 | 8 | 8 | 0 | 0 |
| usart-stdio | O0 | 147 | 35 | 34 | 1 | 0 |
| usart_irq_console | O0 | 89 | 1 | 1 | 0 | 0 |
| adc-dac-printf | O2 | 148 | 34 | 34 | 0 | 0 |
| 15 more firmwares (blink, button, cdcacm, cryptobasic, dac-dma, fancyblink, mandel, miniblink, msc, random, sdram, tick_blink, timer, usart, usart_console, usart_irq, usbmidi) at O0/O2/O2-noinline | -- | 1,044 | 0 | 0 | 0 | 0 |
| **total, 28 (firmware, opt) cells** | | **1,902** | **148** | **147** | **1** | **0** |

The fifteen zero rows are correctly zero, not a matcher failure: those
firmwares call nothing from newlib/libgcc/libstdc++ beyond what already
matched in the rows above (they are pure `libopencm3` register-poking code,
which this library was never built to know), and the point of the "wrong"
column is that it stayed at **1 of 148** (0.7%) rather than that recall is
high -- most of a Cortex-M firmware's text is project and HAL code no
toolchain signature library can ever name.

**Defect found and fixed: the archive builder's same-address alias
tie-break picked the wrong ARM EABI name, every time.** Before the fix,
`wrong` was **21 of 148** (14%), every single one a libgcc IEEE-754 helper:
ARM's RTABI mandates helper names like `__aeabi_dadd`, and GCC's libgcc
defines that symbol as a same-address alias of the *generic* portable
libcall name (`__adddf3`) inside one object
(`_arm_addsubdf3.o`, confirmed with
`glaurung.analysis.flirt_signatures_from_archive_path`: both names, same
`member`, same `address`, same bytes). `build_flirt_library.py`'s
`public_alias_rank` (added for glibc's `puts`/`_IO_puts`, where the
unprefixed name is public) broke the tie by length alone once leading-
underscore counts matched, which always picked the shorter, non-RTABI name
-- and every Cortex-M firmware calls the RTABI name, so it never matched.
Fixed in `python/glaurung/tools/build_flirt_library.py::public_alias_rank`
by adding an `__aeabi_`-prefix tier between the underscore-count tier and
the length tie-break; a new test,
`test_archive_builder_prefers_the_aeabi_alias_over_the_shorter_libgcc_name`
in `python/tests/test_flirt_library_builder.py`, reproduces the exact
`_arm_addsubdf3.o` case. The existing x86_64 `mathlib` library is
unaffected (rebuild is still byte-identical; no `__aeabi_`-prefixed name
exists in that archive).

**Residual "wrong" (1 of 148): `usart-stdio`'s `fflush` names as
`fflush_unlocked`, and this one is not fixable at the archive level.**
`libc_a-fflush.o`'s own `fflush` is 116 bytes (`crc16=9051`); the function
the firmware actually calls "fflush" is 72 bytes and byte-identical to
`libc_a-fflush_u.o`'s `fflush_unlocked` (confirmed by reading both the
signature patterns and the real firmware bytes at the call site: the first
32 bytes match `fflush_unlocked`'s pattern exactly and diverge from
`fflush`'s at byte 0). `nm` on the unstripped image shows only one name,
`fflush`, at that address -- not the two-names-one-address case documented
below for the holdout corpus. The most likely explanation is newlib's own
weak-alias resolution across `fflush.o`/`fflush_u.o` selecting a definition
this archive-only, unlinked-object analysis cannot see: which of several
same-named implementations across different translation units in one static
archive a specific link resolves to depends on link order and what else in
the program references, which is invisible without simulating the link.
FLIRT and Ghidra FunctionID share this exact blind spot for any archive with
more than one body under a name. Not fixed; reported per the task brief's
instruction to stop and report rather than paper over an archive-level
defect.

### Validation: `decbench-holdout` (3 of 8 available ARM EABI5 projects)

`/nas4/data/binary-analysis/decbench-holdout-source-rebuild-2026-08-06/O0/`,
all three built with the identical toolchain (`.comment`:
`GCC: (15:13.2.rel1-2) 13.2.1 20231009`). Chosen for multilib diversity, read
off `.ARM.attributes` the same way: `freertos/RTOSDemo.out` is `v7`/`7-M`
(no FPU) -> `thumb/v7-m/nofp`; `nuttx/nuttx` is `v7E-M` with no `Tag_FP_arch`
-> `thumb/v7e-m/nofp`; `betaflight/betaflight_STM32F405.elf` is `v7E-M` +
`VFPv4-D16` + `HardFP SP only` -> `thumb/v7e-m+fp/hard`, same as the whole
`rt-libopencm3` corpus. **Ground truth is `arm-none-eabi-nm -S
--defined-only` on the binary itself, as a set of names per address, not
`addr2name.json`**: this corpus's own `stripped/` output is
byte-**identical** to `compiled/` for every ARM project checked (sha256
verified for `freertos`, `betaflight` and `nuttx`) -- a real defect in that
corpus's rebuild pipeline, recorded here because it means there is no
separately-stripped ARM binary in that corpus to test against; the matcher
itself does not care, since `flirt_match_functions_with_evidence_path` names
functions from CFG discovery, never from the symbol table.

| project | multilib | in truth | named | correct | wrong | ambiguous |
|---|---|--:|--:|--:|--:|--:|
| freertos | thumb/v7-m/nofp | 150 | 6 | 6 | 0 | 0 |
| nuttx | thumb/v7e-m/nofp | 1,026 | 11 | 11 | 0 | 0 |
| betaflight | thumb/v7e-m+fp/hard | 4,544 | 45 | 45 | 0 | 0 |
| **total** | | **5,720** | **62** | **62** | **0** | **0** |

**Zero wrong, and the reason it is not a coincidence is worth recording.**
The first run, before the alias-set fix below, reported 23 wrong -- all the
same libgcc IEEE-754 pairs as `rt-libopencm3`, but in the *opposite*
direction (`got '__aeabi_d2uiz', truth '__fixunsdfsi'`). `nm -S` on both
`nuttx` and `betaflight` shows **both** names at the same address for every
one of these (`0801ff50 00000040 T __aeabi_d2uiz` and
`0801ff50 00000040 T __fixunsdfsi` in the same `nm` listing) -- a genuine
weak-alias pair present simultaneously in the final binary, unlike
`usart-stdio`'s `fflush` above. Scoring against a single arbitrarily-chosen
`nm` line would have manufactured 23 "wrong" verdicts out of what is
actually 23 correct ones under a name the truth extraction happened not to
prefer. `tools/validate_cortex_m_signatures.py::truth_from_nm` was changed
to collect every name at an address into a set and accept membership, which
is the same "no name beats a wrong name, but two names can both be right"
principle the matcher itself already applies to `warp-guid` ambiguity.

### Summary

| corpus | cells | functions in truth | named | correct | wrong | ambiguous |
|---|--:|--:|--:|--:|--:|--:|
| `rt-libopencm3` | 28 (firmware x opt) | 1,902 | 148 | 147 | 1 | 0 |
| `decbench-holdout` | 3 projects | 5,720 | 62 | 62 | 0 | 0 |
| **total** | | **7,622** | **210** | **209** | **1** | **0** |

Recall (named / in truth) is low in absolute terms -- **2.8%** -- because
the denominator is *every* function in a firmware, and the overwhelming
majority of a Cortex-M firmware's text is the RTOS/HAL/application code no
toolchain signature library was ever going to name (`libopencm3`, ChibiOS,
NuttX and application logic itself). Precision is what this measurement was
actually for, and it holds: **209 of 210 named functions were correct**, and
the one exception is a documented, reproducible archive-level limitation
rather than a false positive from an under-specified pattern.

### Reproduction

```bash
export GLAURUNG_ARMTC=/nas4/data/binary-analysis/armtc/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi
uv run python tools/harvest_armtc.py --toolchain-root "$GLAURUNG_ARMTC" \
    --output ~/.cache/glaurung/system-libs/armtc-13.2.1/manifest.json
uv run python tools/build_armtc_signatures.py \
    --manifest ~/.cache/glaurung/system-libs/armtc-13.2.1/manifest.json \
    --output ~/.cache/glaurung/system-libs/armtc-13.2.1/sigs
uv run python tools/validate_cortex_m_signatures.py \
    --sigs-dir ~/.cache/glaurung/system-libs/armtc-13.2.1/sigs
```

Not shipped in `data/sigs/`, same as every other harvested set on this page:
keying, deduplication and a shipping policy at this scale are the wider
program's open questions, not this measurement's.
