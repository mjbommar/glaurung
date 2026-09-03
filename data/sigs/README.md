# Shipped signature libraries

## `glaurung-base.x86_64.flirt.json`

**Contents:** 16 relocation-masked signatures for the `mathlib_*` functions of
this repository's own sample library, built from the unlinked object inside
`samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a`.

**Key:** `mathlib / 1.0.0 / gcc-15.2.0-O2 / x86_64`, recorded in the file's
`library` object. A library is keyed by `(name, version, variant, arch)`
because no exact or masked scheme crosses an optimisation level. A corpus
spanning gcc and clang across `-O0` to `-O3` is not one library; it is N
libraries sharing a name, and cross-variant matching is a different rung of the
identity ladder (`docs/history/program-measures-2026-09-02.md`).

**Licence:** first-party. `mathlib.c` is this repository's own sample source
(`samples/source/library/mathlib.c`); nothing here is derived from a
third-party library, and no third-party bytes are redistributed. Note that
FLIRT's format deliberately splits pattern from mask so that a signature set is
not a copy of the library it describes; the same split is used here.

**Rebuild:**

```bash
uv run python -m glaurung.tools.build_flirt_library \
    --archive samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a \
    --library-name mathlib --library-version 1.0.0 \
    --variant gcc-15.2.0-O2 --arch x86_64 \
    --output data/sigs/glaurung-base.x86_64.flirt.json
```

The output is deterministic (sorted keys, sorted entries), so a rebuild that
changed nothing produces a zero-line diff.

## What changed, and why

Before 2026-09-02 this file held **30 exact 32-byte prologues harvested from
linked sample binaries**. That is the contaminated input: a linked image has no
relocation table, so every `call rel32` and RIP-relative `lea` in the window is
an absolute the linker chose for *that* link. Measured on the one real archive
in the tree, 19 of 20 functions have a relocation inside their 32-byte window;
those signatures could never match the same function in another build.

The rebuild takes the unlinked `.o` instead, where the relocation table says
byte for byte which parts the linker will overwrite. Measured against two
images that link the same archive different ways
(`tests/fixtures/flirt/`): **16 of 16** signed functions are named in both,
where an exact-byte matcher reaches **0 of 16** -- not one of them has the same
32 bytes in the two images.

Four of the archive's twenty functions get no signature: they are 10 to 11
bytes of generic code (`mathlib_version_major` is `endbr64; mov eax, 1; ret`),
and the builder's `min_fixed_bytes` floor declines to sign them. That floor is
16, and it is measured: at 8 those four produced four false positives across
the 2,801-function fixture corpus. A ten-byte function that returns a constant
is not identifiable by its bytes at any pattern length.

## Schema

Version `"2"`. Every field added after v1 is optional and every default is the
v1 behaviour, so an old file still loads and still matches exactly.

| Field | Meaning |
|---|---|
| `prologue_hex` | The pattern, `prologue_len` bytes. |
| `mask_hex` | Same byte length; `ff` = fixed, `00` = variant. **Absent = all fixed.** |
| `crc16` / `crc_len` | IDA's FLIRT CRC16 over the `crc_len` bytes following the pattern, stopping at the first variant byte. `crc_len` 0 = no CRC. |
| `function_len` | The symbol's size in the archive. Provenance; not compared. |
| `refs` | `{offset, name}` references into the body, used as a second-level disambiguator when pattern and CRC leave more than one candidate. |
| `library` | `(name, version, variant, arch)` for the whole file. |

Variant bytes hold whatever the builder happened to see and are never compared;
do not read them as library content.

## The `gsig/1` container

`glaurung-base.x86_64.flirt.json` above is the interchange form: reviewable,
diffable, what `build_flirt_library.py` writes and what a reviewer reads. It
is not what a large corpus ships in. `gsig/1` (`src/flirt/gsig/`) is a chunked
binary container carrying the same content -- interned strings, bitmap masks,
64 KiB independently zstd-compressed sections -- at roughly 13x smaller over
a 561-library, 222,339-signature harvested set (1,326 bytes/signature JSON
against 101 bytes/signature `gsig`). See the "The gsig/1 container" section of
[`docs/reference/function-signature-libraries.md`](../../docs/reference/function-signature-libraries.md)
for the full measurements and the format layout.

The matcher reads either format transparently, dispatching on the file's
first four bytes (`GSIG` or `{`/whitespace), so nothing here needs to change
to work with a `.gsig` library. Convert either way with:

```bash
uv run python -m glaurung.tools.sig_convert to-gsig \
    data/sigs/glaurung-base.x86_64.flirt.json \
    data/sigs/glaurung-base.x86_64.flirt.gsig

uv run python -m glaurung.tools.sig_convert info \
    data/sigs/glaurung-base.x86_64.flirt.gsig
```

Only the JSON form is shipped here today: this library is 16 signatures, far
below the scale where the container's size advantage matters, and keeping one
reviewable file per shipped library is simpler until the distribution lane
(manifest, minisign, client cache) lands.

## Where the code is

- `src/flirt/mod.rs` -- the loader and matcher; `FlirtLibrary::from_path`
  dispatches between JSON and `gsig/1`.
- `src/flirt/archive.rs` -- deriving masks, CRCs and references from a `.a`.
- `src/flirt/crc16.rs` -- IDA's exact CRC16 variant.
- `src/flirt/gsig/` -- the `gsig/1` container: `wire.rs` (the on-disk record
  shapes), `writer.rs`, `reader.rs`, `codec.rs` (zstd via `ruzstd`), `convert.rs`
  (lossless JSON conversion).
- `python/glaurung/tools/build_flirt_library.py` -- the builder CLI
  (`--format gsig` writes a container directly).
- `python/glaurung/tools/sig_convert.py` -- convert, describe, and round-trip
  a library between the two formats.
- `tests/flirt_signature_matching.rs` -- the measurements quoted above.
- `tests/flirt_gsig_golden.rs`, `tests/fixtures/flirt/gsig/` -- the `gsig/1`
  golden-hash fixture.
