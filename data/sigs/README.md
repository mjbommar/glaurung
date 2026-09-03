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

## The distribution channel's files

Since 2026-09-03 this directory is also the **bundled fallback** for the signed
signature-set channel described in
[`docs/reference/signature-distribution.md`](../../docs/reference/signature-distribution.md).
Everything here ships inside the wheel (`[tool.maturin].include` in
`pyproject.toml`).

| Path | What it is |
|---|---|
| `manifest.schema.json` | JSON Schema for a distribution manifest. Executed by `glaurung.sigs.manifest.validate_against_schema`, not decorative. |
| `bundled-manifest.json` | The signed manifest for the bundled `base` subset. |
| `bundled-manifest.json.minisig` | Its detached minisign signature. |
| `base/<sha256>` | The bundled blobs, named by digest exactly as in the cache. |
| `trusted-keys/*.pub` | Which minisign keys this installation trusts. See that directory's README. |
| `NOTICE` | The licence position and per-blob provenance for the bundled set. |

The bundled set is a **fallback**, not the corpus: two blobs, 125 signatures,
76,414 bytes. It exists so `pip install glaurung` on a machine with no network
can still name library functions. The real set is 171 blobs and 125 MB and
goes through the release channel.
`python/tests/test_sigs_packaging.py::test_the_bundled_set_stays_small` caps
the whole directory at 256 KiB.

`glaurung-base.x86_64.flirt.json` is *both* the named file the Rust loader
resolves and, byte for byte, one of the content-addressed blobs under `base/`.
`test_the_demo_library_and_its_bundled_copy_are_the_same_bytes` pins them
together.

### Rebuilding the bundled set

Needs the signing secret key, which is not in this repository.

```bash
# 1. Stage the two source libraries and a provenance index.
mkdir -p "$TMPDIR/bundled-staging"
cp data/sigs/glaurung-base.x86_64.flirt.json "$TMPDIR/bundled-staging/mathlib.flirt.json"
cp <harvest>/linux-amd64.x86_64-linux-gnu.libz.flirt.json "$TMPDIR/bundled-staging/libz.flirt.json"
# ...plus an index.json holding one record per file (see the harvester's own
# index.json for the field names).

# 2. Publish it as a set whose blob URLs point at the real release tag.
uv run python tools/publish_signature_set.py \
    --blobs "$TMPDIR/bundled-staging" --set base \
    --set-version 2026.09.1-bundled --release-tag 2026.09.1 --serial 1 \
    --secret-key <path to the production key> \
    --out "$TMPDIR/bundled-out"

# 3. Install the result.
cp "$TMPDIR/bundled-out/manifest.json"          data/sigs/bundled-manifest.json
cp "$TMPDIR/bundled-out/manifest.json.minisig"  data/sigs/bundled-manifest.json.minisig
cp "$TMPDIR/bundled-out/NOTICE"                 data/sigs/NOTICE
rm -f data/sigs/base/* && cp "$TMPDIR/bundled-out/blobs/"* data/sigs/base/
```

Then `uv run pytest python/tests/test_sigs_packaging.py -q`, which checks the
signature verifies, every named blob is present and hashes correctly, and no
orphan file sits in `base/`.
