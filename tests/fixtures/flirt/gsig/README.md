# `gsig/1` golden fixtures

One library per identity scheme, in both formats, committed so that
`tests/flirt_gsig_golden.rs` can assert the container's bytes rather than only
its behaviour.

| File | What it is | SHA-256 |
|---|---|---|
| `mingw_crt_three.x86_64.flirt.json` | The JSON library, built from [`../coff/mingw_crt_three.msvc.lib`](../coff/README.md) | `b3c067204d0d567fa85ddb619a54e81d52471db04a0ecaa3b15626d3aeae21d3` |
| `mingw_crt_three.x86_64.flirt.gsig` | The same library as a `gsig/1` container, default codec | `0cfcc67998b269834423f0d48c21a2892a83d18ff24d9f5e6043065c43bcd0e5` |
| `warp_sample.x86_64.warp.json` | A four-entry `warp-function-guid-v1` library. **Synthetic**, see below | `f6f4fe7487f5d7f8fee3d43da457dc48b0cce7b7586cae49319bfaaf53c53a07` |
| `warp_sample.x86_64.warp.gsig` | The same library as a `gsig/1` container, default codec | `b7d166126f02edbbeeb87414076ebef26a1f4ebf7388a750839d7406fa749717` |

1,526 bytes against 6,955 -- a 4.6x ratio, which is what twelve signatures
gets you. The corpus-scale numbers, where interning and the columnar layout
actually pay, are in
[`docs/reference/function-signature-libraries.md`](../../../../docs/reference/function-signature-libraries.md).

## Why the WARP fixture is synthetic

The masked-pattern fixture is derived from a real archive, which is right: its
job is to pin what the harvester actually emits. The WARP fixture's job is
different. It pins the *container's* record layout, and what has to be covered
is every optional shape at once -- an entry with no constraints, an ambiguous
GUID shared by two names, a constraint at offset `0` **and** one with a `null`
offset (which are different facts, and would otherwise collapse into each
other unnoticed), and a non-empty `sources`/`stats` envelope. A real library
is 1,035 entries covering a subset of that, and the only real WARP libraries
on this machine are derived from Microsoft system binaries, which is not a
licence question a test fixture should be settling. Four hand-written entries
cover more and commit less.

The GUIDs are real UUIDs but name nothing: they are the container's key
material, not evidence about any binary.

## Why a golden file and not just a round-trip test

A round-trip test proves the reader agrees with the writer. It cannot notice
the two of them drifting together -- a changed field order, a different chunk
size, an `Option` that stopped being packed into the flags byte. Every one of
those silently invalidates every `.gsig` already published, and a
content-addressed distribution notices only when a hash it has already
announced stops matching. This fixture is the tripwire.

## Refreshing it

Only when the format deliberately changes, and never as a way to make a red
test green. From the repository root:

```bash
uv run python -m glaurung.tools.build_flirt_library \
    --archive tests/fixtures/flirt/coff/mingw_crt_three.msvc.lib \
    --library-name mingw_crt_three --library-version 13.0.0 \
    --variant mingw-w64-gcc --arch x86_64 \
    --output tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.json

uv run python -m glaurung.tools.sig_convert to-gsig \
    tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.json \
    tests/fixtures/flirt/gsig/mingw_crt_three.x86_64.flirt.gsig

# The WARP fixture's JSON is hand-maintained; only the container is rebuilt.
uv run python -m glaurung.tools.sig_convert to-gsig --scheme warp \
    tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.json \
    tests/fixtures/flirt/gsig/warp_sample.x86_64.warp.gsig

sha256sum tests/fixtures/flirt/gsig/*
```

Then update the table above **and** the constants in
`tests/flirt_gsig_golden.rs`, and say in the commit message what changed about
the format.

## What can legitimately move the hash

* A change to the container: the header, the chunk table, a section's
  encoding, the record layout, the sort order, the chunk size.
* A `ruzstd` upgrade. The default codec is `ruzstd`'s `Fastest` level, and a
  compressor is allowed to emit different valid frames between versions. The
  version is pinned in `Cargo.lock`, so this only happens on a deliberate
  bump -- and when it does, the right response is to refresh the fixture in
  the same commit as the bump, not to loosen the test.

Nothing else should. In particular the `gsig-zstd` cargo feature must **not**:
it adds a codec, it does not change the default one, and
`tests/flirt_gsig_golden.rs` runs in both configurations.

## Provenance

The archive this is derived from is MinGW-w64 (Zope Public Licence 2.1, see
[`../coff/LICENSE.mingw-w64.txt`](../coff/LICENSE.mingw-w64.txt)). What is
committed here are *signatures* -- masked patterns, CRCs and names -- not
object code; see the "Legal position" section of the signature-library
programme notes.
