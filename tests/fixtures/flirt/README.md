# FLIRT relink fixtures

Two linked images built from **the same static archive** two different ways.
They exist to test the one property the v1 signature design could not have:
that a signature built from an unlinked `.o` still names the function after the
linker has moved it.

## What is here

| File | What it is |
|---|---|
| `driver_a.c` | A small PIE driver calling five `mathlib_*` entry points. |
| `driver_b.c` | A longer non-PIE driver with three filler functions ahead of `main`, calling a different subset. |
| `build.sh` | Builds both. Run only when deliberately refreshing the fixture. |
| `mathlib_link_a.x86_64.elf` | Committed output of `driver_a.c` + `libmathlib.a`, PIE. |
| `mathlib_link_b.x86_64.elf` | Committed output of `driver_b.c` + `libmathlib.a`, non-PIE. |
| `mathlib_link_a.stripped.x86_64.elf` | `strip --strip-all` of link A. The library's real job is naming functions in a binary with no symbol table, and that cannot be tested on one that has it. |

The archive is
`samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a`, which
this repository already ships and which is built by
`samples/docker/build-linux.sh` from `samples/source/library/mathlib.c`.

## Why the outputs are committed

The test must run on a machine with no compiler, and the two images must not
quietly change identity when someone's gcc is upgraded -- a fixture that
rebuilds itself is a fixture that cannot regress. `build.sh` prints the
toolchain and the SHA-256 of each output so a refresh is auditable.

## Provenance

Everything here is first-party: `mathlib.c` and `mathlib.h` are this
repository's own sample sources, and the two drivers were written for this
fixture. There is no third-party code and no third-party licence to carry.
The images link glibc dynamically, so no glibc code is redistributed in them.

## Recorded toolchain

Built 2026-09-02 on Ubuntu:

```
gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0
GNU ld (GNU Binutils for Ubuntu) 2.46
mathlib_link_a.x86_64.elf 2837f6ccd2d312e7fe8e4e686d6725b75138dc311e4a2f970cc5d1632afa375a
mathlib_link_b.x86_64.elf cdc37aebcea2042179053bee7d6b58efd27d0e3117172889e0b4671522e0b0f8
mathlib_link_a.stripped.x86_64.elf 36646af62e2948ca04ff7e8a2f3d75e539f6974df1e643ad098192997b4bd641
```

Note that the SHA-256s are of *that* build; `gcc` is not bit-reproducible
across versions and `build.sh` does not try to make it so. What the tests
depend on is the two images' *contents differing in the ways a relink differs*,
not their hashes, so a refresh that changes the hashes is fine as long as the
measurement below still holds.

## What the fixtures measure

`tests/flirt_signature_matching.rs`, measured 2026-09-02:

- **0 of 16** signed `mathlib_*` functions have identical 32-byte windows in
  the two images. That is the ceiling an exact-byte matcher can reach here.
- **16 of 16** are named in both images by the shipped, relocation-masked
  library.
- The same library with `mask_hex` and the CRC stripped names **0 of 16**.
- Five symbols carry no signature at all -- `mathlib_version`,
  `mathlib_version_major`, `mathlib_version_minor`, `mathlib_get_global_seed`
  and `mathlib_set_global_seed`. Each is 7 to 19 bytes of generic code with
  fewer than 16 fixed pattern bytes, and the builder's `min_fixed_bytes` rule
  declines to sign them. That is the rule working, not a miss: at a floor of 8
  those signatures produced four false positives across the fixture corpus.

`python/tests/test_flirt_matching.py`, on the stripped image:

- **16** `mathlib_*` functions recovered by name from a binary with no symbol
  table at all.

`python/tests/test_warp_function_guids.py`:

- **22 of 22** `mathlib_*` functions keep the same WARP function GUID across
  the relink.
