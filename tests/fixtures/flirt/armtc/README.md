# Cortex-M (bare metal) signature fixture

The bare-metal ARM half of `tests/fixtures/flirt/`. The ELF fixtures one
directory up prove a masked signature survives a relink on x86_64 (glibc);
`coff/` proves the builder reads COFF at all; this one proves the same
builder handles **Thumb-2 relocations** (`R_ARM_THM_MOVW_ABS_NC`/`MOVT`,
`R_ARM_ABS32`) on a real newlib archive, without pulling in a large newlib
tree wholesale.

## What is here

| File | What it is |
|---|---|
| `newlib_subset.thumb-v7e-m-fp-hard.a` | Three unlinked newlib objects from the ARM GNU Toolchain 13.2.Rel1's `arm-none-eabi/lib/thumb/v7e-m+fp/hard/libc.a`: `libc_a-tolower.o`, `libc_a-toupper.o` (each one function, 20 bytes, a `R_ARM_ABS32`/`MOVW`+`MOVT` pair loading `_ctype_` inside the 32-byte pattern window -- exactly the Thumb-2 relocation case this fixture exists to exercise) and `libc_a-memset.o` (one function, 162 bytes, no relocation in its pattern window, a CRC-bearing control). |
| `LICENSE.newlib.txt` | The newlib/libgloss licence section of the toolchain's own `license.txt` (lines 8721-10644 of the 13.2.Rel1 release), committed verbatim because newlib's BSD-style notices require it alongside redistribution. |
| `build.sh` | Rebuilds the archive from `$GLAURUNG_ARMTC`. Run only when deliberately refreshing. |

## Why these three

`tolower`/`toupper` are the smallest members in the whole archive that carry
a **relocation inside the first 32 bytes** rather than only past-function-end
padding (`docs/reference/function-signature-libraries.md`, "COFF archives",
generalizes the same masking rule to any relocatable format): both load the
address of newlib's `_ctype_` table via a Thumb-2 `MOVW`/`MOVT` pair, and
`object` reports that as two `R_ARM_ABS32`-flavoured half relocations at
offsets 16 and 20 -- inside the pattern, unlike `libgcc.a`'s call-heavy
routines where the relocation usually lands past the 32-byte window. Their
recorded `refs` (`_ctype_` at offset 16) also exercises the L4
referenced-name disambiguator with two candidates that share one reference
target but differ in their fixed bytes (the `'a'`/`'A'` range-check
immediates). `memset` is included as a relocation-free, CRC-bearing control,
the same role `libmathlib.a`'s longer functions play one directory up.

## Provenance and licence

Both objects come from **newlib 4.3.0** as shipped in the **ARM GNU Toolchain
13.2.Rel1** (`arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi`,
`arm-none-eabi-gcc 13.2.1 20231009`), extracted from
`arm-none-eabi/lib/thumb/v7e-m+fp/hard/libc.a` with `arm-none-eabi-ar x`. See
`build.sh` for the exact commands.

newlib is BSD-style (Red Hat/Cygnus notice plus a University of California,
Berkeley notice; see `LICENSE.newlib.txt`), which is why the archive is
committed rather than gated on `GLAURUNG_ARMTC` alone. No GPL-only code is
included: `libgcc.a` is not committed here (the wider validation in
`docs/reference/function-signature-libraries.md` runs directly against the
NAS-hosted toolchain via `GLAURUNG_ARMTC`, never a committed copy).

## Recorded toolchain

```
toolchain: arm-none-eabi-gcc (Arm GNU Toolchain 13.2.rel1 (Build arm-13.7)) 13.2.1 20231009
binutils:  arm-none-eabi-ar (from the same release)
newlib:    4.3.0
source:    arm-none-eabi/lib/thumb/v7e-m+fp/hard/libc.a
newlib_subset.thumb-v7e-m-fp-hard.a  62ceb8896b21e473993f5dd6ffaee7f6cc6dbb0b0d2d4ddb9bd9a10e3ab67ed7
LICENSE.newlib.txt                   a0929659eaf3a4c8b16f1e8a590ced8ca9a6d1b1df918a32bd4d9e6c9baa55e9
```

## What this fixture measures

`python/tests/test_flirt_cortex_m_fixture.py`:

| Measurement | Result |
|---|---|
| Raw signatures extracted | **3** |
| Signatures with a relocation inside the 32-byte pattern | **2** (`tolower`, `toupper`) |
| Signatures with a CRC | **1** (`memset`) |
| Unique after the ambiguity check | **3** -- `tolower` and `toupper` share a reference target (`_ctype_`) but differ in their fixed comparison-immediate bytes, so they do not collide |
| Rebuild determinism | byte-identical JSON on a second build |
