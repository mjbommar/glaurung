# Rust sysroot fixture

One real `.rlib` from an installed rustup toolchain, committed so
`python/tests/test_rust_sysroot_harvest.py` can exercise
`glaurung.tools.harvest_rust_sysroot` and the FLIRT archive builder on a
machine with no Rust toolchain at all.

## What is here

| File | What it is |
|---|---|
| `libpanic_unwind-e6943c8b7850575a.rlib` | The `panic_unwind` crate's `.rlib` from the `1.88.0-x86_64-unknown-linux-gnu` toolchain (`rustc 1.88.0 (6b00bc388 2025-06-23)`), copied byte for byte from `~/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/`. 36,178 bytes. |
| `LICENSE-MIT.txt`, `LICENSE-APACHE.txt` | Copied verbatim from the same toolchain's `share/doc/rust/licenses/`, alongside the redistributed object per both licences' notice requirement. |

## Why this crate

It is one of the thirteen priority crates the Rust half of the
signature-library program builds (ledger item 11), it is small enough to
commit (well under the ~200 KB the project's fixture convention allows), and
-- unlike some of its still-smaller neighbours in the sysroot (`unwind`,
`rustc_std_workspace_core`) -- its single `.rcgu.o` member actually defines
functions: 4 raw signatures, 4 unique, measured with

```bash
uv run python -m glaurung.tools.build_flirt_library \
    --archive tests/fixtures/rust_sysroot/libpanic_unwind-e6943c8b7850575a.rlib \
    --library-name panic_unwind --library-version 1.88.0 \
    --variant 1.88.0-x86_64-unknown-linux-gnu --arch x86_64 \
    --output /tmp/panic_unwind.flirt.json
```

## Licence

`rust-lang/rust`, dual `MIT OR Apache-2.0`, same as the rest of the standard
library (`library/panic_unwind/` in the `rust-lang/rust` monorepo). See
"Rust" in `docs/reference/signature-sources.md`.

## Members

```
$ ar t libpanic_unwind-e6943c8b7850575a.rlib
lib.rmeta
panic_unwind-e6943c8b7850575a.panic_unwind.<cgu-hash>-cgu.0.rcgu.o
```

`lib.rmeta` is rustc's own metadata format, not an object file;
`glaurung.analysis.flirt_signatures_from_archive_path` skips any archive
member that does not parse as an object, so this fixture also stands as a
regression test for that behaviour without needing a full `libstd.rlib`
(58 MB on this box) in the tree.
