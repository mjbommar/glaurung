# Android test fixtures

Real binaries used by the Android format tests. All are genuine artifacts
produced by real toolchains (no hand-mocked bytes), kept small and checked in so
tests run without a cross toolchain or network.

| File | What it is | How to rebuild | Used by |
|------|------------|----------------|---------|
| `packed_android.so` | AArch64 shared object with APS2-packed `DT_ANDROID_RELA` | `build.sh` | `tests/android_packed_relocations.rs` |
| `packed_relr.so` | AArch64 shared object with a `DT_RELR` table | `build.sh` | `tests/android_packed_relocations.rs` |
| `unpacked.so` | Same source, plain `DT_RELA` (reference) | `build.sh` | (debugging) |
| `relocs.c` | Source for the three `.so` fixtures | — | `build.sh` |
| `pac_bti` | AArch64 ELF built `-mbranch-protection=standard` (BTI+PAC+GCS); contains `paciasp`/`autiasp`, `bti`, and register-indirect `br` | see `pac.c` | `tests/android_pac_bti_cfg.rs` |
| `pac_bti_stripped` | `pac_bti` with `strip -s` (only UND dynamic imports remain) | `aarch64-linux-gnu-strip -s pac_bti -o pac_bti_stripped` | `tests/android_pac_stripped_discovery.rs` |
| `pac.c` | Source for `pac_bti` | — | — |
| `sample_full.apk` | ZIP with two `classes*.dex` (multidex) + the real binary manifest, all DEFLATE'd | `build_dex.sh` note | `src/formats/apk/tests.rs` |
| `sample.dex` | DEX compiled by `d8` from the `dexsrc/` Java classes | `build_dex.sh` | `src/formats/dex/tests.rs` |
| `sample.apk` | Minimal ZIP carrying `classes.dex` | `build_dex.sh` | `tests/android_dex_triage.rs` |
| `dexsrc/*.java` | Source for `sample.dex` | — | `build_dex.sh` |
| `AndroidManifest_termux_api.axml` | Compiled binary manifest extracted from `com.termux.api` (F-Droid, GPLv3) | see below | `src/formats/axml/tests.rs` |

## Rebuilding the AXML manifest fixture

```bash
curl -sSL -o termux_api.apk https://f-droid.org/repo/com.termux.api_51.apk
unzip -o termux_api.apk AndroidManifest.xml
mv AndroidManifest.xml AndroidManifest_termux_api.axml
```

Ground truth for the AXML tests was cross-checked with
`aapt2 dump xmltree --file AndroidManifest.xml termux_api.apk`.

## `pac_bti`

```bash
aarch64-linux-gnu-gcc -O2 -mbranch-protection=standard -o pac_bti pac.c
# Verify the hardening feature note:
aarch64-linux-gnu-readelf -n pac_bti | grep -i 'feature'   # -> BTI, PAC, GCS
```
