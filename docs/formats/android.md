# Android ecosystem support

Glaurung understands the core Android container, bytecode, manifest, and native
hardening formats. Everything here is exercised by real-fixture tests under
`tests/fixtures/android/` (see that directory's `README.md` for provenance and
rebuild recipes).

## Native ELF: bionic packed relocations (`src/formats/elf/packed_relocations.rs`)

Real device `.so` files store their relative relocations compressed. The ELF
parser now decodes both schemes so addresses/xrefs are correct:

- **APS2** — `DT_ANDROID_REL` / `DT_ANDROID_RELA`. Group-delta + SLEB128 stream.
  `ElfParser::android_packed_relocations()`.
- **RELR** — `DT_RELR` / `DT_ANDROID_RELR`. Bitmap of relative relocations.
  `ElfParser::relr_relocations()`.

Validated against AArch64 objects linked with `lld --pack-dyn-relocs=android`
and `=relr`, cross-checked with `llvm-readelf`.

## AArch64 hardening (PAC / BTI) — `src/analysis/cfg.rs`

- Control-flow classification recognises pointer-authenticated returns
  (`retaa`/`retab`), authenticated indirect calls (`blraa*`/`blrab*`), and
  register-indirect branches (`br`, `braa*`, `brab*`). Previously bare `br`
  (tail calls, PLT) was unclassified, so the linear sweep ran past it.
- `bti`/`paciasp`/`pacibsp`/`autiasp` are treated as ordinary (non-terminating)
  instructions.
- A PAC-prologue scanner (`scan_aarch64_prologue_function_starts`) recovers
  function entries from `paciasp`/`pacibsp` landing pads on **stripped** hardened
  binaries, rewinding to a preceding `bti c` when present.

Validated on a `-mbranch-protection=standard` binary (GNU-property note:
`BTI, PAC, GCS`) and its stripped copy.

## DEX (`src/formats/dex/`)

Read-only, bounds-checked parser for `classes*.dex`:

- Header + string / type / proto / field / method / class_def tables.
- Modified UTF-8 (MUTF-8/CESU-8) string decoding, including surrogate pairs.
- `class_names()`, `method_signature(i)` → `Lclass;->name(params)ret`.

Detected in triage as `Format::Dex` (magic `dex\n0NN\0` + endian tag).

## AXML — binary `AndroidManifest.xml` (`src/formats/axml/`)

- `ResStringPool` (UTF-8 and UTF-16), full chunk walker → `XmlEvent` stream.
- `manifest::ManifestSummary`: package, requested permissions, components
  (activity/service/receiver/provider) with the effective `exported` flag, the
  guarding `android:permission`, provider `authorities`, and `<intent-filter>`
  deep links.

Validated against a real device manifest with `aapt2 dump xmltree` ground truth.

## APK / AAB / JAR (`src/formats/apk/`)

- Triage disambiguates ZIPs into `apk` / `aab` / `jar` from member paths.
- `ApkReader` reads the ZIP central directory and inflates members
  (`stored`/`deflate`): `dex_names()` (multidex order), `manifest_bytes()`,
  `resources_arsc()`, `read(name)`.

This closes the loop: an on-disk APK → every `classes*.dex` (class/method list)
and → `AndroidManifest.xml` (exported attack surface).

## Not yet covered (needs device images / dedicated toolchains)

- OAT / VDEX / CDEX (require `dex2oat`; OAT is an ELF with an `oatdata` symbol).
- `resources.arsc` value resolution (`@resource` → concrete value).
- SELinux `sepolicy`, Binder/AIDL `onTransact` modelling, HAL/HIDL vtables,
  Trusty/QSEE `MCLF` trustlets, GKI/KMI symbol borrowing.
