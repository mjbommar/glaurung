# External corpora

> **Kind:** reference · **Status:** maintained

> **Provenance.** Every URL, size and SHA-256 on this page was
> read off the fetch that produced the local copy on 2026-09-02, and each
> checksum was compared against the one upstream publishes. Nothing here is
> checked into the repository: these are large, externally licensed artifacts
> that live under `$HOME/.cache/glaurung/corpora/` and are located by an
> environment variable.

## Why this page exists

Four corpora feed Glaurung's measurement work and none of them can be
committed:

* `tests/decompiler_fixtures/build/` — **built locally**, gitignored, ~40
  minutes. Documented in [`decompiler-testing.md`](decompiler-testing.md).
* `samples/` — **checked in**, small, documented in
  [`samples/README.md`](../../samples/README.md).
* Published research corpora — **downloaded**, tens of gigabytes, this page.
* NAS-mounted corpora — **read-only, never copied or downloaded**, this page.
  Large, pre-built binary/toolchain trees that live on `/nas4` and are
  referenced by path plus sha256 rather than fetched, because copying them
  would just duplicate bytes an agent must not write to `/nas4` to produce in
  the first place.

A downloaded corpus is only useful as evidence if a later reader can tell that
they have the same bytes. So each entry below records the exact source, the
byte size, the SHA-256, whether that SHA-256 matches the one the publisher
states, and the licence. A number measured against "the Cisco dataset" with no
such record is not reproducible, and
[`identity-measurement.md`](identity-measurement.md) is explicit that a number
without its conditions is not comparable to anything.

## Disk and etiquette

These live under `$HOME/.cache/glaurung/corpora/<name>/`, never in the
repository, never in `/tmp` (which is a shared quota'd tmpfs here — see
`CLAUDE.md`). Set `TMPDIR` before any fetch:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
```

Current total: **17 GB**, all of it Cisco Dataset-1.

---

## Cisco Talos `binary_function_similarity` — Dataset-1

The artifact of Marcelli, Graziano, Ugarte-Pedrero, Fratantonio, Mansouri and
Balzarotti, *How Machine Learning Is Solving the Binary Function Similarity
Problem*, USENIX Security '22
([paper](https://www.usenix.org/system/files/sec22-marcelli.pdf),
[repository](https://github.com/Cisco-Talos/binary_function_similarity)).

**Why this one.** It is the corpus whose published tables our numbers are meant
to sit beside, and it is the only ingested corpus that varies architecture and
bitness — the XA and XB lanes the in-house fixture matrix cannot express.
Report 01 §3 of the research package names it as the cross-check corpus for
exactly that reason.

**License: MIT** for the repository code and the dataset assembly
(`LICENSE` at the repository root, `Copyright (c) 2019-2022 Cisco Talos`). The
compiled binaries carry the licences of the projects they were built from;
those are reproduced in full under `Binaries/LICENSES/` in the repository
(17 files: ClamAV, Curl, Nmap, OpenSSL, UnRAR, Z3, Zlib and ten more used by
Dataset-2). A local copy of the repository tree, including those licence files,
is at `$GLAURUNG_CISCO_CORPUS/repo/`.

### What was fetched

Downloads are Google Drive objects. Upstream's own
[`gdrive_download.py`](https://github.com/Cisco-Talos/binary_function_similarity/blob/main/gdrive_download.py)
holds the file IDs and a `SHA256_DICT`; the "matches upstream" column below is
a comparison against that dictionary.

| Artifact | Google Drive ID | Bytes | SHA-256 | Matches upstream |
|---|---|---|---|---|
| `Dataset-1.zip` (compiled binaries) | `1QpRgVJZTM52bfB6PvCKwVnmkKdHenUai` | 4,081,408,993 | `f45edac9a7414c3bef77b271bcba083656e148d08d2da8ed5d667d887af35e46` | yes |
| `Dataset-Vulnerability.zip` (binaries) | `1i9CEJ7IGwyFF_3VlQWVsJRVW1XMXy96Z` | 5,154,926 | `0b916bd0fc5107e34d5d06c0e7037337b6e0dc5042b475ca3be5ccba7d7d1bd7` | yes |
| `DBs/Dataset-1/features.zip` (ground truth) | `1gu7ZEhpg3JkznX3_VV2SBCyc6LO7sX2q` | 5.07 GB (gdown's reported total; the archive was deleted after extraction and no exact byte count was recorded before it went) | `23a154929ac0600ac5a5893689088f166e1b34fd526f1fc45b6d9cf06ff987f5` | yes |
| repository tarball (`refs/heads/main`) | n/a — `https://codeload.github.com/Cisco-Talos/binary_function_similarity/tar.gz/refs/heads/main` | 65,860,149 | `06e2b8ab09b326c45836f40dc465f616979594f050000afdb5fab650d1d8668a` | n/a (a branch tarball is not a fixed artifact) |

**The features archive was deleted after extraction.** It is 5.07 GB of
IDA-derived feature JSONs — ACFGs, FunctionSimSearch hashes, Zeek strands —
which is precisely what this project does *not* want: the point is to compute
our own features from the binaries. Only the ground-truth CSVs were extracted
(356 MB), and those are what the loader reads:

| File | SHA-256 |
|---|---|
| `DBs/Dataset-1/testing_Dataset-1.csv` | `86b98d5c3e4d4f20f76f3df4bf8ec8331925d9b97f3facda2e993f7e1ef1e08e` |
| `DBs/Dataset-1/pairs/testing/pos_rank_testing_Dataset-1.csv` | `928bbbf50f7d4db48a83a32b331cc42656538033eda504f8b9d2de2cee7fa392` |
| `DBs/Dataset-1/pairs/testing/neg_rank_testing_Dataset-1.csv` | `f9d1d7ff800cea5a8b1eb79fc53b4df94625811770c5dba188a25dfa47bc1b40` |
| `DBs/Dataset-1/pairs/testing/pos_testing_Dataset-1.csv` | `59a66064f06b85a99fa7592d28c8c0e9bf5844660922f01e9b9bbe56e2b38275` |
| `DBs/Dataset-1/pairs/testing/neg_testing_Dataset-1.csv` | `0e5fd7a198bb761f0d15b95b452692c98daa9b856a68f566665ee64ce7205eb3` |

Also extracted: `validation_Dataset-1.csv` and `pairs/validation/`. **Not**
fetched: `training_Dataset-1.csv` (it is inside the same archive but was not
needed — the published tables are computed on the `testing` split), the
Dataset-2 binaries (a Trex subset, password-protected in the archive), and
every `features.zip` for the other datasets.

### On disk

```text
$HOME/.cache/glaurung/corpora/cisco-talos-dataset1/
├── Binaries/
│   ├── Dataset-1/            12 GB, 5,489 ELF binaries, 7 projects, NOT stripped
│   └── Dataset-Vulnerability/ 12 MB, 6 OpenSSL 1.0.2 libcrypto builds
├── DBs/Dataset-1/            356 MB of ground-truth CSVs (above)
├── repo/                     196 MB, the repository tree: LICENSE,
│                             Binaries/LICENSES/, and the published results
│                             CSVs under Results/notebooks/metrics_and_plots/
├── meta/                     the upstream READMEs and gdrive_download.py
└── zips/                     3.9 GB, the two verified binary archives
```

`Binaries/Dataset-1` holds exactly the 5,489 binaries the paper reports.
Naming is `<project>/<arch><bit>-<compiler>-<version>-<opt>_<library>`:

* **6 architecture/bitness combinations** — 1,040 x86, 1,040 x64, 895 arm32,
  825 arm64, 770 mips32, 919 mips64
* **8 compilers** — gcc 4.8, 5, 7, 9; clang 3.5, 5.0, 7, 9
* **5 optimisation levels** — O0, O1, O2, O3, Os
* **inlining disabled throughout**, which is Marcelli's own simplification and
  the reason this corpus cannot supply a NoInline lane

`Binaries/Dataset-Vulnerability` is the ranking task: four cross-compiled
`libcrypto.so.1.0.0` builds of OpenSSL 1.0.2d (x64, x86, arm32, mips32) plus
the same library lifted out of two real firmware images, a NETGEAR R7000
(arm32, OpenSSL 1.0.2h) and a TP-Link Deco-M4 (mips32). It is fetched and
recorded; **no lane consumes it yet**.

### How to fetch it again

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
ROOT="$HOME/.cache/glaurung/corpora/cisco-talos-dataset1"
mkdir -p "$ROOT/zips" && cd "$ROOT/zips"

uvx --from gdown gdown 1QpRgVJZTM52bfB6PvCKwVnmkKdHenUai -O Dataset-1.zip
uvx --from gdown gdown 1i9CEJ7IGwyFF_3VlQWVsJRVW1XMXy96Z -O Dataset-Vulnerability.zip
sha256sum -c <<'EOF'
f45edac9a7414c3bef77b271bcba083656e148d08d2da8ed5d667d887af35e46  Dataset-1.zip
0b916bd0fc5107e34d5d06c0e7037337b6e0dc5042b475ca3be5ccba7d7d1bd7  Dataset-Vulnerability.zip
EOF
unzip -q Dataset-1.zip -d "$ROOT/Binaries"
unzip -q Dataset-Vulnerability.zip -d "$ROOT/Binaries"

# Ground truth. 5.07 GB down, 356 MB kept, archive deleted.
cd "$ROOT" && mkdir -p DBs/Dataset-1
uvx --from gdown gdown 1gu7ZEhpg3JkznX3_VV2SBCyc6LO7sX2q -O features.zip
unzip -q features.zip 'testing_Dataset-1.csv' 'validation_Dataset-1.csv' \
      'pairs/*' -d DBs/Dataset-1
rm features.zip

# The repository, for the licences and the published results tables.
curl -sSL -o repo.tar.gz \
  https://codeload.github.com/Cisco-Talos/binary_function_similarity/tar.gz/refs/heads/main
tar xzf repo.tar.gz && mv binary_function_similarity-main repo && rm repo.tar.gz
```

Note that `gdown --id <id>` no longer exists; current `gdown` takes the id as a
positional argument, which is what upstream's script has not been updated for.
`uvx --from gdown gdown` is the invocation this project uses — never system
`pip`.

### Who reads it

`tests/identity_retrieval/cisco.rs`, via **`GLAURUNG_CISCO_CORPUS`** pointing
at the directory above. Unset, every Dataset-1 test skips loudly and asserts
nothing. See [`identity-measurement.md`](identity-measurement.md#cisco-dataset-1)
for what is measured and what the numbers are.

---

## ARM GNU Toolchain (`armtc`) and Cortex-M validation firmware — NAS, read-only

Three trees under `/nas4/data/binary-analysis/`, used together to build and
validate the Cortex-M FLIRT signature libraries in
[`function-signature-libraries.md`](../reference/function-signature-libraries.md#cortex-m-bare-metal).
None of them is downloaded or copied anywhere by this repository's tooling;
`tools/harvest_armtc.py` records NAS path plus sha256 and nothing else.

**`armtc/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi/`** — the
prebuilt ARM GNU Toolchain release (`arm-none-eabi-gcc 13.2.1 20231009`,
newlib `4.3.0`), 780 static archives (`libc.a`, `libc_nano.a`, `libg.a`,
`libm.a`, `libstdc++.a`, `libstdc++_nano.a`, `libsupc++.a`, `libnosys.a`,
`librdimon*.a`, `libgcov.a`, `libcaf_single.a`) across 39 multilibs under
`arm-none-eabi/lib/{arm,thumb}/**` plus `libgcc.a` under
`lib/gcc/arm-none-eabi/13.2.1/**`. Licence: newlib/libgloss is BSD-style
(the toolchain's own `license.txt`, lines 8721-10644); libgcc/libstdc++ are
GPLv3 plus the GCC Runtime Library Exception. Read by
`GLAURUNG_ARMTC` (Python-side only, e.g.
`tools/harvest_armtc.py --toolchain-root "$GLAURUNG_ARMTC"`, and
`python/tests/test_flirt_cortex_m_fixture.py`'s live-toolchain check).

**`rt-libopencm3/`** — 20 real STM32F4 firmwares from the `libopencm3`
example tree (`blink`, `usart-stdio`, `lcd-dma`, ...), each with a `stripped/`
and an `asrun/` (unstripped, DWARF-carrying) copy at three optimisation
levels (`O0`, `O2`, `O2-noinline`), plus `addr2name.json` (decimal VA -> name
ground truth, some addresses carrying the Thumb bit) and `srcloc.json`. Built
with the *same* toolchain release above (`arm-none-eabi-gcc 13.2.1
20231009`, confirmed from each firmware's `.comment` section) and a gcc14
variant not used by this measurement.

**`decbench-holdout-source-rebuild-2026-08-06/{O0,O2,O2-noinline}/<project>/{compiled,stripped}/`**
— DecBench holdout projects rebuilt from source, several of them bare-metal
ARM EABI5 statically linked firmware: `libopencm3`, `chibios`, `freertos`,
`nuttx`, `riot-os`, `betaflight`, `cleanflight`, `crazyflie`. **Recorded
defect:** for every ARM project checked (`freertos`, `nuttx`, `betaflight`),
`stripped/<binary>` is byte-**identical** to `compiled/<binary>` (sha256
verified) — the corpus's strip step is a no-op for these targets, so there is
no separately-stripped ARM binary to test blind recovery against in this
holdout set. Ground truth for the ARM validation table is read directly off
the binary's own symbol table (`arm-none-eabi-nm -S --defined-only`) rather
than from a separate stripped/unstripped pair.

None of these three trees count toward the "current total" above — they are
never copied into `$HOME/.cache/glaurung/`, only read in place.

## Not ingested, and why

**BinKit 2.0** ([SoftSec-KAIST/BinKit](https://github.com/SoftSec-KAIST/BinKit),
MIT). 371,928 binaries, 8 architectures, 1,904 option combinations, plus the
**NoInline, PIE, LTO, SizeOpt and Obfuscation** sub-datasets. Report 01 §3
ranks it first, and the NoInline lane in particular is the only route to the
field's dominant failure mode: Shi et al. measure 81.8% of HermesSim's failures
and 83.6% of DeJina's as involving *differential inlining*. It is hundreds of
gigabytes and is deliberately not downloaded here. When it is wanted, take the
NoInline sub-dataset alone and record it on this page in the same shape.

**Dataset-2** of the Cisco release (a subset of Trex's binaries). Fetched by
upstream's script alongside Dataset-1, skipped here: it adds no free variable
Dataset-1 does not already have, and its archive is password-protected
(`notasecret`), which is a needless extra step for no new lane.

**Dataset-1 IDBs and feature archives.** IDA Pro databases and IDA-derived
features. The point of this work is to compute our own representation from the
binaries; importing someone else's features would measure their extractor.
