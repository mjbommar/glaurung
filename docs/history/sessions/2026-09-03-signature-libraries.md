# 2026-09-03 — Signature libraries: from a 16-signature demo to a published database

> **Kind:** record · **Date:** 2026-09-03

One day, one goal: make the function-signature library real. It started
as sixteen exact prologues taken from linked sample binaries and ended as
a published, signed, content-addressed database of 533,820 signatures in
446 libraries, fetched and verified by a clean client from
`https://assets.glaurung.dev`. This is the record of what was built,
what was measured, what broke, and what is still open. The design is
[`design/signature-library-program-2026-09-03.md`](../../design/signature-library-program-2026-09-03.md);
the live pages are
[`reference/function-signature-libraries.md`](../../reference/function-signature-libraries.md),
[`reference/signature-sources.md`](../../reference/signature-sources.md) and
[`reference/signature-distribution.md`](../../reference/signature-distribution.md).

## What shipped, in order

1. **COFF archives.** MinGW and MSVC archives yielded zero signatures
   because COFF symbols carry no size. `5e882019`.
2. **Docker harvest with provenance.** The sample images export their
   system archives with `dpkg` versions recorded: 419 archives, 508 MB.
3. **Design page and research.** Four literature surveys, the measured
   case for one library per (distro, release, arch, package version), the
   `gsig/1` container, the channel and the licence position.
4. **Network harvester.** Debian via snapshot's `/mr/` and `/file/`,
   Ubuntu via Launchpad, Alpine via the CDN; 14 cells, resumable, paced.
5. **Windows WARP libraries** from the NAS PE+PDB corpus: 82 libraries,
   329,695 GUIDs; cross-servicing recall 0.83 to 0.94 with at most three
   wrong per binary; zero false names on 48 MinGW programs.
6. **Cortex-M** from the ARM GNU 13.2.1 toolchain: 48 libraries, 32,812
   signatures, 209 of 210 correct on real firmware; a libgcc alias
   tie-break defect fixed (21 wrong to 1).
7. **Distribution**: signed content-addressed manifests, `glaurung sigs`,
   cache and offline mode, a publish tool with an external-signature flow.
8. **`gsig/1`**: 101 bytes per signature against 1,326 as JSON; loads
   once per process; twice as fast and half the memory on the merged set.
9. **Rust std**: 26 libraries; same-toolchain recall 47 to 48 percent,
   cross-toolchain zero.
10. **Matcher correctness**: the builder's ambiguity key now agrees with
    the matcher (276 indistinguishable keys to 0); referenced-name
    resolution in the analysis pass (2,931 to 2,979 correct of 4,357, wrong
    unchanged at 12); the library is loaded once per process.
11. **Infrastructure**: bucket `assets.glaurung.dev`, CloudFront with
    origin access control, ACM, Route 53, all private-bucket; the
    maintainer's passphrase-protected minisign key; NAS backups of the key
    pair and both release sets.
12. **Published**: set `base 2026.09.1` (serial 1, 292 JSON blobs) and then
    `2026.09.2` (serial 2, the whole database re-cut as `gsig/1`, 36.3 MiB).

## What the measurements say

Precision is essentially solved and coverage is a breadth problem. A
static binary built with this box's glibc 2.43 scores, per library cell:

| Cell | Named | Correct | Wrong | of |
|---|---|---|---|---|
| Ubuntu resolute (26.04) | 731 | 727 | 4 | 1,090 |
| Ubuntu noble (24.04) | 185 | 182 | 3 | 1,090 |
| Ubuntu jammy (22.04) | 51 | 49 | 2 | 1,090 |
| Debian trixie | 1 | 1 | 0 | 1,090 |
| Debian bookworm, Alpine, other arches | 0 | 0 | 0 | 1,090 |

The four "wrong" are IFUNC dispatch stubs sharing an address with their
resolver. The right cell names two thirds of the glibc code in a stripped
static binary; the wrong distro names nothing.

For installed distro binaries the honest number is near zero by design:
`/usr/bin/emacs` (12 MB, 32 shared libraries, 6,770 functions) gets 8
names, the static glibc stubs every program carries. `/usr/bin/ls` on this
box is the Rust coreutils rewrite (23,101 functions) and matches 310
functions from the Rust 1.88.0 set. Signatures pay on statically linked
code, Rust, musl containers, firmware and Windows system binaries, not on
dynamically linked userland.

## What broke, and the rules that came out of it

- **Opus API overload** killed every Opus lane twice mid-task; each was
  finished by a Sonnet agent working in the same worktree from git state.
  Never resume a dead agent into a worktree another agent now owns.
- **A chained job ran in the main checkout** after its `cd` target (the
  integration worktree) vanished under another session's sweep. Every
  chained `cd` is now `cd ... || exit 1`; the integration worktree moved to
  `~/.cache/glaurung/worktrees/identity-integration`.
- **The publish tool told the maintainer to sign with the wrong trusted
  comment** (short form), which verifies with stock minisign and is refused
  by every client. Three signing rounds were lost. The tool now prints the
  manifest's canonical comment and refuses any other; the signing script
  derives it and verifies before installing.
- **`rm -rf` on variable-built paths** was replaced by guarded deletes and
  the owning tool (`git worktree remove`, `cargo clean`).
- **No third-party signature sets**, by decision: an import lane for
  `mandiant/siglib` was stopped and its outputs removed.
- One agent ran `git stash` and one ran `git checkout -- <file>` against
  instructions; both were reversed without loss and are recorded here.

## Open

- The GitHub Releases mirror (the tool prints the commands, unrun).
- MSVC CRT and STL patterns need an archive source we own (a Build Tools
  or `xwin` install on a licensed device) and a NOTICE review.
- A WARP matcher in the analysis pass: WARP libraries are ingested into the
  KB but not consulted during discovery.
- Broadening the coverage measurement: `tools/measure_signature_coverage.py`
  landed with these numbers. Ubuntu 26.04 `/usr/bin`: 2,153 of 2,191 ELF
  files are dynamically linked and 5 static; over the 17 files with debug
  truth, 0.83 percent of all functions and 26.8 percent of library-code
  functions were named, almost all of it `ld.so` matching the exact
  `ubuntu-resolute` glibc cell. Windows 11 image, 169 PEs with a cached PDB:
  26.1 percent of all functions and 81.8 percent of library-code functions
  named at 99.4 percent precision; on the 38 binaries whose build is a
  library source, 68.1 percent of all functions with zero wrong. The
  whole-`/usr/bin` sweep without truth was not completed.
- The production fix for CFG wall-clock non-determinism (`design/cfg-discovery-determinism-2026-09-02.md`).
- Breadth: the `base` matrix covers Debian bookworm and trixie, Ubuntu
  jammy, noble and resolute, Alpine 3.20 and 3.21, amd64 and arm64; Fedora,
  uClibc, more releases and more libraries are the next harvests.
