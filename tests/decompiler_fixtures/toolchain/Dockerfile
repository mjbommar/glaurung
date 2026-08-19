# Fingerprinted compile toolchain for the decompiler fixture gate.
#
# REPRODUCIBILITY, PRECISELY: the base image is pinned by digest, but the compiler
# packages installed below come from the live Ubuntu archive and are mutable, so
# this image is NOT bit-reproducible over time. What the gate actually relies on is
# the FINGERPRINT: the observed gcc/g++/clang/clang++/ld/libc version strings are
# recorded in baseline.json under `__toolchain__` and asserted before any verdict
# is compared. An archive update therefore fails the gate loudly with a refresh
# instruction, instead of silently shifting what the baseline means.
#
# WHY THIS EXISTS
# ---------------
# tests/decompiler_fixtures/baseline.json records a pass/fail verdict for every
# fixture function in every toolchain lane. That verdict depends on the compiler
# that built the fixture (codegen idioms differ per gcc/clang release) AND on the
# compiler that rebuilds our own decompiled C (gcc >= 14 promotes several C
# diagnostics that gcc 11 only warns about to hard errors). Recorded against
# whatever compilers happen to sit on a developer's host, the baseline is not a
# regression gate -- it is a record of one machine.
#
# So every compiler invocation the gate makes runs inside this image. The base is
# pinned by digest and Ubuntu 22.04 is deliberately OLD: binaries it produces
# link against glibc 2.35, so they load and execute on any newer host or CI
# runner (execution stays native -- only compilation is containerised).
#
# The observed compiler versions are recorded in baseline.json under
# `__toolchain__` and asserted by the gate, so archive drift inside 22.04 fails
# loudly with a refresh instruction instead of silently moving the baseline.
FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

# gcc/g++ 11 and clang/clang++ 14 (the 22.04 defaults). libstdc++-11-dev gives
# clang++ a working C++ runtime -- without it the C++ fixture's clang lanes are
# unbuildable and drop out of the gate entirely.
#
# rustc (1.75.0 from jammy-updates) builds the six `.rs` fixtures, whose 12
# `rustc:{O0,O2}` lanes have per-function verdicts in baseline.json. It was
# MISSING here until 2026-08-18 while those lanes worked on the machines that
# recorded them, because `fixture_toolchain.ensure_image` builds only when the
# TAG is absent: the image on those machines carried a fourth layer
# (`docker history glaurung-fixture-toolchain:1` -> `apt-get install ... rustc`)
# that no committed Dockerfile ever contained. Proven by building this file
# under a second tag: `exec: "rustc": executable file not found in $PATH` on all
# 12 lanes, and every C/C++ lane fine.
#
# `__toolchain__` cannot see the difference. It probes gcc/g++/clang/clang++/ld/
# libc and no rustc, so the image WITH rustc and the image WITHOUT it produce a
# byte-identical fingerprint. Closing that needs one entry in
# `fixture_toolchain._VERSION_PROBES` plus a regeneration of all four committed
# baselines, since every recorded `__toolchain__` would then be missing a key.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc g++ clang libstdc++-11-dev libc6-dev rustc \
 && rm -rf /var/lib/apt/lists/*

# NOT provisioned: `golang-go`. Five Go fixtures sit in
# `tests/decompiler_fixtures/src/` (176-180, 1,131 lines, 36 `//export`ed
# entry points) that NOTHING builds and no gate declares -- `manifest.
# assert_fixtures_declared` and `fixture_harness._fixture_sources` both glob
# `.c`, `.cpp` and `.rs` only, so the sources are structurally invisible. Adding
# the package alone would provision a compiler with no lane; the fixtures need
# `manifest.REQUIRED_FUNCTIONS` entries and all four baselines regenerated
# first. Measured 2026-08-18: with `golang-go` (Go 1.18.1) added to this image,
# all five build `-buildmode=c-shared` clean, so the toolchain half is one line.

# Compilation is hermetic: no network, deterministic locale/timezone.
ENV LC_ALL=C.UTF-8 TZ=UTC
