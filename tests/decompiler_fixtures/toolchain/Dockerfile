# Pinned compile toolchain for the decompiler fixture gate.
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
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc g++ clang libstdc++-11-dev libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# Compilation is hermetic: no network, deterministic locale/timezone.
ENV LC_ALL=C.UTF-8 TZ=UTC
