Samples: Sources, Builds, and System Artifacts

Overview
- Sources live under `samples/source/` (c, cpp, fortran, java, python).
- Build outputs and collected artifacts go under `samples/binaries/`.
- Metadata JSON files are written to `samples/binaries/metadata/`.

Build/Collect
- Entry: `samples/build-binaries.sh`
  - Compiles C/C++ with `gcc` and `clang-20` across `-O0..-O3`, plus debug/stripped.
  - Cross-builds when toolchains exist: `aarch64-linux-gnu-gcc`, `riscv64-linux-gnu-gcc`, and `gcc -m32` if supported.
  - Compiles Fortran with `gfortran-15` across `-O0..-O3` (+debug).
  - Compiles Java (`javac`), emits `.class` and `.jar` (if `jar` present).
  - Compiles Python `.pyc` and optimized `.opt.pyc`.
  - Collects kernel images, initrd, kernel configs from `/boot` and common system binaries + their shared libraries.

Index/Manifest
- After building/collecting, run `scripts/index_samples.py`.
  - Produces `samples/binaries/index.json` with sha256, size, and file type for each artifact, plus tool versions.

Prerequisites
- Install compilers/toolchains you want to exercise (examples):
  - `build-essential gcc g++` (or equivalent)
  - `clang-20` toolchain
  - `gfortran-15`
  - Cross toolchains: `aarch64-linux-gnu-gcc`, `riscv64-linux-gnu-gcc`, `gcc-multilib`
  - Java: `openjdk-11-jdk` (or newer)
  - Optional utilities: `file`, `ldd`

Notes
- The scripts detect tools dynamically and skip missing ones gracefully.
- Kernel and system binary collection reads from the host (`/boot`, PATH); run locally with appropriate permissions.

