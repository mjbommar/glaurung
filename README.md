# GLAURUNG

<p align="center">
  <img src="assets/glaurung-512.png" alt="GLAURUNG" width="512" height="512">
</p>

<p align="center">
  <strong>Answering the question: what if Ghidra were written in Rust/Python with first-class AI integration?</strong>
</p>


## Samples and Multiplatform Builds

- Sample source code, Dockerfiles, and build scripts live under `samples/`.
- Quick start to build example binaries in isolated Docker images:
  - `cd samples && ./build-multiplatform.sh linux/amd64` (single target)
  - `./build-multiplatform.sh linux/amd64 linux/arm64 windows/amd64` (multiple)
- Outputs are extracted to `samples/binaries/platforms/<os>/<arch>/export/` with subfolders for `native/`, `cross/`, `fortran/`, `java/`, and `python/`.
- Filenames encode compiler and flags (e.g., `hello-gcc-O2`, `hello-clang-debug`, `hello-c-x86_64-mingw.exe`).
- Run `python scripts/index_samples.py` to generate inventory and metadata (`samples/binaries/index.json`).

See `samples/README.md` for the full matrix, layout, and usage.

