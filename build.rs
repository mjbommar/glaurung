use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=BITWUZLA_LIB_DIR");
    println!("cargo:rerun-if-env-changed=BITWUZLA_RUNTIME_LIB_DIRS");
    println!("cargo:rerun-if-env-changed=GLAURUNG_BITWUZLA_TYPECHECK_ONLY");
    if env::var_os("CARGO_FEATURE_SOLVER_BITWUZLA").is_none() {
        return;
    }

    // Type-check escape hatch. Panicking here when the library is absent made
    // `--features solver-bitwuzla` -- and therefore `--all-features`, which is
    // what `scripts/lint-rust.sh` and `scripts/harden.sh` run -- die in the
    // build script before rustc ever saw the source. Both scripts were
    // consequently dead on every machine without Bitwuzla installed, which is
    // how `src/symbolic/solver/bitwuzla_backend.rs` sat with a non-exhaustive
    // `match` on `BinOp` for seventeen days with nothing to notice. This lets
    // `cargo check` (which never links) cover the module anyway. It emits no
    // link directives, so a real `cargo build` under this variable fails at
    // link time with undefined Bitwuzla symbols -- deliberately, and the
    // warning below says so.
    if env::var_os("BITWUZLA_LIB_DIR").is_none()
        && env::var_os("GLAURUNG_BITWUZLA_TYPECHECK_ONLY").is_some()
    {
        println!(
            "cargo:warning=GLAURUNG_BITWUZLA_TYPECHECK_ONLY is set and BITWUZLA_LIB_DIR is not: \
             building solver-bitwuzla WITHOUT linking Bitwuzla. `cargo check` is valid; \
             `cargo build`/`cargo test` will fail at link time."
        );
        return;
    }

    let library_dir = env::var_os("BITWUZLA_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "solver-bitwuzla requires BITWUZLA_LIB_DIR pointing at the pinned 0.9.1 library \
                 (or GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1 for a link-free `cargo check`)"
            )
        });
    let library = library_dir.join(shared_library_name());
    assert!(
        library.is_file(),
        "BITWUZLA_LIB_DIR does not contain {}: {}",
        shared_library_name().display(),
        library.display()
    );

    println!("cargo:rustc-link-search=native={}", library_dir.display());
    println!("cargo:rustc-link-lib=dylib=bitwuzla");
    let runtime_dirs = env::var_os("BITWUZLA_RUNTIME_LIB_DIRS")
        .map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_else(|| vec![library_dir]);
    assert!(
        !runtime_dirs.is_empty(),
        "Bitwuzla runtime path list is empty"
    );
    for directory in runtime_dirs {
        assert!(
            directory.is_dir(),
            "Bitwuzla runtime library directory does not exist: {}",
            directory.display()
        );
        if cfg!(target_family = "unix") {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", directory.display());
        }
    }
}

fn shared_library_name() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new("libbitwuzla.dylib")
    } else if cfg!(target_os = "windows") {
        Path::new("bitwuzla.dll")
    } else {
        Path::new("libbitwuzla.so")
    }
}
