use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=BITWUZLA_LIB_DIR");
    println!("cargo:rerun-if-env-changed=BITWUZLA_RUNTIME_LIB_DIRS");
    if env::var_os("CARGO_FEATURE_SOLVER_BITWUZLA").is_none() {
        return;
    }

    let library_dir = env::var_os("BITWUZLA_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("solver-bitwuzla requires BITWUZLA_LIB_DIR pointing at the pinned 0.9.1 library")
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
