//! Common test utilities and helpers.
//!
//! This module provides shared functionality for both unit tests and integration tests.

use std::path::Path;

/// Test helper for checking if sample files exist
pub fn sample_file_exists<P: AsRef<Path>>(relative_path: P) -> bool {
    let full_path = Path::new("samples").join(relative_path);
    full_path.exists()
}

/// Get the full path to a sample file
pub fn sample_file_path<P: AsRef<Path>>(relative_path: P) -> std::path::PathBuf {
    Path::new("samples").join(relative_path)
}

/// Common test data and constants
pub mod test_data {
    /// Sample ELF file (GCC compiled)
    pub const SAMPLE_ELF_GCC: &str =
        "binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0";

    /// Sample ELF file (Clang compiled)
    pub const SAMPLE_ELF_CLANG: &str =
        "binaries/platforms/linux/amd64/export/native/clang/O0/hello-clang-O0";

    /// Sample PE file (MinGW cross-compiled)
    pub const SAMPLE_PE_EXE: &str =
        "binaries/platforms/linux/amd64/export/cross/windows-x86_64/hello-c-x86_64-mingw.exe";

    /// Sample JAR file
    pub const SAMPLE_JAR: &str = "binaries/platforms/linux/amd64/export/java/HelloWorld.jar";

    /// Sample Java class file
    pub const SAMPLE_JAVA_CLASS: &str =
        "binaries/platforms/linux/amd64/export/java/HelloWorld.class";

    /// Sample Python bytecode
    pub const SAMPLE_PYTHON_PYC: &str = "binaries/platforms/linux/amd64/export/python/hello.pyc";

    /// Sample Fortran executable
    pub const SAMPLE_FORTRAN: &str =
        "binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0";
}

/// Test utilities for file operations
pub mod file_utils {
    use std::fs;
    use std::path::Path;

    /// Read a file with error context
    pub fn read_file_with_context<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, String> {
        let path_ref = path.as_ref();
        fs::read(path_ref).map_err(|e| format!("Failed to read file {:?}: {}", path_ref, e))
    }

    /// Check if path exists with better error messages
    pub fn assert_path_exists<P: AsRef<Path>>(path: P, context: &str) {
        let path_ref = path.as_ref();
        if !path_ref.exists() {
            panic!("{}: Path does not exist: {:?}", context, path_ref);
        }
    }
}
