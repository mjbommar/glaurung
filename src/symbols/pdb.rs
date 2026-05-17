//! Native PDB symbol and type ingestion.
//!
//! This module is intentionally small for the first ingestion slice: it opens a
//! PDB, reports coarse table counts, and locates complete struct/class type
//! records by name.

use std::fs::File;
use std::path::{Path, PathBuf};

use ::pdb::{FallibleIterator, TypeData};

/// PDB implementation used by the ingestor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbBackend {
    /// The pure-Rust `pdb` crate backend.
    Native,
}

/// Coarse metadata from a PDB file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSummary {
    /// Number of records in the TPI type stream.
    pub type_count: usize,
    /// Number of records in the global symbol stream.
    pub symbol_count: usize,
}

/// Summary for a named PDB struct/class type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbStructSummary {
    /// Struct/class name as stored in the PDB.
    pub name: String,
    /// Declared byte size of the type.
    pub byte_size: u64,
    /// Top-level field count from the class/structure record.
    pub field_count: usize,
}

/// Entry point for reading PDB symbol and type information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIngestor {
    path: PathBuf,
    backend: PdbBackend,
}

impl PdbIngestor {
    /// Create an ingestor using the native Rust PDB backend.
    pub fn open<P: Into<PathBuf>>(path: P) -> Self {
        Self::with_backend(path, PdbBackend::Native)
    }

    /// Create an ingestor with an explicit backend.
    pub fn with_backend<P: Into<PathBuf>>(path: P, backend: PdbBackend) -> Self {
        Self {
            path: path.into(),
            backend,
        }
    }

    /// Return the selected backend.
    pub fn backend(&self) -> PdbBackend {
        self.backend
    }

    /// Return the PDB path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read coarse type and symbol counts from the PDB.
    pub fn summarize(&self) -> ::pdb::Result<PdbSummary> {
        match self.backend {
            PdbBackend::Native => self.summarize_native(),
        }
    }

    /// Locate a complete struct/class type record by exact PDB name.
    pub fn find_struct(&self, name: &str) -> ::pdb::Result<Option<PdbStructSummary>> {
        match self.backend {
            PdbBackend::Native => self.find_struct_native(name),
        }
    }

    fn open_native(&self) -> ::pdb::Result<::pdb::PDB<'static, File>> {
        let file = File::open(&self.path)?;
        ::pdb::PDB::open(file)
    }

    fn summarize_native(&self) -> ::pdb::Result<PdbSummary> {
        let mut pdb = self.open_native()?;
        let type_count = pdb.type_information()?.len();
        let mut symbol_count = 0usize;

        match pdb.global_symbols() {
            Ok(symbol_table) => {
                let mut symbols = symbol_table.iter();
                while symbols.next()?.is_some() {
                    symbol_count += 1;
                }
            }
            Err(::pdb::Error::GlobalSymbolsNotFound) => {}
            Err(error) => return Err(error),
        }

        Ok(PdbSummary {
            type_count,
            symbol_count,
        })
    }

    fn find_struct_native(&self, name: &str) -> ::pdb::Result<Option<PdbStructSummary>> {
        let mut pdb = self.open_native()?;
        let type_information = pdb.type_information()?;
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next()? {
            let parsed = match typ.parse() {
                Ok(parsed) => parsed,
                Err(::pdb::Error::UnimplementedTypeKind(_)) => continue,
                Err(error) => return Err(error),
            };

            if let TypeData::Class(class) = parsed {
                if class.name.as_bytes() == name.as_bytes() && !class.properties.forward_reference()
                {
                    return Ok(Some(PdbStructSummary {
                        name: class.name.to_string().into_owned(),
                        byte_size: class.size,
                        field_count: usize::from(class.count),
                    }));
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_pdb(name: &str) -> Option<PathBuf> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
            .join(name);
        path.is_file().then_some(path)
    }

    #[test]
    fn pdb_ingestor_loads_ntkrnlmp_and_finds_eprocess() {
        let Some(path) = fixture_pdb("ntkrnlmp.pdb") else {
            eprintln!("skipping PDB fixture test: ntkrnlmp.pdb is not present");
            return;
        };

        let ingestor = PdbIngestor::open(path);
        assert_eq!(ingestor.backend(), PdbBackend::Native);

        let summary = ingestor.summarize().expect("summarize ntkrnlmp.pdb");
        assert!(
            summary.type_count > 1_000,
            "unexpectedly small type stream: {}",
            summary.type_count
        );
        assert!(
            summary.symbol_count > 0,
            "expected at least one global symbol"
        );

        let eprocess = ingestor
            .find_struct("_EPROCESS")
            .expect("find _EPROCESS")
            .expect("_EPROCESS should exist in ntkrnlmp.pdb");

        assert_eq!(eprocess.name, "_EPROCESS");
        assert_eq!(eprocess.byte_size, 2_944);
        assert!(
            eprocess.field_count >= 140,
            "unexpected _EPROCESS field count: {}",
            eprocess.field_count
        );
    }
}
