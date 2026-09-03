//! Python bindings for `crate::flirt` -- signature extraction and matching.
//!
//! [`flirt_signatures_from_archive_path_py`] exists so
//! `tools/build_flirt_library.py` can derive variant-byte masks from a `.a`
//! archive's relocation tables without reimplementing ELF, Mach-O and COFF
//! relocation parsing in Python. The derivation itself lives in
//! `src/flirt/archive.rs`; this is a thin marshalling layer over it.
//!
//! [`flirt_match_functions_with_evidence_path_py`] is the KB-facing match
//! path: `python/glaurung/llm/kb/siglib.py` drives it to populate
//! `function_match` rows with the escalation level named, per
//! `docs/history/program-measures-2026-09-02/03-schema.sql` section 8.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// Extract masked signatures from every object member of an `ar` archive.
///
/// Args:
///     path: Path to a `.a` (or `.lib`) archive of unlinked objects.
///     pattern_len: Pattern length in bytes. Defaults to 32, as FLIRT uses.
///     min_function_len: Skip symbols smaller than this. Defaults to 8.
///     min_fixed_bytes: Skip signatures comparing fewer than this many bytes
///         after masking. Defaults to 16; see `ArchiveOptions` for the
///         measurement behind that number.
///
/// Returns:
///     A list of dicts, one per function, with the keys ``name``,
///     ``prologue_hex``, ``mask_hex``, ``crc16``, ``crc_len``,
///     ``function_len``, ``refs`` (a list of ``{offset, name}``),
///     ``source_binary``, ``member``, ``address`` and ``masked_bytes``. The
///     first eight are exactly the on-disk signature schema; the last three
///     are provenance used to distinguish aliases from ambiguity.
///
/// Raises:
///     OSError: the file cannot be read.
///     ValueError: the file is not an `ar` archive.
#[pyfunction]
#[pyo3(
    name = "flirt_signatures_from_archive_path",
    signature = (path, pattern_len = 32, min_function_len = 8, min_fixed_bytes = 16)
)]
fn flirt_signatures_from_archive_path_py(
    py: Python<'_>,
    path: &str,
    pattern_len: usize,
    min_function_len: u64,
    min_fixed_bytes: usize,
) -> PyResult<Py<PyList>> {
    let data = std::fs::read(path)?;
    let options = crate::flirt::archive::ArchiveOptions {
        pattern_len,
        min_function_len,
        min_fixed_bytes,
        ..Default::default()
    };
    let sigs = py
        .detach(|| crate::flirt::archive::signatures_from_archive(&data, &options))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let rows = PyList::empty(py);
    for sig in sigs {
        let d = PyDict::new(py);
        d.set_item("name", &sig.entry.name)?;
        d.set_item("prologue_hex", &sig.entry.prologue_hex)?;
        d.set_item("mask_hex", &sig.entry.mask_hex)?;
        d.set_item("crc16", sig.entry.crc16)?;
        d.set_item("crc_len", sig.entry.crc_len)?;
        d.set_item("function_len", sig.entry.function_len)?;
        let refs = PyList::empty(py);
        for r in &sig.entry.refs {
            let rd = PyDict::new(py);
            rd.set_item("offset", r.offset)?;
            rd.set_item("name", &r.name)?;
            refs.append(rd)?;
        }
        d.set_item("refs", refs)?;
        d.set_item("source_binary", &sig.entry.source_binary)?;
        d.set_item("member", &sig.member)?;
        d.set_item("address", sig.address)?;
        d.set_item("masked_bytes", sig.masked_bytes)?;
        rows.append(d)?;
    }
    Ok(rows.unbind())
}

/// Match every function discovered in `path` against a FLIRT library,
/// evidence-carrying.
///
/// Unlike the rename pass wired into discovery (`apply_flirt_overrides`),
/// this does not mutate anything and does not skip functions that already
/// carry a real name -- it is the read side an auditable `function_match` row
/// needs, over the full domain of discovered functions rather than only the
/// `sub_*` placeholders a rename would touch. See
/// `crate::flirt::match_functions_with_evidence` and
/// [`crate::flirt::FlirtLibrary::match_at_with_evidence`] for what each
/// evidence string means.
///
/// Args:
///     path: Path to an executable or object file.
///     library_path: Path to a FLIRT-style JSON signature library (schema
///         version ``"1"`` or ``"2"``).
///
/// Returns:
///     A list of dicts, one per matched function, sorted by entry VA, with
///     the keys ``entry_va``, ``names`` (a list; one entry unless
///     ``ambiguous``), ``ambiguous`` and ``evidence`` (``None`` when
///     ``ambiguous`` is true). Functions with no surviving candidate are
///     simply absent.
///
/// Raises:
///     OSError: either file cannot be read.
///     ValueError: `library_path` does not parse as a FLIRT library.
#[pyfunction]
#[pyo3(name = "flirt_match_functions_with_evidence_path", signature = (path, library_path))]
fn flirt_match_functions_with_evidence_path_py<'py>(
    py: Python<'py>,
    path: &str,
    library_path: &str,
) -> PyResult<Bound<'py, PyList>> {
    let data = std::fs::read(path)?;
    // Through the process-level cache, so a caller matching many binaries
    // against one library parses that library once.
    let lib = crate::flirt::library_for(std::path::Path::new(library_path))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let mut matches = py.detach(|| {
        let budgets = crate::analysis::cfg::Budgets::default();
        let (functions, _cg) = crate::analysis::cfg::analyze_functions_bytes(&data, &budgets);
        crate::flirt::match_functions_with_evidence(&data, &functions, &lib)
    });
    matches.sort_by_key(|m| m.entry_va);

    let rows = PyList::empty(py);
    for m in matches {
        let d = PyDict::new(py);
        d.set_item("entry_va", m.entry_va)?;
        d.set_item("names", m.names)?;
        d.set_item("ambiguous", m.ambiguous)?;
        d.set_item("evidence", m.evidence)?;
        rows.append(d)?;
    }
    Ok(rows)
}

/// Tell `crate::flirt` where the installed `data/sigs/` is.
///
/// Rust cannot work this out: the running executable is `python`, so
/// `current_exe()` is useless and a cwd-relative `data/sigs` only resolves
/// inside a checkout. The extension module's own `__file__` *is* the anchor --
/// it sits at `<package root>/glaurung/_native.<abi>.so` in a wheel and at
/// `<repo>/python/glaurung/_native.<abi>.so` after `maturin develop` -- so
/// both `glaurung/data/sigs` (packaged) and `<repo>/data/sigs` (checkout) are
/// one relative step from it. This mirrors
/// `python/glaurung/llm/kb/type_db.py::_stdlib_bundle_dir`, which resolves
/// `data/types/` from `__file__` for the same reason.
///
/// Best effort and silent: a missing `__file__` leaves the cwd-relative
/// fallback in `crate::flirt::default_library_paths` in force, which is what
/// every caller had before.
fn register_packaged_sig_dir(m: &Bound<'_, PyModule>) {
    let Ok(file) = m.filename() else {
        return;
    };
    let path = std::path::PathBuf::from(file.to_string_lossy().as_ref());
    let Some(package_dir) = path.parent() else {
        return;
    };
    // Installed: `<site-packages>/glaurung/data/sigs`.
    let packaged = package_dir.join("data/sigs");
    if packaged.is_dir() {
        crate::flirt::set_packaged_sig_dir(packaged);
        return;
    }
    // Checkout: the module lives at `<repo>/python/glaurung/`.
    if let Some(repo) = package_dir.parent().and_then(std::path::Path::parent) {
        let in_repo = repo.join("data/sigs");
        if in_repo.is_dir() {
            crate::flirt::set_packaged_sig_dir(in_repo);
        }
    }
}

/// Register the FLIRT bindings onto the existing `analysis` submodule.
///
/// Must run **after** `analysis::register_analysis_bindings`.
pub fn register_flirt_bindings(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_packaged_sig_dir(m);
    let analysis_mod = m.getattr("analysis")?;
    let analysis_mod = analysis_mod.downcast::<PyModule>()?;
    analysis_mod.add_function(wrap_pyfunction!(
        flirt_signatures_from_archive_path_py,
        analysis_mod
    )?)?;
    analysis_mod.add_function(wrap_pyfunction!(
        flirt_match_functions_with_evidence_path_py,
        analysis_mod
    )?)?;
    analysis_mod.add("FLIRT_MASKED_PATTERN_SCHEME", crate::flirt::MASKED_PATTERN_SCHEME)?;
    Ok(())
}
