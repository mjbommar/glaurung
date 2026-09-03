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
///     library_path: Path to a FLIRT-style signature library, in **either**
///         format: a JSON library (schema version ``"1"`` or ``"2"``) or a
///         ``gsig/1`` container. The format is decided by the file's first
///         four bytes, not by its name.
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
    // against one library parses that library once. `library_for` dispatches
    // on the file's magic, so this works for both JSON and `gsig/1`.
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

/// Load a signature library in whichever format it is on disk, mapping the
/// one error type onto `OSError` / `ValueError` the way Python callers expect.
fn load_library(path: &str) -> PyResult<crate::flirt::FlirtLibrary> {
    crate::flirt::FlirtLibrary::from_path(std::path::Path::new(path)).map_err(|e| match e {
        crate::flirt::LoadError::Io(io) => PyErr::from(io),
        other => pyo3::exceptions::PyValueError::new_err(format!("{path}: {other}")),
    })
}

/// Read a JSON library off disk into the shared in-memory shape.
fn read_library_file(path: &str) -> PyResult<crate::flirt::FlirtLibraryFile> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{path}: {e}")))
}

fn codec_from_name(codec: &str) -> PyResult<crate::flirt::gsig::Encoder> {
    crate::flirt::gsig::Encoder::from_name(codec).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown gsig codec {codec:?}; this build has \"store\" and \"zstd\"\
             , and \"zstd-max\" only with the `gsig-zstd` cargo feature"
        ))
    })
}

/// Describe a signature library: what format it is, what it holds, and --
/// for a ``gsig/1`` container -- how each section is sized and compressed.
///
/// The per-section sizes come from the chunk table, which is uncompressed by
/// design, so they are exact rather than estimated. Both formats are loaded to
/// answer the metadata questions (`schema_version` and the library key live in
/// the container's own Meta section); this is not a header-only peek.
///
/// Args:
///     path: Path to a JSON or ``gsig/1`` signature library.
///
/// Returns:
///     A dict. Both formats carry ``format`` (``"gsig"`` or ``"json"``),
///     ``file_size``, ``schema_version``, ``arch``, ``prologue_len``,
///     ``n_signatures`` and ``library`` (the ``(name, version, variant,
///     arch)`` key, or ``None``). A ``gsig`` library adds ``format_version``,
///     ``reader_min``, ``arch_tag``, ``scheme``, ``n_strings``, ``n_guids``,
///     ``dict_id``, ``header_len``, ``chunk_count`` and ``chunks`` -- one dict
///     per section with ``kind``, ``name``, ``chunks``, ``compressed_bytes``
///     and ``uncompressed_bytes``.
///
/// Raises:
///     OSError: the file cannot be read.
///     ValueError: it is neither format.
#[pyfunction]
#[pyo3(name = "flirt_library_info_path", signature = (path))]
fn flirt_library_info_path_py<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
    let file_size = std::fs::metadata(path)?.len();
    let out = PyDict::new(py);
    out.set_item("path", path)?;
    out.set_item("file_size", file_size)?;

    let mut magic = [0u8; 4];
    {
        use std::io::Read;
        let mut handle = std::fs::File::open(path)?;
        let _ = handle.read(&mut magic)?;
    }

    if crate::flirt::gsig::is_gsig(&magic) {
        let loaded = crate::flirt::gsig::GsigLibrary::open(std::path::Path::new(path))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{path}: {e}")))?;
        let header = loaded.header();
        out.set_item("format", "gsig")?;
        out.set_item("format_version", header.format_version)?;
        out.set_item("reader_min", header.reader_min)?;
        out.set_item("arch", loaded.arch())?;
        out.set_item("arch_tag", loaded.arch_tag().as_str())?;
        out.set_item("scheme", loaded.scheme().as_str())?;
        out.set_item("schema_version", loaded.schema_version())?;
        out.set_item("prologue_len", loaded.prologue_len())?;
        out.set_item("n_signatures", header.n_signatures)?;
        out.set_item("n_strings", header.n_strings)?;
        out.set_item("n_guids", loaded.guid_count())?;
        out.set_item("dict_id", header.dict_id)?;
        out.set_item("header_len", header.header_len)?;
        out.set_item("chunk_count", header.chunk_count)?;
        let chunks = PyList::empty(py);
        for (kind, count, compressed, uncompressed) in loaded.chunk_summary() {
            let row = PyDict::new(py);
            row.set_item("kind", *kind)?;
            row.set_item(
                "name",
                crate::flirt::gsig::ChunkKind::from_u8(*kind).map(|k| k.as_str()),
            )?;
            row.set_item("chunks", *count)?;
            row.set_item("compressed_bytes", *compressed)?;
            row.set_item("uncompressed_bytes", *uncompressed)?;
            chunks.append(row)?;
        }
        out.set_item("chunks", chunks)?;
        set_library_key(py, &out, loaded.library())?;
        return Ok(out);
    }

    let file = read_library_file(path)?;
    out.set_item("format", "json")?;
    out.set_item("schema_version", &file.schema_version)?;
    out.set_item("arch", &file.arch)?;
    out.set_item(
        "arch_tag",
        crate::flirt::gsig::Arch::from_name(&file.arch).as_str(),
    )?;
    out.set_item("scheme", crate::flirt::MASKED_PATTERN_SCHEME)?;
    out.set_item("prologue_len", file.prologue_len)?;
    out.set_item("n_signatures", file.entries.len())?;
    set_library_key(py, &out, file.library.as_ref())?;
    Ok(out)
}

fn set_library_key(
    py: Python<'_>,
    out: &Bound<'_, PyDict>,
    key: Option<&crate::flirt::FlirtLibraryKey>,
) -> PyResult<()> {
    match key {
        None => out.set_item("library", py.None()),
        Some(key) => {
            let d = PyDict::new(py);
            d.set_item("name", &key.name)?;
            d.set_item("version", &key.version)?;
            d.set_item("variant", &key.variant)?;
            d.set_item("arch", &key.arch)?;
            out.set_item("library", d)
        }
    }
}

/// Read a signature library of either format and return it as JSON text.
///
/// This is how a Python caller reads a ``.gsig``: through the reader that
/// wrote it, never by parsing container bytes in Python. The text is compact
/// (no indentation) and its key order is `serde`'s, so a caller that wants the
/// canonical on-disk form should re-dump it with ``json.dumps(...,
/// indent=2, sort_keys=True)`` -- which is exactly what
/// ``glaurung.tools.sig_convert`` does.
///
/// Args:
///     path: Path to a JSON or ``gsig/1`` signature library.
///
/// Returns:
///     The library as a JSON string.
///
/// Raises:
///     OSError: the file cannot be read.
///     ValueError: it is neither format.
#[pyfunction]
#[pyo3(name = "flirt_library_to_json_str", signature = (path))]
fn flirt_library_to_json_str_py(path: &str) -> PyResult<String> {
    let mut magic = [0u8; 4];
    {
        use std::io::Read;
        let mut handle = std::fs::File::open(path)?;
        let _ = handle.read(&mut magic)?;
    }
    let file = if crate::flirt::gsig::is_gsig(&magic) {
        let loaded = crate::flirt::gsig::GsigLibrary::open(std::path::Path::new(path))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{path}: {e}")))?;
        crate::flirt::gsig::library_file_from_gsig(&loaded)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{path}: {e}")))?
    } else {
        read_library_file(path)?
    };
    serde_json::to_string(&file).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Load a signature library and match one window of bytes against it.
///
/// The narrowest thing a matcher can be asked to do, and therefore what
/// "time to first match" means for a library: load the file, build the index,
/// answer one lookup. It is also how a test asserts that a `.gsig` and the
/// JSON it came from resolve a window identically.
///
/// Args:
///     library_path: A JSON or ``gsig/1`` signature library.
///     data: Bytes read from a candidate function's entry. Must be at least
///         the library's ``prologue_len``; a signature that records a CRC
///         needs up to 255 bytes more, and one whose CRC range runs off the
///         end simply does not match.
///
/// Returns:
///     A dict with ``names`` (empty when nothing matched, one name for a
///     unique verdict, several when ambiguous), ``ambiguous`` and
///     ``evidence`` (``"flirt-L1"``, ``"flirt-L2"``, or ``None``).
///
/// Raises:
///     OSError: the library cannot be read.
///     ValueError: it is neither format.
#[pyfunction]
#[pyo3(name = "flirt_library_match_bytes", signature = (library_path, data))]
fn flirt_library_match_bytes_py<'py>(
    py: Python<'py>,
    library_path: &str,
    data: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let lib = load_library(library_path)?;
    let (verdict, evidence) = lib.match_at_with_evidence(data, None);
    let out = PyDict::new(py);
    match verdict {
        crate::flirt::FlirtMatch::None => {
            out.set_item("names", Vec::<String>::new())?;
            out.set_item("ambiguous", false)?;
            out.set_item("evidence", py.None())?;
        }
        crate::flirt::FlirtMatch::Unique(name) => {
            out.set_item("names", vec![name])?;
            out.set_item("ambiguous", false)?;
            out.set_item("evidence", evidence)?;
        }
        crate::flirt::FlirtMatch::Ambiguous(names) => {
            out.set_item("names", names)?;
            out.set_item("ambiguous", true)?;
            out.set_item("evidence", py.None())?;
        }
    }
    Ok(out)
}

/// Write a `gsig/1` container from a JSON library's text.
///
/// Takes text rather than a path so a builder that has just produced a
/// library in memory does not have to write JSON to disk first.
///
/// Args:
///     json_text: A JSON signature library, schema version ``"1"`` or ``"2"``.
///     output_path: Where to write the container.
///     codec: ``"zstd"`` (default, pure Rust), ``"store"``, or ``"zstd-max"``
///         when the crate was built with the ``gsig-zstd`` feature.
///
/// Returns:
///     A dict with ``bytes_written``, ``n_signatures``, ``n_strings``,
///     ``chunk_count`` and ``sha256``.
///
/// Raises:
///     OSError: the output cannot be written.
///     ValueError: the text is not a library, the codec is unknown, or the
///         library holds something the container cannot represent (an entry
///         whose mask length disagrees with its pattern, for instance).
#[pyfunction]
#[pyo3(name = "flirt_gsig_write_from_json_str", signature = (json_text, output_path, codec = "zstd"))]
fn flirt_gsig_write_from_json_str_py<'py>(
    py: Python<'py>,
    json_text: &str,
    output_path: &str,
    codec: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let file: crate::flirt::FlirtLibraryFile = serde_json::from_str(json_text)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let options = crate::flirt::gsig::WriteOptions {
        encoder: codec_from_name(codec)?,
        ..Default::default()
    };
    let bytes = py
        .detach(|| crate::flirt::gsig::library_file_to_gsig(&file, &options))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    std::fs::write(output_path, &bytes)?;

    let header = crate::flirt::gsig::GsigHeader::parse(&bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let out = PyDict::new(py);
    out.set_item("bytes_written", bytes.len())?;
    out.set_item("n_signatures", header.n_signatures)?;
    out.set_item("n_strings", header.n_strings)?;
    out.set_item("chunk_count", header.chunk_count)?;
    out.set_item("codec", codec)?;
    out.set_item("sha256", {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&bytes))
    })?;
    Ok(out)
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
    analysis_mod.add_function(wrap_pyfunction!(flirt_library_info_path_py, analysis_mod)?)?;
    analysis_mod.add_function(wrap_pyfunction!(
        flirt_library_to_json_str_py,
        analysis_mod
    )?)?;
    analysis_mod.add_function(wrap_pyfunction!(
        flirt_library_match_bytes_py,
        analysis_mod
    )?)?;
    analysis_mod.add_function(wrap_pyfunction!(
        flirt_gsig_write_from_json_str_py,
        analysis_mod
    )?)?;
    analysis_mod.add(
        "FLIRT_MASKED_PATTERN_SCHEME",
        crate::flirt::MASKED_PATTERN_SCHEME,
    )?;
    analysis_mod.add("GSIG_FORMAT_VERSION", crate::flirt::gsig::FORMAT_VERSION)?;
    Ok(())
}
