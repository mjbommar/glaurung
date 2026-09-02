//! `src/flirt/` against real signatures, real binaries, and -- above all --
//! real opportunities to be wrong.
//!
//! # Why this file exists
//!
//! FLIRT is the component with the worst consequence-to-coverage ratio in the
//! tree. Its four existing tests all drive a four-line hand-written JSON
//! literal; not one of them opens a binary. Meanwhile a FLIRT hit writes a
//! name into the knowledge base under `set_by=flirt`, which
//! `python/glaurung/llm/kb/provenance.py` ranks at **50** -- above `auto`,
//! above `propagated`, above `borrowed`. A false positive here does not
//! degrade an answer, it *outranks* the correct one, and the analyst sees a
//! confident wrong name with no indication anything is unusual.
//!
//! So the load-bearing direction is the negative one: a function that is NOT
//! a known library function must not be given a library name.
//!
//! # What "a real static library" turned out to mean here
//!
//! The Phase 5 plan asks for a `.sig` built from a real `libc.a`/`libstdc++.a`.
//! Two things about this repository make that a different job than it sounds:
//!
//! 1. **`src/flirt/` does not consume FLIRT.** Despite the name it reads
//!    neither IDA `.sig` nor `.pat`. It reads a bespoke JSON file of
//!    `{name, prologue_hex}` pairs and does **exact byte equality** on a
//!    fixed-length window at the entry VA -- no wildcard mask, no CRC, no tail
//!    byte, none of the machinery that makes real FLIRT robust to relocation.
//!    There is no code in the tree that could load a genuine `.sig`.
//! 2. **Exact-byte matching cannot survive the trip out of a `.a`.** An
//!    archive member is relocatable: every call and every global reference in
//!    its first 32 bytes is a placeholder that the linker overwrites. The
//!    first test below measures this on the one real static library the
//!    repository ships, `libmathlib.a`, and reports how many of its functions
//!    are affected. That number is the honest ceiling on this design's recall
//!    against statically linked code, and it is a property of the algorithm,
//!    not of our corpus.
//!
//! Nothing in the tree is statically linked against `libmathlib.a` (the one
//! consumer, `samples/.../libraries/test_mathlib`, links the shared object),
//! and linking one at test time would need a compiler in the test
//! environment. So the *match* direction is exercised against binaries the
//! repository does have -- the 206-fixture matrix -- where ground truth is the
//! symbol table and is exact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use glaurung::core::address::{Address, AddressKind};
use glaurung::core::function::{Function, FunctionKind};
use glaurung::flirt::{
    apply_flirt_overrides, discover_flirt_seeds, FlirtLibrary, FlirtLibraryFile,
    FlirtSignatureEntry,
};
use object::read::archive::ArchiveFile;
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

/// The prologue length the shipped library and the Python builder both use.
/// `python/glaurung/tools/build_flirt_library.py:PROLOGUE_LEN`.
const SHIPPED_PROLOGUE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Measured ratchets. Produced on 2026-08-31 against the 206-fixture matrix.
// ---------------------------------------------------------------------------

/// Functions in a fixture that the shipped default library gives a name to.
///
/// **Must be zero.** `data/sigs/glaurung-base.x86_64.flirt.json` holds 19
/// relocation-masked signatures built from `libmathlib.a`; the fixture corpus
/// is unrelated C. Every hit would be a `set_by=flirt` write of a wrong name
/// into a real project's KB, so this is a hard ceiling, not a statistical one.
///
/// The value was measured on 2026-08-31 against the previous library (30 exact
/// prologues from linked C++ samples). It has **not** been re-measured since
/// the library was rebuilt from the archive, because
/// `tests/decompiler_fixtures/build` is gitignored and was absent in the
/// worktree that made the change -- this test skips itself in that state. The
/// ceiling stays at zero because it is a correctness bound, not an observation.
const MAX_SHIPPED_LIBRARY_FALSE_POSITIVES: usize = 0;

/// Names assigned to clang-built functions by a library built from gcc.
///
/// **Must be zero, and is** at the shipped 32-byte prologue: two compilers
/// never emit the same 32 bytes for different source. See the prologue-length
/// test for what happens when that window is shortened.
const MAX_CROSS_COMPILER_FALSE_POSITIVES: usize = 0;

// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_build_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("decompiler_fixtures")
        .join("build")
}

/// One function located in one binary, with the name the symbol table gives it.
#[derive(Clone, Debug)]
struct KnownFunction {
    name: String,
    va: u64,
    /// The `prologue_len` bytes at the entry VA, when that many are readable.
    prologue: Vec<u8>,
}

/// Read every sized text symbol from an object, plus its entry prologue.
///
/// Zero-sized symbols are CRT boilerplate with no extent. Symbols appear in
/// both `.symtab` and `.dynsym`, hence the dedupe. Note that the prologue is
/// allowed to run past the end of a short function into its neighbour --
/// that is precisely what the shipped builder does, and pretending otherwise
/// here would test something the product does not do.
fn known_functions(path: &Path, prologue_len: usize) -> Vec<KnownFunction> {
    let Ok(data) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(obj) = object::File::parse(&*data) else {
        return Vec::new();
    };
    let mut seen: BTreeMap<String, KnownFunction> = BTreeMap::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.size() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || seen.contains_key(name) {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        let Ok(section) = obj.section_by_index(index) else {
            continue;
        };
        let Ok(Some(bytes)) = section.data_range(sym.address(), prologue_len as u64) else {
            continue;
        };
        seen.insert(
            name.to_string(),
            KnownFunction {
                name: name.to_string(),
                va: sym.address(),
                prologue: bytes.to_vec(),
            },
        );
    }
    seen.into_values().collect()
}

/// Every FUNC symbol start in an object, including the zero-sized ones.
///
/// The zero-sized entries are the CRT stubs -- `register_tm_clones`,
/// `frame_dummy`, `_init`. They carry no extent so they cannot become
/// signatures, but they ARE real function starts, and a seed that lands on one
/// is correct rather than stray. Leaving them out of the ground truth is how
/// the first draft of this file reported five true positives as defects.
fn all_function_starts(path: &Path) -> BTreeMap<u64, BTreeSet<String>> {
    let mut out: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let Ok(data) = std::fs::read(path) else {
        return out;
    };
    let Ok(obj) = object::File::parse(&*data) else {
        return out;
    };
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        out.entry(sym.address())
            .or_default()
            .insert(name.to_string());
    }
    out
}

/// Group signatures by their bytes, so "which names are indistinguishable to
/// an exact-byte matcher" is answerable.
///
/// This is the equivalence the matcher actually implements. Any assertion that
/// a specific *name* comes back is really an assertion about this map, and
/// stating it that way is what separates a matcher defect from two functions
/// that genuinely emit the same 32 bytes.
fn names_by_prologue(sigs: &[(String, Vec<u8>)]) -> BTreeMap<Vec<u8>, BTreeSet<String>> {
    let mut out: BTreeMap<Vec<u8>, BTreeSet<String>> = BTreeMap::new();
    for (name, bytes) in sigs {
        out.entry(bytes.clone()).or_default().insert(name.clone());
    }
    out
}

/// Every fixture `.so` for one `(compiler, opt)` slice, sorted by fixture name.
///
/// Sorted because several measurements below depend on which of two equally
/// valid candidates is seen first, and `read_dir` order is not stable across
/// machines.
fn fixture_paths(compiler: &str, opt: &str) -> Vec<(String, PathBuf)> {
    let suffix = format!("-{compiler}-{opt}.so");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(fixture_build_dir()) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(&suffix) {
            out.push((stem.to_string(), entry.path()));
        }
    }
    out.sort();
    out
}

fn skip_fixtures() -> bool {
    if fixture_paths("gcc", "O2").is_empty() {
        eprintln!(
            "SKIP: {} is empty or absent. It is gitignored and built by the \
             fixture harness; see docs/development/decompiler-testing.md.",
            fixture_build_dir().display()
        );
        return true;
    }
    false
}

/// Serialize signatures to the on-disk schema and load them back.
///
/// Going through JSON rather than calling `FlirtLibrary::from_file` directly
/// is deliberate: the serialized form is the product's actual input, and a
/// hex-encoding or field-name regression would be invisible to an in-memory
/// construction.
fn library_from(sigs: &[(String, Vec<u8>)], prologue_len: usize) -> FlirtLibrary {
    let file = FlirtLibraryFile {
        schema_version: "1".to_string(),
        arch: "x86_64".to_string(),
        prologue_len,
        entries: sigs
            .iter()
            .map(|(name, bytes)| FlirtSignatureEntry {
                name: name.clone(),
                prologue_hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
                source_binary: "tests/decompiler_fixtures/build".to_string(),
                // No mask, no CRC, no refs: this helper deliberately builds
                // the v1 shape, because most measurements in this file are
                // about what exact-byte matching can and cannot do.
                ..Default::default()
            })
            .collect(),
        index: Default::default(),
        library: None,
        stats: serde_json::Value::Null,
    };
    let json = serde_json::to_string(&file).expect("signature library must serialize");
    FlirtLibrary::from_json(&json).expect("signature library must deserialize")
}

/// Signatures for every named function across a set of fixture binaries.
fn signatures_from(paths: &[(String, PathBuf)], prologue_len: usize) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (_, path) in paths {
        for f in known_functions(path, prologue_len) {
            if f.prologue.len() == prologue_len {
                out.push((f.name, f.prologue));
            }
        }
    }
    out
}

/// Placeholder `sub_<hex>` functions at the true entry points of a binary.
///
/// This is the state `apply_flirt_overrides` is designed to see: discovery has
/// found the code but has no name for it. Using the *true* entry points rather
/// than invented addresses means a match here is a match on real function
/// bytes at a real function start.
fn placeholders(functions: &[KnownFunction]) -> Vec<Function> {
    functions
        .iter()
        .map(|f| {
            let addr = Address::new(AddressKind::VA, f.va, 64, None, None)
                .expect("fixture VAs are valid 64-bit addresses");
            Function::new(format!("sub_{:x}", f.va), addr, FunctionKind::Normal)
                .expect("placeholder function must construct")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. What a real static library can and cannot give this design.
// ---------------------------------------------------------------------------

/// Build signatures from the one real static library in the tree, and measure
/// why they could never match a linked image.
///
/// `samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a` is a
/// genuine `ar` archive holding a genuine relocatable object. Extracting
/// prologues from it works. *Using* them does not, and this test says exactly
/// why with a number: it counts how many of the 21 `mathlib_*` functions have
/// a relocation inside the 32-byte window that becomes their signature.
///
/// A relocation in the window means the bytes in the archive are placeholders
/// the linker will overwrite, so the signature is guaranteed never to match
/// the linked form. This is the argument for the design being wildcard-based
/// (real FLIRT) rather than exact-byte, and it is measured rather than
/// asserted so the number appears in the log every run.
#[test]
fn signatures_from_a_real_static_library_are_relocation_contaminated() {
    let archive_path =
        repo_root().join("samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a");
    let Ok(data) = std::fs::read(&archive_path) else {
        panic!(
            "{} is missing. It is committed, not generated, so its absence \
             means the samples tree was pruned -- fix the checkout rather \
             than skipping this test.",
            archive_path.display()
        );
    };
    let archive = ArchiveFile::parse(&*data).expect("libmathlib.a must parse as an archive");

    let mut total = 0usize;
    let mut contaminated = 0usize;
    let mut sigs: Vec<(String, Vec<u8>)> = Vec::new();
    for member in archive.members() {
        let member = member.expect("archive member must parse");
        let member_data = member.data(&*data).expect("archive member data must read");
        let obj = object::File::parse(member_data).expect("mathlib.o must parse as ELF");

        // Relocation offsets, per section index, so a function's window can be
        // tested against the section it actually lives in.
        let mut relocs: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
        for section in obj.sections() {
            let offsets: Vec<u64> = section.relocations().map(|(off, _)| off).collect();
            relocs.insert(section.index().0, offsets);
        }

        for sym in obj.symbols() {
            if sym.kind() != SymbolKind::Text || sym.size() == 0 {
                continue;
            }
            let Ok(name) = sym.name() else { continue };
            let Some(index) = sym.section_index() else {
                continue;
            };
            let Ok(section) = obj.section_by_index(index) else {
                continue;
            };
            let Ok(Some(bytes)) = section.data_range(sym.address(), SHIPPED_PROLOGUE_LEN as u64)
            else {
                continue;
            };
            total += 1;
            sigs.push((name.to_string(), bytes.to_vec()));

            let start = sym.address();
            let end = start + SHIPPED_PROLOGUE_LEN as u64;
            if relocs
                .get(&index.0)
                .is_some_and(|offs| offs.iter().any(|o| *o >= start && *o < end))
            {
                contaminated += 1;
            }
        }
    }

    assert!(
        total >= 20,
        "only {total} functions found in libmathlib.a; expected the ~20 \
         sized mathlib_* entry points. The archive reader, not the library, \
         is broken."
    );

    // The extraction itself must work: the signatures round-trip and match
    // their own bytes. That much of the pipeline is sound.
    let lib = library_from(&sigs, SHIPPED_PROLOGUE_LEN);
    for (name, bytes) in &sigs {
        assert_eq!(
            lib.match_prologue(bytes),
            Some(name.as_str()),
            "signature for {name} extracted from libmathlib.a does not match \
             the bytes it was built from -- the hex round trip is broken"
        );
    }

    eprintln!(
        "libmathlib.a: {total} functions, {contaminated} ({:.0}%) have a \
         relocation inside their 32-byte signature window and therefore could \
         never match the same function after linking",
        100.0 * contaminated as f64 / total as f64
    );
}

// ---------------------------------------------------------------------------
// 2. The match direction: does a signature find the function it came from?
// ---------------------------------------------------------------------------

/// Every signature built from a binary must name that binary's functions.
///
/// Recall against the source binary is the one place this design should be
/// perfect, and anything less points at the VA-to-file-offset mapping in
/// `build_va_map` rather than at the matcher. It is the only test in the file
/// that exercises `apply_flirt_overrides` end to end on real ELF section
/// tables.
///
/// "Correct" here means the returned name is one of the names that share the
/// target's exact 32 bytes -- not necessarily the name the symbol table uses.
/// An exact-byte matcher cannot distinguish two functions that emit identical
/// prologues, and 44 of them in this corpus do (`dot_product_f32` and
/// `dot_product_f64`; a C++ `D1`/`D2` destructor pair; `fib` and its
/// `fib.localalias`). Demanding the symbol-table name would be demanding
/// something the algorithm cannot deliver, and would hide the failures it
/// genuinely can: a miss, or a name from a different byte sequence entirely.
///
/// Since the v2 matcher those shared-prologue functions come back **unnamed**
/// rather than under an arbitrary one of their peers' names, which is the
/// point of `FlirtMatch::Ambiguous`. They are therefore excluded from the
/// miss count below and reported separately.
#[test]
fn a_library_names_the_functions_it_was_built_from() {
    if skip_fixtures() {
        return;
    }
    let mut checked = 0usize;
    let mut ambiguous = 0usize;
    let mut unmatched: Vec<String> = Vec::new();
    let mut wrong_bytes: Vec<String> = Vec::new();

    for (stem, path) in fixture_paths("gcc", "O2") {
        let functions = known_functions(&path, SHIPPED_PROLOGUE_LEN);
        let sigs: Vec<(String, Vec<u8>)> = functions
            .iter()
            .filter(|f| f.prologue.len() == SHIPPED_PROLOGUE_LEN)
            .map(|f| (f.name.clone(), f.prologue.clone()))
            .collect();
        if sigs.is_empty() {
            continue;
        }
        let equivalent = names_by_prologue(&sigs);
        let lib = library_from(&sigs, SHIPPED_PROLOGUE_LEN);
        let data = std::fs::read(&path).expect("fixture must read");
        let mut funcs = placeholders(&functions);
        apply_flirt_overrides(&data, &mut funcs, &lib);

        for (placeholder, truth) in funcs.iter().zip(functions.iter()) {
            if truth.prologue.len() != SHIPPED_PROLOGUE_LEN {
                continue;
            }
            checked += 1;
            let peers = &equivalent[&truth.prologue];
            let shares_its_bytes = peers.len() > 1;
            if shares_its_bytes {
                ambiguous += 1;
            }
            if placeholder.name == format!("sub_{:x}", truth.va) {
                // Since the matcher gained an ambiguity verdict it declines to
                // name a function whose bytes are shared with a differently
                // named one, instead of picking whichever the map happened to
                // hold. Not naming those is the correct outcome, so only a
                // function with a UNIQUE byte sequence counts as a miss here.
                if !shares_its_bytes && unmatched.len() < 10 {
                    unmatched.push(format!(
                        "  {stem}: {} at {:#x} was not matched at all",
                        truth.name, truth.va
                    ));
                }
            } else if !peers.contains(&placeholder.name) {
                if wrong_bytes.len() < 10 {
                    wrong_bytes.push(format!(
                        "  {stem}: {} at {:#x} came back as {}, whose bytes differ",
                        truth.name, truth.va, placeholder.name
                    ));
                }
            }
        }
    }

    assert!(
        checked >= 500,
        "only {checked} functions were checked; expected roughly a thousand \
         from 206 fixtures. The corpus join is broken, not the matcher."
    );
    assert!(
        unmatched.is_empty(),
        "{} of {checked} functions were NOT recovered by a library built from \
         their own binary. Self-recall must be total; a gap here is the \
         VA->file-offset mapping, not the signature:\n{}",
        unmatched.len(),
        unmatched.join("\n")
    );
    assert!(
        wrong_bytes.is_empty(),
        "{} of {checked} functions were given a name belonging to a DIFFERENT \
         byte sequence. That is not prologue ambiguity, it is the matcher \
         reading the wrong bytes:\n{}",
        wrong_bytes.len(),
        wrong_bytes.join("\n")
    );
    eprintln!(
        "flirt self-recall: every function with a unique 32-byte prologue was \
         recovered out of {checked} checked; {ambiguous} share their prologue \
         with a differently named function and are deliberately left unnamed"
    );
}

/// A name that is not a `sub_*` placeholder must survive a matching signature.
///
/// This is the Rust-side half of the KB provenance rule. `set_by=flirt` ranks
/// above `auto` but below `dwarf` and `manual`, and the enforcement of that
/// ordering starts here: if `apply_flirt_overrides` overwrote a name that
/// DWARF or an analyst had already established, no amount of care in
/// `provenance.py` could put it back.
#[test]
fn a_matching_signature_never_overwrites_an_established_name() {
    if skip_fixtures() {
        return;
    }
    let mut checked = 0usize;
    for (stem, path) in fixture_paths("gcc", "O2").into_iter().take(40) {
        let functions = known_functions(&path, SHIPPED_PROLOGUE_LEN);
        let sigs: Vec<(String, Vec<u8>)> = functions
            .iter()
            .filter(|f| f.prologue.len() == SHIPPED_PROLOGUE_LEN)
            // Build the library under DIFFERENT names, so any overwrite is
            // visible rather than being a no-op that happens to look right.
            .map(|f| {
                (
                    format!("flirt_would_call_this_{}", f.name),
                    f.prologue.clone(),
                )
            })
            .collect();
        if sigs.is_empty() {
            continue;
        }
        let lib = library_from(&sigs, SHIPPED_PROLOGUE_LEN);
        let data = std::fs::read(&path).expect("fixture must read");

        // Same entry points, but already carrying the names DWARF gave them.
        let mut funcs: Vec<Function> = functions
            .iter()
            .map(|f| {
                let addr = Address::new(AddressKind::VA, f.va, 64, None, None).unwrap();
                Function::new(f.name.clone(), addr, FunctionKind::Normal).unwrap()
            })
            .collect();

        let renamed = apply_flirt_overrides(&data, &mut funcs, &lib);
        assert_eq!(
            renamed, 0,
            "{stem}: apply_flirt_overrides renamed {renamed} functions that \
             already had a real name. Every signature in this library matches, \
             so the guard being tested is the `sub_` prefix check -- if it is \
             gone, FLIRT will overwrite DWARF."
        );
        for (f, truth) in funcs.iter().zip(functions.iter()) {
            assert_eq!(f.name, truth.name, "{stem}: {} was renamed", truth.name);
            checked += 1;
        }
    }
    assert!(
        checked >= 100,
        "only {checked} established names were offered to the matcher; the \
         loop found nothing to protect, which is a vacuous pass"
    );
}

// ---------------------------------------------------------------------------
// 3. The direction that poisons a knowledge base.
// ---------------------------------------------------------------------------

/// The library glaurung ships must not put a wrong name anywhere in the
/// fixture corpus.
///
/// This is the closest thing in the file to a production test.
/// `load_default_library()` picks up `data/sigs/glaurung-base.x86_64.flirt.json`
/// on any run started from the repository root, and every hit it produces is
/// written with `set_by=flirt`, which outranks `auto` in the KB. The shipped
/// signatures are 19 relocation-masked symbols from `libmathlib.a`; the
/// fixtures are unrelated C.
///
/// Both entry points are exercised, because they fail differently:
/// `apply_flirt_overrides` can only mislabel a function discovery already
/// found, while `discover_flirt_seeds` slides its window one byte at a time
/// through the whole text section and can invent an entry point in the middle
/// of an instruction.
#[test]
fn the_shipped_signature_library_names_nothing_wrongly() {
    if skip_fixtures() {
        return;
    }
    let lib_path = repo_root().join("data/sigs/glaurung-base.x86_64.flirt.json");
    let text = std::fs::read_to_string(&lib_path).unwrap_or_else(|e| {
        panic!(
            "{} must be readable ({e}). It is committed and is what \
             load_default_library() finds in production.",
            lib_path.display()
        )
    });
    let lib = FlirtLibrary::from_json(&text).expect("shipped library must parse");
    assert!(
        lib.signature_count() >= 15,
        "the shipped library holds only {} signatures; if it has been emptied \
         this test proves nothing. The floor moved from 20 to 15 when the \
         library was rebuilt from libmathlib.a: 19 masked signatures from an \
         unlinked archive replaced 30 exact prologues from linked samples.",
        lib.signature_count()
    );
    assert_eq!(
        lib.prologue_len, SHIPPED_PROLOGUE_LEN,
        "the shipped library's prologue length changed; the false-positive \
         measurements in this file are all relative to it"
    );

    let mut false_positives: Vec<String> = Vec::new();
    let mut stray_seeds: Vec<String> = Vec::new();
    let mut seeds_total = 0usize;
    let mut scanned = 0usize;

    for (compiler, opt) in [("gcc", "O2"), ("clang", "O2"), ("gcc", "O0")] {
        for (stem, path) in fixture_paths(compiler, opt) {
            let functions = known_functions(&path, SHIPPED_PROLOGUE_LEN);
            if functions.is_empty() {
                continue;
            }
            let data = std::fs::read(&path).expect("fixture must read");
            let mut funcs = placeholders(&functions);
            apply_flirt_overrides(&data, &mut funcs, &lib);
            scanned += funcs.len();
            for (f, truth) in funcs.iter().zip(functions.iter()) {
                if f.name != format!("sub_{:x}", truth.va) && f.name != truth.name {
                    false_positives.push(format!(
                        "  {stem}-{compiler}-{opt}: {} at {:#x} named {}",
                        truth.name, truth.va, f.name
                    ));
                }
            }

            // A seed is acceptable only if it lands on an address the symbol
            // table calls a function AND uses one of that address's names.
            // The corpus does contain a legitimate hit: every fixture links
            // the same `register_tm_clones` CRT stub that the samples the
            // library was built from do, so its 32 bytes really are identical.
            let starts = all_function_starts(&path);
            for (va, name) in discover_flirt_seeds(&data, &[], &lib) {
                seeds_total += 1;
                let ok = starts.get(&va).is_some_and(|names| names.contains(&name));
                if !ok && stray_seeds.len() < 10 {
                    stray_seeds.push(format!(
                        "  {stem}-{compiler}-{opt}: {name} at {va:#x} (symbol \
                         table says {:?})",
                        starts.get(&va)
                    ));
                }
            }
        }
    }

    assert!(
        scanned >= 1000,
        "only {scanned} functions were offered to the shipped library; the \
         loop found nothing, which is a vacuous pass"
    );
    assert!(
        false_positives.len() <= MAX_SHIPPED_LIBRARY_FALSE_POSITIVES,
        "the shipped signature library named {} of {scanned} fixture \
         functions (ratchet {MAX_SHIPPED_LIBRARY_FALSE_POSITIVES}). Each one \
         is a set_by=flirt write of a C++ sample's name onto unrelated C, and \
         flirt outranks auto in the KB:\n{}",
        false_positives.len(),
        false_positives.join("\n")
    );
    assert!(
        stray_seeds.is_empty(),
        "{} of {seeds_total} seeds from the shipped library did not land on a \
         function start carrying that name. discover_flirt_seeds slides byte \
         by byte, so a stray seed makes the disassembler decode from a \
         mid-instruction offset and invent a function:\n{}",
        stray_seeds.len(),
        stray_seeds.join("\n")
    );
    eprintln!(
        "shipped library ({} signatures) vs {scanned} fixture functions: {} \
         false positives, {seeds_total} seeds all landing on named function starts",
        lib.signature_count(),
        false_positives.len()
    );
}

/// A library built from gcc output must not name clang's functions.
///
/// The corpus is ideal for this: the same 206 sources, so every name in the
/// library also exists in every target -- but compiled by a different
/// compiler, so no *correct* match is possible on bytes. Every hit is
/// therefore unambiguously a false positive, with no need to adjudicate
/// borderline cases.
#[test]
fn a_gcc_built_library_does_not_name_clang_functions() {
    if skip_fixtures() {
        return;
    }
    let gcc = fixture_paths("gcc", "O2");
    let clang = fixture_paths("clang", "O2");
    let sigs = signatures_from(&gcc, SHIPPED_PROLOGUE_LEN);
    assert!(
        sigs.len() >= 500,
        "only {} gcc signatures were built; expected roughly a thousand",
        sigs.len()
    );
    let lib = library_from(&sigs, SHIPPED_PROLOGUE_LEN);

    let mut wrong: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for (stem, path) in &clang {
        let functions = known_functions(path, SHIPPED_PROLOGUE_LEN);
        if functions.is_empty() {
            continue;
        }
        let data = std::fs::read(path).expect("fixture must read");
        let mut funcs = placeholders(&functions);
        apply_flirt_overrides(&data, &mut funcs, &lib);
        for (f, truth) in funcs.iter().zip(functions.iter()) {
            scanned += 1;
            let untouched = f.name == format!("sub_{:x}", truth.va);
            // A hit is acceptable only if gcc and clang happened to emit
            // byte-identical code for the SAME function -- then the name is
            // right and it is not a false positive.
            if !untouched && f.name != truth.name {
                wrong.push(format!(
                    "  {stem}: clang's {} at {:#x} was named {} by a gcc signature",
                    truth.name, truth.va, f.name
                ));
            }
        }
    }

    assert!(
        scanned >= 500,
        "only {scanned} clang functions were offered to the gcc library"
    );
    assert!(
        wrong.len() <= MAX_CROSS_COMPILER_FALSE_POSITIVES,
        "{} of {scanned} clang functions were given a gcc signature's name \
         (ratchet {MAX_CROSS_COMPILER_FALSE_POSITIVES}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    eprintln!(
        "gcc library ({} signatures) vs {scanned} clang functions: {} wrong names",
        lib.signature_count(),
        wrong.len()
    );
}

/// Seeds must land on function starts, never mid-instruction.
///
/// `discover_flirt_seeds` slides its window one byte at a time across the
/// whole text section. That is what lets it find functions in a stripped
/// binary, and it is also the only place in the module that can invent an
/// entry point out of the middle of an instruction. Seeding a false start
/// makes the disassembler decode from a wrong offset, which produces a
/// plausible but entirely fictional function body -- and then names it.
///
/// Run against the binary the signatures came from, every seed has a correct
/// answer available, so any seed that is not a known function start is a
/// defect with no mitigating explanation.
#[test]
fn discovered_seeds_land_only_on_real_function_starts() {
    if skip_fixtures() {
        return;
    }
    let mut seeds_total = 0usize;
    let mut ambiguous_names = 0usize;
    let mut off_start: Vec<String> = Vec::new();
    let mut wrong_bytes: Vec<String> = Vec::new();

    for (stem, path) in fixture_paths("gcc", "O2") {
        let functions = known_functions(&path, SHIPPED_PROLOGUE_LEN);
        let sigs: Vec<(String, Vec<u8>)> = functions
            .iter()
            .filter(|f| f.prologue.len() == SHIPPED_PROLOGUE_LEN)
            .map(|f| (f.name.clone(), f.prologue.clone()))
            .collect();
        if sigs.is_empty() {
            continue;
        }
        let equivalent = names_by_prologue(&sigs);
        let lib = library_from(&sigs, SHIPPED_PROLOGUE_LEN);
        let data = std::fs::read(&path).expect("fixture must read");

        let starts = all_function_starts(&path);
        let prologue_at: BTreeMap<u64, &Vec<u8>> =
            functions.iter().map(|f| (f.va, &f.prologue)).collect();

        for (va, name) in discover_flirt_seeds(&data, &[], &lib) {
            seeds_total += 1;
            let Some(names_here) = starts.get(&va) else {
                if off_start.len() < 10 {
                    off_start.push(format!(
                        "  {stem}: seeded {name} at {va:#x}, which no symbol \
                         calls a function"
                    ));
                }
                continue;
            };
            if names_here.contains(&name) {
                continue;
            }
            // Wrong name at a real start: acceptable only when the seeded
            // name's signature is byte-identical to what is at this address,
            // which an exact-byte matcher cannot tell apart.
            let indistinguishable = prologue_at
                .get(&va)
                .and_then(|bytes| equivalent.get(*bytes))
                .is_some_and(|peers| peers.contains(&name));
            if indistinguishable {
                ambiguous_names += 1;
            } else if wrong_bytes.len() < 10 {
                wrong_bytes.push(format!(
                    "  {stem}: {va:#x} is {names_here:?} but was seeded as \
                     {name}, whose bytes differ"
                ));
            }
        }
    }

    assert!(
        seeds_total >= 500,
        "only {seeds_total} seeds were produced across the corpus; a library \
         built from each binary's own functions should re-find nearly all of \
         them. Nothing was tested."
    );
    assert!(
        off_start.is_empty(),
        "{} of {seeds_total} seeds did not land on a known function start. A \
         seed at a non-start address makes the disassembler decode from a \
         wrong offset and invent a function:\n{}",
        off_start.len(),
        off_start.join("\n")
    );
    assert!(
        wrong_bytes.is_empty(),
        "{} of {seeds_total} seeds landed on a real function start under a \
         name belonging to DIFFERENT bytes:\n{}",
        wrong_bytes.len(),
        wrong_bytes.join("\n")
    );
    eprintln!(
        "discover_flirt_seeds: {seeds_total} seeds, all on real function \
         starts; {ambiguous_names} carried a byte-identical sibling's name"
    );
}

/// Shortening the prologue is what turns this matcher into a name generator.
///
/// The 32-byte window is the only thing standing between `set_by=flirt` and
/// nonsense, and nothing in the Rust enforces it -- `prologue_len` is a field
/// in the JSON file, so any regenerated or third-party library can pick a
/// different one. This test measures the cost of that choice on real bytes at
/// four widths and pins the result, so a future "let's use 8 bytes, it's
/// faster" change fails with the number attached.
///
/// Two numbers are measured per width:
///
/// * **Indistinguishable functions** -- how many of the ~940 gcc functions
///   share their window with a differently-named function. Those are the ones
///   an exact-byte matcher can never name correctly, and they are also where
///   the second finding below bites.
/// * **Cross-compiler false positives** -- how many clang functions a
///   gcc-built library gives a name to that is not their own.
///
/// The second finding, which this test documents rather than fixes:
/// `FlirtLibrary::from_file` keys a `HashMap` by prologue bytes and inserts
/// unconditionally, so two entries with the same prologue and different names
/// silently resolve to whichever came last. The module's doc comment says
/// "Library signatures with identical prologues but different names were
/// already pruned at build time", and that pruning exists -- in
/// `build_flirt_library.py`, which reports `dropped_ambiguous: 5` for the
/// shipped file. Nothing in the Rust re-checks it. Even at the shipped
/// 32-byte width this corpus contains functions that would collide.
#[test]
fn a_short_prologue_manufactures_false_positives() {
    if skip_fixtures() {
        return;
    }
    let gcc = fixture_paths("gcc", "O2");
    let clang = fixture_paths("clang", "O2");

    // (len, indistinguishable functions, total gcc functions, wrong names,
    //  clang functions scanned)
    let mut summary: Vec<(usize, usize, usize, usize, usize)> = Vec::new();
    for &len in &[4usize, 8, 16, SHIPPED_PROLOGUE_LEN] {
        let sigs = signatures_from(&gcc, len);
        assert!(!sigs.is_empty(), "no signatures at prologue_len {len}");

        // Count FUNCTIONS in ambiguous buckets, not buckets. At four bytes a
        // handful of buckets absorb almost the whole corpus, so counting
        // buckets would make the shortest window look like the safest one.
        let equivalent = names_by_prologue(&sigs);
        let indistinguishable = sigs
            .iter()
            .filter(|(_, bytes)| equivalent[bytes].len() > 1)
            .count();

        let lib = library_from(&sigs, len);
        let mut wrong = 0usize;
        let mut scanned = 0usize;
        for (_, path) in &clang {
            let functions = known_functions(path, len);
            if functions.is_empty() {
                continue;
            }
            let data = std::fs::read(path).expect("fixture must read");
            let mut funcs = placeholders(&functions);
            apply_flirt_overrides(&data, &mut funcs, &lib);
            for (f, truth) in funcs.iter().zip(functions.iter()) {
                scanned += 1;
                if f.name != format!("sub_{:x}", truth.va) && f.name != truth.name {
                    wrong += 1;
                }
            }
        }
        eprintln!(
            "prologue_len {len:2}: {} distinct signatures, {indistinguishable}/{} \
             gcc functions indistinguishable, {wrong}/{scanned} clang \
             functions given a gcc name",
            lib.signature_count(),
            sigs.len()
        );
        summary.push((len, indistinguishable, sigs.len(), wrong, scanned));
    }

    let at = |len: usize| -> (usize, usize, usize, usize) {
        let row = summary
            .iter()
            .find(|(l, _, _, _, _)| *l == len)
            .expect("every width was measured");
        (row.1, row.2, row.3, row.4)
    };

    // The shipped width must stay clean in the direction that reaches the KB.
    let (indist32, total32, wrong32, scanned32) = at(SHIPPED_PROLOGUE_LEN);
    assert!(
        wrong32 <= MAX_CROSS_COMPILER_FALSE_POSITIVES,
        "at the shipped 32-byte prologue, {wrong32} of {scanned32} clang \
         functions were given a gcc signature's name (ratchet \
         {MAX_CROSS_COMPILER_FALSE_POSITIVES})"
    );
    let indist_rate = indist32 as f64 / total32 as f64;
    assert!(
        indist_rate <= MAX_INDISTINGUISHABLE_AT_SHIPPED_LEN,
        "{indist32} of {total32} functions ({indist_rate:.4}) share their \
         32-byte prologue with a differently-named function; ratchet is \
         {MAX_INDISTINGUISHABLE_AT_SHIPPED_LEN:.4}. FlirtLibrary::from_file \
         resolves each of those silently by last-insert-wins, so whichever \
         name loads second wins for every hit."
    );

    // And the short widths must remain demonstrably worse, or this test has
    // stopped measuring what it claims to.
    let (indist4, total4, wrong4, _) = at(4);
    assert!(
        indist4 * 2 > total4,
        "a 4-byte prologue left only {indist4} of {total4} functions \
         indistinguishable. That is not credible -- `f30f1efa` (endbr64) alone \
         starts most of them -- so the measurement is broken, not the matcher."
    );
    assert!(
        wrong4 > wrong32,
        "a 4-byte prologue produced {wrong4} cross-compiler false positives \
         and a 32-byte one produced {wrong32}. If shortening the window costs \
         nothing, the corpus stopped being representative."
    );
}

/// Fraction of gcc fixture functions whose 32-byte prologue is shared with a
/// differently-named function.
///
/// **Measured: 58 of 888 = 6.53%.** At 16 bytes it is 176/924 (19%), at 8
/// bytes 560/938 (60%), at 4 bytes 920/938 (98%). Those 58 are functions the
/// matcher can only name by coin flip, and the coin is `HashMap::insert`
/// order.
const MAX_INDISTINGUISHABLE_AT_SHIPPED_LEN: f64 = 0.0654;

// ---------------------------------------------------------------------------
// 5. The property v1 could not have: surviving a relink.
// ---------------------------------------------------------------------------

/// One of the two committed images that link the same archive different ways.
///
/// Built by `tests/fixtures/flirt/build.sh` and committed rather than
/// generated, so this test runs on a machine with no compiler and so the two
/// images cannot change identity under a toolchain upgrade.
/// `tests/fixtures/flirt/README.md` records the toolchain and provenance.
fn relink_fixture(name: &str) -> PathBuf {
    repo_root().join("tests/fixtures/flirt").join(name)
}

/// Named `mathlib_*` functions in one of the relink fixtures, with the bytes
/// at the entry that the matcher would see.
fn mathlib_functions(path: &Path, window: usize) -> BTreeMap<String, (u64, Vec<u8>)> {
    let mut out = BTreeMap::new();
    let Ok(data) = std::fs::read(path) else {
        return out;
    };
    let Ok(obj) = object::File::parse(&*data) else {
        return out;
    };
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.size() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if !name.starts_with("mathlib_") {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        let Ok(section) = obj.section_by_index(index) else {
            continue;
        };
        // As much as the matcher can ever want; a short read is fine, and a
        // signature whose CRC range runs past it simply will not match.
        let want = window as u64;
        let mut bytes = Vec::new();
        for len in (1..=want).rev() {
            if let Ok(Some(b)) = section.data_range(sym.address(), len) {
                bytes = b.to_vec();
                break;
            }
        }
        if bytes.len() < SHIPPED_PROLOGUE_LEN {
            continue;
        }
        out.insert(name.to_string(), (sym.address(), bytes));
    }
    out
}

/// **The load-bearing test.** One archive, two link layouts, one library.
///
/// `libmathlib.a` is linked into `mathlib_link_a` (PIE, one driver) and
/// `mathlib_link_b` (non-PIE, a longer driver calling a different subset), so
/// its functions land at different addresses with different resolved call and
/// data displacements in the two images. A signature built from the *archive*
/// must name the same function in both -- that is the entire difference
/// between a signature library and a byte-for-byte record of one link.
///
/// The test also counts how many of those functions have identical 32-byte
/// windows across the two links, because that count is the ceiling an
/// exact-byte matcher could ever reach on the same data.
#[test]
fn one_archive_linked_two_ways_is_named_in_both() {
    let lib_path = repo_root().join("data/sigs/glaurung-base.x86_64.flirt.json");
    let text = std::fs::read_to_string(&lib_path)
        .unwrap_or_else(|e| panic!("{} must be readable ({e})", lib_path.display()));
    let lib = FlirtLibrary::from_json(&text).expect("shipped library must parse");
    let window = lib.match_window();

    let a = mathlib_functions(&relink_fixture("mathlib_link_a.x86_64.elf"), window);
    let b = mathlib_functions(&relink_fixture("mathlib_link_b.x86_64.elf"), window);
    assert!(
        a.len() >= 5 && b.len() >= 5,
        "the relink fixtures carry {} and {} mathlib_* symbols; they are \
         committed, so this means the checkout is incomplete rather than that \
         the linker changed its mind",
        a.len(),
        b.len()
    );

    let mut both_links_named = 0usize;
    let mut checked = 0usize;
    let mut misses: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    let mut exact_bytes_agree = 0usize;

    // Only functions the library actually carries. A symbol the builder
    // declined to sign -- `mathlib_version_minor` is seven bytes, `endbr64;
    // xor eax,eax; ret` -- is not a miss, it is the builder's `min_fixed_bytes`
    // rule working. Counting those as failures would push toward signing
    // things that cannot be identified.
    let signed: BTreeSet<String> = lib.signatures().iter().map(|s| s.name.clone()).collect();
    let mut unsigned: Vec<String> = Vec::new();

    for (name, (va_a, bytes_a)) in &a {
        let Some((va_b, bytes_b)) = b.get(name) else {
            continue;
        };
        if !signed.contains(name) {
            unsigned.push(name.clone());
            continue;
        }
        checked += 1;
        if bytes_a[..SHIPPED_PROLOGUE_LEN] == bytes_b[..SHIPPED_PROLOGUE_LEN] {
            exact_bytes_agree += 1;
        }
        let got_a = lib.match_at(bytes_a).unique().map(str::to_string);
        let got_b = lib.match_at(bytes_b).unique().map(str::to_string);
        match (got_a.as_deref(), got_b.as_deref()) {
            (Some(x), Some(y)) if x == name && y == name => both_links_named += 1,
            (Some(x), Some(y)) => wrong.push(format!(
                "  {name}: link A at {va_a:#x} came back as {x}, link B at \
                 {va_b:#x} as {y}"
            )),
            _ => misses.push(format!("  {name}: link A {got_a:?}, link B {got_b:?}")),
        }
    }

    assert!(
        wrong.is_empty(),
        "the shipped library gave {} archive function(s) a name belonging to a \
         different function. A masked signature that matches the wrong thing \
         is worse than no signature:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert_eq!(
        both_links_named,
        checked,
        "only {both_links_named} of {checked} archive functions were named in \
         BOTH link layouts. This is the property the mask exists for; a gap \
         here means the relocation-derived mask is not covering everything the \
         linker rewrote:\n{}",
        misses.join("\n")
    );
    assert!(
        checked >= 15,
        "only {checked} of the archive's functions were both signed and \
         present in the two links; the library or the fixtures shrank"
    );
    eprintln!(
        "relink: {both_links_named}/{checked} mathlib functions named in both \
         link layouts; only {exact_bytes_agree}/{checked} have identical \
         32-byte windows, which is all an exact-byte matcher could ever reach. \
         {} symbol(s) carry no signature at all ({unsigned:?}).",
        unsigned.len()
    );
}

/// The same measurement with the masks stripped, which is what v1 was.
///
/// Without this the test above proves only that *something* works. With it,
/// the masks are shown to be the cause: the identical pipeline over the
/// identical bytes, with `mask_hex` and the CRC removed, recalls less.
#[test]
fn the_same_library_without_masks_does_not_survive_the_relink() {
    let lib_path = repo_root().join("data/sigs/glaurung-base.x86_64.flirt.json");
    let text = std::fs::read_to_string(&lib_path).expect("shipped library must read");
    let mut file: FlirtLibraryFile =
        serde_json::from_str(&text).expect("shipped library must deserialize");
    let masked_entries = file.entries.iter().filter(|e| e.mask_hex.is_some()).count();
    assert!(
        masked_entries >= 15,
        "only {masked_entries} shipped signatures carry a mask; if the library \
         went back to being unmasked this comparison is vacuous"
    );
    for e in file.entries.iter_mut() {
        e.mask_hex = None;
        e.crc16 = None;
        e.crc_len = 0;
    }
    let unmasked = FlirtLibrary::from_file(file);
    let window = unmasked.match_window();

    let a = mathlib_functions(&relink_fixture("mathlib_link_a.x86_64.elf"), window);
    let b = mathlib_functions(&relink_fixture("mathlib_link_b.x86_64.elf"), window);

    let mut checked = 0usize;
    let mut named_in_both = 0usize;
    let signed: BTreeSet<String> = unmasked
        .signatures()
        .iter()
        .map(|s| s.name.clone())
        .collect();
    for (name, (_, bytes_a)) in &a {
        let Some((_, bytes_b)) = b.get(name) else {
            continue;
        };
        if !signed.contains(name) {
            continue;
        }
        checked += 1;
        if unmasked.match_at(bytes_a).unique() == Some(name.as_str())
            && unmasked.match_at(bytes_b).unique() == Some(name.as_str())
        {
            named_in_both += 1;
        }
    }
    assert!(checked >= 5, "only {checked} functions compared; vacuous");
    assert!(
        named_in_both < checked,
        "the UNMASKED library named all {checked} functions in both links. \
         Either the two fixtures are not actually different layouts, or the \
         archive's code contains no relocations -- either way the masked test \
         above is proving nothing."
    );
    eprintln!(
        "relink without masks: {named_in_both}/{checked} named in both layouts \
         (the masked library reaches {checked}/{checked})"
    );
}

/// A signature from this archive must not name a function that is not from it.
///
/// The negative direction, run against binaries present in every checkout
/// rather than against the gitignored fixture corpus. `mathlib_*` names are
/// distinctive, so any hit outside the two relink fixtures is unambiguously
/// wrong and needs no adjudication.
#[test]
fn the_shipped_library_names_nothing_in_unrelated_samples() {
    let lib_path = repo_root().join("data/sigs/glaurung-base.x86_64.flirt.json");
    let text = std::fs::read_to_string(&lib_path).expect("shipped library must read");
    let lib = FlirtLibrary::from_json(&text).expect("shipped library must parse");

    let root = repo_root().join("samples/binaries/platforms/linux/amd64/export/native");
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                paths.push(path);
            }
        }
    }
    paths.sort();

    let mut scanned = 0usize;
    let mut binaries = 0usize;
    let mut hits: Vec<String> = Vec::new();
    for path in paths.iter().take(60) {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if !data.starts_with(b"\x7fELF") {
            continue;
        }
        binaries += 1;
        let functions = known_functions(path, SHIPPED_PROLOGUE_LEN);
        if functions.is_empty() {
            continue;
        }
        let mut funcs = placeholders(&functions);
        scanned += funcs.len();
        apply_flirt_overrides(&data, &mut funcs, &lib);
        for (f, truth) in funcs.iter().zip(functions.iter()) {
            if f.name != format!("sub_{:x}", truth.va) {
                hits.push(format!(
                    "  {}: {} at {:#x} named {}",
                    path.display(),
                    truth.name,
                    truth.va,
                    f.name
                ));
            }
        }
    }
    assert!(
        binaries >= 5 && scanned >= 100,
        "only {scanned} functions across {binaries} sample binaries were \
         offered to the shipped library; a vacuous pass"
    );
    assert!(
        hits.is_empty(),
        "the shipped mathlib library named {} function(s) in binaries that do \
         not link it. Each one would be a set_by=flirt write outranking \
         auto:\n{}",
        hits.len(),
        hits.join("\n")
    );
    eprintln!(
        "shipped library vs {scanned} functions in {binaries} unrelated \
         samples: 0 names assigned"
    );
}
