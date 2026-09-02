//! Loading the matched-build corpus and applying the published ground-truth
//! filters.
//!
//! # Where the labels come from
//!
//! `tests/decompiler_fixtures/build/` holds 206 C sources compiled by two
//! compilers at two optimisation levels with symbol tables intact, so
//! `(fixture, symbol name)` is an exact, free ground-truth key -- the same
//! join `tests/similarity_retrieval.rs` uses. This module adds the filters
//! Marcelli et al. (USENIX'22) apply before counting anything, because a
//! number computed without them is not comparable to a published one.
//!
//! # Locating the corpus
//!
//! The build directory is **gitignored**: it is produced by the fixture
//! harness, so a fresh checkout (and every agent worktree) legitimately has
//! none. Resolution order:
//!
//! 1. `GLAURUNG_IDENTITY_CORPUS` -- a path to a populated build directory.
//!    This is how a worktree points at the main checkout's corpus.
//! 2. `$CARGO_MANIFEST_DIR/tests/decompiler_fixtures/build`.
//!
//! When neither exists the harness **skips loudly** on stderr and the tests
//! return without asserting. A vacuous pass that says nothing is the failure
//! mode that avoids.
//!
//! `GLAURUNG_IDENTITY_CORPUS` is read from `tests/`, not from `src/`, so it is
//! outside the env-var allowlist `python/tests/test_src_dependency_boundaries.py`
//! enforces over the product tree. It is documented here and in
//! `docs/development/identity-measurement.md` instead.

// `FunctionSample` and `BlockFacts` are the harness's plug surface: they carry
// what the three schemes landing next need (`blocks`/`edges` for the L1
// structural invariants, `image_path`/`va` for WARP and the CFR) and only CTPH
// is implemented today, so several fields have no reader yet. Narrowing them to
// what CTPH uses would mean widening them again three times, and each widening
// would silently change what a scheme is allowed to see.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use glaurung::analysis::cfg::{
    analyze_functions_bytes, analyze_functions_bytes_with_seeds, Budgets,
};
use glaurung::core::binary::Endianness;
use glaurung::core::disassembler::{Architecture, Disassembler};
use glaurung::core::function::{Function, FunctionFlags, FunctionKind};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

/// The two compilers the corpus was built with.
pub const COMPILERS: [&str; 2] = ["gcc", "clang"];

/// The two optimisation levels that keep a symbol table.
///
/// `O2strip` exists in the build directory too, but it carries no symbols, so
/// it can supply no ground-truth label and is not a slice here.
pub const OPT_LEVELS: [&str; 2] = ["O0", "O2"];

/// Minimum basic-block count a function must have to be scored.
///
/// Marcelli et al. discard functions with fewer than 5 basic blocks and TikNib
/// does the same. Tiny functions are overwhelmingly one-line wrappers whose
/// retrieval says nothing about a representation, and they inflate every
/// metric that counts them. See `docs/history/program-measures-2026-09-02.md`,
/// "Measurement protocol".
pub const MIN_BASIC_BLOCKS: usize = 5;

/// The CFG discovery budget every harness call site uses -- never
/// `Budgets::default()` directly.
///
/// `docs/design/cfg-discovery-determinism-2026-09-02.md` traces the harness's
/// run-to-run digest instability to `Budgets::default().timeout_ms` (100ms):
/// it is a *per-function* wall clock, restarted at every seed, so its firing
/// point depends on CPU contention rather than on the bytes analysed -- on a
/// loaded machine the same curl binary produced 6/6 distinct digests, one
/// function's block count moving between 148 (timeout) and 2048 (the
/// deterministic `max_blocks` cap) run to run. `timeout_ms: 0` does **not**
/// disable the check (`elapsed > timeout_ms` fires on the first nonzero
/// tick, unlike `total_timeout_ms` where `0` means unbounded), so this uses
/// `u64::MAX` instead: the wall clock can now never fire, and the step
/// budgets (`max_blocks`, `max_instructions`, `max_functions`, left at their
/// `Budgets::default()` values) are what bound worst-case work, exactly as
/// option (b) in that document recommends. `src/` is unchanged.
pub fn harness_budgets() -> Budgets {
    Budgets {
        timeout_ms: u64::MAX,
        ..Budgets::default()
    }
}

/// Symbols that are CRT / compiler boilerplate rather than program code.
///
/// These are emitted near-identically into every object in the corpus, so they
/// are simultaneously the easiest possible positives and completely
/// uninformative. Marcelli's "discard compiler intrinsics" filter is this list
/// plus the PLT rule in [`is_plt_or_thunk`].
const CRT_SYMBOLS: [&str; 10] = [
    "_init",
    "_fini",
    "_start",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "__libc_csu_init",
    "__libc_csu_fini",
    "call_weak_fn",
];

/// The instruction set a sample's bytes are in.
///
/// Threaded through [`FunctionSample`] rather than pinned at the top of this
/// file, because the second corpus this harness loads (Cisco Talos Dataset-1,
/// see `cisco.rs`) spans six of them. Anything that decodes a sample's bytes
/// -- the dedupe hash below, a lifting scheme later -- must ask the sample what
/// it is holding instead of assuming x86-64. The doc comment on
/// [`normalized_instruction_hash`] used to say this change was owed; this is it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleArch {
    /// The corpus's own spelling: `x86`, `x64`, `arm32`, `arm64`, `mips32`,
    /// `mips64`. Used in slice labels and printed with every task, so it is
    /// Marcelli's name rather than ours -- a reader comparing our rows against
    /// the published tables should not have to translate.
    pub name: &'static str,
    pub architecture: Architecture,
    pub endianness: Endianness,
    /// 32 or 64. The free variable the XB (cross-bitness) task varies.
    pub bits: u8,
}

/// Ordered by [`SampleArch::name`], which is unique across the constants
/// below.
///
/// Hand-written rather than derived because `Architecture` and `Endianness`
/// are product enums that implement neither `Ord` nor `PartialOrd`. Ordering
/// on the name keeps a `BTreeMap` keyed by a configuration stable and
/// human-readable (`arm32 < arm64 < mips32 < ...`), which is what makes a
/// printed slice list and a JSON report diffable run to run.
impl Ord for SampleArch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(other.name)
    }
}

impl PartialOrd for SampleArch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl SampleArch {
    pub const X86: Self = Self {
        name: "x86",
        architecture: Architecture::X86,
        endianness: Endianness::Little,
        bits: 32,
    };
    pub const X86_64: Self = Self {
        name: "x64",
        architecture: Architecture::X86_64,
        endianness: Endianness::Little,
        bits: 64,
    };
    pub const ARM32: Self = Self {
        name: "arm32",
        architecture: Architecture::ARM,
        endianness: Endianness::Little,
        bits: 32,
    };
    pub const ARM64: Self = Self {
        name: "arm64",
        architecture: Architecture::ARM64,
        endianness: Endianness::Little,
        bits: 64,
    };
    pub const MIPS32: Self = Self {
        name: "mips32",
        architecture: Architecture::MIPS,
        endianness: Endianness::Little,
        bits: 32,
    };
    pub const MIPS64: Self = Self {
        name: "mips64",
        architecture: Architecture::MIPS64,
        endianness: Endianness::Little,
        bits: 64,
    };

    /// The instruction-set family, ignoring width.
    ///
    /// XB (cross-bitness) is "same family, different width", so a task
    /// constraint needs this and not the name.
    pub fn family(self) -> &'static str {
        match self.architecture {
            Architecture::X86 | Architecture::X86_64 => "x86",
            Architecture::ARM | Architecture::ARM64 => "arm",
            Architecture::MIPS | Architecture::MIPS64 => "mips",
            _ => "other",
        }
    }

    /// Whether Glaurung can **lift** this architecture to LLIR, as opposed to
    /// merely disassembling it.
    ///
    /// `false` for MIPS: `src/ir/lift/` covers x86, x86-64, ARM and AArch64
    /// only, while `disasm::registry` reaches MIPS through Capstone. CFG-shaped
    /// and byte-shaped schemes therefore run on a MIPS slice; an IR scheme must
    /// fail extraction there so the harness reports a coverage hole instead of
    /// scoring a degenerate signature.
    pub fn is_liftable(self) -> bool {
        !matches!(self.architecture, Architecture::MIPS | Architecture::MIPS64)
    }
}

/// One labelled function, and the entire input surface a scheme may look at.
///
/// A scheme sees the bytes, the entry VA, the image on disk and the discovered
/// CFG. That set is deliberate: CTPH uses only `bytes`, the L1 structural
/// invariants will use `blocks`/`edges`, and WARP and the CFR need
/// `image_path` and `va` so they can re-open the image and lift it.
#[derive(Clone, Debug)]
pub struct FunctionSample {
    /// Fixture stem, e.g. `13_loop_early_exit`. Half of the ground-truth key.
    pub fixture: String,
    /// Symbol name, e.g. `bisect`. The other half.
    pub name: String,
    /// `gcc` or `clang`.
    pub compiler: &'static str,
    /// `O0` or `O2`.
    pub opt: &'static str,
    /// The instruction set `bytes` holds. Always [`SampleArch::X86_64`] for
    /// this corpus; the Cisco corpus in `cisco.rs` sets all six.
    pub arch: SampleArch,
    /// The image this function was read out of.
    pub image_path: PathBuf,
    /// Entry virtual address inside that image.
    pub va: u64,
    /// The function's bytes, `[va, va + symbol size)`.
    pub bytes: Vec<u8>,
    /// Basic blocks discovered by `glaurung::analysis::cfg`, sorted by start VA.
    pub blocks: Vec<BlockFacts>,
    /// CFG edges as `(from_block_index, to_block_index)` over that sort order,
    /// sorted and deduped. An edge leaving the function (a tail call) lands on
    /// `usize::MAX`.
    pub edges: Vec<(usize, usize)>,
}

impl FunctionSample {
    /// The ground-truth key. Two samples are the same function iff these match.
    pub fn label(&self) -> (&str, &str) {
        (&self.fixture, &self.name)
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// One basic block, reduced to what an identity scheme may key on.
#[derive(Clone, Debug)]
pub struct BlockFacts {
    pub start_va: u64,
    pub end_va: u64,
    pub instruction_count: u32,
}

/// One compilation configuration's slice of a corpus, filtered and sorted.
///
/// The in-house corpus varies `(compiler, opt)` only, so `arch` is x86-64 and
/// `version` is empty there. The Cisco corpus varies all five, and its slice
/// key is the whole tuple; `label` is what gets printed either way.
#[derive(Debug)]
pub struct Slice {
    pub compiler: &'static str,
    pub opt: &'static str,
    /// The instruction set every sample in this slice was compiled for.
    pub arch: SampleArch,
    /// Compiler version, e.g. `9` or `3.5`. Empty when the corpus does not
    /// vary it -- and empty is honest rather than a fabricated `"unknown"`,
    /// because a slice label that names a version the corpus never fixed would
    /// read as a free variable that was actually held constant.
    pub version: &'static str,
    /// Sorted by `(fixture, name)`. The sort is load-bearing, not cosmetic:
    /// schemes at this input size produce heavy ties, and `read_dir` order
    /// varies between machines, so an unsorted pool would make every measured
    /// accuracy wander run to run.
    pub samples: Vec<FunctionSample>,
    pub filters: FilterCounts,
}

impl Slice {
    /// The slice's printed name: `x64-gcc-9-O2`, or `gcc/O0` when the corpus
    /// fixes architecture and version.
    pub fn label(&self) -> String {
        if self.version.is_empty() {
            format!("{}/{}", self.compiler, self.opt)
        } else {
            format!(
                "{}-{}-{}-{}",
                self.arch.name, self.compiler, self.version, self.opt
            )
        }
    }
}

/// How many candidate functions each published filter removed.
///
/// Printed with every result and written into the JSON report. Two harnesses
/// that disagree on these counts are not measuring the same denominator, which
/// is the exact comparability failure the protocol calls out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilterCounts {
    /// Named text symbols with a zero `st_size`, skipped before `considered`.
    ///
    /// Counted separately because on this corpus it is where the CRT
    /// boilerplate actually goes: gcc and clang emit `frame_dummy`,
    /// `register_tm_clones` and friends with no extent, so they never reach
    /// the CRT name filter below and that filter's count is legitimately zero.
    /// Without this field that zero would read as "the filter is not running".
    pub skipped_unsized: usize,
    /// Sized, named text symbols seen before any filter ran.
    pub considered: usize,
    /// Removed: the symbol is not in `.text`.
    pub dropped_non_text: usize,
    /// Removed: a PLT entry, a thunk, or CRT boilerplate.
    pub dropped_plt_or_thunk: usize,
    /// Removed: CFG discovery found no body at the symbol's VA.
    pub dropped_no_cfg: usize,
    /// Removed: fewer than [`MIN_BASIC_BLOCKS`] basic blocks.
    pub dropped_small: usize,
    /// Removed: a duplicate of an already kept `(name, normalized instruction
    /// hash)`.
    pub dropped_duplicate: usize,
    /// Survivors.
    pub kept: usize,
}

impl FilterCounts {
    pub(crate) fn add(&mut self, other: &FilterCounts) {
        self.skipped_unsized += other.skipped_unsized;
        self.considered += other.considered;
        self.dropped_non_text += other.dropped_non_text;
        self.dropped_plt_or_thunk += other.dropped_plt_or_thunk;
        self.dropped_no_cfg += other.dropped_no_cfg;
        self.dropped_small += other.dropped_small;
        self.dropped_duplicate += other.dropped_duplicate;
        self.kept += other.kept;
    }

    pub fn summary(&self) -> String {
        format!(
            "considered {} (+{} unsized, skipped) -> kept {} (dropped: \
             non-.text {}, plt/thunk/crt {}, no-cfg {}, <{} blocks {}, \
             duplicate {})",
            self.considered,
            self.skipped_unsized,
            self.kept,
            self.dropped_non_text,
            self.dropped_plt_or_thunk,
            self.dropped_no_cfg,
            MIN_BASIC_BLOCKS,
            self.dropped_small,
            self.dropped_duplicate,
        )
    }

    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "skipped_unsized": self.skipped_unsized,
            "considered": self.considered,
            "dropped_non_text": self.dropped_non_text,
            "dropped_plt_or_thunk": self.dropped_plt_or_thunk,
            "dropped_no_cfg": self.dropped_no_cfg,
            "dropped_under_min_blocks": self.dropped_small,
            "dropped_duplicate": self.dropped_duplicate,
            "kept": self.kept,
            "min_basic_blocks": MIN_BASIC_BLOCKS,
        })
    }
}

/// The whole loaded corpus: one [`Slice`] per `(compiler, opt)`.
#[derive(Debug)]
pub struct Corpus {
    pub root: PathBuf,
    slices: BTreeMap<(&'static str, &'static str), Slice>,
    /// Filter counts summed over every slice.
    pub filters: FilterCounts,
    /// Wall-clock seconds the load took, for the docs table.
    pub load_seconds: f64,
}

impl Corpus {
    pub fn slice(&self, compiler: &str, opt: &str) -> Option<&Slice> {
        self.slices
            .iter()
            .find(|((c, o), _)| *c == compiler && *o == opt)
            .map(|(_, s)| s)
    }

    /// Every slice, in `(compiler, opt)` order.
    pub fn slices(&self) -> impl Iterator<Item = &Slice> {
        self.slices.values()
    }
}

/// Resolve the corpus root, or `None` with the reason already on stderr.
pub fn corpus_root() -> Option<PathBuf> {
    let from_env = std::env::var_os("GLAURUNG_IDENTITY_CORPUS").map(PathBuf::from);
    let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("decompiler_fixtures")
        .join("build");
    for candidate in [from_env.clone(), Some(fallback.clone())]
        .into_iter()
        .flatten()
    {
        let populated = std::fs::read_dir(&candidate)
            .map(|d| d.count())
            .unwrap_or(0);
        if populated > 0 {
            return Some(candidate);
        }
    }
    eprintln!(
        "SKIP: no identity corpus. Looked at {}{}. It is gitignored and built \
         by the fixture harness (docs/development/decompiler-testing.md); point \
         GLAURUNG_IDENTITY_CORPUS at a populated build directory. Protocol: \
         docs/development/identity-measurement.md.",
        fallback.display(),
        match from_env {
            Some(p) => format!(" and GLAURUNG_IDENTITY_CORPUS={}", p.display()),
            None => " (GLAURUNG_IDENTITY_CORPUS unset)".to_string(),
        }
    );
    None
}

/// Load the corpus once per test binary and share it across every test.
///
/// Cargo runs the tests of one target in a single process, so CFG discovery --
/// by far the most expensive part of the harness -- is paid exactly once no
/// matter how many tasks are scored.
pub fn corpus() -> Option<&'static Corpus> {
    static CORPUS: OnceLock<Option<Corpus>> = OnceLock::new();
    CORPUS.get_or_init(load_corpus).as_ref()
}

fn load_corpus() -> Option<Corpus> {
    let root = corpus_root()?;
    let started = std::time::Instant::now();
    let mut slices = BTreeMap::new();
    let mut totals = FilterCounts::default();
    for compiler in COMPILERS {
        for opt in OPT_LEVELS {
            let slice = load_slice(&root, compiler, opt);
            totals.add(&slice.filters);
            slices.insert((compiler, opt), slice);
        }
    }
    let corpus = Corpus {
        root,
        slices,
        filters: totals,
        load_seconds: started.elapsed().as_secs_f64(),
    };
    eprintln!(
        "corpus: {} in {:.1}s from {}",
        corpus.filters.summary(),
        corpus.load_seconds,
        corpus.root.display()
    );
    for slice in corpus.slices() {
        eprintln!(
            "  {}/{}: {} functions",
            slice.compiler,
            slice.opt,
            slice.samples.len()
        );
    }
    Some(corpus)
}

fn load_slice(root: &Path, compiler: &'static str, opt: &'static str) -> Slice {
    use rayon::prelude::*;

    let suffix = format!("-{compiler}-{opt}.so");
    let mut images: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            // `<fixture>-<compiler>-<opt>.so` only. `.build.json` and
            // `.dwarf.so` share the prefix and are not images to score.
            if let Some(fixture) = file_name.strip_suffix(&suffix) {
                if !fixture.is_empty() && !fixture.ends_with(".dwarf") {
                    images.push((fixture.to_string(), entry.path()));
                }
            }
        }
    }
    images.sort();

    // Deterministic despite the parallelism: `par_iter().map().collect()` into
    // a `Vec` preserves input order, and the dedupe below runs serially over
    // that ordered result.
    let per_image: Vec<(Vec<FunctionSample>, FilterCounts)> = images
        .par_iter()
        .map(|(fixture, path)| load_image(fixture, path, compiler, opt))
        .collect();

    let mut filters = FilterCounts::default();
    let mut samples: Vec<FunctionSample> = Vec::new();
    // Dedupe by (name, normalized instruction hash), the published rule. The
    // hash is over the MNEMONIC sequence, not the bytes: two copies of one
    // helper differ in every relocated operand but agree on the opcode stream,
    // and it is that agreement the filter exists to catch.
    let mut seen: BTreeMap<(String, u64), ()> = BTreeMap::new();
    for (image_samples, counts) in per_image {
        filters.add(&counts);
        for sample in image_samples {
            let key = (sample.name.clone(), normalized_instruction_hash(&sample));
            if seen.insert(key, ()).is_some() {
                filters.dropped_duplicate += 1;
                filters.kept -= 1;
                continue;
            }
            samples.push(sample);
        }
    }
    samples.sort_by(|a, b| (&a.fixture, &a.name).cmp(&(&b.fixture, &b.name)));

    Slice {
        compiler,
        opt,
        // The fixture build directory is x86-64 ELF throughout; the `--arch`
        // matrix that would vary this writes elsewhere.
        arch: SampleArch::X86_64,
        version: "",
        samples,
        filters,
    }
}

/// Read one image: symbols, CFG discovery, and every filter but the dedupe.
fn load_image(
    fixture: &str,
    path: &Path,
    compiler: &'static str,
    opt: &'static str,
) -> (Vec<FunctionSample>, FilterCounts) {
    let mut counts = FilterCounts::default();
    let Ok(data) = std::fs::read(path) else {
        return (Vec::new(), counts);
    };
    let Ok(obj) = object::File::parse(&*data) else {
        return (Vec::new(), counts);
    };

    struct RawSymbol {
        name: String,
        va: u64,
        bytes: Vec<u8>,
        in_text: bool,
    }

    // Pass 1: sized, named text symbols, deduped by name (a symbol appears in
    // both `.symtab` and `.dynsym`).
    let mut raw: BTreeMap<String, RawSymbol> = BTreeMap::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || raw.contains_key(name) {
            continue;
        }
        // A zero-sized symbol carries no extent, so there is nothing to hash
        // and no block count to filter on. Counted rather than skipped
        // silently: on this corpus it is where the CRT boilerplate goes.
        if sym.size() == 0 {
            counts.skipped_unsized += 1;
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        let Ok(section) = obj.section_by_index(index) else {
            continue;
        };
        let in_text = section.name().unwrap_or("") == ".text";
        let Ok(Some(bytes)) = section.data_range(sym.address(), sym.size()) else {
            continue;
        };
        raw.insert(
            name.to_string(),
            RawSymbol {
                name: name.to_string(),
                va: sym.address(),
                bytes: bytes.to_vec(),
                in_text,
            },
        );
    }
    counts.considered = raw.len();

    // Pass 2: ONE CFG discovery over the image, seeded with the symbol VAs we
    // care about. One call per image rather than one per function: discovery
    // is the expensive step and it amortises over the whole object.
    let seeds: Vec<u64> = raw.values().filter(|s| s.in_text).map(|s| s.va).collect();
    let budgets = harness_budgets();
    let (functions, _cg) = analyze_functions_bytes_with_seeds(&data, &budgets, &seeds);
    let by_va: BTreeMap<u64, &Function> =
        functions.iter().map(|f| (f.entry_point.value, f)).collect();

    let mut out = Vec::new();
    for symbol in raw.into_values() {
        if !symbol.in_text {
            counts.dropped_non_text += 1;
            continue;
        }
        if is_plt_or_thunk(&symbol.name, by_va.get(&symbol.va).copied()) {
            counts.dropped_plt_or_thunk += 1;
            continue;
        }
        let Some(func) = by_va.get(&symbol.va) else {
            counts.dropped_no_cfg += 1;
            continue;
        };
        let (blocks, edges) = cfg_facts(func);
        if blocks.len() < MIN_BASIC_BLOCKS {
            counts.dropped_small += 1;
            continue;
        }
        counts.kept += 1;
        out.push(FunctionSample {
            fixture: fixture.to_string(),
            name: symbol.name,
            compiler,
            opt,
            arch: SampleArch::X86_64,
            image_path: path.to_path_buf(),
            va: symbol.va,
            bytes: symbol.bytes,
            blocks,
            edges,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, counts)
}

/// Reduce a discovered `Function` to sorted blocks and index-form edges.
///
/// Block ORDER is not part of any identity in the literature (report 03:
/// "Nobody stores block order"), so edges are expressed over the start-VA
/// ordering and sorted. An edge to a block outside the function is a tail
/// call; it keeps a sentinel index rather than being dropped, so the block's
/// out-degree stays honest.
pub(crate) fn cfg_facts(func: &Function) -> (Vec<BlockFacts>, Vec<(usize, usize)>) {
    let mut blocks: Vec<BlockFacts> = func
        .basic_blocks
        .iter()
        .map(|b| BlockFacts {
            start_va: b.start_address.value,
            end_va: b.end_address.value,
            instruction_count: b.instruction_count,
        })
        .collect();
    blocks.sort_by_key(|b| b.start_va);
    blocks.dedup_by_key(|b| b.start_va);
    let index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    let mut edges: Vec<(usize, usize)> = func
        .edges
        .iter()
        .map(|(from, to)| {
            (
                index.get(&from.value).copied().unwrap_or(usize::MAX),
                index.get(&to.value).copied().unwrap_or(usize::MAX),
            )
        })
        .collect();
    edges.sort_unstable();
    edges.dedup();
    (blocks, edges)
}

/// PLT entries, thunks and CRT boilerplate.
///
/// Three independent signals, because no one of them is complete: the `@plt`
/// suffix catches the linker's own naming, `FunctionKind::Thunk` catches what
/// discovery classified, and the CRT list catches the objects gcc and clang
/// staple onto every shared object.
///
/// **On this corpus it removes nothing**, and that is not a bug: these are
/// single-translation-unit shared objects, so ELF `.symtab` carries no `@plt`
/// names (that spelling is objdump's and IDA's, not the linker's) and the CRT
/// symbols are emitted with `st_size == 0`, which
/// [`FilterCounts::skipped_unsized`] accounts for before this filter is
/// reached. The rule is still applied because the harness is meant to take a
/// linked multi-object binary later, where all three signals fire. It has a
/// direct unit test below so its zero count is never the only evidence about
/// whether it works.
pub(crate) fn is_plt_or_thunk(name: &str, func: Option<&Function>) -> bool {
    if name.contains("@plt") {
        return true;
    }
    if CRT_SYMBOLS.contains(&name) {
        return true;
    }
    if name.starts_with("__x86.get_pc_thunk") || name.starts_with("__tls_get_addr") {
        return true;
    }
    matches!(func.map(|f| f.kind), Some(FunctionKind::Thunk))
}

/// FNV-1a over the function's mnemonic sequence.
///
/// This is the "normalized instruction hash" half of the published dedupe key.
/// It is a linear sweep of the function's bytes through the architecture's
/// disassembler keeping only mnemonics: operands carry relocated addresses and
/// reallocated registers, which is exactly the variation the dedupe must see
/// through. A linear sweep can desync on data-in-code; when it does the
/// affected function simply fails to dedupe against its twin, which costs the
/// filter a little recall and cannot manufacture a false merge.
///
/// The decoder comes from [`FunctionSample::arch`], so the same rule applies
/// unchanged to the six architectures of the Cisco corpus. The fallback branch
/// (no backend for the architecture) hashes into a separate domain rather than
/// silently agreeing with a decoded stream.
pub(crate) fn normalized_instruction_hash(sample: &FunctionSample) -> u64 {
    use glaurung::core::address::{Address, AddressKind};

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mix = |hash: &mut u64, bytes: &[u8]| {
        for b in bytes {
            *hash ^= u64::from(*b);
            *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };

    let Some(backend) =
        glaurung::disasm::registry::for_arch(sample.arch.architecture, sample.arch.endianness)
    else {
        mix(&mut hash, b"raw-bytes:");
        mix(&mut hash, &sample.bytes);
        return hash;
    };

    let mut offset = 0usize;
    while offset < sample.bytes.len() {
        let Ok(addr) = Address::new(
            AddressKind::VA,
            sample.va.wrapping_add(offset as u64),
            sample.arch.bits,
            None,
            None,
        ) else {
            break;
        };
        match backend.disassemble_instruction(&addr, &sample.bytes[offset..]) {
            Ok(insn) => {
                mix(&mut hash, insn.mnemonic.as_bytes());
                mix(&mut hash, b"|");
                offset += usize::from(insn.length.max(1));
            }
            Err(_) => {
                mix(&mut hash, b"?|");
                offset += 1;
            }
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PLT/thunk/CRT rule, tested directly.
    ///
    /// On the fixture corpus this filter removes zero functions (see the doc
    /// comment on [`is_plt_or_thunk`]), so the corpus counts alone can never
    /// tell a working filter from one that returns `false` unconditionally.
    /// This is the test that can.
    #[test]
    fn plt_and_crt_names_are_recognised() {
        assert!(is_plt_or_thunk("memcpy@plt", None));
        assert!(is_plt_or_thunk("frame_dummy", None));
        assert!(is_plt_or_thunk("_init", None));
        assert!(is_plt_or_thunk("__x86.get_pc_thunk.bx", None));
        assert!(!is_plt_or_thunk("bisect", None));
        assert!(!is_plt_or_thunk("checksum", None));
        // A name that merely CONTAINS a CRT name is not one.
        assert!(!is_plt_or_thunk("my_init", None));
        assert!(!is_plt_or_thunk("_initialise", None));
    }

    /// `harness_budgets()` fixes the run-to-run digest instability traced in
    /// `docs/design/cfg-discovery-determinism-2026-09-02.md`: discover the
    /// same fixture bytes twice and the recovered `(entry, blocks, edges)`
    /// set must match exactly, with no function carrying
    /// `FunctionFlags::CFG_WALK_TIMEOUT` (the per-function wall clock that
    /// document identifies as the source of the jitter). Skips loudly, like
    /// every other corpus-backed test here, when the gitignored fixture
    /// build directory is absent.
    #[test]
    fn discovery_is_deterministic_with_harness_budgets() {
        let Some(root) = corpus_root() else {
            return;
        };
        let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&root)
            .expect("corpus_root() already checked this directory is readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "so"))
            .collect();
        fixtures.sort();
        let Some(path) = fixtures.first() else {
            eprintln!(
                "SKIP: identity corpus at {} has no .so fixtures",
                root.display()
            );
            return;
        };
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let budgets = harness_budgets();

        let discover = |data: &[u8]| -> (Vec<(u64, usize, usize)>, usize) {
            let (functions, _cg) = analyze_functions_bytes(data, &budgets);
            let mut timed_out = 0usize;
            let mut digest: Vec<(u64, usize, usize)> = functions
                .iter()
                .map(|f| {
                    if f.has_flag(FunctionFlags::CFG_WALK_TIMEOUT) {
                        timed_out += 1;
                    }
                    let (blocks, edges) = cfg_facts(f);
                    (f.entry_point.value, blocks.len(), edges.len())
                })
                .collect();
            digest.sort();
            (digest, timed_out)
        };

        let (run0, timeouts0) = discover(&data);
        let (run1, timeouts1) = discover(&data);
        assert_eq!(
            timeouts0,
            0,
            "{}: {timeouts0} function(s) hit CFG_WALK_TIMEOUT under harness_budgets() -- \
             the per-function wall clock must never fire",
            path.display()
        );
        assert_eq!(
            timeouts1,
            0,
            "{}: {timeouts1} function(s) hit CFG_WALK_TIMEOUT under harness_budgets() -- \
             the per-function wall clock must never fire",
            path.display()
        );
        assert_eq!(
            run0,
            run1,
            "{}: CFG discovery under harness_budgets() must be bit-reproducible run to \
             run; see docs/design/cfg-discovery-determinism-2026-09-02.md",
            path.display()
        );
    }
}
