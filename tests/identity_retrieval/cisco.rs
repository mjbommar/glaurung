//! Cisco Talos **Dataset-1** as a second corpus for the identity harness, and
//! the XA (cross-architecture) and XB (cross-bitness) lanes the in-house
//! fixture matrix cannot provide.
//!
//! # Why this corpus and not another
//!
//! `docs/history/program-measures-2026-09-02.md` (plan item 9, and section 3
//! of report 01) names two external corpora. This is the second of them, and
//! it is the one that makes our numbers land in a *published table*: it is the
//! artifact of Marcelli et al., "How Machine Learning Is Solving the Binary
//! Function Similarity Problem" (USENIX Security '22), so a row measured here
//! sits next to that paper's Tables 3 and 4 without re-derivation. It is MIT
//! licensed. BinKit 2.0, the other candidate, is hundreds of gigabytes and is
//! deliberately not ingested.
//!
//! Dataset-1 is 5,489 binaries from 7 projects, built for **six architecture /
//! bitness combinations** (x86, x86-64, ARM32, ARM64, MIPS32, MIPS64), by
//! **eight compilers** (gcc 4.8/5/7/9, clang 3.5/5.0/7/9) at **five
//! optimisation levels** (O0-O3, Os), with **inlining disabled**. The in-house
//! corpus varies two things; this one varies five, which is the whole point:
//! Marcelli's headline finding is that a representation good with one free
//! variable can be at chance with several, and no lane in this harness could
//! see that before.
//!
//! # Where it lives, and how to point at it
//!
//! **`GLAURUNG_CISCO_CORPUS`** -- a path to a directory holding
//!
//! ```text
//! Binaries/Dataset-1/<project>/<arch><bit>-<compiler>-<version>-<opt>_<library>
//! DBs/Dataset-1/testing_Dataset-1.csv
//! DBs/Dataset-1/pairs/testing/{pos,neg}_rank_testing_Dataset-1.csv   (optional)
//! ```
//!
//! which is the upstream layout. `docs/development/corpora.md` records exactly
//! what was fetched, from where, with sizes and SHA-256s, and how to fetch it
//! again. When the variable is unset or the layout is not there, every test in
//! this file **skips loudly** on stderr and asserts nothing: a vacuous pass
//! that says nothing is the failure mode to avoid.
//!
//! Like `GLAURUNG_IDENTITY_CORPUS`, this variable is read from `tests/` and
//! never from `src/`, so it is outside the allowlist
//! `python/tests/test_src_dependency_boundaries.py` enforces over the product
//! tree. It is documented here and in
//! `docs/development/identity-measurement.md` instead.
//!
//! # Ground truth
//!
//! The **selection CSV** (`testing_Dataset-1.csv`), not our own symbol walk.
//! It carries one row per selected function with `idb_path, fva, func_name,
//! start_ea, end_ea, bb_num, hashopcodes, project, library, arch, bit,
//! compiler, version, optimizations`, and it is the population Marcelli's
//! published numbers are computed over. Discovery is used only to obtain the
//! CFG at each listed VA -- the labels and the extents come from the CSV, so
//! our denominator is theirs.
//!
//! That choice has a measured cost worth stating up front: the CSV is a
//! ~10% **sample** of each binary's functions, drawn independently per binary.
//! So a slice holds a few hundred functions (good: the ranking pool needs
//! more than 100 candidates) while the *twin join* between two slices holds
//! only tens (bad: several rows land below
//! [`crate::metrics::MIN_SCORED_FOR_A_MEASUREMENT`] and are flagged
//! `[UNDERPOWERED]`). Marcelli hit the same wall and answered it with explicit
//! pair files; [`published_pairs`] reads those, and
//! [`PublishedPairPool::coverage`] says how much of one is reachable from the
//! binaries actually loaded.
//!
//! # MIPS
//!
//! Glaurung **disassembles** MIPS (`disasm::registry` routes MIPS/MIPS64 to
//! Capstone) and does **not lift** it (`src/ir/lift/` is x86, x86-64, ARM and
//! AArch64). So the MIPS lanes here are real for byte-shaped and CFG-shaped
//! schemes and must be a reported coverage hole for an IR-shaped one.
//! [`crate::corpus::SampleArch::is_liftable`] is the switch, and
//! [`CiscoCorpus::coverage_notes`] is where the hole gets written down.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use glaurung::analysis::cfg::analyze_functions_bytes_with_seeds;
use glaurung::core::function::Function;
use object::{Object, ObjectSection};

use crate::corpus::{
    cfg_facts, harness_budgets, is_plt_or_thunk, normalized_instruction_hash, FilterCounts,
    FunctionSample, SampleArch, Slice, MIN_BASIC_BLOCKS,
};

/// The environment variable that points at an unpacked Dataset-1.
pub const CORPUS_ENV: &str = "GLAURUNG_CISCO_CORPUS";

/// One compilation configuration: the five-dimensional key Dataset-1 varies.
///
/// Every field is `&'static str` or a `SampleArch` constant rather than an
/// owned string, because the set is closed and small (6 x 8 x 5 = 240) and
/// because a slice key that can be constructed from arbitrary text is a slice
/// key that can silently name a configuration the corpus does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Config {
    pub arch: SampleArch,
    /// `gcc` or `clang`.
    pub compiler: &'static str,
    /// The version as it appears in a **file name**: `9`, `4.8`, `3.5`, `5.0`.
    /// The CSV spells gcc versions differently; see [`Config::csv_version`].
    pub version: &'static str,
    /// `O0`, `O1`, `O2`, `O3` or `Os`.
    pub opt: &'static str,
}

impl Config {
    /// The file-name prefix, e.g. `x64-gcc-9-O2`.
    ///
    /// A binary is `<prefix>_<library>` inside `Binaries/Dataset-1/<project>/`.
    pub fn prefix(&self) -> String {
        format!(
            "{}-{}-{}-{}",
            self.arch.name, self.compiler, self.version, self.opt
        )
    }

    /// The `version` column as the CSV spells it.
    ///
    /// gcc rows read `gcc_9`, clang rows read `9`. Verified against
    /// `testing_Dataset-1.csv`: the file name says `x64-gcc-9-O2` and the row
    /// says `gcc,gcc_9`. Getting this wrong does not error -- it silently
    /// matches zero rows and produces an empty slice, which is why
    /// [`CiscoCorpus::load`] refuses to return a slice it could not fill.
    pub fn csv_version(&self) -> String {
        if self.compiler == "gcc" {
            format!("gcc_{}", self.version)
        } else {
            self.version.to_string()
        }
    }

    /// The `arch` column, which is the family without the width (`x`, `arm`,
    /// `mips`), paired with the `bit` column.
    pub fn csv_arch(&self) -> (&'static str, u8) {
        let family = match self.arch.family() {
            "x86" => "x",
            other => other,
        };
        (family, self.arch.bits)
    }

    pub fn label(&self) -> String {
        self.prefix()
    }
}

/// The nine configurations the default lane loads.
///
/// Chosen to make **one** compilation variable free per task wherever
/// possible, which is the discipline Marcelli's Table 3 columns follow, and to
/// keep the default test under ~90 seconds. gcc 9 / clang 9 are the newest
/// pair in the corpus, so a reader comparing against the published tables is
/// looking at the same end of the version axis.
pub const DEFAULT_CONFIGS: &[Config] = &[
    Config {
        arch: SampleArch::X86_64,
        compiler: "gcc",
        version: "9",
        opt: "O0",
    },
    Config {
        arch: SampleArch::X86_64,
        compiler: "gcc",
        version: "9",
        opt: "O2",
    },
    Config {
        arch: SampleArch::X86_64,
        compiler: "clang",
        version: "9",
        opt: "O0",
    },
    Config {
        arch: SampleArch::X86_64,
        compiler: "clang",
        version: "9",
        opt: "O2",
    },
    Config {
        arch: SampleArch::X86,
        compiler: "gcc",
        version: "9",
        opt: "O2",
    },
    Config {
        arch: SampleArch::ARM32,
        compiler: "gcc",
        version: "9",
        opt: "O2",
    },
    Config {
        arch: SampleArch::ARM64,
        compiler: "gcc",
        version: "9",
        opt: "O2",
    },
    Config {
        arch: SampleArch::MIPS32,
        compiler: "gcc",
        version: "9",
        opt: "O2",
    },
    Config {
        arch: SampleArch::MIPS64,
        compiler: "gcc",
        version: "9",
        opt: "O2",
    },
];

/// The libraries the default lane loads, from the **testing** split.
///
/// `testing_Dataset-1.csv` covers exactly two projects, `nmap` (libraries
/// `ncat`, `nmap`, `nping`) and `z3`. The z3 binaries are ~30 MB each and
/// would put one slice, never mind nine, far past the time budget; the three
/// nmap-project binaries are 765 KB, 3.8 MB and 905 KB and together give
/// slices of 238-369 functions, which is the >100 the ranking pool needs.
///
/// All three are loaded: two of them alone leave the MIPS32 slice below the
/// 101 candidates a ranking pool needs, and the twin joins between two
/// configurations below the threshold at which a row may be quoted.
pub const DEFAULT_LIBRARIES: &[&str] = &["ncat", "nmap", "nping"];

/// The split whose selection CSV and pair files this module reads.
///
/// `testing` deliberately, not `training`: Marcelli's published Tables 3 and 4
/// are computed on the testing split, and a number measured on a different
/// split is not comparable to them however similar it looks.
pub const SPLIT: &str = "testing";

// ---------------------------------------------------------------------------
// Locating the corpus
// ---------------------------------------------------------------------------

/// Where the corpus is, or `None` with the reason already printed.
pub fn corpus_root() -> Option<PathBuf> {
    let Some(root) = std::env::var_os(CORPUS_ENV).map(PathBuf::from) else {
        eprintln!(
            "SKIP: {CORPUS_ENV} is unset, so the Cisco Talos Dataset-1 lanes \
             (XA, XB, and the published-pool cross-check) did not run. The \
             corpus is ~12 GB of MIT-licensed binaries plus 356 MB of ground \
             truth; docs/development/corpora.md has the exact URLs, sizes and \
             SHA-256s and the command to fetch it."
        );
        return None;
    };
    let binaries = root.join("Binaries").join("Dataset-1");
    let selection = selection_csv_path(&root);
    if !binaries.is_dir() || !selection.is_file() {
        eprintln!(
            "SKIP: {CORPUS_ENV}={} does not hold an unpacked Dataset-1. \
             Expected a directory {} and a file {}. See \
             docs/development/corpora.md.",
            root.display(),
            binaries.display(),
            selection.display()
        );
        return None;
    }
    Some(root)
}

fn selection_csv_path(root: &Path) -> PathBuf {
    root.join("DBs")
        .join("Dataset-1")
        .join(format!("{SPLIT}_Dataset-1.csv"))
}

fn pair_csv_path(root: &Path, kind: &str) -> PathBuf {
    root.join("DBs")
        .join("Dataset-1")
        .join("pairs")
        .join(SPLIT)
        .join(format!("{kind}_rank_{SPLIT}_Dataset-1.csv"))
}

// ---------------------------------------------------------------------------
// The selection CSV
// ---------------------------------------------------------------------------

/// The columns of `testing_Dataset-1.csv`, in order.
///
/// Asserted against the file's header on every load. The upstream file has an
/// unnamed leading index column, which is why the first entry is empty.
const SELECTION_COLUMNS: [&str; 15] = [
    "",
    "idb_path",
    "fva",
    "func_name",
    "start_ea",
    "end_ea",
    "bb_num",
    "hashopcodes",
    "project",
    "library",
    "arch",
    "bit",
    "compiler",
    "version",
    "optimizations",
];

/// One row of the selection CSV, reduced to what the loader needs.
#[derive(Clone, Debug)]
struct SelectionRow {
    /// `IDBs/Dataset-1/<project>/<prefix>_<library>.i64`, upstream's own path
    /// into the IDA database tree. The binary is the same path with `IDBs`
    /// swapped for `Binaries` and the `.i64` suffix removed.
    idb_path: String,
    project: String,
    library: String,
    func_name: String,
    fva: u64,
    end_ea: u64,
    /// IDA's basic-block count for the function. Kept so the loader can be
    /// cross-checked against the published population rather than trusting our
    /// own discovery to agree with it.
    bb_num: u32,
}

impl SelectionRow {
    /// The binary this row's function lives in, under `<root>/Binaries/...`.
    fn image_path(&self, root: &Path) -> Option<PathBuf> {
        let rest = self.idb_path.strip_prefix("IDBs/")?;
        let rest = rest.strip_suffix(".i64")?;
        Some(root.join("Binaries").join(rest))
    }
}

/// `0x5c0ad8` -> `0x5c0ad8u64`. Upstream writes every address this way.
fn parse_hex(text: &str) -> Option<u64> {
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(body, 16).ok()
}

/// Stream the selection CSV, keeping the rows that match a wanted config.
///
/// Hand-parsed on `,` rather than through a CSV crate: the four files this
/// module reads were checked to contain **no quoting at all** and a fixed
/// field count (522,004 rows of `testing_Dataset-1.csv`, 0 with a wrong count,
/// 0 containing a double quote), and adding a dependency to the root manifest
/// for a test-only reader is a cost the whole crate pays. The header assertion
/// below is what keeps that shortcut honest: a file that ever grows a quoted
/// field will not silently mis-parse, because it will not have this header.
fn read_selection(
    path: &Path,
    wanted: &BTreeMap<(String, u8, String, String, String), Config>,
    libraries: &BTreeSet<&str>,
) -> Result<Vec<(Config, SelectionRow)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("{} is empty", path.display()))?;
    let header_fields: Vec<&str> = header.split(',').collect();
    if header_fields != SELECTION_COLUMNS {
        return Err(format!(
            "{} has header {:?}, expected {:?}. The hand-rolled parser in \
             this module assumes that exact shape and no quoting; upstream \
             changing the file must fail here rather than mis-parse.",
            path.display(),
            header_fields,
            SELECTION_COLUMNS
        ));
    }

    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != SELECTION_COLUMNS.len() {
            return Err(format!(
                "{}: row with {} fields, expected {}: {line}",
                path.display(),
                f.len(),
                SELECTION_COLUMNS.len()
            ));
        }
        let library = f[9];
        if !libraries.contains(library) {
            continue;
        }
        let Ok(bit) = f[11].parse::<u8>() else {
            continue;
        };
        let key = (
            f[10].to_string(),
            bit,
            f[12].to_string(),
            f[13].to_string(),
            f[14].to_string(),
        );
        let Some(config) = wanted.get(&key) else {
            continue;
        };
        let (Some(fva), Some(end_ea), Ok(bb_num)) =
            (parse_hex(f[2]), parse_hex(f[5]), f[6].parse::<u32>())
        else {
            continue;
        };
        out.push((
            *config,
            SelectionRow {
                idb_path: f[1].to_string(),
                project: f[8].to_string(),
                library: library.to_string(),
                func_name: f[3].to_string(),
                fva,
                end_ea,
                bb_num,
            },
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// Dataset-1, loaded for one set of configurations and libraries.
#[derive(Debug)]
pub struct CiscoCorpus {
    pub root: PathBuf,
    slices: BTreeMap<Config, Slice>,
    pub filters: FilterCounts,
    /// Per configuration: how many KEPT functions our CFG discovery gives
    /// fewer than [`MIN_BASIC_BLOCKS`] blocks for, although IDA's flowchart --
    /// which is what put the function in the published population at all --
    /// reported five or more.
    ///
    /// This is not a filter and it does not move a denominator. It is a
    /// measurement of Glaurung against IDA on the same functions, and it is
    /// the single most interesting thing the first run of this lane produced:
    /// it is near zero on x86-64 and very high on MIPS32.
    pub cfg_disagreements: BTreeMap<Config, usize>,
    pub load_seconds: f64,
    /// Selection rows that matched a wanted `(config, library)` before any
    /// filter ran. The published population this corpus is a view of.
    pub selection_rows: usize,
    /// Binaries opened.
    pub images: usize,
}

impl CiscoCorpus {
    pub fn slice(&self, config: &Config) -> Option<&Slice> {
        self.slices.get(config)
    }

    pub fn slices(&self) -> impl Iterator<Item = (&Config, &Slice)> {
        self.slices.iter()
    }

    /// What this corpus can and cannot say about a scheme, in words.
    ///
    /// Written into the JSON report. The MIPS note is the load-bearing one:
    /// two of the nine slices are an architecture Glaurung disassembles but
    /// does not lift, so an IR-shaped scheme scoring zero there is a coverage
    /// hole and not a result, and nothing else in the report distinguishes the
    /// two.
    pub fn coverage_notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        let unliftable: Vec<String> = self
            .slices
            .keys()
            .filter(|c| !c.arch.is_liftable())
            .map(|c| c.label())
            .collect();
        if !unliftable.is_empty() {
            notes.push(format!(
                "IR-shaped schemes cannot cover {} of {} slices ({}): \
                 src/ir/lift/ implements x86, x86-64, ARM and AArch64, and \
                 disasm::registry reaches MIPS only through Capstone. A byte- \
                 or CFG-shaped scheme covers all of them. An IR scheme must \
                 FAIL extraction on these slices so the failure count says so.",
                unliftable.len(),
                self.slices.len(),
                unliftable.join(", ")
            ));
        }
        notes.push(format!(
            "Ground truth is Marcelli's {SPLIT} selection CSV, which samples \
             roughly a tenth of each binary's functions independently per \
             binary. Pools are therefore large enough to rank in (>100) while \
             cross-configuration twin joins are small; rows below the \
             measurement threshold are flagged UNDERPOWERED and must not be \
             quoted."
        ));
        let worst = self
            .cfg_disagreements
            .iter()
            .filter_map(|(c, n)| {
                let kept = self.slices.get(c)?.samples.len();
                Some((c.label(), *n, kept))
            })
            .max_by_key(|(_, n, kept)| (*n * 1000) / (*kept).max(1));
        if let Some((label, n, kept)) = worst {
            notes.push(format!(
                "Every function here passed IDA's >=5-basic-block filter \
                 upstream, so the <5-block filter is applied on the PUBLISHED \
                 count and removes nothing. Where our discovery disagrees it \
                 is recorded instead: worst slice {label}, {n} of {kept} \
                 functions ({:.0}%) recover fewer than 5 blocks under \
                 glaurung::analysis::cfg. That is a statement about our CFG \
                 recovery on that architecture, not about the corpus.",
                100.0 * n as f64 / kept.max(1) as f64
            ));
        }
        notes
    }

    fn load(root: PathBuf, configs: &[Config], libraries: &[&str]) -> Option<CiscoCorpus> {
        use rayon::prelude::*;

        let started = std::time::Instant::now();
        let wanted: BTreeMap<(String, u8, String, String, String), Config> = configs
            .iter()
            .map(|c| {
                let (family, bits) = c.csv_arch();
                (
                    (
                        family.to_string(),
                        bits,
                        c.compiler.to_string(),
                        c.csv_version(),
                        c.opt.to_string(),
                    ),
                    *c,
                )
            })
            .collect();
        let library_set: BTreeSet<&str> = libraries.iter().copied().collect();

        let rows = match read_selection(&selection_csv_path(&root), &wanted, &library_set) {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("SKIP: could not read the Dataset-1 selection CSV: {e}");
                return None;
            }
        };
        if rows.is_empty() {
            eprintln!(
                "SKIP: the Dataset-1 selection CSV matched none of the {} \
                 requested configurations across libraries {:?}. Either the \
                 split is wrong (this module reads `{SPLIT}`) or a Config \
                 names a version spelling the CSV does not use.",
                configs.len(),
                libraries
            );
            return None;
        }
        let selection_rows = rows.len();

        // Group by (config, image). One CFG discovery per image, seeded with
        // that image's listed VAs: discovery is the expensive step and it
        // amortises over every function in the binary.
        let mut by_image: BTreeMap<(Config, PathBuf), Vec<SelectionRow>> = BTreeMap::new();
        let mut missing_images: BTreeSet<String> = BTreeSet::new();
        for (config, row) in rows {
            match row.image_path(&root) {
                Some(path) if path.is_file() => {
                    by_image.entry((config, path)).or_default().push(row);
                }
                _ => {
                    missing_images.insert(row.idb_path.clone());
                }
            }
        }
        if !missing_images.is_empty() {
            eprintln!(
                "cisco: {} selection rows name a binary that is not on disk \
                 (first: {}); those rows are dropped and never counted as a \
                 miss.",
                missing_images.len(),
                missing_images.iter().next().unwrap()
            );
        }
        let images = by_image.len();

        let work: Vec<((Config, PathBuf), Vec<SelectionRow>)> = by_image.into_iter().collect();
        let loaded: Vec<(Config, Vec<FunctionSample>, FilterCounts, usize)> = work
            .par_iter()
            .map(|((config, path), rows)| {
                let (samples, counts, disagreements) = load_image(*config, path, rows);
                (*config, samples, counts, disagreements)
            })
            .collect();

        let mut per_config: BTreeMap<Config, (Vec<FunctionSample>, FilterCounts, usize)> =
            BTreeMap::new();
        for (config, samples, counts, disagreements) in loaded {
            let entry = per_config.entry(config).or_default();
            entry.0.extend(samples);
            entry.1.add(&counts);
            entry.2 += disagreements;
        }

        let mut totals = FilterCounts::default();
        let mut slices = BTreeMap::new();
        let mut cfg_disagreements = BTreeMap::new();
        for (config, (samples, mut counts, disagreements)) in per_config {
            cfg_disagreements.insert(config, disagreements);
            // Dedupe by (name, normalized instruction hash) within the slice,
            // the published rule. Runs serially over an order the parallel
            // stage preserved, so the survivor of a duplicate pair is the same
            // one on every machine.
            let mut samples = samples;
            samples.sort_by(|a, b| (&a.fixture, &a.name, a.va).cmp(&(&b.fixture, &b.name, b.va)));
            let mut seen: BTreeSet<(String, u64)> = BTreeSet::new();
            let mut kept = Vec::with_capacity(samples.len());
            for sample in samples {
                let key = (sample.name.clone(), normalized_instruction_hash(&sample));
                if !seen.insert(key) {
                    counts.dropped_duplicate += 1;
                    counts.kept -= 1;
                    continue;
                }
                kept.push(sample);
            }
            totals.add(&counts);
            slices.insert(
                config,
                Slice {
                    compiler: config.compiler,
                    opt: config.opt,
                    arch: config.arch,
                    version: config.version,
                    samples: kept,
                    filters: counts,
                },
            );
        }

        let corpus = CiscoCorpus {
            root,
            slices,
            filters: totals,
            cfg_disagreements,
            load_seconds: started.elapsed().as_secs_f64(),
            selection_rows,
            images,
        };
        eprintln!(
            "cisco corpus: {} selection rows over {} images -> {} in {:.1}s from {}",
            corpus.selection_rows,
            corpus.images,
            corpus.filters.summary(),
            corpus.load_seconds,
            corpus.root.display()
        );
        for (config, slice) in corpus.slices() {
            let disagreements = corpus.cfg_disagreements.get(config).copied().unwrap_or(0);
            eprintln!(
                "  {}: {} functions, {} ({:.0}%) recover <{MIN_BASIC_BLOCKS} blocks under our \
                 discovery though IDA reported >={MIN_BASIC_BLOCKS}{}",
                config.label(),
                slice.samples.len(),
                disagreements,
                100.0 * disagreements as f64 / slice.samples.len().max(1) as f64,
                if config.arch.is_liftable() {
                    ""
                } else {
                    "  [disassembled, not liftable]"
                }
            );
        }
        Some(corpus)
    }
}

/// Read one image: its listed functions, their CFGs, and every filter but the
/// slice-wide dedupe.
fn load_image(
    config: Config,
    path: &Path,
    rows: &[SelectionRow],
) -> (Vec<FunctionSample>, FilterCounts, usize) {
    let mut counts = FilterCounts {
        considered: rows.len(),
        ..FilterCounts::default()
    };
    // Kept functions where our discovery recovers fewer than
    // `MIN_BASIC_BLOCKS` blocks although IDA reported five or more.
    let mut disagreements = 0usize;

    let Ok(data) = std::fs::read(path) else {
        counts.dropped_no_cfg += rows.len();
        return (Vec::new(), counts, 0);
    };
    let Ok(obj) = object::File::parse(&*data) else {
        counts.dropped_no_cfg += rows.len();
        return (Vec::new(), counts, 0);
    };

    let seeds: Vec<u64> = rows.iter().map(|r| r.fva).collect();
    let (functions, _cg) = analyze_functions_bytes_with_seeds(&data, &harness_budgets(), &seeds);
    let by_va: BTreeMap<u64, &Function> =
        functions.iter().map(|f| (f.entry_point.value, f)).collect();

    let mut out = Vec::new();
    for row in rows {
        // `.text` filter, by the section the VA lands in rather than by a
        // symbol's section index: this loader never looks at the symbol table.
        let Some(section) = section_containing(&obj, row.fva) else {
            counts.dropped_non_text += 1;
            continue;
        };
        if section != ".text" {
            counts.dropped_non_text += 1;
            continue;
        }
        if is_plt_or_thunk(&row.func_name, by_va.get(&row.fva).copied()) {
            counts.dropped_plt_or_thunk += 1;
            continue;
        }
        // The <5-block filter runs on the PUBLISHED block count, not on ours.
        //
        // Upstream already applied it: `features/flowchart_Dataset-1.csv` is
        // defined as "functions with at least five basic blocks" and the
        // selection CSV is drawn from it, so every row here should pass. Doing
        // it this way keeps the population exactly Marcelli's, which is the
        // whole reason to ingest his corpus -- and it moves our own
        // disagreement with IDA out of the denominator, where it would have
        // silently shrunk a pool, and into `cfg_disagreements`, where it is a
        // reported number about Glaurung's CFG recovery. Measured: 78% of the
        // mips32 rows recover fewer than five blocks under our discovery while
        // IDA reports five or more, which is a finding, not a filter.
        if (row.bb_num as usize) < MIN_BASIC_BLOCKS {
            counts.dropped_small += 1;
            continue;
        }
        let Some(func) = by_va.get(&row.fva) else {
            counts.dropped_no_cfg += 1;
            continue;
        };
        let (blocks, edges) = cfg_facts(func);
        if blocks.len() < MIN_BASIC_BLOCKS {
            disagreements += 1;
        }
        let Some(bytes) = function_bytes(&obj, row.fva, row.end_ea) else {
            counts.dropped_no_cfg += 1;
            continue;
        };
        counts.kept += 1;
        out.push(FunctionSample {
            // The ground-truth key is (library, function name): the same
            // function name in two different binaries of one project -- `main`
            // in `ncat` and in `nping` -- is two different functions, and
            // `library` is the column upstream uses to keep them apart.
            fixture: row.library.clone(),
            name: row.func_name.clone(),
            compiler: config.compiler,
            opt: config.opt,
            arch: config.arch,
            image_path: path.to_path_buf(),
            va: row.fva,
            bytes,
            blocks,
            edges,
        });
    }
    (out, counts, disagreements)
}

/// The name of the section containing `va`, if any.
fn section_containing(obj: &object::File<'_>, va: u64) -> Option<String> {
    for section in obj.sections() {
        let start = section.address();
        let size = section.size();
        if size > 0 && va >= start && va < start.saturating_add(size) {
            return section.name().ok().map(|n| n.to_string());
        }
    }
    None
}

/// The bytes of `[fva, end_ea)`, read out of whichever section holds them.
///
/// `end_ea` is upstream's own end, taken from IDA's flowchart, so the extent is
/// theirs and not ours -- the same reason the labels are.
fn function_bytes(obj: &object::File<'_>, fva: u64, end_ea: u64) -> Option<Vec<u8>> {
    if end_ea <= fva {
        return None;
    }
    let size = end_ea - fva;
    for section in obj.sections() {
        if let Ok(Some(bytes)) = section.data_range(fva, size) {
            return Some(bytes.to_vec());
        }
    }
    None
}

/// Load the default lane's corpus once per test binary.
pub fn corpus() -> Option<&'static CiscoCorpus> {
    static CORPUS: OnceLock<Option<CiscoCorpus>> = OnceLock::new();
    CORPUS
        .get_or_init(|| {
            let root = corpus_root()?;
            CiscoCorpus::load(root, DEFAULT_CONFIGS, DEFAULT_LIBRARIES)
        })
        .as_ref()
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// One Dataset-1 retrieval task: a query configuration, a pool configuration,
/// and the compilation variables free between them.
#[derive(Clone, Copy, Debug)]
pub struct CiscoTask {
    /// Marcelli's task name, suffixed where this configuration set splits one
    /// of his tasks across several architectures.
    pub name: &'static str,
    pub query: Config,
    pub pool: Config,
    /// Printed with every number. A number without it is not comparable to
    /// anything, including our own next run.
    pub free_variables: &'static str,
}

impl CiscoTask {
    pub fn conditions(&self) -> String {
        format!(
            "{} -> {} (free: {})",
            self.query.label(),
            self.pool.label(),
            self.free_variables
        )
    }

    /// The variables that actually differ between the two configurations.
    ///
    /// Computed from the configs rather than read off `free_variables`, so the
    /// declared free-variable string can be checked against reality instead of
    /// being trusted. `tests` below asserts they agree for every task: a task
    /// whose label says "architecture" while its two configs also differ in
    /// optimisation is a mislabelled measurement, and mislabelled measurements
    /// are precisely what the protocol document warns about.
    pub fn actual_free_variables(&self) -> Vec<&'static str> {
        let mut free = Vec::new();
        if self.query.arch.family() != self.pool.arch.family() {
            free.push("architecture");
        }
        if self.query.arch.bits != self.pool.arch.bits {
            free.push("bitness");
        }
        if self.query.compiler != self.pool.compiler {
            free.push("compiler");
        }
        if self.query.version != self.pool.version {
            free.push("version");
        }
        if self.query.opt != self.pool.opt {
            free.push("optimisation");
        }
        free
    }
}

const X64_GCC9_O0: Config = DEFAULT_CONFIGS[0];
const X64_GCC9_O2: Config = DEFAULT_CONFIGS[1];
const X64_CLANG9_O0: Config = DEFAULT_CONFIGS[2];
const X64_CLANG9_O2: Config = DEFAULT_CONFIGS[3];
const X86_GCC9_O2: Config = DEFAULT_CONFIGS[4];
const ARM32_GCC9_O2: Config = DEFAULT_CONFIGS[5];
const ARM64_GCC9_O2: Config = DEFAULT_CONFIGS[6];
const MIPS32_GCC9_O2: Config = DEFAULT_CONFIGS[7];
const MIPS64_GCC9_O2: Config = DEFAULT_CONFIGS[8];

/// Every task the default configuration set expresses.
///
/// The first three are the ones the in-house corpus already runs, repeated
/// here so a reader can see what changing corpus alone does to a number. The
/// rest are the lanes that did not exist before this file: **XB**, which Shi
/// et al. name as the task separating IR representations from token
/// representations, and four **XA** lanes, one per foreign architecture, kept
/// separate rather than pooled because "cross-architecture" averaged over ARM
/// and MIPS hides which of the two a scheme fails on.
pub const TASKS: &[CiscoTask] = &[
    CiscoTask {
        name: "XO",
        query: X64_GCC9_O0,
        pool: X64_GCC9_O2,
        free_variables: "optimisation",
    },
    // XC is measured at O0 rather than at O2 because the twin join is more
    // than twice as large there (71 shared labels against 23), and a row with
    // 23 scored queries is below the threshold at which it may be quoted. The
    // free variable is the same either way.
    CiscoTask {
        name: "XC",
        query: X64_GCC9_O0,
        pool: X64_CLANG9_O0,
        free_variables: "compiler",
    },
    CiscoTask {
        name: "XM",
        query: X64_GCC9_O0,
        pool: X64_CLANG9_O2,
        free_variables: "compiler + optimisation",
    },
    CiscoTask {
        name: "XB",
        query: X64_GCC9_O2,
        pool: X86_GCC9_O2,
        free_variables: "bitness",
    },
    CiscoTask {
        name: "XA-arm64",
        query: X64_GCC9_O2,
        pool: ARM64_GCC9_O2,
        free_variables: "architecture",
    },
    CiscoTask {
        name: "XA-mips64",
        query: X64_GCC9_O2,
        pool: MIPS64_GCC9_O2,
        free_variables: "architecture",
    },
    CiscoTask {
        name: "XA+XB-arm32",
        query: X64_GCC9_O2,
        pool: ARM32_GCC9_O2,
        free_variables: "architecture + bitness",
    },
    CiscoTask {
        name: "XA+XB-mips32",
        query: X64_GCC9_O2,
        pool: MIPS32_GCC9_O2,
        free_variables: "architecture + bitness",
    },
    CiscoTask {
        name: "XA+XO",
        query: X64_GCC9_O0,
        pool: ARM64_GCC9_O2,
        free_variables: "architecture + optimisation",
    },
];

/// Score one scheme over every task the corpus can run.
///
/// Reuses [`crate::metrics::evaluate_slices`] verbatim, so this corpus's
/// numbers come out of the same twin join, the same seeded 100-negative draw
/// and the same pessimistic tie rule as the in-house corpus's. That sameness
/// is the entire point: two harnesses that reimplement the protocol are two
/// harnesses that will disagree about a denominator.
pub fn evaluate<S: crate::scheme::Scheme>(
    scheme: &S,
    corpus: &CiscoCorpus,
    tasks: &[CiscoTask],
) -> crate::metrics::SchemeReport {
    let (extraction_us, extraction_samples) = measure_extraction_cost(scheme, corpus);
    let mut results = Vec::new();
    for task in tasks {
        let (Some(queries), Some(pool)) = (corpus.slice(&task.query), corpus.slice(&task.pool))
        else {
            continue;
        };
        results.push(crate::metrics::evaluate_slices(
            scheme,
            task.name,
            &task.conditions(),
            None,
            queries,
            pool,
        ));
    }
    crate::metrics::SchemeReport {
        scheme: format!("cisco-{}", scheme.name()),
        description: scheme.description().to_string(),
        results,
        extraction_us_per_function: extraction_us,
        extraction_samples,
        corpus_root: corpus.root.clone(),
        corpus_load_seconds: corpus.load_seconds,
        corpus_filters: corpus.filters,
        slice_sizes: corpus
            .slices()
            .map(|(c, s)| (c.label(), c.opt.to_string(), s.samples.len()))
            .collect(),
        corpus_name: format!(
            "Cisco Talos binary_function_similarity Dataset-1 ({SPLIT} split, \
             {} configurations, libraries {:?})",
            corpus.slices.len(),
            DEFAULT_LIBRARIES
        ),
        unsupported_tasks: UNSUPPORTED_TASKS
            .iter()
            .map(|(n, w)| (n.to_string(), w.to_string()))
            .collect(),
        coverage_notes: corpus.coverage_notes(),
        profile: crate::metrics::build_profile(),
    }
}

fn measure_extraction_cost<S: crate::scheme::Scheme>(
    scheme: &S,
    corpus: &CiscoCorpus,
) -> (f64, usize) {
    let mut total = std::time::Duration::ZERO;
    let mut count = 0usize;
    for (_, slice) in corpus.slices() {
        for sample in &slice.samples {
            let started = std::time::Instant::now();
            let sig = scheme.extract(sample);
            total += started.elapsed();
            count += 1;
            std::hint::black_box(&sig);
        }
    }
    if count == 0 {
        return (0.0, 0);
    }
    (total.as_secs_f64() * 1e6 / count as f64, count)
}

/// What Dataset-1 still cannot express, or what this lane does not attempt.
pub const UNSUPPORTED_TASKS: &[(&str, &str)] = &[
    (
        "XM-S / XM-M / XM-L",
        "the XM size strata. Runnable here -- crate::tasks::Stratum applies \
         to any slice -- but not run by default: the selection CSV samples ~10% \
         of each binary, so an XM row already holds tens of queries and \
         splitting it three ways would produce three rows that are all \
         UNDERPOWERED.",
    ),
    (
        "NoInline",
        "Dataset-1 is built with inlining DISABLED throughout, so it cannot \
         contrast inlined against non-inlined. That is Marcelli's own \
         simplification and it sidesteps the field's dominant failure mode \
         (81-84% of failures in the best tools involve differential inlining). \
         BinKit 2.0's NoInline sub-dataset is the lane for it; BinKit is \
         hundreds of GB and is deliberately not ingested.",
    ),
    (
        "Obfuscation",
        "Obfuscator-LLVM SUB/BCF/FLA lanes exist only in BinKit.",
    ),
    (
        "pool 10k / 100k",
        "Shi et al. report that growing the pool from 10k to 100k costs \
         2.1-15.1 MRR points. Reaching those pool sizes here means loading z3 \
         (229 binaries at ~30 MB), which is what the published-pair lane needs \
         too. Not in the default lane's time budget.",
    ),
];

// ---------------------------------------------------------------------------
// Marcelli's published ranking pools
// ---------------------------------------------------------------------------

/// One query from a published ranking pool: its positive twin and its 100
/// published negatives.
#[derive(Clone, Debug)]
pub struct PublishedQuery {
    /// `XA`, `XC`, `XC+XB` or `XM`, upstream's own spelling.
    pub task: String,
    pub query_idb: String,
    pub query_fva: u64,
    pub query_name: String,
    pub positive_idb: String,
    pub positive_fva: u64,
    /// `(idb_path, fva)` for each published negative.
    pub negatives: Vec<(String, u64)>,
}

/// The published ranking pools, read from
/// `pairs/testing/{pos,neg}_rank_testing_Dataset-1.csv`.
///
/// # Why this exists even though the default lane does not use it
///
/// A number is comparable to Marcelli's Table 4 only if it is measured over
/// *his* pools. Ours are drawn by [`crate::metrics::sample_negatives`] from
/// the same population under the same 100-per-positive rule, which is the same
/// discipline but not the same draw. This type is the bridge, and
/// [`PublishedPairPool::coverage`] is the honest part of it: it reports what
/// fraction of a published pool the loaded binaries can actually resolve, so a
/// partial run reports itself as partial instead of quietly scoring 3% of a
/// task and printing a number that looks like Table 4.
///
/// Measured on the fetched corpus: the four published pools hold 200 queries
/// each with exactly 100 negatives per query, and they draw on **921 distinct
/// binaries**, 229 of them z3 at ~30 MB. That is why the lane that consumes
/// this is `#[ignore]`d and the default lane only checks the pools' shape.
#[derive(Debug, Default)]
pub struct PublishedPairPool {
    pub queries: Vec<PublishedQuery>,
}

/// The columns of a pair CSV, in order.
const PAIR_COLUMNS: [&str; 8] = [
    "",
    "idb_path_1",
    "fva_1",
    "func_name_1",
    "idb_path_2",
    "fva_2",
    "func_name_2",
    "db_type",
];

impl PublishedPairPool {
    /// Read both halves of the published ranking pool.
    pub fn load(root: &Path) -> Result<PublishedPairPool, String> {
        let pos = read_pair_csv(&pair_csv_path(root, "pos"))?;
        let neg = read_pair_csv(&pair_csv_path(root, "neg"))?;

        // Upstream keys a query by (task, idb_path_1, fva_1): the same
        // function can be a query in more than one task, and its negatives
        // differ per task, so the task has to be part of the key.
        let mut by_query: BTreeMap<(String, String, u64), Vec<(String, u64)>> = BTreeMap::new();
        for row in &neg {
            by_query
                .entry((row.db_type.clone(), row.idb1.clone(), row.fva1))
                .or_default()
                .push((row.idb2.clone(), row.fva2));
        }

        let mut queries = Vec::with_capacity(pos.len());
        for row in pos {
            let key = (row.db_type.clone(), row.idb1.clone(), row.fva1);
            let negatives = by_query.remove(&key).unwrap_or_default();
            queries.push(PublishedQuery {
                task: row.db_type,
                query_idb: row.idb1,
                query_fva: row.fva1,
                query_name: row.name1,
                positive_idb: row.idb2,
                positive_fva: row.fva2,
                negatives,
            });
        }
        Ok(PublishedPairPool { queries })
    }

    /// Task names present, with how many queries each holds.
    pub fn task_sizes(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for q in &self.queries {
            *out.entry(q.task.clone()).or_insert(0) += 1;
        }
        out
    }

    /// How many of this pool's queries are fully resolvable from a set of
    /// loaded `idb_path`s -- query, positive and all 100 negatives present.
    ///
    /// A partially resolvable query is NOT usable: dropping some of its
    /// negatives shrinks its ranking pool and inflates its rank, which is the
    /// silent-inflation failure Marcelli names.
    pub fn coverage(&self, loaded_idbs: &BTreeSet<String>) -> (usize, usize) {
        let mut full = 0usize;
        for q in &self.queries {
            let ok = loaded_idbs.contains(&q.query_idb)
                && loaded_idbs.contains(&q.positive_idb)
                && q.negatives.iter().all(|(idb, _)| loaded_idbs.contains(idb));
            if ok {
                full += 1;
            }
        }
        (full, self.queries.len())
    }

    /// Every distinct `idb_path` the pool refers to.
    pub fn referenced_idbs(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for q in &self.queries {
            out.insert(q.query_idb.clone());
            out.insert(q.positive_idb.clone());
            for (idb, _) in &q.negatives {
                out.insert(idb.clone());
            }
        }
        out
    }
}

struct PairRow {
    idb1: String,
    fva1: u64,
    name1: String,
    idb2: String,
    fva2: u64,
    db_type: String,
}

fn read_pair_csv(path: &Path) -> Result<Vec<PairRow>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = text.lines();
    let header: Vec<&str> = lines
        .next()
        .ok_or_else(|| format!("{} is empty", path.display()))?
        .split(',')
        .collect();
    if header != PAIR_COLUMNS {
        return Err(format!(
            "{} has header {:?}, expected {:?}",
            path.display(),
            header,
            PAIR_COLUMNS
        ));
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != PAIR_COLUMNS.len() {
            return Err(format!(
                "{}: row with {} fields, expected {}",
                path.display(),
                f.len(),
                PAIR_COLUMNS.len()
            ));
        }
        let (Some(fva1), Some(fva2)) = (parse_hex(f[2]), parse_hex(f[5])) else {
            return Err(format!("{}: unparseable address in {line}", path.display()));
        };
        out.push(PairRow {
            idb1: f[1].to_string(),
            fva1,
            name1: f[3].to_string(),
            idb2: f[4].to_string(),
            fva2,
            db_type: f[7].to_string(),
        });
    }
    Ok(out)
}

/// The published pools, loaded once, or `None` with a printed reason.
pub fn published_pairs() -> Option<&'static PublishedPairPool> {
    static POOL: OnceLock<Option<PublishedPairPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let root = corpus_root()?;
        match PublishedPairPool::load(&root) {
            Ok(pool) => Some(pool),
            Err(e) => {
                eprintln!(
                    "SKIP: the published ranking pools are not present: {e}. \
                     They ship in DBs/Dataset-1/features.zip, not in the git \
                     repository; docs/development/corpora.md says how to get \
                     them."
                );
                None
            }
        }
    })
    .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config -> CSV spelling map, which has no other test and silently
    /// produces an empty slice when it is wrong.
    #[test]
    fn csv_spellings_match_the_upstream_columns() {
        assert_eq!(X64_GCC9_O2.csv_version(), "gcc_9");
        assert_eq!(X64_CLANG9_O2.csv_version(), "9");
        assert_eq!(X64_GCC9_O2.csv_arch(), ("x", 64));
        assert_eq!(X86_GCC9_O2.csv_arch(), ("x", 32));
        assert_eq!(ARM32_GCC9_O2.csv_arch(), ("arm", 32));
        assert_eq!(MIPS64_GCC9_O2.csv_arch(), ("mips", 64));
        assert_eq!(X64_GCC9_O2.prefix(), "x64-gcc-9-O2");
        assert_eq!(MIPS32_GCC9_O2.prefix(), "mips32-gcc-9-O2");
    }

    #[test]
    fn addresses_parse_the_way_upstream_writes_them() {
        assert_eq!(parse_hex("0x5c0ad8"), Some(0x5c_0ad8));
        assert_eq!(parse_hex("0x0"), Some(0));
        assert_eq!(
            parse_hex("5c0ad8"),
            None,
            "a bare hex string is not upstream's form"
        );
        assert_eq!(parse_hex("0xzz"), None);
    }

    /// An IDB path becomes a binary path, and nothing else does.
    #[test]
    fn idb_paths_map_onto_binary_paths() {
        let row = SelectionRow {
            idb_path: "IDBs/Dataset-1/nmap/x64-gcc-9-O2_ncat.i64".to_string(),
            project: "nmap".to_string(),
            library: "ncat".to_string(),
            func_name: "main".to_string(),
            fva: 0x1000,
            end_ea: 0x1100,
            bb_num: 7,
        };
        assert_eq!(
            row.image_path(Path::new("/corpus")).unwrap(),
            Path::new("/corpus/Binaries/Dataset-1/nmap/x64-gcc-9-O2_ncat")
        );
        let wrong = SelectionRow {
            idb_path: "Binaries/Dataset-1/nmap/x64-gcc-9-O2_ncat".to_string(),
            ..row
        };
        assert!(
            wrong.image_path(Path::new("/corpus")).is_none(),
            "a path that is not an IDB path must not be silently accepted"
        );
    }

    /// Every task's declared free-variable string must match the difference
    /// its two configurations actually have.
    ///
    /// This is the assertion that stops a mislabelled row, which is the exact
    /// failure the protocol document warns about ("the same tool, SAFE, scores
    /// MRR 0.918 and 0.17 in two published papers on different protocols").
    #[test]
    fn declared_free_variables_match_the_configurations() {
        for task in TASKS {
            let actual = task.actual_free_variables();
            assert!(
                !actual.is_empty(),
                "{} varies nothing: query and pool are the same configuration",
                task.name
            );
            let declared: Vec<&str> = task.free_variables.split(" + ").collect();
            assert_eq!(
                actual, declared,
                "{} declares free variables {:?} but its configurations differ \
                 in {:?}",
                task.name, declared, actual
            );
        }
    }

    /// Every task must name a configuration the default lane loads, or it can
    /// never run and its absence looks like a skip.
    #[test]
    fn every_task_uses_a_loaded_configuration() {
        for task in TASKS {
            assert!(
                DEFAULT_CONFIGS.contains(&task.query),
                "{} queries {} which DEFAULT_CONFIGS does not load",
                task.name,
                task.query.label()
            );
            assert!(
                DEFAULT_CONFIGS.contains(&task.pool),
                "{} pools {} which DEFAULT_CONFIGS does not load",
                task.name,
                task.pool.label()
            );
        }
    }

    /// The XA and XB lanes exist, which is the whole reason this corpus was
    /// ingested. `crate::tasks::UNSUPPORTED_TASKS` says the in-house corpus
    /// cannot express them; if they ever vanish from here, that statement
    /// becomes true again with nothing saying so.
    #[test]
    fn the_cross_architecture_and_cross_bitness_lanes_exist() {
        let names: Vec<&str> = TASKS.iter().map(|t| t.name).collect();
        assert!(names.contains(&"XB"), "no cross-bitness lane: {names:?}");
        assert!(
            names.iter().any(|n| n.starts_with("XA")),
            "no cross-architecture lane: {names:?}"
        );
        let architectures: BTreeSet<&str> = TASKS
            .iter()
            .map(|t| t.pool.arch.family())
            .chain(TASKS.iter().map(|t| t.query.arch.family()))
            .collect();
        assert_eq!(
            architectures,
            BTreeSet::from(["x86", "arm", "mips"]),
            "the task set must reach all three instruction-set families the \
             corpus ships; it reaches {architectures:?}"
        );
    }

    /// MIPS is disassembled and not lifted, and the corpus must say so rather
    /// than let an IR scheme's zero read as a measurement.
    #[test]
    fn mips_is_marked_unliftable_and_the_others_are_not() {
        assert!(!SampleArch::MIPS32.is_liftable());
        assert!(!SampleArch::MIPS64.is_liftable());
        for arch in [
            SampleArch::X86,
            SampleArch::X86_64,
            SampleArch::ARM32,
            SampleArch::ARM64,
        ] {
            assert!(arch.is_liftable(), "{} should be liftable", arch.name);
        }
    }
}
