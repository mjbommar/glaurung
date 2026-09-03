//! From a binary on disk to a value fingerprint per function.
//!
//! The pipeline is the CFR's minus the graph, plus a run:
//!
//! 1. [`crate::ir::lift_function::lift_function_from_image`] -- machine code to
//!    LLIR.
//! 2. [`crate::ir::abi::annotate_calls`] -- attach the convention's call
//!    effects, so a call defines its return register like any other
//!    instruction.
//! 3. `super::harvest::run_seed`, once per seed, bounded by the interpreter's
//!    own instruction budget.
//! 4. `super::filter::filter_run`, then the branch-condition pass.
//!
//! There is no SSA step and no structuring step. Values are what the machine
//! computes; nothing downstream of the lifter changes them, so nothing
//! downstream of the lifter is run.
//!
//! # x86-64 only, and why that is a gate rather than a caveat
//!
//! `crate::exec::Machine::new` builds an x86-64 register file and the x86-64
//! helper set. Running an ARM64 function through it would not fail loudly; it
//! would read every register as zero and produce a fingerprint that looks like
//! a measurement. So the architecture is checked and refused rather than
//! assumed. AArch64 is one `Machine::new_with_arch` away and is the next
//! slice's work, along with the register list in `super::seeds`.

use std::collections::BTreeMap;
use std::path::Path;

use super::branch::branch_elements;
use super::filter::{filter_run, FilterCounts};
use super::fingerprint::ValueFingerprint;
use super::harvest::{run_seed, RunOutcome, ValueContext};
use super::settings::{ValueSettings, ValueVersion};
use crate::analysis::cfg::Budgets;
use crate::core::binary::Arch;
use crate::core::function::Function;
use crate::ir::call_args::CallConv;
use crate::ir::types::{Endian, LlirFunction};
use crate::program::image::{ImageMemoryKind, ProgramImage};
use crate::program::session::ProgramSession;

/// Why a whole binary could not be fingerprinted.
///
/// A *function* that cannot be lifted is not an error -- it is skipped -- for
/// the same reason as in the CFR lane: one undecodable function in a shared
/// library must not cost the other eleven hundred their fingerprints.
#[derive(Debug)]
pub enum ValueError {
    /// The file could not be read or parsed.
    Image(crate::program::image::ProgramImageError),
    /// The target has no calling convention Glaurung models, so call effects
    /// cannot be attached.
    NoCallingConvention(crate::target::TargetId),
    /// The interpreter this scheme drives is x86-64 only.
    UnsupportedArchitecture(Arch),
}

impl std::fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueError::Image(error) => write!(formatter, "{error}"),
            ValueError::NoCallingConvention(target) => write!(
                formatter,
                "no calling convention is modelled for {target:?}, so call \
                 effects cannot be attached"
            ),
            ValueError::UnsupportedArchitecture(arch) => write!(
                formatter,
                "value fingerprints run the concrete interpreter over an \
                 x86-64 register file; {arch:?} is not supported yet"
            ),
        }
    }
}

impl std::error::Error for ValueError {}

/// What the runs cost and how far they got.
///
/// Reported next to every number, because a fingerprint built from three runs
/// that all hit the budget in the first loop is not the same measurement as one
/// built from three runs that returned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HarvestStats {
    /// Runs performed.
    pub seeds: u8,
    /// Instructions retired across every run.
    pub steps: u64,
    pub returned: u8,
    pub budget_exhausted: u8,
    pub halted: u8,
    pub no_block: u8,
    pub filter: FilterCounts,
    /// Every run exhausted its budget **and** no value survived the filters.
    ///
    /// This is the coverage failure worth counting separately: the difference
    /// between "the budget was too small" and "the budget was too small to
    /// learn anything at all".
    pub budget_exhausted_before_any_value: bool,
}

/// One function's fingerprint, with the facts a measurement needs beside it.
#[derive(Debug, Clone)]
pub struct FunctionValues {
    pub entry_va: u64,
    /// The symbol name, when the image has one. Never part of the fingerprint.
    pub name: Option<String>,
    pub block_count: usize,
    pub instruction_count: usize,
    pub stats: HarvestStats,
    pub fingerprint: ValueFingerprint,
}

/// The fingerprint of one already-lifted function.
///
/// This is the seam the unit tests build against: hand-written LLIR in,
/// fingerprint out, no image and no disk.
pub fn fingerprint_of(
    function: &LlirFunction,
    context: &ValueContext<'_>,
) -> (ValueFingerprint, HarvestStats) {
    let settings = context.settings;
    let seeds = settings.seed_count();
    let mut stats = HarvestStats {
        seeds,
        ..HarvestStats::default()
    };
    let mut elements: Vec<u64> = Vec::new();

    for seed in 0..seeds {
        let harvest = run_seed(function, context, seed);
        stats.steps += harvest.steps;
        match harvest.outcome {
            RunOutcome::Returned => stats.returned += 1,
            RunOutcome::BudgetExhausted => stats.budget_exhausted += 1,
            RunOutcome::Halted(_) => stats.halted += 1,
            RunOutcome::NoBlock(_) => stats.no_block += 1,
        }
        let (kept, counts) = filter_run(&harvest, context);
        stats.filter.merge(counts);
        elements.extend(kept);
    }

    stats.budget_exhausted_before_any_value =
        stats.budget_exhausted == seeds && stats.filter.kept == 0;

    if settings.branch_conditions {
        elements.extend(branch_elements(function));
    }

    let version = ValueVersion::current(settings);
    (ValueFingerprint::from_elements(version, &elements), stats)
}

/// Compute a value fingerprint for one function against an already-open image.
pub fn fingerprint_for_function(
    image: &ProgramImage,
    function: &Function,
    cc: CallConv,
    settings: ValueSettings,
    external_names: &BTreeMap<u64, String>,
) -> Option<FunctionValues> {
    let mut llir = crate::ir::lift_function::lift_function_from_image(image, function).ok()?;
    if llir.blocks.is_empty() {
        return None;
    }
    crate::ir::abi::annotate_calls(&mut llir, cc);

    let is_mapped = |address: u64| image.memory_kind_at(address).is_some();
    let image_word =
        |address: u64, size: u8, endian: Endian| read_image_word(image, address, size, endian);
    let context = ValueContext {
        settings,
        is_mapped_address: &is_mapped,
        image_word: &image_word,
        external_names,
    };

    let (fingerprint, stats) = fingerprint_of(&llir, &context);
    let entry_va = function.entry_point.value;
    Some(FunctionValues {
        entry_va,
        name: image
            .defined_symbol_name_at(entry_va)
            .map(ToString::to_string),
        block_count: llir.blocks.len(),
        instruction_count: llir.blocks.iter().map(|block| block.instrs.len()).sum(),
        stats,
        fingerprint,
    })
}

/// Compute a value fingerprint for every discovered function in `path`.
pub fn fingerprints_for_path(
    path: &Path,
    settings: ValueSettings,
    budgets: &Budgets,
) -> Result<Vec<FunctionValues>, ValueError> {
    let session = ProgramSession::from_path(path).map_err(ValueError::Image)?;
    let target = *session.target();
    let image = session.image();
    if image.arch() != Arch::X86_64 {
        return Err(ValueError::UnsupportedArchitecture(image.arch()));
    }
    let cc = target
        .calling_convention()
        .ok_or(ValueError::NoCallingConvention(target.id()))?;
    let functions = session.discover_functions(budgets, &[]);
    let external = crate::identity::cfr::extract::external_names(image);

    let mut out = Vec::with_capacity(functions.len());
    for function in functions.iter() {
        if let Some(entry) = fingerprint_for_function(image, function, cc, settings, &external) {
            out.push(entry);
        }
    }
    out.sort_by_key(|entry| entry.entry_va);
    Ok(out)
}

/// Read `size` initialised, **read-only** image bytes at a VA as an integer.
///
/// Read-only rather than "any mapped range" because that is the memory whose
/// contents are the same in every run of the program: vSim starts with
/// `.rodata` and `.text` mapped and everything else uninitialised, and writable
/// static storage is only the same as its file image until something writes to
/// it. `.bss` is mapped but not file-backed and falls out of
/// `va_to_file_offset` on its own.
fn read_image_word(image: &ProgramImage, address: u64, size: u8, endian: Endian) -> Option<u128> {
    if size == 0 || usize::from(size) > 16 {
        return None;
    }
    if image.memory_kind_at(address) != Some(ImageMemoryKind::ReadOnly) {
        return None;
    }
    let offset = image.va_to_file_offset(address)?;
    let bytes = image.bytes();
    let end = offset.checked_add(usize::from(size))?;
    if end > bytes.len() {
        return None;
    }
    let slice = &bytes[offset..end];
    let mut word = 0u128;
    match endian {
        Endian::Little => {
            for (index, byte) in slice.iter().enumerate() {
                word |= u128::from(*byte) << (8 * index);
            }
        }
        Endian::Big => {
            for byte in slice {
                word = (word << 8) | u128::from(*byte);
            }
        }
    }
    Some(word)
}
