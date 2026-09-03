//! From a binary on disk to a CFR signature per function.
//!
//! The pipeline is deliberately short, and stops well before the decompiler
//! does:
//!
//! 1. [`crate::ir::lift_function::lift_function_from_image`] -- machine code to
//!    LLIR.
//! 2. [`crate::ir::abi::annotate_calls`] -- attach the convention's call
//!    effects, so a call participates in def/use like any other instruction.
//!    Without it a call defines nothing and every post-call read reaches a
//!    stale value.
//! 3. [`super::normalize`] -- **only when [`CfrSettings::normalize`] is set**,
//!    which it is not by default. An unsound local peephole normaliser over a
//!    *copy* of the function. With the flag off this step does not exist and
//!    every signature byte is what it was before the normaliser was written,
//!    which `super::normalize::tests` pins against digests measured on the
//!    commit before it.
//! 4. [`crate::ir::ssa::compute_ssa_for_target`] -- SSA identities.
//! 5. CFR-G, CFR-C, the feature multiset.
//!
//! It stops there on purpose. Structuring (`structure_v2`) introduces
//! `BinOp::LogicalAnd` and `BinOp::LogicalOr`, which are source-level
//! short-circuit operators and not machine semantics; type recovery and
//! prototype recovery introduce names, which are masked anyway; and every one
//! of those stages is under active development, so a signature that depended on
//! them would move when the *renderer* moved. An identity must not.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::graph::{self, GraphContext};
use super::signature::{CfrSettings, CfrSignature, CfrVersion};
use super::widths::WidthCensus;
use super::{blocks, wl};
use crate::analysis::cfg::Budgets;
use crate::core::function::Function;
use crate::ir::call_args::CallConv;
use crate::ir::ssa::{compute_ssa_for_target, SsaInfo};
use crate::ir::types::LlirFunction;
use crate::program::image::ProgramImage;
use crate::program::session::ProgramSession;

/// Why a whole binary could not be signed.
///
/// A *function* that cannot be lifted is not an error -- it is skipped and
/// counted -- because one undecodable function in a shared library must not
/// cost the other eleven hundred their signatures.
#[derive(Debug)]
pub enum CfrError {
    /// The file could not be read or parsed.
    Image(crate::program::image::ProgramImageError),
    /// The target has no calling convention Glaurung models, so call effects
    /// cannot be attached and every call would be a hole in the dataflow.
    NoCallingConvention(crate::target::TargetId),
}

impl std::fmt::Display for CfrError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CfrError::Image(error) => write!(formatter, "{error}"),
            CfrError::NoCallingConvention(target) => write!(
                formatter,
                "no calling convention is modelled for {target:?}, so call \
                 effects cannot be attached and the dataflow graph would be \
                 missing every call"
            ),
        }
    }
}

impl std::error::Error for CfrError {}

/// One function's signature, with the facts a measurement needs alongside it.
#[derive(Debug, Clone)]
pub struct FunctionCfr {
    pub entry_va: u64,
    /// The symbol name, when the image has one. Never part of the signature.
    pub name: Option<String>,
    pub block_count: usize,
    pub instruction_count: usize,
    /// How much of the function width inference resolved.
    pub width_census: WidthCensus,
    pub signature: CfrSignature,
}

/// Compute a CFR signature for every discovered function in `path`.
///
/// Functions that cannot be lifted are omitted rather than reported as empty
/// signatures: an empty vector compares as "no answer" to everything, which
/// would be indistinguishable from a genuinely featureless function.
pub fn signatures_for_path(
    path: &Path,
    settings: CfrSettings,
    budgets: &Budgets,
) -> Result<Vec<FunctionCfr>, CfrError> {
    let session = ProgramSession::from_path(path).map_err(CfrError::Image)?;
    let target = *session.target();
    let cc = target
        .calling_convention()
        .ok_or(CfrError::NoCallingConvention(target.id()))?;
    let functions = session.discover_functions(budgets, &[]);
    let image = session.image();
    let external = external_names(image);
    let stack_registers = super::stack::stack_registers_for(cc);

    let mut out = Vec::with_capacity(functions.len());
    for function in functions.iter() {
        if let Some(entry) =
            signature_for_function(image, function, cc, settings, &external, &stack_registers)
        {
            out.push(entry);
        }
    }
    out.sort_by_key(|entry| entry.entry_va);
    Ok(out)
}

/// Compute one function's signature against an already-open image.
pub fn signature_for_function(
    image: &ProgramImage,
    function: &Function,
    cc: CallConv,
    settings: CfrSettings,
    external_names: &BTreeMap<u64, String>,
    stack_registers: &BTreeSet<&'static str>,
) -> Option<FunctionCfr> {
    let mut llir = crate::ir::lift_function::lift_function_from_image(image, function).ok()?;
    if llir.blocks.is_empty() {
        return None;
    }
    crate::ir::abi::annotate_calls(&mut llir, cc);
    // The peephole normaliser is opt-in and runs on a COPY. Its output feeds
    // the signature and nothing else; the decompiler never sees it. See
    // `super::normalize`.
    let llir = if settings.normalize {
        super::normalize::normalize_function(&llir)
    } else {
        llir
    };
    let ssa = compute_ssa_for_target(&llir, *image.target());
    let is_mapped = |address: u64| image.memory_kind_at(address).is_some();
    let context = GraphContext {
        settings,
        external_names,
        is_mapped_address: &is_mapped,
        stack_registers,
    };
    let (signature, census) = signature_of(&llir, &ssa, &context);
    let entry_va = function.entry_point.value;
    Some(FunctionCfr {
        entry_va,
        name: image
            .defined_symbol_name_at(entry_va)
            .map(ToString::to_string),
        block_count: llir.blocks.len(),
        instruction_count: llir.blocks.iter().map(|block| block.instrs.len()).sum(),
        width_census: census,
        signature,
    })
}

/// The signature of one already-lifted function, plus its width census.
///
/// This is the seam unit tests build against: hand-written LLIR in, signature
/// out, no image and no disk.
pub fn signature_of(
    function: &LlirFunction,
    ssa: &SsaInfo,
    context: &GraphContext<'_>,
) -> (CfrSignature, WidthCensus) {
    let dataflow = graph::build(function, ssa, context);
    let rows = wl::refine(&dataflow, wl::DATAFLOW_ITERATIONS);
    let mut features: Vec<u32> = Vec::new();
    for row in &rows {
        features.extend(row.iter().map(|label| *label as u32));
    }
    features.extend(blocks::block_features(function, &dataflow, &rows));
    let version = CfrVersion::current(context.settings);
    (
        CfrSignature::from_features(version, &features),
        dataflow.width_census(),
    )
}

/// Address-to-name map for calls that leave the image.
///
/// An external symbol is a stable interface: `memcpy` is `memcpy` in every
/// build of every version, so its name is kept in the label. This resolves the
/// stub addresses a direct call actually targets -- ELF PLT entries, PE import
/// thunks and IAT slots, Mach-O stubs -- because that is the address the
/// instruction names.
pub fn external_names(image: &ProgramImage) -> BTreeMap<u64, String> {
    use crate::core::binary::Format;
    let bytes = image.bytes();
    let pairs: Vec<(u64, String)> = match image.format() {
        Format::ELF => crate::analysis::elf_plt::elf_plt_map(bytes),
        Format::PE => {
            let mut pairs = crate::analysis::pe_iat::pe_import_thunk_map(bytes);
            pairs.extend(crate::analysis::pe_iat::pe_iat_map(bytes));
            pairs
        }
        Format::MachO => crate::analysis::macho_stubs::macho_stubs_map(bytes),
        _ => Vec::new(),
    };
    pairs
        .into_iter()
        .map(|(address, name)| (address, normalize_import_name(&name)))
        .collect()
}

/// Strip the decorations a linker adds to an imported name.
///
/// `puts@plt`, `__isoc99_scanf@@GLIBC_2.7` and `KERNEL32.dll!CreateFileW` all
/// name the same interface across builds; the suffix is toolchain state, not
/// program identity.
fn normalize_import_name(name: &str) -> String {
    let name = name.split("@@").next().unwrap_or(name);
    let name = name.strip_suffix("@plt").unwrap_or(name);
    let name = name.rsplit('!').next().unwrap_or(name);
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_names_lose_their_linker_decoration() {
        assert_eq!(normalize_import_name("puts@plt"), "puts");
        assert_eq!(
            normalize_import_name("__isoc99_scanf@@GLIBC_2.7"),
            "__isoc99_scanf"
        );
        assert_eq!(
            normalize_import_name("KERNEL32.dll!CreateFileW"),
            "CreateFileW"
        );
        assert_eq!(normalize_import_name("memcpy"), "memcpy");
    }
}
