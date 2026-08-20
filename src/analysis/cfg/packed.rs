//! Deciding what to analyse when the bytes handed to us are not the program.
//!
//! Split out of `cfg.rs` rather than left in it: that file is the largest in the
//! tree at 2,575 lines against a 1,000-line target, and this is a self-contained
//! question — *which image do we analyse* — answered before any discovery runs.
//! Keeping it here also puts the three outcomes in one place, where they can be
//! read together.

use super::{
    analyze_functions_unpacked, Budgets, CallGraph, Deadline, Function, FunctionDiscoveryStats,
};

/// Whole-binary discovery, after making sure there is a binary to discover in.
///
/// A packed image is not a hard input, it is a *different* input: the code that
/// disassembles is the packer's decompressor and the program is a compressed
/// blob no disassembler can see. Discovery over one does not come back empty, it
/// comes back with the stub — on `tests/realistic_corpus/`'s UPX variant, eight
/// functions, none of them among the eighty-three we linked in.
///
/// So the packed case is settled here, before any analysis runs, and it has
/// exactly three outcomes, all of them recorded in the stats:
///
/// * not packed — analyse the bytes as given;
/// * packed and recovered — analyse the ORIGINAL image, and say so;
/// * packed and not recovered — analyse what there is, but mark the functions
///   as the stub's and record why the program could not be reached.
///
/// A caller that already handed us a `ProgramImage` is left alone: they indexed
/// specific bytes, and quietly analysing different ones would break the
/// correspondence they are relying on.
pub(super) fn analyze_functions_bytes_within(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
    deadline: Deadline<'_>,
    image: Option<&crate::program::image::ProgramImage>,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    if image.is_some() {
        return analyze_functions_unpacked(data, budgets, requested_vas, deadline, image);
    }
    match crate::unpack::recover(data) {
        Ok(None) => analyze_functions_unpacked(data, budgets, requested_vas, deadline, None),
        Ok(Some(recovered)) => {
            let (functions, cg, mut stats) = analyze_functions_unpacked(
                &recovered.bytes,
                budgets,
                requested_vas,
                deadline,
                None,
            );
            stats.packer = Some(recovered.packer.to_string());
            stats.unpacked = true;
            stats.original_entry = Some(recovered.original_entry);
            (functions, cg, stats)
        }
        Err(failure) => {
            let (functions, cg, mut stats) =
                analyze_functions_unpacked(data, budgets, requested_vas, deadline, None);
            let functions = mark_as_stub(functions, failure.packer);
            stats.packer = Some(failure.packer.to_string());
            stats.unpacked = false;
            stats.unpack_error = Some(failure.reason);
            (functions, cg, stats)
        }
    }
}

/// Rename anonymous functions found in a stub so they cannot read as the program's.
///
/// `sub_401b20` in a result list is a claim: it says "the program has a function
/// here". On an image we could not unpack that claim is false for every entry,
/// and the stats field saying so is not visible through the two-tuple entry
/// point most callers use. The name is, everywhere — in the CLI, in the KB, in
/// an agent's prompt — so the name is where this belongs.
fn mark_as_stub(functions: Vec<Function>, packer: &str) -> Vec<Function> {
    let prefix = format!("{}_stub_", packer.to_ascii_lowercase());
    functions
        .into_iter()
        .map(|mut f| {
            if let Some(rest) = f.name.strip_prefix("sub_") {
                f.name = format!("{prefix}{rest}");
            }
            f
        })
        .collect()
}
