//! Conservative source-arity facts recovered from direct callers.
//!
//! Definition-local liveness cannot retain a parameter which optimization
//! erased from the callee.  Multiple direct callers can provide a conservative
//! high-confidence arity candidate when they independently agree on a balanced
//! outgoing stack area beyond the target ABI's register bank.  This owner reuses
//! the normal lifted-IR, SSA, structuring, and argument-reconstruction machinery;
//! it does not decode a second architecture-specific model of call setup.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::analysis::cfg::{discover_function_image_at, Budgets};
use crate::analysis::exception::EhFrameFunction;
use crate::ir::ast::Function;
use crate::ir::call_args::CallConv;
use crate::ir::lift_function::lift_function_from_image;
use crate::ir::types::{CallTarget, Op};
use crate::program::environment::direct_call_sites;
use crate::program::image::ProgramImage;

const MAX_DIRECT_CALLERS_PER_ENVIRONMENT: usize = 32;
const MIN_AGREEING_DIRECT_CALLS: usize = 2;

fn caller_ast(
    image: &ProgramImage,
    budgets: &Budgets,
    cc: CallConv,
    owner: u64,
) -> Option<(crate::ir::types::LlirFunction, Function)> {
    let targeted_budgets = Budgets {
        max_functions: 1,
        ..*budgets
    };
    let function = discover_function_image_at(image, &targeted_budgets, owner)?;
    let mut lifted = lift_function_from_image(image, &function, image.arch())?;
    crate::ir::abi::annotate_calls(&mut lifted, cc);
    let ssa = crate::ir::ssa::compute_ssa(&lifted);
    let region = crate::ir::structure::recover_verified(&lifted, &ssa);
    let (numbered, _, _) =
        crate::ir::value_number::value_number_with_parameter_slots(&lifted, &ssa, cc);
    let ast = crate::ir::ast::lower(&numbered, &region, function.name.clone());
    Some((lifted, ast))
}

fn agreed_stack_proven_arity(cc: CallConv, observations: &[(u64, usize)]) -> Option<usize> {
    if observations.len() < MIN_AGREEING_DIRECT_CALLS {
        return None;
    }
    let distinct_owners = observations
        .iter()
        .map(|(owner, _)| *owner)
        .collect::<HashSet<_>>();
    if distinct_owners.len() < MIN_AGREEING_DIRECT_CALLS {
        return None;
    }
    let arity = observations.first()?.1;
    if observations
        .iter()
        .any(|(_, observation)| *observation != arity)
    {
        return None;
    }
    // A single push-shaped word may be ABI alignment rather than a source
    // argument (Diffutils does exactly this). Requiring independent agreement
    // rejects that observed false positive while retaining the OpenSSH contract.
    let register_prefix = crate::ir::abi::argument_slots(cc).len();
    match cc {
        CallConv::SysVAmd64 if arity > register_prefix => Some(arity),
        _ => None,
    }
}

/// Recover conservative parameter-arity candidates from all direct calls.
///
/// Every raw call prefilter must belong to an exact unwind interval, survive
/// lifting at the same instruction address, and produce one agreeing
/// stack-bounded AST observation. Missing, singleton, or conflicting evidence
/// suppresses the fact rather than selecting a majority.
pub(super) fn recover_direct_caller_arities(
    image: &ProgramImage,
    budgets: &Budgets,
    cc: CallConv,
    fdes: &[EhFrameFunction],
    requested_vas: &HashSet<u64>,
) -> HashMap<u64, usize> {
    if requested_vas.is_empty() || cc != CallConv::SysVAmd64 || fdes.is_empty() {
        return HashMap::new();
    }
    let targets = requested_vas
        .iter()
        .copied()
        .map(|target| (target, "requested function"))
        .collect::<HashMap<_, _>>();
    let sites = direct_call_sites(image, &targets);
    if sites.len() > MAX_DIRECT_CALLERS_PER_ENVIRONMENT {
        return HashMap::new();
    }

    let mut sites_by_owner = BTreeMap::<u64, BTreeSet<(u64, u64)>>::new();
    for (site, target) in sites {
        let Some(owner) = fdes
            .iter()
            .find(|function| function.start <= site && site < function.end)
            .map(|function| function.start)
        else {
            // A byte-pattern hit which cannot be attributed to a complete
            // function prevents an exact all-callsite claim.
            return HashMap::new();
        };
        sites_by_owner
            .entry(owner)
            .or_default()
            .insert((site, target));
    }

    let mut observations = HashMap::<u64, Vec<(u64, usize)>>::new();
    let mut invalid = HashSet::<u64>::new();
    for (owner, expected_sites) in sites_by_owner {
        let Some((lifted, ast)) = caller_ast(image, budgets, cc, owner) else {
            invalid.extend(expected_sites.iter().map(|(_, target)| *target));
            continue;
        };
        let lifted_sites = lifted
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| match instruction.op {
                Op::Call {
                    target: CallTarget::Direct(target),
                    ..
                } if requested_vas.contains(&target) => Some((instruction.va, target)),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if lifted_sites != expected_sites {
            invalid.extend(
                expected_sites
                    .iter()
                    .chain(lifted_sites.iter())
                    .map(|(_, target)| *target),
            );
            continue;
        }
        let stack_proven =
            crate::ir::caller_arity::stack_proven_direct_call_arities(&ast, cc, requested_vas);
        let owner_targets = expected_sites
            .iter()
            .map(|(_, target)| *target)
            .collect::<BTreeSet<_>>();
        for target in owner_targets {
            let expected_count = expected_sites
                .iter()
                .filter(|(_, candidate)| *candidate == target)
                .count();
            let found = stack_proven
                .iter()
                .filter_map(|(candidate, arity)| (*candidate == target).then_some(*arity))
                .collect::<Vec<_>>();
            if found.len() != expected_count {
                invalid.insert(target);
            } else {
                observations
                    .entry(target)
                    .or_default()
                    .extend(found.into_iter().map(|arity| (owner, arity)));
            }
        }
    }

    requested_vas
        .iter()
        .filter(|target| !invalid.contains(target))
        .filter_map(|target| {
            agreed_stack_proven_arity(cc, observations.get(target)?).map(|arity| (*target, arity))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::agreed_stack_proven_arity;
    use crate::ir::call_args::CallConv;

    #[test]
    fn caller_arity_requires_agreement_and_stack_evidence() {
        assert_eq!(
            agreed_stack_proven_arity(CallConv::SysVAmd64, &[(0x1000, 8), (0x2000, 8)]),
            Some(8)
        );
        assert_eq!(
            agreed_stack_proven_arity(CallConv::SysVAmd64, &[(0x1000, 8), (0x2000, 7)]),
            None
        );
        assert_eq!(
            agreed_stack_proven_arity(CallConv::SysVAmd64, &[(0x1000, 8), (0x1000, 8)]),
            None
        );
        assert_eq!(
            agreed_stack_proven_arity(CallConv::SysVAmd64, &[(0x1000, 8)]),
            None
        );
        assert_eq!(
            agreed_stack_proven_arity(CallConv::SysVAmd64, &[(0x1000, 6), (0x2000, 6)]),
            None
        );
        assert_eq!(agreed_stack_proven_arity(CallConv::SysVAmd64, &[]), None);
    }
}
