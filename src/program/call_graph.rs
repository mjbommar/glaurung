//! Program-scoped call structure keyed by stable function identity.
//!
//! This is the input an interprocedural fixed point needs: a node set that is
//! exactly the discovered functions, edges keyed by identity rather than by
//! spelling, and a deterministic strongly-connected-component condensation.
//!
//! It deliberately does NOT reuse [`crate::core::call_graph::CallGraph`], which
//! `analyze_functions_image_with_seeds` returns and `ProgramSession` discards.
//! That structure is a Python-facing report, not an analysis input, and it
//! cannot serve as one:
//!
//! * its `nodes` are function NAMES captured during discovery, while its edges
//!   are built from the names left after the symbol, DWARF and FLIRT rename
//!   passes, so the two halves disagree — `CallGraph::validate()` rejects the
//!   graph produced for a plain `hello world` with
//!   `Err("Edge references unknown caller function: _start")`;
//! * a caller reached only through the `sub_<va>` fallback is never added as a
//!   node, so roots such as `main` and `_start` are missing from `nodes`;
//! * names are not injective: two static functions sharing a spelling collapse
//!   to one node.
//!
//! # Soundness: edges are a lower bound
//!
//! Discovery records a call target only when it resolves one
//! (`analysis::cfg`'s `if let Some(tgt) = resolved_target`), so an unresolved
//! indirect call contributes NO edge here. Absence of out-edges therefore does
//! not prove a function is a leaf, and absence of a cycle does not prove a
//! function is non-recursive. Consumers must fail closed on that:
//! [`ProgramCallGraph::shares_component`] returning `true` is proof of a cycle,
//! but `false` is not proof of acyclicity, so it may be used to spend MORE
//! effort and never as the sole termination guarantee.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::function::Function;
use crate::program::image::ProgramImage;

/// A function's identity for the life of one loaded image.
///
/// This is the normalized ENTRY, not a range. [`Function`] carries
/// `chunks: Vec<AddressRange>` because `.cold` splits and MSVC funclets make one
/// function several intervals; keying on a range would give one function two
/// identities the moment the linker moved half of it.
///
/// The normalization is [`ProgramImage::normalize_function_entry`], which strips
/// the ARM Thumb bit — the only place a function entry has two spellings. Three
/// existing keys (`DiscoveryKey`, `EnvironmentKey`, and the `ProgramEnvironment`
/// prototype map) already canonicalize through it, so this shares their identity
/// rather than inventing a fourth.
///
/// Not stable across a re-link, and it does not pretend to be. Anything that
/// must survive a rebuild belongs to [`crate::program::symbols::SymbolStore`],
/// which is keyed on linkage spelling for exactly that reason.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FunctionId(u64);

impl FunctionId {
    /// Canonicalize one entry address into an identity for this image.
    pub fn new(image: &ProgramImage, entry_va: u64) -> Self {
        Self(image.normalize_function_entry(entry_va))
    }

    /// The normalized entry address behind this identity.
    pub fn entry_va(self) -> u64 {
        self.0
    }
}

/// One proven call target of a function.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum CallTarget {
    /// Another discovered function in this image.
    Internal(FunctionId),
    /// A proven target with no discovered body: a PLT stub, an import thunk, or
    /// an address outside the analyzed set. Kept rather than dropped so a
    /// consumer can tell "calls something we did not analyze" from "calls
    /// nothing", which is the distinction an interprocedural fact depends on.
    External(u64),
}

/// Index of a strongly connected component in [`ProgramCallGraph::components`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ComponentId(usize);

/// The discovered call structure of one image, keyed by [`FunctionId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramCallGraph {
    functions: Vec<FunctionId>,
    callees: BTreeMap<FunctionId, Vec<CallTarget>>,
    components: Vec<Vec<FunctionId>>,
    component_of: BTreeMap<FunctionId, ComponentId>,
}

impl ProgramCallGraph {
    /// Build the call structure of one already discovered function set.
    ///
    /// Every discovered function becomes a node, including roots that call but
    /// are never called. Ordering is by `FunctionId` throughout, so the node
    /// list, the edge lists and the condensation are byte-identical for the same
    /// input regardless of the `HashSet` iteration order inside [`Function`].
    pub fn from_discovered(image: &ProgramImage, functions: &[Function]) -> Self {
        let mut nodes: BTreeSet<FunctionId> = BTreeSet::new();
        for function in functions {
            nodes.insert(FunctionId::new(image, function.entry_point.value));
        }

        let mut callees: BTreeMap<FunctionId, Vec<CallTarget>> = BTreeMap::new();
        for function in functions {
            let caller = FunctionId::new(image, function.entry_point.value);
            // `Function::callees` is a `HashSet<Address>`; sort into a set here
            // so the edge order is the identity order and never the hash order.
            let mut targets: BTreeSet<CallTarget> = BTreeSet::new();
            for callee in &function.callees {
                let normalized = image.normalize_function_entry(callee.value);
                if normalized == 0 {
                    continue;
                }
                let target = FunctionId(normalized);
                if nodes.contains(&target) {
                    targets.insert(CallTarget::Internal(target));
                } else {
                    targets.insert(CallTarget::External(normalized));
                }
            }
            // A function discovered twice (split chunks merged late) must not
            // lose the edges of either copy.
            callees
                .entry(caller)
                .or_default()
                .extend(targets.into_iter());
        }
        for edges in callees.values_mut() {
            edges.sort_unstable();
            edges.dedup();
        }

        let functions: Vec<FunctionId> = nodes.into_iter().collect();
        let (components, component_of) = condense(&functions, &callees);
        Self {
            functions,
            callees,
            components,
            component_of,
        }
    }

    /// Every discovered function, in ascending identity order.
    pub fn functions(&self) -> &[FunctionId] {
        &self.functions
    }

    /// The proven call targets of one function, in ascending order.
    ///
    /// An empty result does NOT prove the function is a leaf — see the module
    /// documentation on unresolved indirect calls.
    pub fn known_callees(&self, function: FunctionId) -> &[CallTarget] {
        self.callees
            .get(&function)
            .map_or(&[][..], |edges| edges.as_slice())
    }

    /// The strongly connected components, in reverse topological order.
    ///
    /// Callees precede their callers, which is the order a monotone bottom-up
    /// propagation must visit.
    pub fn components(&self) -> &[Vec<FunctionId>] {
        &self.components
    }

    /// The component containing one function, if it was discovered.
    pub fn component_of(&self, function: FunctionId) -> Option<ComponentId> {
        self.component_of.get(&function).copied()
    }

    /// The functions of one component, in ascending identity order.
    pub fn component_members(&self, component: ComponentId) -> &[FunctionId] {
        self.components
            .get(component.0)
            .map_or(&[][..], |members| members.as_slice())
    }

    /// Whether two functions are mutually reachable through proven calls.
    ///
    /// `true` is proof of a cycle. **`false` is not proof of acyclicity**: the
    /// edge set is a lower bound, so a cycle closed by an unresolved indirect
    /// call is invisible here. Use this to justify spending more analysis
    /// effort, never as the only reason a recursion terminates.
    pub fn shares_component(&self, one: FunctionId, other: FunctionId) -> bool {
        match (self.component_of(one), self.component_of(other)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Whether this function is inside a proven call cycle, including a direct
    /// self-call.
    pub fn is_recursive(&self, function: FunctionId) -> bool {
        let Some(component) = self.component_of(function) else {
            return false;
        };
        if self.components[component.0].len() > 1 {
            return true;
        }
        self.known_callees(function)
            .contains(&CallTarget::Internal(function))
    }

    /// Components containing more than one function, or one self-calling
    /// function.
    pub fn recursive_component_count(&self) -> usize {
        self.components
            .iter()
            .filter(|component| {
                component.len() > 1
                    || component
                        .first()
                        .is_some_and(|&only| self.is_recursive(only))
            })
            .count()
    }
}

/// Iterative Tarjan condensation.
///
/// Iterative rather than recursive on purpose: a call chain is as deep as the
/// program allows, and the decompiler already runs its deepest pass on a
/// dedicated thread for stack headroom (`ir/ast.rs`). A recursive condensation
/// would reintroduce that hazard for no gain.
fn condense(
    functions: &[FunctionId],
    callees: &BTreeMap<FunctionId, Vec<CallTarget>>,
) -> (Vec<Vec<FunctionId>>, BTreeMap<FunctionId, ComponentId>) {
    let mut next_index = 0usize;
    let mut index: BTreeMap<FunctionId, usize> = BTreeMap::new();
    let mut low: BTreeMap<FunctionId, usize> = BTreeMap::new();
    let mut on_stack: BTreeSet<FunctionId> = BTreeSet::new();
    let mut stack: Vec<FunctionId> = Vec::new();
    let mut components: Vec<Vec<FunctionId>> = Vec::new();
    let mut component_of: BTreeMap<FunctionId, ComponentId> = BTreeMap::new();
    // (node, index of the next out-edge to visit)
    let mut frames: Vec<(FunctionId, usize)> = Vec::new();

    let internal = |node: FunctionId, cursor: usize| -> Option<FunctionId> {
        callees
            .get(&node)?
            .iter()
            .filter_map(|target| match target {
                CallTarget::Internal(id) => Some(*id),
                CallTarget::External(_) => None,
            })
            .nth(cursor)
    };

    for &root in functions {
        if index.contains_key(&root) {
            continue;
        }
        index.insert(root, next_index);
        low.insert(root, next_index);
        next_index += 1;
        stack.push(root);
        on_stack.insert(root);
        frames.push((root, 0));

        while let Some((node, cursor)) = frames.pop() {
            if let Some(child) = internal(node, cursor) {
                frames.push((node, cursor + 1));
                if !index.contains_key(&child) {
                    index.insert(child, next_index);
                    low.insert(child, next_index);
                    next_index += 1;
                    stack.push(child);
                    on_stack.insert(child);
                    frames.push((child, 0));
                } else if on_stack.contains(&child) {
                    let candidate = index[&child];
                    let current = low[&node];
                    low.insert(node, current.min(candidate));
                }
                continue;
            }

            if low[&node] == index[&node] {
                let mut component = Vec::new();
                while let Some(member) = stack.pop() {
                    on_stack.remove(&member);
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                component.sort_unstable();
                let id = ComponentId(components.len());
                for &member in &component {
                    component_of.insert(member, id);
                }
                components.push(component);
            }

            if let Some(&(parent, _)) = frames.last() {
                let candidate = low[&node];
                let current = low[&parent];
                low.insert(parent, current.min(candidate));
            }
        }
    }

    (components, component_of)
}
