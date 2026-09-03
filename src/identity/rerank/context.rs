//! The context the per-function matcher never sees: two call graphs and a
//! library partition of the reference corpus.
//!
//! Everything here is plain data keyed by the two opaque identifiers in
//! [`super::graph`], so the re-rank stage is scheme-agnostic by construction --
//! it cannot reach into a signature even if a later change wanted it to.

use std::collections::{BTreeMap, BTreeSet};

use super::graph::{QueryId, ReferenceId};

/// A library, a package, or any other partition of the reference corpus whose
/// members a compiler would plausibly emit together.
///
/// RevDecode's `lib_name`. On the fixture corpus one group is one image, which
/// is also one translation unit; on a real corpus it is whatever
/// `(name, version, variant, architecture, platform)` key the signature library
/// is built on.
pub type GroupId = u32;

/// Which query calls which, which reference function calls which, and which
/// library each reference function belongs to.
///
/// Call edges are a **lower bound** on both sides, and the scoring is built to
/// tolerate that: an unresolved indirect call contributes no edge, so a missing
/// edge means "no evidence" and never "evidence against". See the soundness
/// note on [`crate::program::call_graph`], which makes the same promise about
/// the same underlying discovery data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallContext {
    query_calls: BTreeSet<(QueryId, QueryId)>,
    reference_calls: BTreeSet<(ReferenceId, ReferenceId)>,
    reference_group: BTreeMap<ReferenceId, GroupId>,
    group_functions: BTreeMap<GroupId, usize>,
    corpus_functions: usize,
}

impl CallContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that query function `caller` calls query function `callee`.
    pub fn add_query_call(&mut self, caller: QueryId, callee: QueryId) -> &mut Self {
        self.query_calls.insert((caller, callee));
        self
    }

    /// Record that reference function `caller` calls reference function
    /// `callee`.
    pub fn add_reference_call(&mut self, caller: ReferenceId, callee: ReferenceId) -> &mut Self {
        self.reference_calls.insert((caller, callee));
        self
    }

    /// Put one reference function in a library.
    ///
    /// A reference function with no group takes part in no adjacency reward,
    /// which is the correct reading of "we do not know where this came from":
    /// RevDecode's Alg. 1 rewards a *match*, and an unknown provenance cannot
    /// match anything, not even another unknown one.
    pub fn set_reference_group(&mut self, reference: ReferenceId, group: GroupId) -> &mut Self {
        if let Some(previous) = self.reference_group.insert(reference, group) {
            if let Some(count) = self.group_functions.get_mut(&previous) {
                *count = count.saturating_sub(1);
            }
        } else {
            self.corpus_functions += 1;
        }
        *self.group_functions.entry(group).or_insert(0) += 1;
        self
    }

    /// The number of reference functions this context knows about, the
    /// denominator of the library score.
    pub fn corpus_functions(&self) -> usize {
        self.corpus_functions
    }

    pub fn group_of(&self, reference: ReferenceId) -> Option<GroupId> {
        self.reference_group.get(&reference).copied()
    }

    /// RevDecode Eq. 8: `1 - n_lib / n_corpus`.
    ///
    /// A candidate from a library that is a small part of the corpus is more
    /// specific evidence than one from a library that is most of it. Zero for a
    /// reference function with no known library, and zero when the corpus is
    /// empty, both of which are "no evidence" rather than "maximum evidence" --
    /// the formula's `1 -` makes the unguarded answer 1.0, which would be the
    /// wrong default in exactly the case where nothing is known.
    pub fn library_score(&self, reference: ReferenceId) -> f64 {
        if self.corpus_functions == 0 {
            return 0.0;
        }
        let Some(group) = self.group_of(reference) else {
            return 0.0;
        };
        let in_group = self.group_functions.get(&group).copied().unwrap_or(0);
        1.0 - (in_group as f64 / self.corpus_functions as f64)
    }

    /// RevDecode Alg. 1, reduced to its one modelled level: `same_group` when
    /// both candidates come from the same library, `0.0` otherwise.
    pub fn adjacency_score(&self, a: ReferenceId, b: ReferenceId, same_group: f64) -> f64 {
        match (self.group_of(a), self.group_of(b)) {
            (Some(ga), Some(gb)) if ga == gb => same_group,
            _ => 0.0,
        }
    }

    /// How well a candidate pair reproduces the query pair's call relation.
    ///
    /// The term this stage adds to the paper. `query_a` and `query_b` are two
    /// query functions; `ref_a` and `ref_b` are candidates for them. The score
    /// is the fraction of the query pair's call directions that the candidate
    /// pair also has:
    ///
    /// * the query pair has no call relation either way -- `0.0`, no evidence.
    ///   This is the overwhelmingly common case and it must be neutral, not a
    ///   penalty: adding a constant to every edge into a layer changes no
    ///   ordering within it, and a *penalty* proportional to nothing would.
    /// * one direction in the query, reproduced -- `1.0`.
    /// * both directions in the query (mutual recursion), one reproduced --
    ///   `0.5`.
    ///
    /// Asymmetric on purpose: `A calls B` matched by `b calls a` scores
    /// nothing. Direction is most of what a call edge says.
    pub fn call_agreement(
        &self,
        query_a: QueryId,
        query_b: QueryId,
        ref_a: ReferenceId,
        ref_b: ReferenceId,
    ) -> f64 {
        let forward = self.query_calls.contains(&(query_a, query_b));
        let backward = self.query_calls.contains(&(query_b, query_a));
        let present = usize::from(forward) + usize::from(backward);
        if present == 0 {
            return 0.0;
        }
        let mut matched = 0usize;
        if forward && self.reference_calls.contains(&(ref_a, ref_b)) {
            matched += 1;
        }
        if backward && self.reference_calls.contains(&(ref_b, ref_a)) {
            matched += 1;
        }
        matched as f64 / present as f64
    }

    /// Whether the two query functions have any call relation at all.
    ///
    /// Reported by the harness as the fraction of layer-adjacent pairs the call
    /// term can even fire on: a term that never fires and a term that fires and
    /// finds nothing look identical in a summary metric, and only the first is
    /// a reason to change the layer order.
    pub fn query_pair_is_related(&self, a: QueryId, b: QueryId) -> bool {
        self.query_calls.contains(&(a, b)) || self.query_calls.contains(&(b, a))
    }

    pub fn query_call_count(&self) -> usize {
        self.query_calls.len()
    }

    pub fn reference_call_count(&self) -> usize {
        self.reference_calls.len()
    }
}
