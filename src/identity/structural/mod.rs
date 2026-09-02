//! Structural invariants of a function's control-flow graph (the L1 rung).
//!
//! One [`StructuralSignature`] per discovered function: a handful of scalars,
//! every one of them a graph or multiset invariant, every one of them
//! B-tree-indexable in SQLite with no approximate-nearest-neighbour structure
//! anywhere. It answers the question the identity ladder assigns to L1 --
//! *which functions changed between two builds?* -- and it answers it at
//! BinDiff quality on data `analysis::cfg` already computes.
//!
//! ```text
//! MD-index (top-down, bottom-up, relaxed)   BinDiff graph_util.h
//! small-primes product over mnemonics       Dullien & Rolles, SSTIC'05
//! blocks / edges / back edges / SCCs        textbook
//! cyclomatic complexity                     E - N + 2
//! instructions, calls out, callers in       analysis::cfg + a re-decode
//! rare constants, string references         FunctionSimSearch, CodeCMR
//! ```
//!
//! # Why these and not a hash
//!
//! A digest answers "same or not". These answer "how far apart", which is what
//! a *ranked* changed-function list needs, and they do it without a model, a
//! corpus or a training step. `docs/research/program-measures-2026-09-02.md`
//! puts this at the top of its ranked plan for exactly that reason: a rebuild
//! of the same source with the same compiler has zero free compilation
//! variables, and in that regime structural invariants are close to exact while
//! costing a few dozen bytes a function.
//!
//! What they do **not** do is cross an optimisation level or an architecture.
//! The SPP is a multiset over one ISA's mnemonics; the MD-index moves whenever
//! the optimiser changes the edge set, which is most of what an optimiser does.
//! Cross-toolchain matching is L2's job (`crate::identity::cfr`), and using L1
//! for it would produce confident nonsense.
//!
//! # Determinism
//!
//! Every field is computed from a canonicalised [`graph::CfgShape`] (blocks
//! sorted, edges deduplicated and sorted); the MD-index sorts its per-edge
//! terms before summing them; the rare-constant multiset is sorted before it is
//! truncated; the SPP is a commutative product. Two runs over the same bytes
//! produce bit-identical signatures, which the module's own integration tests
//! assert.
//!
//! # Layout
//!
//! | module | owns |
//! |---|---|
//! | [`graph`] | the canonical CFG, BFS levels, dominators, back edges, SCCs |
//! | [`mdindex`] | BinDiff's MD-index in its three variants |
//! | [`spp`] | mnemonic normalization, the prime table, the product |
//! | [`code`] | re-decoding a function's blocks for the stream-level facts |

pub mod code;
pub mod graph;
pub mod mdindex;
pub mod spp;

use serde::{Deserialize, Serialize};

use crate::core::call_graph::CallGraph;
use crate::core::function::Function;

pub use code::{code_facts_from_function_bytes, CodeFacts, ImageCode};
pub use graph::CfgShape;
pub use mdindex::{md_index_agreement, md_index_bottom_up, md_index_relaxed, md_index_top_down};
pub use spp::{mnemonic_spp, normalize_mnemonic};

/// The scheme name these signatures are stored under.
///
/// Any change to the mnemonic table, the MD-index level convention or the
/// rare-constant threshold invalidates every stored row, so the version is part
/// of the name rather than a column somewhere else. BSim versions its strategy
/// in the database for the same reason.
pub const SCHEME: &str = "glaurung-structural-l1-v1";

/// Structural invariants of one function, the L1 rung of the identity ladder.
///
/// Ordering is total and lexicographic over every field, with the three
/// floating-point MD-indices ordered by [`f64::total_cmp`], so a `BTreeSet` of
/// signatures and a `sort()` both work and neither depends on NaN behaviour --
/// the fields cannot be NaN, but a type whose `Ord` is only conditionally
/// correct is a trap for the caller who eventually stores one.
///
/// **JSON is a diagnostic format for this type, not a storage format.**
/// `serde_json`'s default float parser is accurate to one unit in the last
/// place, not bit-exact, so a signature that goes out through JSON and comes
/// back may differ in the last bit of an MD-index. Persist through SQLite
/// `REAL`, which stores an IEEE-754 double verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralSignature {
    /// The function's entry virtual address. Identity of the row, not of the
    /// function -- it moves on every relink, which is the whole reason the rest
    /// of this struct exists.
    pub entry_va: u64,
    /// The discoverer's name for the function, or a symbol when one resolved.
    pub name: String,

    /// MD-index with BinDiff's default weights and BFS levels from the entry.
    ///
    /// Per edge `(s, t)`, `1 / (sqrt2*indeg(s) + sqrt3*outdeg(s) +
    /// sqrt5*indeg(t) + sqrt7*outdeg(t) + sqrt11*level(s) + sqrt13*level(t))`,
    /// summed over all edges with the terms sorted first. See [`mdindex`].
    pub md_index_top_down: f64,
    /// The same sum with `level` taken from a BFS rooted at the exit blocks.
    ///
    /// Degrees do not swap; only the level numbering changes. A pair of
    /// functions that agree top-down and disagree bottom-up differ in where
    /// their returns sit relative to the branching.
    pub md_index_bottom_up: f64,
    /// The same sum with weights `{2,3,5,7,0,0}`, so both level terms vanish.
    ///
    /// BinDiff runs this as a separate, lower-confidence matching pass (0.7
    /// against 1.0): it survives an edit that moves a block's depth without
    /// changing local degrees, and it is the variant to reach for when the two
    /// builds differ by an inlining decision.
    pub md_index_relaxed: f64,

    /// Small Primes Product over the normalized mnemonics, modulo `2^64`.
    ///
    /// Order-independent by construction, so instruction scheduling does not
    /// move it. Always odd for a non-empty function; 1 for an empty one.
    pub mnemonic_spp: u64,

    /// Basic blocks in the recovered CFG.
    pub basic_blocks: u32,
    /// Distinct control-flow edges.
    pub edges: u32,
    /// Edges `(u, v)` where `v` dominates `u`.
    pub back_edges: u32,
    /// Distinct natural-loop headers, i.e. distinct back-edge targets.
    pub loops: u32,
    /// Strongly connected components, trivial ones included.
    pub strongly_connected_components: u32,
    /// McCabe complexity, `E - N + 2`, clamped at 1.
    pub cyclomatic_complexity: u32,

    /// Instructions decoded across the function's blocks.
    pub instructions: u32,
    /// Calls whose target is an immediate operand.
    pub calls_out_direct: u32,
    /// Calls through a register or memory operand.
    pub calls_out_indirect: u32,
    /// Distinct call sites reaching this function, from the call graph.
    ///
    /// Zero when no call graph was supplied, which is not the same as "nothing
    /// calls it" -- [`StructuralSignature::from_function`] takes the call graph
    /// as an `Option` precisely so the two cases stay distinguishable to the
    /// caller that chose.
    pub callers_in: u32,

    /// Large non-address constants, ascending, with multiplicity.
    ///
    /// See [`code::RARE_CONSTANT_MIN`] for what "large" means and
    /// [`code::RARE_CONSTANT_CAP`] for the bound.
    pub rare_constants: Vec<u64>,
    /// Distinct referenced addresses holding a NUL-terminated printable run.
    pub string_refs: u32,
}

/// IEEE 754 total order as a `u64`, so a struct containing an `f64` can derive
/// a real `Ord`.
///
/// Flips the sign bit for positives and inverts everything for negatives, which
/// maps the doubles onto `u64` order-isomorphically. This is the same transform
/// `f64::total_cmp` performs internally; doing it here rather than calling
/// `total_cmp` lets the whole signature reduce to one comparable tuple.
fn total_order_bits(v: f64) -> u64 {
    let bits = v.to_bits() as i64;
    let mask = ((bits >> 63) as u64) >> 1;
    (bits as u64) ^ (mask | 0x8000_0000_0000_0000)
}

impl StructuralSignature {
    /// The tuple this signature orders and compares by.
    ///
    /// Field order here is the sort order: the three MD-indices first because
    /// they are the discriminative scalars a range query would index on, then
    /// the counts, then the identity of the row. Nested into two groups because
    /// `Ord` is only implemented for tuples up to twelve elements, and a
    /// two-tuple of tuples compares lexicographically in exactly the same
    /// order as the flat one would.
    #[allow(clippy::type_complexity)]
    fn ord_key(
        &self,
    ) -> (
        (u64, u64, u64, u64, u32, u32, u32, u32, u32, u32),
        (u32, u32, u32, u32, u32, &Vec<u64>, u64, &String),
    ) {
        (
            (
                total_order_bits(self.md_index_top_down),
                total_order_bits(self.md_index_bottom_up),
                total_order_bits(self.md_index_relaxed),
                self.mnemonic_spp,
                self.basic_blocks,
                self.edges,
                self.back_edges,
                self.loops,
                self.strongly_connected_components,
                self.cyclomatic_complexity,
            ),
            (
                self.instructions,
                self.calls_out_direct,
                self.calls_out_indirect,
                self.callers_in,
                self.string_refs,
                &self.rare_constants,
                self.entry_va,
                &self.name,
            ),
        )
    }

    /// The CFG shape this signature was computed from.
    ///
    /// Blocks come from `func.basic_blocks`, edges from `func.edges`, and the
    /// entry from `func.entry_point`. Nothing else in `Function` participates,
    /// which is what makes the graph half of the signature testable from
    /// hand-built inputs.
    pub fn shape_of(func: &Function) -> CfgShape {
        let blocks: Vec<u64> = func
            .basic_blocks
            .iter()
            .map(|b| b.start_address.value)
            .collect();
        let edges: Vec<(u64, u64)> = func.edges.iter().map(|(a, b)| (a.value, b.value)).collect();
        CfgShape::new(&blocks, &edges, func.entry_point.value)
    }

    /// Compute a signature for one discovered function.
    ///
    /// `image` supplies the instruction stream; pass `None` to compute the
    /// graph half alone, which is what a caller that only has a CFG (a test, or
    /// a consumer of an imported graph) can do. `call_graph` supplies
    /// [`Self::callers_in`]; pass `None` when the whole-program graph is not
    /// available and read the resulting zero as "not measured".
    pub fn from_function(
        func: &Function,
        image: Option<&ImageCode<'_>>,
        call_graph: Option<&CallGraph>,
    ) -> Self {
        let shape = Self::shape_of(func);
        let facts = image
            .and_then(|img| img.facts(func))
            .unwrap_or_else(CodeFacts::empty);
        Self::from_parts(
            func.entry_point.value,
            func.name.clone(),
            &shape,
            &facts,
            callers_in(func, call_graph),
        )
    }

    /// Assemble a signature from a shape, stream facts, and a caller count.
    ///
    /// The seam every unit test uses: it takes no `Function`, no image and no
    /// call graph, so a shape whose MD-index was computed on paper can be
    /// turned into a signature directly.
    pub fn from_parts(
        entry_va: u64,
        name: String,
        shape: &CfgShape,
        facts: &CodeFacts,
        callers_in: u32,
    ) -> Self {
        Self {
            entry_va,
            name,
            md_index_top_down: md_index_top_down(shape),
            md_index_bottom_up: md_index_bottom_up(shape),
            md_index_relaxed: md_index_relaxed(shape),
            mnemonic_spp: facts.mnemonic_spp,
            basic_blocks: shape.block_count() as u32,
            edges: shape.edge_count() as u32,
            back_edges: shape.back_edges().len() as u32,
            loops: shape.loop_headers() as u32,
            strongly_connected_components: shape.strongly_connected_components() as u32,
            cyclomatic_complexity: shape.cyclomatic_complexity(),
            instructions: facts.instructions,
            calls_out_direct: facts.calls_out_direct,
            calls_out_indirect: facts.calls_out_indirect,
            callers_in,
            rare_constants: facts.rare_constants.clone(),
            string_refs: facts.string_refs,
        }
    }

    /// Blocks absorbed into cycles: `basic_blocks - strongly_connected_components`.
    ///
    /// Zero for an acyclic function. More discriminative than either count on
    /// its own, and it is the quantity that separates a loop nest from a long
    /// straight-line function with the same block count.
    pub fn cyclic_blocks(&self) -> u32 {
        self.basic_blocks
            .saturating_sub(self.strongly_connected_components)
    }
}

/// How many distinct callers reach `func`, per the call graph.
///
/// `analysis::cfg` keys call-graph vertices by function *name*, not by address
/// (`cfg::worklist` builds `name_by_va` and falls back to `sub_<hex>`), so this
/// counts distinct caller names. Two call sites in the same caller therefore
/// count once, which is the in-degree BinDiff's call-graph MD-index pass reads.
///
/// Falls back to `func.callers` when no graph is supplied. That set is only
/// populated where discovery folded a cold chunk into its parent, so the
/// fallback is usually 0 -- read a zero as "not measured", which is why the
/// call graph is an explicit parameter rather than something guessed at.
fn callers_in(func: &Function, call_graph: Option<&CallGraph>) -> u32 {
    match call_graph {
        Some(cg) => cg
            .edges
            .iter()
            .filter(|e| e.callee == func.name)
            .map(|e| e.caller.as_str())
            .collect::<std::collections::BTreeSet<&str>>()
            .len() as u32,
        None => func.callers.len() as u32,
    }
}

impl PartialEq for StructuralSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ord_key() == other.ord_key()
    }
}

impl Eq for StructuralSignature {}

impl PartialOrd for StructuralSignature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StructuralSignature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ord_key().cmp(&other.ord_key())
    }
}

/// Weight of the count blend in [`ranking_similarity`]. See its docs.
pub const W_COUNTS: f64 = 0.45;
/// Weight of the MD-index blend in [`ranking_similarity`].
pub const W_MD_INDEX: f64 = 0.35;
/// Weight of the mnemonic-SPP term in [`ranking_similarity`].
pub const W_SPP: f64 = 0.12;
/// Weight of the rare-constant term in [`ranking_similarity`].
pub const W_CONSTANTS: f64 = 0.08;

/// How alike two signatures are, in `[0, 1]`, for patch-diff ranking.
///
/// # The blend
///
/// ```text
/// counts   = 0.55*ratio(edges) + 0.30*ratio(blocks) + 0.15*ratio(instructions)
/// md       = mean( agree(top_down), agree(bottom_up), agree(relaxed) )
///            where agree(a,b) = 1 - |a-b| / (1 + a + b)
/// spp      = 1 when the two products are equal, else 0
/// consts   = Jaccard over the rare-constant multisets (1 when both are empty)
///
/// similarity = 0.45*counts + 0.35*md + 0.12*spp + 0.08*consts
/// ```
///
/// `ratio(a, b)` is `min/max`, and 1.0 when both are zero.
///
/// # Why these weights
///
/// The inner `counts` blend is BinDiff's own function-similarity formula,
/// verbatim: `0.55*edge_ratio + 0.30*bb_ratio + 0.15*insn_ratio` (report 03,
/// "BinExport / BinDiff"). BinDiff then averages that against a single
/// MD-index agreement, i.e. 50/50. We keep the same shape and move twenty
/// points of it onto two signals BinDiff's *score* omits even though its
/// *matcher* trusts them: `prime signature matching` runs at confidence 0.9 and
/// `string references` at 0.7 in `bindiff.json`, so both are treated there as
/// near-decisive evidence of identity while contributing nothing to the number
/// that ranks the result. The MD-index share stays the largest single term
/// because it is the only one of the four that moves smoothly with the size of
/// a control-flow edit -- SPP is a step function and the count ratios saturate.
///
/// The constant term is small on purpose. A function with no large constants is
/// common, and giving "both empty" a full 0.08 would inflate every small
/// function's score; 0.08 is enough to break a tie between two candidates that
/// agree structurally and not enough to create one.
///
/// # What it is not
///
/// Not a metric. It satisfies symmetry and identity, but nothing here
/// establishes a triangle inequality, and it must not be used as an index
/// distance. It is a ranking score, which is the use BinDiff puts its own blend
/// to.
pub fn ranking_similarity(a: &StructuralSignature, b: &StructuralSignature) -> f64 {
    let counts = 0.55 * ratio(a.edges, b.edges)
        + 0.30 * ratio(a.basic_blocks, b.basic_blocks)
        + 0.15 * ratio(a.instructions, b.instructions);

    let md = (md_index_agreement(a.md_index_top_down, b.md_index_top_down)
        + md_index_agreement(a.md_index_bottom_up, b.md_index_bottom_up)
        + md_index_agreement(a.md_index_relaxed, b.md_index_relaxed))
        / 3.0;

    let spp = if a.mnemonic_spp == b.mnemonic_spp {
        1.0
    } else {
        0.0
    };

    let consts = multiset_jaccard(&a.rare_constants, &b.rare_constants);

    (W_COUNTS * counts + W_MD_INDEX * md + W_SPP * spp + W_CONSTANTS * consts).clamp(0.0, 1.0)
}

/// `min/max` of two counts; 1.0 when both are zero.
fn ratio(a: u32, b: u32) -> f64 {
    if a == b {
        return 1.0;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    f64::from(lo) / f64::from(hi)
}

/// Jaccard over two sorted multisets: `|intersection| / |union|`, counting
/// multiplicity. 1.0 when both are empty.
fn multiset_jaccard(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let mut i = 0usize;
    let mut j = 0usize;
    let mut inter = 0usize;
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let union = a.len() + b.len() - inter;
    if union == 0 {
        return 1.0;
    }
    inter as f64 / union as f64
}

/// Compute a signature for every function discovered in `data`.
///
/// The image is parsed once and the disassembler backend selected once, then
/// reused across functions -- doing it per function is what makes a naive
/// implementation of this pass quadratic in setup cost. Results come back
/// sorted by entry address.
///
/// A function whose architecture has no decoder still gets a signature: the
/// graph half is computed from discovery's own output and the stream half comes
/// back as [`CodeFacts::empty`]. That is a real answer for CFG-shaped
/// questions and a documented zero for the rest, which is better than dropping
/// the function from the list.
pub fn structural_signatures(
    data: &[u8],
    functions: &[Function],
    call_graph: Option<&CallGraph>,
) -> Vec<StructuralSignature> {
    let image = ImageCode::new(data);
    let mut out: Vec<StructuralSignature> = functions
        .iter()
        .map(|f| StructuralSignature::from_function(f, image.as_ref(), call_graph))
        .collect();
    out.sort_by_key(|s| s.entry_va);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(shape: &CfgShape, facts: &CodeFacts) -> StructuralSignature {
        StructuralSignature::from_parts(0x1000, "f".to_string(), shape, facts, 0)
    }

    fn facts_with(instructions: u32, spp: u64, constants: Vec<u64>) -> CodeFacts {
        CodeFacts {
            instructions,
            mnemonic_spp: spp,
            calls_out_direct: 0,
            calls_out_indirect: 0,
            rare_constants: constants,
            string_refs: 0,
        }
    }

    #[test]
    fn a_signature_is_equal_to_itself_and_scores_one() {
        let shape = CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2), (0, 2)], 0);
        let f = facts_with(20, 1_234_567, vec![0x4000, 0xdead_beef]);
        let a = sig(&shape, &f);
        let b = sig(&shape, &f);
        assert_eq!(a, b);
        assert!((ranking_similarity(&a, &b) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn ordering_is_total_and_survives_a_sort() {
        let one = sig(
            &CfgShape::new(&[0, 1], &[(0, 1)], 0),
            &facts_with(2, 3, vec![]),
        );
        let two = sig(
            &CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2), (0, 2)], 0),
            &facts_with(9, 5, vec![]),
        );
        let mut v = vec![two.clone(), one.clone()];
        v.sort();
        assert_eq!(v.len(), 2);
        // Whichever order they land in, sorting is idempotent and the pair is
        // strictly ordered (they differ in every count).
        assert_ne!(v[0], v[1]);
        let mut again = v.clone();
        again.sort();
        assert_eq!(v, again);
    }

    #[test]
    fn similarity_is_symmetric() {
        let a = sig(
            &CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2)], 0),
            &facts_with(10, 7, vec![0x9999]),
        );
        let b = sig(
            &CfgShape::new(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3), (1, 3)], 0),
            &facts_with(18, 11, vec![0x9999, 0x1_0000]),
        );
        assert_eq!(ranking_similarity(&a, &b), ranking_similarity(&b, &a));
    }

    #[test]
    fn a_bigger_edit_scores_lower_than_a_smaller_one() {
        let base = CfgShape::new(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)], 0);
        let one_edge = CfgShape::new(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3), (1, 3)], 0);
        let rewritten = CfgShape::new(
            &[0, 1, 2, 3, 4, 5, 6, 7],
            &[
                (0, 1),
                (1, 2),
                (2, 3),
                (3, 4),
                (4, 5),
                (5, 6),
                (6, 7),
                (1, 7),
                (2, 6),
            ],
            0,
        );
        let f = facts_with(20, 101, vec![]);
        let a = sig(&base, &f);
        let small = sig(&one_edge, &facts_with(22, 103, vec![]));
        let big = sig(&rewritten, &facts_with(60, 107, vec![]));
        assert!(
            ranking_similarity(&a, &small) > ranking_similarity(&a, &big),
            "a one-edge change must rank as closer than a rewrite"
        );
    }

    #[test]
    fn equal_spp_contributes_exactly_its_weight() {
        let shape = CfgShape::new(&[0, 1], &[(0, 1)], 0);
        let same = sig(&shape, &facts_with(5, 42, vec![]));
        let other = sig(&shape, &facts_with(5, 43, vec![]));
        let delta = ranking_similarity(&same, &same) - ranking_similarity(&same, &other);
        assert!((delta - W_SPP).abs() < 1e-12, "SPP term should be {W_SPP}");
    }

    #[test]
    fn constant_jaccard_is_the_documented_multiset_ratio() {
        assert_eq!(multiset_jaccard(&[], &[]), 1.0);
        assert_eq!(multiset_jaccard(&[1, 2, 3], &[1, 2, 3]), 1.0);
        assert_eq!(multiset_jaccard(&[1, 2], &[3, 4]), 0.0);
        // |inter| = 1, |union| = 2 + 2 - 1 = 3
        assert!((multiset_jaccard(&[1, 2], &[2, 3]) - 1.0 / 3.0).abs() < 1e-12);
        // Multiplicity counts: {1,1} vs {1} -> inter 1, union 2.
        assert!((multiset_jaccard(&[1, 1], &[1]) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn count_ratio_treats_both_zero_as_agreement() {
        assert_eq!(ratio(0, 0), 1.0);
        assert_eq!(ratio(4, 4), 1.0);
        assert_eq!(ratio(1, 2), 0.5);
        assert_eq!(ratio(2, 1), 0.5);
    }

    #[test]
    fn total_order_bits_is_order_isomorphic() {
        let vals = [-1.0f64, -0.5, -0.0, 0.0, 0.5, 1.0, 100.0, f64::INFINITY];
        for w in vals.windows(2) {
            assert!(
                total_order_bits(w[0]) <= total_order_bits(w[1]),
                "{} should map below {}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn cyclic_blocks_counts_what_the_loops_absorbed() {
        let acyclic = sig(
            &CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2)], 0),
            &CodeFacts::empty(),
        );
        assert_eq!(acyclic.cyclic_blocks(), 0);
        let looped = sig(
            &CfgShape::new(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0),
            &CodeFacts::empty(),
        );
        // 4 blocks, 3 components ({1,2} merged) => 1 absorbed.
        assert_eq!(looped.cyclic_blocks(), 1);
        assert_eq!(looped.back_edges, 1);
        assert_eq!(looped.loops, 1);
    }

    /// JSON is a lossy transport for the MD-indices, by one unit in the last
    /// place, and this test pins that rather than hiding it.
    ///
    /// `serde_json`'s default float parser trades the last bit for speed; the
    /// exact round trip is behind its `float_roundtrip` feature, which this
    /// crate does not enable. Every integer field and the constant multiset do
    /// round-trip exactly. The consequence is scoped and named in the type's
    /// docs: JSON is a diagnostic format for these, and the two places that
    /// compare MD-indices for equality -- the KB row and the diff rematch --
    /// both go through SQLite `REAL`, which stores the IEEE-754 double
    /// verbatim, and both quantise before comparing anyway.
    #[test]
    fn serde_round_trips_to_within_one_ulp() {
        let s = sig(
            &CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2), (0, 2)], 0),
            &facts_with(11, 999, vec![0x2000, 0x3000]),
        );
        let json = serde_json::to_string(&s).expect("serialize");
        let back: StructuralSignature = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(s.entry_va, back.entry_va);
        assert_eq!(s.name, back.name);
        assert_eq!(s.mnemonic_spp, back.mnemonic_spp);
        assert_eq!(s.basic_blocks, back.basic_blocks);
        assert_eq!(s.edges, back.edges);
        assert_eq!(s.back_edges, back.back_edges);
        assert_eq!(s.loops, back.loops);
        assert_eq!(
            s.strongly_connected_components,
            back.strongly_connected_components
        );
        assert_eq!(s.cyclomatic_complexity, back.cyclomatic_complexity);
        assert_eq!(s.instructions, back.instructions);
        assert_eq!(s.rare_constants, back.rare_constants);
        assert_eq!(s.string_refs, back.string_refs);
        for (a, b) in [
            (s.md_index_top_down, back.md_index_top_down),
            (s.md_index_bottom_up, back.md_index_bottom_up),
            (s.md_index_relaxed, back.md_index_relaxed),
        ] {
            assert!(
                (a - b).abs() <= f64::EPSILON * a.abs().max(1.0),
                "{a} and {b} differ by more than one ulp"
            );
        }
    }
}
