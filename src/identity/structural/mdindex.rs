//! BinDiff's MD-index over a [`CfgShape`].
//!
//! The MD-index (Dullien, Carrera, Eppler and Porst, "Automated Attacker
//! Correlation for Malicious Code", 2010) is a graph invariant: one real number
//! per control-flow graph, unchanged by block reordering, renaming or a shift
//! in addresses, and moved by a genuine edit to the edge set. That is exactly
//! the property patch diffing wants -- a rebuild that only relinks leaves it
//! alone, while an added branch does not.
//!
//! # The formula
//!
//! Verified against `google/bindiff`'s `graph_util.h` (Apache-2.0),
//! `CalculateMdIndexInternal`, which reads verbatim:
//!
//! ```text
//! const double md_index =
//!     (sqrt(weights[0]) * in_degree_source +
//!      sqrt(weights[1]) * out_degree_source +
//!      sqrt(weights[2]) * in_degree_target +
//!      sqrt(weights[3]) * out_degree_target + sqrt(weights[4]) * level_source +
//!      sqrt(weights[5]) * level_target);
//! return 1.0 / md_index;
//! ```
//!
//! with `kDefaultWeights = {2, 3, 5, 7, 11, 13}`. Note the reciprocal is of the
//! *sum*, not of its square root -- Diaphora's `md_index` column uses
//! `1/sqrt(embedding)` over the same five-term embedding, so the two tools'
//! numbers are not interchangeable and ours follow BinDiff.
//!
//! The graph index sums the per-edge terms. **The terms are sorted before they
//! are summed**, which BinDiff's own comment explains: "Sorting the summands
//! before adding them together is important because of rounding errors."
//! Floating-point addition is not associative, so an unsorted sum makes the
//! index depend on edge enumeration order and two runs over the same function
//! can disagree in the last few bits. [`md_index`] sorts with
//! [`f64::total_cmp`], which is a total order and therefore reproducible.
//!
//! # The three variants
//!
//! | variant | weights | `level` |
//! |---|---|---|
//! | [`md_index_top_down`] | `{2,3,5,7,11,13}` | BFS from the entry |
//! | [`md_index_bottom_up`] | `{2,3,5,7,11,13}` | BFS from the exits |
//! | [`md_index_relaxed`] | `{2,3,5,7,0,0}` | dropped (`sqrt(0) == 0`) |
//!
//! Degrees do **not** swap between top-down and bottom-up: BinDiff changes only
//! which BFS numbering feeds `level_source` and `level_target`. The relaxed
//! variant is BinDiff's own level-free pass (confidence 0.7 in `bindiff.json`,
//! against 1.0 for the level-bearing one); it survives an edit that changes how
//! deep a block sits without changing the local degree structure, which is why
//! it is a separate, weaker matching pass rather than a replacement.

use super::graph::CfgShape;

/// BinDiff's `kDefaultWeights`: the first six primes under the square root.
pub const WEIGHTS_DEFAULT: [f64; 6] = [2.0, 3.0, 5.0, 7.0, 11.0, 13.0];

/// The level-free weights: `sqrt(0) == 0` removes both level terms.
pub const WEIGHTS_RELAXED: [f64; 6] = [2.0, 3.0, 5.0, 7.0, 0.0, 0.0];

/// The MD-index of `graph` under `weights`, with `levels` as the topological
/// level of each block.
///
/// Per edge `(s, t)`:
///
/// ```text
/// 1 / ( sqrt(w0)*indeg(s) + sqrt(w1)*outdeg(s)
///     + sqrt(w2)*indeg(t) + sqrt(w3)*outdeg(t)
///     + sqrt(w4)*level(s) + sqrt(w5)*level(t) )
/// ```
///
/// The terms are collected, sorted by [`f64::total_cmp`], and then summed, so
/// the result does not depend on the order edges were enumerated in.
///
/// An edge whose denominator is zero contributes nothing. BinDiff asserts the
/// denominator is non-zero and would divide by it in a release build; the case
/// is reachable here -- a single isolated self-loop under the relaxed weights
/// has in-degree and out-degree summing to a non-zero value, but a
/// zero-degree-on-both-ends edge cannot exist, so in practice this guard fires
/// only for a caller that hand-built an inconsistent shape. Skipping is the
/// only choice that keeps the result finite.
pub fn md_index(graph: &CfgShape, levels: &[u32], weights: &[f64; 6]) -> f64 {
    let w: [f64; 6] = [
        weights[0].sqrt(),
        weights[1].sqrt(),
        weights[2].sqrt(),
        weights[3].sqrt(),
        weights[4].sqrt(),
        weights[5].sqrt(),
    ];
    let mut terms: Vec<f64> = Vec::with_capacity(graph.edge_count());
    for &(s, t) in graph.edges() {
        let denom = w[0] * f64::from(graph.in_degree(s))
            + w[1] * f64::from(graph.out_degree(s))
            + w[2] * f64::from(graph.in_degree(t))
            + w[3] * f64::from(graph.out_degree(t))
            + w[4] * f64::from(levels[s])
            + w[5] * f64::from(levels[t]);
        if denom == 0.0 {
            continue;
        }
        terms.push(1.0 / denom);
    }
    terms.sort_by(|a, b| a.total_cmp(b));
    terms.iter().sum()
}

/// The top-down MD-index: default weights, BFS levels from the entry.
pub fn md_index_top_down(graph: &CfgShape) -> f64 {
    md_index(graph, &graph.levels_top_down(), &WEIGHTS_DEFAULT)
}

/// The bottom-up MD-index: default weights, BFS levels from the exit blocks.
pub fn md_index_bottom_up(graph: &CfgShape) -> f64 {
    md_index(graph, &graph.levels_bottom_up(), &WEIGHTS_DEFAULT)
}

/// The relaxed MD-index: weights `{2,3,5,7,0,0}`, so levels drop out entirely.
pub fn md_index_relaxed(graph: &CfgShape) -> f64 {
    md_index(graph, &vec![0u32; graph.block_count()], &WEIGHTS_RELAXED)
}

/// BinDiff's agreement between two MD-indices: `1 - |a - b| / (1 + a + b)`.
///
/// 1.0 when the two are equal, falling towards 0 as they diverge, and bounded
/// in `[0, 1]` for non-negative inputs. The `1 +` in the denominator is what
/// keeps a pair of tiny indices (two two-block functions) from reading as
/// wildly different because their absolute difference is large relative to
/// their magnitude.
pub fn md_index_agreement(a: f64, b: f64) -> f64 {
    let denom = 1.0 + a + b;
    if denom <= 0.0 {
        return 0.0;
    }
    (1.0 - (a - b).abs() / denom).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!(
            (a - b).abs() < 1e-12,
            "expected {b} (+/- 1e-12), computed {a}"
        );
    }

    /// A single edge `0 -> 1`.
    ///
    /// Degrees: indeg(0)=0, outdeg(0)=1, indeg(1)=1, outdeg(1)=0.
    /// Top-down levels: 0 is the only in-degree-0 vertex so level(0)=0,
    /// level(1)=1. Bottom-up: 1 is the only out-degree-0 vertex so level(1)=0,
    /// level(0)=1.
    ///
    /// top-down denominator = sqrt3*1 + sqrt5*1 + sqrt13*1
    ///                      = 1.7320508075688772 + 2.23606797749979
    ///                        + 3.605551275463989 = 7.573670060532656
    /// bottom-up denominator = sqrt3*1 + sqrt5*1 + sqrt11*1
    ///                      = 1.7320508075688772 + 2.23606797749979
    ///                        + 3.3166247903554 = 7.284743575424068
    /// relaxed denominator   = sqrt3*1 + sqrt5*1 = 3.968118785068667
    #[test]
    fn single_edge_matches_the_hand_computed_value() {
        let g = CfgShape::new(&[0, 1], &[(0, 1)], 0);
        let s3 = 3f64.sqrt();
        let s5 = 5f64.sqrt();
        let s11 = 11f64.sqrt();
        let s13 = 13f64.sqrt();
        approx(md_index_top_down(&g), 1.0 / (s3 + s5 + s13));
        approx(md_index_bottom_up(&g), 1.0 / (s3 + s5 + s11));
        approx(md_index_relaxed(&g), 1.0 / (s3 + s5));
    }

    /// A triangle: `0 -> 1`, `1 -> 2`, `0 -> 2`.
    ///
    /// Degrees: indeg = [0, 1, 2], outdeg = [2, 1, 0].
    /// Top-down levels = [0, 1, 1]; bottom-up levels = [1, 1, 0].
    ///
    /// Top-down, per edge:
    ///   (0,1): sqrt2*0 + sqrt3*2 + sqrt5*1 + sqrt7*1 + sqrt11*0 + sqrt13*1
    ///   (0,2): sqrt2*0 + sqrt3*2 + sqrt5*2 + sqrt7*0 + sqrt11*0 + sqrt13*1
    ///   (1,2): sqrt2*1 + sqrt3*1 + sqrt5*2 + sqrt7*0 + sqrt11*1 + sqrt13*1
    #[test]
    fn triangle_matches_the_hand_computed_value() {
        let g = CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2), (0, 2)], 0);
        let s2 = 2f64.sqrt();
        let s3 = 3f64.sqrt();
        let s5 = 5f64.sqrt();
        let s7 = 7f64.sqrt();
        let s11 = 11f64.sqrt();
        let s13 = 13f64.sqrt();

        let e01 = 1.0 / (s3 * 2.0 + s5 + s7 + s13);
        let e02 = 1.0 / (s3 * 2.0 + s5 * 2.0 + s13);
        let e12 = 1.0 / (s2 + s3 + s5 * 2.0 + s11 + s13);
        let mut terms = [e01, e02, e12];
        terms.sort_by(|a, b| a.total_cmp(b));
        approx(md_index_top_down(&g), terms.iter().sum());

        // Bottom-up: levels = [1, 1, 0].
        let b01 = 1.0 / (s3 * 2.0 + s5 + s7 + s11 + s13);
        let b02 = 1.0 / (s3 * 2.0 + s5 * 2.0 + s11);
        let b12 = 1.0 / (s2 + s3 + s5 * 2.0 + s11);
        let mut bterms = [b01, b02, b12];
        bterms.sort_by(|a, b| a.total_cmp(b));
        approx(md_index_bottom_up(&g), bterms.iter().sum());

        // Relaxed: both level terms vanish.
        let r01 = 1.0 / (s3 * 2.0 + s5 + s7);
        let r02 = 1.0 / (s3 * 2.0 + s5 * 2.0);
        let r12 = 1.0 / (s2 + s3 + s5 * 2.0);
        let mut rterms = [r01, r02, r12];
        rterms.sort_by(|a, b| a.total_cmp(b));
        approx(md_index_relaxed(&g), rterms.iter().sum());
    }

    #[test]
    fn empty_and_edgeless_graphs_are_zero() {
        let empty = CfgShape::new(&[], &[], 0);
        assert_eq!(md_index_top_down(&empty), 0.0);
        let one = CfgShape::new(&[0x10], &[], 0x10);
        assert_eq!(md_index_top_down(&one), 0.0);
        assert_eq!(md_index_bottom_up(&one), 0.0);
        assert_eq!(md_index_relaxed(&one), 0.0);
    }

    #[test]
    fn index_is_invariant_to_block_addresses() {
        let a = CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2), (0, 2)], 0);
        let b = CfgShape::new(
            &[0x4000, 0x4010, 0x4020],
            &[(0x4000, 0x4010), (0x4010, 0x4020), (0x4000, 0x4020)],
            0x4000,
        );
        assert_eq!(md_index_top_down(&a), md_index_top_down(&b));
        assert_eq!(md_index_bottom_up(&a), md_index_bottom_up(&b));
        assert_eq!(md_index_relaxed(&a), md_index_relaxed(&b));
    }

    #[test]
    fn index_is_invariant_to_the_order_edges_were_given_in() {
        let a = CfgShape::new(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3), (1, 3)], 0);
        let b = CfgShape::new(&[3, 1, 0, 2], &[(1, 3), (2, 3), (1, 2), (0, 1)], 0);
        assert_eq!(
            md_index_top_down(&a).to_bits(),
            md_index_top_down(&b).to_bits()
        );
    }

    #[test]
    fn an_added_edge_moves_the_index() {
        let a = CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let b = CfgShape::new(&[0, 1, 2], &[(0, 1), (1, 2), (0, 2)], 0);
        assert_ne!(md_index_top_down(&a), md_index_top_down(&b));
    }

    #[test]
    fn top_down_and_bottom_up_separate_a_mirrored_shape() {
        // A fan-out (one block branching to three) and a fan-in (three blocks
        // joining one) have the same relaxed index but different levels.
        let fan_out = CfgShape::new(&[0, 1, 2, 3], &[(0, 1), (0, 2), (0, 3)], 0);
        let fan_in = CfgShape::new(&[0, 1, 2, 3], &[(0, 3), (1, 3), (2, 3)], 0);
        assert_ne!(
            md_index_top_down(&fan_out),
            md_index_top_down(&fan_in),
            "levels should separate a fan-out from a fan-in"
        );
    }

    #[test]
    fn agreement_is_one_on_equal_indices_and_falls_off() {
        approx(md_index_agreement(1.5, 1.5), 1.0);
        approx(md_index_agreement(0.0, 0.0), 1.0);
        assert!(md_index_agreement(1.0, 5.0) < md_index_agreement(1.0, 2.0));
        assert!(md_index_agreement(1.0, 100.0) >= 0.0);
    }
}
