//! Weisfeiler-Lehman relabelling, and the reason the result is a metric.
//!
//! The 1-dimensional WL kernel counts matching refined labels at each of `h`
//! iterations. It is an inner product between *explicit* feature vectors --
//! counts of WL labels -- so it is positive semi-definite by construction, and
//! therefore `d(a, b) = sqrt(k(a,a) + k(b,b) - 2k(a,b))` is a genuine
//! pseudo-metric: a metric on the WL-feature equivalence classes. It satisfies
//! the triangle inequality exactly, deterministically, in time linear in the
//! edge count and in `h`. Approximate graph edit distance offers none of that.
//!
//! The guarantee is one-sided, and it is worth stating plainly: equal graphs
//! give equal features, and different features prove the graphs differ, but
//! equal features do not prove the graphs are the same. 1-WL cannot distinguish
//! every pair of non-isomorphic graphs. It matters less here than in chemistry,
//! where the graphs are unlabelled: a CFR-G node carries a six-field label, and
//! the labels do most of the discrimination.
//!
//! # Where the numbers come from
//!
//! Three iterations over the dataflow graph, one over the block graph. Both are
//! BSim's, which is the only design in the survey with a decade of production
//! use behind the choice.

use super::commutativity::Mixing;
use super::graph::CfrGraph;

/// Weisfeiler-Lehman iterations over the dataflow graph.
pub const DATAFLOW_ITERATIONS: usize = 3;

/// Compress a label's canonical encoding into 64 bits with BLAKE3.
///
/// BLAKE3 rather than a cheap non-cryptographic mixer because these labels are
/// the identity: two different label encodings colliding is two different
/// functions reported as one, and unlike a false negative, that failure is
/// silent. The truncation to 64 bits (and later to 32 for the stored feature)
/// reintroduces collisions at a rate the birthday bound makes calculable, which
/// is exactly the property a corpus-scale index needs.
pub fn compress(bytes: &[u8]) -> u64 {
    let digest = blake3::hash(bytes);
    u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("32-byte digest"))
}

/// Mix two 64-bit values into one, order-dependently.
///
/// SplitMix64's finaliser applied to a rotate-and-xor combination: cheap, has
/// no fixed points at zero, and avalanches. Used only *inside* a round, where a
/// collision costs one wrong feature rather than a wrong identity; the round's
/// result is recompressed with BLAKE3 before it becomes a label.
fn mix(a: u64, b: u64) -> u64 {
    // The odd constant is xored in unconditionally so `mix(0, 0)` is not zero.
    // Without it a node with one zero-labelled input accumulates to the same
    // value as a node with no inputs at all, and an empty neighbourhood is not
    // the same fact as a neighbourhood of one.
    let mut x = a.rotate_left(29) ^ b.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x517c_c1b7_2722_0a95;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// The refined label of every node at every iteration, `labels[i][node]`.
///
/// `labels[0]` is the seed -- the compressed label tuple, before any
/// neighbourhood is consulted. There are `iterations + 1` rows.
pub fn refine(graph: &CfrGraph, iterations: usize) -> Vec<Vec<u64>> {
    let nodes = graph.nodes();
    let mut rows: Vec<Vec<u64>> = Vec::with_capacity(iterations + 1);
    let seed: Vec<u64> = nodes
        .iter()
        .map(|node| compress(node.label.encode().as_bytes()))
        .collect();
    rows.push(seed);

    for iteration in 1..=iterations {
        let previous = &rows[iteration - 1];
        let mut next = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            let accumulated = match node.mixing {
                // Order-independent: a multiset sum, so two identical inputs
                // still count twice (an XOR would cancel them).
                Mixing::Commutative => node.inputs.iter().fold(0u64, |accumulated, edge| {
                    accumulated.wrapping_add(mix(
                        u64::from(edge.kind.tag()),
                        previous[edge.target as usize],
                    ))
                }),
                // Order-dependent: the operand position is folded in, which is
                // what keeps `a - b` and `b - a` apart.
                Mixing::Positional => node.inputs.iter().fold(0u64, |accumulated, edge| {
                    let tagged = mix(
                        u64::from(edge.position) << 8 | u64::from(edge.kind.tag()),
                        previous[edge.target as usize],
                    );
                    mix(accumulated, tagged)
                }),
            };
            let mut buffer = [0u8; 24];
            buffer[..8].copy_from_slice(&previous[index].to_le_bytes());
            buffer[8..16].copy_from_slice(&accumulated.to_le_bytes());
            buffer[16..].copy_from_slice(&(iteration as u64).to_le_bytes());
            next.push(compress(&buffer));
        }
        rows.push(next);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mixer_is_order_sensitive_and_has_no_zero_fixed_point() {
        assert_ne!(mix(1, 2), mix(2, 1));
        assert_ne!(mix(0, 0), 0);
    }

    #[test]
    fn compression_is_stable_across_calls() {
        assert_eq!(
            compress(b"add|w64|2|derived|-|-"),
            compress(b"add|w64|2|derived|-|-")
        );
        assert_ne!(
            compress(b"add|w64|2|derived|-|-"),
            compress(b"sub|w64|2|derived|-|-")
        );
    }
}
