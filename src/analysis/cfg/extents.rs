//! Declared function extents, and what they prove about a heuristic seed.
//!
//! Discovery already refuses a heuristic seed that lands inside a function it
//! has *walked* ([`super::body_index::va_in_discovered_body`]). That gate is
//! blind to the one case that matters most on C++ code, because it reasons
//! about reachable blocks and a **landing pad is not reachable**: the unwinder
//! arrives by indirect jump from outside the CFG, so no walk of the parent ever
//! covers it.
//!
//! `136_cpp_exception_unwinding:gcc:O0` is the worked example. Its FDE table
//! declares `cpp_destructors_run_while_unwinding` as `0x13f0..0x1558`. At
//! `0x14f0`, strictly inside that range, sits
//!
//! ```text
//!   14f0:  f3 0f 1e fa    endbr64            <- CET lands the unwinder here
//!   14f4:  48 89 c3       mov %rax,%rbx
//!   14f7:  48 8d 45 d0    lea -0x30(%rbp),%rax
//! ```
//!
//! which is a textbook prologue head — `endbr64` opens essentially every
//! function in a current distro build — so the prologue scan proposes it, the
//! discovered-body gate finds no covering blocks, and it becomes `sub_14f0`.
//! Emitted as a standalone function it *must* read an undefined value: the
//! `-0x30(%rbp)` it dereferences belongs to the parent's frame. That single
//! false function is why the def-before-use census moved `gcc:O0` by one.
//!
//! The evidence to reject it was already loaded and simply never consulted.
//! This module consults it.
//!
//! # Why an FDE is not always a function
//!
//! `.eh_frame` describes *unwind* ranges, and the linker emits **one FDE for the
//! whole `.plt`** (and `.plt.got`, and `.plt.sec`) rather than one per stub. In
//! the same fixture those are `0x1020..0x10a0`, `0x10a0..0x10b0` and
//! `0x10b0..0x1120` — three FDEs covering fourteen 16-byte import stubs, every
//! one of which is a genuine function that discovery must keep. Taking such a
//! range at face value cost six of them on the first attempt here (22 emitted
//! functions fell to 15, not 21).
//!
//! So a range that overlaps a known PLT stub range is describing a section and
//! declares nothing. That exclusion is exact rather than heuristic: the PLT
//! bounds come from the section table the same parse produced.
//!
//! # Why this does not cost recall
//!
//! Extents come from `.eh_frame`, so a binary with no unwind tables declares no
//! extents and nothing here fires. That is exactly the population the prologue
//! scan exists for — hand-written assembly, `-fno-asynchronous-unwind-tables`
//! builds, the stripped/sstripped lanes — and it is untouched. This only ever
//! removes a candidate that some *other* function has already claimed by
//! declaration, which is a claim discovery is not entitled to override with a
//! byte pattern.

use std::collections::HashMap;

/// Function ranges some authority has declared, sorted for containment queries.
pub(super) struct DeclaredExtents {
    /// `[start, end)` sorted by `start`.
    ranges: Vec<(u64, u64)>,
}

impl DeclaredExtents {
    /// Build from the `.eh_frame` map that discovery already computes.
    ///
    /// Two kinds of range are dropped:
    ///
    /// * Degenerate ones (`end <= start`) — they cannot contain anything, and
    ///   keeping them would only widen the binary search's answer set.
    /// * Any range overlapping `plt_stub_ranges`, because a PLT FDE covers a
    ///   whole section of import stubs rather than one function. See the module
    ///   docstring for what including them cost.
    pub(super) fn from_eh_frame(
        extent: &HashMap<u64, u64>,
        plt_stub_ranges: &[std::ops::Range<u64>],
    ) -> Self {
        let overlaps_plt = |start: u64, end: u64| {
            plt_stub_ranges
                .iter()
                .any(|plt| start < plt.end && plt.start < end)
        };
        let mut ranges: Vec<(u64, u64)> = extent
            .iter()
            .map(|(start, end)| (*start, *end))
            .filter(|(start, end)| *end > *start && !overlaps_plt(*start, *end))
            .collect();
        ranges.sort_unstable();
        Self { ranges }
    }

    /// The start of a declared function that contains `va` **strictly inside**.
    ///
    /// Strictly: a candidate that equals a declared start is that function, not
    /// an intrusion into it, and must be allowed through — rejecting it would
    /// delete real functions rather than false ones.
    ///
    /// Only the greatest start `<= va` is examined. FDE ranges do not overlap —
    /// the unwinder requires a unique FDE per PC, so two covering an address
    /// would be a malformed table — which makes that candidate the only one.
    pub(super) fn containing_start(&self, va: u64) -> Option<u64> {
        let above = self.ranges.partition_point(|(start, _)| *start <= va);
        let (start, end) = *self.ranges.get(above.checked_sub(1)?)?;
        (start < va && va < end).then_some(start)
    }

    /// How many ranges are declared. Zero means this gate cannot fire.
    pub(super) fn len(&self) -> usize {
        self.ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extents(pairs: &[(u64, u64)]) -> DeclaredExtents {
        DeclaredExtents::from_eh_frame(&pairs.iter().copied().collect(), &[])
    }

    fn extents_with_plt(pairs: &[(u64, u64)], plt: &[std::ops::Range<u64>]) -> DeclaredExtents {
        DeclaredExtents::from_eh_frame(&pairs.iter().copied().collect(), plt)
    }

    #[test]
    fn the_landing_pad_that_motivated_this_is_rejected() {
        // The real FDE table of 136_cpp_exception_unwinding:gcc:O0, and the
        // real address the prologue scan proposed inside it.
        let e = extents(&[
            (0x1239, 0x1337),
            (0x1337, 0x13f0),
            (0x13f0, 0x1558),
            (0x1558, 0x1650),
        ]);
        assert_eq!(e.containing_start(0x14f0), Some(0x13f0));
    }

    #[test]
    fn a_declared_start_is_not_inside_itself() {
        // The whole point of "strictly": every real function in the table is a
        // start, and this must never reject one.
        let e = extents(&[(0x1337, 0x13f0), (0x13f0, 0x1558)]);
        assert_eq!(e.containing_start(0x13f0), None);
        assert_eq!(e.containing_start(0x1337), None);
    }

    #[test]
    fn the_exclusive_end_belongs_to_the_next_function() {
        let e = extents(&[(0x1000, 0x1100)]);
        assert_eq!(e.containing_start(0x1100), None);
        assert_eq!(e.containing_start(0x10ff), Some(0x1000));
    }

    #[test]
    fn an_address_in_no_declared_range_is_free() {
        // The stripped case in miniature: nothing declared here, so nothing is
        // rejected, and prologue recall is unaffected.
        let e = extents(&[(0x1000, 0x1100)]);
        assert_eq!(e.containing_start(0x2000), None);
        assert_eq!(e.containing_start(0x0900), None);
        assert_eq!(extents(&[]).containing_start(0x1050), None);
    }

    #[test]
    fn a_gap_between_two_ranges_is_free() {
        // Alignment padding between functions is declared by neither.
        let e = extents(&[(0x1000, 0x1100), (0x1200, 0x1300)]);
        assert_eq!(e.containing_start(0x1150), None);
        assert_eq!(e.containing_start(0x1250), Some(0x1200));
    }

    #[test]
    fn a_degenerate_range_contains_nothing() {
        let e = extents(&[(0x1000, 0x1000), (0x1200, 0x1100)]);
        assert_eq!(e.len(), 0);
        assert_eq!(e.containing_start(0x1000), None);
    }

    #[test]
    fn a_section_wide_plt_fde_declares_nothing() {
        // The real `.plt`, `.plt.got` and `.plt.sec` FDEs of the same fixture,
        // and the real stub addresses inside them. Every one of these is a
        // function; taking the FDE at face value deleted six of them.
        let e = extents_with_plt(
            &[
                (0x1020, 0x10a0),
                (0x10a0, 0x10b0),
                (0x10b0, 0x1120),
                (0x13f0, 0x1558),
            ],
            &[0x1020..0x10a0, 0x10a0..0x10b0, 0x10b0..0x1120],
        );
        for stub in [0x1030, 0x1040, 0x1090, 0x10c0, 0x1110] {
            assert_eq!(e.containing_start(stub), None, "stub {stub:#x} rejected");
        }
        // ...and the real function's extent still does its job.
        assert_eq!(e.containing_start(0x14f0), Some(0x13f0));
    }

    #[test]
    fn a_plt_range_only_excludes_what_it_overlaps() {
        // Partial overlap counts: a range that merely touches the PLT is still
        // not a trustworthy function extent, and the alternative — keeping it —
        // is the failure mode that deletes real stubs.
        let e = extents_with_plt(&[(0x1000, 0x2000), (0x3000, 0x4000)], &[0x1ff0..0x1ff8]);
        assert_eq!(e.containing_start(0x1500), None);
        assert_eq!(e.containing_start(0x3500), Some(0x3000));
    }

    #[test]
    fn lookup_does_not_depend_on_map_iteration_order() {
        // `from_eh_frame` reads a HashMap, whose order varies per run; the
        // sort is what makes the binary search correct, and this fails if it
        // is ever dropped.
        let forward = extents(&[(0x1000, 0x1100), (0x1200, 0x1300), (0x1400, 0x1500)]);
        let reverse = extents(&[(0x1400, 0x1500), (0x1200, 0x1300), (0x1000, 0x1100)]);
        for va in [0x1050, 0x1250, 0x1450, 0x1150, 0x1000] {
            assert_eq!(forward.containing_start(va), reverse.containing_start(va));
        }
    }
}
