//! Point-in-body lookups over the functions discovered so far.
//!
//! The worklist loop asks two questions about every seed it pops, and once more
//! about every call/jump target of every function it discovers:
//!
//! * does `va` fall strictly inside a body some other function already owns?
//!   ([`super::va_in_discovered_body`])
//! * is `va` a basic-block leader some other function already owns?
//!   ([`super::va_is_discovered_block_leader`])
//!
//! Both were answered by scanning the whole result vector and, inside it, every
//! basic block of every function -- so the cost of one question grew with the
//! answer set, and the loop asks a question per seed. On
//! `win10-webservices.dll` (1.39 MB, 4,382 functions, 49,917 blocks) that pair
//! of scans was 2.35 s of a 5.12 s analysis: 4,616 seeds times ~50,000 blocks
//! is 146 million interval tests to answer 4,616 yes/no questions.
//!
//! This index answers both in O(1) by keeping the counts instead of recomputing
//! them. `cover[va]` is how many owned intervals contain `va`; `leaders[va]` is
//! how many owned blocks start there. Neither counter can answer the question
//! on its own, because both callers exclude the function whose *entry* is `va`
//! -- so the query subtracts that one function's own contribution, found
//! through `by_entry` in O(1) rather than by searching. The identity being
//! preserved is exactly:
//!
//! ```text
//! exists f in functions: f.entry != va && f covers va
//!   <=>  (intervals covering va) > (intervals covering va owned by entry va)
//! ```
//!
//! Painting is O(bytes of the function being added), so the whole run pays
//! O(code size) for insertion instead of O(seeds x blocks) for queries.
//!
//! Two exact fallbacks keep this from ever being an approximation: a query for
//! a VA outside the executable window, and a saturated `u8` counter, both defer
//! to the original linear scan. Neither is reachable on a real binary -- every
//! caller range-checks the VA first, and saturation needs 255 function bodies
//! over one byte -- but they mean the index cannot answer differently from the
//! scan it replaces even if one were.

use super::*;

/// The interval set a function contributes, mirroring [`super::va_in_function_body`]
/// exactly: basic blocks when it has them (strictly inside, so `[start+1, end)`),
/// otherwise its declared ranges (`[start, start+size)`).
fn for_each_interval(func: &Function, mut visit: impl FnMut(u64, u64)) {
    if !func.basic_blocks.is_empty() {
        for block in &func.basic_blocks {
            let lo = block.start_address.value.saturating_add(1);
            let hi = block.end_address.value;
            if lo < hi {
                visit(lo, hi);
            }
        }
        return;
    }
    for range in func.all_ranges() {
        let lo = range.start.value;
        let hi = lo.saturating_add(range.size);
        if lo < hi {
            visit(lo, hi);
        }
    }
}

fn intervals_covering(func: &Function, va: u64) -> u32 {
    let mut count = 0u32;
    for_each_interval(func, |lo, hi| {
        if va >= lo && va < hi {
            count = count.saturating_add(1);
        }
    });
    count
}

/// An executable window larger than this is left to the linear fallback rather
/// than allocating a byte per address. Real images are three orders of
/// magnitude under it; a synthetic one with a 128 MB executable span gets the
/// old behaviour instead of a 128 MB allocation.
const MAX_WINDOW_BYTES: u64 = 128 << 20;

pub(super) struct BodyIndex {
    base: u64,
    /// Number of owned intervals covering each byte of the executable window,
    /// saturating: 255 means "at least 255", which sends the query to the exact
    /// fallback rather than risking an off-by-saturation answer.
    cover: Vec<u8>,
    /// `block start VA -> how many owned blocks start there`.
    leaders: std::collections::HashMap<u64, u32>,
    /// `entry VA -> indices into the caller's function vector`. A `Vec` because
    /// nothing forbids two discovered functions sharing an entry.
    by_entry: std::collections::HashMap<u64, Vec<u32>>,
}

impl BodyIndex {
    /// An index spanning every executable region, or a disabled one (pure
    /// fallback) when there are none or the span is implausible.
    pub(super) fn new(regions: &[ExecRegion]) -> Self {
        let lo = regions.iter().map(|r| r.start).min().unwrap_or(0);
        let hi = regions.iter().map(|r| r.end).max().unwrap_or(0);
        let span = hi.saturating_sub(lo);
        let cover = if span == 0 || span > MAX_WINDOW_BYTES {
            Vec::new()
        } else {
            vec![0u8; span as usize]
        };
        Self {
            base: lo,
            cover,
            leaders: std::collections::HashMap::new(),
            by_entry: std::collections::HashMap::new(),
        }
    }

    /// A disabled index: every query defers to the linear scan. Used by the
    /// unit tests that exercise `cap_discovered_functions_at_va` directly.
    #[cfg(test)]
    pub(super) fn disabled() -> Self {
        Self {
            base: 0,
            cover: Vec::new(),
            leaders: std::collections::HashMap::new(),
            by_entry: std::collections::HashMap::new(),
        }
    }

    fn slot(&self, va: u64) -> Option<usize> {
        if self.cover.is_empty() {
            return None;
        }
        let offset = va.checked_sub(self.base)?;
        usize::try_from(offset)
            .ok()
            .filter(|i| *i < self.cover.len())
    }

    /// Add or subtract one function's geometry. Intervals are clamped to the
    /// window: a byte outside it is only ever *queried* through the fallback,
    /// which reads the functions themselves, so dropping it here cannot change
    /// an answer.
    fn paint(&mut self, func: &Function, add: bool) {
        if self.cover.is_empty() {
            return;
        }
        let base = self.base;
        let len = self.cover.len() as u64;
        let cover = &mut self.cover;
        for_each_interval(func, |lo, hi| {
            let lo = lo.saturating_sub(base).min(len);
            let hi = hi.saturating_sub(base).min(len);
            for slot in &mut cover[lo as usize..hi as usize] {
                *slot = if add {
                    slot.saturating_add(1)
                } else {
                    slot.saturating_sub(1)
                };
            }
        });
    }

    fn count_leaders(&mut self, func: &Function, add: bool) {
        for block in &func.basic_blocks {
            let entry = self.leaders.entry(block.start_address.value).or_insert(0);
            *entry = if add {
                entry.saturating_add(1)
            } else {
                entry.saturating_sub(1)
            };
        }
    }

    /// Record a newly discovered function at `index` in the caller's vector.
    pub(super) fn insert(&mut self, index: usize, func: &Function) {
        self.by_entry
            .entry(func.entry_point.value)
            .or_default()
            .push(index as u32);
        self.count_leaders(func, true);
        self.paint(func, true);
    }

    /// Withdraw a function's geometry before it is mutated in place. Its entry
    /// registration survives, because capping never moves an entry point.
    pub(super) fn unpaint(&mut self, func: &Function) {
        self.count_leaders(func, false);
        self.paint(func, false);
    }

    /// Re-add the geometry withdrawn by [`Self::unpaint`].
    pub(super) fn repaint(&mut self, func: &Function) {
        self.count_leaders(func, true);
        self.paint(func, true);
    }

    /// How many of the intervals covering `va` belong to a function whose entry
    /// point IS `va` -- the contribution both callers exclude.
    fn own_cover(&self, functions: &[Function], va: u64) -> u32 {
        self.by_entry.get(&va).map_or(0, |indices| {
            indices
                .iter()
                .filter_map(|index| functions.get(*index as usize))
                .map(|func| intervals_covering(func, va))
                .sum()
        })
    }

    /// [`super::va_in_discovered_body`] with `current: None`, in O(1).
    pub(super) fn contains_body(&self, functions: &[Function], va: u64) -> bool {
        let Some(slot) = self.slot(va) else {
            return va_in_discovered_body(functions, None, va);
        };
        let total = self.cover[slot];
        if total == 0 {
            return false;
        }
        if total == u8::MAX {
            return va_in_discovered_body(functions, None, va);
        }
        u32::from(total) > self.own_cover(functions, va)
    }

    /// [`super::va_is_discovered_block_leader`], in O(1).
    pub(super) fn is_block_leader(&self, functions: &[Function], va: u64) -> bool {
        if self.cover.is_empty() {
            return va_is_discovered_block_leader(functions, va);
        }
        let Some(&total) = self.leaders.get(&va) else {
            return false;
        };
        if total == 0 {
            return false;
        }
        let own: u32 = self.by_entry.get(&va).map_or(0, |indices| {
            indices
                .iter()
                .filter_map(|index| functions.get(*index as usize))
                .map(|func| {
                    func.basic_blocks
                        .iter()
                        .filter(|block| block.start_address.value == va)
                        .count() as u32
                })
                .sum()
        });
        total > own
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, size: u64) -> AddressRange {
        let address = Address::new(AddressKind::VA, start, 64, None, None).unwrap();
        AddressRange::new(address, size, None).unwrap()
    }

    fn func(entry_va: u64, blocks: &[(u64, u64)], chunks: &[(u64, u64)]) -> Function {
        let entry = Address::new(AddressKind::VA, entry_va, 64, None, None).unwrap();
        let mut function =
            Function::new(format!("sub_{entry_va:x}"), entry, FunctionKind::Normal).unwrap();
        for (start, end) in blocks {
            let start_address = Address::new(AddressKind::VA, *start, 64, None, None).unwrap();
            let end_address = Address::new(AddressKind::VA, *end, 64, None, None).unwrap();
            function.basic_blocks.push(BasicBlock::new(
                format!("bb_{start:x}"),
                start_address,
                end_address,
                1,
                None,
                None,
            ));
        }
        for (start, size) in chunks {
            function.add_chunk(range(*start, *size));
        }
        function
    }

    fn regions() -> Vec<ExecRegion> {
        vec![ExecRegion {
            start: 0x1000,
            end: 0x9000,
            _file_off_start: 0,
        }]
    }

    /// The index must agree with the scan it replaces on every address of the
    /// window, not merely on the ones a caller happens to ask about.
    #[test]
    fn index_agrees_with_the_linear_scan_everywhere() {
        let functions = vec![
            func(0x1000, &[(0x1000, 0x1040), (0x1040, 0x1080)], &[]),
            func(0x2000, &[], &[(0x2000, 0x80)]),
            // Deliberately overlapping: a second owner over the same bytes.
            func(0x1030, &[(0x1020, 0x1060)], &[]),
        ];
        let mut index = BodyIndex::new(&regions());
        for (position, function) in functions.iter().enumerate() {
            index.insert(position, function);
        }
        for va in 0x1000u64..0x2100 {
            assert_eq!(
                index.contains_body(&functions, va),
                va_in_discovered_body(&functions, None, va),
                "contains_body disagrees at {va:#x}"
            );
            assert_eq!(
                index.is_block_leader(&functions, va),
                va_is_discovered_block_leader(&functions, va),
                "is_block_leader disagrees at {va:#x}"
            );
        }
    }

    /// A function's own entry is never "inside its own body", but a *different*
    /// function's body covering that same address is. Getting this wrong would
    /// silently drop or admit seeds, so it is asserted on its own.
    #[test]
    fn entry_of_one_function_inside_another_body_is_still_covered() {
        let functions = vec![
            func(0x1000, &[(0x1000, 0x1100)], &[]),
            func(0x1040, &[(0x1040, 0x1080)], &[]),
        ];
        let mut index = BodyIndex::new(&regions());
        for (position, function) in functions.iter().enumerate() {
            index.insert(position, function);
        }
        // 0x1040 is the second function's entry and strictly inside the first.
        assert!(index.contains_body(&functions, 0x1040));
        assert_eq!(
            index.contains_body(&functions, 0x1040),
            va_in_discovered_body(&functions, None, 0x1040)
        );
        // Only owner is the function entered here, so it is not "in a body".
        assert!(!index.contains_body(&functions, 0x1000));
    }

    #[test]
    fn unpaint_then_repaint_restores_the_counts() {
        let functions = vec![func(0x1000, &[(0x1000, 0x1100)], &[])];
        let mut index = BodyIndex::new(&regions());
        index.insert(0, &functions[0]);
        assert!(index.contains_body(&functions, 0x1080));
        index.unpaint(&functions[0]);
        assert!(!index.contains_body(&functions, 0x1080));
        index.repaint(&functions[0]);
        assert!(index.contains_body(&functions, 0x1080));
    }

    /// A VA outside the executable window has no slot, so the query must fall
    /// back to the exact scan rather than reporting "not covered".
    #[test]
    fn a_va_outside_the_window_falls_back_to_the_scan() {
        let functions = vec![func(0x40000, &[(0x40000, 0x40100)], &[])];
        let mut index = BodyIndex::new(&regions());
        index.insert(0, &functions[0]);
        assert!(index.slot(0x40080).is_none());
        assert_eq!(
            index.contains_body(&functions, 0x40080),
            va_in_discovered_body(&functions, None, 0x40080)
        );
        assert!(index.contains_body(&functions, 0x40080));
    }
}
