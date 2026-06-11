//! Sparse, paged byte-addressed memory, generic over the value [`Domain`].
//!
//! Memory is a map of 4 KiB pages; each page is an array of `Domain::Val` bytes
//! (width 8, unset = zero). Multi-byte loads/stores assemble/split through the
//! domain's `concat`/`extract`, honouring endianness, so the same memory serves
//! the concrete and symbolic backends. A non-page-crossing access (the common
//! case) does a single page lookup then indexes; page-crossing accesses fall to
//! a per-byte slow path.
//!
//! Permissions, dirty-page COW snapshots, and MMIO/hook regions arrive in later
//! increments (`docs/design/execution-engine/02-architecture/machine-state.md`).

use std::collections::HashMap;

use crate::exec::domain::Domain;
use crate::ir::types::{Endian, Width};

const PAGE_BITS: u32 = 12;
const PAGE_SIZE: usize = 1 << PAGE_BITS;
const PAGE_MASK: u64 = (PAGE_SIZE as u64) - 1;

/// Sparse, **paged** byte-addressed memory holding `Domain::Val` bytes. Each
/// touched 4 KiB page is a `Box<[Option<Val>; 4096]>` (unset = zero). A
/// non-page-crossing access (the common case) does one page lookup then indexes
/// — instead of one hash per byte.
pub struct Memory<D: Domain> {
    pages: HashMap<u64, Box<[Option<D::Val>]>>,
}

impl<D: Domain> Default for Memory<D> {
    fn default() -> Self {
        Self {
            pages: HashMap::new(),
        }
    }
}

// Cloneable regardless of domain (`Domain::Val: Clone`); used to fork states.
impl<D: Domain> Clone for Memory<D> {
    fn clone(&self) -> Self {
        Self {
            pages: self.pages.clone(),
        }
    }
}

fn fresh_page<D: Domain>() -> Box<[Option<D::Val>]> {
    vec![None; PAGE_SIZE].into_boxed_slice()
}

impl<D: Domain> Memory<D> {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if `[addr, addr+size)` lies within a single page.
    fn in_one_page(addr: u64, size: usize) -> bool {
        (addr & PAGE_MASK) + size as u64 <= PAGE_SIZE as u64
    }

    /// One byte (width 8), zero if unmapped (slow path, used across page bounds).
    fn byte(&self, dom: &mut D, addr: u64) -> D::Val {
        let pg = addr >> PAGE_BITS;
        let off = (addr & PAGE_MASK) as usize;
        self.pages
            .get(&pg)
            .and_then(|p| p[off].clone())
            .unwrap_or_else(|| dom.constant(Width::W8, 0))
    }

    fn set_byte(&mut self, addr: u64, byte: D::Val) {
        let pg = addr >> PAGE_BITS;
        let off = (addr & PAGE_MASK) as usize;
        self.pages.entry(pg).or_insert_with(fresh_page::<D>)[off] = Some(byte);
    }

    /// Load `size` bytes at `addr` with the given byte order, returning a value
    /// of width `8 * size`.
    pub fn load(&mut self, dom: &mut D, addr: u64, size: u8, endian: Endian) -> D::Val {
        debug_assert!(size >= 1);
        let n = size as usize;
        // Collect bytes in increasing-address (LSB-first) order.
        let lsb_first: Vec<D::Val> = if Self::in_one_page(addr, n) {
            let pg = addr >> PAGE_BITS;
            let base = (addr & PAGE_MASK) as usize;
            match self.pages.get(&pg) {
                Some(p) => (0..n)
                    .map(|i| {
                        p[base + i]
                            .clone()
                            .unwrap_or_else(|| dom.constant(Width::W8, 0))
                    })
                    .collect(),
                None => (0..n).map(|_| dom.constant(Width::W8, 0)).collect(),
            }
        } else {
            (0..size as u64)
                .map(|i| self.byte(dom, addr.wrapping_add(i)))
                .collect()
        };
        // Order most-significant first for left-to-right concat.
        let msb_first: Vec<&D::Val> = match endian {
            Endian::Little => lsb_first.iter().rev().collect(),
            Endian::Big => lsb_first.iter().collect(),
        };
        let mut acc = msb_first[0].clone();
        let mut acc_w = 8u16;
        for b in &msb_first[1..] {
            acc = dom.concat(&acc, b, Width(acc_w), Width::W8);
            acc_w += 8;
        }
        acc
    }

    /// Store the low `size` bytes of `val` at `addr` with the given byte order.
    pub fn store(&mut self, dom: &mut D, addr: u64, val: &D::Val, size: u8, endian: Endian) {
        let n = size as usize;
        if Self::in_one_page(addr, n) {
            let pg = addr >> PAGE_BITS;
            let base = (addr & PAGE_MASK) as usize;
            let page = self.pages.entry(pg).or_insert_with(fresh_page::<D>);
            for i in 0..n {
                let lo = (i as u16) * 8;
                let byte = dom.extract(val, lo + 8, lo);
                let off = match endian {
                    Endian::Little => base + i,
                    Endian::Big => base + (n - 1 - i),
                };
                page[off] = Some(byte);
            }
        } else {
            for i in 0..size as u64 {
                let lo = (i * 8) as u16;
                let byte = dom.extract(val, lo + 8, lo);
                let target = match endian {
                    Endian::Little => addr.wrapping_add(i),
                    Endian::Big => addr.wrapping_add(size as u64 - 1 - i),
                };
                self.set_byte(target, byte);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::concrete::Concrete;

    fn mem() -> (Concrete, Memory<Concrete>) {
        (Concrete, Memory::new())
    }

    #[test]
    fn unmapped_reads_zero() {
        let (mut d, mut m) = mem();
        assert_eq!(m.load(&mut d, 0x1000, 8, Endian::Little), 0);
    }

    #[test]
    fn store_then_load_little_endian() {
        let (mut d, mut m) = mem();
        let v = d.constant(Width::W32, 0xdead_beef);
        m.store(&mut d, 0x2000, &v, 4, Endian::Little);
        // Byte layout: 0x2000=ef, 0x2001=be, 0x2002=ad, 0x2003=de.
        assert_eq!(m.load(&mut d, 0x2000, 1, Endian::Little), 0xef);
        assert_eq!(m.load(&mut d, 0x2003, 1, Endian::Little), 0xde);
        assert_eq!(m.load(&mut d, 0x2000, 4, Endian::Little), 0xdead_beef);
    }

    #[test]
    fn store_then_load_big_endian() {
        let (mut d, mut m) = mem();
        let v = d.constant(Width::W32, 0xdead_beef);
        m.store(&mut d, 0x3000, &v, 4, Endian::Big);
        // Big-endian: 0x3000=de (most significant) ... 0x3003=ef.
        assert_eq!(m.load(&mut d, 0x3000, 1, Endian::Little), 0xde);
        assert_eq!(m.load(&mut d, 0x3003, 1, Endian::Little), 0xef);
        assert_eq!(m.load(&mut d, 0x3000, 4, Endian::Big), 0xdead_beef);
    }

    #[test]
    fn eight_byte_round_trip() {
        let (mut d, mut m) = mem();
        let v = d.constant(Width::W64, 0x0123_4567_89ab_cdef);
        m.store(&mut d, 0x4000, &v, 8, Endian::Little);
        assert_eq!(
            m.load(&mut d, 0x4000, 8, Endian::Little),
            0x0123_4567_89ab_cdef
        );
    }

    #[test]
    fn overlapping_writes_take_latest() {
        let (mut d, mut m) = mem();
        let a = d.constant(Width::W16, 0xaaaa);
        let b = d.constant(Width::W8, 0xbb);
        m.store(&mut d, 0x5000, &a, 2, Endian::Little);
        m.store(&mut d, 0x5000, &b, 1, Endian::Little);
        // low byte overwritten, high byte preserved
        assert_eq!(m.load(&mut d, 0x5000, 2, Endian::Little), 0xaabb);
    }

    #[test]
    fn store_load_across_page_boundary() {
        // 8-byte access at 0xFFE spans pages 0 and 1 — exercises the slow path.
        let (mut d, mut m) = mem();
        let v = d.constant(Width::W64, 0x1122_3344_5566_7788);
        m.store(&mut d, 0xFFE, &v, 8, Endian::Little);
        assert_eq!(
            m.load(&mut d, 0xFFE, 8, Endian::Little),
            0x1122_3344_5566_7788
        );
        // Spot-check individual bytes land on both sides of the boundary.
        assert_eq!(m.load(&mut d, 0xFFE, 1, Endian::Little), 0x88); // page 0
        assert_eq!(m.load(&mut d, 0x1000, 1, Endian::Little), 0x66); // page 1
    }
}
