//! Minimal byte-addressed memory, generic over the value [`Domain`].
//!
//! This is the Phase-1 starting point: a sparse `addr -> byte` map where each
//! byte is a `Domain::Val` of width 8. Multi-byte loads/stores assemble/split
//! through the domain's `concat`/`extract`, honouring endianness, so the same
//! memory serves the concrete and (future) symbolic backends. Unmapped bytes
//! read as zero.
//!
//! The full softmmu (page tables, permissions, sparse pages, dirty-page COW
//! snapshots, MMIO/hook regions) arrives in later Phase-1/Phase-3 increments
//! (`docs/design/execution-engine/02-architecture/machine-state.md`); this keeps
//! the interpreter testable end-to-end now.

use std::collections::HashMap;

use crate::exec::domain::Domain;
use crate::ir::types::{Endian, Width};

/// Sparse byte-addressed memory holding `Domain::Val` bytes.
pub struct Memory<D: Domain> {
    bytes: HashMap<u64, D::Val>,
}

impl<D: Domain> Default for Memory<D> {
    fn default() -> Self {
        Self {
            bytes: HashMap::new(),
        }
    }
}

// Cloneable regardless of domain (`Domain::Val: Clone`); used to fork states.
impl<D: Domain> Clone for Memory<D> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

impl<D: Domain> Memory<D> {
    pub fn new() -> Self {
        Self::default()
    }

    /// One byte (width 8), zero if unmapped.
    fn byte(&self, dom: &mut D, addr: u64) -> D::Val {
        match self.bytes.get(&addr) {
            Some(v) => v.clone(),
            None => dom.constant(Width::W8, 0),
        }
    }

    /// Load `size` bytes at `addr` with the given byte order, returning a value
    /// of width `8 * size`.
    pub fn load(&mut self, dom: &mut D, addr: u64, size: u8, endian: Endian) -> D::Val {
        debug_assert!(size >= 1);
        // Collect bytes in increasing-address order.
        let lsb_first: Vec<D::Val> = (0..size as u64).map(|i| self.byte(dom, addr + i)).collect();
        // Order them most-significant first for left-to-right concat.
        let msb_first: Vec<&D::Val> = match endian {
            // little-endian: highest address is most significant
            Endian::Little => lsb_first.iter().rev().collect(),
            // big-endian: lowest address is most significant
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
        for i in 0..size as u64 {
            // Byte i (0 = least significant) = bits [8*i, 8*i+8).
            let lo = (i * 8) as u16;
            let byte = dom.extract(val, lo + 8, lo);
            let target = match endian {
                Endian::Little => addr + i,
                Endian::Big => addr + (size as u64 - 1 - i),
            };
            self.bytes.insert(target, byte);
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
}
