//! The block/temp/frame builder: the only place that mints VAs, temporaries and
//! stack slots for a lowered function.
//!
//! `LlirFunction` is addressed by VA because it was built for lifted code, so a
//! synthetic function has to invent one. Keeping the invention in one type is
//! what stops two lowering rules disagreeing about what `end_va` means.

use crate::ir::types::{
    BinOp, CmpOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, UnOp, VReg, Value, Width,
};

/// First synthetic block VA. Deliberately far from the fixture binaries' load
/// addresses so a confused mix of lowered and lifted blocks cannot silently
/// resolve.
pub const BLOCK_BASE: u64 = 0x1000_0000;

/// Distance between synthetic block VAs.
pub const BLOCK_STRIDE: u64 = 0x40;

/// The `end_va` of a block that has no fall-through.
///
/// No block starts here, so `Machine::run_function` answers a fall-through that
/// should have been impossible with `Outcome::NoBlock(0)` --- a loud lowering
/// bug rather than execution continuing into an unrelated block.
pub const NO_FALLTHROUGH_VA: u64 = 0;

/// Base VA of the lowered function's frame. Locals are allocated upward from
/// here at fixed offsets, so every local access is an absolute displacement and
/// needs no frame register.
pub const FRAME_BASE: u64 = 0x2000_0000;

/// Index of a block under construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef(usize);

/// Builds one [`LlirFunction`]: blocks, temporaries and frame slots.
#[derive(Debug)]
pub struct FnBuilder {
    blocks: Vec<LlirBlock>,
    current: usize,
    next_temp: u32,
    next_slot: u64,
}

impl Default for FnBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FnBuilder {
    /// A builder with one block, already current.
    pub fn new() -> Self {
        let mut builder = Self {
            blocks: Vec::new(),
            current: 0,
            next_temp: 0,
            next_slot: FRAME_BASE,
        };
        let entry = builder.new_block();
        builder.current = entry.0;
        builder
    }

    /// The entry block's VA.
    pub fn entry_va(&self) -> u64 {
        BLOCK_BASE
    }

    /// A fresh, unreachable block. Its `end_va` starts at
    /// [`NO_FALLTHROUGH_VA`]; a caller that wants a fall-through sets it.
    pub fn new_block(&mut self) -> BlockRef {
        let index = self.blocks.len();
        let start_va = BLOCK_BASE + (index as u64) * BLOCK_STRIDE;
        self.blocks.push(LlirBlock {
            start_va,
            end_va: NO_FALLTHROUGH_VA,
            instrs: Vec::new(),
            succs: Vec::new(),
        });
        BlockRef(index)
    }

    /// The VA a block starts at.
    pub fn va_of(&self, block: BlockRef) -> u64 {
        self.blocks[block.0].start_va
    }

    /// The block ops are currently appended to.
    pub fn current(&self) -> BlockRef {
        BlockRef(self.current)
    }

    /// Append subsequent ops to `block`.
    pub fn switch_to(&mut self, block: BlockRef) {
        self.current = block.0;
    }

    /// Make `block` the current block's fall-through successor.
    ///
    /// This is the *only* way a block acquires a fall-through, so the invariant
    /// `end_va` is read under --- "the start of the fall-through successor" ---
    /// is enforced in one place.
    pub fn fall_through_to(&mut self, block: BlockRef) {
        let target = self.blocks[block.0].start_va;
        let current = &mut self.blocks[self.current];
        current.end_va = target;
        if !current.succs.contains(&target) {
            current.succs.push(target);
        }
    }

    /// Append one op to the current block.
    pub fn emit(&mut self, op: Op) {
        let block = &mut self.blocks[self.current];
        let va = block.start_va;
        if let Op::Jump { target } | Op::CondJump { target, .. } = &op {
            let target = *target;
            if !block.succs.contains(&target) {
                block.succs.push(target);
            }
        }
        block.instrs.push(LlirInstr { va, op });
    }

    /// A fresh temporary.
    pub fn temp(&mut self) -> VReg {
        let id = self.next_temp;
        self.next_temp += 1;
        VReg::Temp(id)
    }

    /// Allocate a frame slot of `bytes`, 8-byte aligned, and return its VA.
    ///
    /// Every slot is 8-aligned and at least 8 bytes wide even for a `char`, so
    /// no two locals ever share a machine word. Overlapping slots would make a
    /// narrow store silently clobber its neighbour, and that failure looks
    /// exactly like a lowering bug in the arithmetic.
    pub fn slot(&mut self, bytes: u64) -> u64 {
        let addr = self.next_slot;
        self.next_slot += bytes.max(8).next_multiple_of(8);
        addr
    }

    /// `dst = const`.
    pub fn assign_const(&mut self, dst: &VReg, value: i64) {
        self.emit(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(value),
        });
    }

    /// `dst = src`.
    pub fn assign(&mut self, dst: &VReg, src: &VReg) {
        self.emit(Op::Assign {
            dst: dst.clone(),
            src: Value::Reg(src.clone()),
        });
    }

    /// `dst = lhs op rhs`, at the interpreter's 64-bit temporary width. The
    /// caller renormalizes to the C type; see the module docs.
    pub fn binop(&mut self, dst: &VReg, op: BinOp, lhs: &VReg, rhs: &VReg) {
        self.emit(Op::Bin {
            dst: dst.clone(),
            op,
            lhs: Value::Reg(lhs.clone()),
            rhs: Value::Reg(rhs.clone()),
        });
    }

    /// `dst = op src`.
    pub fn unop(&mut self, dst: &VReg, op: UnOp, src: &VReg) {
        self.emit(Op::Un {
            dst: dst.clone(),
            op,
            src: Value::Reg(src.clone()),
        });
    }

    /// `dst = (lhs op rhs)` as a 0/1 predicate.
    pub fn cmp(&mut self, dst: &VReg, op: CmpOp, lhs: &VReg, rhs: &VReg) {
        self.emit(Op::Cmp {
            dst: dst.clone(),
            op,
            lhs: Value::Reg(lhs.clone()),
            rhs: Value::Reg(rhs.clone()),
        });
    }

    /// `dst = (src != 0)`, the C truth test.
    pub fn truth(&mut self, src: &VReg) -> VReg {
        let dst = self.temp();
        self.emit(Op::Cmp {
            dst: dst.clone(),
            op: CmpOp::Ne,
            lhs: Value::Reg(src.clone()),
            rhs: Value::Const(0),
        });
        dst
    }

    /// Reduce `src` to `width` bits and re-extend it to the canonical 64-bit
    /// form for a type of that width and signedness, writing `dst`.
    ///
    /// This is the renormalization the whole representation rests on. It is a
    /// no-op only at 64 bits, where the extension has nothing to do.
    pub fn normalize(&mut self, dst: &VReg, src: &VReg, width: Width, signed: bool) {
        if width.bits() >= 64 {
            if dst != src {
                self.assign(dst, src);
            }
            return;
        }
        let narrow = self.temp();
        self.emit(Op::Trunc {
            dst: narrow.clone(),
            src: Value::Reg(src.clone()),
            from: Width::W64,
            to: width,
        });
        let op = if signed {
            Op::SExt {
                dst: dst.clone(),
                src: Value::Reg(narrow),
                from: width,
                to: Width::W64,
            }
        } else {
            Op::ZExt {
                dst: dst.clone(),
                src: Value::Reg(narrow),
                from: width,
                to: Width::W64,
            }
        };
        self.emit(op);
    }

    /// Load `bytes` from the absolute address `addr` into `dst`.
    pub fn load_abs(&mut self, dst: &VReg, addr: u64, bytes: u8) {
        self.emit(Op::Load {
            dst: dst.clone(),
            addr: MemOp::plain(None, None, 0, addr as i64, bytes),
        });
    }

    /// Store the low `bytes` of `src` to the absolute address `addr`.
    pub fn store_abs(&mut self, addr: u64, bytes: u8, src: &VReg) {
        self.emit(Op::Store {
            addr: MemOp::plain(None, None, 0, addr as i64, bytes),
            src: Value::Reg(src.clone()),
        });
    }

    /// An unconditional jump to `block`, ending the current block.
    pub fn jump(&mut self, block: BlockRef) {
        let target = self.va_of(block);
        self.emit(Op::Jump { target });
    }

    /// Branch to `taken` when `cond` is set; the current block falls through to
    /// `not_taken`.
    pub fn branch(&mut self, cond: &VReg, taken: BlockRef, not_taken: BlockRef) {
        let target = self.va_of(taken);
        self.emit(Op::CondJump {
            cond: cond.clone(),
            target,
            inverted: false,
        });
        self.fall_through_to(not_taken);
    }

    /// Finish: the blocks in creation order, with the entry first.
    pub fn finish(self) -> LlirFunction {
        LlirFunction {
            entry_va: BLOCK_BASE,
            blocks: self.blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_with_no_fallthrough_points_at_no_block() {
        let mut b = FnBuilder::new();
        b.emit(Op::Return);
        let f = b.finish();
        assert_eq!(f.entry_va, BLOCK_BASE);
        assert_eq!(f.blocks[0].end_va, NO_FALLTHROUGH_VA);
    }

    #[test]
    fn fall_through_records_the_successors_start_va_not_the_next_index() {
        let mut b = FnBuilder::new();
        let first = b.current();
        let _skipped = b.new_block();
        let target = b.new_block();
        b.switch_to(first);
        b.fall_through_to(target);
        let f = b.finish();
        // Third block, so BLOCK_BASE + 2 * stride --- and NOT the block that
        // happens to sit next in the vector.
        assert_eq!(f.blocks[0].end_va, BLOCK_BASE + 2 * BLOCK_STRIDE);
        assert_ne!(f.blocks[0].end_va, f.blocks[1].start_va);
    }

    #[test]
    fn slots_are_eight_byte_aligned_and_never_overlap() {
        let mut b = FnBuilder::new();
        let a = b.slot(1);
        let c = b.slot(4);
        let d = b.slot(8);
        assert_eq!(c - a, 8, "a one-byte local still owns a whole word");
        assert_eq!(d - c, 8);
        assert!(a.is_multiple_of(8) && c.is_multiple_of(8) && d.is_multiple_of(8));
    }
}
