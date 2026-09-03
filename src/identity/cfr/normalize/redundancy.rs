//! Pass (d): dead-store and redundant-write elimination inside the peephole.
//!
//! # The three rules
//!
//! **Redundant register write.** A pure operation whose destination is
//! overwritten later in the same block, with no read of that register in
//! between, computes a value nobody can observe. It becomes [`Op::Nop`]. Only
//! pure operations are removed: a call, an intrinsic and a store are kept
//! whatever happens to their results.
//!
//! **Store-store elimination.** A store whose bytes are overwritten by a later
//! store in the same block, with no intervening memory read and no intervening
//! operation that may write those same bytes, is dropped. `[rbp-8] = rdi`
//! followed by `[rbp-8] = rax` keeps only the second.
//!
//! **Load-after-store forwarding.** A load from bytes the block itself stored,
//! with nothing in between that may have overwritten them, becomes a copy of
//! the stored value. This is the single most valuable rule at `-O0`, where
//! every local round-trips through the frame: `[rbp-8] = edi; eax = [rbp-8]`
//! becomes `eax = edi`, which is what the same source compiles to directly at
//! `-O2`.
//!
//! All three obey the peephole invariant: a register the block reads but never
//! writes is a parameter and is never eliminated, and a *store* is only ever
//! removed when this block itself proves it dead. The block's last write to any
//! location survives, because a later block may read it.
//!
//! # Precedent
//!
//! VexINE's list names all three: *"redundant-write elimination ... load-store
//! and store-store elimination"*. BSim reaches the same place from the other
//! direction by abstracting stack mechanics away entirely; Binary Ninja's MLIL
//! says "the stack as a concept is not present". Dead-store elimination is
//! standard in every compiler; Glaurung's own `ir::dead_stores` does the sound
//! global version for rendering.
//!
//! # Why unsound is fine here
//!
//! The alias rule ([`super::common::may_alias`]) proves only one thing apart:
//! two accesses through the *same* base and index at disjoint displacements.
//! Everything else is treated as possibly-aliasing, which is the conservative
//! direction and costs recall rather than correctness.
//!
//! Two of the three rules are in fact sound as written -- a write killed by a
//! later write in the same block with no read between is dead on every path
//! out of that block, and so is a store to bytes the block immediately
//! overwrites. The unsoundness is concentrated in load forwarding, which
//! believes [`super::common::may_alias`]: a store through a base register the
//! peephole cannot relate to the load's base is judged non-aliasing whenever
//! the two expressions are syntactically identical and the displacements are
//! disjoint, and two syntactically different expressions that happen to hold
//! the same address defeat it in the other direction. Both errors cost a
//! feature rather than a program, because nothing downstream of this executes.
//!
//! One further conservatism the rules do rely on: `Op::Unknown` is an
//! instruction the lifter refused, so its read set is empty in
//! `crate::ir::use_def` and unbounded in reality. Every scan stops at one.
//!
//! # Bound
//!
//! Each rule is a single scan with a bounded forward lookahead: the redundant
//! write scan looks ahead until it finds a read, a redefinition or the end of
//! the block, so the worst case is `O(n^2)` on a block of `n` instructions and
//! the typical case is a handful of steps. No rule creates work for another
//! rule in the same invocation; the driver's round cap bounds the repetition.

use crate::ir::types::{LlirBlock, Op, Value};

use super::common;

/// Rewrite one block in place. Returns whether anything changed.
pub fn run(block: &mut LlirBlock) -> bool {
    let mut changed = false;
    changed |= forward_loads(block);
    changed |= drop_overwritten_stores(block);
    changed |= drop_overwritten_registers(block);
    changed
}

/// Load-after-store forwarding.
fn forward_loads(block: &mut LlirBlock) -> bool {
    let mut changed = false;
    for index in 0..block.instrs.len() {
        let Op::Load { dst, addr } = &block.instrs[index].op else {
            continue;
        };
        let (destination, address) = (dst.clone(), addr.clone());
        let mut stored: Option<Value> = None;
        for earlier in (0..index).rev() {
            let candidate = &block.instrs[earlier].op;
            if let Op::Store { addr, src } = candidate {
                if common::same_location(addr, &address) {
                    stored = Some(src.clone());
                    break;
                }
                if common::may_alias(addr, &address) {
                    break;
                }
                continue;
            }
            if common::writes_memory(candidate) {
                break;
            }
        }
        let Some(value) = stored else { continue };
        // A store of the destination register back into itself is not a
        // simplification, and a self-copy would be dropped as a shadow node
        // anyway.
        if value == Value::Reg(destination.clone()) {
            continue;
        }
        block.instrs[index].op = Op::Assign {
            dst: destination,
            src: value,
        };
        changed = true;
    }
    changed
}

/// Store-store elimination.
fn drop_overwritten_stores(block: &mut LlirBlock) -> bool {
    let mut dead: Vec<usize> = Vec::new();
    for index in 0..block.instrs.len() {
        let Op::Store { addr, .. } = &block.instrs[index].op else {
            continue;
        };
        let address = addr.clone();
        for later in index + 1..block.instrs.len() {
            let candidate = &block.instrs[later].op;
            if common::reads_memory(candidate) {
                break;
            }
            if let Op::Store { addr, .. } = candidate {
                if common::same_location(addr, &address) {
                    dead.push(index);
                    break;
                }
                if common::may_alias(addr, &address) {
                    break;
                }
                continue;
            }
            if common::writes_memory(candidate) {
                break;
            }
        }
    }
    for index in &dead {
        block.instrs[*index].op = Op::Nop;
    }
    !dead.is_empty()
}

/// Redundant register write elimination.
fn drop_overwritten_registers(block: &mut LlirBlock) -> bool {
    let mut dead: Vec<usize> = Vec::new();
    for index in 0..block.instrs.len() {
        let op = &block.instrs[index].op;
        if !common::is_pure(op) {
            continue;
        }
        let defs = common::defs_of(op);
        if defs.len() != 1 {
            continue;
        }
        let written = defs[0].clone();
        for later in index + 1..block.instrs.len() {
            let candidate = &block.instrs[later].op;
            if matches!(candidate, Op::Unknown { .. })
                || common::uses_of(candidate).contains(&written)
            {
                break;
            }
            if common::defs_of(candidate).contains(&written) {
                dead.push(index);
                break;
            }
        }
    }
    for index in &dead {
        block.instrs[*index].op = Op::Nop;
    }
    !dead.is_empty()
}
