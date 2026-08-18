//! The detectors: what makes a memory access or a modelled callee a
//! reportable primitive.
//!
//! One entry point per dangerous shape — controlled read/write and
//! double-fetch at a raw access, use-after-free and double-free over the
//! tracked heap, stack overflow and integer overflow, and the callee
//! summaries that stand in for an uninspected API.
//!
//! `Alloc` stays in the parent for the same reason `State` does: the heap
//! detectors here read its private `base`/`size`/`freed`, and a child can
//! only reach those through an ancestor, never through a sibling.

use std::collections::{BTreeMap, BTreeSet};

use crate::exec::domain::{BranchDecision, Domain};
use crate::exec::RegArch;
use crate::ir::types::{BinOp, CmpOp, Endian, Op, VReg, Width};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::SolveResult;

use super::query::{
    concretize_addr, eval_concrete, freely_controllable, path_provenance, push_sink, reach_model,
    read_arg, read_arg_with_width, severity_of, witness_for_predicate, witness_for_value,
};
use super::solve::solve_probe_traced;
use super::stats::record_path_stat;
use super::{Alloc, ApiSummary, Severity, Sink, SinkKind, State};

/// Record the sink(s) for a memory access at `va` through `addr_val`. Emits a
/// controlled read/write (severity from the sentinel test), a double-fetch if the
/// same attacker pointer was read before, and a null-page dereference when either
/// the address or the reaching path is attacker-controlled. This last distinction
/// covers command-selected dereferences of an internal NULL field: the pointer is
/// not tainted, but attacker input controls whether it is dereferenced.
pub(super) fn record_access(
    st: &mut State,
    va: u64,
    addr_val: ExprId,
    write: bool,
    sinks: &mut Vec<Sink>,
) {
    let concrete_address = st.machine.dom.as_u64(&addr_val);
    let concrete_low_page = concrete_address.is_some_and(|address| address < 0x1000);
    record_path_stat(|stats| {
        *stats.memory_access_sites.entry(va).or_default() += 1;
        if let Some(address) = concrete_address {
            *stats
                .concrete_access_addresses
                .entry(va)
                .or_default()
                .entry(address)
                .or_default() += 1;
        }
        if concrete_low_page {
            *stats.low_page_access_sites.entry(va).or_default() += 1;
        }
    });

    // A deref entirely covered by a probed (validated) region is trusted.
    if is_validated(st, addr_val) {
        return;
    }
    let tainted_by = st.taint.provenance_of(&st.machine.dom.pool, addr_val);
    let path_tainted_by = path_provenance(st);
    // Solve the path condition once and reuse it for every sink at this access
    // (controlled R/W, double-fetch, null-deref) instead of re-solving per sink.
    let Some(reach) = reach_model(st) else {
        return; // path infeasible
    };
    let free_addr = freely_controllable(st, addr_val);

    // Linux NULL-member dereferences are commonly a small nonzero address
    // (`NULL + field_offset`), so treat the first page as the null page. For a
    // symbolic address, retain the exact-zero witness used historically.
    let null_witness = if concrete_low_page || free_addr {
        Some(reach.clone())
    } else if tainted_by.is_empty() {
        None
    } else {
        witness_for_value(st, addr_val, 0)
    };
    if let Some(witness) = null_witness {
        let null_provenance = if tainted_by.is_empty() {
            path_tainted_by
        } else {
            tainted_by.clone()
        };
        if !null_provenance.is_empty() {
            sinks.push(Sink {
                va,
                kind: SinkKind::NullDeref,
                witness,
                severity: if free_addr {
                    Severity::Arbitrary
                } else {
                    Severity::Constrained
                },
                tainted_by: null_provenance,
            });
        }
    }

    if tainted_by.is_empty() {
        return; // no attacker control over the address itself
    }
    let severity = if free_addr {
        Severity::Arbitrary
    } else {
        severity_of(st, addr_val)
    };
    let kind = if write {
        SinkKind::ControlledWrite
    } else {
        SinkKind::ControlledRead
    };
    sinks.push(Sink {
        va,
        kind,
        witness: reach.clone(),
        severity,
        tainted_by: tainted_by.clone(),
    });

    // Double-fetch (TOCTOU): a second read of the same attacker pointer.
    if !write && !st.tainted_reads.insert(addr_val) {
        sinks.push(Sink {
            va,
            kind: SinkKind::DoubleFetch,
            witness: reach.clone(),
            severity,
            tainted_by: tainted_by.clone(),
        });
    }
}

/// True if every free symbol of `addr` was vouched for by a probe (and there is
/// at least one) — i.e. the deref lies wholly within a probed region.
fn is_validated(st: &State, addr: ExprId) -> bool {
    let mut syms = BTreeMap::new();
    st.machine.dom.pool.collect_syms(addr, &mut syms);
    !syms.is_empty() && syms.keys().all(|id| st.validated.contains(id))
}

/// Flag a [`SinkKind::UseAfterFree`] if `ptr` concretizes into a freed block.
pub(super) fn uaf_check(st: &mut State, va: u64, ptr: ExprId, sinks: &mut Vec<Sink>) -> bool {
    if !st.allocations.iter().any(|allocation| allocation.freed) {
        return true;
    }
    let Some(a) = eval_concrete(st, ptr) else {
        return false;
    };
    let hit = st
        .allocations
        .iter()
        .any(|al| al.freed && a >= al.base && a < al.base.saturating_add(al.size));
    if hit {
        push_sink(st, va, SinkKind::UseAfterFree, ptr, Vec::new(), sinks);
    }
    true
}

/// Stack window (bytes) around `rsp` within which a `memcpy` destination is
/// treated as an on-stack buffer for overflow purposes.
const STACK_WINDOW: u64 = 0x1_0000;

/// Apply a callee summary, recording the attacker-controlled primitives it
/// exposes, then modeling its return value.
pub(super) fn apply_summary(
    st: &mut State,
    va: u64,
    summary: ApiSummary,
    sinks: &mut Vec<Sink>,
) -> bool {
    match summary {
        ApiSummary::HavocReturn => havoc_return(st),
        ApiSummary::CopyMemory => {
            let Some(dst) = read_arg(st, 0) else {
                return false;
            };
            let Some(src) = read_arg(st, 1) else {
                return false;
            };
            let Some(len) = read_arg(st, 2) else {
                return false;
            };
            if !uaf_check(st, va, dst, sinks) || !uaf_check(st, va, src, sinks) {
                return false;
            }
            record_access(st, va, dst, true, sinks);
            record_access(st, va, src, false, sinks);
            if !stack_overflow_check(st, va, dst, len, sinks) {
                return false;
            }
            havoc_return(st);
        }
        ApiSummary::Alloc { size_arg } => {
            let Some(size_val) = read_arg(st, size_arg) else {
                return false;
            };
            // Choose a concrete size in a sane range for the bump allocator.
            let Some(size) = eval_concrete(st, size_val) else {
                return false;
            };
            let size = size.clamp(1, 0x10_000);
            let base = st.heap_next;
            st.heap_next = st.heap_next.saturating_add((size + 0xF) & !0xF);
            st.allocations.push(Alloc {
                base,
                size,
                freed: false,
            });
            let ret = st.machine.dom.constant(Width::W64, base as u128);
            let register = return_reg(st);
            st.machine
                .regs
                .write(&mut st.machine.dom, &VReg::phys(register), ret);
        }
        ApiSummary::Free { ptr_arg } => {
            let Some(ptr) = read_arg(st, ptr_arg) else {
                return false;
            };
            if !do_free(st, va, ptr, sinks) {
                return false;
            }
            havoc_return(st);
        }
        ApiSummary::Probe { addr_arg, len_arg } => {
            let Some(addr) = read_arg(st, addr_arg) else {
                return false;
            };
            let Some(len) = read_arg(st, len_arg) else {
                return false;
            };
            // A probe whose length can be zero validates nothing (bypassable).
            if witness_for_value(st, len, 0).is_some() {
                let prov = st.taint.provenance_of(&st.machine.dom.pool, addr);
                push_sink(st, va, SinkKind::ProbeBypass, len, prov, sinks);
            }
            // A successful probe vouches for the address's symbols on this path.
            let mut syms = BTreeMap::new();
            st.machine.dom.pool.collect_syms(addr, &mut syms);
            for id in syms.keys() {
                st.validated.insert(*id);
            }
            havoc_return(st);
        }
        ApiSummary::DangerousCall { args, kind } => {
            if !dangerous_call(st, va, args, kind, sinks) {
                return false;
            }
            havoc_return(st);
        }
        ApiSummary::RetrieveBuffer { out_ptr_arg } => {
            // *arg[out_ptr_arg] := fresh SystemBuffer-tainted pointer.
            let Some(out_ptr) = read_arg(st, out_ptr_arg) else {
                return false;
            };
            let Some(addr) = eval_concrete(st, out_ptr) else {
                return false;
            };
            if addr != 0 {
                let e = st.machine.dom.fresh(Width::W64);
                if let Expr::Sym { id, .. } = st.machine.dom.pool.get(e) {
                    let id = *id;
                    st.taint.mark(id, "SystemBuffer");
                }
                st.machine
                    .mem
                    .store(&mut st.machine.dom, addr, &e, 8, Endian::Little);
            }
            havoc_return(st); // returns a status/value
        }
        ApiSummary::BoundedSignedIndex {
            index_arg,
            width,
            min,
            max,
        } => {
            let Some(index) = read_arg_with_width(st, index_arg, width) else {
                return false;
            };
            let min_value = st.machine.dom.constant(width, min as u128);
            let max_value = st.machine.dom.constant(width, max as u128);
            let below = st.machine.dom.cmp(CmpOp::Slt, &index, &min_value, width);
            let above = st.machine.dom.cmp(CmpOp::Slt, &max_value, &index, width);
            let outside = st.machine.dom.binop(BinOp::Or, &below, &above, Width::W1);
            if let Some(witness) = witness_for_predicate(st, outside) {
                let tainted_by = st.taint.provenance_of(&st.machine.dom.pool, index);
                sinks.push(Sink {
                    va,
                    kind: SinkKind::OutOfBoundsIndex,
                    witness,
                    severity: Severity::Constrained,
                    tainted_by,
                });
            }
            havoc_return(st);
        }
    }
    true
}

fn return_reg(st: &State) -> &'static str {
    match st.machine.regs.arch() {
        RegArch::X86_64 => "rax",
        RegArch::AArch64 => "x0",
    }
}

/// Havoc the architecture's return register with a fresh symbol — the sound
/// over-approximation for a summarized callee whose result we don't model.
pub(super) fn havoc_return(st: &mut State) {
    let register = return_reg(st);
    let ret = st.machine.dom.fresh(Width::W64);
    st.machine
        .regs
        .write(&mut st.machine.dom, &VReg::phys(register), ret);
}

/// `ExFreePool(ptr)`: a second free of an already-freed block is a double-free;
/// otherwise mark the matching live block freed.
fn do_free(st: &mut State, va: u64, ptr: ExprId, sinks: &mut Vec<Sink>) -> bool {
    let Some(a) = eval_concrete(st, ptr) else {
        return false;
    };
    if let Some(al) = st.allocations.iter_mut().find(|al| al.base == a) {
        if al.freed {
            push_sink(st, va, SinkKind::DoubleFree, ptr, Vec::new(), sinks);
        } else {
            al.freed = true;
        }
    }
    true
}

/// Flag a [`SinkKind::StackOverflow`] when a `memcpy` destination is on the stack
/// and the length is attacker-controlled (an unbounded copy onto the frame).
fn expression_contains(pool: &ExprPool, root: ExprId, needle: ExprId) -> bool {
    if root == needle {
        return true;
    }
    // Constants and free symbols are too common to establish stack ancestry by
    // DAG membership alone. Free-symbol sharing is handled separately below.
    if matches!(pool.get(needle), Expr::Const { .. } | Expr::Sym { .. }) {
        return false;
    }
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        match *pool.get(id) {
            Expr::Bin { a, b, .. } | Expr::Cmp { a, b, .. } => {
                if a == needle || b == needle {
                    return true;
                }
                pending.extend([a, b]);
            }
            Expr::Un { a, .. }
            | Expr::ZExt { a, .. }
            | Expr::SExt { a, .. }
            | Expr::Trunc { a, .. }
            | Expr::Extract { a, .. } => {
                if a == needle {
                    return true;
                }
                pending.push(a);
            }
            Expr::Concat { hi, lo, .. } => {
                if hi == needle || lo == needle {
                    return true;
                }
                pending.extend([hi, lo]);
            }
            Expr::Ite { c, t, e, .. } => {
                if c == needle || t == needle || e == needle {
                    return true;
                }
                pending.extend([c, t, e]);
            }
            Expr::Const { .. } | Expr::Sym { .. } => {}
        }
    }
    false
}

fn shares_structural_origin(pool: &ExprPool, lhs: ExprId, rhs: ExprId) -> bool {
    if lhs == rhs {
        return true;
    }
    if expression_contains(pool, lhs, rhs) {
        return true;
    }
    let mut lhs_symbols = BTreeMap::new();
    pool.collect_syms(lhs, &mut lhs_symbols);
    if lhs_symbols.is_empty() {
        return false;
    }
    let mut rhs_symbols = BTreeMap::new();
    pool.collect_syms(rhs, &mut rhs_symbols);
    lhs_symbols
        .keys()
        .any(|symbol| rhs_symbols.contains_key(symbol))
}

pub(super) fn stack_overflow_check(
    st: &mut State,
    va: u64,
    dst: ExprId,
    len: ExprId,
    sinks: &mut Vec<Sink>,
) -> bool {
    let len_prov = st.taint.provenance_of(&st.machine.dom.pool, len);
    if len_prov.is_empty() {
        return true; // a fixed-length copy can't overflow under attacker control
    }
    let (stack_register, frame_register) = match st.machine.regs.arch() {
        RegArch::X86_64 => ("rsp", "rbp"),
        RegArch::AArch64 => ("sp", "x29"),
    };
    let rsp_v = st
        .machine
        .regs
        .read(&mut st.machine.dom, &VReg::phys(stack_register));
    let rbp_v = st
        .machine
        .regs
        .read(&mut st.machine.dom, &VReg::phys(frame_register));
    if !shares_structural_origin(&st.machine.dom.pool, dst, rsp_v)
        && !shares_structural_origin(&st.machine.dom.pool, dst, rbp_v)
    {
        return true;
    }
    let Some(rsp) = eval_concrete(st, rsp_v) else {
        return false;
    };
    if rsp == 0 {
        return true; // stack pointer not modeled on this path
    }
    let Some(dst_a) = eval_concrete(st, dst) else {
        return false;
    };
    let lo = rsp.saturating_sub(STACK_WINDOW);
    let hi = rsp.saturating_add(STACK_WINDOW);
    if dst_a >= lo && dst_a <= hi {
        push_sink(st, va, SinkKind::StackOverflow, len, len_prov, sinks);
    }
    true
}

/// Flag a [`SinkKind::IntegerOverflow`] when an attacker-tainted `add`/`sub`/`mul`
/// can wrap at its operand width — the kind of unchecked size arithmetic that
/// precedes an undersized allocation or bounds bypass. Only `Bin` ops are
/// considered; everything else is a no-op.
pub(super) fn check_int_overflow(st: &mut State, va: u64, op: &Op, sinks: &mut Vec<Sink>) {
    let Op::Bin {
        dst,
        op: bop,
        lhs,
        rhs,
    } = op
    else {
        return;
    };
    // Restrict to size-style arithmetic (add/mul); subtraction is dominated by
    // compare lowering on dispatch codes and is overwhelmingly noise.
    if !matches!(bop, BinOp::Add | BinOp::Mul) {
        return;
    }
    let w = dst.width().unwrap_or(Width::W64);
    let a = st.machine.read(lhs, w);
    let b = st.machine.read(rhs, w);

    // Only attacker-influenced arithmetic is interesting.
    let mut prov: BTreeSet<String> = BTreeSet::new();
    prov.extend(st.taint.provenance_of(&st.machine.dom.pool, a));
    prov.extend(st.taint.provenance_of(&st.machine.dom.pool, b));
    if prov.is_empty() {
        return;
    }

    // Build the overflow predicate at width `w`:
    //   add: (a + b) <u a          (unsigned carry out)
    //   sub: a <u b                (unsigned borrow / underflow)
    //   mul: widen to 2w, result's high half != 0
    let dom = &mut st.machine.dom;
    let pred = match bop {
        BinOp::Add => {
            let sum = dom.binop(BinOp::Add, &a, &b, w);
            dom.cmp(CmpOp::Ult, &sum, &a, w)
        }
        BinOp::Sub => dom.cmp(CmpOp::Ult, &a, &b, w),
        BinOp::Mul => {
            let dw = Width(w.bits().saturating_mul(2));
            if dw.bits() > 128 || dw.bits() <= w.bits() {
                return; // can't widen safely
            }
            let za = dom.zext(&a, w, dw);
            let zb = dom.zext(&b, w, dw);
            let prod = dom.binop(BinOp::Mul, &za, &zb, dw);
            let hi = dom.extract(&prod, dw.bits(), w.bits());
            let zero = dom.constant(Width(dw.bits() - w.bits()), 0);
            dom.cmp(CmpOp::Ne, &hi, &zero, Width(dw.bits() - w.bits()))
        }
        _ => unreachable!(),
    };

    if let SolveResult::Sat(witness) =
        solve_probe_traced(st, (pred, true), "integer-overflow", "other", va)
    {
        sinks.push(Sink {
            va,
            kind: SinkKind::IntegerOverflow,
            witness,
            severity: Severity::Arbitrary,
            tainted_by: prov.into_iter().collect(),
        });
    }
}

/// A routine dangerous when any of `args` is attacker-tainted: aggregate the
/// provenance of the tainted args and raise one `kind` sink.
fn dangerous_call(
    st: &mut State,
    va: u64,
    args: &[u8],
    kind: SinkKind,
    sinks: &mut Vec<Sink>,
) -> bool {
    let mut prov: BTreeSet<String> = BTreeSet::new();
    let mut tainted_arg: Option<ExprId> = None;
    for &a in args {
        let Some(v) = read_arg(st, a) else {
            return false;
        };
        let p = st.taint.provenance_of(&st.machine.dom.pool, v);
        if !p.is_empty() {
            prov.extend(p);
            tainted_arg = Some(v);
        }
    }
    if let Some(v) = tainted_arg {
        push_sink(st, va, kind, v, prov.into_iter().collect(), sinks);
    }
    true
}

/// Execute a memory op through the symbolic explorer's single address and taint
/// policy. Symbol-free addresses avoid a solver, while symbolic addresses use
/// the configured concretization policy. Returns `Some(())` when handled.
pub(super) fn execute_memory_op(st: &mut State, op: &Op) -> Option<()> {
    match op {
        Op::Load { dst, addr } => {
            let av = st.machine.eval_addr(addr);
            let address_provenance = st.taint.provenance_of(&st.machine.dom.pool, av);
            let a = concretize_addr(st, av)?;
            // Taint-through-memory: a load from an attacker-controlled pointer into
            // *uninitialized* memory yields fresh attacker data (mirrors a
            // fully-symbolic memory model). Mark the fresh symbol so values read
            // out of `*(SystemBuffer)` stay attacker-controlled downstream — this
            // is what lets handle/PID/pointer args derived from buffer contents be
            // detected. Detect "uninitialized" via the memory map, not the loaded
            // value, since an uninitialized multi-byte load is a `Concat` of zero
            // bytes (never a bare `Const`).
            let mut content_provenance = address_provenance.clone();
            content_provenance.extend(st.taint.memory_provenance(a, addr.size));
            content_provenance.sort();
            content_provenance.dedup();
            let val =
                if !content_provenance.is_empty() && !st.machine.mem.is_initialized(a, addr.size) {
                    let w = Width::from_bytes(addr.size as u16);
                    let fresh = st.machine.dom.fresh(w);
                    if let Expr::Sym { id, .. } = *st.machine.dom.pool.get(fresh) {
                        for source in &content_provenance {
                            st.taint.mark(id, format!("*{source}"));
                        }
                    }
                    st.machine
                        .mem
                        .store(&mut st.machine.dom, a, &fresh, addr.size, addr.endian);
                    fresh
                } else {
                    st.machine
                        .mem
                        .load(&mut st.machine.dom, a, addr.size, addr.endian)
                };
            st.machine.regs.write(&mut st.machine.dom, dst, val);
            Some(())
        }
        Op::CondLoad {
            dst,
            cond,
            inverted,
            addr,
            fallback,
        } => {
            let c = st.machine.regs.read(&mut st.machine.dom, cond);
            let execute = match st.machine.dom.as_branch(&c) {
                BranchDecision::Taken => !*inverted,
                BranchDecision::NotTaken => *inverted,
                BranchDecision::Fork => return None,
            };
            if !execute {
                let width = Width::from_bytes(addr.size as u16);
                let value = st.machine.read(fallback, width);
                st.machine.regs.write(&mut st.machine.dom, dst, value);
                return Some(());
            }
            let av = st.machine.eval_addr(addr);
            let a = concretize_addr(st, av)?;
            let value = st
                .machine
                .mem
                .load(&mut st.machine.dom, a, addr.size, addr.endian);
            st.machine.regs.write(&mut st.machine.dom, dst, value);
            Some(())
        }
        Op::Store { addr, src } => {
            let av = st.machine.eval_addr(addr);
            let a = concretize_addr(st, av)?;
            let w = Width::from_bytes(addr.size as u16);
            let v = st.machine.read(src, w);
            st.machine
                .mem
                .store(&mut st.machine.dom, a, &v, addr.size, addr.endian);
            Some(())
        }
        Op::CondStore {
            cond,
            inverted,
            addr,
            src,
        } => {
            let c = st.machine.regs.read(&mut st.machine.dom, cond);
            let execute = match st.machine.dom.as_branch(&c) {
                BranchDecision::Taken => !*inverted,
                BranchDecision::NotTaken => *inverted,
                BranchDecision::Fork => return None,
            };
            if !execute {
                return Some(());
            }
            let av = st.machine.eval_addr(addr);
            let a = concretize_addr(st, av)?;
            let width = Width::from_bytes(addr.size as u16);
            let value = st.machine.read(src, width);
            st.machine
                .mem
                .store(&mut st.machine.dom, a, &value, addr.size, addr.endian);
            Some(())
        }
        _ => None,
    }
}
