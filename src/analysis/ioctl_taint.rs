//! IOCTL-handler abstract interpretation for Windows WDM drivers.
//!
//! Tracks a small register-only abstract domain that recognises the
//! IRP-derived values an IRP_MJ_DEVICE_CONTROL handler touches:
//! the Irp pointer (arg2 / rdx on x64), the IO_STACK_LOCATION pointer
//! (Irp + 0xB8), the SystemBuffer (Irp + 0x18), and the standard
//! Parameters.DeviceIoControl fields (IoControlCode, lengths,
//! Type3InputBuffer).
//!
//! Uses iterative dataflow over the CFG already built by
//! `crate::analysis::cfg`, lifted to LLIR by `crate::ir::lift_function`.
//! At each `Load` / `Store` op we attach the abstract taint of the base
//! register; the caller can then filter for the specific deref pattern
//! they care about (NULL-deref of SystemBuffer, double-fetch on
//! Type3InputBuffer, etc.).
//!
//! See `docs/design/ioctl-taint.md` for the broader design.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use crate::ir::types::{
    BinOp as IrBinOp, CallTarget, CmpOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value,
};

/// Abstract taint values. A register either carries a known IRP-derived
/// kind, a known integer constant (used for null-check inference), or
/// `Top` (we don't know).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Taint {
    Top,
    Const(i64),
    DeviceObject,
    Irp,
    StackLoc,
    SystemBuffer,
    Type3InputBuffer,
    InputLen,
    OutputLen,
    IoCtlCode,
    UserBuffer,
}

impl Taint {
    /// `meet` in the flat-with-bottom lattice. Equal values stay; any
    /// disagreement collapses to `Top`.
    fn meet(self, other: Self) -> Self {
        if self == other {
            self
        } else {
            Taint::Top
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Taint::Top => "Top",
            Taint::Const(_) => "Const",
            Taint::DeviceObject => "DeviceObject",
            Taint::Irp => "Irp",
            Taint::StackLoc => "StackLoc",
            Taint::SystemBuffer => "SystemBuffer",
            Taint::Type3InputBuffer => "Type3InputBuffer",
            Taint::InputLen => "InputLen",
            Taint::OutputLen => "OutputLen",
            Taint::IoCtlCode => "IoCtlCode",
            Taint::UserBuffer => "UserBuffer",
        }
    }
}

/// Per-register abstract state. Missing keys are implicitly `Top`.
pub type State = HashMap<String, Taint>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// One IRP-derived memory access discovered by the analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFinding {
    /// VA of the `Load` or `Store` LLIR op that produced the access.
    pub deref_va: u64,
    /// Start VA of the block containing the deref.
    pub block_va: u64,
    /// Physical register name at the deref (e.g. `"rdi"`).
    pub base_reg: String,
    /// Abstract taint of the base register at the deref point.
    pub base_kind: Taint,
    /// Constant displacement off the base register.
    pub disp: i64,
    /// Access width in bytes (1, 2, 4, 8).
    pub access_width: u8,
    pub access: Access,
    /// True if the base register has been compared against 0 on every
    /// path that reaches this deref, with the deref dominated by the
    /// "not zero" branch.
    pub guarded_by_nullcheck: bool,
}

/// Build an `LlirFunction` from a linear sequence of LLIR instructions
/// by splitting at control-flow terminators and at every jcc/jmp
/// immediate target.
///
/// Glaurung's CFG pass misses jump-table-dispatched case bodies that
/// the compiler emits for IOCTL switches: the table lives in `.rdata`
/// and the dispatch goes through `jmp [rip + rcx*8 + table]`, so the
/// CFG never adds those case-body addresses as block heads. Linear
/// lifting + post-terminator block heads recovers them, at the cost
/// of running the analysis over straight-line code that may include
/// data/padding (we filter on Unknown ops later).
pub fn build_llir_function_linear(entry_va: u64, instrs: Vec<LlirInstr>) -> LlirFunction {
    if instrs.is_empty() {
        return LlirFunction {
            entry_va,
            blocks: vec![],
        };
    }

    // Collect block-head VAs:
    //   - entry_va
    //   - every immediate target of a Jump/CondJump
    //   - the instruction immediately following any terminator
    //     (Return, Unconditional Jump, Unknown)
    let va_set: HashSet<u64> = instrs.iter().map(|i| i.va).collect();
    let mut heads: BTreeSet<u64> = BTreeSet::new();
    heads.insert(entry_va);
    for (i, ins) in instrs.iter().enumerate() {
        match &ins.op {
            Op::Jump { target } | Op::CondJump { target, .. } => {
                if va_set.contains(target) {
                    heads.insert(*target);
                }
            }
            _ => {}
        }
        // ANY terminator-shaped instruction implies the next machine
        // instruction is a new block head:
        //   - Jump (unconditional)
        //   - CondJump (the fall-through path is a new block)
        //   - Return / Unknown (post-terminator may be reached from a
        //     jump table or simply be the start of an orphan region)
        if matches!(
            &ins.op,
            Op::Jump { .. } | Op::CondJump { .. } | Op::Return | Op::Unknown { .. }
        ) {
            // Find the next machine VA. Multiple LLIR ops can share a
            // VA (e.g. cmp expands to several flag writes); we want the
            // first op whose VA strictly exceeds `ins.va`.
            for next in instrs.iter().skip(i + 1) {
                if next.va > ins.va {
                    heads.insert(next.va);
                    break;
                }
            }
        }
    }

    // Position each head at the FIRST index where its VA appears in
    // `instrs`. Multiple LLIR ops can share a VA (a `cmp` machine insn
    // expands into a Load + 5 Cmp flag-writes + a Bin), and collecting
    // straight into a HashMap keeps the LAST entry per key — which
    // would make `end_idx` point at the LAST op of the next head's VA,
    // bleeding all-but-one of those expansion ops INTO the previous
    // block. Use `entry().or_insert(i)` to lock in the first occurrence.
    let mut pos_of_va: HashMap<u64, usize> = HashMap::new();
    for (i, ins) in instrs.iter().enumerate() {
        pos_of_va.entry(ins.va).or_insert(i);
    }
    let mut head_positions: Vec<(u64, usize)> = heads
        .iter()
        .filter_map(|va| pos_of_va.get(va).map(|p| (*va, *p)))
        .collect();
    head_positions.sort_by_key(|(_, p)| *p);

    // Build blocks: [head_pos[i] .. head_pos[i+1]).
    let mut blocks: Vec<LlirBlock> = Vec::with_capacity(head_positions.len());
    for (k, (head_va, start_idx)) in head_positions.iter().enumerate() {
        let end_idx = head_positions
            .get(k + 1)
            .map(|(_, p)| *p)
            .unwrap_or(instrs.len());
        if end_idx == 0 || end_idx <= *start_idx {
            continue;
        }
        let block_instrs = instrs[*start_idx..end_idx].to_vec();
        let end_va = block_instrs.last().map(|i| i.va).unwrap_or(*head_va) + 1;
        // Compute successors from the last op of the block.
        let mut succs: Vec<u64> = Vec::new();
        if let Some(last) = block_instrs.last() {
            match &last.op {
                Op::Jump { target } => {
                    if va_set.contains(target) {
                        succs.push(*target);
                    }
                }
                Op::CondJump { target, .. } => {
                    if va_set.contains(target) {
                        succs.push(*target);
                    }
                    // Fall-through is the next head, if any. We
                    // compare VAs (not head positions) because the
                    // fall-through head must be at a strictly larger
                    // VA than the cond_jump's own VA.
                    let cur_va = block_instrs.last().map(|i| i.va).unwrap_or(0);
                    for (nva, _) in head_positions.iter().skip(k + 1) {
                        if *nva > cur_va {
                            succs.push(*nva);
                            break;
                        }
                    }
                }
                Op::Return | Op::Unknown { .. } => {} // no successors
                _ => {
                    // Fall-through to the next head.
                    if let Some(&(nva, _)) = head_positions.get(k + 1) {
                        succs.push(nva);
                    }
                }
            }
        }
        succs.sort_unstable();
        succs.dedup();
        blocks.push(LlirBlock {
            start_va: *head_va,
            end_va,
            instrs: block_instrs,
            succs,
        });
    }

    LlirFunction { entry_va, blocks }
}

/// Output of the analysis pass.
#[derive(Debug, Clone, Default)]
pub struct IoctlTaintResult {
    /// IRP-derived memory accesses, in deref-VA order.
    pub findings: Vec<TaintFinding>,
    /// Per-block IN abstract state. Useful for debugging and for
    /// follow-up detectors that need register provenance at a specific
    /// block head.
    pub block_in: BTreeMap<u64, State>,
    /// Heuristically-chosen state used to seed orphan (jump-table)
    /// case bodies. Exposed for debugging.
    pub dispatcher_state: State,
}

// --- Register aliasing (x86-64) ---------------------------------------------

/// Map every named sub-register to its 64-bit canonical root. Both ARM64
/// and x86-32 callers can pass through unrecognised names (they map to
/// themselves).
fn canon_reg(name: &str) -> &str {
    match name {
        // RAX family
        "rax" | "eax" | "ax" | "ah" | "al" => "rax",
        // RBX
        "rbx" | "ebx" | "bx" | "bh" | "bl" => "rbx",
        // RCX
        "rcx" | "ecx" | "cx" | "ch" | "cl" => "rcx",
        // RDX
        "rdx" | "edx" | "dx" | "dh" | "dl" => "rdx",
        // RSI
        "rsi" | "esi" | "si" | "sil" => "rsi",
        // RDI
        "rdi" | "edi" | "di" | "dil" => "rdi",
        // RBP
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        // RSP
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        // R8..R15
        "r8" | "r8d" | "r8w" | "r8b" | "r8l" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" | "r9l" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" | "r10l" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" | "r11l" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" | "r12l" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" | "r13l" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" | "r14l" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" | "r15l" => "r15",
        other => other,
    }
}

fn vreg_canon(v: &VReg) -> Option<String> {
    match v {
        VReg::Phys(n) => Some(canon_reg(n).to_string()),
        _ => None,
    }
}

/// MS x64 caller-saved general-purpose registers. A `Call` clobbers
/// these (the function we're calling may overwrite them); callee-saved
/// registers retain their abstract taint across a call boundary.
const CALLER_SAVED: &[&str] = &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

// --- Struct-field map -------------------------------------------------------

/// Given an abstract base value and a displacement, return the abstract
/// value of the loaded field. `None` if no rule matches.
fn struct_field(base: Taint, disp: i64) -> Option<Taint> {
    match (base, disp) {
        (Taint::Irp, 0x18) => Some(Taint::SystemBuffer),
        (Taint::Irp, 0x30) => Some(Taint::UserBuffer),
        (Taint::Irp, 0xB8) => Some(Taint::StackLoc),
        (Taint::StackLoc, 0x08) => Some(Taint::OutputLen),
        (Taint::StackLoc, 0x10) => Some(Taint::InputLen),
        (Taint::StackLoc, 0x18) => Some(Taint::IoCtlCode),
        (Taint::StackLoc, 0x20) => Some(Taint::Type3InputBuffer),
        _ => None,
    }
}

// --- Lattice ----------------------------------------------------------------

/// Set `state[reg]` to `value`. Writing to a register also kills any
/// sibling sub-register entries by canonicalising.
fn write_reg(state: &mut State, reg: &str, value: Taint) {
    let key = canon_reg(reg).to_string();
    if value == Taint::Top {
        state.remove(&key);
    } else {
        state.insert(key, value);
    }
}

fn read_reg(state: &State, reg: &str) -> Taint {
    state
        .get(canon_reg(reg))
        .copied()
        .unwrap_or(Taint::Top)
}

/// In-place meet of `into` ← `into ∧ other`. Returns true when `into`
/// changed.
fn meet_into(into: &mut State, other: &State) -> bool {
    let mut changed = false;
    // First handle keys in `into`: meet with `other` (missing in other = Top).
    let keys: Vec<String> = into.keys().cloned().collect();
    for k in keys {
        let a = into.get(&k).copied().unwrap_or(Taint::Top);
        let b = other.get(&k).copied().unwrap_or(Taint::Top);
        let m = a.meet(b);
        if m == Taint::Top {
            into.remove(&k);
            changed = true;
        } else if m != a {
            into.insert(k, m);
            changed = true;
        }
    }
    // Keys only in `other` meet against Top → drop. Nothing to add.
    let _ = other;
    changed
}

// --- Null-check tracking ----------------------------------------------------

/// A pending flag definition that says "flag = (R == 0)". When a
/// `CondJump` later branches on this flag, we know R is null on the
/// taken side (`!inverted`) or non-null on the fall-through side.
#[derive(Debug, Clone)]
struct NullEq {
    /// Canonical register name being compared against 0.
    reg: String,
}

/// Per-block view of "registers known non-null on entry to this block".
type NonNull = BTreeSet<String>;

// --- Transfer function ------------------------------------------------------

fn transfer_value(state: &State, v: &Value) -> Taint {
    match v {
        Value::Reg(r) => vreg_canon(r)
            .map(|c| read_reg(state, &c))
            .unwrap_or(Taint::Top),
        Value::Const(c) => Taint::Const(*c),
        Value::Addr(_) => Taint::Top,
    }
}

/// Apply a single op to `state`. Returns an optional null-check
/// definition the op just produced (used downstream to refine `nonnull`
/// on branch edges).
fn apply_op(state: &mut State, op: &Op) -> Option<NullEq> {
    match op {
        Op::Assign { dst, src } => {
            let v = transfer_value(state, src);
            if let Some(d) = vreg_canon(dst) {
                write_reg(state, &d, v);
            }
            None
        }
        Op::CondAssign { dst, .. } => {
            if let Some(d) = vreg_canon(dst) {
                write_reg(state, &d, Taint::Top);
            }
            None
        }
        Op::Bin { dst, op, lhs, rhs } => {
            // Special case: `xor r, r` is the canonical zero idiom. Track
            // it as Const(0) so downstream code recognises it as a null
            // marker. Everything else loses taint.
            if matches!(op, IrBinOp::Xor) {
                if let (Value::Reg(a), Value::Reg(b)) = (lhs, rhs) {
                    if vreg_canon(a) == vreg_canon(b) {
                        if let Some(d) = vreg_canon(dst) {
                            write_reg(state, &d, Taint::Const(0));
                        }
                        return None;
                    }
                }
            }
            if let Some(d) = vreg_canon(dst) {
                write_reg(state, &d, Taint::Top);
            }
            None
        }
        Op::Un { dst, .. } => {
            if let Some(d) = vreg_canon(dst) {
                write_reg(state, &d, Taint::Top);
            }
            None
        }
        Op::Cmp { dst: _, op, lhs, rhs } => {
            // Recognise null-against-self idiom (TEST R, R) and
            // explicit `CMP R, 0`. Both make the Z flag = (R == 0).
            //
            // The lifter encodes `test r, r` as Cmp(Eq, R, R) writing
            // Flag::Z, and `cmp r, 0` as Cmp(Eq, R, 0). Either is good
            // enough.
            let (subj, val) = (lhs, rhs);
            let subj_reg = if let Value::Reg(r) = subj {
                vreg_canon(r)
            } else {
                None
            };
            let val_is_self = matches!((subj, val), (Value::Reg(a), Value::Reg(b)) if vreg_canon(a) == vreg_canon(b));
            let val_is_zero = matches!(val, Value::Const(0));
            if matches!(op, CmpOp::Eq) && subj_reg.is_some() && (val_is_self || val_is_zero) {
                return Some(NullEq {
                    reg: subj_reg.unwrap(),
                });
            }
            None
        }
        Op::Load { dst, addr } => {
            let v = transfer_load(state, addr);
            if let Some(d) = vreg_canon(dst) {
                write_reg(state, &d, v);
            }
            None
        }
        Op::Store { .. } => None,
        Op::Call { .. } => {
            for r in CALLER_SAVED {
                state.remove(*r);
            }
            None
        }
        Op::Jump { .. } | Op::CondJump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => None,
    }
}

fn transfer_load(state: &State, addr: &MemOp) -> Taint {
    let Some(base) = &addr.base else {
        return Taint::Top;
    };
    let Some(base_canon) = vreg_canon(base) else {
        return Taint::Top;
    };
    let base_taint = read_reg(state, &base_canon);
    if let Some(t) = struct_field(base_taint, addr.disp) {
        t
    } else {
        Taint::Top
    }
}

// --- Driver: per-function fixpoint -----------------------------------------

/// Build a map from block start VA → block index, so we can resolve
/// CFG successors quickly.
fn va_index(lf: &LlirFunction) -> HashMap<u64, usize> {
    lf.blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect()
}

/// Walk a block's ops, applying the transfer function and recording
/// every IRP-derived memory access. The block-entry `nonnull` set is
/// refined intra-block by Cmp/CondJump pairs (only the CondJump at the
/// end of the block matters for successors; this function does not
/// propagate that — that's the caller's job).
fn step_block(
    block: &LlirBlock,
    in_state: &State,
    in_nonnull: &NonNull,
    findings: &mut Vec<TaintFinding>,
) -> (State, Vec<EdgeFact>) {
    let mut state = in_state.clone();
    let mut local_nonnull = in_nonnull.clone();
    let mut pending_nulleq: Option<NullEq> = None;

    for (idx, ins) in block.instrs.iter().enumerate() {
        // Record any IRP-derived deref BEFORE we apply the op's
        // register write (the read happens before the write on the
        // same instruction).
        match &ins.op {
            Op::Load { addr, .. } => {
                if let Some(f) = make_finding(state.borrow_state(), &local_nonnull, block.start_va, ins.va, addr, Access::Read) {
                    findings.push(f);
                }
            }
            Op::Store { addr, .. } => {
                if let Some(f) = make_finding(state.borrow_state(), &local_nonnull, block.start_va, ins.va, addr, Access::Write) {
                    findings.push(f);
                }
            }
            _ => {}
        }

        // Apply the op to the abstract state.
        let nulleq = apply_op(&mut state, &ins.op);

        // If this op produced a null-eq flag, remember it; the CondJump
        // at end-of-block will consume it.
        if nulleq.is_some() {
            pending_nulleq = nulleq;
        }

        // Intra-block: a successful null-check (`if (R == NULL) goto X`
        // not taken) refines `local_nonnull` only for the fall-through
        // successor — we don't model that intra-block here. For
        // multi-branch IOCTL dispatchers the deref happens inside a
        // case body block, not the dispatcher, so the nonnull info has
        // to propagate via edges. See edge handling below.

        // Suppress lint about idx if not used in future iterations.
        let _ = idx;
    }

    // Determine outgoing edges with refined nonnull facts.
    let mut edges: Vec<EdgeFact> = Vec::new();
    let last = block.instrs.last().map(|i| &i.op);
    match last {
        Some(Op::CondJump { cond: _, target, inverted }) => {
            // Any pending NullEq from this block applies. The lifter
            // emits cmp/test → flag write → jcc reading that flag in a
            // contiguous sequence; the most recent NullEq within the
            // block is what this CondJump is branching on. Flag VRegs
            // are not physical so we don't try to match flag names.
            let nulleq = pending_nulleq.as_ref();
            // Two successors: the conditional target and (typically)
            // the fall-through.
            // Successors are recorded in block.succs; we treat the
            // first entry == target as the taken side.
            let taken_va = *target;
            let mut taken_nonnull = local_nonnull.clone();
            let mut not_taken_nonnull = local_nonnull.clone();
            if let Some(neq) = nulleq {
                if *inverted {
                    // jne / jnz: taken when flag is FALSE
                    // → taken means (R == 0) is false → R nonnull on taken
                    // → fallthrough means R IS zero
                    taken_nonnull.insert(neq.reg.clone());
                } else {
                    // je / jz: taken when flag is TRUE
                    // → taken means R IS zero
                    // → fallthrough means R is nonnull
                    not_taken_nonnull.insert(neq.reg.clone());
                }
            }
            for s in &block.succs {
                let nn = if *s == taken_va {
                    taken_nonnull.clone()
                } else {
                    not_taken_nonnull.clone()
                };
                edges.push(EdgeFact { to_va: *s, state: state.clone(), nonnull: nn });
            }
        }
        _ => {
            for s in &block.succs {
                edges.push(EdgeFact { to_va: *s, state: state.clone(), nonnull: local_nonnull.clone() });
            }
        }
    }

    (state, edges)
}

/// Helper trait to expose &State from a State (alias-free workaround).
trait BorrowState {
    fn borrow_state(&self) -> &State;
}
impl BorrowState for State {
    fn borrow_state(&self) -> &State {
        self
    }
}

struct EdgeFact {
    to_va: u64,
    state: State,
    nonnull: NonNull,
}

fn make_finding(
    state: &State,
    nonnull: &NonNull,
    block_va: u64,
    deref_va: u64,
    addr: &MemOp,
    access: Access,
) -> Option<TaintFinding> {
    let base = addr.base.as_ref()?;
    let base_canon = vreg_canon(base)?;
    let kind = read_reg(state, &base_canon);
    let interesting = matches!(
        kind,
        Taint::SystemBuffer | Taint::UserBuffer | Taint::Type3InputBuffer
    );
    if !interesting {
        return None;
    }
    Some(TaintFinding {
        deref_va,
        block_va,
        base_reg: base_canon.clone(),
        base_kind: kind,
        disp: addr.disp,
        access_width: addr.size,
        access,
        guarded_by_nullcheck: nonnull.contains(&base_canon),
    })
}

/// Run the IOCTL abstract-interpretation pass on a single function.
pub fn analyze(lf: &LlirFunction) -> IoctlTaintResult {
    let n = lf.blocks.len();
    if n == 0 {
        return IoctlTaintResult::default();
    }

    let idx = va_index(lf);

    // Per-block IN states + IN nonnull sets. A block is "visited" once
    // at least one predecessor edge has been folded into it; subsequent
    // edges meet with the existing IN (lossy on disagreement), but the
    // FIRST edge seeds the state verbatim.
    let mut block_in: Vec<State> = vec![State::new(); n];
    let mut block_nonnull: Vec<NonNull> = vec![NonNull::new(); n];
    let mut block_seeded: Vec<bool> = vec![false; n];

    // Initial state for the entry block (MS x64 calling convention):
    //   rcx = arg1 = DeviceObject
    //   rdx = arg2 = Irp
    let entry_idx = idx.get(&lf.entry_va).copied().unwrap_or(0);
    let mut entry = State::new();
    entry.insert("rcx".to_string(), Taint::DeviceObject);
    entry.insert("rdx".to_string(), Taint::Irp);
    block_in[entry_idx] = entry;
    block_seeded[entry_idx] = true;

    // Findings are accumulated; the final result keeps the latest
    // findings produced when each block's IN reached fixpoint.
    let mut findings: Vec<TaintFinding> = Vec::new();

    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(entry_idx);
    let mut in_worklist: Vec<bool> = vec![false; n];
    in_worklist[entry_idx] = true;

    // Cap iterations defensively; a flat lattice + meet should
    // terminate quickly but malformed CFGs could in principle loop.
    let mut steps = 0usize;
    let max_steps = 32 * n + 256;

    while let Some(bi) = worklist.pop_front() {
        in_worklist[bi] = false;
        steps += 1;
        if steps > max_steps {
            break;
        }

        let in_state = block_in[bi].clone();
        let in_nn = block_nonnull[bi].clone();

        let mut local_findings: Vec<TaintFinding> = Vec::new();
        let (_out_state, edges) = step_block(&lf.blocks[bi], &in_state, &in_nn, &mut local_findings);
        // Replace findings for this block on every revisit. We index
        // findings by deref_va so duplicates from re-visits get
        // overwritten cleanly at the end.
        for f in local_findings {
            // De-dup later; preserve latest.
            findings.push(f);
        }

        for ef in edges {
            if let Some(&succ_idx) = idx.get(&ef.to_va) {
                let (changed_state, changed_nn) = if !block_seeded[succ_idx] {
                    // First arrival at this successor: seed verbatim.
                    block_in[succ_idx] = ef.state.clone();
                    block_nonnull[succ_idx] = ef.nonnull.clone();
                    block_seeded[succ_idx] = true;
                    (true, true)
                } else {
                    let cs = meet_into(&mut block_in[succ_idx], &ef.state);
                    let before = block_nonnull[succ_idx].clone();
                    block_nonnull[succ_idx] =
                        block_nonnull[succ_idx].intersection(&ef.nonnull).cloned().collect();
                    let cn = block_nonnull[succ_idx] != before;
                    (cs, cn)
                };
                if (changed_state || changed_nn) && !in_worklist[succ_idx] {
                    worklist.push_back(succ_idx);
                    in_worklist[succ_idx] = true;
                }
            }
        }
    }

    // Second pass: jump-table-dispatched case bodies have no CFG
    // predecessors and never received the entry-block's IRP-derived
    // taint state. For each orphan block, seed its IN with the
    // function-wide stable state: the meet (most-precise consensus)
    // of OUT-states across every real-worklist-seeded block.
    //
    // Why this works for IOCTL handlers: the prologue loads
    // SystemBuffer / StackLoc / etc into callee-saved registers once,
    // and they stay constant for the rest of the function. So those
    // registers have the SAME abstract value at every seeded OUT —
    // the meet keeps them. Caller-saved scratch registers that get
    // clobbered by intermediate calls disagree across paths and meet
    // to Top, which is correct (we can't trust them at orphan
    // entry).
    //
    // Linear-VA seeding chains the previous approach used (orphan
    // inheriting from immediately-prior OUT) loses state if any
    // single intermediate block has a clobbering call. The
    // function-meet is robust to that.
    let stable_state: State =
        choose_dispatcher_state(&lf, &block_in, &block_nonnull, &block_seeded);

    let mut blocks_by_va: Vec<(usize, u64)> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (i, b.start_va))
        .collect();
    blocks_by_va.sort_by_key(|(_, va)| *va);

    for &(i, _va) in &blocks_by_va {
        if block_seeded[i] {
            continue;
        }
        block_in[i] = stable_state.clone();
        block_seeded[i] = true;
        let mut tmp: Vec<TaintFinding> = Vec::new();
        let (_out_state, _edges) = step_block(
            &lf.blocks[i],
            &block_in[i],
            &block_nonnull[i],
            &mut tmp,
        );
        for f in tmp {
            findings.push(f);
        }
    }

    // De-duplicate findings by deref_va, keeping the LAST (latest
    // fixpoint state).
    let mut by_va: BTreeMap<u64, TaintFinding> = BTreeMap::new();
    for f in findings {
        by_va.insert(f.deref_va, f);
    }
    let findings: Vec<TaintFinding> = by_va.into_values().collect();

    // Convert block_in vec → BTreeMap keyed by start VA.
    let block_in_map: BTreeMap<u64, State> = lf
        .blocks
        .iter()
        .zip(block_in.into_iter())
        .map(|(b, s)| (b.start_va, s))
        .collect();

    IoctlTaintResult {
        findings,
        block_in: block_in_map,
        dispatcher_state: stable_state,
    }
}

/// Choose the OUT-state to seed orphan (jump-table-dispatched) case
/// bodies with. The IOCTL switch dispatcher block has — by
/// construction — the richest IRP-derived register state in the
/// function: SystemBuffer, StackLoc, and IoCtlCode are all live at the
/// indirect jmp out of it. We approximate "is this the dispatcher?"
/// by counting how many distinct IRP-derived taints appear in the
/// block's OUT state.
///
/// Ties: prefer the earliest-VA candidate. Multiple-major-function
/// handlers have one dispatcher per major function; the IOCTL one is
/// typically the first to reach maximum richness.
fn choose_dispatcher_state(
    lf: &LlirFunction,
    block_in: &[State],
    block_nonnull: &[NonNull],
    block_seeded: &[bool],
) -> State {
    fn ioctl_score(s: &State) -> usize {
        // Count the number of registers holding a "deep" IRP-derived
        // value. SystemBuffer / UserBuffer / Type3InputBuffer / StackLoc
        // / IoCtlCode / InputLen / OutputLen all signal "we made it
        // into the dispatcher". Irp / DeviceObject by themselves are
        // entry-block state and not unique to a dispatcher.
        s.values()
            .filter(|t| {
                matches!(
                    t,
                    Taint::SystemBuffer
                        | Taint::UserBuffer
                        | Taint::Type3InputBuffer
                        | Taint::StackLoc
                        | Taint::IoCtlCode
                        | Taint::InputLen
                        | Taint::OutputLen
                )
            })
            .count()
    }
    let mut best: Option<(usize, u64, State)> = None;
    for (i, block) in lf.blocks.iter().enumerate() {
        if !block_seeded[i] {
            continue;
        }
        let mut tmp: Vec<TaintFinding> = Vec::new();
        let (out_state, _edges) =
            step_block(block, &block_in[i], &block_nonnull[i], &mut tmp);
        let score = ioctl_score(&out_state);
        if score == 0 {
            continue;
        }
        let va = block.start_va;
        let pick = match &best {
            None => true,
            Some((bs, bv, _)) => score > *bs || (score == *bs && va < *bv),
        };
        if pick {
            best = Some((score, va, out_state));
        }
    }
    best.map(|(_, _, s)| s).unwrap_or_default()
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::*;

    fn vr(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn instr(va: u64, op: Op) -> LlirInstr {
        LlirInstr { va, op }
    }

    fn block(start: u64, end: u64, instrs: Vec<LlirInstr>, succs: Vec<u64>) -> LlirBlock {
        LlirBlock { start_va: start, end_va: end, instrs, succs }
    }

    /// Synthesise the usbprint.sys SystemBuffer dispatch shape:
    /// entry block loads SystemBuffer into rdi, then we jump to a case
    /// body that does `[rdi + 0]`.
    #[test]
    fn detects_systembuffer_deref_via_case_body() {
        let entry = block(
            0x1000,
            0x1010,
            vec![
                // mov rsi, rdx  (rsi = Irp)
                instr(0x1000, Op::Assign { dst: vr("rsi"), src: Value::Reg(vr("rdx")) }),
                // mov rdi, [rsi + 0x18]  (rdi = SystemBuffer)
                instr(
                    0x1003,
                    Op::Load {
                        dst: vr("rdi"),
                        addr: MemOp::plain(Some(vr("rsi")), None, 0, 0x18, 8),
                    },
                ),
                // jmp 0x2000
                instr(0x1006, Op::Jump { target: 0x2000 }),
            ],
            vec![0x2000],
        );
        let case = block(
            0x2000,
            0x2008,
            vec![
                // movzx eax, byte [rdi]   ← BUG site
                instr(
                    0x2000,
                    Op::Load {
                        dst: vr("rax"),
                        addr: MemOp::plain(Some(vr("rdi")), None, 0, 0, 1),
                    },
                ),
                instr(0x2004, Op::Return),
            ],
            vec![],
        );
        let lf = LlirFunction { entry_va: 0x1000, blocks: vec![entry, case] };
        let res = analyze(&lf);
        assert_eq!(res.findings.len(), 1, "{:?}", res.findings);
        let f = &res.findings[0];
        assert_eq!(f.deref_va, 0x2000);
        assert_eq!(f.base_kind, Taint::SystemBuffer);
        assert_eq!(f.base_reg, "rdi");
        assert_eq!(f.disp, 0);
        assert!(!f.guarded_by_nullcheck);
    }

    /// Stack-loc reload pattern: r14 = [rdx + 0xB8] (StackLoc). Later
    /// `mov [r14 + 0], edx` MUST NOT be flagged as a SystemBuffer deref.
    /// This is the xboxgip.sys false-positive shape from the v5 sweep.
    #[test]
    fn does_not_confuse_stackloc_with_systembuffer() {
        let entry = block(
            0x3000,
            0x3010,
            vec![
                // mov r14, [rdx + 0xB8]   (r14 = StackLoc)
                instr(
                    0x3000,
                    Op::Load {
                        dst: vr("r14"),
                        addr: MemOp::plain(Some(vr("rdx")), None, 0, 0xB8, 8),
                    },
                ),
                // mov [r14 + 0], edx       ← would be FP under v5 monotonic
                instr(
                    0x3007,
                    Op::Store {
                        addr: MemOp::plain(Some(vr("r14")), None, 0, 0, 4),
                        src: Value::Reg(vr("edx")),
                    },
                ),
                instr(0x300a, Op::Return),
            ],
            vec![],
        );
        let lf = LlirFunction { entry_va: 0x3000, blocks: vec![entry] };
        let res = analyze(&lf);
        assert!(res.findings.is_empty(), "FP cluster: {:?}", res.findings);
    }

    /// Null-check on the SystemBuffer-tainted register: the deref on
    /// the "non-null" branch should be marked `guarded_by_nullcheck`.
    #[test]
    fn null_check_guards_following_deref() {
        let entry = block(
            0x4000,
            0x4010,
            vec![
                // rdi = [rdx + 0x18]   (SystemBuffer)
                instr(
                    0x4000,
                    Op::Load {
                        dst: vr("rdi"),
                        addr: MemOp::plain(Some(vr("rdx")), None, 0, 0x18, 8),
                    },
                ),
                // test rdi, rdi   →  Cmp(Eq, rdi, rdi) writing %zf
                instr(
                    0x4007,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(vr("rdi")),
                        rhs: Value::Reg(vr("rdi")),
                    },
                ),
                // je 0x4100   (taken == "rdi IS zero"; we don't deref on that path)
                // jne 0x4100 inverted=true means "taken when not zero".
                // Lift inverted matches the existing `lift_x86` convention.
                instr(
                    0x400a,
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x4100, // "rdi == 0" target
                        inverted: false,
                    },
                ),
            ],
            vec![0x4100, 0x4020],
        );
        let null_path = block(
            0x4100,
            0x4104,
            vec![instr(0x4100, Op::Return)],
            vec![],
        );
        let safe_path = block(
            0x4020,
            0x4028,
            vec![
                // movzx eax, byte [rdi]   ← guarded by the null check
                instr(
                    0x4020,
                    Op::Load {
                        dst: vr("rax"),
                        addr: MemOp::plain(Some(vr("rdi")), None, 0, 0, 1),
                    },
                ),
                instr(0x4024, Op::Return),
            ],
            vec![],
        );
        let lf = LlirFunction {
            entry_va: 0x4000,
            blocks: vec![entry, null_path, safe_path],
        };
        let res = analyze(&lf);
        let f = res
            .findings
            .iter()
            .find(|f| f.deref_va == 0x4020)
            .expect("expected a SystemBuffer deref at 0x4020");
        assert_eq!(f.base_kind, Taint::SystemBuffer);
        assert!(
            f.guarded_by_nullcheck,
            "deref on the not-null branch should be marked guarded"
        );
    }

    /// MS x64 call clobbers caller-saved regs: SystemBuffer in rdx
    /// (caller-saved) is lost across a call, but if it was in rdi
    /// (callee-saved) it survives.
    #[test]
    fn call_clobbers_caller_saved_only() {
        let lf = LlirFunction {
            entry_va: 0x5000,
            blocks: vec![block(
                0x5000,
                0x5020,
                vec![
                    // rax = [rdx + 0x18]  (rax = SystemBuffer)
                    instr(
                        0x5000,
                        Op::Load {
                            dst: vr("rax"),
                            addr: MemOp::plain(Some(vr("rdx")), None, 0, 0x18, 8),
                        },
                    ),
                    // rdi = [rdx + 0x18]  (rdi = SystemBuffer)
                    instr(
                        0x5007,
                        Op::Load {
                            dst: vr("rdi"),
                            addr: MemOp::plain(Some(vr("rdx")), None, 0, 0x18, 8),
                        },
                    ),
                    // call foo
                    instr(
                        0x500e,
                        Op::Call {
                            target: CallTarget::Direct(0xDEAD),
                        },
                    ),
                    // After call: rax must be Top, rdi must still be SystemBuffer
                    instr(
                        0x5013,
                        Op::Load {
                            dst: vr("rcx"),
                            addr: MemOp::plain(Some(vr("rax")), None, 0, 0, 1),
                        },
                    ),
                    instr(
                        0x5018,
                        Op::Load {
                            dst: vr("rcx"),
                            addr: MemOp::plain(Some(vr("rdi")), None, 0, 0, 1),
                        },
                    ),
                    instr(0x501c, Op::Return),
                ],
                vec![],
            )],
        };
        let res = analyze(&lf);
        // Only the rdi-based deref at 0x5018 should be a finding.
        let interesting: Vec<&TaintFinding> = res
            .findings
            .iter()
            .filter(|f| f.base_kind == Taint::SystemBuffer)
            .collect();
        assert_eq!(interesting.len(), 1, "{:?}", res.findings);
        assert_eq!(interesting[0].deref_va, 0x5018);
        assert_eq!(interesting[0].base_reg, "rdi");
    }
}
