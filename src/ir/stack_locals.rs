//! Promote stack-relative memory accesses to named locals.
//!
//! A lot of decompiled noise comes from seeing `*(u64)&[%rsp+0x158]` over
//! and over. This pass rewrites every such access whose base is a stack
//! register (rsp/ebp/sp/x29) and whose effective address is a constant
//! displacement into a named local variable. A slot is identified by its
//! `(base, disp)` alone, so a read and a write of the same slot resolve to one
//! local (keeping its def/use chain intact); the recovered access width is
//! carried alongside the name and narrowed to the true load width.
//!
//! Naming:
//! * Positive displacements from rsp/sp — likely caller-allocated scratch —
//!   become `stack_N` where N counts the slot in first-appearance order.
//! * Negative displacements from a frame pointer (rbp/x29) — classic local
//!   variables — become `local_N`.
//! * Zero-displacement `[rsp]` (stack top) becomes `stack_top`.
//!
//! Pointer arithmetic that isn't a concrete load/store (e.g. `rsp = rsp - 8`)
//! is **not** touched — those are stack-pointer updates that should keep
//! the `%rsp` form so a reader can see the prologue/epilogue shape. Address-valued
//! call arguments are different: a constant frame-relative address is promoted
//! to [`Expr::StackAddr`] so the C renderer passes `&local_N`, never arithmetic
//! on an uninitialised `rbp`/`rsp` local.

use std::collections::{HashMap, HashSet};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

mod address_aliases;
#[cfg(test)]
mod arm32_tests;
mod bounded_overlap;

const STACK_BASES: &[&str] = &["rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "fp"];
const FRAME_POINTER_BASES: &[&str] = &["rbp", "ebp", "bp", "x29", "w29", "fp"];

fn is_stack_base(name: &str) -> bool {
    STACK_BASES.contains(&name)
}

fn is_frame_pointer(name: &str) -> bool {
    FRAME_POINTER_BASES.contains(&name)
}

/// Opaque key for the (base_name, disp) of a stack slot. Deliberately does NOT
/// include the access size: the *same* memory slot is often read and written at
/// spellings the lowering reports with different sizes (a 4-byte load vs a store
/// whose size we don't thread through), and keying on size would then mint two
/// different local names for one variable — severing its def/use chain. The
/// recovered size is tracked in the map *value* instead (see [`SlotVal`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SlotKey {
    base: String,
    disp: i64,
}

/// Promoted local metadata. `declared_size` is the narrowest access width and
/// drives the C declaration; `span_size` is the widest access and records the
/// bytes owned by the slot so a later field read inside a wide spill can be
/// extracted from the parent instead of becoming an undefined overlapping local.
#[derive(Debug, Clone)]
struct SlotVal {
    name: String,
    declared_size: u8,
    span_size: u8,
    /// A bounded stack object recovered from indexed frame accesses.  Every
    /// constant and indexed access inside this interval must be rendered
    /// through the same byte-array identity; otherwise an earlier zeroing
    /// store and a later indexed load become unrelated C locals.
    object_size: Option<u16>,
    /// Whether an observed boundary proves the end of this object. A negative
    /// address escape with no following slot uses a conservative extent to the
    /// frame base; that extent may support the escaped cursor itself, but must
    /// not absorb unrelated current-SP accesses through coordinate aliasing.
    bounded_object: bool,
    /// Exact source spelling recovered from authoritative debug information.
    /// This remains separate from machine width: `COLUMN *` and `long` can
    /// both occupy eight bytes while having fundamentally different C types.
    source_type: Option<String>,
    source_name: Option<String>,
    /// Whether `object_size` is the source-declared extent rather than a
    /// recovered guess. `bounded_object` says only that SOMETHING bounds the
    /// object — a neighbouring slot, a partition boundary — which is enough to
    /// stop it swallowing what follows and not enough to reason about its last
    /// byte. Only an exact extent makes a one-past-the-end address meaningful.
    debug_proven: bool,
}

#[derive(Clone, Copy)]
struct StackContext {
    cc: Option<CallConv>,
    rbp_repurposed: bool,
    /// Whether the body establishes an x86 frame pointer (`mov %rsp, %rbp`).
    /// When it does, the function has TWO frame anchors — `rbp` and the entry
    /// stack pointer — separated by a constant, so `rbp-0x8` and
    /// `entry_rsp-0x8` are different storage that would want the same
    /// offset-bearing name.
    frame_pointer_established: bool,
    /// The ARM32 register this body proves is its frame anchor, in the
    /// encoding's own spelling. See [`arm_frame_register`].
    arm_frame_register: Option<&'static str>,
    /// Exact source-level arity when debug/prototype evidence locks it.
    /// Candidate stack arguments at or beyond this bound are frame storage,
    /// never additional parameters invented from a recovered displacement.
    parameter_count: Option<usize>,
}

/// Authoritative source-level extent for one stack-resident aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackObjectHint {
    pub base: String,
    pub disp: i64,
    pub size: u16,
    pub aggregate: bool,
    pub source_name: Option<String>,
    pub c_type: Option<String>,
    /// Whether the producer expressed this object against `DW_OP_call_frame_cfa`
    /// rather than a named base register.
    ///
    /// The CFA is the CALLER's stack pointer, and the x86 front end spells it
    /// here as a frame-pointer displacement — which is only a real coordinate
    /// when the body establishes a frame pointer. A `-O2` body that omits one
    /// addresses the same storage from the entry stack pointer, so the hint has
    /// to be rebased rather than silently naming storage nothing references.
    /// A hint the producer read from an actual base register (`DW_OP_breg6`) is
    /// already in the coordinate the body uses and is never rebased.
    pub cfa_relative: bool,
}

/// Source-level facts recovered while promoting frame storage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackLocalFacts {
    pub sizes: HashMap<String, u8>,
    pub source_types: HashMap<String, String>,
    pub source_names: HashMap<String, String>,
    /// Frame coordinate `(base, disp)` each promoted name was minted from.
    ///
    /// This is the join MIR evidence needs. MIR memory objects are keyed by
    /// `ObjectIdentity::MirValue(ValueId)` over numbered LLIR, while the AST
    /// consumers are keyed by the promoted-local NAME, and the name cannot be
    /// parsed back into a coordinate: `local_{disp:x}` keeps only
    /// `disp.unsigned_abs()`, losing the base and the sign, and the mint
    /// deliberately falls back to an appearance-order `stack_N` when that hex
    /// name is taken — exactly because `rbp-0x18` and `entry_rsp-0x18` are
    /// different storage. Only this pass knows the answer, so it publishes it.
    ///
    /// A name reachable from two different coordinates is WITHHELD rather than
    /// resolved to whichever slot was iterated last. Several machine keys
    /// intentionally collapse to one source role (`entry_rsp+0` and `esp+0`
    /// both render as `stack_top`), and binding object evidence through an
    /// ambiguous name would attach a proven fact to the wrong variable.
    pub frame_coordinates: HashMap<String, (String, i64)>,
}

fn merge_source_type(current: &mut Option<String>, incoming: Option<&str>) {
    let Some(incoming) = incoming else {
        return;
    };
    match current {
        None => *current = Some(incoming.to_string()),
        Some(existing) if existing == incoming => {}
        Some(_) => *current = None,
    }
}

fn is_active_stack_base(name: &str, ctx: StackContext) -> bool {
    is_stack_base(name)
        && !(ctx.rbp_repurposed && matches!(crate::ir::abi::ssa_base(name), "rbp" | "ebp" | "bp"))
}

fn is_arm_frame_pointer(name: &str, ctx: StackContext) -> bool {
    let base = crate::ir::abi::ssa_base(name);
    matches!(ctx.cc, Some(CallConv::Arm | CallConv::ArmHardFloat))
        && (matches!(base, "fp" | "r11") || ctx.arm_frame_register == Some(base))
}

/// The ARM32 register this body establishes as its frame anchor, in the
/// encoding's own spelling.
///
/// A32 keeps AAPCS's `fp` (r11), which the disassembler already spells with the
/// architectural name that [`STACK_BASES`] carries. Thumb-2 cannot reach the
/// high registers from most sixteen-bit encodings, so GCC anchors Thumb frames
/// on `r7` instead — an ordinary callee-saved register everywhere else, and one
/// that frame-pointer-omitted code at `-O2` uses as scratch in both encodings.
///
/// The anchor is therefore recognised only from a prologue that derives it from
/// the stack pointer. That proof is what makes `[r7+4]` an argument home rather
/// than a dereference of whatever pointer the caller left in `r7`, and it is
/// the piece ARM32's Thumb mode was missing: `entry_sp` reached A32's `fp`
/// through [`STACK_BASES`] and never reached Thumb's `r7` at all.
fn arm_frame_register(body: &[Stmt], cc: Option<CallConv>) -> Option<&'static str> {
    if !matches!(cc, Some(CallConv::Arm | CallConv::ArmHardFloat)) {
        return None;
    }
    fn derived_from_the_stack_pointer(src: &Expr) -> bool {
        match src {
            Expr::Reg(VReg::Phys(name)) => crate::ir::abi::ssa_base(name) == "sp",
            Expr::Lea {
                base: Some(VReg::Phys(name)),
                index: None,
                ..
            } => crate::ir::abi::ssa_base(name) == "sp",
            Expr::Bin {
                op: crate::ir::types::BinOp::Add | crate::ir::types::BinOp::Sub,
                lhs,
                rhs,
            } => matches!(rhs.as_ref(), Expr::Const(_)) && derived_from_the_stack_pointer(lhs),
            _ => false,
        }
    }
    // The prologue is a top-level statement, exactly as `frame_pointer_assignment`
    // assumes for x86. A frame register first assigned inside a branch is not a
    // frame establishment this pass will trust.
    body.iter().find_map(|statement| {
        let Stmt::Assign {
            dst: VReg::Phys(dst),
            src,
        } = statement
        else {
            return None;
        };
        let candidate = match crate::ir::abi::ssa_base(dst) {
            "fp" => "fp",
            "r7" => "r7",
            "r11" => "r11",
            _ => return None,
        };
        derived_from_the_stack_pointer(src).then_some(candidate)
    })
}

/// Whether the function's first assignment to x86's nominal frame register
/// makes it an ordinary callee-saved value instead of establishing a frame.
fn rbp_is_repurposed(body: &[Stmt], cc: Option<CallConv>) -> bool {
    if !matches!(
        cc,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32)
    ) {
        return false;
    }
    frame_pointer_assignment(body).is_some_and(|establishes| !establishes)
}

/// Whether the body establishes an x86 frame pointer.
///
/// This is NOT `!rbp_is_repurposed`: a function that never writes `rbp` at all
/// (the ordinary frame-pointer-omitted `-O2` shape) repurposes nothing and
/// establishes nothing.
fn frame_pointer_is_established(body: &[Stmt], cc: Option<CallConv>) -> bool {
    matches!(
        cc,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32)
    ) && frame_pointer_assignment(body) == Some(true)
}

/// `Some(true)` when the first assignment to x86's nominal frame register comes
/// from the stack pointer, `Some(false)` when it comes from anything else, and
/// `None` when the register is never assigned.
fn frame_pointer_assignment(body: &[Stmt]) -> Option<bool> {
    for statement in body {
        let Stmt::Assign {
            dst: VReg::Phys(dst),
            src,
        } = statement
        else {
            continue;
        };
        if !matches!(crate::ir::abi::ssa_base(dst), "rbp" | "ebp" | "bp") {
            continue;
        }
        return Some(matches!(
            src,
            Expr::Reg(VReg::Phys(stack))
                if matches!(crate::ir::abi::ssa_base(stack), "rsp" | "esp" | "sp")
        ));
    }
    None
}

/// The coordinate a debug-proven stack object actually occupies in THIS body.
///
/// `DW_OP_call_frame_cfa` is an offset from the caller's stack pointer, and the
/// x86 front ends re-express it as a frame-pointer displacement because that is
/// the coordinate an `-O0` body addresses its frame with. A body that omits the
/// frame pointer never forms that address, so the hint lands on a key nothing
/// else in the function ever reaches: measured at `c2fb19d`, the proven extent
/// of `a` in `196_disjoint_frame_slots:gcc:O2:dfs196_alias_control` sat at
/// `rbp-48` while every access resolved against `entry_rsp`, leaving `rsp+12` a
/// bare scalar that the array's own initialising loop never appeared to define.
///
/// The omitted frame pointer would have sat exactly one machine word below the
/// entry stack pointer — the word the prologue's `push` would have consumed — so
/// the rebase is `disp - stack_word_size`. It applies only to CFA-derived hints:
/// one the producer read from a real base register (`DW_OP_breg6`) is already in
/// the coordinate the body uses, and rebasing it would move a correct object.
fn rebased_hint_coordinate(hint: &StackObjectHint, ctx: StackContext) -> Option<(String, i64)> {
    let frame_pointer_omitted = hint.cfa_relative
        && is_frame_pointer(&hint.base)
        && !ctx.frame_pointer_established
        && matches!(
            ctx.cc,
            Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32)
        );
    if !frame_pointer_omitted {
        return Some((hint.base.clone(), hint.disp));
    }
    Some((
        entry_stack_base(ctx).to_string(),
        hint.disp.checked_sub(stack_word_size(ctx))?,
    ))
}

/// Rewrite stack-relative memory accesses to named locals.
pub fn promote_stack_locals(f: &mut Function) {
    let _ = promote_stack_locals_typed(f, None);
}

/// Like [`promote_stack_locals`], but also returns the recovered byte size of
/// each promoted local (`local_0 -> 4`, `stack_1 -> 8`, ...), taken from the
/// width of the memory accesses that defined the slot. Callers thread this into
/// type recovery so a 4-byte spill slot renders as `int` rather than the
/// blanket `long`. When a name is defined at more than one width the widest is
/// kept (the safest committed size).
pub fn promote_stack_locals_typed(f: &mut Function, cc: Option<CallConv>) -> HashMap<String, u8> {
    promote_stack_locals_typed_with_parameter_count(f, cc, None)
}

/// Promote stack storage while respecting an optional authoritative parameter
/// count. This matters for optimized non-leaf functions: control-flow joins can
/// expose saved registers through a positive entry-stack displacement that has
/// the same machine shape as a genuine stack-passed argument. DWARF or another
/// locked prototype disambiguates the two without weakening stripped-binary
/// inference.
pub fn promote_stack_locals_typed_with_parameter_count(
    f: &mut Function,
    cc: Option<CallConv>,
    parameter_count: Option<usize>,
) -> HashMap<String, u8> {
    promote_stack_locals_typed_with_parameter_count_and_objects(f, cc, parameter_count, &[])
}

/// Promote stack storage with optional debug-proven aggregate boundaries.
pub fn promote_stack_locals_typed_with_parameter_count_and_objects(
    f: &mut Function,
    cc: Option<CallConv>,
    parameter_count: Option<usize>,
    object_hints: &[StackObjectHint],
) -> HashMap<String, u8> {
    promote_stack_locals_with_facts(f, cc, parameter_count, object_hints).sizes
}

/// Promote stack storage and retain authoritative source types alongside the
/// traditional machine-size map.
pub fn promote_stack_locals_with_facts(
    f: &mut Function,
    cc: Option<CallConv>,
    parameter_count: Option<usize>,
    object_hints: &[StackObjectHint],
) -> StackLocalFacts {
    let mut map: HashMap<SlotKey, SlotVal> = HashMap::new();
    let mut names = SlotNames::default();
    let ctx = StackContext {
        cc,
        rbp_repurposed: rbp_is_repurposed(&f.body, cc),
        frame_pointer_established: frame_pointer_is_established(&f.body, cc),
        arm_frame_register: arm_frame_register(&f.body, cc),
        parameter_count,
    };
    address_aliases::expand(&mut f.body, ctx);
    for hint in object_hints {
        let Some((hint_base, hint_disp)) = rebased_hint_coordinate(hint, ctx) else {
            continue;
        };
        let authoritative_entry_coordinate = hint_base == entry_stack_base(ctx);
        if hint.size == 0
            || (!is_active_stack_base(&hint_base, ctx) && !authoritative_entry_coordinate)
        {
            continue;
        }
        let key = SlotKey {
            base: hint_base.clone(),
            disp: hint_disp,
        };
        let source_name = reserve_source_local_name(hint.source_name.as_deref(), &mut names);
        let name = map.get(&key).map_or_else(
            || alloc_name(&hint_base, hint_disp, &mut names, ctx),
            |slot| slot.name.clone(),
        );
        let scalar_size = (!hint.aggregate)
            .then(|| u8::try_from(hint.size).ok())
            .flatten();
        if !hint.aggregate && scalar_size.is_none() {
            continue;
        }
        map.entry(key)
            .and_modify(|slot| {
                if hint.aggregate {
                    slot.object_size = Some(slot.object_size.unwrap_or(0).max(hint.size));
                } else if slot.object_size.is_none() {
                    let size = scalar_size.expect("validated scalar size");
                    slot.declared_size = slot.declared_size.max(size);
                    slot.span_size = slot.span_size.max(size);
                }
                slot.bounded_object = true;
                slot.debug_proven |= hint.aggregate;
                merge_source_type(&mut slot.source_type, hint.c_type.as_deref());
                merge_source_type(&mut slot.source_name, source_name.as_deref());
            })
            .or_insert(SlotVal {
                name,
                declared_size: scalar_size.unwrap_or(1),
                span_size: scalar_size.unwrap_or(1),
                object_size: hint.aggregate.then_some(hint.size),
                bounded_object: true,
                source_type: hint.c_type.clone(),
                source_name,
                debug_proven: hint.aggregate,
            });
    }
    // Stack-address aliases and label stack depths depend on each other: an
    // epilogue can restore SP through an alias, while an alias defined after a
    // textual epilogue needs the target label's actual incoming depth. Solve
    // the two small monotone analyses together instead of letting either use
    // textual fallthrough as a control-flow substitute.
    let mut address_defs = HashMap::new();
    let mut label_deltas = HashMap::new();
    let mut coordinates_converged = false;
    for _ in 0..64 {
        let next_label_deltas = collect_label_stack_deltas(&f.body, ctx, &address_defs);
        let next_address_defs = collect_stack_address_defs(&f.body, ctx, &next_label_deltas);
        if next_label_deltas == label_deltas && next_address_defs == address_defs {
            coordinates_converged = true;
            break;
        }
        label_deltas = next_label_deltas;
        address_defs = next_address_defs;
    }
    if !coordinates_converged {
        // A cyclic disagreement is not evidence for an address alias. Retain
        // only label depths derivable without aliases and let unresolved
        // address expressions remain explicit in the output.
        address_defs.clear();
        label_deltas = collect_label_stack_deltas(&f.body, ctx, &address_defs);
    }
    seed_indexed_stack_objects(
        &f.body,
        &mut map,
        &mut names,
        ctx,
        &address_defs,
        &label_deltas,
    );
    let mut sp_delta = Some(0i64);
    rewrite_body(
        &mut f.body,
        &mut map,
        &mut names,
        ctx,
        &mut sp_delta,
        &address_defs,
        &label_deltas,
    );
    reconcile_late_address_taken_objects(&mut f.body, &map);
    // Several machine SlotKeys can intentionally collapse to one source-level
    // role (notably `entry_rsp+0` and `esp+0` both render as `stack_top`).  Join
    // by that final identity explicitly. A bare `collect()` made HashMap
    // iteration order choose the declaration width, so identical inputs could
    // alternate between `char` and `long` across processes.
    let mut facts = StackLocalFacts::default();
    // Names withheld from `frame_coordinates` because two machine slot keys
    // reached them; see the field's documentation.
    let mut ambiguous_coordinates: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for (key, slot) in map {
        let name = slot.name;
        match facts.frame_coordinates.entry(name.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                if !ambiguous_coordinates.contains(&name) {
                    entry.insert((key.base.clone(), key.disp));
                }
            }
            std::collections::hash_map::Entry::Occupied(entry)
                if entry.get() != &(key.base.clone(), key.disp) =>
            {
                entry.remove();
                ambiguous_coordinates.insert(name.clone());
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }
        facts
            .sizes
            .entry(name.clone())
            .and_modify(|size: &mut u8| *size = (*size).max(slot.declared_size))
            .or_insert(slot.declared_size);
        if let Some(source_type) = slot.source_type {
            match facts.source_types.entry(name.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(source_type);
                }
                std::collections::hash_map::Entry::Occupied(entry)
                    if entry.get() != &source_type =>
                {
                    entry.remove();
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
        }
        if let Some(source_name) = slot.source_name {
            facts.source_names.insert(name, source_name);
        }
    }
    facts
}

/// Where a calling convention puts the arguments that do not fit in registers:
/// how many arrive in registers, and the frame-pointer offset of the first stacked
/// one in a standard frame.
///
/// SysV AMD64: six integer registers, then `[rbp+16]` upward — `[rbp]` holds the
/// saved frame pointer and `[rbp+8]` the return address. Cdecl32 has no integer
/// register arguments and starts at `[ebp+8]` in four-byte slots. AArch64 AAPCS:
/// eight registers, then `[x29+16]`, the frame record being `{fp, lr}`. AAPCS32
/// uses four integer registers; a canonical frame saves one four-byte `fp`
/// below the entry SP, so its first stacked integer argument is `[fp+4]`.
/// Win64 remains deliberately absent: its 32-byte shadow space needs separate
/// treatment, and guessing at an ABI is how a decompiler invents a parameter
/// that does not exist.
fn stack_arg_layout(cc: CallConv) -> Option<(usize, i64, i64)> {
    match cc {
        CallConv::SysVAmd64 => Some((6, 16, 8)),
        CallConv::Cdecl32 => Some((0, 8, 4)),
        CallConv::Aarch64 => Some((8, 16, 8)),
        CallConv::Arm | CallConv::ArmHardFloat => Some((4, 4, 4)),
        CallConv::Win64 => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackFlow {
    Unreachable,
    Known(i64),
    Unknown,
}

fn merge_stack_flows(left: StackFlow, right: StackFlow) -> StackFlow {
    match (left, right) {
        (StackFlow::Unreachable, other) | (other, StackFlow::Unreachable) => other,
        (StackFlow::Known(a), StackFlow::Known(b)) if a == b => StackFlow::Known(a),
        (StackFlow::Known(_), StackFlow::Known(_))
        | (StackFlow::Unknown, _)
        | (_, StackFlow::Unknown) => StackFlow::Unknown,
    }
}

fn merge_stack_flow_entry(states: &mut HashMap<u64, StackFlow>, label: u64, incoming: StackFlow) {
    if incoming == StackFlow::Unreachable {
        return;
    }
    states
        .entry(label)
        .and_modify(|known| *known = merge_stack_flows(*known, incoming))
        .or_insert(incoming);
}

/// Propagate entry-stack deltas over residual goto control flow before any
/// memory expression is rewritten.
///
/// Structured AST order is usually execution order, but optimized functions
/// retain labels after one or more textual epilogues. A branch into such a
/// label still executes in the original frame. This bounded monotone analysis
/// records goto edges and replays backward edges until each label is Known or
/// conservatively Unknown; Unreachable never poisons a reachable predecessor.
fn collect_label_stack_deltas(
    body: &[Stmt],
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> HashMap<u64, Option<i64>> {
    fn update_stack_assignment(
        flow: StackFlow,
        dst: &VReg,
        src: &Expr,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
    ) -> StackFlow {
        match flow {
            StackFlow::Known(delta) => {
                stack_delta_after_assignment(dst, src, Some(delta), ctx, address_defs)
                    .map(StackFlow::Known)
                    .unwrap_or(StackFlow::Unknown)
            }
            other => other,
        }
    }

    fn walk(
        body: &[Stmt],
        mut flow: StackFlow,
        target_states: &mut HashMap<u64, StackFlow>,
        label_states: &mut HashMap<u64, StackFlow>,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
    ) -> StackFlow {
        for statement in body {
            match statement {
                Stmt::Assign { dst, src } if is_stack_pointer_reg(dst, ctx) => {
                    flow = update_stack_assignment(flow, dst, src, ctx, address_defs);
                }
                Stmt::Push { .. } => {
                    if let StackFlow::Known(delta) = flow {
                        flow = StackFlow::Known(delta - stack_word_size(ctx));
                    }
                }
                Stmt::Pop { .. } => {
                    if let StackFlow::Known(delta) = flow {
                        flow = StackFlow::Known(delta + stack_word_size(ctx));
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    let then_flow = walk(
                        then_body,
                        flow,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    let else_flow = else_body.as_deref().map_or(flow, |else_body| {
                        walk(
                            else_body,
                            flow,
                            target_states,
                            label_states,
                            ctx,
                            address_defs,
                        )
                    });
                    flow = merge_stack_flows(then_flow, else_flow);
                }
                Stmt::While { body, .. } => {
                    let body_flow =
                        walk(body, flow, target_states, label_states, ctx, address_defs);
                    flow = merge_stack_flows(flow, body_flow);
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    flow = walk(
                        std::slice::from_ref(init.as_ref()),
                        flow,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    let loop_entry = flow;
                    let body_flow = walk(
                        body,
                        loop_entry,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    let stepped = walk(
                        std::slice::from_ref(step.as_ref()),
                        body_flow,
                        target_states,
                        label_states,
                        ctx,
                        address_defs,
                    );
                    flow = merge_stack_flows(loop_entry, stepped);
                }
                Stmt::DoWhile { body, .. } => {
                    let body_flow =
                        walk(body, flow, target_states, label_states, ctx, address_defs);
                    flow = merge_stack_flows(flow, body_flow);
                }
                Stmt::Switch { cases, default, .. } => {
                    let incoming = flow;
                    let mut exits = StackFlow::Unreachable;
                    for (_, case_body) in cases {
                        exits = merge_stack_flows(
                            exits,
                            walk(
                                case_body,
                                incoming,
                                target_states,
                                label_states,
                                ctx,
                                address_defs,
                            ),
                        );
                    }
                    if let Some(default_body) = default {
                        exits = merge_stack_flows(
                            exits,
                            walk(
                                default_body,
                                incoming,
                                target_states,
                                label_states,
                                ctx,
                                address_defs,
                            ),
                        );
                    } else {
                        exits = merge_stack_flows(exits, incoming);
                    }
                    flow = exits;
                }
                Stmt::Goto { target } => {
                    merge_stack_flow_entry(target_states, *target, flow);
                    flow = StackFlow::Unreachable;
                }
                Stmt::Label(label) => {
                    let targeted = target_states
                        .get(label)
                        .copied()
                        .unwrap_or(StackFlow::Unreachable);
                    flow = merge_stack_flows(flow, targeted);
                    merge_stack_flow_entry(label_states, *label, flow);
                }
                Stmt::Return { .. } | Stmt::IndirectGoto { .. } => {
                    flow = StackFlow::Unreachable;
                }
                Stmt::Store { .. }
                | Stmt::Call { .. }
                | Stmt::Assign { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
        flow
    }

    let mut target_states = HashMap::new();
    let mut label_states = HashMap::new();
    for _ in 0..64 {
        let before = target_states.clone();
        label_states.clear();
        let _ = walk(
            body,
            StackFlow::Known(0),
            &mut target_states,
            &mut label_states,
            ctx,
            address_defs,
        );
        if target_states == before {
            break;
        }
    }

    label_states
        .into_iter()
        .map(|(label, flow)| {
            let delta = match flow {
                StackFlow::Known(delta) => Some(delta),
                StackFlow::Unreachable | StackFlow::Unknown => None,
            };
            (label, delta)
        })
        .collect()
}

/// Discover the starts of bounded indexed frame regions before rewriting any
/// statement.  Adjacent starts normally partition the compiler frame and the
/// frame base closes the final region.  Compilers also spell one array through
/// adjacent, same-stride views (for example, `base - 36 + 4 * (i + 1)` and
/// `base - 32 + 4 * i`); those views must share storage rather than becoming
/// separate C arrays.  This intentionally recovers storage, not an element
/// type: byte-array identity is enough for C pointer arithmetic to preserve
/// aliases between wide zeroing stores and later byte/int indexing.
fn seed_indexed_stack_objects(
    body: &[Stmt],
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    label_deltas: &HashMap<u64, Option<i64>>,
) {
    fn collect_expr(
        expr: &Expr,
        sp_delta: Option<i64>,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
        starts: &mut Vec<(String, i64, u8)>,
    ) {
        if let Some((base, disp, Some(_), scale)) =
            resolved_memory_address(expr, sp_delta, ctx, address_defs)
        {
            if scale != 0 && disp < 0 {
                starts.push((base, disp, scale));
            }
        }
        match expr {
            Expr::Deref { addr, .. } => collect_expr(addr, sp_delta, ctx, address_defs, starts),
            Expr::Call { target, args, .. } => {
                collect_expr(target, sp_delta, ctx, address_defs, starts);
                for argument in args {
                    collect_expr(argument, sp_delta, ctx, address_defs, starts);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                collect_expr(lhs, sp_delta, ctx, address_defs, starts);
                collect_expr(rhs, sp_delta, ctx, address_defs, starts);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                collect_expr(cond, sp_delta, ctx, address_defs, starts);
                collect_expr(if_true, sp_delta, ctx, address_defs, starts);
                collect_expr(if_false, sp_delta, ctx, address_defs, starts);
            }
            Expr::Un { src, .. } => collect_expr(src, sp_delta, ctx, address_defs, starts),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                collect_expr(expr, sp_delta, ctx, address_defs, starts)
            }
            Expr::FunctionTableEntry { index, .. } => {
                collect_expr(index, sp_delta, ctx, address_defs, starts)
            }
            Expr::WideArithmetic { args, .. } => {
                for arg in args {
                    collect_expr(arg, sp_delta, ctx, address_defs, starts);
                }
            }
            Expr::Reg(_)
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Unknown(_) => {}
        }
    }

    fn walk(
        body: &[Stmt],
        ctx: StackContext,
        mut sp_delta: Option<i64>,
        address_defs: &HashMap<VReg, (String, i64)>,
        label_deltas: &HashMap<u64, Option<i64>>,
        starts: &mut Vec<(String, i64, u8)>,
    ) -> Option<i64> {
        for stmt in body {
            match stmt {
                Stmt::Assign { dst, src } => {
                    // AAPCS uses r7/r11/fp arithmetic to restore SP in the
                    // epilogue. At this pre-value-folding stage the constant
                    // adjustment can still be a temporary register, which has
                    // the same syntax as a dynamic array index. It is machine
                    // frame bookkeeping, not an indexed memory access and
                    // must not seed a byte object spanning the entire frame.
                    let arm_epilogue_frame_arithmetic = matches!(
                        (dst, src),
                        (
                            VReg::Phys(name),
                            Expr::Bin { lhs, rhs, .. }
                        ) if is_arm_frame_pointer(name, ctx)
                            && matches!(lhs.as_ref(), Expr::Reg(_))
                            && matches!(rhs.as_ref(), Expr::Reg(_))
                    );
                    if !arm_epilogue_frame_arithmetic {
                        collect_expr(src, sp_delta, ctx, address_defs, starts);
                    }
                    if is_stack_pointer_reg(dst, ctx) {
                        sp_delta =
                            stack_delta_after_assignment(dst, src, sp_delta, ctx, address_defs);
                    }
                }
                Stmt::Store { addr, src, .. } => {
                    collect_expr(addr, sp_delta, ctx, address_defs, starts);
                    collect_expr(src, sp_delta, ctx, address_defs, starts);
                }
                Stmt::Call { target, args, .. } => {
                    collect_expr(target, sp_delta, ctx, address_defs, starts);
                    for arg in args {
                        collect_expr(arg, sp_delta, ctx, address_defs, starts);
                    }
                }
                Stmt::Return { value } => {
                    if let Some(value) = value {
                        collect_expr(value, sp_delta, ctx, address_defs, starts);
                    }
                    sp_delta = None;
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    collect_expr(cond, sp_delta, ctx, address_defs, starts);
                    let then_delta =
                        walk(then_body, ctx, sp_delta, address_defs, label_deltas, starts);
                    let else_delta = else_body.as_deref().map_or(sp_delta, |branch| {
                        walk(branch, ctx, sp_delta, address_defs, label_deltas, starts)
                    });
                    let then_falls = body_falls_through(then_body);
                    let else_falls = else_body.as_deref().is_none_or(body_falls_through);
                    sp_delta = match (then_falls, else_falls) {
                        (true, true) => merge_stack_deltas(then_delta, else_delta),
                        (true, false) => then_delta,
                        (false, true) => else_delta,
                        (false, false) => None,
                    };
                }
                Stmt::While { cond, body } => {
                    collect_expr(cond, sp_delta, ctx, address_defs, starts);
                    let body_delta = walk(body, ctx, sp_delta, address_defs, label_deltas, starts);
                    sp_delta = merge_stack_deltas(sp_delta, body_delta);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    sp_delta = walk(
                        std::slice::from_ref(init.as_ref()),
                        ctx,
                        sp_delta,
                        address_defs,
                        label_deltas,
                        starts,
                    );
                    collect_expr(cond, sp_delta, ctx, address_defs, starts);
                    let loop_entry = sp_delta;
                    let mut body_delta =
                        walk(body, ctx, loop_entry, address_defs, label_deltas, starts);
                    body_delta = walk(
                        std::slice::from_ref(step.as_ref()),
                        ctx,
                        body_delta,
                        address_defs,
                        label_deltas,
                        starts,
                    );
                    sp_delta = merge_stack_deltas(loop_entry, body_delta);
                }
                Stmt::DoWhile { body, cond } => {
                    let body_delta = walk(body, ctx, sp_delta, address_defs, label_deltas, starts);
                    collect_expr(cond, body_delta, ctx, address_defs, starts);
                    sp_delta = merge_stack_deltas(sp_delta, body_delta);
                }
                Stmt::Push { value } => {
                    collect_expr(value, sp_delta, ctx, address_defs, starts);
                    sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
                }
                Stmt::Pop { .. } => {
                    sp_delta = sp_delta.map(|delta| delta + stack_word_size(ctx));
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    collect_expr(discriminant, sp_delta, ctx, address_defs, starts);
                    let incoming = sp_delta;
                    let mut exits = Vec::new();
                    for (_, branch) in cases {
                        exits.push(walk(
                            branch,
                            ctx,
                            incoming,
                            address_defs,
                            label_deltas,
                            starts,
                        ));
                    }
                    if let Some(branch) = default {
                        exits.push(walk(
                            branch,
                            ctx,
                            incoming,
                            address_defs,
                            label_deltas,
                            starts,
                        ));
                    } else {
                        exits.push(incoming);
                    }
                    sp_delta = exits
                        .into_iter()
                        .reduce(merge_stack_deltas)
                        .unwrap_or(incoming);
                }
                Stmt::IndirectGoto { target } => {
                    collect_expr(target, sp_delta, ctx, address_defs, starts);
                    sp_delta = None;
                }
                Stmt::Label(label) => {
                    sp_delta = label_deltas.get(label).copied().unwrap_or(None);
                }
                Stmt::Goto { .. } => sp_delta = None,
                Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
        sp_delta
    }

    let mut starts = Vec::new();
    let _ = walk(body, ctx, Some(0), address_defs, label_deltas, &mut starts);
    starts.sort();
    starts.dedup();

    let mut grouped_starts: Vec<(String, i64, Vec<u8>)> = Vec::new();
    for (base, start, scale) in starts {
        let joined_existing =
            if let Some((last_base, last_start, scales)) = grouped_starts.last_mut() {
                if *last_base == base && *last_start == start {
                    if !scales.contains(&scale) {
                        scales.push(scale);
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };
        if !joined_existing {
            grouped_starts.push((base, start, vec![scale]));
        }
    }

    // An indexed view displaced by at most one of its own elements from the
    // preceding same-stride view is an aliasing bias, not a new allocation.
    // Compare consecutive displacement groups so chains such as -40/-36/-32
    // coalesce even when another access width also starts at one boundary.
    let mut partitions = Vec::new();
    for (index, (base, start, scales)) in grouped_starts.iter().enumerate() {
        let aliases_previous = index
            .checked_sub(1)
            .and_then(|previous| grouped_starts.get(previous))
            .is_some_and(|(previous_base, previous_start, previous_scales)| {
                previous_base == base
                    && start.checked_sub(*previous_start).is_some_and(|gap| {
                        gap > 0
                            && scales.iter().any(|scale| {
                                previous_scales.contains(scale) && gap <= i64::from(*scale)
                            })
                    })
            });
        if !aliases_previous {
            partitions.push((base.clone(), *start));
        }
    }

    // A partition that OVERLAPS a debug-proven object is not a second
    // allocation, and seeding it makes the recompiled C allocate two arrays
    // where the machine had one. Two ways this arises, both measured:
    //
    // * the partition starts inside the object — `nodes[i].next` is an indexed
    //   access eight bytes into `struct Node nodes[8]`
    //   (`111_self_referential_struct:gcc:O2`, which put the list terminator in
    //   the wrong object);
    // * the partition starts BELOW it and runs through it — gcc addresses
    //   `int32_t temp[16]` at `rsp+0x30` as `0x2c(%rsp) + (out+1)*4`, so the
    //   recovered start is one element low and the conservative extent then
    //   covers the whole proven array plus the scalar in front of it
    //   (`24_merge_sort:gcc:O2:merge_sort_i32`).
    //
    // The existing rule ("never replace an exact extent with the heuristic's
    // conservative partition") covered only an exact START match.
    let proven: Vec<(String, i64, i64)> = map
        .iter()
        .filter(|(_, slot)| slot.debug_proven)
        .filter_map(|(key, slot)| {
            let end = key.disp.checked_add(i64::from(slot.object_size?))?;
            Some((key.base.clone(), key.disp, end))
        })
        .collect();
    for index in 0..partitions.len() {
        let (base, start) = &partitions[index];
        let end = partitions
            .get(index + 1)
            .filter(|(next_base, _)| next_base == base)
            .map_or(0, |(_, next_start)| *next_start);
        if proven
            .iter()
            .any(|(proven_base, proven_start, proven_end)| {
                proven_base == base && *start < *proven_end && end > *proven_start
            })
        {
            continue;
        }
        let Some(extent) = end.checked_sub(*start) else {
            continue;
        };
        let Ok(size) = u16::try_from(extent) else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let key = SlotKey {
            base: base.clone(),
            disp: *start,
        };
        let name = alloc_name(base, *start, names, ctx);
        // Debug-proven aggregate bounds are seeded before this heuristic and
        // are authoritative. Never replace an exact `temp[16]` extent with the
        // heuristic's conservative "to the frame base" partition merely
        // because both observe the same indexed start.
        map.entry(key).or_insert_with(|| SlotVal {
            name,
            declared_size: 1,
            span_size: 1,
            object_size: Some(size),
            bounded_object: partitions.get(index + 1).is_some(),
            source_type: None,
            source_name: None,
            debug_proven: false,
        });
    }
}

fn rewrite_body(
    body: &mut [Stmt],
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: &mut Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
    label_deltas: &HashMap<u64, Option<i64>>,
) {
    for s in body.iter_mut() {
        match s {
            Stmt::IndirectGoto { target } => {
                rewrite_expr(target, map, names, ctx, *sp_delta, address_defs);
                *sp_delta = None;
            }
            Stmt::Assign { dst, src } => {
                rewrite_expr(src, map, names, ctx, *sp_delta, address_defs);
                // `mov %rsp,%rbp` DEFINES a coordinate system; it does not
                // compute a loop bound. `collect_stack_address_defs` already
                // treats a write to an architectural frame base that way, and
                // the frame base is one past the end of whatever object ends at
                // it — so without the same rule here, `-O0`'s prologue rendered
                // as a dead `stack_0 = &local_c[0] + 12` and stopped being
                // recognised as a prologue at all. Only the END-POINTER reading
                // is withheld: an address INSIDE a known object is still that
                // object's address whatever the destination register is.
                let establishes_a_frame_base = matches!(
                    dst, VReg::Phys(name) if is_active_stack_base(name, ctx)
                );
                if !is_stack_pointer_reg(dst, ctx) {
                    if let Some(object_addr) = stack_assignment_object_address(
                        src,
                        map,
                        *sp_delta,
                        ctx,
                        address_defs,
                        !establishes_a_frame_base,
                    ) {
                        *src = object_addr;
                    }
                }
                if is_stack_pointer_reg(dst, ctx) {
                    *sp_delta =
                        stack_delta_after_assignment(dst, src, *sp_delta, ctx, address_defs);
                }
            }
            Stmt::Store { addr, src, size } => {
                // Whether this store addressed MEMORY before promotion. A store
                // whose address is already a bare register is a pointer write
                // (`*p = v`) and must never be mistaken for a slot assignment —
                // see `argument_slot_assignment`.
                let addressed_memory = matches!(addr, Expr::Lea { .. });
                // Store's addr is an Lea — we need to rewrite the Lea itself
                // into a Reg reference when the lea points to a stack slot.
                try_promote_lea_to_local(addr, *size, map, names, ctx, *sp_delta, address_defs);
                rewrite_expr(src, map, names, ctx, *sp_delta, address_defs);
                // A by-reference closure capture stores a frame address into a
                // field before the closure is called. This escape is every bit
                // as strong as passing the address directly to a callee: the
                // pointee must retain storage identity instead of rendering as
                // arithmetic on an uninitialised frame register.
                promote_address_taken_stack_object(src, map, names, ctx, *sp_delta, address_defs);
                if addressed_memory {
                    if let Some(parameter) = argument_slot_assignment(addr, *size, ctx) {
                        *s = Stmt::Assign {
                            dst: parameter,
                            src: src.clone(),
                        };
                    }
                }
            }
            Stmt::Call { target, args, .. } => {
                rewrite_expr(target, map, names, ctx, *sp_delta, address_defs);
                for a in args {
                    rewrite_expr(a, map, names, ctx, *sp_delta, address_defs);
                    promote_address_taken_stack_object(a, map, names, ctx, *sp_delta, address_defs);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e, map, names, ctx, *sp_delta, address_defs);
                }
                *sp_delta = None;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, map, names, ctx, *sp_delta, address_defs);
                let incoming = *sp_delta;
                let mut then_delta = incoming;
                rewrite_body(
                    then_body,
                    map,
                    names,
                    ctx,
                    &mut then_delta,
                    address_defs,
                    label_deltas,
                );
                let mut else_delta = incoming;
                if let Some(eb) = else_body {
                    rewrite_body(
                        eb,
                        map,
                        names,
                        ctx,
                        &mut else_delta,
                        address_defs,
                        label_deltas,
                    );
                }
                let then_falls_through = body_falls_through(then_body);
                let else_falls_through = else_body.as_deref().is_none_or(body_falls_through);
                *sp_delta = match (then_falls_through, else_falls_through) {
                    (true, true) => merge_stack_deltas(then_delta, else_delta),
                    (true, false) => then_delta,
                    (false, true) => else_delta,
                    (false, false) => None,
                };
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, map, names, ctx, *sp_delta, address_defs);
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    names,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                rewrite_body(
                    std::slice::from_mut(init.as_mut()),
                    map,
                    names,
                    ctx,
                    sp_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_expr(cond, map, names, ctx, *sp_delta, address_defs);
                let loop_entry = *sp_delta;
                let mut body_delta = loop_entry;
                rewrite_body(
                    body,
                    map,
                    names,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_body(
                    std::slice::from_mut(step.as_mut()),
                    map,
                    names,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                *sp_delta = merge_stack_deltas(loop_entry, body_delta);
            }
            Stmt::DoWhile { body, cond } => {
                let incoming = *sp_delta;
                let mut body_delta = incoming;
                rewrite_body(
                    body,
                    map,
                    names,
                    ctx,
                    &mut body_delta,
                    address_defs,
                    label_deltas,
                );
                rewrite_expr(cond, map, names, ctx, body_delta, address_defs);
                *sp_delta = merge_stack_deltas(incoming, body_delta);
            }
            Stmt::Push { value } => {
                rewrite_expr(value, map, names, ctx, *sp_delta, address_defs);
                *sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(discriminant, map, names, ctx, *sp_delta, address_defs);
                let incoming = *sp_delta;
                let mut merged: Option<Option<i64>> = None;
                for (_, body) in cases.iter_mut() {
                    let mut case_delta = incoming;
                    rewrite_body(
                        body,
                        map,
                        names,
                        ctx,
                        &mut case_delta,
                        address_defs,
                        label_deltas,
                    );
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, case_delta),
                        None => case_delta,
                    });
                }
                if let Some(b) = default {
                    let mut default_delta = incoming;
                    rewrite_body(
                        b,
                        map,
                        names,
                        ctx,
                        &mut default_delta,
                        address_defs,
                        label_deltas,
                    );
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, default_delta),
                        None => default_delta,
                    });
                } else {
                    merged = Some(match merged {
                        Some(prior) => merge_stack_deltas(prior, incoming),
                        None => incoming,
                    });
                }
                *sp_delta = merged.unwrap_or(incoming);
            }
            Stmt::Pop { .. } => {
                *sp_delta = sp_delta.map(|delta| delta + stack_word_size(ctx));
            }
            // Labels have no machine effect, but textual order is not control-
            // flow order. Restore the fixed-point state collected from every
            // fallthrough and goto predecessor (including targets that appear
            // after an epilogue in the rendered body).
            Stmt::Label(label) => {
                *sp_delta = label_deltas.get(label).copied().unwrap_or(None);
            }
            Stmt::Goto { .. } => *sp_delta = None,
            Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

fn is_stack_pointer_reg(reg: &VReg, ctx: StackContext) -> bool {
    matches!(
        (ctx.cc, reg),
        (
            Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32),
            VReg::Phys(name)
        ) if matches!(name.as_str(), "rsp" | "esp")
    ) || matches!(
        (ctx.cc, reg),
        (
            Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64),
            VReg::Phys(name),
        ) if name == "sp"
    ) || matches!(
        (ctx.cc, reg),
        (None, VReg::Phys(name)) if matches!(name.as_str(), "rsp" | "esp")
    )
}

fn entry_stack_base(ctx: StackContext) -> &'static str {
    match ctx.cc {
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64) => "entry_sp",
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32) | None => "entry_rsp",
    }
}

fn stack_word_size(ctx: StackContext) -> i64 {
    match ctx.cc {
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Cdecl32) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    }
}

fn stack_delta_after_assignment(
    dst: &VReg,
    src: &Expr,
    before: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<i64> {
    if !is_stack_pointer_reg(dst, ctx) {
        return before;
    }
    let (base, disp) = resolve_stack_address(src, before, ctx, address_defs)?;
    if base == entry_stack_base(ctx) {
        Some(disp)
    } else {
        None
    }
}

fn merge_stack_deltas(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    (a == b).then_some(a).flatten()
}

/// Whether `expr` would carry `register`'s frame coordinate.
///
/// This mirrors exactly the shapes [`resolve_stack_address`] resolves: a copy,
/// a displaced address, and a dereference of either. A cast, a comparison, or
/// any other arithmetic cannot produce a stack address from one, so a use in
/// those positions consumes the register's bits without inheriting its
/// coordinate.
fn expression_roots_at(expr: &Expr, register: &VReg) -> bool {
    match expr {
        Expr::Reg(reg) => reg == register,
        Expr::Lea { base, index, .. } => {
            base.as_ref() == Some(register) || index.as_ref() == Some(register)
        }
        Expr::Deref { addr, .. } => expression_roots_at(addr, register),
        Expr::Bin {
            op: crate::ir::types::BinOp::Add | crate::ir::types::BinOp::Sub,
            lhs,
            rhs,
        } => expression_roots_at(lhs, register) || expression_roots_at(rhs, register),
        _ => false,
    }
}

/// Whether `register`'s frame coordinate is dead over the rest of the body.
///
/// The value a Thumb epilogue writes back into `r7` is the restored entry-stack
/// address (`adds r7, #32; mov sp, r7`). Its consumers are the stack-pointer
/// restore and the flag and width temporaries ARM's lowering hangs off the same
/// add — machine bookkeeping that names no source storage and cannot compete
/// with the coordinate the prologue established. A memory access through the
/// register, a copy that would inherit the coordinate, an escape into a call,
/// or a returned address all keep the overwrite ambiguous.
fn frame_coordinate_is_dead_after(body: &[Stmt], register: &VReg, ctx: StackContext) -> bool {
    body.iter().all(|statement| {
        if !crate::ir::dead_stores::stmt_reads(statement, register) {
            return true;
        }
        match statement {
            // The stack-pointer restore is the teardown's whole purpose.
            Stmt::Assign { dst, .. } if is_stack_pointer_reg(dst, ctx) => true,
            Stmt::Assign { src, .. } => !expression_roots_at(src, register),
            _ => false,
        }
    })
}

fn body_falls_through(body: &[Stmt]) -> bool {
    let Some(last) = body.last() else {
        return true;
    };
    match last {
        Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } => false,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => body_falls_through(then_body) || else_body.as_deref().is_none_or(body_falls_through),
        _ => true,
    }
}

/// Promote a `Deref { addr: Lea { base: stack_base, disp, .. } }` into a
/// `Reg(local_name)` reference. Walks sub-expressions so nested derefs fold.
fn rewrite_expr(
    e: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    match e {
        Expr::Deref { addr, size } => {
            let size_val = *size;
            rewrite_expr(addr, map, names, ctx, sp_delta, address_defs);
            if let Some(source_value) = bounded_overlap::aapcs_top_padding_scalar_value(
                addr.as_ref(),
                size_val,
                map,
                sp_delta,
                ctx,
                address_defs,
            ) {
                *e = source_value;
                return;
            }
            if let Some(object_addr) =
                stack_object_address(addr.as_ref(), size_val, map, sp_delta, ctx, address_defs)
            {
                **addr = object_addr;
                return;
            }
            // After recursion, see whether the addr is a bare Lea of a
            // stack slot; if so, collapse the whole deref into a Reg ref.
            if let Some((key_base, key_disp)) =
                resolved_memory_slot(addr.as_ref(), sp_delta, ctx, address_defs)
            {
                let ordinary_key = SlotKey {
                    base: key_base.clone(),
                    disp: key_disp,
                };
                let key = bounded_scalar_slot(map, &key_base, key_disp, size_val, sp_delta, ctx)
                    .map(|(key, _)| key)
                    .unwrap_or(ordinary_key);
                if let Some(entry) = map.get_mut(&key) {
                    // A narrower load at the same starting address is a view
                    // into a previously wider scalar spill, not evidence that
                    // the parent object itself is narrow.  Preserve the full
                    // declaration and materialise the little-endian view
                    // explicitly; otherwise a dword call result followed by a
                    // byte union-field read becomes a one-byte C local and its
                    // upper bytes are irretrievably lost.
                    if size_val < entry.span_size && entry.span_size <= 8 {
                        entry.declared_size = entry.declared_size.max(entry.span_size);
                        let alias = entry.name.clone();
                        *e = extract_little_endian_subvalue(alias, 0, size_val);
                        return;
                    }
                    // A load reports the true access width — let it win for
                    // the declaration while preserving the widest owned span.
                    entry.declared_size = entry.declared_size.min(size_val);
                    entry.span_size = entry.span_size.max(size_val);
                    let alias = entry.name.clone();
                    *e = Expr::Reg(VReg::phys(alias));
                    return;
                }
                if matches!(ctx.cc, Some(CallConv::SysVAmd64 | CallConv::Win64)) {
                    let child_end = key_disp.saturating_add(i64::from(size_val));
                    let parent = map
                        .iter()
                        .filter(|(candidate, slot)| {
                            candidate.base == key_base
                                && candidate.disp < key_disp
                                && slot.span_size <= 8
                                && child_end
                                    <= candidate.disp.saturating_add(i64::from(slot.span_size))
                        })
                        .max_by_key(|(candidate, _)| candidate.disp)
                        .map(|(candidate, slot)| (candidate.disp, slot.name.clone()));
                    if let Some((parent_disp, parent_name)) = parent {
                        *e = extract_little_endian_subvalue(
                            parent_name,
                            (key_disp - parent_disp) as u8,
                            size_val,
                        );
                        return;
                    }
                }
                let alias = alloc_name(&key_base, key_disp, names, ctx);
                map.insert(
                    key,
                    SlotVal {
                        name: alias.clone(),
                        declared_size: size_val,
                        span_size: size_val,
                        object_size: None,
                        bounded_object: false,
                        source_type: None,
                        source_name: None,
                        debug_proven: false,
                    },
                );
                *e = Expr::Reg(VReg::phys(alias));
                return;
            }
        }
        Expr::Call { target, args, .. } => {
            rewrite_expr(target, map, names, ctx, sp_delta, address_defs);
            for argument in args {
                rewrite_expr(argument, map, names, ctx, sp_delta, address_defs);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, map, names, ctx, sp_delta, address_defs);
            rewrite_expr(rhs, map, names, ctx, sp_delta, address_defs);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond, map, names, ctx, sp_delta, address_defs);
            rewrite_expr(if_true, map, names, ctx, sp_delta, address_defs);
            rewrite_expr(if_false, map, names, ctx, sp_delta, address_defs);
        }
        Expr::Un { src, .. } => rewrite_expr(src, map, names, ctx, sp_delta, address_defs),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            rewrite_expr(expr, map, names, ctx, sp_delta, address_defs)
        }
        Expr::FunctionTableEntry { index, .. } => {
            rewrite_expr(index, map, names, ctx, sp_delta, address_defs)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                rewrite_expr(argument, map, names, ctx, sp_delta, address_defs);
            }
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
    }
}

/// Revisit promoted scalar accesses when an address escape was discovered
/// later in statement order.
///
/// A closure commonly initializes its captured scalar before storing
/// ``&scalar`` into the closure object. The first access has already become a
/// bare promoted local by the time the later store proves that the slot is an
/// addressable object. Reconcile those earlier and later scalar spellings with
/// the final slot map so the renderer declares and accesses one byte object.
fn reconcile_late_address_taken_objects(body: &mut [Stmt], map: &HashMap<SlotKey, SlotVal>) {
    #[derive(Clone)]
    struct ObjectView {
        object: VReg,
        size: u16,
        offset: i64,
        width: u8,
    }

    let roots = map
        .iter()
        .filter_map(|(key, slot)| {
            slot.object_size
                .map(|size| (key, VReg::phys(slot.name.clone()), size))
        })
        .collect::<Vec<_>>();
    let mut objects: HashMap<VReg, ObjectView> = HashMap::new();
    for (key, slot) in map {
        if slot.bounded_object && slot.object_size.is_none() {
            continue;
        }
        let Some((root, object, size)) = roots
            .iter()
            .filter(|(root, _, size)| {
                root.base == key.base
                    && root.disp <= key.disp
                    && key.disp < root.disp.saturating_add(i64::from(*size))
            })
            .max_by_key(|(root, _, _)| root.disp)
        else {
            continue;
        };
        objects.insert(
            VReg::phys(slot.name.clone()),
            ObjectView {
                object: object.clone(),
                size: *size,
                offset: key.disp.saturating_sub(root.disp),
                width: slot.declared_size,
            },
        );
    }
    if objects.is_empty() {
        return;
    }

    fn object_address(reg: &VReg, objects: &HashMap<VReg, ObjectView>) -> Option<Expr> {
        objects.get(reg).map(|view| {
            let object = Expr::StackAddr {
                object: view.object.clone(),
                size: view.size,
            };
            if view.offset == 0 {
                object
            } else {
                Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(object),
                    rhs: Box::new(Expr::Const(view.offset)),
                }
            }
        })
    }

    fn rewrite_value(expr: &mut Expr, objects: &HashMap<VReg, ObjectView>) {
        if let Expr::Reg(reg) = expr {
            if let Some(view) = objects.get(reg) {
                *expr = Expr::Deref {
                    addr: Box::new(object_address(reg, objects).expect("known object view")),
                    size: view.width,
                };
            }
            return;
        }
        match expr {
            Expr::Deref { addr, .. } => {
                if let Expr::Reg(reg) = addr.as_ref() {
                    if let Some(address) = object_address(reg, objects) {
                        **addr = address;
                        return;
                    }
                }
                rewrite_value(addr, objects);
            }
            Expr::Call { target, args, .. } => {
                rewrite_value(target, objects);
                for argument in args {
                    rewrite_value(argument, objects);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                rewrite_value(lhs, objects);
                rewrite_value(rhs, objects);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                rewrite_value(cond, objects);
                rewrite_value(if_true, objects);
                rewrite_value(if_false, objects);
            }
            Expr::Un { src, .. } => rewrite_value(src, objects),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                rewrite_value(expr, objects)
            }
            Expr::FunctionTableEntry { index, .. } => rewrite_value(index, objects),
            Expr::WideArithmetic { args, .. } => {
                for arg in args {
                    rewrite_value(arg, objects);
                }
            }
            Expr::StackAddr { .. }
            | Expr::Lea { .. }
            | Expr::PdbFieldAddr { .. }
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
            Expr::Reg(_) => unreachable!(),
        }
    }

    fn walk(body: &mut [Stmt], objects: &HashMap<VReg, ObjectView>) {
        for statement in body {
            match statement {
                Stmt::Assign { src, .. } => rewrite_value(src, objects),
                Stmt::Store { addr, src, .. } => {
                    if let Expr::Reg(reg) = addr {
                        if let Some(address) = object_address(reg, objects) {
                            *addr = address;
                        }
                    }
                    rewrite_value(src, objects);
                }
                Stmt::Call {
                    target,
                    args,
                    dst: _,
                    call_spec: _,
                } => {
                    rewrite_value(target, objects);
                    for arg in args {
                        rewrite_value(arg, objects);
                    }
                }
                Stmt::Return { value } => {
                    if let Some(value) = value {
                        rewrite_value(value, objects);
                    }
                }
                Stmt::If {
                    cond,
                    then_body,
                    else_body,
                } => {
                    rewrite_value(cond, objects);
                    walk(then_body, objects);
                    if let Some(else_body) = else_body {
                        walk(else_body, objects);
                    }
                }
                Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                    rewrite_value(cond, objects);
                    walk(body, objects);
                }
                Stmt::For {
                    init,
                    cond,
                    step,
                    body,
                } => {
                    walk(std::slice::from_mut(init.as_mut()), objects);
                    rewrite_value(cond, objects);
                    walk(std::slice::from_mut(step.as_mut()), objects);
                    walk(body, objects);
                }
                Stmt::Switch {
                    discriminant,
                    cases,
                    default,
                } => {
                    rewrite_value(discriminant, objects);
                    for (_, case) in cases {
                        walk(case, objects);
                    }
                    if let Some(default) = default {
                        walk(default, objects);
                    }
                }
                Stmt::IndirectGoto { target } => rewrite_value(target, objects),
                Stmt::Push { value } => rewrite_value(value, objects),
                Stmt::Pop { .. }
                | Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::Break
                | Stmt::Nop
                | Stmt::Unknown(_)
                | Stmt::Comment(_)
                | Stmt::Throw { .. }
                | Stmt::TryCatch { .. } => {}
            }
        }
    }

    walk(body, &objects);
}

/// Recover a constant stack/frame-relative call argument as the address of a
/// real C object. angr represents the same fact with `StackBaseOffset`; Ghidra
/// gives its stack pointer a `TypeSpacebase` and resolves offsets through the
/// function's local symbol map. The important invariant is shared: a stack
/// address is storage identity, not an integer expression over a renderable
/// machine register.
fn promote_address_taken_stack_object(
    expr: &mut Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    // A debug scalar is seeded in CFA/entry-SP coordinates before the body is
    // walked. If its address escapes through the post-prologue SP spelling,
    // promote that exact seeded slot into an addressable object instead of
    // creating a second, uninitialised current-SP object beside it.
    let scalar_address = resolved_memory_address(expr, sp_delta, ctx, address_defs).or_else(|| {
        resolve_stack_address(expr, sp_delta, ctx, address_defs)
            .map(|(base, disp)| (base, disp, None, 1))
    });
    if let Some((base, disp, index, _scale)) = scalar_address {
        if index.is_none() {
            if let Some((key, relative)) = bounded_scalar_slot(map, &base, disp, 0, sp_delta, ctx) {
                let entry = map
                    .get_mut(&key)
                    .expect("bounded scalar key came from this map");
                let size = u16::from(entry.span_size);
                entry.object_size = Some(size);
                let object = Expr::StackAddr {
                    object: VReg::phys(entry.name.clone()),
                    size,
                };
                *expr = if relative == 0 {
                    object
                } else {
                    Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(object),
                        rhs: Box::new(Expr::Const(relative)),
                    }
                };
                return;
            }
        }
    }
    // A call can receive a slice whose start is computed dynamically, e.g.
    // `memcpy(rsp + index*4 + 48, src, n)`.  This is the same address shape as
    // an indexed load/store, but there is no dereference node for
    // `rewrite_expr` to promote.  Root it in an already-seeded object before
    // falling back to the constant-address path below.
    if let Some(object_addr) = stack_object_address(expr, 0, map, sp_delta, ctx, address_defs) {
        *expr = object_addr;
        return;
    }
    // An address definition may point inside an object that an earlier call,
    // store, or debug hint already seeded. Preserve that interior byte offset:
    // collapsing `&local[0] + 1` to `&local[0]` changes the stored value even
    // though both addresses identify the same underlying stack object.
    if let Some(object_addr) =
        stack_object_constant_address(expr, map, sp_delta, ctx, address_defs, false)
    {
        *expr = object_addr;
        return;
    }
    // `push {r7, lr}` saves the CALLER's frame register, and the alias map is
    // keyed by register rather than by program point, so that store's source
    // resolves to THIS frame's anchor coordinate. The anchor is by construction
    // the base of the whole frame, so the "grow conservatively to the frame
    // base" extent below measures the frame, not an object: A32's `fp` sits one
    // word below the CFA and produced a harmless four-byte slot, while Thumb's
    // `r7` sits at the bottom and produced a forty-byte array that swallowed
    // `seed`'s argument home. A bare anchor is evidence of a machine word at
    // that coordinate and of nothing wider. Every path that joins an ALREADY
    // proven object — a DWARF aggregate, a seeded partition, an observed run of
    // slots — has run above, so a genuine escape into a known object still
    // resolves at its real extent.
    let bare_frame_anchor =
        matches!(expr, Expr::Reg(VReg::Phys(name)) if is_arm_frame_pointer(name, ctx));
    let recovered = escaped_stack_address(expr, sp_delta, ctx, address_defs, false);
    let Some((base, disp)) = recovered else {
        return;
    };
    let (key_base, key_disp) = normalized_stack_slot(&base, disp, sp_delta, ctx);
    let key = SlotKey {
        base: key_base.clone(),
        disp: key_disp,
    };
    // AAPCS own-frame memory can remain in current-SP coordinates until an
    // address escapes. Address SSA and DWARF CFA facts use the entry-SP
    // coordinate, however. If the scalar was initialized before its address
    // was copied, move that existing slot metadata to the now-proven object
    // coordinate so the already-rendered scalar name can be reconciled with
    // the object rather than leaving an initialized scalar beside an
    // uninitialized byte array.
    if matches!(
        ctx.cc,
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64)
    ) && key_base == "entry_sp"
        && !map.contains_key(&key)
    {
        if let Some(current_disp) = sp_delta.and_then(|delta| key_disp.checked_sub(delta)) {
            let current_key = SlotKey {
                base: "sp".to_string(),
                disp: current_disp,
            };
            if let Some(existing) = map.remove(&current_key) {
                map.insert(key.clone(), existing);
            }
        }
    }
    let next_slot_extent = map
        .keys()
        .filter(|candidate| candidate.base == key_base && candidate.disp > key_disp)
        .map(|candidate| candidate.disp - key_disp)
        .min()
        .and_then(|extent| u16::try_from(extent).ok())
        .filter(|extent| *extent > 0);
    let pointer_size = match ctx.cc {
        Some(CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    };
    let entry = map.entry(key).or_insert_with(|| SlotVal {
        name: alloc_name(&key_base, key_disp, names, ctx),
        declared_size: pointer_size,
        span_size: pointer_size,
        object_size: None,
        bounded_object: false,
        source_type: None,
        source_name: None,
        debug_proven: false,
    });
    let object = VReg::phys(entry.name.clone());
    // A frame-local object starts at a negative offset and grows toward the
    // frame base on the supported downward-growing stacks. Reserving the whole
    // interval to the base is conservative (it may include padding or adjacent
    // machine slots), but unlike a pointer-sized scalar it cannot be overrun by
    // a constructor whose recovered source type is not yet known. Cap at the C
    // representation's bounded u16 extent so hostile displacements cannot make
    // the renderer request an unbounded object.
    let conservative_size = if key_disp < 0 {
        u16::try_from(key_disp.unsigned_abs())
            .unwrap_or(u16::MAX)
            .max(u16::from(pointer_size))
    } else {
        u16::from(pointer_size)
    };
    // A separately observed slot closer to the frame base is a hard object
    // boundary.  Without it, an address-taken struct at rbp-0x20 absorbs an
    // independent argument at rbp-0x14 merely because its source type is not
    // yet known.
    let size = if bare_frame_anchor {
        u16::from(pointer_size)
    } else {
        next_slot_extent.unwrap_or(conservative_size)
    };
    // Persist the storage identity in the slot map, not only in this call
    // argument.  Later loads/stores must remain dereferences of the same byte
    // array; rewriting them as scalar `Reg(local)` values would make C decay
    // the array to its address and use pointer bits as object contents.
    entry.object_size = Some(entry.object_size.unwrap_or(0).max(size));
    entry.bounded_object |= next_slot_extent.is_some() || key_disp >= 0;
    *expr = Expr::StackAddr { object, size };
}

/// Recover definitions that carry a constant frame/stack address into a call.
///
/// These registers are already SSA-versioned by the value model (`rax#4`,
/// `rax#8`, ...), so their identity is path-stable. Keeping this small semantic
/// map is the minimum equivalent of looking through an AIL virtual-variable or
/// a Ghidra Varnode definition; it avoids asking the general expression pass to
/// move an address computation across unrelated effects.
fn collect_stack_address_defs(
    body: &[Stmt],
    ctx: StackContext,
    label_deltas: &HashMap<u64, Option<i64>>,
) -> HashMap<VReg, (String, i64)> {
    fn record_definition(
        dst: &VReg,
        address: Option<(String, i64)>,
        out: &mut HashMap<VReg, (String, i64)>,
        ambiguous: &mut HashSet<VReg>,
    ) {
        if ambiguous.contains(dst) {
            return;
        }
        match (out.get(dst), address) {
            (None, Some(address)) => {
                out.insert(dst.clone(), address);
            }
            (Some(existing), Some(address)) if existing == &address => {}
            (Some(_), Some(_)) | (Some(_), None) => {
                out.remove(dst);
                ambiguous.insert(dst.clone());
            }
            // A definition that carries no stack address makes the register
            // ambiguous even when it is seen FIRST. The map is keyed by
            // register, not by program point, so a single later address
            // definition would otherwise claim the whole body — including the
            // region where the register held something else entirely. GCC's
            // pre-value-folding Thumb lowering reuses one temporary for both a
            // loaded integer and the epilogue's frame address, and the frame
            // coordinate leaking backwards over the integer uses made four
            // ordinary adds look like subscripted frame accesses, seeding a
            // byte array over the whole frame. Value-numbered bodies define
            // each name once and are unaffected.
            (None, None) => {
                ambiguous.insert(dst.clone());
            }
        }
    }

    fn walk_direct(
        body: &[Stmt],
        out: &mut HashMap<VReg, (String, i64)>,
        ambiguous: &mut HashSet<VReg>,
        ctx: StackContext,
        sp_delta: &mut Option<i64>,
        label_deltas: &HashMap<u64, Option<i64>>,
    ) {
        for (statement_index, stmt) in body.iter().enumerate() {
            match stmt {
                Stmt::Assign { dst, src } => {
                    let address = resolve_stack_address(src, *sp_delta, ctx, out);
                    if is_stack_pointer_reg(dst, ctx) {
                        *sp_delta = address.and_then(|(base, disp)| {
                            (base == entry_stack_base(ctx)).then_some(disp)
                        });
                    } else if matches!(dst, VReg::Phys(name) if is_arm_frame_pointer(name, ctx)) {
                        // An epilogue overwrite of the frame register is frame
                        // teardown, not a competing reaching frame definition.
                        // A32 restores the unversioned `fp` from its saved stack
                        // word; Thumb first re-adds the prologue constant
                        // (`adds r7, #32; mov sp, r7`), which GCC lowers through
                        // register temporaries so it is not a foldable stack
                        // expression. Ignore either only when the current path
                        // terminates and every later read of the register feeds
                        // a stack-pointer restore — machine bookkeeping that
                        // addresses no source storage. A fall-through nested
                        // body or any other live use remains ambiguous.
                        let terminal_teardown = address.is_none()
                            && out.contains_key(dst)
                            && !body_falls_through(&body[statement_index + 1..])
                            && frame_coordinate_is_dead_after(
                                &body[statement_index + 1..],
                                dst,
                                ctx,
                            );
                        if terminal_teardown {
                            continue;
                        }
                        // Preserve the exact entry-SP coordinate captured
                        // by `r7#1 = sp` or `fp = sp + 4`; later direct
                        // arithmetic must resolve to the same DWARF CFA
                        // object. x86's `rbp = rsp` remains a coordinate-
                        // system establishment below.
                        record_definition(dst, address, out, ambiguous);
                        continue;
                    } else if matches!(dst, VReg::Phys(name) if is_active_stack_base(name, ctx)) {
                        // Architectural frame bases define the coordinate
                        // system used by DWARF and local naming. In particular,
                        // `rbp = rsp` is a frame establishment, not an immutable
                        // SSA address alias to rebase as `entry_rsp`.
                        out.remove(dst);
                        ambiguous.insert(dst.clone());
                    } else {
                        record_definition(dst, address, out, ambiguous);
                    }
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    let incoming = *sp_delta;
                    let mut then_delta = incoming;
                    walk_direct(
                        then_body,
                        out,
                        ambiguous,
                        ctx,
                        &mut then_delta,
                        label_deltas,
                    );
                    let mut else_delta = incoming;
                    if let Some(body) = else_body {
                        walk_direct(body, out, ambiguous, ctx, &mut else_delta, label_deltas);
                    }
                    let then_falls_through = body_falls_through(then_body);
                    let else_falls_through = else_body.as_deref().is_none_or(body_falls_through);
                    *sp_delta = match (then_falls_through, else_falls_through) {
                        (true, true) => merge_stack_deltas(then_delta, else_delta),
                        (true, false) => then_delta,
                        (false, true) => else_delta,
                        (false, false) => None,
                    };
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    let incoming = *sp_delta;
                    let mut body_delta = incoming;
                    walk_direct(body, out, ambiguous, ctx, &mut body_delta, label_deltas);
                    *sp_delta = merge_stack_deltas(incoming, body_delta);
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    walk_direct(
                        std::slice::from_ref(init.as_ref()),
                        out,
                        ambiguous,
                        ctx,
                        sp_delta,
                        label_deltas,
                    );
                    let loop_entry = *sp_delta;
                    let mut body_delta = loop_entry;
                    walk_direct(body, out, ambiguous, ctx, &mut body_delta, label_deltas);
                    walk_direct(
                        std::slice::from_ref(step.as_ref()),
                        out,
                        ambiguous,
                        ctx,
                        &mut body_delta,
                        label_deltas,
                    );
                    *sp_delta = merge_stack_deltas(loop_entry, body_delta);
                }
                Stmt::Switch { cases, default, .. } => {
                    let incoming = *sp_delta;
                    let mut merged: Option<Option<i64>> = None;
                    for (_, body) in cases {
                        let mut case_delta = incoming;
                        walk_direct(body, out, ambiguous, ctx, &mut case_delta, label_deltas);
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, case_delta),
                            None => case_delta,
                        });
                    }
                    if let Some(body) = default {
                        let mut default_delta = incoming;
                        walk_direct(body, out, ambiguous, ctx, &mut default_delta, label_deltas);
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, default_delta),
                            None => default_delta,
                        });
                    } else {
                        merged = Some(match merged {
                            Some(prior) => merge_stack_deltas(prior, incoming),
                            None => incoming,
                        });
                    }
                    *sp_delta = merged.unwrap_or(incoming);
                }
                Stmt::Push { .. } => {
                    *sp_delta = sp_delta.map(|delta| delta - stack_word_size(ctx));
                }
                Stmt::Pop { .. } => {
                    *sp_delta = sp_delta.map(|delta| delta + stack_word_size(ctx));
                }
                Stmt::Label(label) => {
                    *sp_delta = label_deltas.get(label).copied().unwrap_or(None);
                }
                Stmt::Goto { .. } | Stmt::Return { .. } | Stmt::IndirectGoto { .. } => {
                    *sp_delta = None;
                }
                _ => {}
            }
        }
    }

    let mut ambiguous = HashSet::new();
    loop {
        let prior_ambiguities = ambiguous.len();
        let mut defs = HashMap::new();
        let mut sp_delta = Some(0);
        walk_direct(
            body,
            &mut defs,
            &mut ambiguous,
            ctx,
            &mut sp_delta,
            label_deltas,
        );
        if ambiguous.len() == prior_ambiguities {
            return defs;
        }
    }
}

/// Resolve an expression that carries a stable stack address. Stack-pointer
/// values are converted to an architectural-entry displacement immediately;
/// SSA aliases can then be used after later stack-pointer adjustments without
/// changing which source object they identify.
fn resolve_stack_address(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64)> {
    fn base_address(
        reg: &VReg,
        sp_delta: Option<i64>,
        ctx: StackContext,
        address_defs: &HashMap<VReg, (String, i64)>,
    ) -> Option<(String, i64)> {
        if is_stack_pointer_reg(reg, ctx) {
            return sp_delta.map(|disp| (entry_stack_base(ctx).to_string(), disp));
        }
        if let Some(address) = address_defs.get(reg) {
            return Some(address.clone());
        }
        match reg {
            VReg::Phys(name) if is_active_stack_base(name, ctx) => Some((name.clone(), 0)),
            _ => None,
        }
    }

    match expr {
        Expr::Reg(reg) => base_address(reg, sp_delta, ctx, address_defs),
        Expr::Lea {
            base: Some(base),
            index: None,
            disp,
            segment: None,
            ..
        } => {
            let (base, base_disp) = base_address(base, sp_delta, ctx, address_defs)?;
            Some((base, base_disp.checked_add(*disp)?))
        }
        Expr::Bin { op, lhs, rhs } => {
            let (base, base_disp) = resolve_stack_address(lhs, sp_delta, ctx, address_defs)?;
            let Expr::Const(amount) = rhs.as_ref() else {
                return None;
            };
            let adjustment = match op {
                crate::ir::types::BinOp::Add => *amount,
                crate::ir::types::BinOp::Sub => amount.checked_neg()?,
                _ => return None,
            };
            Some((base, base_disp.checked_add(adjustment)?))
        }
        _ => None,
    }
}

/// Resolve only concrete load/store addresses. Direct `sp` accesses retain
/// their current-pass spelling so ARM push/pop rematerialization can still see
/// `[sp]`; an SSA alias such as `r7#1 = sp` instead uses its frozen entry-stack
/// displacement.
fn resolved_memory_slot(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64)> {
    let (base, disp, index, _) = resolved_memory_address(expr, sp_delta, ctx, address_defs)?;
    index.is_none().then_some((base, disp))
}

/// Resolve a stack memory operand while retaining its optional dynamic index.
/// The constant part is normalized to entry-SP coordinates exactly like scalar
/// slots, so frame-pointer omission does not create a second storage identity.
fn resolved_memory_address(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<(String, i64, Option<VReg>, u8)> {
    fn scaled_index(expr: &Expr) -> Option<(VReg, u8, i64)> {
        match expr {
            Expr::Reg(index) => Some((index.clone(), 1, 0)),
            Expr::Bin {
                op: crate::ir::types::BinOp::Mul,
                lhs,
                rhs,
            } => {
                let (Expr::Reg(index), Expr::Const(scale)) = (lhs.as_ref(), rhs.as_ref()) else {
                    let (Expr::Const(scale), Expr::Reg(index)) = (lhs.as_ref(), rhs.as_ref())
                    else {
                        return None;
                    };
                    return u8::try_from(*scale)
                        .ok()
                        .filter(|scale| *scale > 0)
                        .map(|scale| (index.clone(), scale, 0));
                };
                u8::try_from(*scale)
                    .ok()
                    .filter(|scale| *scale > 0)
                    .map(|scale| (index.clone(), scale, 0))
            }
            Expr::Bin {
                op: crate::ir::types::BinOp::Shl,
                lhs,
                rhs,
            } => {
                let (Expr::Reg(index), Expr::Const(shift)) = (lhs.as_ref(), rhs.as_ref()) else {
                    return None;
                };
                u32::try_from(*shift)
                    .ok()
                    .and_then(|shift| 1u8.checked_shl(shift))
                    .filter(|scale| *scale > 0)
                    .map(|scale| (index.clone(), scale, 0))
            }
            Expr::Bin { op, lhs, rhs }
                if matches!(
                    op,
                    crate::ir::types::BinOp::Add | crate::ir::types::BinOp::Sub
                ) =>
            {
                if let Expr::Const(amount) = rhs.as_ref() {
                    let (index, scale, offset) = scaled_index(lhs)?;
                    let adjustment = match op {
                        crate::ir::types::BinOp::Add => *amount,
                        crate::ir::types::BinOp::Sub => amount.checked_neg()?,
                        _ => unreachable!(),
                    };
                    return Some((index, scale, offset.checked_add(adjustment)?));
                }
                if matches!(op, crate::ir::types::BinOp::Add) {
                    if let Expr::Const(amount) = lhs.as_ref() {
                        let (index, scale, offset) = scaled_index(rhs)?;
                        return Some((index, scale, offset.checked_add(*amount)?));
                    }
                }
                None
            }
            _ => None,
        }
    }

    // Alias expansion represents a constant stack address as ordinary
    // arithmetic (`sp + 68`) instead of a low-level Lea. Resolve that exact
    // non-indexed form before looking for dynamic address components; otherwise
    // the address-valued definition promotes while a store through the same
    // alias remains rooted at an uninitialised synthetic `sp` C local.
    if matches!(ctx.cc, Some(CallConv::Arm | CallConv::ArmHardFloat)) {
        if let Some((base, disp)) = resolve_stack_address(expr, sp_delta, ctx, address_defs) {
            return Some((base, disp, None, 1));
        }
    }

    // Argument reconstruction represents effective addresses as ordinary AST
    // arithmetic rather than `Lea`: `((stack_base + index*scale) + disp)`.
    // Recover that form before handling the lower-level memory operand below.
    if let Expr::Bin { op, lhs, rhs } = expr {
        if let Expr::Const(amount) = rhs.as_ref() {
            let adjustment = match op {
                crate::ir::types::BinOp::Add => Some(*amount),
                crate::ir::types::BinOp::Sub => amount.checked_neg(),
                _ => None,
            };
            if let Some(adjustment) = adjustment {
                if let Some((base, disp, index, scale)) =
                    resolved_memory_address(lhs, sp_delta, ctx, address_defs)
                {
                    return Some((base, disp.checked_add(adjustment)?, index, scale));
                }
            }
        }
        if matches!(op, crate::ir::types::BinOp::Add) {
            for (base_expr, index_expr) in
                [(lhs.as_ref(), rhs.as_ref()), (rhs.as_ref(), lhs.as_ref())]
            {
                if let (Some((base, disp)), Some((index, scale, index_offset))) = (
                    resolve_stack_address(base_expr, sp_delta, ctx, address_defs),
                    scaled_index(index_expr),
                ) {
                    return Some((base, disp.checked_add(index_offset)?, Some(index), scale));
                }
            }
        }
    }

    let Expr::Lea {
        base: Some(base),
        index,
        scale,
        disp,
        segment: None,
    } = expr
    else {
        return None;
    };
    if let Some((resolved_base, base_disp)) = address_defs.get(base) {
        return Some((
            resolved_base.clone(),
            base_disp.checked_add(*disp)?,
            index.clone(),
            *scale,
        ));
    }
    if let VReg::Phys(name) = base {
        if is_active_stack_base(name, ctx) {
            let (base, disp) = normalized_stack_slot(name, *disp, sp_delta, ctx);
            return Some((base, disp, index.clone(), *scale));
        }
    }

    // Addition is commutative when the SIB scale is one. Encoders freely put
    // the stack-derived alias in the index field (`[rax+r8]`) and the logical
    // subscript in the base field. Recover the same object while retaining the
    // non-stack base as the dynamic byte offset.
    let stack_index = index.as_ref()?;
    if *scale != 1 {
        return None;
    }
    let (resolved_base, resolved_disp) =
        if let Some((resolved_base, base_disp)) = address_defs.get(stack_index) {
            (resolved_base.clone(), base_disp.checked_add(*disp)?)
        } else if let VReg::Phys(name) = stack_index {
            if is_active_stack_base(name, ctx) {
                normalized_stack_slot(name, *disp, sp_delta, ctx)
            } else {
                return None;
            }
        } else {
            return None;
        };
    Some((resolved_base, resolved_disp, Some(base.clone()), 1))
}

/// Re-express an AAPCS current-SP coordinate in DWARF's CFA coordinate.
///
/// Ordinary own-frame slots may retain their current-SP spelling. Debug-proven
/// aggregate objects are different: their locations are relative to the
/// call-frame address (the entry SP), so look through that second coordinate
/// only when an authoritative object actually contains the access.
fn aapcs_entry_stack_coordinate(
    base: &str,
    disp: i64,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> Option<(&'static str, i64)> {
    (matches!(
        ctx.cc,
        Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64)
    ) && base == "sp")
        .then(|| disp.checked_add(sp_delta?))?
        .map(|disp| ("entry_sp", disp))
}

/// The promoted object an access at `(base, disp)` falls inside.
///
/// `allow_end_pointer` admits an address that lands exactly ONE PAST the end of
/// a debug-proven object. `lea 0x20(%rsp),%rdx` is the bound `&a[8]` of the loop
/// that fills the `int32_t a[8]` at `rsp`, and C says that address exists; while
/// a heuristic object ran to the frame base it was swallowed by accident, and
/// with the exact DWARF extent, refusing it left the bound as arithmetic on an
/// undefined `rsp` (`196_disjoint_frame_slots:gcc:O2:dfs196_indexed_control`).
///
/// Three conditions keep it from absorbing the NEXT object, which occupies the
/// very same coordinate and is what makes this dangerous:
///
/// * a DEREFERENCE there is still refused — only `access_size == 0` qualifies;
/// * the extent must be debug-proven. A recovered extent's last byte is a
///   guess: allowing this for every bounded object added 275 undefined reads to
///   `rustc:O0` and 165 to `rustc:O2`, whose iterator code is built out of end
///   pointers, while moving no cell;
/// * only a value-producing ASSIGNMENT asks for it. An address handed to a
///   CALLEE that lands one past an object is far more likely to be the
///   neighbouring object — at `-O0`, `Movable b` sitting directly above
///   `Movable a` became `&a + 8` and the recompiled C wrote past `a`'s end
///   (`10_cpp_runtime_shapes:gcc:O0:cpp_move`).
///
/// A slot that really starts at that coordinate and is already an object still
/// wins, because the selection below keeps the greatest start.
fn containing_stack_object<'a>(
    map: &'a HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    access_size: u8,
    indexed: bool,
    require_bounded: bool,
    allow_end_pointer: bool,
) -> Option<(i64, &'a SlotVal, u16)> {
    let access_end = disp.checked_add(i64::from(access_size))?;
    map.iter()
        .filter_map(|(key, slot)| {
            let size = slot.object_size?;
            let end = key.disp.checked_add(i64::from(size))?;
            let end_pointer =
                allow_end_pointer && access_size == 0 && disp == end && slot.debug_proven;
            (key.base == base
                && (!require_bounded || slot.bounded_object)
                && key.disp <= disp
                && (disp < end || end_pointer)
                && (indexed || access_end <= end || end_pointer))
                .then_some((key.disp, slot, size))
        })
        .max_by_key(|(start, _, _)| *start)
}

fn bounded_scalar_at_coordinate(
    map: &HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    access_size: u8,
) -> Option<(SlotKey, i64)> {
    let Some(access_end) = disp.checked_add(i64::from(access_size)) else {
        return None;
    };
    map.iter()
        .filter_map(|(key, slot)| {
            let slot_end = key.disp.checked_add(i64::from(slot.span_size))?;
            (key.base == base
                && slot.bounded_object
                && slot.object_size.is_none()
                // A scalar hint can become a C lvalue only for a whole-value
                // access at its exact base. Partial/interior machine-word
                // transports need byte-object semantics that this path does
                // not yet model; collapsing them loses untouched bytes.
                && key.disp == disp
                && (access_size == 0 || access_size == slot.span_size)
                && if access_size == 0 {
                    disp < slot_end
                } else {
                    access_end <= slot_end
                })
            .then_some((key.clone(), disp - key.disp))
        })
        .max_by_key(|(key, _)| key.disp)
}

fn bounded_scalar_slot(
    map: &HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    access_size: u8,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> Option<(SlotKey, i64)> {
    aapcs_entry_stack_coordinate(base, disp, sp_delta, ctx)
        .and_then(|(alternate_base, alternate_disp)| {
            bounded_scalar_at_coordinate(map, alternate_base, alternate_disp, access_size)
        })
        .or_else(|| bounded_scalar_at_coordinate(map, base, disp, access_size))
}

/// A debug-proven object an INDEXED access addresses from one element BELOW it.
///
/// Compilers routinely bias a subscript rather than the base: gcc reaches
/// `int32_t temp[16]` at `rsp+0x30` as `0x2c(%rsp) + (out+1)*4`, so the
/// recovered constant part sits one element under the proven array while the
/// effective address is inside it. `seed_indexed_stack_objects` already treats
/// that shape as an aliasing bias when comparing two heuristic partitions; this
/// is the same rule against an authoritative extent, and it is what lets the
/// proven object own the access instead of a second array being invented under
/// it. The relative offset comes out NEGATIVE, which is exactly the bias the
/// machine applied: `&temp[0] + (out + 1)*4 - 4`.
///
/// Bounded by one element deliberately. A larger gap is a different allocation,
/// not a bias, and the caller has already asked every containment rule first.
fn biased_indexed_object<'a>(
    map: &'a HashMap<SlotKey, SlotVal>,
    base: &str,
    disp: i64,
    index: Option<&VReg>,
    scale: u8,
) -> Option<(i64, &'a SlotVal, u16)> {
    index?;
    if scale == 0 {
        return None;
    }
    let reach = disp.checked_add(i64::from(scale))?;
    map.iter()
        .filter_map(|(key, slot)| {
            let size = slot.object_size?;
            (key.base == base && slot.debug_proven && disp < key.disp && key.disp <= reach)
                .then_some((key.disp, slot, size))
        })
        .min_by_key(|(start, _, _)| *start)
}

/// Materialise an access inside a seeded stack region as byte-pointer
/// arithmetic rooted at one [`Expr::StackAddr`].
fn stack_object_address(
    expr: &Expr,
    access_size: u8,
    map: &HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
) -> Option<Expr> {
    let (base, disp, index, scale) = resolved_memory_address(expr, sp_delta, ctx, address_defs)?;
    if index.is_some() && scale == 0 {
        return None;
    }
    let alternate = aapcs_entry_stack_coordinate(&base, disp, sp_delta, ctx);
    if bounded_scalar_slot(map, &base, disp, access_size, sp_delta, ctx).is_some() {
        return None;
    }
    let contained = alternate
        .and_then(|(alternate_base, alternate_disp)| {
            containing_stack_object(
                map,
                alternate_base,
                alternate_disp,
                access_size,
                index.is_some(),
                true,
                false,
            )
            .map(|(start, slot, size)| (alternate_disp, start, slot, size))
        })
        .or_else(|| {
            containing_stack_object(map, &base, disp, access_size, index.is_some(), false, false)
                .map(|(start, slot, size)| (disp, start, slot, size))
        });
    let biased = alternate
        .and_then(|(alternate_base, alternate_disp)| {
            biased_indexed_object(map, alternate_base, alternate_disp, index.as_ref(), scale)
                .map(|(start, slot, size)| (alternate_disp, start, slot, size))
        })
        .or_else(|| {
            biased_indexed_object(map, &base, disp, index.as_ref(), scale)
                .map(|(start, slot, size)| (disp, start, slot, size))
        });
    // An object that contains only the FIRST address of an indexed sequence is
    // not the array that sequence walks. `queue[head++]` at
    // `23_topological_sort:i386:O2` is addressed `0x58(%esp,%edi,4)` with `%edi`
    // starting at one — a base one element low, exactly the merge_sort bias —
    // and there the element below `queue` is the LAST element of the adjacent
    // `indegree[16]`. Containment therefore matched, and matched the wrong
    // array: every dynamic address the sequence produces is in `queue`, and only
    // the base byte is in `indegree`. Before the CFA repair neither array was
    // proven and the heuristic partitioned from the biased base, which is why
    // this shape has no host-lane analogue and survived two `@o0`/`@o2` sweeps.
    //
    // Two conditions, both needed. The sequence must leave the containing
    // object by its SECOND element, and the base must not be that object's own
    // start — a bias displaces the base from the array it walks, so a base
    // sitting exactly on an object is that object being addressed directly.
    // Without the second condition a one-element proven object indexed at its
    // own start would hand itself to whatever follows it.
    let escapes_immediately = |start: i64, size: u16| {
        disp > start
            && start
                .checked_add(i64::from(size))
                .is_some_and(|end| end <= disp.saturating_add(i64::from(scale)))
    };
    let (object_disp, start, slot, object_size) = match (contained, biased) {
        (Some((_, start, _, size)), Some(biased)) if escapes_immediately(start, size) => biased,
        (Some(contained), _) => contained,
        (None, biased) => biased?,
    };

    let mut offset = index.map(|index| {
        let index = Expr::Reg(index);
        if scale == 1 {
            index
        } else {
            Expr::Bin {
                op: crate::ir::types::BinOp::Mul,
                lhs: Box::new(index),
                rhs: Box::new(Expr::Const(i64::from(scale))),
            }
        }
    });
    let relative = object_disp.checked_sub(start)?;
    if relative != 0 {
        offset = Some(match offset {
            Some(index) => Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(index),
                rhs: Box::new(Expr::Const(relative)),
            },
            None => Expr::Const(relative),
        });
    }
    let object = Expr::StackAddr {
        object: VReg::phys(slot.name.clone()),
        size: object_size,
    };
    Some(match offset {
        Some(offset) => Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(object),
            rhs: Box::new(offset),
        },
        None => object,
    })
}

/// Recover a value-producing copy of the current frame/stack address. This is
/// distinct from a memory operand: optimized code often moves `rsp` into a
/// callee-saved register and then advances that register as an array cursor.
fn stack_object_constant_address(
    expr: &Expr,
    map: &HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    allow_end_pointer: bool,
) -> Option<Expr> {
    let recovered = escaped_stack_address(expr, sp_delta, ctx, address_defs, true)?;
    let (base, disp) = normalized_stack_slot(&recovered.0, recovered.1, sp_delta, ctx);
    let alternate = aapcs_entry_stack_coordinate(&base, disp, sp_delta, ctx);
    let (object_disp, start, slot, size) = alternate
        .and_then(|(alternate_base, alternate_disp)| {
            containing_stack_object(
                map,
                alternate_base,
                alternate_disp,
                0,
                true,
                true,
                allow_end_pointer,
            )
            .map(|(start, slot, size)| (alternate_disp, start, slot, size))
        })
        .or_else(|| {
            containing_stack_object(map, &base, disp, 0, true, false, allow_end_pointer)
                .map(|(start, slot, size)| (disp, start, slot, size))
        })?;
    let object = Expr::StackAddr {
        object: VReg::phys(slot.name.clone()),
        size,
    };
    let relative = object_disp.checked_sub(start)?;
    Some(if relative != 0 {
        Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(object),
            rhs: Box::new(Expr::Const(relative)),
        }
    } else {
        object
    })
}

/// Materialise a copied frame address even when the object was first observed
/// as contiguous scalar initialisers. Optimised GCC commonly zeroes a small
/// array with lane stores, then copies `rsp` into a cursor for the scalar
/// fallback. A separately recovered indexed object at the next displacement is
/// a hard boundary; otherwise only a gap-free run of promoted slots is joined.
fn stack_assignment_object_address(
    expr: &Expr,
    map: &mut HashMap<SlotKey, SlotVal>,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    allow_end_pointer: bool,
) -> Option<Expr> {
    if let Some(existing) =
        stack_object_constant_address(expr, map, sp_delta, ctx, address_defs, allow_end_pointer)
    {
        return Some(existing);
    }
    let recovered = escaped_stack_address(expr, sp_delta, ctx, address_defs, true)?;
    let (base, disp) = normalized_stack_slot(&recovered.0, recovered.1, sp_delta, ctx);
    let key = SlotKey {
        base: base.clone(),
        disp,
    };
    let first = map.get(&key)?;
    if first.object_size.is_some() {
        return stack_object_constant_address(
            expr,
            map,
            sp_delta,
            ctx,
            address_defs,
            allow_end_pointer,
        );
    }

    let boundary = map
        .iter()
        .filter(|(candidate, slot)| {
            candidate.base == base && candidate.disp > disp && slot.object_size.is_some()
        })
        .map(|(candidate, _)| candidate.disp)
        .min();
    let mut candidates = map
        .iter()
        .filter(|(candidate, slot)| {
            candidate.base == base
                && candidate.disp >= disp
                && candidate.disp < boundary.unwrap_or(i64::MAX)
                && slot.object_size.is_none()
        })
        .map(|(candidate, slot)| (candidate.disp, slot.span_size))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(candidate_disp, _)| *candidate_disp);
    let mut end = disp.checked_add(i64::from(first.span_size))?;
    let mut extends_first_slot = false;
    for (candidate_disp, span) in candidates {
        if candidate_disp > end {
            break;
        }
        let candidate_end = candidate_disp.checked_add(i64::from(span))?;
        if candidate_disp > disp && candidate_end > end {
            extends_first_slot = true;
        }
        end = end.max(candidate_end);
    }
    // A lone saved frame pointer is also an eight-byte slot followed by
    // `rbp = rsp`. It is frame establishment, not evidence that the slot is an
    // address-taken array. Require a second contiguous scalar initializer to
    // extend the candidate object before joining the run.
    if !extends_first_slot {
        return None;
    }
    if boundary == Some(end) {
        end = boundary?;
    }
    let minimum_size = match ctx.cc {
        Some(CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat) => 4,
        Some(CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64) | None => 8,
    };
    let size = u16::try_from(end.checked_sub(disp)?)
        .ok()
        .filter(|size| *size > 0)?
        .max(minimum_size);
    let slot = map.get_mut(&key)?;
    slot.object_size = Some(size);
    slot.bounded_object = true;
    stack_object_constant_address(expr, map, sp_delta, ctx, address_defs, allow_end_pointer)
}

/// Resolve an escaping stack address without broadening the established x86
/// frame model. AAPCS needs the SSA frame-pointer definition (`r7#1 = sp`) to
/// reach the entry-SP coordinate; x86 frame registers deliberately retain
/// their architectural coordinate and use the narrower legacy spelling.
fn escaped_stack_address(
    expr: &Expr,
    sp_delta: Option<i64>,
    ctx: StackContext,
    address_defs: &HashMap<VReg, (String, i64)>,
    prefer_active_base: bool,
) -> Option<(String, i64)> {
    if matches!(ctx.cc, Some(CallConv::Arm | CallConv::ArmHardFloat)) {
        return resolve_stack_address(expr, sp_delta, ctx, address_defs);
    }
    if prefer_active_base {
        return match expr {
            Expr::Reg(VReg::Phys(name)) if is_active_stack_base(name, ctx) => {
                Some((name.clone(), 0))
            }
            Expr::Reg(reg) => address_defs.get(reg).cloned(),
            _ => constant_stack_address(expr, ctx),
        };
    }
    constant_stack_address(expr, ctx).or_else(|| match expr {
        Expr::Reg(reg) => address_defs.get(reg).cloned(),
        _ => None,
    })
}

fn constant_stack_address(expr: &Expr, ctx: StackContext) -> Option<(String, i64)> {
    match expr {
        Expr::Lea {
            base: Some(VReg::Phys(base)),
            index: None,
            disp,
            segment: None,
            ..
        } if is_active_stack_base(base, ctx) => Some((base.clone(), *disp)),
        Expr::Bin { op, lhs, rhs } => {
            let (Expr::Reg(VReg::Phys(base)), Expr::Const(amount)) = (lhs.as_ref(), rhs.as_ref())
            else {
                return None;
            };
            if !is_active_stack_base(base, ctx) {
                return None;
            }
            let disp = match op {
                crate::ir::types::BinOp::Add => *amount,
                crate::ir::types::BinOp::Sub => amount.checked_neg()?,
                _ => return None,
            };
            Some((base.clone(), disp))
        }
        _ => None,
    }
}

fn extract_little_endian_subvalue(parent: String, byte_offset: u8, size: u8) -> Expr {
    let wide_parent = Expr::Cast {
        signed: false,
        width: 8,
        expr: Box::new(Expr::Reg(VReg::phys(parent))),
    };
    let shifted = Expr::Bin {
        op: crate::ir::types::BinOp::Shr,
        lhs: Box::new(wide_parent),
        rhs: Box::new(Expr::Const(i64::from(byte_offset) * 8)),
    };
    Expr::Cast {
        signed: false,
        width: size,
        expr: Box::new(shifted),
    }
}

/// Store-address Lea: turn the full `&[base+disp]` into a `Reg(local)`.
/// The parameter a just-promoted store address names, when the store writes an
/// incoming argument's HOME SLOT.
///
/// A write to that slot is an assignment to the parameter, not a store through
/// it. On SysV AMD64 and AArch64 the first several arguments arrive in
/// registers, so the shape barely occurs; cdecl32 passes EVERY argument on the
/// stack, so a plain `x = f(x);` on a parameter compiles to exactly this store.
/// Left as a store it rendered `*(int *)(arg2) = v` — a dereference of the
/// parameter's VALUE, which faults on a scalar parameter and silently corrupts
/// memory through a pointer one.
///
/// Two guards keep this exact rather than approximate:
///
/// * the caller only asks when the address was an `Expr::Lea` before promotion,
///   so a genuine `*p = v` (whose address is already a register) can never
///   arrive here;
/// * the write must cover the WHOLE slot. A narrower write is a byte-level
///   effect on the argument's memory that a scalar assignment cannot express,
///   and keeps its store form.
fn argument_slot_assignment(addr: &Expr, size: u8, ctx: StackContext) -> Option<VReg> {
    let Expr::Reg(register @ VReg::Phys(name)) = addr else {
        return None;
    };
    crate::ir::ast::parse_arg_index(name)?;
    let (_reg_args, _first, stride) = ctx.cc.and_then(stack_arg_layout)?;
    (i64::from(size) == stride).then(|| register.clone())
}

fn try_promote_lea_to_local(
    addr: &mut Expr,
    size: u8,
    map: &mut HashMap<SlotKey, SlotVal>,
    names: &mut SlotNames,
    ctx: StackContext,
    sp_delta: Option<i64>,
    address_defs: &HashMap<VReg, (String, i64)>,
) {
    if let Some(object_addr) = stack_object_address(addr, size, map, sp_delta, ctx, address_defs) {
        *addr = object_addr;
        return;
    }
    // A later narrower read at the exact same address can narrow the declaration,
    // while `span_size` retains the bytes this store defined for overlap recovery.
    let Some((key_base, key_disp)) = resolved_memory_slot(addr, sp_delta, ctx, address_defs) else {
        return;
    };
    let ordinary_key = SlotKey {
        base: key_base.clone(),
        disp: key_disp,
    };
    let key = bounded_scalar_slot(map, &key_base, key_disp, size, sp_delta, ctx)
        .map(|(key, _)| key)
        .unwrap_or(ordinary_key);
    let entry = map.entry(key).or_insert_with(|| SlotVal {
        name: alloc_name(&key_base, key_disp, names, ctx),
        declared_size: size,
        span_size: size,
        object_size: None,
        bounded_object: false,
        source_type: None,
        source_name: None,
        debug_proven: false,
    });
    entry.declared_size = entry.declared_size.min(size);
    entry.span_size = entry.span_size.max(size);
    let alias = entry.name.clone();
    *addr = Expr::Reg(VReg::phys(alias));
}

/// Express an rsp-relative slot against the architectural entry rsp when the
/// current delta is known. This makes `[rsp+16]` after one push the same slot as
/// `[entry_rsp+8]`, and gives naming an ABI-stable displacement.
fn normalized_stack_slot(
    base: &str,
    disp: i64,
    sp_delta: Option<i64>,
    ctx: StackContext,
) -> (String, i64) {
    // `sp` is normalised unconditionally for ARM32, whose whole frame model this
    // already describes. AArch64 was deliberately excluded: `resolve_stack_address`
    // gives it an `entry_sp` identity through a different path, and unifying them
    // here moves a lane that is already 82% correct.
    //
    // That exclusion is kept for the callee's OWN frame and lifted only at or
    // above the entry stack pointer, which is the caller's territory and the only
    // place an AAPCS64 stacked argument can live. A frame-pointer-omitted
    // `ldr w9, [sp]` is exactly how `sum_arg9`/`sum_arg10` read their ninth and
    // tenth arguments, and without the entry-relative spelling those promoted to
    // an undefined `stack_top`.
    //
    // The `disp + delta >= 0` bound is not cosmetic and was not reasoned into
    // existence: normalising AArch64's negative (own-frame) offsets too renamed
    // `24_merge_sort:aarch64:O2:merge_sort_i32`'s locals, split its scratch buffer,
    // and turned a passing execution differential into a failing one. See
    // `tools/arch_roundtrip.py --check`.
    let architectural_sp = base == "rsp" || (base == "esp" && ctx.cc == Some(CallConv::Cdecl32));
    let aapcs_sp = base == "sp"
        && matches!(
            ctx.cc,
            Some(CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64)
        );
    if architectural_sp || aapcs_sp {
        if let Some(delta) = sp_delta {
            let normalized = disp + delta;
            let own_frame_of_aarch64 = ctx.cc == Some(CallConv::Aarch64) && normalized < 0;
            if !own_frame_of_aarch64 {
                return (entry_stack_base(ctx).to_string(), normalized);
            }
        }
    }
    (base.to_string(), disp)
}

fn alloc_name(base: &str, disp: i64, names: &mut SlotNames, ctx: StackContext) -> String {
    // Both AAPCS variants stack the arguments that do not fit in registers
    // directly at the ENTRY stack pointer. `lr`/`x30` is a register, so unlike
    // x86 there is no return-address word in front of them; the AArch64
    // `{fp, lr}` frame record is pushed BELOW entry_sp by the callee's own
    // prologue and so does not sit in front of them either. That puts the first
    // stacked argument at `entry_sp+0` — which the `disp == 0` shortcut below
    // would otherwise name `stack_top`, leaving `sum_arg5`'s fifth argument
    // (ARM32) and `sum_arg9`'s ninth (AArch64) undefined locals that the
    // rebuilt C read as garbage.
    //
    // ARM32 passes four integer arguments in `r0`-`r3` and stacks the rest in
    // four-byte slots; AArch64 passes eight in `x0`-`x7` and stacks the rest in
    // eight-byte slots (AAPCS64 §5.4.2 rounds every stacked argument up to a
    // doubleword).
    //
    // A KNOWN parameter count is required here, not optional as it is for SysV.
    // `[rbp+16]` on x86-64 sits above a saved frame pointer and a return
    // address, which is structural evidence the slot belongs to the caller;
    // `entry_sp+0` has no such anchor, and without the bound an
    // outgoing-argument slot would be renamed into a parameter that does not
    // exist.
    if base == "entry_sp" {
        let stacked = match ctx.cc {
            Some(CallConv::Arm | CallConv::ArmHardFloat) => Some((4usize, 4i64)),
            Some(CallConv::Aarch64) => Some((8usize, 8i64)),
            _ => None,
        };
        if let Some((register_arguments, stride)) = stacked {
            if disp >= 0 && disp % stride == 0 {
                let candidate = register_arguments + (disp / stride) as usize;
                if ctx.parameter_count.is_some_and(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
        }
    }
    if disp == 0 {
        return "stack_top".to_string();
    }
    // Below the entry stack pointer is the function's own frame, but only when
    // that pointer is the frame's ONLY anchor. AAPCS keeps the existing
    // unconditional `entry_sp` behaviour; on x86 a `mov %rsp, %rbp` prologue
    // makes `rbp` the anchor and `entry_rsp-0x8` the saved-`rbp` slot, so both
    // would compete for `local_8`.
    let own_frame_anchor =
        base == entry_stack_base(ctx) && (base == "entry_sp" || !ctx.frame_pointer_established);
    if (is_frame_pointer(base) || own_frame_anchor) && disp < 0 {
        // Name frame locals by their offset (`[rbp-0xc]` -> `local_c`), the
        // Ghidra/IDA convention. The offset is genuine recovered information and
        // lets an offset-aware consumer align our locals to the ground truth,
        // rather than an appearance-order counter that carries no such signal.
        //
        // Below the ENTRY stack pointer is the function's own frame whether or
        // not it kept a frame pointer, so a frame-pointer-omitted `-O2` build
        // gets the same offset-bearing names an `-O0` build does. Only
        // `entry_sp` (AAPCS) used to qualify; `entry_rsp` fell through to the
        // appearance-order `stack_N` counter, which is why 55 of the 250
        // sample-set functions — nearly all of them `-O2`/`-O2-noinline` —
        // published no offset for any of their frame slots.
        //
        // The offset alone is not a unique identity: a function that keeps a
        // frame pointer AND addresses its outgoing-argument area through the
        // entry stack pointer has two anchors, and `rbp-0x18` is not the same
        // storage as `entry_rsp-0x18`. Minting one name for both would splice
        // two variables into one, so a name already taken falls back to the
        // conservative appearance-order counter.
        let candidate = format!("local_{:x}", disp.unsigned_abs());
        if names.taken.insert(candidate.clone()) {
            names.local_counter += 1; // keep the counter advancing for legacy callers
            return candidate;
        }
    }
    // A positive frame-pointer offset at or above the ABI's first stacked-argument
    // slot IS AN INCOMING PARAMETER, not a local. Naming it `stack_N` invents a
    // local the function never assigns — which is precisely what the def-before-use
    // verifier reports for `sum_arg7`..`sum_arg10` (`stack_0 is read but never
    // defined`) — and leaves it out of the signature, so the recompiled function
    // reads uninitialised memory instead of its own argument.
    if is_frame_pointer(base) && disp > 0 {
        if let Some((reg_args, first, stride)) = ctx.cc.and_then(stack_arg_layout) {
            if disp >= first && (disp - first) % stride == 0 {
                let candidate = reg_args + ((disp - first) / stride) as usize;
                if ctx.parameter_count.is_none_or(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
        }
    }
    // A frame-pointer-omitted x86 function addresses incoming stack arguments
    // relative to the architectural entry stack pointer.  The return address
    // occupies the first machine word: SysV AMD64's stacked arguments therefore
    // start at entry_rsp+8 after six register arguments, while cdecl32 starts at
    // entry_esp+4 and has no integer register arguments.  `esp` is normalised to
    // the canonical `entry_rsp` spelling above so both modes share slot identity.
    if base == "entry_rsp" {
        match ctx.cc {
            Some(CallConv::SysVAmd64) if disp >= 8 && (disp - 8) % 8 == 0 => {
                let candidate = 6 + ((disp - 8) / 8) as usize;
                if ctx.parameter_count.is_none_or(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
            Some(CallConv::Cdecl32) if disp >= 4 && (disp - 4) % 4 == 0 => {
                let candidate = ((disp - 4) / 4) as usize;
                if ctx.parameter_count.is_none_or(|count| candidate < count) {
                    return format!("arg{candidate}");
                }
            }
            _ => {}
        }
    }
    // Positive offsets from the entry stack pointer are the caller's
    // outgoing-argument / scratch area, and anything whose offset-bearing name
    // was already claimed by another anchor lands here too.
    let n = names.stack_counter;
    names.stack_counter += 1;
    let name = format!("stack_{}", n);
    names.taken.insert(name.clone());
    name
}

fn reserve_source_local_name(name: Option<&str>, names: &mut SlotNames) -> Option<String> {
    let name = name?;
    if !crate::ir::naming::valid_authoritative_local_name(name)
        || !names.taken.insert(name.to_string())
    {
        return None;
    }
    Some(name.to_string())
}

/// Frame-slot name allocation state for one function.
///
/// Names must be unique within a function: they become the promoted variable's
/// identity, so two distinct slots sharing one name would merge into a single
/// variable in the rendered C.
#[derive(Debug, Default)]
struct SlotNames {
    stack_counter: usize,
    local_counter: usize,
    taken: std::collections::HashSet<String>,
}

#[cfg(test)]
mod overlap_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    /// EPIC 3 prerequisite: the promoted-local name must be joinable back to the
    /// frame coordinate it was minted from.
    ///
    /// MIR memory objects are keyed by `ObjectIdentity::MirValue(ValueId)` over
    /// numbered LLIR; `high_variables` is keyed by the promoted-local NAME.
    /// Nothing maps between them, which is the blocker on migrating the first
    /// production aggregate consumer to verified MIR evidence.
    ///
    /// The name cannot be parsed back into a coordinate. `local_{disp:x}` keeps
    /// only `disp.unsigned_abs()`, so it loses the base and the sign, and the
    /// mint deliberately falls back to an appearance-order `stack_N` when the
    /// hex name is already taken — precisely because `rbp-0x18` and
    /// `entry_rsp-0x18` are different storage. So the mapping has to be exported
    /// by the pass that owns it.
    #[test]
    fn promotion_exports_the_frame_coordinate_behind_each_promoted_name() {
        let mut f = Function {
            name: "coords".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", -8, 4),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rbp", -16, 8),
                },
            ],
        };

        let facts = promote_stack_locals_with_facts(&mut f, Some(CallConv::SysVAmd64), None, &[]);

        let named = |source: &Stmt| match source {
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } => name.clone(),
            other => panic!("expected a promoted read, got {other:?}"),
        };
        let first = named(&f.body[0]);
        let second = named(&f.body[1]);
        assert_ne!(first, second, "distinct slots must get distinct names");

        assert_eq!(
            facts.frame_coordinates.get(first.as_str()),
            Some(&("rbp".to_string(), -8)),
            "the -8 slot must publish its exact (base, disp); got {:?}",
            facts.frame_coordinates
        );
        assert_eq!(
            facts.frame_coordinates.get(second.as_str()),
            Some(&("rbp".to_string(), -16)),
            "the -16 slot must publish its exact (base, disp); got {:?}",
            facts.frame_coordinates
        );
    }

    /// The negative control that makes the export safe to join against.
    ///
    /// Several machine slot keys intentionally collapse to one source-level role
    /// (`entry_rsp+0` and `esp+0` both render as `stack_top`). A name reached
    /// from two different coordinates cannot identify storage, so it must be
    /// ABSENT rather than resolve to whichever key happened to be iterated last
    /// — attaching MIR object evidence through an ambiguous name would bind a
    /// fact to the wrong variable.
    #[test]
    fn a_name_reached_from_two_coordinates_is_withheld_rather_than_guessed() {
        let mut f = Function {
            name: "collapsed".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("entry_rsp", 0, 8),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rsp", 0, 8),
                },
            ],
        };

        let facts = promote_stack_locals_with_facts(&mut f, Some(CallConv::SysVAmd64), None, &[]);

        for (name, coordinate) in &facts.frame_coordinates {
            assert!(
                facts.sizes.contains_key(name),
                "every exported coordinate must belong to a promoted name: \
                 {name} -> {coordinate:?}"
            );
        }
        // Whatever collapses, no exported name may disagree with itself: the
        // map is a function, and ambiguity is dropped on the floor.
        assert_eq!(
            facts.frame_coordinates.len(),
            facts
                .frame_coordinates
                .keys()
                .collect::<std::collections::HashSet<_>>()
                .len()
        );
    }

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }
    fn lea(base: &str, disp: i64) -> Expr {
        Expr::Lea {
            base: Some(reg(base)),
            index: None,
            scale: 0,
            disp,
            segment: None,
        }
    }
    fn deref_of(base: &str, disp: i64, size: u8) -> Expr {
        Expr::Deref {
            addr: Box::new(lea(base, disp)),
            size,
        }
    }
    fn indexed_deref(base: &str, index: &str, scale: u8, disp: i64, size: u8) -> Expr {
        Expr::Deref {
            addr: Box::new(Expr::Lea {
                base: Some(reg(base)),
                index: Some(reg(index)),
                scale,
                disp,
                segment: None,
            }),
            size,
        }
    }

    fn promoted(base: &str, disp: i64, cc: Option<CallConv>) -> String {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of(base, disp, 4),
            }],
        };
        promote_stack_locals_typed(&mut f, cc);
        match &f.body[0] {
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(n)),
                ..
            } => n.clone(),
            other => panic!("expected a promoted register, got {other:?}"),
        }
    }

    #[test]
    fn a_positive_frame_offset_is_a_stack_passed_argument_not_a_local() {
        // SysV AMD64: [rbp] is the saved frame pointer, [rbp+8] the return address,
        // so [rbp+16] upward are the arguments that did not fit in the six integer
        // registers. Calling them `stack_N` invents a local the function never
        // assigns, and leaves the parameter out of the signature.
        let cc = Some(CallConv::SysVAmd64);
        assert_eq!(promoted("rbp", 16, cc), "arg6");
        assert_eq!(promoted("rbp", 24, cc), "arg7");
        assert_eq!(promoted("rbp", 32, cc), "arg8");
        assert_eq!(promoted("rbp", 40, cc), "arg9");
    }

    #[test]
    fn a_locked_two_parameter_prototype_rejects_spurious_stack_arguments() {
        let mut f = Function {
            name: "ackermann".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", 40, 8),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rsp", 8, 8),
                },
            ],
        };

        let sizes = promote_stack_locals_typed_with_parameter_count(
            &mut f,
            Some(CallConv::SysVAmd64),
            Some(2),
        );

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_0"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "stack_1"
        ));
        assert!(!sizes.keys().any(|name| name.starts_with("arg")));
    }

    /// AAPCS puts arguments 0..3 in `r0`..`r3` and the rest on the caller's
    /// stack, starting at the ENTRY stack pointer with no return-address word in
    /// front of them — `lr` is a register on ARM.
    ///
    /// A locked parameter count is required, not optional as it is for SysV:
    /// `[rbp+16]` on x86-64 sits above a saved frame pointer and a return
    /// address, which is structural evidence that the slot belongs to the
    /// caller, and ARM32 has no such anchor at `entry_sp+0`.
    #[test]
    fn aapcs_stack_arguments_start_at_the_entry_stack_pointer() {
        for cc in [CallConv::Arm, CallConv::ArmHardFloat] {
            let mut f = Function {
                name: "sum_arg7".into(),
                entry_va: 0,
                body: vec![
                    Stmt::Assign {
                        dst: reg("r0"),
                        src: deref_of("sp", 0, 4),
                    },
                    Stmt::Assign {
                        dst: reg("r1"),
                        src: deref_of("sp", 4, 4),
                    },
                    Stmt::Assign {
                        dst: reg("r2"),
                        src: deref_of("sp", 8, 4),
                    },
                ],
            };
            promote_stack_locals_typed_with_parameter_count(&mut f, Some(cc), Some(7));
            let names: Vec<String> = f
                .body
                .iter()
                .map(|s| match s {
                    Stmt::Assign {
                        src: Expr::Reg(VReg::Phys(n)),
                        ..
                    } => n.clone(),
                    other => panic!("expected a promoted register, got {other:?}"),
                })
                .collect();
            assert_eq!(names, ["arg4", "arg5", "arg6"], "{cc:?}");
        }
    }

    /// A canonical A32 O0 frame pushes `fp` and then sets `fp = sp`, so the
    /// caller's entry stack pointer is `fp + 4`. The fifth and sixth integer
    /// parameters must keep their source argument identities when accessed
    /// through that second frame coordinate.
    #[test]
    fn aapcs_frame_pointer_stack_arguments_follow_the_saved_fp() {
        for cc in [CallConv::Arm, CallConv::ArmHardFloat] {
            let mut f = Function {
                name: "sum_arg6".into(),
                entry_va: 0,
                body: vec![
                    Stmt::Assign {
                        dst: reg("r0"),
                        src: deref_of("fp", 4, 4),
                    },
                    Stmt::Assign {
                        dst: reg("r1"),
                        src: deref_of("fp", 8, 4),
                    },
                ],
            };
            promote_stack_locals_typed_with_parameter_count(&mut f, Some(cc), Some(6));
            let names: Vec<String> = f
                .body
                .iter()
                .map(|stmt| match stmt {
                    Stmt::Assign {
                        src: Expr::Reg(VReg::Phys(name)),
                        ..
                    } => name.clone(),
                    other => panic!("expected a promoted argument, got {other:?}"),
                })
                .collect();
            assert_eq!(names, ["arg4", "arg5"], "{cc:?}");
        }
    }

    /// AAPCS64 is the same rule with eight register arguments and eight-byte
    /// stacked slots. This is what `06_calling_conventions:aarch64:sum_arg9`
    /// and `sum_arg10` read: `ldr w9, [sp]` / `ldr w8, [sp, #8]` in the `-O2`
    /// build, which used to promote to an undefined `stack_top`.
    #[test]
    fn aapcs64_stack_arguments_start_at_the_entry_stack_pointer() {
        let mut f = Function {
            name: "sum_arg10".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("x0"),
                    src: deref_of("sp", 0, 4),
                },
                Stmt::Assign {
                    dst: reg("x1"),
                    src: deref_of("sp", 8, 4),
                },
            ],
        };
        promote_stack_locals_typed_with_parameter_count(&mut f, Some(CallConv::Aarch64), Some(10));
        let names: Vec<String> = f
            .body
            .iter()
            .map(|s| match s {
                Stmt::Assign {
                    src: Expr::Reg(VReg::Phys(n)),
                    ..
                } => n.clone(),
                other => panic!("expected a promoted register, got {other:?}"),
            })
            .collect();
        assert_eq!(names, ["arg8", "arg9"]);
    }

    /// The bound applies to AAPCS64 too: an eight-argument function reads
    /// nothing from the caller's frame, so `[sp]` is ordinary stack storage.
    #[test]
    fn aapcs64_never_invents_a_stack_argument_beyond_the_prototype() {
        for count in [None, Some(8)] {
            let mut f = Function {
                name: "sum_arg8".into(),
                entry_va: 0,
                body: vec![Stmt::Assign {
                    dst: reg("x0"),
                    src: deref_of("sp", 0, 8),
                }],
            };
            promote_stack_locals_typed_with_parameter_count(&mut f, Some(CallConv::Aarch64), count);
            assert!(
                matches!(&f.body[0], Stmt::Assign {
                    src: Expr::Reg(VReg::Phys(name)), ..
                } if !name.starts_with("arg")),
                "count {count:?} invented a stack argument: {:?}",
                f.body[0]
            );
        }
    }

    /// The count is the bound: a four-argument AAPCS function reads nothing
    /// from the caller's frame, so `[sp]` there is ordinary stack storage and
    /// must NOT become a fifth parameter.
    #[test]
    fn aapcs_never_invents_a_stack_argument_beyond_the_prototype() {
        for count in [None, Some(4)] {
            let mut f = Function {
                name: "sum_arg4".into(),
                entry_va: 0,
                body: vec![Stmt::Assign {
                    dst: reg("r0"),
                    src: deref_of("sp", 0, 4),
                }],
            };
            promote_stack_locals_typed_with_parameter_count(&mut f, Some(CallConv::Arm), count);
            assert!(
                matches!(&f.body[0], Stmt::Assign {
                    src: Expr::Reg(VReg::Phys(name)), ..
                } if !name.starts_with("arg")),
                "count {count:?} invented a stack argument: {:?}",
                f.body[0]
            );
        }
    }

    #[test]
    fn cdecl32_arguments_start_at_ebp_plus_eight_in_four_byte_slots() {
        let cc = Some(CallConv::Cdecl32);
        assert_eq!(promoted("ebp", 8, cc), "arg0");
        assert_eq!(promoted("ebp", 12, cc), "arg1");
        assert_eq!(promoted("ebp", 16, cc), "arg2");
        assert_eq!(promoted("ebp", -4, cc), "local_4");
    }

    #[test]
    fn an_unchanged_entry_stack_pointer_exposes_optimized_sysv_stack_arguments() {
        // GCC/Clang -O2 omit the frame pointer for leaf functions such as
        // `sum_arg10`. With no prologue adjustment, [rsp] is the return address
        // and [rsp+8], [rsp+16], ... are the arguments after r9. Treating those
        // reads as `stack_N` locals truncates the C signature at six arguments
        // and makes the rebuilt function consume uninitialised locals.
        let mut f = Function {
            name: "sum_arg8".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 8, 4),
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rsp", 16, 8),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg6"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg7"
        ));
        assert_eq!(sizes.get("arg6"), Some(&4));
        assert_eq!(sizes.get("arg7"), Some(&8));
    }

    /// `x = step_index(x);` on a cdecl32 `int` parameter compiles to
    /// `mov %eax,0x8(%ebp)`. That writes the parameter, and rendering it as a
    /// store through the parameter (`*(int *)(arg0) = ...`) dereferences the
    /// argument's VALUE — a wild pointer for a scalar.
    #[test]
    fn a_full_width_write_to_a_cdecl32_argument_slot_assigns_the_parameter() {
        let mut f = Function {
            name: "writes_its_argument".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: lea("rbp", 8),
                src: Expr::Reg(reg("eax")),
                size: 4,
            }],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert!(
            matches!(
                &f.body[0],
                Stmt::Assign { dst: VReg::Phys(name), .. } if name == "arg0"
            ),
            "expected an assignment to arg0, got {:?}",
            f.body[0]
        );
    }

    /// A byte-wide write into an argument slot changes one byte of it. A scalar
    /// assignment would clobber the other three, so the store form is kept.
    #[test]
    fn a_narrow_write_to_a_cdecl32_argument_slot_stays_a_store() {
        let mut f = Function {
            name: "writes_one_byte".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: lea("rbp", 8),
                src: Expr::Reg(reg("al")),
                size: 1,
            }],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert!(
            matches!(&f.body[0], Stmt::Store { .. }),
            "expected the store to survive, got {:?}",
            f.body[0]
        );
    }

    /// `*p = v` through a pointer parameter is a memory write, not a redefinition
    /// of `p`. Its address is already a register when this pass sees it, which is
    /// exactly what distinguishes it from the home-slot case above.
    #[test]
    fn a_store_through_a_pointer_argument_is_not_an_argument_assignment() {
        let store = Stmt::Store {
            addr: Expr::Reg(reg("arg0")),
            src: Expr::Reg(reg("eax")),
            size: 4,
        };
        let mut f = Function {
            name: "writes_through_its_argument".into(),
            entry_va: 0,
            body: vec![store.clone()],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert_eq!(f.body[0], store);
    }

    /// The same rule on SysV AMD64, where the shape only arises for a stacked
    /// argument (index 6 and up) and the slot is eight bytes wide.
    #[test]
    fn a_full_width_write_to_a_sysv_stacked_argument_slot_assigns_the_parameter() {
        let mut f = Function {
            name: "writes_arg6".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: lea("rbp", 16),
                src: Expr::Reg(reg("rax")),
                size: 8,
            }],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(
            matches!(
                &f.body[0],
                Stmt::Assign { dst: VReg::Phys(name), .. } if name == "arg6"
            ),
            "expected an assignment to arg6, got {:?}",
            f.body[0]
        );
    }

    #[test]
    fn an_unchanged_entry_esp_exposes_optimized_cdecl32_arguments() {
        let mut f = Function {
            name: "cdecl_pair".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("esp", 4, 4),
                },
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("esp", 8, 4),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert!(matches!(
            &f.body[0],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg0"
        ));
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg1"
        ));
        assert_eq!(sizes.get("arg0"), Some(&4));
        assert_eq!(sizes.get("arg1"), Some(&4));
    }

    #[test]
    fn cdecl32_callee_saved_pushes_are_normalized_before_mapping_arguments() {
        fn subtract_esp() -> Stmt {
            Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(4)),
                },
            }
        }

        let mut f = Function {
            name: "rand_str".into(),
            entry_va: 0,
            body: vec![
                subtract_esp(),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("edi")),
                    size: 4,
                },
                subtract_esp(),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("esi")),
                    size: 4,
                },
                subtract_esp(),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("ebx")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("esi"),
                    src: deref_of("esp", 20, 4),
                },
                Stmt::Assign {
                    dst: reg("ebx"),
                    src: deref_of("esp", 16, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::Cdecl32));

        assert!(matches!(
            &f.body[6],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg1"
        ));
        assert!(matches!(
            &f.body[7],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg0"
        ));
    }

    #[test]
    fn an_adjusted_stack_pointer_does_not_invent_incoming_arguments() {
        // Once a function carves out a frame, a positive displacement from the
        // new rsp can be a local or outgoing-call slot. It is not safe to map it
        // to an incoming parameter without normalising the stack delta.
        // `[rsp+16]` after `sub rsp, 32` normalises to entry_rsp-16, i.e. the
        // function's own frame, so it takes the offset-bearing local name -- what
        // this test forbids is an `argN`, not a particular local spelling.
        let mut f = Function {
            name: "has_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 16, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_10"
        ));
    }

    #[test]
    fn a_loop_label_preserves_a_consistent_stack_slot_identity() {
        let mut f = Function {
            name: "loop_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Store {
                    addr: lea("rsp", 8),
                    src: Expr::Reg(reg("rdi")),
                    size: 4,
                },
                Stmt::Label(0x1010),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rsp", 8, 4),
                },
                Stmt::Goto { target: 0x1010 },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_18"
        ));
        assert!(matches!(
            &f.body[3],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_18"
        ));
    }

    #[test]
    fn a_loop_carried_stack_pointer_is_not_frozen_at_one_iteration() {
        let cursor = reg("cursor#1");
        let next = reg("next#1");
        let mut f = Function {
            name: "loop_cursor".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: cursor.clone(),
                    src: lea("rsp", -64),
                },
                Stmt::While {
                    cond: Expr::Const(1),
                    body: vec![
                        Stmt::Store {
                            addr: Expr::Lea {
                                base: Some(cursor.clone()),
                                index: None,
                                scale: 1,
                                disp: 0,
                                segment: None,
                            },
                            src: Expr::Const(7),
                            size: 4,
                        },
                        Stmt::Assign {
                            dst: next.clone(),
                            src: Expr::Bin {
                                op: crate::ir::types::BinOp::Add,
                                lhs: Box::new(Expr::Reg(cursor.clone())),
                                rhs: Box::new(Expr::Const(4)),
                            },
                        },
                        Stmt::Store {
                            addr: Expr::Lea {
                                base: Some(next.clone()),
                                index: None,
                                scale: 1,
                                disp: 0,
                                segment: None,
                            },
                            src: Expr::Const(9),
                            size: 4,
                        },
                        Stmt::Assign {
                            dst: cursor.clone(),
                            src: Expr::Reg(next.clone()),
                        },
                    ],
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::While { body, .. } = &f.body[1] else {
            panic!("expected loop: {:#?}", f.body);
        };
        assert!(
            matches!(
                &body[0],
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(actual),
                        disp: 0,
                        ..
                    },
                    ..
                } if actual == &cursor
            ),
            "loop-varying cursor must remain an indirect store: {:#?}",
            f.body
        );
        assert!(
            matches!(
                &body[2],
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(actual),
                        disp: 0,
                        ..
                    },
                    ..
                } if actual == &next
            ),
            "an alias derived from the loop cursor must also remain indirect: {:#?}",
            f.body
        );
    }

    #[test]
    fn a_goto_after_an_epilogue_keeps_the_target_frame_depth() {
        let adjust = |op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(40)),
            },
        };
        let mut f = Function {
            name: "optimized_recursive_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Push {
                    value: Expr::Reg(reg("rbx")),
                },
                adjust(crate::ir::types::BinOp::Sub),
                Stmt::Store {
                    addr: lea("rsp", 24),
                    src: Expr::Reg(reg("rax")),
                    size: 8,
                },
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![Stmt::Goto { target: 0x1680 }],
                    else_body: None,
                },
                adjust(crate::ir::types::BinOp::Add),
                Stmt::Pop { target: reg("rbx") },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
                Stmt::Label(0x1680),
                Stmt::Store {
                    addr: lea("rsp", 24),
                    src: Expr::Reg(reg("rdi")),
                    size: 8,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count(&mut f, Some(CallConv::SysVAmd64), Some(2));

        let first = match &f.body[2] {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } => name,
            other => panic!("expected promoted first store, got {other:?}"),
        };
        let target = match &f.body[8] {
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } => name,
            other => panic!("expected promoted target store, got {other:?}"),
        };
        assert_eq!(first, target);
    }

    #[test]
    fn address_alias_after_an_epilogue_target_keeps_the_target_frame_depth() {
        let adjust = |amount, op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(amount)),
            },
        };
        let frame_address = reg("rcx#1");
        let mut f = Function {
            name: "optimized_outgoing_address".into(),
            entry_va: 0,
            body: vec![
                adjust(32, crate::ir::types::BinOp::Sub),
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![Stmt::Goto { target: 0x1680 }],
                    else_body: None,
                },
                adjust(32, crate::ir::types::BinOp::Add),
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
                Stmt::Label(0x1680),
                Stmt::Assign {
                    dst: frame_address.clone(),
                    src: lea("rsp", 16),
                },
                adjust(8, crate::ir::types::BinOp::Sub),
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(frame_address),
                    size: 8,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(
            matches!(
                &f.body[7],
                Stmt::Store {
                    src: Expr::StackAddr {
                        object: VReg::Phys(name),
                        ..
                    },
                    ..
                } if name == "local_10"
            ),
            "target-frame address alias was misclassified: {:#?}",
            f.body
        );
    }

    #[test]
    fn a_returning_if_arm_does_not_poison_the_fallthrough_stack_state() {
        let adjust = |op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(32)),
            },
        };
        let mut f = Function {
            name: "early_return_frame".into(),
            entry_va: 0,
            body: vec![
                adjust(crate::ir::types::BinOp::Sub),
                Stmt::Store {
                    addr: lea("rsp", 8),
                    src: Expr::Reg(reg("rdi")),
                    size: 4,
                },
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![
                        adjust(crate::ir::types::BinOp::Add),
                        Stmt::Return {
                            value: Some(Expr::Const(0)),
                        },
                    ],
                    else_body: None,
                },
                Stmt::Label(0x1010),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rsp", 8, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[4],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_18"
        ));
    }

    #[test]
    fn callee_saved_pushes_are_normalized_before_mapping_stack_arguments() {
        // Clang -O2 `sum_arg8` pushes rbx, then reads a6 from [rsp+16] and a7
        // from [rsp+24]. GCC `sum_arg10` has the same shape with rbp. The
        // current rsp is entry_rsp-8, so those addresses are entry_rsp+8 and
        // entry_rsp+16 respectively.
        let mut f = Function {
            name: "sum_arg8".into(),
            entry_va: 0,
            body: vec![
                Stmt::Push {
                    value: Expr::Reg(reg("rbx")),
                },
                Stmt::Assign {
                    dst: reg("r10"),
                    src: deref_of("rsp", 16, 4),
                },
                Stmt::Assign {
                    dst: reg("r11"),
                    src: deref_of("rsp", 24, 4),
                },
                Stmt::Pop { target: reg("rbx") },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg6"
        ));
        assert!(matches!(
            &f.body[2],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "arg7"
        ));
    }

    #[test]
    fn aarch64_stacked_arguments_start_after_eight_registers() {
        let cc = Some(CallConv::Aarch64);
        assert_eq!(promoted("x29", 16, cc), "arg8");
        assert_eq!(promoted("x29", 24, cc), "arg9");
    }

    #[test]
    fn arm_frame_pointer_snapshot_promotes_sp_relative_locals() {
        use crate::ir::types::BinOp;

        // GCC Cortex-M -O0 frame from DecBench's real `console_getc`:
        //
        //   push {r7}; sub sp, #20; mov r7, sp
        //   str r0, [r7, #4]; strb ..., [r7, #15]
        //
        // r7 is an SSA snapshot of the adjusted stack pointer, not a general
        // address. The two accesses are entry_sp-20 and entry_sp-9 and must
        // retain that stable source-storage identity throughout the function.
        let mut f = Function {
            name: "console_getc".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: lea("sp", 0),
                    src: Expr::Reg(reg("r7")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(20)),
                    },
                },
                Stmt::Assign {
                    dst: reg("r7#1"),
                    src: Expr::Reg(reg("sp")),
                },
                Stmt::Store {
                    addr: lea("r7#1", 4),
                    src: Expr::Reg(reg("r0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("r7#1", 15),
                    src: Expr::Const(0),
                    size: 1,
                },
                Stmt::Assign {
                    dst: reg("r3#1"),
                    src: deref_of("r7#1", 15, 1),
                },
                Stmt::Return { value: None },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::Arm));

        assert!(matches!(
            &f.body[4],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_14"
        ));
        assert!(matches!(
            &f.body[5],
            Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_9"
        ));
        assert!(matches!(
            &f.body[6],
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "local_9"
        ));
        assert_eq!(sizes.get("local_14"), Some(&4));
        assert_eq!(sizes.get("local_9"), Some(&1));
    }

    #[test]
    fn frame_locals_and_return_address_slots_are_unaffected() {
        let cc = Some(CallConv::SysVAmd64);
        // Negative frame offsets are the function's own locals.
        assert_eq!(promoted("rbp", -0xc, cc), "local_c");
        // Below the first stacked-argument slot ([rbp+8] is the return address).
        assert_eq!(promoted("rbp", 8, cc), "stack_0");
    }

    #[test]
    fn a_frame_pointer_omitted_frame_slot_is_still_named_by_its_offset() {
        let cc = Some(CallConv::SysVAmd64);
        // `-O2` omits the frame pointer, so the function's own slots are
        // addressed below the ENTRY stack pointer instead of below `rbp`. They
        // are the same storage class and carry the same recovered offset, so
        // they get the same offset-bearing name rather than `stack_N`.
        let mut f = Function {
            name: "no_frame_pointer".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(0x20)),
                    },
                },
                // [rsp+8] with rsp = entry_rsp-0x20 is entry_rsp-0x18.
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rsp", 8, 4),
                },
            ],
        };
        promote_stack_locals_typed(&mut f, cc);
        assert!(
            matches!(
                &f.body[1],
                Stmt::Assign {
                    src: Expr::Reg(VReg::Phys(name)),
                    ..
                } if name == "local_18"
            ),
            "{:?}",
            f.body[1]
        );
        // At or above the entry stack pointer is the caller's territory (return
        // address, stacked arguments, outgoing-argument scratch) and keeps the
        // conservative appearance-order name.
        assert_eq!(promoted("rbp", 8, cc), "stack_0");
    }

    #[test]
    fn two_frame_anchors_at_the_same_offset_get_distinct_names() {
        // `rbp-0x10` and `entry_rsp-0x10` are different storage. Both want the
        // name `local_10`; only one may have it, or the two slots would be
        // spliced into a single variable.
        let mut f = Function {
            name: "two_anchors".into(),
            entry_va: 0,
            body: vec![
                Stmt::Push {
                    value: Expr::Reg(reg("rbp")),
                },
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(0x30)),
                    },
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rbp", -0x10, 4),
                },
                // rsp is entry_rsp-0x38 here, so [rsp+0x28] is entry_rsp-0x10.
                Stmt::Assign {
                    dst: reg("ecx"),
                    src: deref_of("rsp", 0x28, 4),
                },
            ],
        };
        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));
        let name_of = |index: usize| match &f.body[index] {
            Stmt::Assign {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } => name.clone(),
            other => panic!("expected a promoted register, got {other:?}"),
        };
        let (first, second) = (name_of(3), name_of(4));
        assert_ne!(first, second, "distinct slots must not share a name");
        assert!(
            first == "local_10" || second == "local_10",
            "one anchor keeps the offset-bearing name: {first} / {second}"
        );
    }

    #[test]
    fn an_abi_we_do_not_model_keeps_the_conservative_name() {
        // Win64's 32-byte shadow space still has no layout model here. Guessing
        // at that ABI would invent a parameter that does not exist, so it and
        // unknown conventions keep `stack_N`.
        assert_eq!(promoted("rbp", 16, Some(CallConv::Win64)), "stack_0");
        assert_eq!(promoted("rbp", 16, None), "stack_0");
    }

    #[test]
    fn a_misaligned_positive_offset_is_not_an_argument_slot() {
        // Stacked arguments are 8-aligned from the first slot; anything else is not
        // an argument (it could be a field of a by-value struct).
        assert_eq!(promoted("rbp", 20, Some(CallConv::SysVAmd64)), "stack_0");
    }

    #[test]
    fn load_of_stack_slot_becomes_named_local() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rsp", 0x158, 8),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("stack_0")));
        }
    }

    #[test]
    fn indexed_frame_arrays_share_storage_with_constant_initializers() {
        let mut f = Function {
            name: "bfs_shape".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -32),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Store {
                    addr: lea("rbp", -24),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: indexed_deref("rbp", "head", 4, -96, 4),
                },
                Stmt::Assign {
                    dst: reg("ecx"),
                    src: indexed_deref("rbp", "next", 1, -32, 1),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Store { addr: zero0, .. } = &f.body[0] else {
            panic!("expected first initializer");
        };
        let Stmt::Store { addr: zero8, .. } = &f.body[1] else {
            panic!("expected second initializer");
        };
        assert_eq!(
            zero0,
            &Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }
        );
        assert!(matches!(
            zero8,
            Expr::Bin { lhs, rhs, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 } if object == &reg("local_20"))
                    && rhs.as_ref() == &Expr::Const(8)
        ));
        assert!(matches!(
            &f.body[2],
            Stmt::Assign {
                src: Expr::Deref { addr, size: 4 },
                ..
            } if matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 64 } if object == &reg("local_60")))
        ));
        assert!(matches!(
            &f.body[3],
            Stmt::Assign {
                src: Expr::Deref { addr, size: 1 },
                ..
            } if matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 } if object == &reg("local_20")))
        ));
    }

    #[test]
    fn dynamic_stack_object_slice_passed_to_a_call_keeps_object_identity() {
        let mut f = Function {
            name: "merge_copy_shape".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("eax"),
                    src: indexed_deref("rbp", "read_index", 4, -64, 4),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "memcpy".into(),
                    },
                    args: vec![Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Bin {
                            op: crate::ir::types::BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("rbp"))),
                            rhs: Box::new(Expr::Bin {
                                op: crate::ir::types::BinOp::Mul,
                                lhs: Box::new(Expr::Reg(reg("write_index"))),
                                rhs: Box::new(Expr::Const(4)),
                            }),
                        }),
                        rhs: Box::new(Expr::Const(-32)),
                    }],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call: {f:#?}");
        };
        assert!(
            matches!(
                args.as_slice(),
                [Expr::Bin { lhs, .. }]
                    if matches!(lhs.as_ref(), Expr::StackAddr { size: 32, .. })
            ),
            "dynamic call argument lost its stack object: {f:#?}"
        );
    }

    #[test]
    fn adjacent_indexed_stack_views_with_one_element_bias_share_storage() {
        let mut f = Function {
            name: "biased_merge_buffer".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rbp")),
                        index: Some(reg("write_index")),
                        scale: 4,
                        disp: -36,
                        segment: None,
                    },
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "memcpy".into(),
                    },
                    args: vec![Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Bin {
                            op: crate::ir::types::BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("rbp"))),
                            rhs: Box::new(Expr::Bin {
                                op: crate::ir::types::BinOp::Mul,
                                lhs: Box::new(Expr::Reg(reg("read_index"))),
                                rhs: Box::new(Expr::Const(4)),
                            }),
                        }),
                        rhs: Box::new(Expr::Const(-32)),
                    }],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Store { addr, .. } = &f.body[0] else {
            panic!("expected store: {f:#?}");
        };
        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call: {f:#?}");
        };
        let Expr::Bin {
            lhs: store_object, ..
        } = addr
        else {
            panic!("expected indexed object store: {f:#?}");
        };
        let [Expr::Bin {
            lhs: call_object, ..
        }] = args.as_slice()
        else {
            panic!("expected indexed object call argument: {f:#?}");
        };
        assert_eq!(
            store_object, call_object,
            "biased indexed views of one stack array were split: {f:#?}"
        );
    }

    #[test]
    fn stack_address_alias_in_sib_index_position_is_still_an_object() {
        let holder = reg("r8#1");
        let mut f = Function {
            name: "commuted_address".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(104)),
                    },
                },
                Stmt::Assign {
                    dst: holder.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(64)),
                    },
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("next")),
                            index: Some(holder),
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 1,
                    },
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::StackAddr { size: 40, .. },
                ..
            }
        ));
        assert!(matches!(
            &f.body[2],
            Stmt::Assign {
                src: Expr::Deref { addr, size: 1 },
                ..
            } if matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { size: 40, .. }))
        ));
    }

    #[test]
    fn copied_stack_base_unifies_a_contiguous_initialized_array() {
        let mut body = vec![Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(152)),
            },
        }];
        body.extend((0..16).map(|index| Stmt::Store {
            addr: lea("rsp", index * 4),
            src: Expr::Const(0),
            size: 4,
        }));
        // A neighboring indexed object supplies the hard boundary at +64.
        body.push(Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("rsp")),
                index: Some(reg("queue_index")),
                scale: 4,
                disp: 64,
                segment: None,
            },
            src: Expr::Const(1),
            size: 4,
        });
        body.push(Stmt::Assign {
            dst: reg("cursor"),
            src: Expr::Reg(reg("rsp")),
        });
        let mut f = Function {
            name: "topological_sort_shape".into(),
            entry_va: 0,
            body,
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(
            matches!(
                f.body.last(),
                Some(Stmt::Assign {
                    src: Expr::StackAddr { size: 64, .. },
                    ..
                })
            ),
            "the copied stack base must name the whole initialized array: {f:#?}"
        );
        let root = match f.body.last() {
            Some(Stmt::Assign {
                src: Expr::StackAddr { object, .. },
                ..
            }) => object,
            _ => unreachable!(),
        };
        assert!(
            matches!(
                &f.body[2],
                Stmt::Store {
                    addr: Expr::Bin { lhs, rhs, .. },
                    ..
                } if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 64 } if object == root)
                    && rhs.as_ref() == &Expr::Const(4)
            ),
            "the second initializer must alias byte offset four of the object: {f:#?}"
        );
    }

    #[test]
    fn store_to_stack_slot_becomes_named_local_on_lhs() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Store {
                addr: lea("rsp", 0x10),
                src: Expr::Reg(reg("rax")),
                size: 8,
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Store { addr, src, .. } = &f.body[0] {
            assert_eq!(*addr, Expr::Reg(reg("stack_0")));
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn same_slot_reused_gets_same_name() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", 0x10),
                    src: Expr::Const(1),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", 0x10, 8),
                },
            ],
        };
        promote_stack_locals(&mut f);
        let names: Vec<_> = f
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Store { addr, .. } => Some(addr.clone()),
                Stmt::Assign { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names[0], Expr::Reg(reg("stack_0")));
        assert_eq!(names[1], Expr::Reg(reg("stack_0")));
    }

    #[test]
    fn different_slots_get_distinct_names() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", 0x10),
                    src: Expr::Const(1),
                    size: 8,
                },
                Stmt::Store {
                    addr: lea("rsp", 0x18),
                    src: Expr::Const(2),
                    size: 8,
                },
            ],
        };
        promote_stack_locals(&mut f);
        let addrs: Vec<_> = f
            .body
            .iter()
            .filter_map(|s| match s {
                Stmt::Store { addr, .. } => Some(addr.clone()),
                _ => None,
            })
            .collect();
        assert_ne!(addrs[0], addrs[1]);
    }

    #[test]
    fn frame_pointer_negative_offsets_get_local_prefix() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rbp", -0x8, 4),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            // Named by frame offset (Ghidra/IDA convention): `[rbp-0x8]` -> `local_8`.
            assert_eq!(*src, Expr::Reg(reg("local_8")));
        }
    }

    #[test]
    fn same_slot_read_and_write_share_one_local_name() {
        // A store to and a load from the same frame slot must resolve to a
        // single local (its def/use chain stays intact), even though the store
        // path can't see the access width.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0xc),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", -0xc, 4),
                },
            ],
        };
        promote_stack_locals(&mut f);
        let store_name = match &f.body[0] {
            Stmt::Store { addr, .. } => addr.clone(),
            _ => panic!("expected store"),
        };
        let load_name = match &f.body[1] {
            Stmt::Assign { src, .. } => src.clone(),
            _ => panic!("expected assign"),
        };
        assert_eq!(store_name, Expr::Reg(reg("local_c")));
        assert!(matches!(
            load_name,
            Expr::Cast {
                signed: false,
                width: 4,
                expr,
            } if matches!(expr.as_ref(), Expr::Bin { lhs, .. }
                if matches!(lhs.as_ref(), Expr::Cast {
                    signed: false,
                    width: 8,
                    expr,
                } if expr.as_ref() == &Expr::Reg(reg("local_c"))))
        ));
    }

    #[test]
    fn narrow_reads_of_a_wide_spill_keep_the_parent_storage_width() {
        // Both Clang and GCC spill a uint32_t call result and then read its
        // low word and low byte through a union.  Shrinking the declaration to
        // the narrowest read discards the other three bytes before those views
        // are evaluated.
        let mut f = Function {
            name: "payload_head".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0x40),
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("ecx"),
                    src: deref_of("rbp", -0x40, 2),
                },
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("rbp", -0x40, 1),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert_eq!(sizes.get("local_40"), Some(&4), "{f:#?}");
        for (statement, width) in f.body[1..].iter().zip([2, 1]) {
            assert!(
                matches!(
                    statement,
                    Stmt::Assign {
                        src: Expr::Cast {
                            signed: false,
                            width: got,
                            expr,
                        },
                        ..
                    } if *got == width
                        && matches!(expr.as_ref(), Expr::Bin { lhs, .. }
                            if matches!(lhs.as_ref(), Expr::Cast {
                                signed: false,
                                width: 8,
                                expr,
                            } if matches!(expr.as_ref(), Expr::Reg(name) if name == &reg("local_40"))))
                ),
                "missing {width}-byte view: {statement:#?}"
            );
        }
    }

    #[test]
    fn lea_call_argument_becomes_address_of_the_same_recovered_object() {
        let mut f = Function {
            name: "construct".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "Widget::Widget".into(),
                    },
                    args: vec![lea("rbp", -0x20)],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rbp", -0x20, 4),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
        assert!(matches!(
            &f.body[1],
            Stmt::Assign {
                src: Expr::Deref { addr, size: 4 },
                ..
            } if matches!(addr.as_ref(), Expr::StackAddr {
                object,
                size: 32,
            } if object == &reg("local_20"))
        ));
        assert_eq!(sizes.get("local_20"), Some(&8));
    }

    #[test]
    fn address_taken_object_stops_at_the_next_known_frame_slot() {
        // Clang -O0 places an eight-byte decoded header at rbp-0x20, while
        // the original length argument starts at rbp-0x14.  Reserving all the
        // way to rbp would absorb that argument (and the saved input pointer)
        // into the output object, turning later reads into uninitialised field
        // accesses.  A preceding observed slot is a hard upper boundary.
        let mut f = Function {
            name: "decode".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0x14),
                    src: Expr::Reg(reg("esi")),
                    size: 4,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "decode_header".into(),
                    },
                    args: vec![lea("rbp", -0x20)],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rbp", -0x14, 4),
                },
                Stmt::Assign {
                    dst: reg("ecx"),
                    src: deref_of("rbp", -0x1a, 2),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call");
        };
        assert!(
            matches!(args.as_slice(), [Expr::StackAddr {
            object,
            size: 12,
        }] if object == &reg("local_20")),
            "{f:#?}"
        );
        assert!(
            matches!(
                &f.body[2],
                Stmt::Assign { src: Expr::Reg(name), .. } if name == &reg("local_14")
            ),
            "the adjacent argument was absorbed into the object: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[3],
                Stmt::Assign {
                    src: Expr::Deref { addr, size: 2 },
                    ..
                } if matches!(addr.as_ref(), Expr::Bin { lhs, rhs, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 12 }
                        if object == &reg("local_20"))
                        && matches!(rhs.as_ref(), Expr::Const(6)))
            ),
            "the decoded-header field lost object identity: {f:#?}"
        );
    }

    #[test]
    fn reconstructed_frame_arithmetic_call_argument_becomes_stack_object_address() {
        let mut f = Function {
            name: "construct_after_expression_reconstruction".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Addr(0x1000),
                args: vec![Expr::Bin {
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rbp"))),
                    rhs: Box::new(Expr::Const(32)),
                }],
                dst: None,
                call_spec: None,
            }],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[0] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
        assert_eq!(sizes.get("local_20"), Some(&8));
    }

    #[test]
    fn repurposed_rbp_value_is_not_promoted_as_a_stack_object_address() {
        let value = Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(Expr::Reg(reg("rbp"))),
            rhs: Box::new(Expr::Const(2)),
        };
        let mut f = Function {
            name: "optimized_caller".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("rsi"))),
                    },
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x1000,
                        name: "callee".into(),
                    },
                    args: vec![value.clone()],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call: {f:#?}");
        };
        assert_eq!(args, &[value]);
        assert!(
            sizes.is_empty(),
            "repurposed rbp invented locals: {sizes:?}"
        );
    }

    #[test]
    fn stack_address_definition_reaching_a_call_is_materialised() {
        // GCC -O0 computes `rax#4 = rbp - 32`, then argument reconstruction
        // passes `rax#4` to the constructor. The address-producing definition
        // is not adjacent to the call, so ordinary expression reconstruction
        // deliberately leaves it statement-rooted.
        let address = reg("rax#4");
        let mut f = Function {
            name: "construct_via_value".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: address.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Reg(address)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
    }

    #[test]
    fn stack_address_stored_in_a_closure_keeps_the_pointee_object() {
        // GCC/Clang -O0 lower a by-reference lambda capture as:
        //   [rbp-0x28] = 0; rax = rbp-0x28; [rbp-0x18] = rax
        // The address escape is a memory-store value, not a direct call
        // argument. Every access to rbp-0x28 must nevertheless use the same C
        // object before and after the pointer is installed in the closure.
        let address = reg("rax#4");
        let mut f = Function {
            name: "capture_by_reference".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0x28),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("rbp", -0x20),
                    src: Expr::Reg(reg("edi")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: address.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(0x28)),
                    },
                },
                Stmt::Store {
                    addr: lea("rbp", -0x18),
                    src: Expr::Reg(address),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("rbp", -0x28, 4),
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(
            matches!(
                &f.body[0],
                Stmt::Store {
                    addr: Expr::StackAddr { object, size: 8 },
                    ..
                } if object == &reg("local_28")
            ),
            "initializer lost the captured object's identity: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[3],
                Stmt::Store {
                    addr: Expr::Reg(destination),
                    src: Expr::StackAddr { object, size: 8 },
                    size: 8,
                } if destination == &reg("local_18") && object == &reg("local_28")
            ),
            "closure field did not receive &local_28: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[4],
                Stmt::Assign {
                    src: Expr::Deref { addr, size: 4 },
                    ..
                } if matches!(addr.as_ref(), Expr::StackAddr { object, size: 8 }
                    if object == &reg("local_28"))
            ),
            "post-call read lost the captured object's identity: {f:#?}"
        );
    }

    #[test]
    fn interior_stack_address_stored_as_a_value_keeps_its_byte_offset() {
        // GCC -O0 materialises `(long)(local + 1)` through two SSA values:
        //   rax#6 = rbp - 12; rax#7 = rax#6 + 1; [rbp-12] = rax#7
        // The store proves that the source is an escaped stack address, but it
        // must not collapse the interior pointer back to the object's base.
        let base = reg("rax#6");
        let advanced = reg("rax#7");
        let mut f = Function {
            name: "store_advanced_stack_address".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -8),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Assign {
                    dst: base.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(12)),
                    },
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Reg(base.clone())],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: advanced.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(base)),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Store {
                    addr: lea("rbp", -12),
                    src: Expr::Reg(advanced),
                    size: 4,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(
            matches!(
                &f.body[4],
                Stmt::Store {
                    src: Expr::Bin { op: crate::ir::types::BinOp::Add, lhs, rhs },
                    ..
                } if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 4 }
                    if object == &reg("local_c"))
                    && rhs.as_ref() == &Expr::Const(1)
            ),
            "escaped interior address lost its byte offset: {f:#?}"
        );
    }

    /// `sub $N,%rsp` and nothing else: the ordinary `-O2` frame-pointer-omitted
    /// prologue.
    fn frame_prologue(bytes: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(bytes)),
            },
        }
    }

    fn frame_pointer_omitted_prologue() -> Stmt {
        frame_prologue(56)
    }

    /// `int32_t a[8]` at CFA-64, which the SysV front end spells `rbp-48`.
    fn cfa_relative_array_hint() -> [StackObjectHint; 1] {
        [StackObjectHint {
            base: "rbp".into(),
            disp: -48,
            size: 32,
            aggregate: true,
            source_name: Some("a".into()),
            c_type: Some("int32_t[]".into()),
            cfa_relative: true,
        }]
    }

    /// Two adjacent proven arrays, as `23_topological_sort` has them: DWARF
    /// puts `indegree[16]` at the entry coordinate -160 and `queue[16]`
    /// directly above it at -96.
    fn two_adjacent_proven_arrays() -> [StackObjectHint; 2] {
        [
            StackObjectHint {
                base: "rbp".into(),
                disp: -152,
                size: 64,
                aggregate: true,
                source_name: Some("indegree".into()),
                c_type: Some("int32_t[]".into()),
                cfa_relative: true,
            },
            StackObjectHint {
                base: "rbp".into(),
                disp: -88,
                size: 64,
                aggregate: true,
                source_name: Some("queue".into()),
                c_type: Some("int32_t[]".into()),
                cfa_relative: true,
            },
        ]
    }

    #[test]
    fn a_biased_base_in_the_previous_array_still_reaches_the_one_it_walks() {
        // `queue[head++]` is addressed `0x58(%esp,%edi,4)` with `%edi` starting
        // at one — the same one-element bias as merge_sort, except that here the
        // element below `queue` is the LAST element of the adjacent `indegree`.
        // Containment therefore matches, and matches the wrong array: every
        // dynamic address the sequence produces is in `queue`, and only the base
        // byte is in `indegree`. This is what took
        // `23_topological_sort:i386:O2` from pass to fail.
        let mut f = Function {
            name: "kahn".into(),
            entry_va: 0,
            body: vec![
                frame_prologue(160),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: Some(reg("rdi")),
                            scale: 4,
                            disp: 60,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &two_adjacent_proven_arrays(),
        );

        assert!(
            matches!(&f.body[1], Stmt::Assign { src: Expr::Deref { addr, .. }, .. }
                if matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, .. }
                        if object == &reg("local_60")))),
            "biased subscript was claimed by the array below the one it walks: {f:#?}"
        );
    }

    #[test]
    fn an_unbiased_indexed_access_keeps_the_array_it_starts_in() {
        // CONTROL for the rule above: the same two arrays, and an access whose
        // base IS `indegree`'s own start. Nothing is biased here, and the
        // sequence must stay in `indegree`.
        let mut f = Function {
            name: "count".into(),
            entry_va: 0,
            body: vec![
                frame_prologue(160),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: Some(reg("rdi")),
                            scale: 4,
                            disp: 0,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &two_adjacent_proven_arrays(),
        );

        assert!(
            matches!(&f.body[1], Stmt::Assign { src: Expr::Deref { addr, .. }, .. }
                if matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, .. }
                        if object == &reg("local_a0")))),
            "an unbiased access was redirected to the next array: {f:#?}"
        );
    }

    #[test]
    fn a_one_element_object_indexed_at_its_own_start_is_not_handed_to_its_neighbour() {
        // The narrow CONTROL for the second half of the rule. A proven object
        // exactly one element wide is escaped by its own second element, so the
        // "leaves by the second element" test alone would give it away to
        // whatever starts at its end. A base sitting ON an object is that object
        // being addressed, not a bias, and the `disp > start` clause says so.
        let hints = [
            StackObjectHint {
                base: "rbp".into(),
                disp: -152,
                size: 4,
                aggregate: true,
                source_name: Some("one".into()),
                c_type: Some("int32_t[]".into()),
                cfa_relative: true,
            },
            StackObjectHint {
                base: "rbp".into(),
                disp: -148,
                size: 64,
                aggregate: true,
                source_name: Some("many".into()),
                c_type: Some("int32_t[]".into()),
                cfa_relative: true,
            },
        ];
        let mut f = Function {
            name: "single".into(),
            entry_va: 0,
            body: vec![
                frame_prologue(160),
                Stmt::Assign {
                    dst: reg("eax"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("rsp")),
                            index: Some(reg("rdi")),
                            scale: 4,
                            disp: 0,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &hints,
        );

        assert!(
            matches!(&f.body[1], Stmt::Assign { src: Expr::Deref { addr, .. }, .. }
                if matches!(addr.as_ref(), Expr::StackAddr { object, .. }
                    if object == &reg("local_a0"))
                || matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, .. }
                        if object == &reg("local_a0")))),
            "a one-element object gave itself away to its neighbour: {f:#?}"
        );
    }

    #[test]
    fn an_indexed_access_biased_one_element_low_still_reaches_the_proven_object() {
        // gcc reaches `int32_t temp[16]` at `rsp+0x30` as
        // `0x2c(%rsp) + (out+1)*4` — the base one element low, the subscript one
        // element high. Here the proven array is at `entry_rsp-56` in a 64-byte
        // frame, so the store's constant part resolves to `entry_rsp-60` and no
        // object CONTAINS it. Inventing a second array under the proven one is
        // what took `24_merge_sort:gcc:O2:merge_sort_i32` from pass to fail.
        let mut f = Function {
            name: "biased_fill".into(),
            entry_va: 0,
            body: vec![
                frame_prologue(64),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: Some(reg("rcx")),
                        scale: 4,
                        disp: 4,
                        segment: None,
                    },
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &cfa_relative_array_hint(),
        );

        assert!(
            matches!(&f.body[1], Stmt::Store { addr: Expr::Bin { lhs, rhs, .. }, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 }
                    if object == &reg("local_38"))
                    && matches!(rhs.as_ref(), Expr::Bin { rhs: bias, .. }
                        if bias.as_ref() == &Expr::Const(-4))),
            "biased subscript did not reach the proven array: {f:#?}"
        );
    }

    #[test]
    fn a_cfa_object_reaches_a_body_that_omits_the_frame_pointer() {
        // `mov 0xc(%rsp),%edx` reads `a[3]` of an array the caller's CFA places
        // at `rsp+0`. Without the rebase the proven extent sits at `rbp-48`,
        // which this body never forms, and the read becomes a bare scalar that
        // the array's own initialising loop never appears to define.
        let mut f = Function {
            name: "alias_control".into(),
            entry_va: 0,
            body: vec![
                frame_pointer_omitted_prologue(),
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("rsp", 0xc, 4),
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &cfa_relative_array_hint(),
        );

        assert!(
            matches!(
                &f.body[1],
                Stmt::Assign { src: Expr::Deref { addr, size: 4 }, .. }
                    if matches!(addr.as_ref(), Expr::Bin { lhs, rhs, .. }
                        if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 }
                            if object == &reg("local_38"))
                            && rhs.as_ref() == &Expr::Const(12))
            ),
            "interior read did not reach the rebased CFA object: {f:#?}"
        );
    }

    #[test]
    fn a_cfa_object_is_left_alone_when_the_frame_pointer_is_established() {
        // The same hint against `push %rbp; mov %rsp,%rbp`. Here `rbp-48` is a
        // coordinate the body really forms, and rebasing it would move a
        // correct object 8 bytes down.
        let mut f = Function {
            name: "framed".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("rbp", -36, 4),
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &cfa_relative_array_hint(),
        );

        assert!(
            matches!(
                &f.body[1],
                Stmt::Assign { src: Expr::Deref { addr, size: 4 }, .. }
                    if matches!(addr.as_ref(), Expr::Bin { lhs, rhs, .. }
                        if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 }
                            if object == &reg("local_30"))
                            && rhs.as_ref() == &Expr::Const(12))
            ),
            "an established frame pointer's object moved: {f:#?}"
        );
    }

    #[test]
    fn a_base_register_object_is_never_rebased() {
        // `DW_OP_breg6` names `rbp` outright. Even where the prologue detector
        // sees no establishment, that coordinate came from the producer and is
        // not ours to move.
        let mut f = Function {
            name: "breg".into(),
            entry_va: 0,
            body: vec![
                frame_pointer_omitted_prologue(),
                Stmt::Assign {
                    dst: reg("edx"),
                    src: deref_of("rbp", -36, 4),
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            ..cfa_relative_array_hint()[0].clone()
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &hints,
        );

        assert!(
            matches!(
                &f.body[1],
                Stmt::Assign { src: Expr::Deref { addr, size: 4 }, .. }
                    if matches!(addr.as_ref(), Expr::Bin { lhs, rhs, .. }
                        if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 }
                            if object == &reg("local_30"))
                            && rhs.as_ref() == &Expr::Const(12))
            ),
            "a base-register object was rebased: {f:#?}"
        );
    }

    #[test]
    fn an_indexed_access_inside_a_proven_object_does_not_seed_a_second_one() {
        // `nodes[i].next` is an indexed access eight bytes into the array. Left
        // to itself the indexed heuristic partitions from THERE to the frame
        // base, giving one piece of storage two overlapping C arrays — and the
        // recompiled C then allocates them apart.
        let mut f = Function {
            name: "link".into(),
            entry_va: 0,
            body: vec![
                frame_pointer_omitted_prologue(),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: Some(reg("rcx")),
                        scale: 16,
                        disp: 8,
                        segment: None,
                    },
                    src: Expr::Const(0),
                    size: 8,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &cfa_relative_array_hint(),
        );

        assert!(
            matches!(
                &f.body[1],
                Stmt::Store { addr: Expr::Bin { lhs, .. }, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 }
                        if object == &reg("local_38"))
            ),
            "indexed store seeded a second object beside the proven one: {f:#?}"
        );
    }

    #[test]
    fn a_proven_object_admits_a_loop_bound_one_past_its_end() {
        // `lea 0x20(%rsp),%rdx` is `&a[8]`, the bound of the loop that fills
        // `a`. The address exists in C; a DEREFERENCE there still does not.
        let mut f = Function {
            name: "fill".into(),
            entry_va: 0,
            body: vec![
                frame_pointer_omitted_prologue(),
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: lea("rsp", 32),
                },
                Stmt::Assign {
                    dst: reg("ecx"),
                    src: deref_of("rsp", 32, 4),
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &cfa_relative_array_hint(),
        );

        assert!(
            matches!(&f.body[1], Stmt::Assign { src: Expr::Bin { lhs, rhs, .. }, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 32 }
                    if object == &reg("local_38"))
                    && rhs.as_ref() == &Expr::Const(32)),
            "end pointer did not reach the object it bounds: {f:#?}"
        );
        assert!(
            !matches!(&f.body[2], Stmt::Assign { src: Expr::Deref { addr, .. }, .. }
                if matches!(addr.as_ref(), Expr::Bin { lhs, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { .. }))),
            "a read one past the end was admitted: {f:#?}"
        );
    }

    #[test]
    fn an_address_one_past_the_end_handed_to_a_callee_is_not_absorbed() {
        // CONTROL for the rule above. `Movable b` sits directly above
        // `Movable a` at `-O0`, and its constructor takes its address — which
        // is `&a + sizeof a`. Reading that as an interior offset of `a` makes
        // the recompiled C write past `a`'s end, and it did:
        // `10_cpp_runtime_shapes:gcc:O0:cpp_move` went pass -> fail.
        let mut f = Function {
            name: "construct_neighbour".into(),
            entry_va: 0,
            body: vec![
                frame_pointer_omitted_prologue(),
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![lea("rsp", 32)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &cfa_relative_array_hint(),
        );

        let Stmt::Call { args, .. } = &f.body[1] else {
            panic!("call statement disappeared: {f:#?}");
        };
        assert!(
            !matches!(&args[0], Expr::Bin { lhs, .. }
                if matches!(lhs.as_ref(), Expr::StackAddr { object, .. }
                    if object == &reg("local_38"))),
            "the neighbouring object was absorbed into the proven one: {f:#?}"
        );
    }

    #[test]
    fn debug_aggregate_extent_unifies_closure_fields() {
        let mut f = Function {
            name: "invoke_closure".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0x20),
                    src: Expr::Reg(reg("edi")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("rbp", -0x18),
                    src: Expr::Reg(reg("rax")),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![lea("rbp", -0x20)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "rbp".into(),
            disp: -0x20,
            size: 16,
            aggregate: true,
            source_name: None,
            c_type: None,
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::SysVAmd64),
            None,
            &hints,
        );

        assert!(
            matches!(
                &f.body[0],
                Stmt::Store {
                    addr: Expr::StackAddr { object, size: 16 },
                    ..
                } if object == &reg("local_20")
            ),
            "first closure field escaped the aggregate: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[1],
                Stmt::Store { addr: Expr::Bin { lhs, rhs, .. }, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 16 }
                        if object == &reg("local_20"))
                        && rhs.as_ref() == &Expr::Const(8)
            ),
            "second closure field did not alias offset eight: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[2],
                Stmt::Call { args, .. }
                    if matches!(args.as_slice(), [Expr::StackAddr { object, size: 16 }]
                        if object == &reg("local_20"))
            ),
            "closure call lost the 16-byte object: {f:#?}"
        );
    }

    #[test]
    fn debug_scalar_boundary_keeps_scalar_storage() {
        let mut f = Function {
            name: "scalar".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0xc),
                    src: Expr::Reg(reg("edi")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("eax"),
                    src: deref_of("rbp", -0xc, 4),
                },
            ],
        };
        let hints = [
            StackObjectHint {
                cfa_relative: false,
                base: "rbp".into(),
                disp: -0x18,
                size: 24,
                aggregate: true,
                source_name: None,
                c_type: None,
            },
            StackObjectHint {
                cfa_relative: false,
                base: "rbp".into(),
                disp: -0xc,
                size: 4,
                aggregate: false,
                source_name: Some("reg32".into()),
                c_type: Some("int".into()),
            },
        ];

        let facts =
            promote_stack_locals_with_facts(&mut f, Some(CallConv::SysVAmd64), None, &hints);

        assert_eq!(facts.sizes.get("local_c"), Some(&4));
        assert_eq!(
            facts.source_types.get("local_c").map(String::as_str),
            Some("int")
        );
        assert_eq!(
            facts.source_names.get("local_c").map(String::as_str),
            Some("reg32")
        );
        assert!(
            matches!(&f.body[0], Stmt::Store { addr: Expr::Reg(object), .. }
                if object == &reg("local_c")),
            "scalar hint incorrectly became aggregate storage: {f:#?}"
        );
        assert!(
            matches!(&f.body[1], Stmt::Assign { src: Expr::Reg(object), .. }
                if object == &reg("local_c")),
            "scalar load lost its promoted identity: {f:#?}"
        );
    }

    #[test]
    fn aarch64_cfa_object_unifies_sp_relative_closure_fields() {
        // Canonical AArch64 O0 frame: the CFA remains the entry SP while the
        // body addresses a 16-byte closure at current sp+24 after allocating
        // 64 bytes. A debug object at CFA-40 must therefore own both fields and
        // the address passed to operator().
        let mut f = Function {
            name: "invoke_aarch64_closure".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(64)),
                    },
                },
                Stmt::Store {
                    addr: lea("sp", 24),
                    src: Expr::Reg(reg("w0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("sp", 32),
                    src: lea("sp", 16),
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![lea("sp", 24)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "entry_sp".into(),
            disp: -40,
            size: 16,
            aggregate: true,
            source_name: None,
            c_type: None,
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::Aarch64),
            None,
            &hints,
        );

        let object = reg("local_28");
        assert!(
            matches!(
                &f.body[1],
                Stmt::Store {
                    addr: Expr::StackAddr { object: actual, size: 16 },
                    ..
                } if actual == &object
            ),
            "first closure field escaped the CFA object: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[2],
                Stmt::Store { addr: Expr::Bin { lhs, rhs, .. }, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object: actual, size: 16 }
                        if actual == &object)
                        && rhs.as_ref() == &Expr::Const(8)
            ),
            "second closure field did not alias offset eight: {f:#?}"
        );
        assert!(
            matches!(
                &f.body[3],
                Stmt::Call { args, .. }
                    if matches!(args.as_slice(), [Expr::StackAddr { object: actual, size: 16 }]
                        if actual == &object)
            ),
            "closure call lost the CFA-owned object: {f:#?}"
        );
    }

    #[test]
    fn aarch64_cfa_scalar_unifies_current_sp_initializer_and_address_escape() {
        // DWARF names the scalar against the entry SP while instructions use
        // the post-prologue SP. Both spellings must resolve to one object when
        // the scalar's address escapes into a closure.
        let address = reg("x8#1");
        let mut f = Function {
            name: "capture_aarch64_scalar".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(48)),
                    },
                },
                Stmt::Store {
                    addr: lea("sp", 0),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Assign {
                    dst: address.clone(),
                    src: lea("sp", 0),
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Reg(address)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "entry_sp".into(),
            disp: -48,
            size: 4,
            aggregate: false,
            source_name: Some("acc".into()),
            c_type: Some("int".into()),
        }];

        let facts = promote_stack_locals_with_facts(&mut f, Some(CallConv::Aarch64), None, &hints);

        let source_slot = facts
            .source_names
            .iter()
            .find_map(|(slot, name)| (name == "acc").then_some(reg(slot)))
            .expect("DWARF scalar fact");
        assert!(
            matches!(&f.body[1], Stmt::Store {
                addr: Expr::StackAddr { object, size: 4 }, ..
            } if object == &source_slot),
            "initializer and DWARF scalar used different storage: {f:#?}"
        );
        assert!(
            matches!(&f.body[3], Stmt::Call { args, .. }
                if matches!(args.as_slice(), [Expr::StackAddr { object, size: 4 }]
                    if object == &source_slot)),
            "escaped address did not use the initialized DWARF scalar: {f:#?}"
        );
    }

    #[test]
    fn arm32_wide_scalar_half_stores_do_not_collapse_to_one_c_assignment() {
        // A 64-bit source scalar is transported as two 32-bit words on ARM32.
        // Until the IR can express partial scalar stores, mapping both halves
        // to the same C lvalue loses the low half entirely.
        let mut f = Function {
            name: "wide_result".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Store {
                    addr: lea("sp", 0),
                    src: Expr::Reg(reg("r0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("sp", 4),
                    src: Expr::Reg(reg("r1")),
                    size: 4,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "entry_sp".into(),
            disp: -8,
            size: 8,
            aggregate: false,
            source_name: Some("r".into()),
            c_type: Some("unsigned long long".into()),
        }];

        promote_stack_locals_with_facts(&mut f, Some(CallConv::Arm), None, &hints);

        let (Stmt::Store { addr: low, .. }, Stmt::Store { addr: high, .. }) =
            (&f.body[1], &f.body[2])
        else {
            panic!("expected the two transported stores: {f:#?}");
        };
        assert_ne!(
            low, high,
            "two machine-word halves collapsed into one source assignment: {f:#?}"
        );
    }

    #[test]
    fn arm_current_sp_coordinate_maps_to_the_entry_stack_coordinate() {
        let ctx = StackContext {
            cc: Some(CallConv::Arm),
            rbp_repurposed: false,
            frame_pointer_established: false,
            arm_frame_register: None,
            parameter_count: None,
        };

        assert_eq!(
            aapcs_entry_stack_coordinate("sp", 8, Some(-32), ctx),
            Some(("entry_sp", -24))
        );
    }

    #[test]
    fn arm_chained_stack_address_aliases_rejoin_a_cfa_array() {
        // GCC's A32 rb_validate forms parents[i] in three instructions:
        // ip = sp + 336; lr = ip + i*4; [lr - 324]. The composed address is
        // current_sp + 12 + i*4, inside the debug-proven CFA-364 array. Keeping
        // each SSA assignment opaque leaves the final C dereference rooted at
        // an uninitialised synthetic `sp` local.
        let mut f = Function {
            name: "rb_validate_a32".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(36)),
                    },
                },
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(340)),
                    },
                },
                Stmt::Label(0x5a8),
                Stmt::Assign {
                    dst: reg("ip#12"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(336)),
                    },
                },
                Stmt::Assign {
                    dst: reg("lr#16"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("ip#12"))),
                        rhs: Box::new(Expr::Bin {
                            op: crate::ir::types::BinOp::Shl,
                            lhs: Box::new(Expr::Reg(reg("r2#11"))),
                            rhs: Box::new(Expr::Const(2)),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: reg("ip#13"),
                    src: Expr::Deref {
                        addr: Box::new(lea("lr#16", -324)),
                        size: 4,
                    },
                },
                Stmt::Store {
                    addr: lea("lr#16", -324),
                    src: Expr::Reg(reg("ip#13")),
                    size: 4,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "entry_sp".into(),
            disp: -364,
            size: 64,
            aggregate: true,
            source_name: None,
            c_type: None,
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::ArmHardFloat),
            Some(3),
            &hints,
        );

        let expected_object = reg("local_16c");
        let is_indexed_object = |address: &Expr| {
            matches!(
                address,
                Expr::Bin { lhs, rhs, .. }
                    if matches!(lhs.as_ref(), Expr::StackAddr { object, size: 64 }
                        if object == &expected_object)
                        && matches!(rhs.as_ref(), Expr::Bin {
                            op: crate::ir::types::BinOp::Mul,
                            lhs,
                            rhs,
                        } if lhs.as_ref() == &Expr::Reg(reg("r2#11"))
                            && rhs.as_ref() == &Expr::Const(4))
            )
        };
        assert!(
            matches!(&f.body[5], Stmt::Assign {
                src: Expr::Deref { addr, size: 4 }, ..
            } if is_indexed_object(addr)),
            "load did not rejoin the CFA array: {f:#?}"
        );
        assert!(
            matches!(&f.body[6], Stmt::Store { addr, size: 4, .. }
                if is_indexed_object(addr)),
            "store did not rejoin the CFA array: {f:#?}"
        );
    }

    #[test]
    fn arm_constant_stack_alias_store_rejoins_its_cfa_array() {
        // Thumb rb_validate materialises node_stack as r5 = sp + 68 and then
        // stores through [r5]. Alias expansion turns the memory address into
        // ordinary `sp + 68` arithmetic; that form must retain the same stack
        // identity as the address-valued r5 definition.
        let mut f = Function {
            name: "rb_validate_thumb".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(328)),
                    },
                },
                Stmt::Label(0x592),
                Stmt::Assign {
                    dst: reg("r5#2"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(68)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("r5#2")),
                        index: None,
                        scale: 0,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Reg(reg("root")),
                    size: 4,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::Arm),
            Some(3),
            &[StackObjectHint {
                cfa_relative: false,
                base: "entry_sp".into(),
                disp: -292,
                size: 128,
                aggregate: true,
                source_name: None,
                c_type: None,
            }],
        );

        let Stmt::Assign {
            src: Expr::StackAddr { object, size: 128 },
            ..
        } = &f.body[3]
        else {
            panic!("stack alias definition was not promoted: {f:#?}");
        };
        assert!(
            matches!(
                &f.body[4],
                Stmt::Store {
                    addr: Expr::StackAddr {
                        object: store_object,
                        size: 128,
                    },
                    ..
                } if store_object == object
            ),
            "store through the exact alias lost the stack object: {f:#?}"
        );
    }

    #[test]
    fn arm_dynamic_stack_alias_freezes_the_preincrement_index() {
        // r3 captures sp + top*4, then the machine increments top before using
        // [r3+196]. Expanding r3 with the redefined top writes black_stack at
        // top+1. The lifter's t52 copy is the exact old value and must carry
        // the address alias across that redefinition.
        let mut f = Function {
            name: "rb_validate_thumb_black_stack".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(360)),
                    },
                },
                Stmt::Label(0x5bc),
                Stmt::Assign {
                    dst: reg("r3#22"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Bin {
                            op: crate::ir::types::BinOp::Shl,
                            lhs: Box::new(Expr::Reg(reg("r2#8"))),
                            rhs: Box::new(Expr::Const(2)),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: reg("t52"),
                    src: Expr::Reg(reg("r2#8")),
                },
                Stmt::Assign {
                    dst: reg("r2#8"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("t52"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Store {
                    addr: lea("r3#22", 196),
                    src: Expr::Reg(reg("black_count")),
                    size: 4,
                },
            ],
        };

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::Arm),
            Some(3),
            &[StackObjectHint {
                cfa_relative: false,
                base: "entry_sp".into(),
                disp: -164,
                size: 128,
                aggregate: true,
                source_name: None,
                c_type: None,
            }],
        );

        assert!(
            matches!(
                &f.body[5],
                Stmt::Store {
                    addr: Expr::Bin { lhs, rhs, .. },
                    ..
                } if matches!(lhs.as_ref(), Expr::StackAddr { size: 128, .. })
                    && matches!(rhs.as_ref(), Expr::Bin {
                        op: crate::ir::types::BinOp::Mul,
                        lhs,
                        rhs,
                    } if lhs.as_ref() == &Expr::Reg(reg("t52"))
                        && rhs.as_ref() == &Expr::Const(4))
            ),
            "stack alias used the post-increment index: {f:#?}"
        );
    }

    #[test]
    fn arm_cfa_object_unifies_frame_relative_constructor_and_destructor() {
        let mut f = Function {
            name: "cpp_ctor_dtor".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(24)),
                    },
                },
                Stmt::Assign {
                    dst: reg("r7#1"),
                    src: Expr::Reg(reg("sp")),
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("r7#1"))),
                        rhs: Box::new(Expr::Const(8)),
                    }],
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("r3#8"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("r7#1"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Call {
                    target: Expr::Addr(0x2000),
                    args: vec![Expr::Reg(reg("r3#8"))],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "entry_sp".into(),
            disp: -24,
            size: 12,
            aggregate: true,
            source_name: None,
            c_type: None,
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::Arm),
            Some(2),
            &hints,
        );

        for statement in [&f.body[3], &f.body[5]] {
            assert!(
                matches!(
                    statement,
                    Stmt::Call { args, .. }
                        if matches!(args.as_slice(), [Expr::StackAddr { object, size: 12 }]
                            if object == &reg("local_18"))
                ),
                "constructor/destructor did not share the CFA object: {f:#?}"
            );
        }
    }

    #[test]
    fn debug_object_extent_outranks_an_unbounded_indexed_frame_partition() {
        // AArch64 merge_sort has `temp[16]` at CFA-168 (64 bytes).  The generic
        // indexed-frame heuristic sees the same negative start and, with no
        // following indexed partition, conservatively extends it to CFA (168
        // bytes).  That absorbs the canary and saved-register area.  A debug
        // extent is authoritative and must survive that heuristic seeding.
        let key = SlotKey {
            base: "entry_sp".into(),
            disp: -168,
        };
        let mut map = HashMap::from([(
            key.clone(),
            SlotVal {
                name: "local_a8".into(),
                declared_size: 1,
                span_size: 1,
                object_size: Some(64),
                bounded_object: true,
                source_type: None,
                source_name: None,
                debug_proven: false,
            },
        )]);
        let cursor = reg("x9#1");
        let address_defs = HashMap::from([(cursor.clone(), ("entry_sp".into(), -168))]);
        let body = vec![Stmt::Assign {
            dst: reg("w0#1"),
            src: Expr::Deref {
                addr: Box::new(Expr::Lea {
                    base: Some(cursor),
                    index: Some(reg("w1#1")),
                    scale: 4,
                    disp: 0,
                    segment: None,
                }),
                size: 4,
            },
        }];

        seed_indexed_stack_objects(
            &body,
            &mut map,
            &mut SlotNames::default(),
            StackContext {
                cc: Some(CallConv::Aarch64),
                rbp_repurposed: false,
                frame_pointer_established: false,
                arm_frame_register: None,
                parameter_count: Some(2),
            },
            &address_defs,
            &HashMap::new(),
        );

        assert_eq!(map.get(&key).and_then(|slot| slot.object_size), Some(64));
    }

    #[test]
    fn aarch64_address_alias_reconciles_an_earlier_scalar_initializer() {
        let captured = reg("x8#1");
        let mut f = Function {
            name: "capture_scalar_by_reference".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("sp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("sp"))),
                        rhs: Box::new(Expr::Const(64)),
                    },
                },
                Stmt::Store {
                    addr: lea("sp", 16),
                    src: Expr::Const(0),
                    size: 4,
                },
                Stmt::Assign {
                    dst: captured.clone(),
                    src: lea("sp", 16),
                },
                Stmt::Store {
                    addr: lea("sp", 32),
                    src: Expr::Reg(captured),
                    size: 8,
                },
            ],
        };
        let hints = [StackObjectHint {
            cfa_relative: false,
            base: "entry_sp".into(),
            disp: -40,
            size: 16,
            aggregate: true,
            source_name: None,
            c_type: None,
        }];

        promote_stack_locals_typed_with_parameter_count_and_objects(
            &mut f,
            Some(CallConv::Aarch64),
            None,
            &hints,
        );

        let Stmt::Store {
            addr:
                Expr::StackAddr {
                    object: scalar_object,
                    size: scalar_size,
                },
            ..
        } = &f.body[1]
        else {
            panic!("scalar initializer did not become object storage: {f:#?}");
        };
        assert!(*scalar_size >= 4);
        assert!(
            matches!(
                &f.body[3],
                Stmt::Store {
                    src: Expr::StackAddr { object, .. },
                    ..
                } if object == scalar_object
            ),
            "captured pointer and initialized scalar are not one object: {f:#?}"
        );
    }

    #[test]
    fn architectural_frame_pointer_is_not_rebased_as_an_ssa_alias() {
        // `rbp = rsp` establishes the x86 frame coordinate system. It is not
        // an ordinary immutable address value: DWARF and every later frame-slot
        // pass intentionally keep `rbp-N` as `local_N`. Rebasing it to entry_rsp
        // turns address-taken frame objects into unrelated `stack_N` storage.
        let address = reg("rax#4");
        let mut f = Function {
            name: "construct_with_frame_prologue".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                Stmt::Assign {
                    dst: address.clone(),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Call {
                    target: Expr::Addr(0x1000),
                    args: vec![Expr::Reg(address)],
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Call { args, .. } = &f.body[2] else {
            panic!("expected call");
        };
        assert_eq!(
            args,
            &[Expr::StackAddr {
                object: reg("local_20"),
                size: 32,
            }]
        );
    }

    #[test]
    fn frame_establishment_does_not_invent_a_saved_pointer_object() {
        let mut f = Function {
            name: "ordinary_frame_prologue".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(8)),
                    },
                },
                Stmt::Store {
                    addr: lea("rsp", 0),
                    src: Expr::Reg(reg("rbp")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                Stmt::Store {
                    addr: lea("rbp", -4),
                    src: Expr::Const(0),
                    size: 4,
                },
            ],
        };

        promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        assert!(
            matches!(
                &f.body[2],
                Stmt::Assign {
                    dst: VReg::Phys(dst),
                    src: Expr::Reg(VReg::Phys(src)),
                } if dst == "rbp" && src == "rsp"
            ),
            "the frame pointer assignment is not an address-taken array: {f:#?}"
        );
    }

    #[test]
    fn a_narrow_read_inside_a_wide_spill_extracts_the_parent_value() {
        // GCC -O0 `dist2(struct pt a, struct pt b)` spills the packed 8-byte
        // argument with `mov [rbp-0x18], rdi`, then reads `a.y` with
        // `mov edx, [rbp-0x14]`. The latter is the upper half of local_18, not
        // a new local_14 that nothing defines.
        let mut f = Function {
            name: "dist2".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", -0x18),
                    src: Expr::Reg(reg("rdi")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("rdx"),
                    src: deref_of("rbp", -0x14, 4),
                },
            ],
        };

        let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));

        let Stmt::Assign { src, .. } = &f.body[1] else {
            panic!("expected the upper-half load");
        };
        assert!(
            matches!(
                src,
                Expr::Cast {
                    signed: false,
                    width: 4,
                    expr,
                } if matches!(
                    expr.as_ref(),
                    Expr::Bin {
                        op: crate::ir::types::BinOp::Shr,
                        lhs,
                        rhs,
                    } if matches!(
                        lhs.as_ref(),
                        Expr::Cast {
                            signed: false,
                            width: 8,
                            expr,
                        } if matches!(expr.as_ref(), Expr::Reg(VReg::Phys(name)) if name == "local_18")
                    ) && matches!(rhs.as_ref(), Expr::Const(32))
                )
            ),
            "the high field must be extracted from the defined parent spill: {src:#?}"
        );
        assert!(
            !sizes.contains_key("local_14"),
            "an overlapping field must not become an undefined standalone local"
        );
    }

    #[test]
    fn stack_top_zero_offset_gets_special_name() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rsp", 0, 8),
            }],
        };
        promote_stack_locals(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("stack_top")));
        }
    }

    #[test]
    fn colliding_stack_top_views_have_one_deterministic_wide_declaration() {
        // A mixed-width stack function can address the same rendered
        // `stack_top` role through distinct machine views. Those are distinct
        // SlotKeys (`entry_rsp` and `esp`) but ONE C identifier. Collecting the
        // HashMap values directly let whichever key iterated last choose the
        // declaration, so identical decompilations alternated between `char`
        // and `long` (observed on blinded bin_209.elf).
        for _ in 0..64 {
            let mut f = Function {
                name: "mixed_stack_top".into(),
                entry_va: 0,
                body: vec![
                    Stmt::Assign {
                        dst: reg("rax"),
                        src: deref_of("rsp", 0, 8),
                    },
                    Stmt::Assign {
                        dst: reg("al"),
                        src: deref_of("esp", 0, 1),
                    },
                ],
            };

            let sizes = promote_stack_locals_typed(&mut f, Some(CallConv::SysVAmd64));
            assert_eq!(
                sizes.get("stack_top"),
                Some(&8),
                "one rendered identifier must use the widest compatible storage view"
            );
        }
    }

    #[test]
    fn non_stack_base_is_unchanged() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: deref_of("rdi", 8, 8),
            }],
        };
        let orig = f.clone();
        promote_stack_locals(&mut f);
        assert_eq!(f, orig, "rdi-based deref must not be promoted");
    }

    #[test]
    fn stack_pointer_update_is_not_touched() {
        // `%rsp = %rsp - 8;` must stay — it's a stack-pointer adjustment,
        // not a slot access.
        use crate::ir::types::BinOp;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }],
        };
        let orig = f.clone();
        promote_stack_locals(&mut f);
        assert_eq!(f, orig);
    }
}
