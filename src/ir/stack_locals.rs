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

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

mod address_aliases;
mod address_recovery;
#[cfg(test)]
mod arm32_tests;
mod bounded_overlap;
mod coordinate_flow;
mod indexed_objects;
mod rewrite;
mod slot_views;

// Re-imported under their own names so the pass body, the sibling modules and
// the test module keep addressing them exactly as they did while they lived
// here. `bounded_overlap` and `rewrite` reach them through their own `use super::`.
use address_recovery::{
    aapcs_entry_stack_coordinate, bounded_scalar_slot, escaped_stack_address,
    normalized_stack_slot, resolve_stack_address, resolved_memory_address, resolved_memory_slot,
    stack_assignment_object_address, stack_object_address, stack_object_constant_address,
};
use coordinate_flow::{collect_label_stack_deltas, collect_stack_address_defs};
use indexed_objects::seed_indexed_stack_objects;
use rewrite::{reconcile_late_address_taken_objects, rewrite_body};

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

/// Overlay analyst-chosen stack-variable names and types onto the recovered
/// facts, keyed by frame offset.
///
/// # Why this rides the DWARF path
///
/// `StackLocalFacts::source_names` already exists and already means "an
/// authoritative name for this promoted local", populated from debug info and
/// applied by `naming::apply_authoritative_local_names` at the presentation
/// boundary -- after every semantic pass, so a rename cannot turn a scalar
/// assignment into a pointer store. An analyst rename wants exactly that
/// treatment. Building a second mechanism beside it would mean two things that
/// rename a local, disagreeing at the edges.
///
/// # The join
///
/// The project file records a stack variable by FRAME OFFSET; the AST knows it
/// by its promoted NAME, and the name cannot be parsed back into an offset --
/// `local_{disp:x}` keeps only `disp.unsigned_abs()`, losing the base and the
/// sign, and the mint falls back to an appearance-order `stack_N` when that hex
/// spelling is taken. `frame_coordinates` is the only thing that knows the
/// answer, which is why it is published.
///
/// A coordinate `stack_locals` WITHHELD as ambiguous stays withheld: an offset
/// reachable from two different bases is not a variable we can name without
/// guessing which one the analyst meant, and attaching their name to the wrong
/// slot is worse than leaving it as `local_18`.
///
/// Names are validated by the same rule debug names are
/// (`naming::valid_authoritative_local_name`), so an analyst who names a
/// variable `int` or `arg0` gets their name rejected rather than emitted into
/// C that will not compile or that collides with an ABI role.
/// # A rename needs a type, and that is not a formality
///
/// A name is applied only when the slot will also have a source type -- either
/// one the analyst supplied or one already recovered. The renderer's own
/// pairing filter enforces the same rule at the other end, and it is there for
/// correctness, not tidiness. Measured 2026-08-28 on a stripped `-O0` build,
/// renaming the surviving local at `rbp-0xc` with no type attached turned
///
/// ```text
/// int local_c;   local_c = 0;   ... return (unsigned int)(local_c);
/// ```
///
/// into
///
/// ```text
/// long running_total;   *(int *)(running_total) = 0;
/// ```
///
/// -- a pointer store synthesised from a scalar assignment, because the local
/// lost its recovered width along with its `local_` identity. Applying the name
/// here and letting the renderer drop it would be worse than declining: the
/// analyst would see no rename and no reason.
///
/// Returns the promoted names it actually renamed, so a caller can tell the
/// analyst which of their renames did not take.
pub fn apply_analyst_locals(
    facts: &mut StackLocalFacts,
    by_offset: &HashMap<i64, (String, String)>,
) -> std::collections::HashSet<String> {
    let mut applied = std::collections::HashSet::new();
    if by_offset.is_empty() {
        return applied;
    }
    // Built from the coordinates rather than iterated per override, so an
    // offset that maps to several promoted names is detected rather than
    // resolved to whichever was visited last.
    let mut names_at: HashMap<i64, Vec<&String>> = HashMap::new();
    for (name, (_base, disp)) in facts.frame_coordinates.iter() {
        names_at.entry(*disp).or_default().push(name);
    }
    for (offset, (name, ctype)) in by_offset {
        let Some(candidates) = names_at.get(offset) else {
            continue;
        };
        if candidates.len() != 1 {
            continue;
        }
        let promoted = candidates[0].clone();
        let ctype = ctype.trim();
        if !ctype.is_empty() {
            facts.source_types.insert(promoted.clone(), ctype.to_string());
        }
        let name = name.trim();
        // The pair, never one half of it -- see the note above.
        let will_have_a_type = facts.source_types.contains_key(&promoted);
        if !name.is_empty()
            && will_have_a_type
            && crate::ir::naming::valid_authoritative_local_name(name)
        {
            facts.source_names.insert(promoted.clone(), name.to_string());
            applied.insert(promoted);
        }
    }
    applied
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

    /// A load WIDER than the slot it starts in reads the NEIGHBOURING slots
    /// too, and rewriting it to the first slot's name drops the rest.
    ///
    /// GCC -O2 returns a twelve-byte aggregate by writing two dwords into the
    /// red zone and reloading eight bytes across both
    /// (`198_aggregate_return_edges:gcc:O2:agr198_make_trio`). Promoted as one
    /// name, the second member was computed into a C local that nothing read.
    #[test]
    fn a_load_spanning_two_promoted_slots_concatenates_them() {
        use crate::ir::types::BinOp;
        let mut f = Function {
            name: "make_trio".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", -0x14),
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("rsp", -0x10),
                    src: Expr::Reg(reg("ecx")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", -0x14, 8),
                },
            ],
        };
        promote_stack_locals_with_facts(&mut f, Some(CallConv::SysVAmd64), None, &[]);

        let promoted = |statement: &Stmt| match statement {
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            }
            | Stmt::Store {
                addr: Expr::Reg(VReg::Phys(name)),
                ..
            } => name.clone(),
            other => panic!("expected a promoted store, got {other:?}"),
        };
        let low = promoted(&f.body[0]);
        let high = promoted(&f.body[1]);
        assert_ne!(low, high, "distinct slots must get distinct names");

        let Stmt::Assign { src, .. } = &f.body[2] else {
            panic!("expected the wide load, got {:?}", f.body[2]);
        };
        let widened = |name: &str| Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg(name))),
            }),
        };
        assert_eq!(
            src,
            &Expr::Bin {
                op: BinOp::Or,
                lhs: Box::new(widened(&low)),
                rhs: Box::new(Expr::Bin {
                    op: BinOp::Shl,
                    lhs: Box::new(widened(&high)),
                    rhs: Box::new(Expr::Const(32)),
                }),
            },
            "the wide load must read BOTH slots: {:#?}",
            f.body[2]
        );
    }

    /// The second negative control. An INCOMING PARAMETER's width is the
    /// recovered prototype's, not the observed accesses': `[rbp+0x10]` is the
    /// seventh System V argument and the signature already declares its whole
    /// object, so masking it to the four bytes this body happened to write
    /// would drop the rest.
    #[test]
    fn a_wide_load_over_an_incoming_parameter_slot_is_not_concatenated() {
        let mut f = Function {
            name: "seventh_argument".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: lea("rbp", 0x10),
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("rbp", 0x14),
                    src: Expr::Reg(reg("ecx")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rbp", 0x10, 8),
                },
            ],
        };
        promote_stack_locals_with_facts(&mut f, Some(CallConv::SysVAmd64), Some(7), &[]);
        assert!(
            matches!(&f.body[0], Stmt::Assign { dst: VReg::Phys(name), .. }
                | Stmt::Store { addr: Expr::Reg(VReg::Phys(name)), .. } if name == "arg6"),
            "the stacked argument slot must promote to arg6: {:?}",
            f.body[0]
        );
        let Stmt::Assign { src, .. } = &f.body[2] else {
            panic!("expected the wide load, got {:?}", f.body[2]);
        };
        assert!(
            matches!(src, Expr::Reg(_)),
            "a parameter's declaration owns its whole object: {src:#?}"
        );
    }

    /// The third negative control, and the one a measurement found. On i386 an
    /// `fild QWORD` reads eight bytes across two four-byte slots, and the high
    /// one is a copy of the second half of a stacked `int64_t` parameter that
    /// promotion names as a local and nothing defines. Composing made that
    /// undefined read live and turned
    /// `173_float_int_conversions:i386:O0:widen_long_to_double` from pass to
    /// fail; an access wider than the machine word is not one machine value.
    #[test]
    fn a_load_wider_than_the_machine_word_is_not_concatenated() {
        let mut f = Function {
            name: "widen_long_to_double".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: lea("ebp", -8),
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
                Stmt::Store {
                    addr: lea("ebp", -4),
                    src: Expr::Reg(reg("edx")),
                    size: 4,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("ebp", -8, 8),
                },
            ],
        };
        promote_stack_locals_with_facts(&mut f, Some(CallConv::Cdecl32), Some(1), &[]);
        let Stmt::Assign { src, .. } = &f.body[2] else {
            panic!("expected the wide load, got {:?}", f.body[2]);
        };
        assert!(
            matches!(src, Expr::Reg(_)),
            "an access wider than the machine word keeps its single-slot form: {src:#?}"
        );
    }

    /// The negative control. A gap inside the access is a byte no observed
    /// store reached, and no C variable names it — so the concatenation is
    /// refused and the existing single-slot behaviour stands rather than a
    /// value being invented for the hole.
    #[test]
    fn a_wide_load_over_a_gap_keeps_its_single_slot_form() {
        let mut f = Function {
            name: "gap".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Store {
                    addr: lea("rsp", -0x14),
                    src: Expr::Reg(reg("eax")),
                    size: 4,
                },
                // Two bytes short of tiling the eight-byte load below.
                Stmt::Store {
                    addr: lea("rsp", -0x10),
                    src: Expr::Reg(reg("cx")),
                    size: 2,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: deref_of("rsp", -0x14, 8),
                },
            ],
        };
        promote_stack_locals_with_facts(&mut f, Some(CallConv::SysVAmd64), None, &[]);
        let Stmt::Assign { src, .. } = &f.body[2] else {
            panic!("expected the wide load, got {:?}", f.body[2]);
        };
        assert!(
            matches!(src, Expr::Reg(_)),
            "an incompletely tiled access must keep its single-slot form: {src:#?}"
        );
    }
}

#[cfg(test)]
mod analyst_locals_tests {
    use super::*;
    use std::collections::HashSet;

    fn facts_with(coords: &[(&str, &str, i64)]) -> StackLocalFacts {
        let mut facts = StackLocalFacts::default();
        for (name, base, disp) in coords {
            facts
                .frame_coordinates
                .insert(name.to_string(), (base.to_string(), *disp));
            facts.sizes.insert(name.to_string(), 4);
        }
        facts
    }

    fn overrides(items: &[(i64, &str, &str)]) -> HashMap<i64, (String, String)> {
        items
            .iter()
            .map(|(off, name, ty)| (*off, (name.to_string(), ty.to_string())))
            .collect()
    }

    /// The ordinary case: the analyst named the slot at -0x18, and the AST
    /// knows that slot only as `local_18`.
    #[test]
    fn an_offset_is_joined_to_its_promoted_name() {
        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        let applied = apply_analyst_locals(&mut facts, &overrides(&[(-24, "hdr", "struct packet *")]));
        assert_eq!(applied, HashSet::from(["local_18".to_string()]));
        assert_eq!(facts.source_names.get("local_18").map(String::as_str), Some("hdr"));
        assert_eq!(
            facts.source_types.get("local_18").map(String::as_str),
            Some("struct packet *")
        );
    }

    /// An offset reachable from two different bases is not one variable. Naming
    /// it would attach the analyst's name to whichever slot was iterated last.
    #[test]
    fn an_ambiguous_offset_is_left_alone() {
        let mut facts = facts_with(&[("local_18", "rbp", -24), ("stack_0", "entry_rsp", -24)]);
        assert!(apply_analyst_locals(&mut facts, &overrides(&[(-24, "hdr", "int")])).is_empty());
        assert!(facts.source_names.is_empty());
        assert!(facts.source_types.is_empty(), "the type must not land either");
    }

    /// A coordinate `stack_locals` already withheld stays withheld.
    #[test]
    fn a_slot_with_no_coordinate_is_not_named() {
        let mut facts = StackLocalFacts::default();
        facts.sizes.insert("local_18".to_string(), 4);
        assert!(apply_analyst_locals(&mut facts, &overrides(&[(-24, "hdr", "int")])).is_empty());
        assert!(facts.source_names.is_empty());
    }

    /// The analyst gets the same validation debug names get: a name that is a C
    /// keyword or an ABI role would produce C that does not compile, or would
    /// collide with a role the renderer owns.
    #[test]
    fn an_unusable_name_is_rejected_but_the_type_still_applies() {
        for bad in ["int", "return", "1var", "has space", ""] {
            let mut facts = facts_with(&[("local_18", "rbp", -24)]);
            assert!(
                apply_analyst_locals(&mut facts, &overrides(&[(-24, bad, "short")])).is_empty(),
                "accepted {bad:?}"
            );
            assert!(facts.source_names.is_empty(), "accepted {bad:?}");
            assert_eq!(
                facts.source_types.get("local_18").map(String::as_str),
                Some("short"),
                "a bad name must not also discard a good type"
            );
        }
    }

    /// A retype alone is ordinary. A rename alone is REFUSED, because a name
    /// without a type renders as a pointer store -- see the function's note.
    #[test]
    fn a_retype_alone_applies_but_a_rename_alone_does_not() {
        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        assert!(
            apply_analyst_locals(&mut facts, &overrides(&[(-24, "hdr", "")])).is_empty(),
            "a name with no type must not be applied"
        );
        assert!(facts.source_names.is_empty());

        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        apply_analyst_locals(&mut facts, &overrides(&[(-24, "", "unsigned long")]));
        assert!(facts.source_names.is_empty());
        assert_eq!(
            facts.source_types.get("local_18").map(String::as_str),
            Some("unsigned long")
        );
    }

    /// A rename alone DOES apply when the slot already has a recovered type,
    /// which is the DWARF case -- the rule is about the pair existing, not
    /// about the analyst having supplied both halves.
    #[test]
    fn a_rename_alone_applies_when_a_type_was_already_recovered() {
        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        facts.source_types.insert("local_18".to_string(), "int".to_string());
        assert_eq!(
            apply_analyst_locals(&mut facts, &overrides(&[(-24, "hdr", "")])),
            HashSet::from(["local_18".to_string()])
        );
        assert_eq!(facts.source_names.get("local_18").map(String::as_str), Some("hdr"));
        assert_eq!(facts.source_types.get("local_18").map(String::as_str), Some("int"));
    }

    /// An override for an offset this function does not have is a no-op, which
    /// is the common case -- a project holds slots for every function.
    #[test]
    fn an_offset_this_function_does_not_have_is_ignored() {
        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        assert!(apply_analyst_locals(&mut facts, &overrides(&[(-999, "x", "int")])).is_empty());
        assert!(facts.source_names.is_empty());
    }

    /// The analyst outranks DWARF here, which is the same rule the project file
    /// enforces on every writable fact.
    #[test]
    fn an_analyst_name_replaces_a_debug_name() {
        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        facts.source_names.insert("local_18".to_string(), "from_dwarf".to_string());
        facts.source_types.insert("local_18".to_string(), "int".to_string());
        apply_analyst_locals(&mut facts, &overrides(&[(-24, "from_analyst", "long")]));
        assert_eq!(
            facts.source_names.get("local_18").map(String::as_str),
            Some("from_analyst")
        );
        assert_eq!(facts.source_types.get("local_18").map(String::as_str), Some("long"));
    }

    #[test]
    fn an_empty_overlay_changes_nothing() {
        let mut facts = facts_with(&[("local_18", "rbp", -24)]);
        let before = facts.clone();
        assert!(apply_analyst_locals(&mut facts, &HashMap::new()).is_empty());
        assert_eq!(facts, before);
    }
}
