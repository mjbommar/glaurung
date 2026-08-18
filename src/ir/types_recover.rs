//! First-cut type recovery for VRegs in an [`LlirFunction`].
//!
//! v0 scope — deliberately tiny, but useful:
//!
//! * Registers used as the base of a `Load`/`Store` memory operand are
//!   classified as **pointers**. The inferred pointee width comes from the
//!   memory access size.
//! * Registers used solely as shift counts are tagged **unsigned integer**.
//! * Registers that flow into a `CallTarget::Direct` as the first argument
//!   register (by convention x86-64 SysV: `rdi`, AArch64: `x0`) keep their
//!   inferred type if one was set earlier — this is just a pass-through
//!   hook for future argument-type inference.
//!
//! The output is a [`TypeMap`] keyed by [`VReg`]. Later passes can refine
//! it; the AST printer can consume it to print `int`/`char*`/`bool` instead
//! of raw register names.
//!
//! This pass reads only the LLIR — it does not require SSA form — which
//! keeps it cheap and composable. Passes that need SSA precision can
//! consume [`crate::ir::ssa::SsaInfo`] and re-run on a per-version basis.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{BinOp, LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_uses, use_is_proven_input, InstrAddr};

mod float_bank;
mod result_hint;
mod tagging;
mod valued;

#[cfg(test)]
use float_bank::float_argument_bank_slot;
use float_bank::{
    float_live_in_slots, has_float_argument_bank, mixed_entry_spill_order,
    scalar_float_intrinsic_width, scalar_vfp_register,
};
use result_hint::{
    call_result_has_only_guard_uses, join_result_hints, non_return_live_values,
    output_trial_is_dedicated, qualified_result_hint, ResultHintClass,
};
use tagging::{
    classify_int_default, float_return_reg_names, merge_type_hint, propagate_pointer_arithmetic,
    propagate_spill_slot_pointers, return_reg_names, tag_value_regs,
};
// `is_frame_base` has no caller outside `tagging` itself except `mod tests`
// below, which reaches it through `use super::*`. Re-exporting it
// unconditionally would be an unused import in the shipped lib build.
#[cfg(test)]
use tagging::is_frame_base;
pub use tagging::recover_types_for;
pub use valued::recover_types_valued;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeHint {
    /// A pointer; `width` records the access size of the last memory
    /// operation performed through it (1/2/4/8 bytes).
    Pointer { pointee_width: u8 },
    /// Signed/unsigned integer — distinguished by context (shifts tagged
    /// unsigned, arithmetic compared against signed constants tagged signed).
    Int { signed: bool, width: u8 },
    /// IEEE-754 scalar carried in a dedicated floating-point ABI storage
    /// class. `width` is the source value width in bytes (currently 4 or 8),
    /// not the width of the enclosing SIMD register.
    Float { width: u8 },
    /// Value used as a 0/1 boolean (compared equal to zero).
    BoolLike,
    /// The value is used by [`Op::Call`] as an indirect call target, so it
    /// is likely a code pointer.
    CodePointer,
}

/// Stable standalone-C spelling for a recovered value type.
///
/// Call-site specifications and the DecBench renderer consume the same mapping
/// so prototype metadata cannot drift from the declarations eventually printed.
pub fn c_type_for_hint(hint: TypeHint) -> &'static str {
    c_type_for_hint_with_pointer_width(hint, 8)
}

/// Stable standalone-C spelling under the target data model.
///
/// A byte width is a semantic fact; `long` is not.  In particular, an
/// eight-byte integer must be `long long` on ILP32 targets, while the same
/// value can use `long` on LP64.  Keeping this conversion beside
/// [`c_type_for_hint`] gives call prototypes and the final renderer one owner
/// for that distinction.
pub fn c_type_for_hint_with_pointer_width(hint: TypeHint, pointer_width: u8) -> &'static str {
    match hint {
        TypeHint::Int { signed, width } => match (signed, width) {
            (true, 1) => "signed char",
            (false, 1) => "unsigned char",
            (true, 2) => "short",
            (false, 2) => "unsigned short",
            (true, 4) => "int",
            (false, 4) => "unsigned int",
            (true, 8) if pointer_width < 8 => "long long",
            (false, 8) if pointer_width < 8 => "unsigned long long",
            (false, 8) => "unsigned long",
            _ => "long",
        },
        TypeHint::Pointer { pointee_width } => match pointee_width {
            1 => "char *",
            2 => "short *",
            4 => "int *",
            8 if pointer_width < 8 => "long long *",
            8 => "long *",
            _ => "void *",
        },
        TypeHint::BoolLike => "int",
        TypeHint::CodePointer => "void *",
        TypeHint::Float { width: 4 } => "float",
        TypeHint::Float { .. } => "double",
    }
}

#[derive(Debug, Default, Clone)]
pub struct TypeMap {
    inner: HashMap<VReg, TypeHint>,
    // Locked roles are few; deterministic storage avoids adding another
    // randomized collection to type-recovery state.
    locked: BTreeSet<VReg>,
}

impl TypeMap {
    pub fn get(&self, v: &VReg) -> Option<TypeHint> {
        self.inner.get(v).copied()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&VReg, &TypeHint)> {
        self.inner.iter()
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Whether an authoritative external contract owns this rendered role.
    pub(crate) fn is_locked(&self, reg: &VReg) -> bool {
        self.locked.contains(reg)
    }

    /// Public wrapper around [`Self::upsert`] so other modules (e.g. the
    /// Python binding's type-map remapper) can build a `TypeMap`
    /// incrementally from outside this crate's module.
    pub fn upsert_public(&mut self, reg: VReg, new: TypeHint) {
        self.upsert(reg, new)
    }

    /// Install an authoritative external declaration exactly.
    ///
    /// This is intentionally not union-style inference: a locked DWARF/PDB
    /// contract outranks storage-width residue for the same rendered role.
    pub(crate) fn apply_locked_fact(&mut self, reg: VReg, hint: TypeHint) {
        self.inner.insert(reg.clone(), hint);
        self.locked.insert(reg);
    }

    /// Refine a fact after value-keyed analysis identifies the exact value that
    /// occupies this rendered role. This is deliberately distinct from the
    /// union-style `upsert`: SSA identity decides scalar-vs-address class while
    /// the older operation-level analysis retains richer scalar signedness.
    pub(crate) fn refine_from_value(&mut self, reg: VReg, hint: TypeHint) {
        if self.locked.contains(&reg) {
            return;
        }
        let current = self.inner.get(&reg).copied();
        if let (
            Some(TypeHint::Int { signed, .. }),
            TypeHint::Int {
                width: exact_width, ..
            },
        ) = (current, hint)
        {
            // SSA identity is exact width evidence even when the older
            // storage-keyed pass has better signedness context.  Preserve that
            // signedness, but do not let a later 32-bit reuse of the same
            // architectural register narrow a proven ABI-wide returned value.
            self.inner.insert(
                reg,
                TypeHint::Int {
                    signed,
                    width: exact_width,
                },
            );
            return;
        }
        let replace = match (current, hint) {
            (None, _) => true,
            // Per-value identity is decisive when raw-register union confused a
            // scalar lifetime with an address-bearing lifetime (or vice versa).
            (
                Some(TypeHint::Int { .. } | TypeHint::Float { .. } | TypeHint::BoolLike),
                TypeHint::Pointer { .. } | TypeHint::CodePointer,
            )
            | (
                Some(TypeHint::Pointer { .. } | TypeHint::CodePointer),
                TypeHint::Int { .. } | TypeHint::Float { .. } | TypeHint::BoolLike,
            ) => true,
            // A semantic float operation tied to one SSA value is stronger
            // than a flow-insensitive integer default for the same register.
            (Some(TypeHint::Int { .. } | TypeHint::BoolLike), TypeHint::Float { .. }) => true,
            // Exact-value memory evidence may refine the access width or
            // distinguish data from code pointers.
            (
                Some(TypeHint::Pointer { .. } | TypeHint::CodePointer),
                TypeHint::Pointer { .. } | TypeHint::CodePointer,
            ) => true,
            // The older recovery contains richer scalar signedness evidence
            // from operation context (e.g. SHR/SAR). Value identity alone is
            // not a reason to throw that fact away.
            _ => false,
        };
        if replace {
            self.inner.insert(reg, hint);
        }
    }

    /// Discard a legacy storage-keyed fact before a later exact-value analysis
    /// reclassifies that source identity. Final `varN` names were not consumed
    /// by the renderer when raw-register recovery was designed, so facts that
    /// happen to share those spellings are not trustworthy without a prepared
    /// AST definition proof.
    pub(crate) fn clear_value_fact(&mut self, reg: &VReg) {
        if self.locked.contains(reg) {
            return;
        }
        self.inner.remove(reg);
    }

    /// Replace an existing integer width with an ABI-mandated width while
    /// preserving signedness. This is intentionally narrower than `upsert`:
    /// ordinary evidence merging prefers a precise sub-register width, whereas
    /// a later proof that the value's high bits are consumed must be allowed to
    /// restore the complete incoming/return eightbyte. Semantic pointer hints
    /// are never overwritten.
    pub(crate) fn force_int_width(&mut self, reg: VReg, width: u8) {
        if self.locked.contains(&reg) {
            return;
        }
        if let Some(TypeHint::Int { signed, .. }) = self.inner.get(&reg).copied() {
            self.inner.insert(reg, TypeHint::Int { signed, width });
        }
    }

    /// Replace an existing integer's signedness while preserving its recovered
    /// width. A signed AST comparison is stronger evidence than an earlier
    /// zero-extension/index use, but it is not evidence that a pointer or code
    /// pointer should become an integer.
    pub(crate) fn force_int_signedness(&mut self, reg: VReg, signed: bool) {
        if self.locked.contains(&reg) {
            return;
        }
        if let Some(TypeHint::Int { width, .. }) = self.inner.get(&reg).copied() {
            self.inner.insert(reg, TypeHint::Int { signed, width });
        }
    }

    /// Replace a stale pointee width after the prepared AST proves that every
    /// direct access through this value has one different width. Raw-register
    /// recovery can merge unrelated SSA-era uses of the same architectural
    /// register; the final value identity is stronger evidence.
    pub(crate) fn force_pointer_width(&mut self, reg: VReg, pointee_width: u8) {
        if self.locked.contains(&reg) {
            return;
        }
        if matches!(self.inner.get(&reg), Some(TypeHint::Pointer { .. })) {
            self.inner.insert(reg, TypeHint::Pointer { pointee_width });
        }
    }

    /// Replace even a stale pointer classification after a later value-flow
    /// proof establishes that every definition reaching this role is scalar.
    /// Callers must perform that proof on the prepared, value-keyed AST; raw
    /// register evidence alone is deliberately not strong enough to use this.
    pub(crate) fn force_scalar_int(&mut self, reg: VReg, signed: bool, width: u8) {
        if self.locked.contains(&reg) {
            return;
        }
        self.inner.insert(reg, TypeHint::Int { signed, width });
    }

    /// Union-style update: only overwrite when `new` is strictly more
    /// specific than the current entry. Pointers beat ints; specific widths
    /// beat zero-width entries; bool beats nothing.
    fn upsert(&mut self, reg: VReg, new: TypeHint) {
        if self.locked.contains(&reg) {
            return;
        }
        let keep = merge_type_hint(self.inner.get(&reg).copied(), new);
        self.inner.insert(reg, keep);
    }
}

/// Type facts keyed by the value a particular definition produced, rather
/// than by the architectural register that happened to carry it. This is the
/// substrate used by Ghidra's Varnodes and Kuna's per-write Varnode arena; it
/// prevents unrelated register lifetimes from poisoning each other's types.
#[derive(Debug, Default, Clone)]
pub struct TypeMapV {
    inner: HashMap<SsaValue, TypeHint>,
    parameter_refinements: HashMap<SsaValue, TypeHint>,
    strong_parameter_refinements: HashSet<SsaValue>,
}

impl TypeMapV {
    pub fn get(&self, value: &SsaValue) -> Option<TypeHint> {
        self.inner.get(value).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SsaValue, &TypeHint)> {
        self.inner.iter()
    }

    fn upsert(&mut self, value: SsaValue, hint: TypeHint) -> bool {
        let before = self.inner.get(&value).copied();
        // Exact values may legitimately serve as byte and word buffers (for
        // example memset's destination). A register-keyed map has to choose a
        // widest machine view, but an SSA-keyed semantic fact can preserve the
        // conflict honestly: width zero renders `void *` and remains stable if
        // another concrete access arrives later.
        let merged = match (before, hint) {
            (
                Some(TypeHint::Pointer {
                    pointee_width: current,
                }),
                TypeHint::Pointer {
                    pointee_width: incoming,
                },
            ) if current != incoming => TypeHint::Pointer { pointee_width: 0 },
            _ => merge_type_hint(before, hint),
        };
        self.inner.insert(value, merged);
        before != Some(merged)
    }

    fn upsert_parameter_refinement(&mut self, value: SsaValue, hint: TypeHint) -> bool {
        let before = self.parameter_refinements.get(&value).copied();
        let merged = merge_type_hint(before, hint);
        self.parameter_refinements.insert(value, merged);
        before != Some(merged)
    }

    /// Record declaration evidence that is independently sufficient to refine
    /// one exact ABI live-in.  This is deliberately separate from the ordinary
    /// refinement lattice: weak narrow spills still require corroboration,
    /// while a compiler-derived SysV parameter home has already passed its
    /// own provenance and ambiguity checks.
    fn upsert_strong_parameter_refinement(&mut self, value: SsaValue, hint: TypeHint) -> bool {
        let was_strong = self.strong_parameter_refinements.contains(&value);
        let before = self.parameter_refinements.get(&value).copied();
        let merged = match (before, hint) {
            // GCC may zero-extend a signed byte/word merely to transport its
            // bits into another same-width object, then sign-extend a later
            // reload for a semantic use.  Once both facts come from the exact
            // proven parameter home, the sign-extension is the discriminating
            // declaration evidence. A lone zero-extension remains unsigned.
            (
                Some(TypeHint::Int {
                    signed: current_signed,
                    width: current_width,
                }),
                TypeHint::Int {
                    signed: incoming_signed,
                    width: incoming_width,
                },
            ) if was_strong && current_width == incoming_width && current_width <= 2 => {
                TypeHint::Int {
                    signed: current_signed || incoming_signed,
                    width: current_width,
                }
            }
            _ => merge_type_hint(before, hint),
        };
        self.parameter_refinements.insert(value.clone(), merged);
        let inserted = self.strong_parameter_refinements.insert(value);
        before != Some(merged) || inserted
    }

    /// Project only entry definitions back to a compatibility map. This is a
    /// lossless projection for ABI parameters: version zero is the unique
    /// caller-supplied value, while later scratch lifetimes remain excluded.
    pub fn live_in_types(&self) -> TypeMap {
        let mut out = TypeMap::default();
        for (value, hint) in &self.inner {
            if value.version == 0 {
                out.upsert(value.base.clone(), *hint);
            }
        }
        out
    }

    /// Entry-value facts strong enough to change a rendered parameter today.
    ///
    /// Exact AAPCS word-scalar evidence can stand alone. Narrow scalar evidence
    /// still needs a companion because an enum or ABI-promoted integer may be
    /// narrowed only after entry. Pointer evidence is more ambiguous because an
    /// integer MMIO address has the same machine shape, so it needs either a
    /// second independently proven pointer or two proven companion parameters.
    pub fn parameter_refinements(&self) -> TypeMap {
        let mut out = TypeMap::default();
        let live_in_count = self
            .parameter_refinements
            .keys()
            .filter(|value| value.version == 0)
            .count();
        let pointer_count = self
            .parameter_refinements
            .iter()
            .filter(|(value, hint)| {
                value.version == 0
                    && matches!(hint, TypeHint::Pointer { .. } | TypeHint::CodePointer)
            })
            .count();
        let pointers_corroborated = pointer_count >= 2 || live_in_count >= 3;
        let scalars_corroborated = live_in_count >= 2;
        for (value, hint) in &self.parameter_refinements {
            let visible = self.strong_parameter_refinements.contains(value)
                || match hint {
                    TypeHint::Pointer { .. } | TypeHint::CodePointer => pointers_corroborated,
                    TypeHint::Int {
                        signed: false,
                        width,
                    } if *width >= 4 => true,
                    _ => scalars_corroborated,
                };
            if value.version == 0 && visible {
                out.upsert(value.base.clone(), *hint);
            }
        }
        out
    }

    /// Return the output-qualified fact for one exact caller-supplied value.
    ///
    /// This retains the same class-aware safety gate as
    /// [`Self::parameter_refinements`], but does not erase SSA identity by
    /// projecting through a raw register key first.
    fn parameter_refinement(&self, value: &SsaValue) -> Option<TypeHint> {
        if value.version != 0 {
            return None;
        }
        let hint = self.parameter_refinements.get(value).copied()?;
        if self.strong_parameter_refinements.contains(value) {
            return Some(hint);
        }
        if matches!(
            hint,
            TypeHint::Int {
                signed: false,
                width: 4..=u8::MAX,
            }
        ) {
            return Some(hint);
        }
        let live_in_count = self
            .parameter_refinements
            .keys()
            .filter(|candidate| candidate.version == 0)
            .count();
        let pointer_count = self
            .parameter_refinements
            .iter()
            .filter(|(candidate, candidate_hint)| {
                candidate.version == 0
                    && matches!(
                        candidate_hint,
                        TypeHint::Pointer { .. } | TypeHint::CodePointer
                    )
            })
            .count();
        let visible = match hint {
            TypeHint::Pointer { .. } | TypeHint::CodePointer => {
                pointer_count >= 2 || live_in_count >= 3
            }
            _ => live_in_count >= 2,
        };
        visible.then_some(hint)
    }
}

/// One source-level parameter, anchored to the exact SSA live-in from which it
/// was recovered.
///
/// Ghidra keeps this relationship through `Varnode -> HighVariable`; Kuna does
/// the same through its Varnode arena and final prototype actions.  Keeping the
/// SSA key here prevents AST naming (`rdi` -> `arg0`) from becoming a second,
/// lossy type-analysis pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredParameter {
    pub slot: usize,
    pub value: SsaValue,
    pub hint: Option<TypeHint>,
}

/// The source-level return role, anchored to every SSA definition that reaches
/// the ABI result register.
///
/// Input and output registers overlap on ARM/AArch64 (`r0`/`x0`) and on x86
/// (`rax`). Keeping the reaching values here prevents a pointer-valued live-in
/// from contaminating later scalar writes, while still representing the one
/// source-level return type shared by branch-local definitions. This is the
/// same boundary modeled by Ghidra's `propagateAcrossReturns` and Kuna's port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredResult {
    pub values: Vec<SsaValue>,
    pub hint: Option<TypeHint>,
}

/// The source-level meaning of the ABI output storage after output-trial
/// recovery.
///
/// A return register is always live at the machine `RET`, but that does not
/// mean the source function returns it: a void function may leave its loop
/// index, last store value, or another scratch in the register. Ghidra's
/// `ActionReturnRecovery` and Kuna's port distinguish these cases before
/// building a function prototype. Keep the same distinction explicit here so
/// the renderer never has to infer it from a name such as `ret`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveredOutputKind {
    /// Prototype recovery did not run or lacks an architecture contract;
    /// preserve the legacy scalar rendering until stronger evidence exists.
    #[default]
    Unknown,
    /// No dedicated value is produced for the caller. Register contents at
    /// `RET` are residue from another operation.
    Void,
    /// One compatible source result is deliberately placed in ABI output
    /// storage.
    Direct,
    /// The ABI returns an aggregate through a caller-provided hidden pointer.
    /// Detection and storage detail are represented separately from `Direct`
    /// even while aggregate shape recovery remains incomplete.
    HiddenReturn,
}

/// Function prototype facts recovered before AST lowering.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveredPrototype {
    parameters: Vec<RecoveredParameter>,
    parameter_arity_locked: bool,
    locked_parameters: HashSet<usize>,
    result: Option<RecoveredResult>,
    output_kind: RecoveredOutputKind,
    output_locked: bool,
    /// Which ABI storage contract the result obeys — one register, a register
    /// pair, a split across banks, or a caller-provided buffer.
    ///
    /// Orthogonal to `output_kind`, and deliberately so: `output_kind` answers
    /// "is there a source result", this answers "where does it live". Conflating
    /// them is what left `HiddenReturn` a variant no code could construct.
    return_class: crate::ir::abi::ReturnClass,
    /// Float-bank slot -> the EXACT register spelling this function's machine
    /// code reads that storage under.
    ///
    /// Evidence, not a parameter list: a mixed integer/float signature whose
    /// source order cannot be proven keeps only its integer parameters (see
    /// `recover_prototype_with_arm_vfp_args`), and dropping the float bank's
    /// observed spelling with it is what left a declared `float` bound to a
    /// name the body never mentions. A declaration says WHICH ABI register a
    /// parameter occupies; only the body says which of that register's SSA
    /// identities (`xmm0` or its dword lane `xmm0_d0`) actually carries it.
    observed_float_storage: BTreeMap<usize, VReg>,
}

/// Source-ordered storage for a locked scalar AAPCS declaration.
///
/// This is deliberately a declaration projection, not another liveness pass.
/// Unknown types retain the ordinary core-bank default; known hard-float
/// scalars advance the independent VFP bank. A source parameter which cannot
/// be represented by this scalar register model is kept as `argN`, allowing
/// the outgoing-stack oracle to attach it at each call site without inventing
/// a register SSA identity.
fn locked_aapcs_parameter_storage(
    cc: crate::ir::call_args::CallConv,
    declared: &[Option<TypeHint>],
) -> Vec<VReg> {
    use crate::ir::call_args::CallConv;

    let mut core_slot = 0usize;
    let mut vfp_slot = 0usize;
    declared
        .iter()
        .copied()
        .enumerate()
        .map(|(source_slot, hint)| {
            if cc == CallConv::ArmHardFloat {
                match hint {
                    Some(TypeHint::Float { width: 4 }) => {
                        if vfp_slot < 16 {
                            let storage = VReg::phys(format!("s{vfp_slot}"));
                            vfp_slot += 1;
                            return storage;
                        }
                        return VReg::phys(format!("arg{source_slot}"));
                    }
                    Some(TypeHint::Float { width: 8 }) => {
                        vfp_slot += vfp_slot % 2;
                        if vfp_slot + 1 < 16 {
                            let storage = VReg::phys(format!("d{}", vfp_slot / 2));
                            vfp_slot += 2;
                            return storage;
                        }
                        return VReg::phys(format!("arg{source_slot}"));
                    }
                    _ => {}
                }
            }

            let core_width = match hint {
                Some(TypeHint::Int { width: 8, .. }) | Some(TypeHint::Float { width: 8 }) => 2,
                _ => 1,
            };
            if core_width == 2 {
                core_slot += core_slot % 2;
            }
            if core_slot + core_width <= 4 {
                let storage = VReg::phys(format!("r{core_slot}"));
                core_slot += core_width;
                storage
            } else {
                core_slot = 4;
                VReg::phys(format!("arg{source_slot}"))
            }
        })
        .collect()
}

/// Source-ordered storage for a locked scalar System V AMD64 declaration, or
/// `None` when this model cannot represent the signature exactly.
///
/// SysV allocates the INTEGER and SSE classes from two INDEPENDENT counters, so
/// `f(int a, float b, int c, float d)` puts `a` in `rdi`, `c` in `rsi`, `b` in
/// `xmm0` and `d` in `xmm1`. Source position is not the register index in
/// either bank. Without this projection, `apply_locked_parameters` falls back to
/// `abi::argument_registers(cc)[source_slot]` — a flat positional table that has
/// only the integer bank in it — and every `float` parameter is bound to the
/// integer register at its source position. `174_float_compare_classify::
/// sign_bit_of_binary32` recovered `Phys("rdi")` with `hint: Float { width: 4 }`
/// for a function whose whole body is `movd eax, xmm0; shr eax, 31`.
///
/// AGGREGATES FAIL CLOSED, and that is a decision rather than an omission. SysV
/// classifies each EIGHTBYTE of a struct independently, so
/// `struct { long a; double b; }` occupies `rdi` AND `xmm0` — one source
/// parameter drawing one slot from each bank. Two scalar counters cannot
/// express that. Every aggregate, `long double`, and vector type arrives here as
/// `None`, because `dwarf_return_hint_with_env` translates only the scalar
/// spellings the renderer can write exactly, and ONE `None` declines the WHOLE
/// signature: each parameter's bank index depends on the class of every
/// parameter before it, so a single unclassifiable one makes the rest guesses.
/// Declining returns the caller to its pre-existing positional behaviour, which
/// is wrong for floats but no more wrong than it already was — and never
/// silently splits an aggregate across the wrong two registers.
fn locked_sysv_amd64_parameter_storage(
    cc: crate::ir::call_args::CallConv,
    declared: &[Option<TypeHint>],
) -> Option<Vec<VReg>> {
    let integer_bank = crate::ir::abi::argument_registers(cc);
    let sse_bank = crate::ir::abi::sse_argument_registers(cc);
    let mut integer_slot = 0usize;
    let mut sse_slot = 0usize;
    declared
        .iter()
        .copied()
        .enumerate()
        .map(|(source_slot, hint)| {
            // A parameter beyond its bank is passed in memory. Keep the
            // canonical `argN` role so stack recovery can attach the concrete
            // value later, and — this is the part that matters — do NOT let it
            // consume a register from the other bank.
            let spill = || VReg::phys(format!("arg{source_slot}"));
            match hint? {
                // Both `float` and `double` occupy one whole SSE register.
                TypeHint::Float { width: 4 | 8 } => {
                    let storage = sse_bank
                        .get(sse_slot)
                        .map_or_else(spill, |register| VReg::phys(*register));
                    sse_slot += 1;
                    Some(storage)
                }
                // `long double` is x87 and MEMORY-class under SysV; a wider
                // "float" is a vector type that starts a different sequence.
                // Neither is this model's to place.
                TypeHint::Float { .. } => None,
                // An integer wider than one eightbyte is itself a two-register
                // allocation, the same shape as an aggregate.
                TypeHint::Int { width, .. } if width > 8 => None,
                TypeHint::Int { .. }
                | TypeHint::BoolLike
                | TypeHint::Pointer { .. }
                | TypeHint::CodePointer => {
                    let storage = integer_bank
                        .get(integer_slot)
                        .map_or_else(spill, |register| VReg::phys(*register));
                    integer_slot += 1;
                    Some(storage)
                }
            }
        })
        .collect()
}

/// Whether recovered storage denotes the ABI location a declaration asks for.
///
/// With no declared storage this is unconditionally true: conventions without a
/// class-aware projection keep their machine-recovered parameter exactly as
/// before. With one, a dword LANE counts as its parent. A scalar 32-bit
/// transfer (`movd eax, xmm0`) reads `xmm0_d0`, `regview::ssa_parent`
/// deliberately declines to merge that name with `xmm0`, and yet they are the
/// same bits of the same ABI register. Rejecting the lane would replace the
/// recovered parameter with a canonical `xmm0` the body never reads — trading
/// one undefined value for another, which is the AArch64 `d0`-versus-`s0`
/// problem wearing x86-64 spelling.
fn storage_denotes_declared_location(
    cc: crate::ir::call_args::CallConv,
    actual: &VReg,
    expected: Option<&VReg>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    match (actual, expected) {
        (VReg::Phys(actual), VReg::Phys(expected)) => {
            crate::ir::abi::touches_storage(cc, actual, expected)
        }
        _ => actual == expected,
    }
}

impl RecoveredPrototype {
    pub fn parameters(&self) -> &[RecoveredParameter] {
        &self.parameters
    }

    pub fn parameter(&self, slot: usize) -> Option<&RecoveredParameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.slot == slot)
    }

    /// Refine one recovered parameter through its exact entry-value identity.
    ///
    /// A caller that forwards an untouched ABI value to a callee with a
    /// recovered definition-site contract has stronger evidence than the
    /// transport register's machine width.  Keeping this operation value-keyed
    /// prevents a later scratch lifetime in the same physical register from
    /// inheriting the fact.  This does not lock arity: only declared/program
    /// contracts may do that.
    pub(crate) fn refine_parameter_hint_for_value(
        &mut self,
        value: &SsaValue,
        hint: TypeHint,
    ) -> bool {
        let Some(parameter) = self
            .parameters
            .iter_mut()
            .find(|parameter| &parameter.value == value)
        else {
            return false;
        };
        let before = parameter.hint;
        parameter.hint = Some(merge_type_hint(before, hint));
        parameter.hint != before
    }

    pub fn result(&self) -> Option<&RecoveredResult> {
        self.result.as_ref()
    }

    pub fn output_kind(&self) -> RecoveredOutputKind {
        self.output_kind
    }

    /// Which ABI storage contract this function's result obeys.
    ///
    /// Defaults to [`crate::ir::abi::ReturnClass::Single`], which is the one
    /// contract the value model has always assumed. Only a proven declared
    /// aggregate shape moves it (`crate::ir::return_class`).
    pub fn return_class(&self) -> crate::ir::abi::ReturnClass {
        self.return_class
    }

    /// Record a proven ABI result contract for a by-value aggregate.
    ///
    /// Separate from [`Self::apply_locked_output`] because the two facts are
    /// independent: the output KIND says whether a source result exists at all,
    /// while the CLASS says which registers carry it. A `Memory`-class result
    /// exists and is `HiddenReturn`; an `IntegerPair` exists and is `Direct`
    /// across two registers.
    pub(crate) fn apply_return_class(&mut self, class: crate::ir::abi::ReturnClass) {
        self.return_class = class;
    }

    /// Exact machine storage for a proven direct scalar output.
    ///
    /// Branch-local output trials may contribute several SSA values, but they
    /// must all occupy one physical result register. A locked identity function
    /// is the only no-definition exception: its first live-in parameter is also
    /// the result storage. Any disagreement remains unresolved instead of
    /// attaching a fabricated return operand.
    fn direct_return_storage(
        &self,
        function: &LlirFunction,
        cc: crate::ir::call_args::CallConv,
    ) -> Option<VReg> {
        if self.output_kind != RecoveredOutputKind::Direct {
            return None;
        }
        let result = self.result.as_ref()?;
        if let Some(first) = result.values.first() {
            if result.values.iter().all(|value| value.base == first.base) {
                return Some(first.base.clone());
            }
            return None;
        }
        if !self.output_locked || !self.parameter_arity_locked {
            return None;
        }
        let parameter = self.parameter(0)?;
        let VReg::Phys(parameter_name) = &parameter.value.base else {
            return None;
        };
        let class = crate::ir::abi::return_register_class(cc, parameter_name)?;
        let class_is_written = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter_map(|instruction| def_uses(&instruction.op).0)
            .any(|definition| {
                matches!(definition, VReg::Phys(name) if class.contains(&crate::ir::abi::ssa_base(&name)))
            });
        (!class_is_written).then(|| parameter.value.base.clone())
    }

    pub(crate) fn output_is_locked(&self) -> bool {
        self.output_locked
    }

    pub(crate) fn parameter_arity_is_locked(&self) -> bool {
        self.parameter_arity_locked
    }

    pub(crate) fn parameter_is_locked(&self, slot: usize) -> bool {
        self.locked_parameters.contains(&slot)
    }

    /// Apply source-level type evidence without claiming a complete arity.
    ///
    /// Format strings and similar use sites can identify the type of an
    /// already-recovered parameter, but absence from that evidence does not
    /// prove that later parameters do not exist.
    pub(crate) fn apply_parameter_hints(&mut self, hints: &[Option<TypeHint>]) {
        for parameter in &mut self.parameters {
            let Some(incoming) = hints.get(parameter.slot).copied().flatten() else {
                continue;
            };
            // A verified format conversion is source-contract evidence.  It
            // overrides the body heuristic for this exact parameter just as a
            // declared type would, while leaving the parameter list unlocked.
            parameter.hint = Some(incoming);
            self.locked_parameters.insert(parameter.slot);
        }
    }

    /// Replace heuristic live-ins with an authoritative declared parameter list.
    ///
    /// Optimized code routinely reuses every argument register as scratch. The
    /// source declaration owns arity and types when DWARF/PDB provides them;
    /// machine-code recovery still supplies exact SSA identities where they
    /// exist and ABI entry storage supplies missing integer-register values.
    pub(crate) fn apply_locked_parameters(
        &mut self,
        cc: crate::ir::call_args::CallConv,
        declared: &[Option<TypeHint>],
    ) {
        // BTreeMap rather than HashMap: the recovered-spelling search below
        // scans every prior parameter, and a HashMap's iteration order is not
        // reproducible between runs. A prototype that differs run to run is the
        // determinism failure Entry 20 exists to prevent.
        let prior = std::mem::take(&mut self.parameters)
            .into_iter()
            .map(|parameter| (parameter.slot, parameter))
            .collect::<BTreeMap<_, _>>();
        let abi_registers = crate::ir::abi::argument_registers(cc);
        // AAPCS-VFP has independent core and VFP allocation banks. A heuristic
        // live-in `sN` is useful while the source type is unknown, but it
        // cannot remain the storage of a DWARF/PDB-locked integer parameter.
        // Compute declared storage in source order; parameters beyond the
        // available register bank retain their `argN` source role until call-
        // site stack recovery attaches the concrete outgoing value.
        let aapcs_storage = matches!(
            cc,
            crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat
        )
        .then(|| locked_aapcs_parameter_storage(cc, declared));
        // x86-64 SysV has the same two-independent-banks shape, with the same
        // consequence when it is missing: the positional fallback below reaches
        // into `argument_registers`, which holds only the INTEGER bank, and
        // hands a `float` parameter the integer register at its source
        // position. Unlike the AAPCS projection this one may DECLINE (see
        // `locked_sysv_amd64_parameter_storage`); declining leaves the
        // pre-existing positional behaviour exactly as it was.
        let sysv_storage = (cc == crate::ir::call_args::CallConv::SysVAmd64)
            .then(|| locked_sysv_amd64_parameter_storage(cc, declared))
            .flatten();
        self.parameters = declared
            .iter()
            .copied()
            .enumerate()
            .map(|(slot, declared_hint)| {
                let declared_storage = aapcs_storage
                    .as_ref()
                    .or(sysv_storage.as_ref())
                    .and_then(|storage| storage.get(slot))
                    .cloned();
                if let Some(mut parameter) = prior.get(&slot).cloned() {
                    if storage_denotes_declared_location(
                        cc,
                        &parameter.value.base,
                        declared_storage.as_ref(),
                    ) {
                        if declared_hint.is_some() {
                            parameter.hint = declared_hint;
                        }
                        return parameter;
                    }
                }
                // The declaration named an ABI register; the machine code may
                // have been recovered as reading it under a different SSA
                // identity, and filed at a different heuristic slot. Prefer the
                // observed identity over the canonical name — a parameter bound
                // to `xmm0` in a body that only ever reads `xmm0_d0` is an
                // undefined value with a tidier name.
                if let Some(expected) = declared_storage.as_ref() {
                    // A parameter recovered at some other heuristic slot first:
                    // it carries a real SSA version as well as a spelling.
                    let recovered = prior
                        .values()
                        .find(|parameter| {
                            storage_denotes_declared_location(
                                cc,
                                &parameter.value.base,
                                Some(expected),
                            )
                        })
                        .map(|parameter| parameter.value.clone())
                        // Otherwise the float-bank live-in scan's evidence,
                        // which survives even when a mixed signature's source
                        // order could not be proven and its float parameters
                        // were dropped. Entry storage is version zero.
                        .or_else(|| {
                            self.observed_float_storage
                                .values()
                                .find(|storage| {
                                    storage_denotes_declared_location(cc, storage, Some(expected))
                                })
                                .cloned()
                                .map(|base| SsaValue { base, version: 0 })
                        });
                    if let Some(value) = recovered {
                        return RecoveredParameter {
                            slot,
                            value,
                            hint: declared_hint,
                        };
                    }
                }
                let storage = declared_storage
                    .or_else(|| {
                        abi_registers
                            .get(slot)
                            .map(|register| VReg::phys(*register))
                    })
                    // Stack-passed parameters acquire this same canonical role
                    // when stack promotion resolves their positive entry-frame
                    // offset. Retain the declared slot now so the arity lock
                    // does not suppress that later recovery.
                    .unwrap_or_else(|| VReg::phys(format!("arg{slot}")));
                RecoveredParameter {
                    slot,
                    value: SsaValue {
                        base: storage,
                        version: 0,
                    },
                    hint: declared_hint,
                }
            })
            .collect();
        self.parameter_arity_locked = true;
        self.locked_parameters = declared
            .iter()
            .enumerate()
            .filter_map(|(slot, hint)| hint.map(|_| slot))
            .collect();
    }

    /// Apply an authoritative source-level output contract.
    ///
    /// Ghidra keeps a type-locked function output intact during return
    /// recovery, and Kuna carries the same policy. Machine-code output trials
    /// remain responsible for stripped binaries; a declared DWARF/PDB contract
    /// is allowed to disambiguate identical store-and-return/store-only shapes.
    pub(crate) fn apply_locked_output(
        &mut self,
        output_kind: RecoveredOutputKind,
        hint: Option<TypeHint>,
    ) {
        match output_kind {
            RecoveredOutputKind::Direct => {
                let prior = self.result.take();
                self.result = Some(RecoveredResult {
                    values: prior
                        .as_ref()
                        .map(|result| result.values.clone())
                        .unwrap_or_default(),
                    hint: hint.or_else(|| prior.and_then(|result| result.hint)),
                });
                self.output_kind = RecoveredOutputKind::Direct;
                self.output_locked = true;
            }
            RecoveredOutputKind::Void => {
                self.result = None;
                self.output_kind = RecoveredOutputKind::Void;
                self.output_locked = true;
            }
            // A proven MEMORY-class aggregate: the caller allocated the object
            // and the callee returns its address in the result register. The
            // machine result stays exactly as recovered — that address IS what
            // the register holds — so this records the contract without
            // changing a single spelling. Marking it is what lets a consumer
            // distinguish "a value in a register" from "an address of the
            // caller's buffer" instead of inferring it from a size.
            RecoveredOutputKind::HiddenReturn => {
                if let Some(hint) = hint {
                    if let Some(result) = self.result.as_mut() {
                        result.hint = Some(hint);
                    }
                }
                self.output_kind = RecoveredOutputKind::HiddenReturn;
                self.output_locked = true;
            }
            // An unresolved declaration is a fact gap, not permission to
            // discard the machine-code result.
            RecoveredOutputKind::Unknown => {}
        }
    }

    /// Project semantic parameter slots to the renderer's source-level role
    /// names.  This is the only name projection: it does not inspect the AST or
    /// reconstruct a register alias table after naming has already run.
    pub fn parameter_type_map(&self) -> TypeMap {
        let mut out = TypeMap::default();
        for parameter in &self.parameters {
            if let Some(hint) = parameter.hint {
                let role = VReg::phys(format!("arg{}", parameter.slot));
                if self.parameter_is_locked(parameter.slot) {
                    out.apply_locked_fact(role, hint);
                } else {
                    out.upsert_public(role, hint);
                }
            }
        }
        out
    }

    /// Machine storage names for the exact live-in values represented by this
    /// prototype. Integer-only ABIs derive the same mapping from their slot
    /// tables; keeping it on the prototype also represents disjoint storage
    /// classes such as AAPCS VFP `s0` without pretending it aliases `r0`.
    pub fn parameter_role_map(&self) -> HashMap<String, usize> {
        self.parameters
            .iter()
            .filter_map(|parameter| match &parameter.value.base {
                VReg::Phys(name) => Some((name.clone(), parameter.slot)),
                _ => None,
            })
            .collect()
    }

    /// Project the exact SSA output to the renderer's source-level return role.
    pub fn result_type_map(&self) -> TypeMap {
        let mut out = TypeMap::default();
        if let Some(RecoveredResult {
            hint: Some(hint), ..
        }) = &self.result
        {
            out.upsert_public(VReg::phys("ret"), *hint);
        }
        out
    }
}

/// Replace operand-free machine returns with prototype-proven direct values.
///
/// This runs before final SSA. Each return therefore receives the exact
/// branch-local reaching version through the ordinary def/use machinery; AST
/// lowering and emitted-local verification consume that same identity without
/// rescanning for a register name or a last writer.
pub(crate) fn materialize_return_values(
    function: &mut LlirFunction,
    cc: crate::ir::call_args::CallConv,
    prototype: &RecoveredPrototype,
) -> usize {
    let Some(storage) = prototype.direct_return_storage(function, cc) else {
        return 0;
    };
    let mut changed = 0;
    for instruction in function
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.instrs)
    {
        let replacement = match &instruction.op {
            Op::Return => Some(Op::ReturnValue {
                value: Value::Reg(storage.clone()),
            }),
            Op::CondReturn { cond, inverted } => Some(Op::CondReturnValue {
                cond: cond.clone(),
                inverted: *inverted,
                value: Value::Reg(storage.clone()),
            }),
            _ => None,
        };
        if let Some(replacement) = replacement {
            instruction.op = replacement;
            changed += 1;
        }
    }
    changed
}

fn abi_pointer_width(cc: crate::ir::call_args::CallConv) -> u8 {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => 4,
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64 => 8,
    }
}

/// Constrain a result fact to the ABI container when the architecture-neutral
/// register-name table cannot determine a narrower width. This matters for
/// 32-bit ARM `r0`..`r3`, whose names intentionally do not collide with x86's
/// `r8`.. register family in [`crate::ir::types::phys_reg_width`].
fn normalize_value_hint_for_abi(hint: TypeHint, cc: crate::ir::call_args::CallConv) -> TypeHint {
    match hint {
        TypeHint::Int { signed, width } => TypeHint::Int {
            signed,
            width: width.min(abi_pointer_width(cc)),
        },
        _ => hint,
    }
}

/// Recover the function's parameter prototype directly from SSA live-ins.
///
/// The raw-register pass still supplies machine-width evidence while the
/// value-keyed pass may provide a stronger, output-qualified classification.
/// Both are joined *before* lowering.  Subsequent AST rewriting and naming can
/// no longer change which machine value a parameter type describes.
pub fn recover_prototype(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    cc: crate::ir::call_args::CallConv,
    param_slots: &HashSet<usize>,
) -> RecoveredPrototype {
    recover_prototype_with_arm_vfp_args(lf, ssa, cc, param_slots, false)
}

/// Recover storage width from the actual architectural views that read one
/// version-zero parameter value.
///
/// SSA deliberately canonicalizes `rsi` and `esi` to the same storage identity,
/// but their operand widths still carry source-prototype evidence.  Only uses of
/// version zero participate here: a later `mov esi, 1` before a recursive call
/// defines a new value and cannot narrow the incoming `%rsi` parameter.
fn live_in_parameter_view_hint(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    value: &SsaValue,
    raw: &TypeMap,
    cc: crate::ir::call_args::CallConv,
) -> Option<TypeHint> {
    // Architectural reads (a real machine operand) and speculative ABI reads
    // (the argument-register may-use list `abi::annotate_calls` hangs on every
    // call) are accumulated separately. See `use_is_proven_input`.
    let mut real = (0u8, Vec::new());
    let mut speculative = (0u8, Vec::new());
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let (_, uses) = def_uses(&instruction.op);
            for (use_index, register) in uses.iter().enumerate() {
                if ssa.use_value(lf, addr, use_index).as_ref() != Some(value) {
                    continue;
                }
                let bucket = if use_is_proven_input(&instruction.op, use_index) {
                    &mut real
                } else {
                    &mut speculative
                };
                let width = reg_width_bytes(register);
                if width < bucket.0 {
                    continue;
                }
                if width > bucket.0 {
                    bucket.0 = width;
                    bucket.1.clear();
                }
                if let Some(hint) = raw.get(register).filter(|hint| {
                    !matches!(
                        (cc, hint),
                        (
                            crate::ir::call_args::CallConv::Arm
                                | crate::ir::call_args::CallConv::ArmHardFloat,
                            TypeHint::Pointer { .. } | TypeHint::CodePointer
                        )
                    )
                }) {
                    // ARM raw-register pointer class is deliberately excluded
                    // at this exact-value boundary. A later address-bearing
                    // lifetime in the same physical r0-r3 register can
                    // otherwise retype an earlier scalar read; ARM has no
                    // narrow aliases to separate those lifetimes. Qualified
                    // pointer evidence still arrives first through
                    // `parameter_refinement`. Other ABIs retain their
                    // alias-specific raw pointer evidence here.
                    bucket.1.push(hint);
                }
            }
        }
    }
    // A real read is evidence of the source width; the ABI annotation is only a
    // convention-wide placeholder, so it decides nothing unless it is all there
    // is. Without this split every parameter of every function that calls
    // anything was widened to the machine word and rendered `long`.
    let (widest, widest_hints) = if real.0 > 0 { real } else { speculative };
    if widest == 0 {
        return None;
    }
    let hint = widest_hints
        .into_iter()
        .fold(None, |current, hint| Some(merge_type_hint(current, hint)))
        .unwrap_or(TypeHint::Int {
            signed: true,
            width: widest,
        });
    Some(match hint {
        TypeHint::Int { signed, .. } => TypeHint::Int {
            signed,
            width: widest,
        },
        other => other,
    })
}

/// Return address-class evidence attached to the exact ARM live-in value.
///
/// ARM32 has no architectural subregister aliases for r0-r3, so the raw
/// register map cannot distinguish a caller-supplied address from a later
/// scratch lifetime in the same register. Value-keyed recovery can: it marks
/// only the SSA definition actually consumed as an address. Keep this narrow
/// to address classes; ordinary scalar width still comes from architectural
/// views and is normalized at the ABI boundary.
fn arm_live_in_address_hint(
    valued: &TypeMapV,
    value: &SsaValue,
    cc: crate::ir::call_args::CallConv,
) -> Option<TypeHint> {
    if !matches!(
        cc,
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat
    ) {
        return None;
    }
    valued
        .get(value)
        .filter(|hint| matches!(hint, TypeHint::Pointer { .. } | TypeHint::CodePointer))
}

/// Whether every apparent return is the structural terminator of a proven
/// tail call to a declared-void callee.
///
/// LLIR represents a nonlocal tail transfer as `Call + Return` so ordinary CFG
/// and structuring consumers see a closed block. That `Return` is not a machine
/// observation of the caller's result register. Without the explicit tail and
/// void-result facts, a definition from an earlier unrelated call can appear to
/// reach it and invent a scalar source result.
fn all_returns_are_known_void_tail_calls(function: &LlirFunction) -> bool {
    let mut saw_return = false;
    for block in &function.blocks {
        for (index, instruction) in block.instrs.iter().enumerate() {
            if !instruction.op.is_return() {
                continue;
            }
            saw_return = true;
            let known_void_tail = index.checked_sub(1).is_some_and(|call_index| {
                matches!(
                    &block.instrs[call_index].op,
                    Op::Call {
                        effects: Some(effects),
                        ..
                    } if effects.is_tail_call && !effects.result_is_source_value
                )
            });
            if !known_void_tail {
                return false;
            }
        }
    }
    saw_return
}

/// Recover a prototype with the binary-level ARM VFP argument contract.
///
/// VFP and core-register allocation are independent, so stripped mixed-class
/// signatures are not order-identifiable from one function in isolation. The
/// current sound subset accepts only contiguous `s0..sN` live-ins when no core
/// argument register is live; pure-float functions are exact and mixed
/// signatures remain conservatively on the established core-register path.
pub fn recover_prototype_with_arm_vfp_args(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    cc: crate::ir::call_args::CallConv,
    param_slots: &HashSet<usize>,
    arm_vfp_args: bool,
) -> RecoveredPrototype {
    let raw = recover_types_for(lf, cc);
    let valued = recover_types_valued(lf, ssa);
    let observable_parameter_widths =
        crate::ir::prototype_width::ObservableParameterWidths::analyze(lf, ssa, cc);
    let slots = crate::ir::abi::argument_slots(cc);
    let canonical = crate::ir::abi::argument_registers(cc);
    let mut ordered: Vec<usize> = param_slots.iter().copied().collect();
    ordered.sort_unstable();

    let va_to_idx: HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect();
    // `RET` has no explicit operand in this LLIR, so an output trial is the
    // return-register definition that reaches it and has no other explicit
    // consumer. A definition also consumed by a store/comparison is ordinary
    // residue, exactly the case Ghidra rejects with `ancestorOpUse` and Kuna
    // rejects with `ancestor_op_use`.
    let mut definitions = HashMap::new();
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, _ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            if let Some(value) = ssa.def_value(lf, addr) {
                definitions.insert(value, addr);
            }
        }
    }
    let non_return_live = non_return_live_values(lf, ssa);
    let mut direct_values = Vec::new();
    let mut qualified_values = Vec::new();
    let mut direct_facts = Vec::new();
    let mut direct_storage_classes = HashSet::new();
    let mut has_unsupported_output_trial = false;
    let mut has_packed_zero_bridge_trial = false;
    // Ghidra's ParamEntry model and Kuna's port allocate general-purpose and
    // floating-point results from distinct resource sections. Scan them
    // independently as well: a write to `rax` must not kill a reaching `xmm0`
    // definition (or vice versa), and observing both is aggregate evidence.
    for (ret_names, storage_class) in [
        (return_reg_names(cc), ResultHintClass::Integer),
        (float_return_reg_names(cc), ResultHintClass::Float),
    ] {
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, ins) in block.instrs.iter().enumerate() {
                let (Some(VReg::Phys(dst)), _) = def_uses(&ins.op) else {
                    continue;
                };
                if !ret_names.contains(&dst.as_str())
                    || !crate::ir::value_number::def_reaches_return(
                        lf, ret_names, &va_to_idx, block_idx, instr_idx,
                    )
                {
                    continue;
                }
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let Some(value) = ssa.def_value(lf, addr) else {
                    continue;
                };
                // The whole-register view `lift_x86::synchronise_xmm_views`
                // appends after a packed lane write is not a value this
                // function produced — it is the lanes it just wrote, under
                // their other name. Offering it as an output trial made every
                // vectorised `void` function (clang -O2 `mem_copy`) report an
                // unknown result where it had correctly reported none.
                if matches!(
                    &ins.op,
                    Op::Concat {
                        dst: VReg::Phys(name),
                        hi: Value::Reg(VReg::Phys(hi)),
                        lo: Value::Reg(VReg::Phys(lo)),
                    } if hi == &format!("{name}_d1") && lo == &format!("{name}_d0")
                ) {
                    continue;
                }
                let guarded_call_result =
                    call_result_has_only_guard_uses(lf, ssa, &value, &definitions);
                let is_direct =
                    output_trial_is_dedicated(lf, ssa, &value, &definitions, &non_return_live)
                        || guarded_call_result;
                if !is_direct {
                    continue;
                }
                let hint = qualified_result_hint(&ins.op, &valued, &value, cc, storage_class)
                    .or_else(|| {
                        (guarded_call_result && storage_class == ResultHintClass::Integer)
                            .then_some(TypeHint::Int {
                                signed: true,
                                width: abi_pointer_width(cc),
                            })
                    });
                if storage_class == ResultHintClass::Float && hint.is_none() {
                    // PXOR self-zeroing defines both the whole XMM name and
                    // its four scalar-LLIR lanes at one machine VA. The whole
                    // definition is a representation bridge for MOVAPS stores,
                    // not a competing floating result when a qualified integer
                    // return also exists (e.g. clang's vectorized int sum).
                    let packed_zero_bridge = matches!(
                        &ins.op,
                        Op::Assign {
                            dst: VReg::Phys(name),
                            src: Value::Const(0),
                        } if name.starts_with("xmm")
                            && !name.contains("_d")
                            && (0..4).all(|lane| block.instrs.iter().any(|candidate| {
                                candidate.va == ins.va
                                    && matches!(
                                        &candidate.op,
                                        Op::Assign {
                                            dst: VReg::Phys(lane_name),
                                            src: Value::Const(0),
                                        } if lane_name == &format!("{name}_d{lane}")
                                    )
                            }))
                    );
                    if packed_zero_bridge {
                        has_packed_zero_bridge_trial = true;
                    } else {
                        has_unsupported_output_trial = true;
                    }
                }
                if let Some(hint) = hint {
                    let is_literal_null = matches!(
                        &ins.op,
                        Op::Assign {
                            src: Value::Const(0),
                            ..
                        }
                    );
                    direct_facts.push((hint, is_literal_null));
                    direct_storage_classes.insert(storage_class);
                    if !qualified_values.contains(&value) {
                        qualified_values.push(value.clone());
                    }
                }
                if !direct_values.contains(&value) {
                    direct_values.push(value);
                }
            }
        }
    }
    // A function has one source-level result type even when control flow has
    // several return sites. Join the qualified facts across their exact SSA
    // definitions instead of selecting an arbitrary branch or discarding the
    // role. The compatibility join lets pointer evidence type an exact null
    // branch, while refusing to turn an unrelated nonzero scalar into a
    // pointer merely because it shares the ABI result register.
    // Incidental candidates are rejected trials, not conflicting source
    // results. One dedicated trial is therefore sufficient to establish a
    // direct output even if unsupported instructions leave unrelated return-
    // register residue visible on another path.
    let has_machine_return = lf
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .any(|instruction| instruction.op.is_return());
    // ARM32 still lowers broad VFP/DSP instruction families through the
    // footprint-free migration fallback.  Unlike the x86 path (where SIMD
    // arithmetic used for outputs is footprinted above), absence of an ARM
    // result trial in the presence of such an op is not trustworthy.
    let has_opaque_semantics = matches!(
        cc,
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat
    ) && lf.blocks.iter().flat_map(|block| &block.instrs).any(
        |instruction| {
            matches!(
                &instruction.op,
                Op::Intrinsic {
                    ins,
                    outs,
                    reads_mem: true,
                    writes_mem: true,
                    ..
                } if ins.is_empty() && outs.is_empty()
            )
        },
    );
    // An ABI-wide call annotation uses the general-purpose result register
    // when the callee prototype is unknown. That synthetic write is not
    // allowed to conflict with a semantically qualified float definition.
    // Prefer qualified trials when any exist; retain unqualified trials only
    // as the fail-closed legacy result when no class could be established.
    let result_values = if qualified_values.is_empty() {
        direct_values
    } else {
        qualified_values
    };
    has_unsupported_output_trial |=
        has_packed_zero_bridge_trial && !direct_storage_classes.contains(&ResultHintClass::Integer);
    let output_kind = if all_returns_are_known_void_tail_calls(lf) {
        RecoveredOutputKind::Void
    } else {
        match (
            has_machine_return,
            result_values.is_empty(),
            has_unsupported_output_trial || direct_storage_classes.len() > 1,
            has_opaque_semantics,
        ) {
            // A tail-call wrapper, a source-level non-returning function, and an
            // incomplete CFG all have no machine RET. None provides evidence for
            // `void`; keep the source result unknown until call/prototype recovery
            // can distinguish them.
            (false, _, _, _) => RecoveredOutputKind::Unknown,
            // Mixed integer/FP storage can be an aggregate result.  Until that
            // source shape is representable, guessing either half is unsound.
            (true, _, true, _) => RecoveredOutputKind::Unknown,
            // A footprint-free intrinsic is a fact gap, not evidence that no
            // result exists.  A dedicated modeled return trial can still prove a
            // direct result; without one, fail closed rather than inventing void.
            (true, true, false, true) => RecoveredOutputKind::Unknown,
            (true, true, false, false) => RecoveredOutputKind::Void,
            (true, false, false, _) => RecoveredOutputKind::Direct,
        }
    };
    let result = match output_kind {
        RecoveredOutputKind::Direct => Some(RecoveredResult {
            values: result_values,
            hint: join_result_hints(&direct_facts),
        }),
        RecoveredOutputKind::Unknown
        | RecoveredOutputKind::Void
        | RecoveredOutputKind::HiddenReturn => None,
    };

    let mut parameters: Vec<RecoveredParameter> = ordered
        .into_iter()
        .filter_map(|slot| {
            let base = canonical.get(slot).map(|name| VReg::phys(*name))?;
            let value = SsaValue { base, version: 0 };
            let raw_hint = slots.get(slot).and_then(|aliases| {
                aliases.iter().fold(None, |current, alias| {
                    raw.get(&VReg::phys(*alias))
                        .map(|candidate| merge_type_hint(current, candidate))
                        .or(current)
                })
            });
            // `r0`..`r3` have no narrower register aliases on ARM32, so the
            // architecture-neutral raw pass falls back to an eight-byte int.
            // The AAPCS register container is only four bytes. Apply the same
            // ABI boundary used for result values before this fact crosses
            // into the source-level prototype.
            let hint = valued
                .parameter_refinement(&value)
                .or_else(|| arm_live_in_address_hint(&valued, &value, cc))
                .or_else(|| live_in_parameter_view_hint(lf, ssa, &value, &raw, cc))
                .or(raw_hint)
                .map(|hint| normalize_value_hint_for_abi(hint, cc))
                .map(|hint| observable_parameter_widths.refine(&value, hint));
            Some(RecoveredParameter { slot, value, hint })
        })
        .collect();
    let mut observed_float_storage: BTreeMap<usize, VReg> = BTreeMap::new();
    // AAPCS-VFP has to be asked for (`arm_vfp_args`) because the same ARM
    // convention enum covers soft-float builds, where `s0` is not a parameter
    // at all. The x86-64 conventions have no such variant: SSE arguments are
    // the only way a `float` or `double` is passed, so the bank is always live
    // and needs no opt-in. Without this, every float parameter on x86-64 was an
    // undefined live-in and the whole float corpus assigned `local_4 = var0`
    // where `local_4 = arg0` belonged.
    // AAPCS64 needs no opt-in either: unlike ARM32 there is no soft-float
    // variant of the convention, so `v0`-`v7` are always the float bank.
    let float_bank_applies = has_float_argument_bank(cc)
        && (arm_vfp_args
            || matches!(
                cc,
                crate::ir::call_args::CallConv::SysVAmd64
                    | crate::ir::call_args::CallConv::Win64
                    | crate::ir::call_args::CallConv::Aarch64
            ));
    if float_bank_applies {
        let float_register = |slot: usize, observed: String| match cc {
            // `d0` and `s0` are different SSA identities for the same AAPCS64
            // register, so the parameter must carry the spelling the body
            // actually reads or every use of it stays undefined. x86-64 has the
            // same problem in its own spelling: `xmm0` and its dword lane
            // `xmm0_d0` are unrelated SSA identities, and a function whose only
            // parameter instruction is `movd eax, xmm0` reads ONLY the lane.
            crate::ir::call_args::CallConv::SysVAmd64
            | crate::ir::call_args::CallConv::Win64
            | crate::ir::call_args::CallConv::Aarch64
                if !observed.is_empty() =>
            {
                observed
            }
            crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
                format!("xmm{slot}")
            }
            _ => format!("s{slot}"),
        };
        // Width four is a floor, not a claim: `s0` IS binary32 under AAPCS, and
        // on x86-64 an `xmm` live-in is at least a `float`. A `double`
        // parameter is corrected by the DWARF contract when one is available
        // and by the arithmetic that consumes it otherwise. AArch64 is the one
        // case that does not have to guess: the register spelling states the
        // width, `d0` being binary64 exactly as `s0` is binary32.
        let vfp_parameters: Vec<RecoveredParameter> = float_live_in_slots(lf, cc)
            .into_iter()
            .map(|(slot, observed)| {
                let width = if observed.starts_with('d') { 8 } else { 4 };
                RecoveredParameter {
                    slot,
                    value: SsaValue {
                        base: VReg::phys(float_register(slot, observed)),
                        version: 0,
                    },
                    hint: Some(TypeHint::Float { width }),
                }
            })
            .collect();
        // Record the observed storage BEFORE the source-order decision below
        // can discard it. Which ABI register a declared parameter occupies is
        // the declaration's to say; which SSA identity of that register the
        // body reads is only knowable here, and a mixed signature whose order
        // cannot be proven throws the float parameters away.
        observed_float_storage = vfp_parameters
            .iter()
            .map(|parameter| (parameter.slot, parameter.value.base.clone()))
            .collect();

        if parameters.is_empty() {
            // Pure-float signatures are ordered directly by their contiguous
            // bank allocation, exactly as before.
            parameters = vfp_parameters;
        } else if !vfp_parameters.is_empty() {
            // The two AAPCS storage classes do not by themselves identify
            // source order.  Interleave them only when the entry's concrete
            // spill sequence proves one order.
            let candidates: Vec<VReg> = parameters
                .iter()
                .chain(&vfp_parameters)
                .map(|parameter| parameter.value.base.clone())
                .collect();
            if let Some(source_order) = mixed_entry_spill_order(lf, cc, &candidates) {
                let mut by_register: HashMap<VReg, RecoveredParameter> = parameters
                    .into_iter()
                    .chain(vfp_parameters)
                    .map(|parameter| (parameter.value.base.clone(), parameter))
                    .collect();
                parameters = source_order
                    .into_iter()
                    .enumerate()
                    .filter_map(|(slot, register)| {
                        by_register.remove(&register).map(|mut parameter| {
                            parameter.slot = slot;
                            parameter
                        })
                    })
                    .collect();
            }
        }
    }
    parameters.sort_by_key(|parameter| parameter.slot);
    RecoveredPrototype {
        parameters,
        parameter_arity_locked: false,
        locked_parameters: HashSet::new(),
        result,
        output_kind,
        output_locked: false,
        return_class: crate::ir::abi::ReturnClass::Single,
        observed_float_storage,
    }
}

/// The byte width a physical register name implies (`edi`->4, `rdi`->8,
/// `w0`->4, `x0`->8, `di`->2, `dil`->1). Falls back to 8 for unknown names.
fn reg_width_bytes(v: &VReg) -> u8 {
    if let VReg::Phys(n) = v {
        // Value numbering appends `#version` to the architectural spelling.
        // Width belongs to the storage view, not to the SSA identity:
        // `xmm0_d0#3` is still one 32-bit lane. Passing the tagged spelling to
        // `phys_reg_width` misses and falls back to eight bytes, silently
        // widening every numbered SIMD lane to `long`.
        if let Some(w) = crate::ir::types::phys_reg_width(crate::ir::abi::ssa_base(n)) {
            return (w.bits() / 8).max(1) as u8;
        }
    }
    8
}

/// A signed integer hint whose width comes from the register's sub-name. This
/// is the single biggest type-recovery signal at `-O0`: an `int` argument is
/// spilled through the 32-bit view (`edi`/`w0`) while a `long`/pointer uses the
/// 64-bit view (`rdi`/`x0`).
fn int_for_reg(v: &VReg) -> TypeHint {
    TypeHint::Int {
        signed: true,
        width: reg_width_bytes(v),
    }
}

/// Produce a [`TypeMap`] for all register VRegs touched by `lf`.
pub fn recover_types(lf: &LlirFunction) -> TypeMap {
    let mut tm = TypeMap::default();

    // First pass: gather registers that ever receive a plain constant
    // assignment (`%rax = 0`, `%rdi = 42`, …). Any such register cannot be
    // a stable pointer or code-pointer — the pointer classification is
    // noise from an unrelated use-site and would produce `(fnptr)%ret = 0;`
    // style output. We'll use this to post-process the map below.
    let mut gets_const: std::collections::HashSet<VReg> = std::collections::HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Assign {
                dst,
                src: Value::Const(_),
            } = &ins.op
            {
                gets_const.insert(dst.clone());
            }
        }
    }

    for block in &lf.blocks {
        for ins in &block.instrs {
            // Width-from-register-name for every value register (specific
            // classifications below still win via `upsert`).
            tag_value_regs(&ins.op, &mut tm);
            match &ins.op {
                // Any register used as the base of a memory op is a pointer.
                Op::Load { addr, .. }
                | Op::CondLoad { addr, .. }
                | Op::Store { addr, .. }
                | Op::CondStore { addr, .. } => {
                    if let Some(b) = &addr.base {
                        tm.upsert(
                            b.clone(),
                            TypeHint::Pointer {
                                pointee_width: addr.size.max(1),
                            },
                        );
                    }
                    if let Some(i) = &addr.index {
                        // Index registers are unsigned integers (array offsets).
                        tm.upsert(
                            i.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(i),
                            },
                        );
                    }
                }
                // A logical right shift is an unsigned operation on its value;
                // the count is unsigned for every shift family. This distinction
                // is executable semantics, not a source-style guess: widening a
                // 32-bit `shr` operand as signed changes negative inputs into a
                // 64-bit all-ones prefix and doubles the loop trip count.
                Op::Bin {
                    dst,
                    op: BinOp::Shr,
                    lhs,
                    rhs,
                } => {
                    if matches!(dst, VReg::Phys(_)) {
                        tm.upsert(
                            dst.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(dst),
                            },
                        );
                    }
                    if let Value::Reg(r) = lhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(r),
                            },
                        );
                    }
                    if let Value::Reg(r) = rhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(r),
                            },
                        );
                    }
                }
                // Shift counts are unsigned integers.
                Op::Bin {
                    op: BinOp::Shl | BinOp::Sar,
                    rhs,
                    ..
                } => {
                    if let Value::Reg(r) = rhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(r),
                            },
                        );
                    }
                }
                // Indirect call target → code pointer.
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Reg(r)),
                    ..
                } => {
                    tm.upsert(r.clone(), TypeHint::CodePointer);
                }
                // Default: arithmetic-producing binops leave the result a
                // generic signed 8-byte int unless something more specific
                // promotes it later.
                Op::Bin { dst, .. } => {
                    if let VReg::Phys(_) = dst {
                        tm.upsert(dst.clone(), classify_int_default());
                    }
                }
                _ => {}
            }
        }
    }

    // Propagate pointer-ness from a stack slot back to the register spilled
    // into it. At `-O0` a pointer *argument* is spilled to a frame slot
    // (`store [rbp-8] = rdi`) in the prologue and every later dereference goes
    // through a *reload* of that slot into a scratch register — so the pointer
    // classification lands on the reloaded temp, never on the incoming argument
    // register. Link them: `reg -> slot` (the spill) and `slot -> pointer`
    // (a reload of that slot that is itself a pointer), then tag the spilled
    // register as the pointer. This is what recovers `T *` argument types.
    // Address arithmetic first (`p = base + i` with `*p` -> `base` is a pointer),
    // then spill-slot propagation (a slot reloaded into a pointer is a pointer,
    // and so is the argument spilled into it) — so a pointer parameter used as
    // `*(param + i*scale)` resolves through the reload to the parameter. Iterated
    // together so either order of discovery converges.
    for _ in 0..4 {
        propagate_pointer_arithmetic(lf, &mut tm);
        propagate_spill_slot_pointers(lf, &mut tm);
    }

    // Demote pointer / code-pointer classifications for regs that get a
    // constant assignment. They end up as generic ints — which the printer
    // leaves uncluttered.
    let to_demote: Vec<VReg> = tm
        .inner
        .iter()
        .filter(|(k, v)| {
            gets_const.contains(k) && matches!(v, TypeHint::Pointer { .. } | TypeHint::CodePointer)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for k in to_demote {
        let hint = int_for_reg(&k);
        tm.inner.insert(k, hint);
    }

    tm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::{compute_ssa, SsaValue};
    use crate::ir::types::{
        CallEffects, CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value,
    };

    #[test]
    fn frame_bases_cover_arm32_and_ignore_the_ssa_suffix() {
        for name in [
            "rbp", "rsp", "ebp", "esp", "x29", "w29", "sp", "r7", "r11", "fp",
        ] {
            assert!(
                is_frame_base(&VReg::phys(name)),
                "{name} should be a frame base"
            );
            assert!(
                is_frame_base(&VReg::phys(format!("{name}#1"))),
                "{name}#1 should be a frame base"
            );
        }
        for name in ["r0", "r1", "r3", "rax", "rdi", "x0"] {
            assert!(
                !is_frame_base(&VReg::phys(name)),
                "{name} is not a frame base"
            );
            assert!(!is_frame_base(&VReg::phys(format!("{name}#2"))));
        }
    }

    fn mk_block(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn known_void_tail_call_rejects_stale_result_register_residue() {
        let function = mk_block(vec![
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(7),
            },
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: Some(CallEffects {
                    result: Some(VReg::phys("rax")),
                    result_is_source_value: false,
                    args: vec![VReg::phys("rdi")],
                    proven_args: Vec::new(),
                    args_are_exact: true,
                    is_tail_call: true,
                }),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&function);
        let slots = crate::ir::value_number::live_in_arg_slots_llir(
            &function,
            crate::ir::call_args::CallConv::SysVAmd64,
        );

        let prototype = recover_prototype(
            &function,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &slots,
        );

        assert_eq!(prototype.output_kind(), RecoveredOutputKind::Void);
        assert_eq!(
            prototype
                .parameters()
                .iter()
                .map(|parameter| parameter.slot)
                .collect::<Vec<_>>(),
            [0]
        );
    }

    #[test]
    fn ordinary_known_void_call_clobber_is_not_a_source_result() {
        let function = mk_block(vec![
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: Some(CallEffects {
                    result: Some(VReg::phys("rax")),
                    result_is_source_value: false,
                    args: vec![],
                    proven_args: Vec::new(),
                    args_are_exact: true,
                    is_tail_call: false,
                }),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&function);

        let prototype = recover_prototype(
            &function,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::new(),
        );

        assert_eq!(prototype.output_kind(), RecoveredOutputKind::Void);
    }

    #[test]
    fn direct_result_materialization_gives_return_an_exact_ssa_use() {
        let mut function = mk_block(vec![
            Op::Assign {
                dst: VReg::phys("x0"),
                src: Value::Const(0x1111),
            },
            Op::Assign {
                dst: VReg::phys("x0"),
                src: Value::Const(0x2222),
            },
            Op::Return,
        ]);
        let initial_ssa = compute_ssa(&function);
        let returned = initial_ssa
            .def_value(
                &function,
                crate::ir::use_def::InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
            )
            .expect("final x0 definition");
        let prototype = RecoveredPrototype {
            result: Some(RecoveredResult {
                values: vec![returned.clone()],
                hint: Some(TypeHint::Int {
                    signed: false,
                    width: 8,
                }),
            }),
            output_kind: RecoveredOutputKind::Direct,
            ..Default::default()
        };

        assert_eq!(
            materialize_return_values(
                &mut function,
                crate::ir::call_args::CallConv::Aarch64,
                &prototype,
            ),
            1
        );
        assert!(matches!(
            &function.blocks[0].instrs[2].op,
            Op::ReturnValue {
                value: Value::Reg(register),
            } if register == &VReg::phys("x0")
        ));
        let final_ssa = compute_ssa(&function);
        assert_eq!(
            final_ssa.use_value(
                &function,
                crate::ir::use_def::InstrAddr {
                    block_idx: 0,
                    instr_idx: 2,
                },
                0,
            ),
            Some(returned)
        );
    }

    #[test]
    fn value_number_tags_do_not_change_register_view_width() {
        assert_eq!(reg_width_bytes(&VReg::phys("xmm0_d0#3")), 4);
        assert_eq!(reg_width_bytes(&VReg::phys("rax#7")), 8);
    }

    #[test]
    fn abi_call_liveness_does_not_widen_a_narrowly_read_parameter() {
        // `abi::annotate_calls` gives EVERY call the convention's full argument
        // register list as a may-use, so a function that calls anything appears
        // to read all six 64-bit argument registers. That annotation is
        // speculative liveness, not an architectural read: here the only real
        // machine read of `rsi` is the four-byte `esi` spill that `-O0` emits
        // for an `int` parameter, so the recovered parameter must stay 4 bytes
        // wide. Before this was separated, any function containing a call had
        // every parameter widened to the machine word and rendered `long`.
        let mut lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    disp: -0x18,
                    size: 4,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("esi")),
            },
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(0x2000),
                effects: None,
            },
            Op::Return,
        ]);
        crate::ir::abi::annotate_calls(&mut lf, crate::ir::call_args::CallConv::SysVAmd64);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([1]),
        );
        assert_eq!(
            prototype.parameter(1).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            }),
            "the four-byte esi spill is the only real read of the parameter"
        );
    }

    #[test]
    fn a_parameter_only_forwarded_to_a_call_keeps_the_machine_word() {
        // With no architectural read at all the convention's register width is
        // still the best available fact, so the fallback must not narrow.
        let mut lf = mk_block(vec![
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(0x2000),
                effects: None,
            },
            Op::Return,
        ]);
        crate::ir::abi::annotate_calls(&mut lf, crate::ir::call_args::CallConv::SysVAmd64);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([1]),
        );
        assert_eq!(
            prototype.parameter(1).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            }),
            "an unread parameter keeps the ABI register width"
        );
    }

    #[test]
    fn load_base_tagged_pointer() {
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rbp")),
                index: None,
                scale: 0,
                disp: -8,
                size: 8,
                ..Default::default()
            },
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rbp")),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
    }

    #[test]
    fn explicit_zero_extension_recovers_source_and_result_widths() {
        let lf = mk_block(vec![Op::ZExt {
            dst: VReg::phys("eax"),
            src: Value::Reg(VReg::phys("edi")),
            from: crate::ir::types::Width::W32,
            to: crate::ir::types::Width::W64,
        }]);

        let tm = recover_types(&lf);

        assert_eq!(
            tm.get(&VReg::phys("edi")),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
        assert_eq!(
            tm.get(&VReg::phys("eax")),
            Some(TypeHint::Int {
                signed: false,
                width: 8,
            })
        );
    }

    #[test]
    fn value_refinement_preserves_richer_scalar_signedness_but_fixes_class() {
        let role = VReg::phys("arg0");
        let mut tm = TypeMap::default();
        tm.upsert_public(
            role.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        tm.refine_from_value(
            role.clone(),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        assert_eq!(
            tm.get(&role),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            }),
            "value identity must not discard stronger operation-level signedness"
        );

        tm.refine_from_value(role.clone(), TypeHint::Pointer { pointee_width: 1 });
        assert_eq!(
            tm.get(&role),
            Some(TypeHint::Pointer { pointee_width: 1 }),
            "value identity must correct a scalar/address class collision"
        );
    }

    #[test]
    fn locked_output_fact_survives_every_inference_update_path() {
        let role = VReg::phys("ret");
        let declared = TypeHint::Int {
            signed: true,
            width: 4,
        };
        let mut tm = TypeMap::default();
        tm.apply_locked_fact(role.clone(), declared);

        tm.upsert_public(role.clone(), TypeHint::Pointer { pointee_width: 8 });
        tm.refine_from_value(
            role.clone(),
            TypeHint::Int {
                signed: false,
                width: 8,
            },
        );
        tm.force_int_width(role.clone(), 8);
        tm.force_int_signedness(role.clone(), false);
        tm.force_pointer_width(role.clone(), 1);
        tm.force_scalar_int(role.clone(), false, 8);
        tm.clear_value_fact(&role);

        assert_eq!(tm.get(&role), Some(declared));
    }

    #[test]
    fn locked_declared_output_replaces_void_machine_inference() {
        let hint = TypeHint::Int {
            signed: true,
            width: 4,
        };
        let mut prototype = RecoveredPrototype {
            output_kind: RecoveredOutputKind::Void,
            ..RecoveredPrototype::default()
        };

        prototype.apply_locked_output(RecoveredOutputKind::Direct, Some(hint));

        assert_eq!(prototype.output_kind(), RecoveredOutputKind::Direct);
        assert!(prototype.output_is_locked());
        assert_eq!(
            prototype.result().and_then(|result| result.hint),
            Some(hint)
        );
    }

    /// `HiddenReturn` was a variant the type system knew about and no code could
    /// produce: matched in three places, constructed in none. A MEMORY-class
    /// result is what constructs it, and it must not discard the machine result
    /// while doing so — under System V the callee returns the caller's buffer
    /// address in the ordinary result register, so that register still holds a
    /// value the caller may use.
    #[test]
    fn a_memory_class_result_is_a_constructible_hidden_return() {
        let hint = TypeHint::Pointer { pointee_width: 8 };
        let mut prototype = RecoveredPrototype {
            result: Some(RecoveredResult {
                values: vec![SsaValue {
                    base: VReg::phys("rax"),
                    version: 3,
                }],
                hint: None,
            }),
            output_kind: RecoveredOutputKind::Direct,
            ..RecoveredPrototype::default()
        };

        prototype.apply_return_class(crate::ir::abi::ReturnClass::Memory);
        prototype.apply_locked_output(RecoveredOutputKind::HiddenReturn, Some(hint));

        assert_eq!(prototype.output_kind(), RecoveredOutputKind::HiddenReturn);
        assert_eq!(
            prototype.return_class(),
            crate::ir::abi::ReturnClass::Memory
        );
        assert!(prototype.output_is_locked());
        assert_eq!(
            prototype.result().map(|result| result.values.len()),
            Some(1),
            "the machine result register still holds the buffer address"
        );
        assert_eq!(
            prototype.result().and_then(|result| result.hint),
            Some(hint)
        );
    }

    /// The default is the one contract the value model has always assumed. A
    /// prototype that never saw a declared aggregate must not acquire a
    /// two-register or hidden-pointer result by omission.
    #[test]
    fn an_unclassified_prototype_keeps_the_single_register_contract() {
        assert_eq!(
            RecoveredPrototype::default().return_class(),
            crate::ir::abi::ReturnClass::Single
        );
    }

    #[test]
    fn locked_declared_parameters_retain_stack_passed_slots() {
        let hint = Some(TypeHint::Int {
            signed: true,
            width: 8,
        });
        let mut prototype = RecoveredPrototype::default();

        prototype.apply_locked_parameters(crate::ir::call_args::CallConv::SysVAmd64, &[hint; 8]);

        assert!(prototype.parameter_arity_is_locked());
        assert_eq!(prototype.parameters().len(), 8);
        assert_eq!(
            prototype
                .parameter(6)
                .map(|parameter| &parameter.value.base),
            Some(&VReg::phys("arg6"))
        );
        assert_eq!(
            prototype
                .parameter(7)
                .map(|parameter| &parameter.value.base),
            Some(&VReg::phys("arg7"))
        );
    }

    #[test]
    fn partial_parameter_hints_override_heuristics_without_locking_arity() {
        let mut prototype = RecoveredPrototype {
            parameters: (0..2)
                .map(|slot| RecoveredParameter {
                    slot,
                    value: SsaValue {
                        base: VReg::phys(if slot == 0 { "rdi" } else { "rsi" }),
                        version: 0,
                    },
                    hint: Some(TypeHint::Pointer { pointee_width: 8 }),
                })
                .collect(),
            ..RecoveredPrototype::default()
        };

        prototype.apply_parameter_hints(&[None, Some(TypeHint::Pointer { pointee_width: 1 })]);

        assert!(!prototype.parameter_arity_is_locked());
        assert!(!prototype.parameter_is_locked(0));
        assert!(prototype.parameter_is_locked(1));
        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
        assert_eq!(
            prototype.parameter(1).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 1 })
        );
    }

    /// The independent-counter rule, stated as the one signature that
    /// distinguishes it from a positional table: source positions 0/1/2/3 map to
    /// `rdi`/`xmm0`/`rsi`/`xmm1`, NOT `rdi`/`rsi`/`rdx`/`rcx`.
    #[test]
    fn locked_sysv_parameters_allocate_integer_and_sse_banks_independently() {
        let integer = Some(TypeHint::Int {
            signed: true,
            width: 4,
        });
        let float = Some(TypeHint::Float { width: 4 });
        let mut prototype = RecoveredPrototype::default();

        prototype.apply_locked_parameters(
            crate::ir::call_args::CallConv::SysVAmd64,
            &[integer, float, integer, float],
        );

        let storage: Vec<_> = prototype
            .parameters()
            .iter()
            .map(|parameter| parameter.value.base.clone())
            .collect();
        assert_eq!(
            storage,
            vec![
                VReg::phys("rdi"),
                VReg::phys("xmm0"),
                VReg::phys("rsi"),
                VReg::phys("xmm1"),
            ],
            "SysV allocates INTEGER and SSE arguments from two independent \
             counters; a float's source position is not its integer-bank index"
        );
    }

    /// A signature with no floats must be byte-identical to the positional
    /// behaviour that preceded the class-aware map. This is the blast-radius
    /// argument made executable: the only signatures the change can move are the
    /// ones containing an SSE-class parameter.
    #[test]
    fn locked_sysv_integer_only_parameters_are_unchanged_by_the_class_map() {
        let integer = Some(TypeHint::Int {
            signed: true,
            width: 8,
        });
        let pointer = Some(TypeHint::Pointer { pointee_width: 1 });
        let declared = [
            integer, pointer, integer, pointer, integer, pointer, integer,
        ];
        let mut prototype = RecoveredPrototype::default();

        prototype.apply_locked_parameters(crate::ir::call_args::CallConv::SysVAmd64, &declared);

        let storage: Vec<_> = prototype
            .parameters()
            .iter()
            .map(|parameter| parameter.value.base.clone())
            .collect();
        assert_eq!(
            storage,
            vec![
                VReg::phys("rdi"),
                VReg::phys("rsi"),
                VReg::phys("rdx"),
                VReg::phys("rcx"),
                VReg::phys("r8"),
                VReg::phys("r9"),
                VReg::phys("arg6"),
            ]
        );
    }

    /// Aggregates fail CLOSED, and the whole signature declines with them.
    ///
    /// SysV classifies each eightbyte of a struct independently, so
    /// `struct { long; double; }` occupies `rdi` AND `xmm0` — one source
    /// parameter drawing from both banks, which two scalar counters cannot
    /// express. Such a type reaches prototype recovery as `None`, and because
    /// every later parameter's bank index depends on it, the projection must
    /// decline for the entire signature rather than guess past it.
    #[test]
    fn locked_sysv_parameters_decline_the_whole_signature_on_an_aggregate() {
        let float = Some(TypeHint::Float { width: 8 });
        // `None` is what an aggregate, a `long double`, or any other type the
        // renderer cannot spell exactly arrives as.
        let aggregate = None;

        assert_eq!(
            locked_sysv_amd64_parameter_storage(
                crate::ir::call_args::CallConv::SysVAmd64,
                &[aggregate, float],
            ),
            None,
            "an unclassifiable parameter poisons every bank index after it"
        );

        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(
            crate::ir::call_args::CallConv::SysVAmd64,
            &[aggregate, float],
        );
        assert_eq!(
            prototype
                .parameter(1)
                .map(|parameter| parameter.value.base.clone()),
            Some(VReg::phys("rsi")),
            "declining returns the pre-existing positional behaviour untouched"
        );
    }

    /// A declaration names the ABI REGISTER; only the body names the SSA
    /// identity. `movd eax, xmm0` reads the dword lane `xmm0_d0`, which
    /// `regview::ssa_parent` refuses to merge with `xmm0`, so binding the
    /// parameter to the canonical name would leave every use of it undefined.
    #[test]
    fn locked_sysv_float_parameter_keeps_the_dword_lane_the_body_reads() {
        let mut prototype = RecoveredPrototype {
            // What the integer live-in scan produced: a spurious `rdi` at source
            // position zero, which is what a positional map would have kept.
            parameters: vec![RecoveredParameter {
                slot: 0,
                value: SsaValue {
                    base: VReg::phys("rdi"),
                    version: 0,
                },
                hint: None,
            }],
            observed_float_storage: [(0, VReg::phys("xmm0_d0"))].into_iter().collect(),
            ..RecoveredPrototype::default()
        };

        prototype.apply_locked_parameters(
            crate::ir::call_args::CallConv::SysVAmd64,
            &[Some(TypeHint::Float { width: 4 })],
        );

        assert_eq!(
            prototype
                .parameter(0)
                .map(|parameter| parameter.value.base.clone()),
            Some(VReg::phys("xmm0_d0")),
            "the declared SSE register resolves to the exact spelling the \
             machine code reads, not the canonical whole-register name"
        );
    }

    /// Both spellings of the same SSE argument register name one bank slot.
    #[test]
    fn a_scalar_dword_lane_is_the_same_float_argument_bank_slot() {
        use crate::ir::call_args::CallConv;
        for (name, expected) in [
            ("xmm0", Some(0)),
            ("xmm0_d0", Some(0)),
            ("xmm1_d0", Some(1)),
            ("xmm7_d3", Some(7)),
            ("xmm0_d0#4", Some(0)),
            // `xmm8` and above are never parameters under either convention.
            ("xmm8_d0", None),
            ("rdi", None),
        ] {
            assert_eq!(
                float_argument_bank_slot(CallConv::SysVAmd64, &VReg::phys(name)),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn locked_aapcs_integer_parameters_replace_spurious_vfp_live_ins() {
        let hint = Some(TypeHint::Int {
            signed: true,
            width: 4,
        });
        let mut prototype = RecoveredPrototype {
            parameters: (0..8)
                .map(|slot| RecoveredParameter {
                    slot,
                    value: SsaValue {
                        base: if slot < 4 {
                            VReg::phys(format!("r{slot}"))
                        } else {
                            VReg::phys(format!("s{}", slot - 4))
                        },
                        version: 0,
                    },
                    hint,
                })
                .collect(),
            ..RecoveredPrototype::default()
        };

        prototype.apply_locked_parameters(crate::ir::call_args::CallConv::ArmHardFloat, &[hint; 8]);

        let storage: Vec<_> = prototype
            .parameters()
            .iter()
            .map(|parameter| parameter.value.base.clone())
            .collect();
        assert_eq!(
            storage,
            vec![
                VReg::phys("r0"),
                VReg::phys("r1"),
                VReg::phys("r2"),
                VReg::phys("r3"),
                VReg::phys("arg4"),
                VReg::phys("arg5"),
                VReg::phys("arg6"),
                VReg::phys("arg7"),
            ],
            "declared integer types, not heuristic VFP liveness, own AAPCS storage"
        );
    }

    #[test]
    fn spilled_pointer_arg_recovered_through_address_add() {
        use crate::ir::types::BinOp;
        // The `-O0` array-index idiom, post value-numbering:
        //   store [rbp-24] = rdi      ; spill the pointer argument
        //   rdx = rcx * 4             ; scaled index (an offset register)
        //   rax = [rbp-24]            ; reload the spilled pointer
        //   r8  = rax + rdx           ; base + index  (the address)
        //   r9  = *r8                 ; dereference   -> r8 is a pointer
        // Nothing dereferences rdi directly, so the pointer type on the argument
        // can only be recovered by: r8 pointer -> rax (the reload) is the base ->
        // the spill slot -> rdi. Regression guard for that whole chain.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -24,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Bin {
                op: BinOp::Mul,
                dst: VReg::phys("rdx"),
                lhs: Value::Reg(VReg::phys("rcx")),
                rhs: Value::Const(4),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -24,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Bin {
                op: BinOp::Add,
                dst: VReg::phys("r8"),
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Reg(VReg::phys("rdx")),
            },
            Op::Load {
                dst: VReg::phys("r9"),
                addr: MemOp {
                    base: Some(VReg::phys("r8")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(
            matches!(tm.get(&VReg::phys("rdi")), Some(TypeHint::Pointer { .. })),
            "spilled pointer argument rdi should be recovered as a pointer, got {:?}",
            tm.get(&VReg::phys("rdi"))
        );
        // The scaled index must NOT be mistaken for a pointer.
        assert!(
            !matches!(tm.get(&VReg::phys("rdx")), Some(TypeHint::Pointer { .. })),
            "scaled index rdx must not be typed as a pointer"
        );
    }

    #[test]
    fn valued_recovery_does_not_demote_an_earlier_pointer_definition() {
        // One architectural register, two unrelated values:
        //   rdi#0 is the incoming pointer and is dereferenced;
        //   rdi#1 is a later scalar constant.
        // Flow-insensitive recovery demotes the entire register because it sees
        // the constant. Value-keyed recovery must keep the two facts separate.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("eax"),
                addr: MemOp {
                    base: Some(VReg::phys("rdi")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Assign {
                dst: VReg::phys("edi"),
                src: Value::Const(0),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let tm = recover_types_valued(&lf, &ssa);
        let incoming = SsaValue {
            base: VReg::phys("rdi"),
            version: 0,
        };
        let scalar = ssa
            .def_value(
                &lf,
                crate::ir::use_def::InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
            )
            .expect("constant definition value");

        assert_eq!(
            tm.get(&incoming),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert!(matches!(
            tm.get(&scalar),
            Some(TypeHint::Int { width: 4, .. })
        ));
    }

    #[test]
    fn dead_phi_does_not_merge_live_in_scalar_with_later_pointer_reuse() {
        let block = |start_va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va,
            end_va: start_va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: start_va + index as u64 * 4,
                    op,
                })
                .collect(),
            succs,
        };
        // rsi#0 is an integer parameter. Only one branch later reuses rsi as a
        // pointer, and the merge-point phi is dead: nothing reads its result.
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![Op::CondJump {
                        cond: VReg::phys("rsi"),
                        target: 0x1020,
                        inverted: false,
                    }],
                    vec![0x1010, 0x1020],
                ),
                block(
                    0x1010,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rsi"),
                            src: Value::Reg(VReg::phys("rdi")),
                        },
                        Op::Load {
                            dst: VReg::phys("eax"),
                            addr: MemOp {
                                base: Some(VReg::phys("rsi")),
                                index: None,
                                scale: 1,
                                disp: 0,
                                size: 4,
                                ..Default::default()
                            },
                        },
                    ],
                    vec![0x1030],
                ),
                block(0x1020, vec![Op::Nop], vec![0x1030]),
                block(0x1030, vec![Op::Return], vec![]),
            ],
        };
        let ssa = compute_ssa(&lf);
        assert!(
            ssa.phis.iter().any(|phi| phi.base == VReg::phys("rsi")),
            "fixture must contain the dead merge phi"
        );
        let tm = recover_types_valued(&lf, &ssa);
        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rsi"),
                version: 0,
            }),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn real_gcc_o2_loop_propagates_pointer_type_to_live_in_value() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary memory fixture build directory");
        let source = tmp.path().join("09_memory_effects.c");
        let binary = tmp.path().join("09_memory_effects.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/09_memory_effects.c"
                ))
            })
            .expect("write the real memory-effects fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real memory-effects fixture with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("vec_sum"))
            .map(|symbol| symbol.address())
            .expect("exported vec_sum symbol");
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered vec_sum function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift vec_sum");
        let ssa = compute_ssa(&lifted);
        let tm = recover_types_valued(&lifted, &ssa);

        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 4 }),
            "the loop-carried dereference must flow through its phi and pointer increment to arg0"
        );
    }

    #[test]
    fn real_memory_fixture_distinguishes_void_residue_from_direct_outputs() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary output-recovery fixture directory");
        let source = tmp.path().join("09_memory_effects.c");
        let binary = tmp.path().join("09_memory_effects.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/09_memory_effects.c"
                ))
            })
            .expect("write the real memory-effects fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile output-recovery fixture: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read output-recovery fixture");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse fixture ELF");
        let entries: HashMap<String, u64> = object
            .dynamic_symbols()
            .filter_map(|symbol| Some((symbol.name().ok()?.to_owned(), symbol.address())))
            .collect();
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );

        for (name, expected) in [
            ("tick", RecoveredOutputKind::Void),
            ("tick_n", RecoveredOutputKind::Void),
            ("reset_counter", RecoveredOutputKind::Void),
            ("mem_copy", RecoveredOutputKind::Void),
            ("mem_set", RecoveredOutputKind::Void),
            ("read_counter", RecoveredOutputKind::Direct),
            ("cas_update", RecoveredOutputKind::Direct),
            ("vec_sum", RecoveredOutputKind::Direct),
        ] {
            let entry = entries[name];
            let function = functions
                .iter()
                .find(|function| function.entry_point.value == entry)
                .unwrap_or_else(|| panic!("discovered {name}"));
            let lifted = crate::ir::lift_function::lift_function_from_bytes(
                &data,
                function,
                crate::core::binary::Arch::X86_64,
            )
            .unwrap_or_else(|error| panic!("lift {name}: {error}"));
            let ssa = compute_ssa(&lifted);
            let slots = crate::ir::value_number::live_in_arg_slots_llir(
                &lifted,
                crate::ir::call_args::CallConv::SysVAmd64,
            );
            let prototype = recover_prototype(
                &lifted,
                &ssa,
                crate::ir::call_args::CallConv::SysVAmd64,
                &slots,
            );
            assert_eq!(
                prototype.output_kind(),
                expected,
                "source result for {name}"
            );
        }
    }

    #[test]
    fn real_optimized_memory_fixture_keeps_loop_results_and_void_residue_distinct() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        for compiler in ["gcc", "clang"] {
            let tmp = tempfile::tempdir().expect("temporary optimized-output fixture directory");
            let source = tmp.path().join("09_memory_effects.c");
            let binary = tmp.path().join(format!("09_memory_effects-{compiler}.so"));
            std::fs::File::create(&source)
                .and_then(|mut file| {
                    file.write_all(include_bytes!(
                        "../../tests/decompiler_fixtures/src/09_memory_effects.c"
                    ))
                })
                .expect("write the real memory-effects fixture source");
            let build = match Command::new(compiler)
                .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
                .arg(&binary)
                .arg(&source)
                .output()
            {
                Ok(build) => build,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("launch {compiler}: {error}"),
            };
            assert!(
                build.status.success(),
                "compile optimized fixture with {compiler}: {}",
                String::from_utf8_lossy(&build.stderr)
            );

            let data = std::fs::read(&binary).expect("read optimized fixture");
            let object = crate::decompile::profile::parse_object(data.as_slice())
                .expect("parse fixture ELF");
            let entries: HashMap<String, u64> = object
                .dynamic_symbols()
                .filter_map(|symbol| Some((symbol.name().ok()?.to_owned(), symbol.address())))
                .collect();
            let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
                &data,
                &crate::analysis::cfg::Budgets::default(),
            );

            for (name, expected) in [
                ("tick_n", RecoveredOutputKind::Void),
                ("mem_copy", RecoveredOutputKind::Void),
                ("mem_set", RecoveredOutputKind::Void),
                ("cas_update", RecoveredOutputKind::Direct),
                ("vec_sum", RecoveredOutputKind::Direct),
            ] {
                let entry = entries[name];
                let function = functions
                    .iter()
                    .find(|function| function.entry_point.value == entry)
                    .unwrap_or_else(|| panic!("discovered {compiler} {name}"));
                let lifted = crate::ir::lift_function::lift_function_from_bytes(
                    &data,
                    function,
                    crate::core::binary::Arch::X86_64,
                )
                .unwrap_or_else(|error| panic!("lift {compiler} {name}: {error}"));
                let ssa = compute_ssa(&lifted);
                let slots = crate::ir::value_number::live_in_arg_slots_llir(
                    &lifted,
                    crate::ir::call_args::CallConv::SysVAmd64,
                );
                let prototype = recover_prototype(
                    &lifted,
                    &ssa,
                    crate::ir::call_args::CallConv::SysVAmd64,
                    &slots,
                );
                assert_eq!(
                    prototype.output_kind(),
                    expected,
                    "source result for {compiler} -O2 {name}"
                );
            }
        }
    }

    #[test]
    fn real_noreturn_and_tailcall_functions_do_not_masquerade_as_void() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary no-return fixture directory");
        let source = tmp.path().join("no_return.c");
        let binary = tmp.path().join("no_return.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(
                    br#"
__attribute__((noinline)) int callee(int x) { return x + 1; }
int tail_result(int x) { return callee(x); }
int never_returns(void) { for (;;) {} }
"#,
                )
            })
            .expect("write real no-return fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile no-return fixture: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read no-return fixture");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse fixture ELF");
        let entries: HashMap<String, u64> = object
            .dynamic_symbols()
            .filter_map(|symbol| Some((symbol.name().ok()?.to_owned(), symbol.address())))
            .collect();
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );

        for (name, expected) in [
            ("callee", RecoveredOutputKind::Direct),
            ("tail_result", RecoveredOutputKind::Direct),
            ("never_returns", RecoveredOutputKind::Unknown),
        ] {
            let entry = entries[name];
            let function = functions
                .iter()
                .find(|function| function.entry_point.value == entry)
                .unwrap_or_else(|| panic!("discovered {name}"));
            let mut lifted = crate::ir::lift_function::lift_function_from_bytes(
                &data,
                function,
                crate::core::binary::Arch::X86_64,
            )
            .unwrap_or_else(|error| panic!("lift {name}: {error}"));
            // The production pipeline attaches ABI call inputs/results before
            // SSA and type recovery.  Tail-call materialization now happens at
            // the LLIR boundary, so this fixture must exercise the same order:
            // its synthetic Call + Return then proves a direct source result
            // instead of looking like a value-less machine return.
            crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::SysVAmd64);
            let ssa = compute_ssa(&lifted);
            let slots = crate::ir::value_number::live_in_arg_slots_llir(
                &lifted,
                crate::ir::call_args::CallConv::SysVAmd64,
            );
            let prototype = recover_prototype(
                &lifted,
                &ssa,
                crate::ir::call_args::CallConv::SysVAmd64,
                &slots,
            );
            assert_eq!(
                prototype.output_kind(),
                expected,
                "source result for {name}"
            );
        }
    }

    #[test]
    fn opaque_machine_semantics_prevent_void_inference() {
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1004,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::opaque("unmodeled-result-op"),
                    },
                    LlirInstr {
                        va: 0x1002,
                        op: Op::Return,
                    },
                ],
                succs: vec![],
            }],
        };
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::new(),
        );
        assert_eq!(prototype.output_kind(), RecoveredOutputKind::Unknown);
    }

    #[test]
    fn arm_hard_float_mixed_storage_does_not_guess_source_order() {
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Assign {
                            dst: VReg::Temp(0),
                            src: Value::Reg(VReg::phys("r0")),
                        },
                    },
                    LlirInstr {
                        va: 0x1002,
                        op: Op::Intrinsic {
                            name: "vadd.f32".into(),
                            ins: vec![Value::Reg(VReg::phys("s0")), Value::Reg(VReg::phys("s0"))],
                            outs: vec![(VReg::phys("s0"), crate::ir::types::Width::W32)],
                            reads_mem: false,
                            writes_mem: false,
                        },
                    },
                    LlirInstr {
                        va: 0x1006,
                        op: Op::Return,
                    },
                ],
                succs: vec![],
            }],
        };
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype_with_arm_vfp_args(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0]),
            true,
        );

        assert!(
            prototype
                .parameters()
                .iter()
                .all(|parameter| parameter.value.base != VReg::phys("s0")),
            "mixed core/VFP source ordering is not identifiable: {prototype:#?}"
        );
    }

    #[test]
    fn arm_vfp_live_in_prefix_ignores_an_isolated_scratch_read() {
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Store {
                            addr: MemOp::plain(Some(VReg::phys("sp")), None, 0, 0, 4),
                            src: Value::Reg(VReg::phys("s0")),
                        },
                    },
                    // An unsupported producer can leave only this later read
                    // visible. It is scratch evidence, not a reason to discard
                    // the proven contiguous parameter prefix beginning at s0.
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Intrinsic {
                            name: "vadd.f32".into(),
                            ins: vec![Value::Reg(VReg::phys("s14")), Value::Reg(VReg::phys("s0"))],
                            outs: vec![(VReg::phys("s15"), crate::ir::types::Width::W32)],
                            reads_mem: false,
                            writes_mem: false,
                        },
                    },
                ],
                succs: vec![],
            }],
        };

        assert_eq!(
            float_live_in_slots(&lf, crate::ir::call_args::CallConv::ArmHardFloat),
            vec![(0, "s0".to_string())]
        );
    }

    #[test]
    fn core_to_vfp_move_propagates_float_storage_class_to_loaded_bits() {
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Load {
                            dst: VReg::phys("r3"),
                            addr: MemOp::plain(Some(VReg::phys("r0")), None, 0, 4, 4),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Intrinsic {
                            name: "vmov".into(),
                            ins: vec![Value::Reg(VReg::phys("r3"))],
                            outs: vec![(VReg::phys("s14"), crate::ir::types::Width::W32)],
                            reads_mem: false,
                            writes_mem: false,
                        },
                    },
                ],
                succs: vec![],
            }],
        };

        let types = recover_types_for(&lf, crate::ir::call_args::CallConv::ArmHardFloat);
        assert!(
            matches!(types.get(&VReg::phys("r3")), Some(TypeHint::Int { .. })),
            "the core register carries raw bits, not a numerically converted float: {types:#?}"
        );
        assert_eq!(
            types.get(&VReg::phys("s14")),
            Some(TypeHint::Float { width: 4 })
        );
    }

    #[test]
    fn arm_hard_float_descending_entry_spills_recover_mixed_source_order() {
        // Real GCC Cortex-M O0 prologues spill incoming parameters in source
        // order to strictly descending frame offsets.  `pidUpdate` uses this
        // exact class sequence: r0 -> [r7+12], s0 -> [r7+8], r1 (via r3) ->
        // [r7+7], after establishing r7 = sp. Unlike the no-spill case above,
        // this is direct ordering
        // evidence rather than a preferred register-class convention.
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1010,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Bin {
                            dst: VReg::phys("r7"),
                            op: BinOp::Add,
                            lhs: Value::Reg(VReg::phys("sp")),
                            rhs: Value::Const(0),
                        },
                    },
                    LlirInstr {
                        va: 0x1002,
                        op: Op::Store {
                            addr: MemOp::plain(Some(VReg::phys("r7")), None, 0, 12, 4),
                            src: Value::Reg(VReg::phys("r0")),
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Store {
                            addr: MemOp::plain(Some(VReg::phys("r7")), None, 0, 8, 4),
                            src: Value::Reg(VReg::phys("s0")),
                        },
                    },
                    LlirInstr {
                        va: 0x1008,
                        op: Op::Assign {
                            dst: VReg::phys("r3"),
                            src: Value::Reg(VReg::phys("r1")),
                        },
                    },
                    LlirInstr {
                        va: 0x100a,
                        op: Op::Store {
                            addr: MemOp::plain(Some(VReg::phys("r7")), None, 0, 7, 1),
                            src: Value::Reg(VReg::phys("r3")),
                        },
                    },
                    LlirInstr {
                        va: 0x100c,
                        op: Op::Return,
                    },
                ],
                succs: vec![],
            }],
        };
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype_with_arm_vfp_args(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0, 1]),
            true,
        );

        assert_eq!(
            prototype
                .parameters()
                .iter()
                .map(|parameter| (parameter.slot, parameter.value.base.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0, VReg::phys("r0")),
                (1, VReg::phys("s0")),
                (2, VReg::phys("r1")),
            ],
            "mixed parameter roles: {prototype:#?}"
        );
        assert_eq!(
            prototype.parameters()[1].hint,
            Some(TypeHint::Float { width: 4 })
        );
    }

    #[test]
    fn real_hard_float_result_recovers_direct_float_output() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary hard-float fixture directory");
        let source = tmp.path().join("hard_float.c");
        let binary = tmp.path().join("hard_float.elf");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(
                    b"__attribute__((noinline)) float helper(float x) { return x + 1.0f; }\n\
                      float square(float x) { return helper(x) * x; }\n",
                )
            })
            .expect("write real hard-float fixture source");
        let build = match Command::new("arm-none-eabi-gcc")
            .args([
                "-mcpu=cortex-m4",
                "-mthumb",
                "-mfloat-abi=hard",
                "-mfpu=fpv4-sp-d16",
                "-nostdlib",
                "-Wl,-Ttext=0x1000",
                "-Wl,-e,square",
                "-g",
                "-O2",
                "-o",
            ])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch arm-none-eabi-gcc: {error}"),
        };
        assert!(
            build.status.success(),
            "compile hard-float fixture: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read hard-float fixture");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse hard-float ELF");
        let entry = object
            .symbols()
            .find(|symbol| symbol.name().ok() == Some("square"))
            .expect("square symbol")
            .address()
            & !1;
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered square");
        assert!(
            function.has_flag(crate::core::function::FunctionFlags::IS_THUMB),
            "real Cortex-M fixture must retain Thumb mode"
        );
        let mut lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::ARM,
        )
        .expect("lift square");
        crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::Arm);
        assert!(
            lifted
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .any(|instruction| {
                    matches!(instruction.op, Op::Unknown { .. } | Op::Intrinsic { .. })
                }),
            "fixture must exercise an unmodeled VFP result"
        );
        let ssa = compute_ssa(&lifted);
        let slots = crate::ir::value_number::live_in_arg_slots_llir(
            &lifted,
            crate::ir::call_args::CallConv::Arm,
        );
        let prototype =
            recover_prototype(&lifted, &ssa, crate::ir::call_args::CallConv::Arm, &slots);
        assert_eq!(
            prototype.output_kind(),
            RecoveredOutputKind::Direct,
            "lifted hard-float fixture: {lifted:#?}"
        );
        assert_eq!(
            prototype.result().and_then(|result| result.hint),
            Some(TypeHint::Float { width: 4 })
        );
    }

    #[test]
    fn real_x86_simd_float_result_recovers_direct_float_output() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary x86 float fixture directory");
        let source = tmp.path().join("float_result.c");
        let binary = tmp.path().join("float_result.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(
                    b"__attribute__((noinline)) float helper(float x) { return x + 1.0f; }\n\
                      float square(float x) { return helper(x) * x; }\n",
                )
            })
            .expect("write real x86 float fixture source");
        for compiler in ["gcc", "clang"] {
            let build = match Command::new(compiler)
                .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
                .arg(&binary)
                .arg(&source)
                .output()
            {
                Ok(build) => build,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("launch {compiler}: {error}"),
            };
            assert!(
                build.status.success(),
                "compile x86 float fixture with {compiler}: {}",
                String::from_utf8_lossy(&build.stderr)
            );

            let data = std::fs::read(&binary).expect("read x86 float fixture");
            let object = crate::decompile::profile::parse_object(data.as_slice())
                .expect("parse x86 float ELF");
            let entry = object
                .dynamic_symbols()
                .find(|symbol| symbol.name().ok() == Some("square"))
                .expect("square symbol")
                .address();
            let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
                &data,
                &crate::analysis::cfg::Budgets::default(),
            );
            let function = functions
                .iter()
                .find(|function| function.entry_point.value == entry)
                .expect("discovered square");
            let mut lifted = crate::ir::lift_function::lift_function_from_bytes(
                &data,
                function,
                crate::core::binary::Arch::X86_64,
            )
            .expect("lift square");
            crate::ir::abi::annotate_calls(&mut lifted, crate::ir::call_args::CallConv::SysVAmd64);
            let ssa = compute_ssa(&lifted);
            let slots = crate::ir::value_number::live_in_arg_slots_llir(
                &lifted,
                crate::ir::call_args::CallConv::SysVAmd64,
            );
            let prototype = recover_prototype(
                &lifted,
                &ssa,
                crate::ir::call_args::CallConv::SysVAmd64,
                &slots,
            );
            assert_eq!(
                prototype.output_kind(),
                RecoveredOutputKind::Direct,
                "{compiler} output kind"
            );
            assert_eq!(
                prototype.result().and_then(|result| result.hint),
                Some(TypeHint::Float { width: 4 }),
                "{compiler} output type"
            );
        }
    }

    #[test]
    fn real_gcc_o0_spills_propagate_both_string_pointer_live_ins() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary string fixture build directory");
        let source = tmp.path().join("strops.c");
        let binary = tmp.path().join("strops.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!("../../tests/decbench_corpus/src/strops.c"))
            })
            .expect("write the real DecBench string fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real DecBench string fixture with GCC -O0: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("str_cmp"))
            .map(|symbol| symbol.address())
            .expect("exported str_cmp symbol");
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered str_cmp function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift str_cmp");
        let ssa = compute_ssa(&lifted);
        let tm = recover_types_valued(&lifted, &ssa);
        let refinements = tm.parameter_refinements();

        for register in ["rdi", "rsi"] {
            assert_eq!(
                tm.get(&SsaValue {
                    base: VReg::phys(register),
                    version: 0,
                }),
                Some(TypeHint::Pointer { pointee_width: 1 }),
                "{register} must retain its caller-supplied string-pointer type through the spill"
            );
            assert_eq!(
                refinements.get(&VReg::phys(register)),
                Some(TypeHint::Pointer { pointee_width: 1 }),
                "{register} has the spill/reload/dereference proof required to refine a rendered parameter"
            );
        }

        // Prototype recovery is a semantic projection of those exact SSA
        // live-ins, not a second register-name rewrite performed after AST
        // naming.  The value IDs must therefore remain available to every
        // later lowering/rendering stage alongside their source-level slots.
        let param_slots = crate::ir::value_number::live_in_arg_slots_llir(
            &lifted,
            crate::ir::call_args::CallConv::SysVAmd64,
        );
        let prototype = recover_prototype(
            &lifted,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &param_slots,
        );
        assert_eq!(prototype.parameters().len(), 2);
        for (slot, register) in ["rdi", "rsi"].into_iter().enumerate() {
            let parameter = prototype
                .parameter(slot)
                .unwrap_or_else(|| panic!("missing recovered parameter slot {slot}"));
            assert_eq!(
                parameter.value,
                SsaValue {
                    base: VReg::phys(register),
                    version: 0,
                }
            );
            assert_eq!(
                parameter.hint,
                Some(TypeHint::Pointer { pointee_width: 1 }),
                "slot {slot} must carry its qualified SSA type into the prototype"
            );
        }
        let projected = prototype.parameter_type_map();
        assert_eq!(
            projected.get(&VReg::phys("arg0")),
            Some(TypeHint::Pointer { pointee_width: 1 })
        );
        assert_eq!(
            projected.get(&VReg::phys("arg1")),
            Some(TypeHint::Pointer { pointee_width: 1 })
        );
    }

    #[test]
    fn direct_live_in_fact_is_not_yet_a_rendered_parameter_refinement() {
        // A direct memory use proves that this SSA value is address-bearing,
        // but it is not enough to rewrite the source prototype while function
        // boundaries and recovered callees are still incomplete. The first
        // output-facing slice deliberately accepts only the stronger O0
        // spill/reload/dereference chain exercised above.
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("eax"),
            addr: MemOp {
                base: Some(VReg::phys("rdi")),
                index: None,
                scale: 1,
                disp: 0,
                size: 4,
                ..Default::default()
            },
        }]);
        let ssa = compute_ssa(&lf);
        let tm = recover_types_valued(&lf, &ssa);

        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert!(
            tm.parameter_refinements().is_empty(),
            "unqualified live-in facts must remain analysis evidence, not rendered prototype facts"
        );
    }

    #[test]
    fn x86_live_in_pointer_view_remains_available_to_the_prototype() {
        // Unlike ARM r0-r3, x86's architectural aliases distinguish the
        // incoming full-width value from later narrow scratch lifetimes. A
        // direct dereference of version-zero rdi is therefore valid pointer
        // evidence for the recovered function contract.
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("eax"),
            addr: MemOp::plain(Some(VReg::phys("rdi")), None, 1, 0, 4),
        }]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 4 }),
        );
    }

    #[test]
    fn lone_spilled_pointer_fact_is_not_yet_a_rendered_parameter_refinement() {
        // A single address-taken scalar can have this same machine shape after
        // optimization: spill one incoming value, reload it, then let an
        // over-discovered tail use the reload as an address. Requiring a second
        // independently qualified entry value keeps that case from rewriting
        // the public prototype until prototype recovery and function bounds are
        // authoritative.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("ecx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let ssa = compute_ssa(&lf);
        let tm = recover_types_valued(&lf, &ssa);

        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert!(
            tm.parameter_refinements().is_empty(),
            "one qualified live-in is not enough to rewrite a rendered prototype"
        );
    }

    #[test]
    fn later_arm_scratch_address_does_not_retype_an_earlier_spilled_scalar_parameter() {
        use crate::ir::types::{CmpOp, Flag};

        // ARM has no narrow aliases for r0-r3. Flow-insensitive recovery sees
        // the later address-bearing r3 lifetime and historically propagated
        // that pointer class backwards through the earlier `[r7+4]` reload to
        // r0. The exact reload value is used only by an integer comparison, so
        // the source parameter is a machine-word scalar. This is the reduced
        // shape of DecBench's `console_getc(int wait)` defect.
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("r7"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("sp")),
                rhs: Value::Const(0),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r7")), None, 1, 4, 4),
                src: Value::Reg(VReg::phys("r0")),
            },
            Op::Load {
                dst: VReg::phys("r3"),
                addr: MemOp::plain(Some(VReg::phys("r7")), None, 1, 4, 4),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::phys("r3")),
                rhs: Value::Const(0),
            },
            Op::Bin {
                dst: VReg::phys("r3"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r2")),
                rhs: Value::Const(0x100),
            },
            Op::Load {
                dst: VReg::phys("r1"),
                addr: MemOp::plain(Some(VReg::phys("r3")), None, 1, 0, 4),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let valued = recover_types_valued(&lf, &ssa);
        assert_eq!(
            valued.get(&SsaValue {
                base: VReg::phys("r0"),
                version: 0,
            }),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            }),
            "exact-value recovery must keep the live-in scalar before ABI normalization"
        );
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            }),
            "a later r3 address lifetime must not poison r0: {prototype:#?}"
        );
    }

    #[test]
    fn sysv_narrow_parameter_home_refines_the_exact_live_in() {
        // GCC x86-64 -O0 lowers `f(short key)` through the 32-bit ABI view,
        // masks the copied value to AX, and stores only that word in the
        // parameter home.  The narrow store is the source declaration width;
        // the full-width RDI container is not an `int` contract.  This is the
        // reduced stripped-binary shape of DecBench's `prec_name`.
        let lf = mk_block(vec![
            Op::ZExt {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::phys("edi")),
                from: crate::ir::types::Width::W32,
                to: crate::ir::types::Width::W64,
            },
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(0xffff),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -20, 2),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Load {
                dst: VReg::Temp(1),
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -20, 2),
            },
            // A signed short is commonly zero-extended for a bit-preserving
            // same-width copy before a later signed semantic use.  That
            // transport must not turn the declaration unsigned.
            Op::ZExt {
                dst: VReg::phys("rdx"),
                src: Value::Reg(VReg::Temp(1)),
                from: crate::ir::types::Width::W16,
                to: crate::ir::types::Width::W64,
            },
            Op::Store {
                addr: MemOp::plain(None, None, 1, 0x1000, 2),
                src: Value::Reg(VReg::phys("rdx")),
            },
            Op::Load {
                dst: VReg::Temp(2),
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -20, 2),
            },
            Op::SExt {
                dst: VReg::phys("rcx"),
                src: Value::Reg(VReg::Temp(2)),
                from: crate::ir::types::Width::W16,
                to: crate::ir::types::Width::W64,
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 2,
            }),
            "the exact word-sized parameter home must refine RDI: {prototype:#?}"
        );
    }

    #[test]
    fn sysv_unsigned_narrow_parameter_home_stays_unsigned() {
        let lf = mk_block(vec![
            Op::ZExt {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::phys("edi")),
                from: crate::ir::types::Width::W32,
                to: crate::ir::types::Width::W64,
            },
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(0xffff),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -20, 2),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Load {
                dst: VReg::Temp(1),
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -20, 2),
            },
            Op::ZExt {
                dst: VReg::phys("rcx"),
                src: Value::Reg(VReg::Temp(1)),
                from: crate::ir::types::Width::W16,
                to: crate::ir::types::Width::W64,
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: false,
                width: 2,
            }),
            "a lone zero-extension is unsigned declaration evidence: {prototype:#?}"
        );
    }

    #[test]
    fn sysv_narrow_cast_local_does_not_shrink_a_full_width_parameter() {
        // `f(int value) { short local = value; ... }` has an ordinary
        // full-width parameter home before the derived narrow local.  A mask
        // and word store alone must not rewrite that `int` contract.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -20, 4),
                src: Value::Reg(VReg::phys("edi")),
            },
            Op::ZExt {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::phys("edi")),
                from: crate::ir::types::Width::W32,
                to: crate::ir::types::Width::W64,
            },
            Op::Bin {
                dst: VReg::Temp(0),
                op: BinOp::And,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(0xffff),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -2, 2),
                src: Value::Reg(VReg::Temp(0)),
            },
            Op::Load {
                dst: VReg::Temp(1),
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -2, 2),
            },
            Op::SExt {
                dst: VReg::phys("rcx"),
                src: Value::Reg(VReg::Temp(1)),
                from: crate::ir::types::Width::W16,
                to: crate::ir::types::Width::W64,
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            }),
            "a derived short local must not shrink its full-width input: {prototype:#?}"
        );
    }

    #[test]
    fn sysv_direct_narrow_spill_does_not_bypass_corroboration() {
        // With no explicit truncation/mask chain, a word store can equally be
        // `short parameter` or `int parameter assigned to short local`.  One
        // such spill is not independently strong declaration evidence.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -2, 2),
                src: Value::Reg(VReg::phys("edi")),
            },
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp::plain(Some(VReg::phys("rbp")), None, 1, -2, 2),
            },
            Op::SExt {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::Temp(0)),
                from: crate::ir::types::Width::W16,
                to: crate::ir::types::Width::W64,
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            }),
            "an ambiguous direct word spill must remain ABI-container typed: {prototype:#?}"
        );
    }

    #[test]
    fn arm_narrow_spills_qualify_the_complete_parameter_tuple() {
        // GCC -O0 AAPCS shape for `void f(T *p, unsigned char a,
        // unsigned char b)`: spill r0 as a word, r1/r2 as bytes, then reload
        // the byte slots with LDRB's explicit zero extension. The two narrow
        // values independently corroborate the frame-spill provenance, so the
        // pointer parameter can cross the same output-safety gate as them.
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("r7"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("sp")),
                rhs: Value::Const(0),
            },
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -4,
                    size: 4,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("r0")),
            },
            Op::Assign {
                dst: VReg::phys("r3"),
                src: Value::Reg(VReg::phys("r1")),
            },
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -5,
                    size: 1,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("r3")),
            },
            Op::Assign {
                dst: VReg::phys("r3"),
                src: Value::Reg(VReg::phys("r2")),
            },
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -6,
                    size: 1,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("r3")),
            },
            Op::Load {
                dst: VReg::Temp(0),
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -4,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("r3"),
                addr: MemOp {
                    base: Some(VReg::Temp(0)),
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::Temp(1),
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -5,
                    size: 1,
                    ..Default::default()
                },
            },
            Op::ZExt {
                dst: VReg::phys("r1"),
                src: Value::Reg(VReg::Temp(1)),
                from: crate::ir::types::Width::W8,
                to: crate::ir::types::Width::W32,
            },
            Op::Load {
                dst: VReg::Temp(2),
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -6,
                    size: 1,
                    ..Default::default()
                },
            },
            Op::ZExt {
                dst: VReg::phys("r2"),
                src: Value::Reg(VReg::Temp(2)),
                from: crate::ir::types::Width::W8,
                to: crate::ir::types::Width::W32,
            },
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0, 1, 2]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        for slot in [1, 2] {
            assert_eq!(
                prototype
                    .parameter(slot)
                    .and_then(|parameter| parameter.hint),
                Some(TypeHint::Int {
                    signed: false,
                    width: 1,
                }),
                "slot {slot} must retain LDRB's unsigned byte type"
            );
        }
    }

    #[test]
    fn arm_logical_shift_qualifies_one_unsigned_word_parameter() {
        // AAPCS has no unsigned register class, but GCC's LSR for `value / 2`
        // is exact source-level unsignedness evidence. Preserve it through the
        // O0 frame spill without requiring an unrelated second parameter.
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("r7"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("sp")),
                rhs: Value::Const(0),
            },
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -4,
                    size: 4,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("r0")),
            },
            Op::Load {
                dst: VReg::phys("r3"),
                addr: MemOp {
                    base: Some(VReg::phys("r7")),
                    disp: -4,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Bin {
                dst: VReg::phys("r2"),
                op: BinOp::Shr,
                lhs: Value::Reg(VReg::phys("r3")),
                rhs: Value::Const(1),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let valued = recover_types_valued(&lf, &ssa);
        let live_in = SsaValue {
            base: VReg::phys("r0"),
            version: 0,
        };
        assert_eq!(
            valued.get(&live_in),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            }),
            "LSR signedness must reach the exact spilled live-in"
        );
        assert_eq!(
            valued.parameter_refinement(&live_in),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            }),
            "the exact scalar spill proof must qualify the parameter"
        );
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );
    }

    #[test]
    fn arm_direct_logical_shift_outweighs_derived_address_use() {
        // Real shape: ChibiOS `nvicEnableVector(uint32_t n, uint32_t prio)`.
        // `n >> 5` consumes the caller-supplied value as an unsigned word,
        // while `NVIC_BASE + n` derives an MMIO address from the same value.
        // The derived address must not turn the source parameter into `char *`.
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("r3"),
                op: BinOp::Shr,
                lhs: Value::Reg(VReg::phys("r0")),
                rhs: Value::Const(5),
            },
            Op::Bin {
                dst: VReg::phys("r12"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r0")),
                rhs: Value::Const(0xe000_e100),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r12")), None, 0, 0x300, 1),
                src: Value::Reg(VReg::phys("r1")),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0, 1]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            }),
            "direct unsigned-word evidence must own r0: {prototype:#?}"
        );
    }

    #[test]
    fn one_scalar_companion_does_not_corroborate_an_ambiguous_pointer() {
        let pointer = SsaValue {
            base: VReg::phys("r0"),
            version: 0,
        };
        let scalar = SsaValue {
            base: VReg::phys("r1"),
            version: 0,
        };
        let third = SsaValue {
            base: VReg::phys("r2"),
            version: 0,
        };
        let mut types = TypeMapV::default();
        types.upsert_parameter_refinement(pointer.clone(), TypeHint::Pointer { pointee_width: 4 });
        types.upsert_parameter_refinement(
            scalar.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );

        assert_eq!(types.parameter_refinement(&pointer), None);
        assert_eq!(
            types.parameter_refinement(&scalar),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );

        types.upsert_parameter_refinement(
            third,
            TypeHint::Int {
                signed: false,
                width: 1,
            },
        );
        assert_eq!(
            types.parameter_refinement(&pointer),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn lone_narrow_scalar_does_not_override_abi_promotion() {
        // A compiler may spill an enum or promoted integer through a narrow
        // slot after proving its range. One LDRB/LDRH does not by itself prove
        // that the source declaration was char/short.
        let live_in = SsaValue {
            base: VReg::phys("r0"),
            version: 0,
        };
        let mut types = TypeMapV::default();
        types.upsert_parameter_refinement(
            live_in.clone(),
            TypeHint::Int {
                signed: false,
                width: 2,
            },
        );

        assert_eq!(types.parameter_refinement(&live_in), None);
        assert!(types.parameter_refinements().is_empty());
    }

    #[test]
    fn x86_logical_shift_does_not_retype_a_spilled_word_parameter() {
        // The standalone rule targets AAPCS r0-r3, whose register names do not
        // carry width. x86 aliases already encode operand width and must keep
        // their established prototype behavior.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Bin {
                dst: VReg::phys("rcx"),
                op: BinOp::Shr,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(1),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::SysVAmd64,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn wider_pointee_overwrites_narrower() {
        // First use: u8 pointer. Second use: u64 pointer. Result: 8.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 1,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 8,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rbx")),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
    }

    #[test]
    fn return_type_narrowed_from_last_definition() {
        use crate::ir::call_args::CallConv;
        use crate::ir::types::BinOp;
        // rax is used as a pointer base (spurious for the return), but the LAST
        // write to the return register is a 32-bit multiply into eax -> the
        // function returns an int, not a pointer.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Bin {
                dst: VReg::phys("eax"),
                op: BinOp::Mul,
                lhs: Value::Reg(VReg::phys("eax")),
                rhs: Value::Reg(VReg::phys("ecx")),
            },
        ]);
        // Bare recover_types leaves rax as a pointer (union of all uses).
        let raw = recover_types(&lf);
        assert!(matches!(
            raw.get(&VReg::phys("rax")),
            Some(TypeHint::Pointer { .. })
        ));
        // The cc-aware entry corrects it: last def is a 32-bit write to eax.
        let tm = recover_types_for(&lf, CallConv::SysVAmd64);
        assert_eq!(
            tm.get(&VReg::phys("rax")),
            Some(TypeHint::Int {
                signed: true,
                width: 4
            }),
            "return should be narrowed to int from the 32-bit last def"
        );
    }

    #[test]
    fn arm_return_load_keeps_input_pointer_and_output_scalar_separate() {
        use crate::ir::call_args::CallConv;

        // Real ARM leaf shape: r0 enters as a pointer and the load overwrites
        // that same physical register with the scalar returned to the caller.
        // Register-keyed recovery necessarily sees both roles on `r0`; the
        // recovered prototype must retain the two SSA values instead.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("r0"),
                addr: MemOp {
                    base: Some(VReg::phys("r0")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 2,
                    ..Default::default()
                },
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let valued = recover_types_valued(&lf, &ssa);
        assert_eq!(
            valued.get(&SsaValue {
                base: VReg::phys("r0"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 2 }),
            "value-keyed recovery must classify the exact dereferenced live-in"
        );
        let prototype = recover_prototype(&lf, &ssa, CallConv::Arm, &HashSet::from([0]));

        assert_eq!(
            prototype
                .parameter(0)
                .map(|parameter| parameter.value.clone()),
            Some(SsaValue {
                base: VReg::phys("r0"),
                version: 0,
            }),
            "the caller-supplied address must remain the r0 live-in"
        );
        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 2 }),
            "a direct dereference of the exact live-in is sufficient pointer evidence"
        );
        let result = prototype.result().expect("recovered ARM return value");
        assert_eq!(
            result.values,
            vec![SsaValue {
                base: VReg::phys("r0"),
                version: 1,
            }],
            "the loaded scalar must be a distinct SSA output"
        );
        assert!(
            matches!(result.hint, Some(TypeHint::Int { .. })),
            "a scalar load result must not inherit the input pointer type"
        );
        assert!(matches!(
            prototype.result_type_map().get(&VReg::phys("ret")),
            Some(TypeHint::Int { .. })
        ));
    }

    #[test]
    fn arm_spilled_pointer_plus_local_index_refines_the_live_in() {
        // GCC -O0 spills both the caller's buffer and a local loop index.
        // When their reloads are added, both operands look like generic frame
        // reloads; only one slot, however, has caller-supplied provenance.
        // This is the reduced shape of DecBench's console_read(char *buffer).
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("r7"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("sp")),
                rhs: Value::Const(0),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r7")), None, 1, 4, 4),
                src: Value::Reg(VReg::phys("r1")),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r7")), None, 1, 12, 4),
                src: Value::Const(0),
            },
            Op::Load {
                dst: VReg::phys("r2"),
                addr: MemOp::plain(Some(VReg::phys("r7")), None, 1, 4, 4),
            },
            Op::Load {
                dst: VReg::phys("r3"),
                addr: MemOp::plain(Some(VReg::phys("r7")), None, 1, 12, 4),
            },
            Op::Bin {
                dst: VReg::phys("r3"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("r3")),
                rhs: Value::Reg(VReg::phys("r2")),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r3")), None, 1, 0, 1),
                src: Value::Const(65),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([1]),
        );

        assert_eq!(
            prototype.parameter(1).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 1 }),
        );
    }

    #[test]
    fn arm_live_in_with_conflicting_access_widths_is_a_void_pointer() {
        // Optimized byte-buffer routines such as memset access one caller
        // pointer through byte and word stores. Choosing the widest access
        // invents `int *` and makes ordinary char-array call sites invalid C;
        // the honest common contract is an untyped object pointer.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r0")), None, 1, 0, 1),
                src: Value::Const(0),
            },
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("r0")), None, 1, 4, 4),
                src: Value::Const(0),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(
            &lf,
            &ssa,
            crate::ir::call_args::CallConv::Arm,
            &HashSet::from([0]),
        );

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Pointer { pointee_width: 0 }),
        );
    }

    #[test]
    fn arm_unclassified_parameter_uses_the_abi_word_width() {
        use crate::ir::call_args::CallConv;

        // ARM32 has no narrower register spelling corresponding to x86 `edi`
        // or AArch64 `w0`: an ordinary r0 use therefore reaches raw recovery's
        // architecture-neutral eight-byte fallback.  The source parameter
        // cannot exceed its four-byte AAPCS register container.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("sp")),
                    index: None,
                    scale: 0,
                    disp: 4,
                    size: 4,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("r0")),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(&lf, &ssa, CallConv::Arm, &HashSet::from([0]));

        assert_eq!(
            prototype.parameter(0).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn later_outgoing_subregister_value_does_not_narrow_live_in_parameter() {
        use crate::ir::call_args::CallConv;

        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 0,
                    disp: -24,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rsi")),
            },
            Op::Assign {
                dst: VReg::phys("esi"),
                src: Value::Const(1),
            },
            Op::Return,
        ]);
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(&lf, &ssa, CallConv::SysVAmd64, &HashSet::from([1]));

        assert_eq!(
            prototype.parameter(1).and_then(|parameter| parameter.hint),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn prototype_result_unifies_multiple_returning_definitions() {
        use crate::ir::call_args::CallConv;

        let block = |start_va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va,
            end_va: start_va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: start_va + index as u64 * 4,
                    op,
                })
                .collect(),
            succs,
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![Op::CondJump {
                        cond: VReg::phys("r1"),
                        target: 0x1020,
                        inverted: false,
                    }],
                    vec![0x1010, 0x1020],
                ),
                block(
                    0x1010,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("r0"),
                            src: Value::Const(1),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
                block(
                    0x1020,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("r0"),
                            src: Value::Const(2),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        };
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(&lf, &ssa, CallConv::Arm, &HashSet::from([1]));

        let result = prototype
            .result()
            .expect("compatible branch-local definitions form one source result");
        assert_eq!(
            result.values.len(),
            2,
            "the source result must retain both reaching SSA definitions"
        );
        assert!(matches!(
            result.hint,
            Some(TypeHint::Int {
                signed: true,
                width: 4
            })
        ));
        assert!(matches!(
            prototype.result_type_map().get(&VReg::phys("ret")),
            Some(TypeHint::Int { .. })
        ));
    }

    #[test]
    fn prototype_result_propagates_pointer_type_across_null_return() {
        use crate::ir::call_args::CallConv;

        let block = |start_va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va,
            end_va: start_va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: start_va + index as u64 * 4,
                    op,
                })
                .collect(),
            succs,
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![
                        Op::Load {
                            dst: VReg::phys("r3"),
                            addr: MemOp {
                                base: Some(VReg::phys("r2")),
                                size: 4,
                                ..Default::default()
                            },
                        },
                        Op::CondJump {
                            cond: VReg::phys("r1"),
                            target: 0x1020,
                            inverted: false,
                        },
                    ],
                    vec![0x1010, 0x1020],
                ),
                block(
                    0x1010,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("r0"),
                            src: Value::Reg(VReg::phys("r2")),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
                block(
                    0x1020,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("r0"),
                            src: Value::Const(0),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        };
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(&lf, &ssa, CallConv::Arm, &HashSet::from([2]));

        let result = prototype
            .result()
            .expect("pointer and null branches form one source result");
        assert_eq!(result.values.len(), 2);
        assert_eq!(
            result.hint,
            Some(TypeHint::Pointer { pointee_width: 4 }),
            "the canonical pointer type must propagate across the null branch"
        );
        assert_eq!(
            prototype.result_type_map().get(&VReg::phys("ret")),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn prototype_result_rejects_pointer_and_nonzero_integer_join() {
        use crate::ir::call_args::CallConv;

        let block = |start_va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va,
            end_va: start_va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: start_va + index as u64 * 4,
                    op,
                })
                .collect(),
            succs,
        };
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![
                        Op::Load {
                            dst: VReg::phys("r3"),
                            addr: MemOp {
                                base: Some(VReg::phys("r2")),
                                size: 4,
                                ..Default::default()
                            },
                        },
                        Op::CondJump {
                            cond: VReg::phys("r1"),
                            target: 0x1020,
                            inverted: false,
                        },
                    ],
                    vec![0x1010, 0x1020],
                ),
                block(
                    0x1010,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("r0"),
                            src: Value::Reg(VReg::phys("r2")),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
                block(
                    0x1020,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("r0"),
                            src: Value::Const(7),
                        },
                        Op::Return,
                    ],
                    vec![],
                ),
            ],
        };
        let ssa = compute_ssa(&lf);
        let prototype = recover_prototype(&lf, &ssa, CallConv::Arm, &HashSet::from([2]));

        let result = prototype
            .result()
            .expect("both return-reaching SSA definitions remain represented");
        assert_eq!(result.values.len(), 2);
        assert_eq!(
            result.hint, None,
            "a non-null integer cannot share a source result type with a pointer"
        );
        assert!(prototype.result_type_map().is_empty());
    }

    #[test]
    fn result_join_rejects_conflicting_scalar_signedness() {
        assert_eq!(
            join_result_hints(&[
                (
                    TypeHint::Int {
                        signed: true,
                        width: 4,
                    },
                    false,
                ),
                (
                    TypeHint::Int {
                        signed: false,
                        width: 4,
                    },
                    false,
                ),
            ]),
            None,
            "branch-local results must agree before changing the source prototype"
        );
    }

    #[test]
    fn pointer_return_via_full_width_is_preserved() {
        use crate::ir::call_args::CallConv;
        // Last def writes the full 64-bit rax by loading a pointer slot -> a
        // genuine pointer return must survive the refinement.
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rbp")),
                index: None,
                scale: 0,
                disp: -8,
                size: 8,
                ..Default::default()
            },
        }]);
        // Make rax a pointer via a subsequent deref so the union sees a pointer.
        let mut lf = lf;
        lf.blocks[0].instrs.push(LlirInstr {
            va: 0x2000,
            op: Op::Load {
                dst: VReg::phys("rdx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 8,
                    ..Default::default()
                },
            },
        });
        let tm = recover_types_for(&lf, CallConv::SysVAmd64);
        assert!(
            matches!(tm.get(&VReg::phys("rax")), Some(TypeHint::Pointer { .. })),
            "full-width pointer return must be preserved, got {:?}",
            tm.get(&VReg::phys("rax"))
        );
    }

    #[test]
    fn pointer_arg_recovered_through_spill_slot() {
        // -O0 pattern: rdi (arg0) is spilled to [rbp-8], later reloaded into
        // rax which is dereferenced. rax is a pointer; the propagation must
        // push that back onto rdi so the argument types as a pointer.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 0,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 0,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(
            matches!(tm.get(&VReg::phys("rdi")), Some(TypeHint::Pointer { .. })),
            "arg spilled to slot then dereferenced should type as pointer, got {:?}",
            tm.get(&VReg::phys("rdi"))
        );
    }

    #[test]
    fn index_tagged_unsigned_int() {
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rdi")),
                index: Some(VReg::phys("rcx")),
                scale: 4,
                disp: 0,
                size: 4,
                ..Default::default()
            },
        }]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rcx")),
            Some(TypeHint::Int { signed: false, .. })
        ));
    }

    #[test]
    fn cmp_eq_zero_does_not_retype_an_integer_as_bool() {
        use crate::ir::types::{CmpOp, Flag};
        let lf = mk_block(vec![Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(0),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rax")),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn indirect_call_target_is_code_pointer() {
        use crate::ir::types::CallTarget;
        let lf = mk_block(vec![Op::Call {
            target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
            effects: None,
        }]);
        let tm = recover_types(&lf);
        assert_eq!(tm.get(&VReg::phys("rax")), Some(TypeHint::CodePointer));
    }

    #[test]
    fn shift_count_tagged_unsigned() {
        use crate::ir::types::BinOp;
        let lf = mk_block(vec![Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Shl,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Reg(VReg::phys("rcx")),
        }]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rcx")),
            Some(TypeHint::Int { signed: false, .. })
        ));
    }

    #[test]
    fn logical_right_shift_tags_the_shifted_value_unsigned() {
        let lf = mk_block(vec![Op::Bin {
            dst: VReg::phys("edi"),
            op: BinOp::Shr,
            lhs: Value::Reg(VReg::phys("edi")),
            rhs: Value::Const(1),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("edi")),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );
    }

    #[test]
    fn pointer_beats_int_promotion_order() {
        // First: rbx used as arithmetic result (int). Second: rbx used as
        // pointer base. Final type must be pointer.
        use crate::ir::types::BinOp;
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("rbx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rbx")),
                rhs: Value::Const(1),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rbx")),
            Some(TypeHint::Pointer { .. })
        ));
    }

    #[test]
    fn const_assignment_demotes_pointer_classification() {
        // `%rax = load [rax+0]; %rax = 0;` — the load marks %rax as pointer
        // (actually rax is the *dst*, but let's instead use a different
        // reg as a base). Here the scenario is: `rbp` is used as a pointer
        // base in a load, then gets a constant assignment. The constant
        // assignment should demote it.
        use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Load {
                            dst: VReg::phys("rax"),
                            addr: MemOp {
                                base: Some(VReg::phys("rbp")),
                                index: None,
                                scale: 0,
                                disp: 0,
                                size: 8,
                                ..Default::default()
                            },
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rbp"),
                            src: Value::Const(0),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let tm = recover_types(&lf);
        // rbp was seen as a pointer base AND as the target of a const
        // assignment — must be demoted to Int.
        match tm.get(&VReg::phys("rbp")) {
            Some(TypeHint::Int { .. }) | None => {}
            other => panic!("expected Int for demoted rbp; got {:?}", other),
        }
        // Keep the suppress-unused ref to BinOp away from warnings.
        let _ = BinOp::Add;
    }

    #[test]
    fn real_binary_produces_non_empty_type_map() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
                total_timeout_ms: 0,
            },
        );
        let mut saw_pointer = false;
        for f in &funcs {
            if let Ok(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let tm = recover_types(&lf);
                if tm
                    .iter()
                    .any(|(_, t)| matches!(t, TypeHint::Pointer { .. }))
                {
                    saw_pointer = true;
                }
            }
        }
        assert!(
            saw_pointer,
            "expected at least one pointer classification across discovered functions"
        );
    }
}
