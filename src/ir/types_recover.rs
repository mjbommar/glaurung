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

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{BinOp, LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

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
    match hint {
        TypeHint::Int { signed, width } => match (signed, width) {
            (true, 1) => "signed char",
            (false, 1) => "unsigned char",
            (true, 2) => "short",
            (false, 2) => "unsigned short",
            (true, 4) => "int",
            (false, 4) => "unsigned int",
            (false, 8) => "unsigned long",
            _ => "long",
        },
        TypeHint::Pointer { pointee_width } => match pointee_width {
            1 => "char *",
            2 => "short *",
            4 => "int *",
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
        let merged = merge_type_hint(before, hint);
        self.inner.insert(value, merged);
        before != Some(merged)
    }

    fn upsert_parameter_refinement(&mut self, value: SsaValue, hint: TypeHint) -> bool {
        let before = self.parameter_refinements.get(&value).copied();
        let merged = merge_type_hint(before, hint);
        self.parameter_refinements.insert(value, merged);
        before != Some(merged)
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
    /// The full value map is analysis evidence, but output-facing prototype
    /// recovery is not yet a fixed point with function boundaries and callee
    /// prototypes. Until that architecture lands, qualify only the concrete
    /// O0 chain `live-in -> frame spill -> reload -> dereference`, and require
    /// two independently qualified entry values before changing the prototype.
    /// A lone address-taken scalar can otherwise acquire pointer evidence from
    /// an over-discovered tail. Projecting every live-in fact can also replace a
    /// better legacy prototype with evidence from an unknown direct callee.
    pub fn parameter_refinements(&self) -> TypeMap {
        let mut out = TypeMap::default();
        if self
            .parameter_refinements
            .keys()
            .filter(|value| value.version == 0)
            .count()
            < 2
        {
            return out;
        }
        for (value, hint) in &self.parameter_refinements {
            if value.version == 0 {
                out.upsert(value.base.clone(), *hint);
            }
        }
        out
    }

    /// Return the output-qualified fact for one exact caller-supplied value.
    ///
    /// This retains the same two-independent-parameters safety gate as
    /// [`Self::parameter_refinements`], but does not erase SSA identity by
    /// projecting through a raw register key first.
    fn parameter_refinement(&self, value: &SsaValue) -> Option<TypeHint> {
        if self
            .parameter_refinements
            .keys()
            .filter(|candidate| candidate.version == 0)
            .count()
            < 2
        {
            return None;
        }
        (value.version == 0)
            .then(|| self.parameter_refinements.get(value).copied())
            .flatten()
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
    result: Option<RecoveredResult>,
    output_kind: RecoveredOutputKind,
    output_locked: bool,
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

    pub fn result(&self) -> Option<&RecoveredResult> {
        self.result.as_ref()
    }

    pub fn output_kind(&self) -> RecoveredOutputKind {
        self.output_kind
    }

    pub(crate) fn output_is_locked(&self) -> bool {
        self.output_locked
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
            // An unresolved declaration is a fact gap, not permission to
            // discard the machine-code result. Hidden-return declarations need
            // aggregate shape support before they can be applied here.
            RecoveredOutputKind::Unknown | RecoveredOutputKind::HiddenReturn => {}
        }
    }

    /// Project semantic parameter slots to the renderer's source-level role
    /// names.  This is the only name projection: it does not inspect the AST or
    /// reconstruct a register alias table after naming has already run.
    pub fn parameter_type_map(&self) -> TypeMap {
        let mut out = TypeMap::default();
        for parameter in &self.parameters {
            if let Some(hint) = parameter.hint {
                out.upsert_public(VReg::phys(format!("arg{}", parameter.slot)), hint);
            }
        }
        out
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

fn abi_pointer_width(cc: crate::ir::call_args::CallConv) -> u8 {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::Cdecl32 | CallConv::Arm => 4,
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

/// A result fact strong enough to cross the SSA-to-source prototype boundary.
///
/// A narrow load cannot contain a machine pointer, so its scalar class and
/// width are conclusive. A pointer-width load remains unknown: it may be an
/// integer or a pointer read from memory, and guessing either would reproduce
/// the flow-insensitive contamination this prototype object is meant to stop.
fn qualified_result_hint(
    op: &Op,
    valued: &TypeMapV,
    value: &SsaValue,
    cc: crate::ir::call_args::CallConv,
    storage_class: ResultHintClass,
) -> Option<TypeHint> {
    if storage_class == ResultHintClass::Float {
        let Op::Intrinsic { name, outs, .. } = op else {
            return None;
        };
        let semantic_width = match name.as_str() {
            "addss" | "subss" | "mulss" | "divss" => Some(4),
            "addsd" | "subsd" | "mulsd" | "divsd" => Some(8),
            name if name.starts_with("vmov.f32")
                || name.starts_with("vadd.f32")
                || name.starts_with("vsub.f32")
                || name.starts_with("vmul.f32")
                || name.starts_with("vdiv.f32") =>
            {
                Some(4)
            }
            name if name.starts_with("vmov.f64")
                || name.starts_with("vadd.f64")
                || name.starts_with("vsub.f64")
                || name.starts_with("vmul.f64")
                || name.starts_with("vdiv.f64") =>
            {
                Some(8)
            }
            _ => None,
        }?;
        let declared_width = outs
            .iter()
            .find(|(register, _)| register == &value.base)
            .map(|(_, width)| u8::try_from(width.bytes()).expect("LLIR width fits in u8"))?;
        return (declared_width == semantic_width).then_some(TypeHint::Float {
            width: semantic_width,
        });
    }

    match op {
        Op::Load { addr, .. } if addr.size.max(1) < abi_pointer_width(cc) => Some(TypeHint::Int {
            signed: true,
            width: addr.size.max(1),
        }),
        Op::Assign {
            src: Value::Reg(_) | Value::Const(_),
            ..
        }
        | Op::Bin { .. }
        | Op::Un { .. }
        | Op::Cmp { .. }
        | Op::ZExt { .. }
        | Op::SExt { .. }
        | Op::Trunc { .. } => valued
            .get(value)
            .map(|hint| normalize_value_hint_for_abi(hint, cc)),
        // Calls, full-width loads, address constants, conditional updates, and
        // opaque definitions need stronger prototype or merge evidence before
        // they can safely decide pointer-vs-scalar class.
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ResultHintClass {
    Pointer,
    Integer,
    Float,
}

fn result_hint_class(hint: TypeHint) -> ResultHintClass {
    match hint {
        TypeHint::Pointer { .. } | TypeHint::CodePointer => ResultHintClass::Pointer,
        TypeHint::Int { .. } | TypeHint::BoolLike => ResultHintClass::Integer,
        TypeHint::Float { .. } => ResultHintClass::Float,
    }
}

/// Join independently qualified return definitions without inventing a C type
/// that cannot represent all of them.
///
/// Ghidra's `propagateAcrossReturns` first chooses one canonical return type,
/// then propagates it only across compatible return storage. Kuna preserves the
/// same constraint. Our smaller lattice has no union type, so pointer/scalar
/// conflicts fail closed except for C's one compatible scalar value: a literal
/// zero used as a null pointer constant.
fn join_result_hints(facts: &[(TypeHint, bool)]) -> Option<TypeHint> {
    let mut joined = None;
    let mut joined_class = None;
    let mut saw_nonnull_scalar = false;

    for (hint, is_literal_null) in facts {
        let class = result_hint_class(*hint);
        if class == ResultHintClass::Integer && !is_literal_null {
            saw_nonnull_scalar = true;
        }
        match joined_class {
            None => {
                joined = Some(*hint);
                joined_class = Some(class);
            }
            Some(current_class) if current_class == class && joined == Some(*hint) => {}
            Some(current_class) if current_class == class => return None,
            Some(current_class)
                if !saw_nonnull_scalar
                    && matches!(
                        (current_class, class),
                        (ResultHintClass::Pointer, ResultHintClass::Integer)
                            | (ResultHintClass::Integer, ResultHintClass::Pointer)
                    ) =>
            {
                // Every scalar fact seen so far is the literal zero. Preserve
                // the pointer class regardless of branch traversal order.
                if class == ResultHintClass::Pointer {
                    joined = Some(*hint);
                    joined_class = Some(ResultHintClass::Pointer);
                }
            }
            Some(_) => return None,
        }
    }
    joined
}

/// Decide whether one return-register definition is dedicated to the ABI
/// output trial rather than residue from another computation.
///
/// x86 32-bit writes are represented as a semantic write followed by a
/// same-storage zero-extension into the 64-bit parent. Looking only at the
/// final synthetic definition would call every such value "return-only". Walk
/// back through those same-storage view/copy nodes and require the ancestor to
/// have no use except the forwarding node. This is the compact LLIR analogue
/// of Ghidra's incidental COPY/SUBPIECE traversal in `ancestorOpUse` and Kuna's
/// `ancestor_op_use` port.
fn output_trial_is_dedicated(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    candidate: &SsaValue,
    definitions: &HashMap<SsaValue, InstrAddr>,
    non_return_live: &HashSet<SsaValue>,
) -> bool {
    let mut current = candidate.clone();
    let mut visited = HashSet::new();

    while visited.insert(current.clone()) {
        if non_return_live.contains(&current) {
            return false;
        }

        let Some(addr) = definitions.get(&current).copied() else {
            return false;
        };
        let op = &lf.blocks[addr.block_idx].instrs[addr.instr_idx].op;
        let forwards_same_storage = matches!(
            op,
            Op::Assign {
                src: Value::Reg(_),
                ..
            } | Op::ZExt {
                src: Value::Reg(_),
                ..
            } | Op::SExt {
                src: Value::Reg(_),
                ..
            } | Op::Trunc {
                src: Value::Reg(_),
                ..
            }
        );
        if !forwards_same_storage {
            return true;
        }
        let Some(source) = ssa.use_value(lf, addr, 0) else {
            return true;
        };
        if source.base != current.base {
            return true;
        }
        current = source;
    }
    false
}

/// Whether a call result's only explicit consumption is a pure predicate chain.
///
/// `test rax, rax; je fatal; ret` is the canonical optimized shape: the call
/// value is read by control flow *and* is the unchanged machine result on the
/// only returning path.  Treating every compared value as incidental loses
/// that output.  Follow exact SSA uses and allow only view-preserving copies,
/// TEST's self-AND, comparisons, and the final conditional branch; any store,
/// arithmetic, argument use, or other side effect fails closed.
fn call_result_has_only_guard_uses(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    candidate: &SsaValue,
    definitions: &HashMap<SsaValue, InstrAddr>,
) -> bool {
    let Some(definition) = definitions.get(candidate) else {
        return false;
    };
    if !matches!(
        lf.blocks[definition.block_idx].instrs[definition.instr_idx].op,
        Op::Call { .. }
    ) {
        return false;
    }

    let mut pending = vec![candidate.clone()];
    let mut visited = HashSet::new();
    let mut saw_conditional_branch = false;
    while let Some(value) = pending.pop() {
        if !visited.insert(value.clone()) {
            continue;
        }
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let (_, uses) = def_uses(&instruction.op);
                let uses_value = (0..uses.len())
                    .any(|index| ssa.use_value(lf, addr, index).as_ref() == Some(&value));
                if !uses_value {
                    continue;
                }
                match &instruction.op {
                    Op::CondJump { .. } => saw_conditional_branch = true,
                    Op::Assign { .. }
                    | Op::ZExt { .. }
                    | Op::SExt { .. }
                    | Op::Trunc { .. }
                    | Op::Cmp { .. }
                    | Op::Bin {
                        op: crate::ir::types::BinOp::And,
                        ..
                    } => {
                        let Some(next) = ssa.def_value(lf, addr) else {
                            return false;
                        };
                        pending.push(next);
                    }
                    _ => return false,
                }
            }
        }
    }
    saw_conditional_branch
}

/// Values whose dataflow reaches an observable use other than the implicit
/// function return.
///
/// The lifters materialise flag calculations for every arithmetic instruction,
/// even when those flags are dead. Raw use-counting therefore mistakes a dead
/// flag fan-out for source-level consumption. Seed liveness only at side-effect
/// and control-flow operations, then propagate backwards through SSA defs and
/// phi edges. An accumulator returned after a loop stays output-only; the same
/// register used by the loop condition or a store is live residue.
fn non_return_live_values(lf: &LlirFunction, ssa: &SsaInfo) -> HashSet<SsaValue> {
    let mut dependencies: HashMap<SsaValue, Vec<SsaValue>> = HashMap::new();
    let mut live = HashSet::new();

    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let (raw_def, raw_uses) = def_uses(&ins.op);
            let uses: Vec<SsaValue> = (0..raw_uses.len())
                .filter_map(|use_idx| ssa.use_value(lf, addr, use_idx))
                .collect();
            if let Some(definition) = raw_def.as_ref().and_then(|_| ssa.def_value(lf, addr)) {
                dependencies.insert(definition, uses.clone());
            }
            let observable = raw_def.is_none()
                || matches!(ins.op, Op::Call { .. })
                || matches!(
                    ins.op,
                    Op::Intrinsic {
                        reads_mem: true,
                        ..
                    } | Op::Intrinsic {
                        writes_mem: true,
                        ..
                    }
                );
            if observable && !matches!(ins.op, Op::Return | Op::Nop | Op::Jump { .. }) {
                live.extend(uses);
            }
        }
    }

    for phi in &ssa.phis {
        dependencies.insert(
            SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            },
            phi.incoming
                .iter()
                .map(|(_, version)| SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                })
                .collect(),
        );
    }

    loop {
        let before = live.len();
        let frontier: Vec<SsaValue> = live.iter().cloned().collect();
        for value in frontier {
            if let Some(inputs) = dependencies.get(&value) {
                live.extend(inputs.iter().cloned());
            }
        }
        if live.len() == before {
            break;
        }
    }
    live
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
    let raw = recover_types_for(lf, cc);
    let valued = recover_types_valued(lf, ssa);
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
                    has_unsupported_output_trial = true;
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
        .any(|instruction| matches!(instruction.op, Op::Return));
    // ARM32 still lowers broad VFP/DSP instruction families through the
    // footprint-free migration fallback.  Unlike the x86 path (where SIMD
    // arithmetic used for outputs is footprinted above), absence of an ARM
    // result trial in the presence of such an op is not trustworthy.
    let has_opaque_semantics = matches!(cc, crate::ir::call_args::CallConv::Arm)
        && lf
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .any(|instruction| {
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
            });
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
    let output_kind = match (
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

    let parameters = ordered
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
                .or(raw_hint)
                .map(|hint| normalize_value_hint_for_abi(hint, cc));
            Some(RecoveredParameter { slot, value, hint })
        })
        .collect();
    RecoveredPrototype {
        parameters,
        result,
        output_kind,
        output_locked: false,
    }
}

fn merge_type_hint(current: Option<TypeHint>, new: TypeHint) -> TypeHint {
    match (current, new) {
        (None, _) => new,
        // Pointer / CodePointer are the strongest semantic classifications.
        (
            Some(TypeHint::Int { .. }) | Some(TypeHint::Float { .. }) | Some(TypeHint::BoolLike),
            TypeHint::Pointer { .. } | TypeHint::CodePointer,
        ) => new,
        (Some(TypeHint::Pointer { pointee_width: a }), TypeHint::Pointer { pointee_width: b })
            if b > a =>
        {
            new
        }
        (Some(TypeHint::Pointer { .. }) | Some(TypeHint::CodePointer), _) => current.unwrap(),
        (Some(TypeHint::Int { .. }) | Some(TypeHint::BoolLike), TypeHint::Float { .. }) => new,
        (Some(TypeHint::Float { .. }), TypeHint::Int { .. } | TypeHint::BoolLike) => {
            current.unwrap()
        }
        (
            Some(TypeHint::Float {
                width: current_width,
            }),
            TypeHint::Float { width: new_width },
        ) => TypeHint::Float {
            width: current_width.max(new_width),
        },
        (Some(TypeHint::Int { .. }), TypeHint::BoolLike) => new,
        (Some(TypeHint::BoolLike), TypeHint::Int { .. }) => current.unwrap(),
        (Some(TypeHint::BoolLike), TypeHint::BoolLike) => new,
        (
            Some(TypeHint::Int {
                signed: cs,
                width: cw,
            }),
            TypeHint::Int {
                signed: ns,
                width: nw,
            },
        ) => TypeHint::Int {
            signed: cs && ns,
            width: combine_int_width(cw, nw),
        },
    }
}

/// Merge two candidate integer widths. Register sub-names give the true operand
/// width (`edi`=4), while the arithmetic-result fallback conservatively assumes
/// 8; when they disagree the narrower, more-specific width wins. Zero (unknown)
/// defers to the other.
fn combine_int_width(a: u8, b: u8) -> u8 {
    match (a, b) {
        (0, x) | (x, 0) => x,
        (a, b) => a.min(b),
    }
}

fn classify_int_default() -> TypeHint {
    TypeHint::Int {
        signed: true,
        width: 8,
    }
}

/// The byte width a physical register name implies (`edi`->4, `rdi`->8,
/// `w0`->4, `x0`->8, `di`->2, `dil`->1). Falls back to 8 for unknown names.
fn reg_width_bytes(v: &VReg) -> u8 {
    if let VReg::Phys(n) = v {
        if let Some(w) = crate::ir::types::phys_reg_width(n) {
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

/// Tag every physical register that carries a value in `op` with a
/// width-appropriate signed-int hint. The `upsert` policy keeps a more-specific
/// classification (pointer / bool / code-pointer / narrower width), so this only
/// fills in the width for registers nothing else has typed.
fn tag_value_regs(op: &Op, tm: &mut TypeMap) {
    let tag = |val: &Value, tm: &mut TypeMap| {
        if let Value::Reg(r @ VReg::Phys(_)) = val {
            tm.upsert(r.clone(), int_for_reg(r));
        }
    };
    let bytes = |width: crate::ir::types::Width| width.bytes().min(u8::MAX as u16) as u8;
    match op {
        // Jumps through a computed value; the target is an address, and the
        // width hint this pass applies would be wrong for one.
        Op::IndirectJump { .. } => {}
        Op::Assign { dst, src } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), int_for_reg(dst));
            }
            tag(src, tm);
        }
        Op::Store { src, .. } => tag(src, tm),
        Op::Bin { dst, lhs, rhs, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), int_for_reg(dst));
            }
            tag(lhs, tm);
            tag(rhs, tm);
        }
        Op::Un { dst, src, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), int_for_reg(dst));
            }
            tag(src, tm);
        }
        Op::Cmp { lhs, rhs, .. } => {
            tag(lhs, tm);
            tag(rhs, tm);
        }
        Op::ZExt { dst, src, from, to } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(
                    dst.clone(),
                    TypeHint::Int {
                        signed: false,
                        width: bytes(*to),
                    },
                );
            }
            if let Value::Reg(src @ VReg::Phys(_)) = src {
                tm.upsert(
                    src.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*from),
                    },
                );
            }
        }
        Op::SExt { dst, src, from, to } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(
                    dst.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*to),
                    },
                );
            }
            if let Value::Reg(src @ VReg::Phys(_)) = src {
                tm.upsert(
                    src.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*from),
                    },
                );
            }
        }
        Op::Trunc { dst, src, from, to } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(
                    dst.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*to),
                    },
                );
            }
            if let Value::Reg(src @ VReg::Phys(_)) = src {
                tm.upsert(
                    src.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*from),
                    },
                );
            }
        }
        _ => {}
    }
}

/// True for a frame-relative base register (`rbp`/`rsp` on x86-64,
/// `x29`/`sp`/`w29` on AArch64) — the anchors `-O0` code spills locals against.
fn is_frame_base(v: &VReg) -> bool {
    matches!(
        v,
        VReg::Phys(n)
            if matches!(n.as_str(), "rbp" | "rsp" | "ebp" | "esp" | "x29" | "sp" | "w29")
    )
}

/// See the call site in [`recover_types`]. Two forward passes over `lf`:
///   1. record `slot -> register` for each spill store `[frame+disp] = reg`;
///   2. for each reload `reg = [frame+disp]` whose destination is already a
///      pointer in `tm`, propagate that pointer back to the spilled register.
fn propagate_spill_slot_pointers(lf: &LlirFunction, tm: &mut TypeMap) {
    // slot (frame-base name, disp) -> the register most recently spilled there.
    let mut spilled_from: HashMap<(String, i64), VReg> = HashMap::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Store {
                addr,
                src: Value::Reg(r @ VReg::Phys(_)),
            } = &ins.op
            {
                if let Some(base) = &addr.base {
                    if is_frame_base(base) && addr.index.is_none() {
                        if let VReg::Phys(bn) = base {
                            spilled_from.insert((bn.clone(), addr.disp), r.clone());
                        }
                    }
                }
            }
        }
    }
    if spilled_from.is_empty() {
        return;
    }
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Load { dst, addr } = &ins.op {
                if let Some(base) = &addr.base {
                    if is_frame_base(base) && addr.index.is_none() {
                        if let VReg::Phys(bn) = base {
                            if let (Some(src_reg), Some(TypeHint::Pointer { pointee_width })) =
                                (spilled_from.get(&(bn.clone(), addr.disp)), tm.get(dst))
                            {
                                tm.upsert(src_reg.clone(), TypeHint::Pointer { pointee_width });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The registers that carry the return value under `cc`, widest first.
fn return_reg_names(cc: crate::ir::call_args::CallConv) -> &'static [&'static str] {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["rax", "eax", "ax", "al"],
        CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        CallConv::Arm => &["r0"],
    }
}

/// Dedicated floating-point result storage under `cc`, widest aliases first.
fn float_return_reg_names(cc: crate::ir::call_args::CallConv) -> &'static [&'static str] {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["xmm0", "ymm0", "zmm0"],
        CallConv::Cdecl32 => &["st0", "xmm0"],
        CallConv::Aarch64 => &["v0", "q0", "d0", "s0", "h0", "b0"],
        CallConv::Arm => &["d0", "s0"],
    }
}

/// The destination register an op writes to (if it writes a value register).
fn op_dst_reg(op: &Op) -> Option<&VReg> {
    match op {
        Op::Assign { dst, .. }
        | Op::Bin { dst, .. }
        | Op::Un { dst, .. }
        | Op::Load { dst, .. } => Some(dst),
        _ => None,
    }
}

/// Correct the return register's type from the value that is actually
/// *returned*, not the flow-insensitive union of every use of the ABI return
/// register. At `-O0` `rax` is heavily reused as scratch — often as a pointer
/// base while computing an integer result — so the union wrongly reports a
/// pointer return (e.g. `char *str_len(...)` that really returns `int`).
///
/// Key fact: a value produced into a **sub-64-bit** view of the return register
/// (`eax`/`ax`/`al`, `w0`) cannot be a 64-bit pointer. So when the *last*
/// definition of the return register in program order writes such a narrow
/// view, we overwrite every return-register alias with that concrete integer
/// width, clearing any spurious pointer classification. A genuine pointer
/// return writes the full 64-bit register and is left untouched.
fn refine_return_type(lf: &LlirFunction, tm: &mut TypeMap, cc: crate::ir::call_args::CallConv) {
    let ret_names = return_reg_names(cc);
    let mut last_dst: Option<VReg> = None;
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Some(VReg::Phys(n)) = op_dst_reg(&ins.op) {
                if ret_names.contains(&n.as_str()) {
                    last_dst = Some(VReg::phys(n));
                }
            }
        }
    }
    let Some(dst) = last_dst else {
        return;
    };
    let w = reg_width_bytes(&dst);
    if w == 0 || w >= 8 {
        // Full-width (or unknown) last definition: could legitimately be a
        // pointer or a `long`; leave the recovered classification alone.
        return;
    }
    let signed = match tm.get(&dst) {
        Some(TypeHint::Int { signed, .. }) => signed,
        _ => true,
    };
    let hint = TypeHint::Int { signed, width: w };
    for n in ret_names {
        let key = VReg::phys(*n);
        if tm.inner.contains_key(&key) {
            tm.inner.insert(key, hint);
        }
    }
}

/// Production entry point: [`recover_types`] plus the calling-convention-aware
/// return-type correction. Callers that know the ABI (the Python bindings)
/// should prefer this over the bare [`recover_types`].
pub fn recover_types_for(lf: &LlirFunction, cc: crate::ir::call_args::CallConv) -> TypeMap {
    let mut tm = recover_types(lf);
    refine_return_type(lf, &mut tm, cc);
    tm
}

/// Registers whose value is a pure *offset / scaled index* — the index side of
/// an `base + index` address computation, never the pointer base. A register is
/// an offset if it is defined by a multiply or shift (`i * 4`, `i << 2`), or by
/// an add/sub that only combines constants and other offset registers
/// (`0 + i*4`, the `-O0` `lea` idiom). Computed to a fixpoint.
fn offset_registers(lf: &LlirFunction) -> std::collections::HashSet<VReg> {
    let mut offsets: std::collections::HashSet<VReg> = std::collections::HashSet::new();
    let is_off = |offsets: &std::collections::HashSet<VReg>, v: &Value| match v {
        Value::Const(_) => true,
        Value::Reg(r) => offsets.contains(r),
        Value::Addr(_) => false,
    };
    for _ in 0..8 {
        let mut grew = false;
        for block in &lf.blocks {
            for ins in &block.instrs {
                if let Op::Bin { op, dst, lhs, rhs } = &ins.op {
                    let dst_is_off = match op {
                        // A multiply/shift result is a scaled index.
                        BinOp::Mul | BinOp::Shl => true,
                        // An add/sub is an offset only if *both* sides are.
                        BinOp::Add | BinOp::Sub => is_off(&offsets, lhs) && is_off(&offsets, rhs),
                        _ => false,
                    };
                    if dst_is_off && offsets.insert(dst.clone()) {
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    offsets
}

/// Registers that hold a *reload of a spilled value* — the destination of a
/// `Load` from a frame-base slot with no index (`rax = [rbp-24]`). At `-O0` a
/// spilled pointer argument is reloaded this way before each dereference, so a
/// reload operand of an address `add` is the pointer base (the other operand is
/// the index). Feeding these to [`propagate_spill_slot_pointers`] then carries
/// the pointer type back to the incoming argument register.
fn frame_slot_reloads(lf: &LlirFunction) -> std::collections::HashSet<VReg> {
    let mut reloads = std::collections::HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Load { dst, addr } = &ins.op {
                if let Some(base) = &addr.base {
                    if is_frame_base(base) && addr.index.is_none() {
                        reloads.insert(dst.clone());
                    }
                }
            }
        }
    }
    reloads
}

/// Propagate pointer-ness backward through address arithmetic: if a register
/// `p` is used as a pointer (dereferenced) and is defined by `p = base + off`,
/// then `base` is a pointer too. This recovers `T *` argument types once the
/// spill-slot has been coalesced away and the parameter is used directly as
/// `*(base + i*scale)` — the shape value-numbering produces for `a[i]`. Iterated
/// to a fixpoint so a chain of address additions all resolve.
///
/// The base is identified structurally, not by existing type (a spilled pointer
/// parameter looks like a plain `long` until this pass runs, which a type-based
/// heuristic gets backwards). Two complementary signals:
///  * the *offset* operand is a constant or a scaled-index register
///    ([`offset_registers`]) — so the other operand is the base; and
///  * the *base* operand is a frame-slot reload ([`frame_slot_reloads`]) — the
///    reloaded spilled pointer — so the other operand is the index.
fn propagate_pointer_arithmetic(lf: &LlirFunction, tm: &mut TypeMap) {
    let offsets = offset_registers(lf);
    let reloads = frame_slot_reloads(lf);
    let is_offset = |v: &Value| match v {
        Value::Const(_) => true,
        Value::Reg(r) => offsets.contains(r),
        Value::Addr(_) => false,
    };
    let is_reload = |v: &Value| matches!(v, Value::Reg(r) if reloads.contains(r));
    for _ in 0..8 {
        let mut changed = false;
        for block in &lf.blocks {
            for ins in &block.instrs {
                if let Op::Bin {
                    op: BinOp::Add,
                    dst,
                    lhs,
                    rhs,
                } = &ins.op
                {
                    let pw = match tm.get(dst) {
                        Some(TypeHint::Pointer { pointee_width }) => pointee_width,
                        _ => continue,
                    };
                    // Prefer the reload signal (base is the reloaded pointer);
                    // fall back to the offset signal (base is the non-offset
                    // operand). Both agree in the common `*(reload + i*scale)`.
                    let base = if is_reload(lhs) && !is_reload(rhs) {
                        Some(lhs)
                    } else if is_reload(rhs) && !is_reload(lhs) {
                        Some(rhs)
                    } else if is_offset(rhs) && !is_offset(lhs) {
                        Some(lhs)
                    } else if is_offset(lhs) && !is_offset(rhs) {
                        Some(rhs)
                    } else {
                        // Can't tell base from index; leave it alone.
                        None
                    };
                    if let Some(Value::Reg(r)) = base {
                        // Don't downgrade / re-tag an already-pointer register.
                        if !matches!(tm.get(r), Some(TypeHint::Pointer { .. })) {
                            let before = tm.get(r);
                            tm.upsert(r.clone(), TypeHint::Pointer { pointee_width: pw });
                            if tm.get(r) != before {
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
}

/// Raw operands paired with the SSA value each occurrence reads or writes.
/// Keeping the raw operand beside the canonical value is important: the raw
/// spelling retains machine width (`edi` is four bytes), while [`SsaValue`]
/// supplies the cross-view identity (`edi` and `rdi` are the same storage).
struct InstructionValues {
    def: Option<(VReg, SsaValue)>,
    uses: Vec<Option<(VReg, SsaValue)>>,
}

fn instruction_values(lf: &LlirFunction, ssa: &SsaInfo, addr: InstrAddr) -> InstructionValues {
    let op = &lf.blocks[addr.block_idx].instrs[addr.instr_idx].op;
    let (raw_def, raw_uses) = def_uses(op);
    let def = raw_def.zip(ssa.def_value(lf, addr));
    let uses = raw_uses
        .into_iter()
        .enumerate()
        .map(|(index, raw)| ssa.use_value(lf, addr, index).map(|value| (raw, value)))
        .collect();
    InstructionValues { def, uses }
}

fn operand_value(
    operand: &Value,
    values: &InstructionValues,
    cursor: &mut usize,
) -> Option<SsaValue> {
    if !matches!(operand, Value::Reg(_)) {
        return None;
    }
    let value = values
        .uses
        .get(*cursor)
        .and_then(|entry| entry.as_ref())
        .map(|(_, value)| value.clone());
    *cursor += 1;
    value
}

/// Registers carrying a stable address derived only by copies or a constant
/// displacement from an architectural stack/frame pointer.
///
/// ARM32 GCC commonly establishes `r7 = sp + 0` and spills incoming values
/// relative to `r7`. Following that value shape is safer than globally
/// declaring every use of callee-saved `r7` to be a frame access.
fn frame_base_aliases(lf: &LlirFunction) -> HashSet<VReg> {
    let mut bases = HashSet::from([
        VReg::phys("rbp"),
        VReg::phys("rsp"),
        VReg::phys("ebp"),
        VReg::phys("esp"),
        VReg::phys("x29"),
        VReg::phys("w29"),
        VReg::phys("sp"),
    ]);
    for _ in 0..8 {
        let mut grew = false;
        for block in &lf.blocks {
            for instruction in &block.instrs {
                let alias = match &instruction.op {
                    Op::Assign {
                        dst,
                        src: Value::Reg(source),
                    } if bases.contains(source) => Some(dst),
                    Op::Bin {
                        dst,
                        op: BinOp::Add | BinOp::Sub,
                        lhs: Value::Reg(base),
                        rhs: Value::Const(_),
                    } if bases.contains(base) => Some(dst),
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Const(_),
                        rhs: Value::Reg(base),
                    } if bases.contains(base) => Some(dst),
                    _ => None,
                };
                if let Some(alias) = alias {
                    grew |= bases.insert(alias.clone());
                }
            }
        }
        if !grew {
            break;
        }
    }
    bases
}

fn frame_slot(
    addr: &crate::ir::types::MemOp,
    frame_bases: &HashSet<VReg>,
) -> Option<(String, i64)> {
    if addr.index.is_some() {
        return None;
    }
    match addr.base.as_ref() {
        Some(base @ VReg::Phys(name)) if frame_bases.contains(base) => {
            Some((name.clone(), addr.disp))
        }
        _ => None,
    }
}

fn unify_values(tm: &mut TypeMapV, a: &SsaValue, b: &SsaValue) -> bool {
    let a_hint = tm.get(a);
    let b_hint = tm.get(b);
    let mut changed = false;
    if let Some(hint) = a_hint {
        changed |= tm.upsert(b.clone(), hint);
    }
    if let Some(hint) = b_hint {
        changed |= tm.upsert(a.clone(), hint);
    }
    changed
}

/// Values participating in a phi whose result can reach a real instruction
/// use. Our SSA builder deliberately places unpruned phis; treating a dead phi
/// as a type-equivalence edge merges unrelated storage lifetimes at CFG exits.
fn live_phi_values(lf: &LlirFunction, ssa: &SsaInfo) -> HashSet<SsaValue> {
    let mut live = HashSet::new();
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, _) in block.instrs.iter().enumerate() {
            let values = instruction_values(
                lf,
                ssa,
                InstrAddr {
                    block_idx,
                    instr_idx,
                },
            );
            live.extend(values.uses.into_iter().flatten().map(|(_, value)| value));
        }
    }
    for _ in 0..ssa.phis.len().max(1) {
        let mut grew = false;
        for phi in &ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if !live.contains(&result) {
                continue;
            }
            for (_, version) in &phi.incoming {
                grew |= live.insert(SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                });
            }
        }
        if !grew {
            break;
        }
    }
    live
}

/// Recover type facts per SSA definition.
///
/// The inference rules deliberately mirror the established raw-register pass,
/// but all propagation edges carry [`SsaValue`] identities. Copies and phis
/// unify values, stack spills preserve the exact value stored, and pointer
/// arithmetic walks definition/use edges. A later constant definition can
/// therefore be demoted without erasing an earlier pointer in the same
/// architectural register.
pub fn recover_types_valued(lf: &LlirFunction, ssa: &SsaInfo) -> TypeMapV {
    let mut tm = TypeMapV::default();
    let mut constant_defs: HashMap<SsaValue, TypeHint> = HashMap::new();
    let mut copy_edges: Vec<(SsaValue, SsaValue)> = Vec::new();
    let mut reloads: HashSet<SsaValue> = HashSet::new();
    // Exact caller-supplied values spilled into frame slots, together with the
    // store width. Width is part of the provenance proof: a later byte reload
    // may refine an incoming byte only when the entry value was itself stored
    // as a byte, rather than after an unrelated wider slot was partially read.
    let mut live_in_spills: HashMap<(String, i64), Vec<(SsaValue, u8)>> = HashMap::new();
    let live_phi_values = live_phi_values(lf, ssa);
    let frame_bases = frame_base_aliases(lf);

    // Seed local facts and record explicit value-flow edges.
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let values = instruction_values(lf, ssa, addr);

            // Width evidence comes from the raw view at this occurrence.
            if let Some((raw, value)) = &values.def {
                if matches!(raw, VReg::Phys(_)) {
                    tm.upsert(value.clone(), int_for_reg(raw));
                }
            }
            for (raw, value) in values.uses.iter().flatten() {
                if matches!(raw, VReg::Phys(_)) {
                    tm.upsert(value.clone(), int_for_reg(raw));
                }
            }

            match &ins.op {
                Op::Assign { src, .. } => {
                    if let (Some((_, dst)), Value::Reg(_)) = (&values.def, src) {
                        if let Some((_, source)) = values.uses.first().and_then(Option::as_ref) {
                            copy_edges.push((dst.clone(), source.clone()));
                        }
                    } else if matches!(src, Value::Const(_)) {
                        if let Some((raw, dst)) = &values.def {
                            constant_defs.insert(dst.clone(), int_for_reg(raw));
                        }
                    }
                }
                Op::Load { addr, .. } => {
                    let mut use_index = 0usize;
                    if addr.base.is_some() {
                        if let Some((_, base)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                base.clone(),
                                TypeHint::Pointer {
                                    pointee_width: addr.size.max(1),
                                },
                            );
                        }
                        use_index += 1;
                    }
                    if addr.index.is_some() {
                        if let Some((raw, index)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                index.clone(),
                                TypeHint::Int {
                                    signed: false,
                                    width: reg_width_bytes(raw),
                                },
                            );
                        }
                    }
                    if frame_slot(addr, &frame_bases).is_some() {
                        if let Some((_, dst)) = &values.def {
                            reloads.insert(dst.clone());
                        }
                    }
                }
                Op::Store { addr, .. } => {
                    let mut use_index = 0usize;
                    if addr.base.is_some() {
                        if let Some((_, base)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                base.clone(),
                                TypeHint::Pointer {
                                    pointee_width: addr.size.max(1),
                                },
                            );
                        }
                        use_index += 1;
                    }
                    if addr.index.is_some() {
                        if let Some((raw, index)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                index.clone(),
                                TypeHint::Int {
                                    signed: false,
                                    width: reg_width_bytes(raw),
                                },
                            );
                        }
                        use_index += 1;
                    }
                    if let Some(slot) = frame_slot(addr, &frame_bases) {
                        if let Some((_, source)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            // Keep the exact stored value for now. GCC commonly
                            // emits `r3 = r1; strb r3, [frame]` for an AAPCS
                            // byte parameter, so the caller-supplied provenance
                            // may sit behind one or more pure copies. Those copy
                            // edges are resolved after this seed walk.
                            let sources = live_in_spills.entry(slot).or_default();
                            let spill = (source.clone(), addr.size.max(1));
                            if !sources.contains(&spill) {
                                sources.push(spill);
                            }
                        }
                    }
                }
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Reg(_)),
                    ..
                }
                | Op::IndirectJump {
                    target: Value::Reg(_),
                } => {
                    if let Some((_, target)) = values.uses.first().and_then(Option::as_ref) {
                        tm.upsert(target.clone(), TypeHint::CodePointer);
                    }
                }
                Op::Bin {
                    op: BinOp::Shr,
                    lhs,
                    rhs,
                    ..
                } => {
                    if let Some((raw, dst)) = &values.def {
                        tm.upsert(
                            dst.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                    let mut cursor = 0;
                    if let Some(lhs_value) = operand_value(lhs, &values, &mut cursor) {
                        let raw = match lhs {
                            Value::Reg(raw) => raw,
                            _ => unreachable!(),
                        };
                        tm.upsert(
                            lhs_value,
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                    if let Some(rhs_value) = operand_value(rhs, &values, &mut cursor) {
                        let raw = match rhs {
                            Value::Reg(raw) => raw,
                            _ => unreachable!(),
                        };
                        tm.upsert(
                            rhs_value,
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                }
                Op::Bin {
                    op: BinOp::Shl | BinOp::Sar,
                    lhs,
                    rhs,
                    ..
                } => {
                    let mut cursor = 0;
                    let _ = operand_value(lhs, &values, &mut cursor);
                    if let Some(rhs_value) = operand_value(rhs, &values, &mut cursor) {
                        let raw = match rhs {
                            Value::Reg(raw) => raw,
                            _ => unreachable!(),
                        };
                        tm.upsert(
                            rhs_value,
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                }
                Op::ZExt { src, from, to, .. }
                | Op::SExt { src, from, to, .. }
                | Op::Trunc { src, from, to, .. } => {
                    let signed = !matches!(&ins.op, Op::ZExt { .. });
                    if let Some((_, dst)) = &values.def {
                        tm.upsert(
                            dst.clone(),
                            TypeHint::Int {
                                signed,
                                width: to.bytes().min(u8::MAX as u16) as u8,
                            },
                        );
                    }
                    let mut cursor = 0;
                    if let Some(source) = operand_value(src, &values, &mut cursor) {
                        tm.upsert(
                            source,
                            TypeHint::Int {
                                signed,
                                width: from.bytes().min(u8::MAX as u16) as u8,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // Resolve frame-spill provenance through exact copies only. This admits
    // the real ARM `r1 -> r3 -> strb` prologue without treating arithmetic,
    // calls, or later scratch reuse as caller input. SSA definitions make the
    // predecessor relation single-valued; the visited set is a fail-closed
    // guard against malformed cyclic input.
    let copy_sources: HashMap<SsaValue, SsaValue> = copy_edges.iter().cloned().collect();
    for spills in live_in_spills.values_mut() {
        let mut resolved = Vec::new();
        for (source, width) in std::mem::take(spills) {
            let mut candidate = source;
            let mut visited = HashSet::new();
            loop {
                if candidate.version == 0 && matches!(candidate.base, VReg::Phys(_)) {
                    let spill = (candidate, width);
                    if !resolved.contains(&spill) {
                        resolved.push(spill);
                    }
                    break;
                }
                if !visited.insert(candidate.clone()) {
                    break;
                }
                let Some(predecessor) = copy_sources.get(&candidate) else {
                    break;
                };
                candidate = predecessor.clone();
            }
        }
        *spills = resolved;
    }
    live_in_spills.retain(|_, spills| !spills.is_empty());

    // Compute scaled-index/offset values using SSA operands, not register names.
    let mut offsets: HashSet<SsaValue> = HashSet::new();
    for _ in 0..8 {
        let mut grew = false;
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, ins) in block.instrs.iter().enumerate() {
                let Op::Bin { op, lhs, rhs, .. } = &ins.op else {
                    continue;
                };
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let values = instruction_values(lf, ssa, addr);
                let Some((_, dst)) = &values.def else {
                    continue;
                };
                let mut cursor = 0;
                let lhs_value = operand_value(lhs, &values, &mut cursor);
                let rhs_value = operand_value(rhs, &values, &mut cursor);
                let is_offset = |operand: &Value, value: &Option<SsaValue>| match operand {
                    Value::Const(_) => true,
                    Value::Reg(_) => value.as_ref().is_some_and(|value| offsets.contains(value)),
                    Value::Addr(_) => false,
                };
                let result_is_offset = match op {
                    BinOp::Mul | BinOp::Shl => true,
                    BinOp::Add | BinOp::Sub => {
                        is_offset(lhs, &lhs_value) && is_offset(rhs, &rhs_value)
                    }
                    _ => false,
                };
                if result_is_offset && offsets.insert(dst.clone()) {
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }

    // Start from exact SSA values used as memory bases, then walk only
    // value-preserving copies, live phis, and structurally identified pointer
    // arithmetic backwards. A raw-register pointer hint is not sufficient:
    // ARM call-heavy functions routinely reuse r1/r2 as later pointer scratch,
    // which must not retype the incoming full-width integer parameters.
    let mut address_values = HashSet::new();
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            if !matches!(instruction.op, Op::Load { .. } | Op::Store { .. }) {
                continue;
            }
            let values = instruction_values(
                lf,
                ssa,
                InstrAddr {
                    block_idx,
                    instr_idx,
                },
            );
            if let Some((_, base)) = values.uses.first().and_then(Option::as_ref) {
                address_values.insert(base.clone());
            }
        }
    }
    for _ in 0..16 {
        let mut grew = false;
        for (dst, source) in &copy_edges {
            if address_values.contains(dst) {
                grew |= address_values.insert(source.clone());
            }
        }
        for phi in &ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if !live_phi_values.contains(&result) || !address_values.contains(&result) {
                continue;
            }
            for (_, version) in &phi.incoming {
                grew |= address_values.insert(SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                });
            }
        }
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let Op::Bin {
                    op: BinOp::Add | BinOp::Sub,
                    lhs,
                    rhs,
                    ..
                } = &instruction.op
                else {
                    continue;
                };
                let values = instruction_values(
                    lf,
                    ssa,
                    InstrAddr {
                        block_idx,
                        instr_idx,
                    },
                );
                let Some((_, dst)) = &values.def else {
                    continue;
                };
                if !address_values.contains(dst) {
                    continue;
                }
                let mut cursor = 0;
                let lhs_value = operand_value(lhs, &values, &mut cursor);
                let rhs_value = operand_value(rhs, &values, &mut cursor);
                let is_offset = |operand: &Value, value: &Option<SsaValue>| match operand {
                    Value::Const(_) => true,
                    Value::Reg(_) => value
                        .as_ref()
                        .is_some_and(|candidate| offsets.contains(candidate)),
                    Value::Addr(_) => false,
                };
                let base = if is_offset(rhs, &rhs_value) && !is_offset(lhs, &lhs_value) {
                    lhs_value
                } else if matches!(instruction.op, Op::Bin { op: BinOp::Add, .. })
                    && is_offset(lhs, &lhs_value)
                    && !is_offset(rhs, &rhs_value)
                {
                    rhs_value
                } else {
                    None
                };
                if let Some(base) = base {
                    grew |= address_values.insert(base);
                }
            }
        }
        if !grew {
            break;
        }
    }

    // Copies, MULTIEQUAL/phi edges, pointer arithmetic, and spill slots feed
    // each other. Iterate them as one small monotone data-flow problem.
    for _ in 0..16 {
        let mut changed = false;
        for (dst, source) in &copy_edges {
            changed |= unify_values(&mut tm, dst, source);
        }
        for phi in &ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if !live_phi_values.contains(&result) {
                continue;
            }
            for (_, version) in &phi.incoming {
                let incoming = SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                };
                changed |= unify_values(&mut tm, &result, &incoming);
            }
        }

        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, ins) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let values = instruction_values(lf, ssa, addr);
                match &ins.op {
                    Op::Bin {
                        op: BinOp::Add,
                        lhs,
                        rhs,
                        ..
                    } => {
                        let Some((_, dst)) = &values.def else {
                            continue;
                        };
                        let Some(TypeHint::Pointer { pointee_width }) = tm.get(dst) else {
                            continue;
                        };
                        let mut cursor = 0;
                        let lhs_value = operand_value(lhs, &values, &mut cursor);
                        let rhs_value = operand_value(rhs, &values, &mut cursor);
                        let is_offset = |operand: &Value, value: &Option<SsaValue>| match operand {
                            Value::Const(_) => true,
                            Value::Reg(_) => {
                                value.as_ref().is_some_and(|value| offsets.contains(value))
                            }
                            Value::Addr(_) => false,
                        };
                        let is_reload = |value: &Option<SsaValue>| {
                            value.as_ref().is_some_and(|value| reloads.contains(value))
                        };
                        let base = if is_reload(&lhs_value) && !is_reload(&rhs_value) {
                            lhs_value
                        } else if is_reload(&rhs_value) && !is_reload(&lhs_value) {
                            rhs_value
                        } else if is_offset(rhs, &rhs_value) && !is_offset(lhs, &lhs_value) {
                            lhs_value
                        } else if is_offset(lhs, &lhs_value) && !is_offset(rhs, &rhs_value) {
                            rhs_value
                        } else {
                            None
                        };
                        if let Some(base) = base {
                            changed |= tm.upsert(base, TypeHint::Pointer { pointee_width });
                        }
                    }
                    Op::Load { addr, .. } => {
                        let Some(slot) = frame_slot(addr, &frame_bases) else {
                            continue;
                        };
                        let Some(sources) = live_in_spills.get(&slot) else {
                            continue;
                        };
                        let Some((_, dst)) = &values.def else {
                            continue;
                        };
                        match tm.get(dst) {
                            Some(TypeHint::Pointer { pointee_width })
                                if address_values.contains(dst) =>
                            {
                                for (source, stored_width) in sources {
                                    if *stored_width != addr.size.max(1) {
                                        continue;
                                    }
                                    let hint = TypeHint::Pointer { pointee_width };
                                    changed |= tm.upsert(source.clone(), hint);
                                    changed |= tm.upsert_parameter_refinement(source.clone(), hint);
                                }
                            }
                            Some(hint @ TypeHint::Int { width: 1 | 2, .. }) if matches!(hint, TypeHint::Int { width, .. } if width == addr.size.max(1)) =>
                            {
                                // A narrow entry spill followed by a same-width
                                // reload and explicit ZExt/SExt is source-level
                                // parameter evidence, not just storage reuse.
                                // The extension carried by the exact reloaded SSA
                                // value decides unsigned vs signed.
                                for (source, stored_width) in sources {
                                    if *stored_width != addr.size.max(1) {
                                        continue;
                                    }
                                    changed |= tm.upsert(source.clone(), hint);
                                    changed |= tm.upsert_parameter_refinement(source.clone(), hint);
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Constants demote only the definition that received the constant. They do
    // not erase an earlier pointer/code-pointer lifetime in the same storage.
    for (value, hint) in constant_defs {
        tm.inner.insert(value, hint);
    }

    tm
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
                Op::Load { addr, .. } | Op::Store { addr, .. } => {
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
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};

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
        let object = object::read::File::parse(data.as_slice()).expect("parse GCC ELF");
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
        let object = object::read::File::parse(data.as_slice()).expect("parse fixture ELF");
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
            .unwrap_or_else(|| panic!("lift {name}"));
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
            let object = object::read::File::parse(data.as_slice()).expect("parse fixture ELF");
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
                .unwrap_or_else(|| panic!("lift {compiler} {name}"));
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
        let object = object::read::File::parse(data.as_slice()).expect("parse fixture ELF");
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
            .unwrap_or_else(|| panic!("lift {name}"));
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
        let object = object::read::File::parse(data.as_slice()).expect("parse hard-float ELF");
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
            let object = object::read::File::parse(data.as_slice()).expect("parse x86 float ELF");
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
        let object = object::read::File::parse(data.as_slice()).expect("parse GCC ELF");
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
            },
        );
        let mut saw_pointer = false;
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
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
