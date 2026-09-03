//! What the DecBench renderer declares, decided once, before anything prints.
//!
//! Rendering a function to C requires a set of decisions that are *not*
//! formatting: what C type each parameter carries, whether the function returns
//! `void`, which body identifiers are scalars and which are whole frame objects
//! or 128-bit vector temporaries, and what integer width and signedness each
//! declared name was given. Those answers are then consulted from deep inside
//! the expression printer, because a conversion at a representation boundary is
//! only correct against the declaration that was actually emitted.
//!
//! The renderer used to hold those answers in eight separate mutable
//! thread-locals which it filled *as it printed* — the declaration block wrote
//! `DEC_DECLARED_CTYPES` on the same pass that emitted the `long x;` line, so
//! what the body printed depended on a side effect of the statement above it.
//! There was no object to name, inspect, or test, and no way to tell a
//! declaration decision from a formatting one.
//!
//! This module is that object. [`DeclarationPlan::compute`] is a pure function
//! of values — no ambient state is read and none is written — and the renderer
//! installs the result once and then only reads it. The plan is immutable for
//! the whole render, so the printer cannot change a declaration by printing.
//!
//! Scope is deliberately one responsibility. The renderer's other ambient
//! context (source-local renaming, the selected callee prototype table, the
//! renderable-struct set, the global-address set, pointer width, and the
//! semantic wide-cast flag) stays where it is: those answer different questions
//! and would only be coupled back together by moving them here.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::dwarf_render_types::{
    dwarf_prototype_type_is_renderable, source_type_with_complete_struct_alias,
};
use super::{
    ctype_for, infer_return_ctype, is_high_variable, is_promoted_local_in, parse_arg_index,
    CallPrototype, DecIdents, Stmt, TypeHint, TypeMap, VReg,
};
use crate::ir::dwarf_type_env::DwarfTypeEnv;
use crate::ir::types_recover::RecoveredOutputKind;

/// The storage a body-local identifier is declared with.
///
/// The three forms are mutually exclusive and the choice is a semantic one, not
/// a spelling one: a recovered frame object must reserve its complete extent, a
/// value that occupies a whole vector register must not be narrowed to a
/// scalar, and everything else takes a recovered scalar type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LocalDeclaration {
    /// An address-taken frame object of `bytes` bytes.
    StackObject { bytes: u16 },
    /// A value occupying all 16 bytes of a vector register.
    WideVector,
    /// An ordinary scalar declared with this exact C type.
    Scalar { c_type: String },
}

/// Everything the declaration decision depends on.
///
/// Passed as one struct rather than eleven positional parameters so that adding
/// an input is a visible change to the contract of the decision, not a silent
/// extension of an already-long argument list.
pub(super) struct DeclarationInputs<'a> {
    /// Identifiers and storage facts collected from the body by the ident walk.
    pub(super) ids: &'a DecIdents,
    /// The prepared body, used only to type the value actually returned.
    pub(super) body: &'a [Stmt],
    /// Recovered declaration types.
    pub(super) tm: Option<&'a TypeMap>,
    /// Pre-canonicalisation machine widths (see `DeclarationPlan::integer_width`).
    pub(super) width_tm: Option<&'a TypeMap>,
    /// The recovered output contract for the function.
    pub(super) output_kind: RecoveredOutputKind,
    /// An authoritative source prototype, already filtered for arity and
    /// renderability by the caller.
    pub(super) declared_prototype: Option<&'a CallPrototype>,
    /// Source parameter names paired with the authoritative declaration.
    pub(super) declared_parameter_names: Option<&'a [Option<String>]>,
    /// Signature arity, which is an ABI property and may exceed the arguments
    /// still referenced by the body.
    pub(super) arg_count: usize,
    /// Aggregate names with a standalone typedef alias in this translation unit.
    pub(super) source_type_aliases: &'a BTreeSet<String>,
    /// DWARF type environment used to test prototype renderability.
    pub(super) dwarf_type_env: &'a DwarfTypeEnv<'a>,
    /// Exact source aggregate pointer spellings for this render.
    pub(super) struct_pointer_types: &'a HashMap<String, String>,
    /// Names that carry an authoritative source spelling, which is what makes a
    /// renamed slot count as a promoted local.
    pub(super) source_locals: &'a HashSet<String>,
    /// Exact byte widths for complete by-value aggregate spellings referenced
    /// by this function or one of its direct callees.
    pub(super) aggregate_value_widths: &'a HashMap<String, u8>,
}

/// The declarations selected for one function render.
///
/// Constructed once by [`DeclarationPlan::compute`] and read-only thereafter.
/// Every accessor answers a question the printer asks about a name it is about
/// to spell; none of them can change what was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeclarationPlan {
    return_ctype: String,
    returns_void: bool,
    parameters: Vec<String>,
    parameter_names: Vec<String>,
    variadic: bool,
    pointer_parameters: HashMap<String, String>,
    locals: Vec<(String, LocalDeclaration)>,
    declared_ctypes: HashMap<String, String>,
    pointee_widths: HashMap<String, u8>,
    integer_widths: HashMap<String, u8>,
    integer_types: HashMap<String, (bool, u8)>,
    stack_objects: BTreeSet<String>,
    aggregate_value_widths: HashMap<String, u8>,
    aggregate_parameters: HashMap<String, (String, u8)>,
    source_locals: HashSet<String>,
}

impl Default for DeclarationPlan {
    /// The plan a renderer sees when no typed render has installed one.
    ///
    /// `long` is the untyped fallback return spelling; every table is empty, so
    /// each accessor reports "nothing was declared for this name" and the
    /// printer falls back to its untyped path.
    fn default() -> Self {
        Self {
            return_ctype: "long".to_string(),
            returns_void: false,
            parameters: Vec::new(),
            parameter_names: Vec::new(),
            variadic: false,
            pointer_parameters: HashMap::new(),
            locals: Vec::new(),
            declared_ctypes: HashMap::new(),
            pointee_widths: HashMap::new(),
            integer_widths: HashMap::new(),
            integer_types: HashMap::new(),
            stack_objects: BTreeSet::new(),
            aggregate_value_widths: HashMap::new(),
            aggregate_parameters: HashMap::new(),
            source_locals: HashSet::new(),
        }
    }
}

impl DeclarationPlan {
    /// Decide every declaration for one function render.
    ///
    /// Pure: the result depends only on `inputs`, and nothing outside the
    /// returned value is modified.
    pub(super) fn compute(inputs: DeclarationInputs<'_>) -> Self {
        let DeclarationInputs {
            ids,
            body,
            tm,
            width_tm,
            output_kind,
            declared_prototype,
            declared_parameter_names,
            arg_count,
            source_type_aliases,
            dwarf_type_env,
            struct_pointer_types,
            source_locals,
            aggregate_value_widths,
        } = inputs;

        // Names declared as pointers, with their pointee width, so the
        // array-index render can rewrite `*(T*)(base + i*sizeof(T))` as
        // `base[i]`. Only declared pointers appear, so `base[i]` is valid C.
        let mut pointee_widths = HashMap::new();
        // Exact signedness and width of integer declarations, so the printer
        // can rely on C's own integer promotion where that promotion is
        // precisely the cast already represented in IR.
        let mut integer_types = HashMap::new();
        if let Some(tm) = tm {
            for (v, hint) in tm.iter() {
                if let (VReg::Phys(n), TypeHint::Pointer { pointee_width }) = (v, hint) {
                    if parse_arg_index(n).is_some()
                        || is_promoted_local_in(n, source_locals)
                        || is_high_variable(n)
                    {
                        pointee_widths.insert(n.clone(), *pointee_width);
                    }
                }
                if let (VReg::Phys(n), TypeHint::Int { signed, width }) = (v, hint) {
                    if parse_arg_index(n).is_some() || is_promoted_local_in(n, source_locals) {
                        integer_types.insert(n.clone(), (*signed, *width));
                    }
                }
            }
        }

        // The logical-shift cast needs each operand's *machine* width (`edi`=4),
        // which the pre-canonicalisation `width_tm` carries; it is deliberately
        // decoupled from the recovered *declaration* type in `tm` (canonicalised
        // to 64-bit parents to keep def/use versions aligned). Narrowing only the
        // shift cast — not the declaration or the surrounding arithmetic — avoids
        // changing the width at which a widened value (`(uint64_t)a * b`)
        // computes.
        let mut integer_widths = HashMap::new();
        if let Some(wtm) = width_tm.or(tm) {
            for (v, hint) in wtm.iter() {
                if let (VReg::Phys(n), TypeHint::Int { width, .. }) = (v, hint) {
                    if *width > 0
                        && (parse_arg_index(n).is_some() || is_promoted_local_in(n, source_locals))
                    {
                        integer_widths.insert(n.clone(), *width);
                    }
                }
            }
        }

        let returns_void = output_kind == RecoveredOutputKind::Void;
        let variadic = declared_prototype.is_some_and(|prototype| prototype.variadic);
        let return_ctype = declared_prototype.map_or_else(
            || {
                if returns_void {
                    "void".to_string()
                } else {
                    infer_return_ctype(body, tm).to_string()
                }
            },
            |prototype| {
                source_type_with_complete_struct_alias(&prototype.return_type, source_type_aliases)
            },
        );

        // Signature: recovered return plus argument types. A pointer parameter
        // is genuinely a pointer in the signature, but our IR reuses the ABI
        // register as a scratch integer; recording which parameters are
        // pointers lets the body reconcile that int/pointer reuse with casts
        // rather than by weakening the recovered signature.
        let mut declared_ctypes = HashMap::new();
        let mut pointer_parameters = HashMap::new();
        let mut aggregate_parameters = HashMap::new();
        let mut parameters = Vec::with_capacity(arg_count);
        let mut parameter_names = Vec::with_capacity(arg_count);
        let mut used_parameter_names = HashSet::new();
        for index in 0..arg_count {
            let name = format!("arg{index}");
            let recovered_type = || ctype_for(&name, tm).to_string();
            let c_type = declared_prototype
                .and_then(|prototype| prototype.parameter_types.get(index))
                .filter(|c_type| dwarf_prototype_type_is_renderable(c_type, false, dwarf_type_env))
                .map_or_else(recovered_type, |c_type| {
                    source_type_with_complete_struct_alias(c_type, source_type_aliases)
                });
            if c_type.ends_with('*') {
                pointer_parameters.insert(name.clone(), c_type.clone());
            }
            if let Some(width) = aggregate_value_widths.get(&c_type).copied() {
                aggregate_parameters.insert(name.clone(), (c_type.clone(), width));
            }
            declared_ctypes.insert(name, c_type.clone());
            parameters.push(c_type);
            let source_name = declared_parameter_names
                .and_then(|names| names.get(index))
                .and_then(Option::as_deref)
                .filter(|candidate| crate::ir::naming::valid_authoritative_local_name(candidate))
                .filter(|candidate| !ids.locals.contains(*candidate))
                .filter(|candidate| used_parameter_names.insert((*candidate).to_string()))
                .map(str::to_string)
                .unwrap_or_else(|| format!("arg{index}"));
            parameter_names.push(source_name);
        }

        // Promoted stack slots and exact SSA-derived `varN` values may take a
        // recovered type. The high-variable pass admits `varN` only when every
        // definition agrees and no integer/address-arithmetic use exists.
        // Physical frame/ABI registers and unproven values stay `long` to
        // preserve C parseability (`rsp & -16`, `rbp + ret`, etc.).
        //
        // Declaration order is the source order where one is known: it affects
        // stack layout and therefore recompilation fidelity at O0, and sorting
        // after a DWARF rename would reverse the original storage order merely
        // because the new names compare differently.
        let mut locals = Vec::new();
        for local in ids.source_local_order.iter().chain(
            ids.locals
                .iter()
                .filter(|local| !ids.source_local_members.contains(*local)),
        ) {
            if let Some(bytes) = ids.stack_objects.get(local) {
                locals.push((
                    local.clone(),
                    LocalDeclaration::StackObject { bytes: *bytes },
                ));
                continue;
            }
            if ids.wide_locals.contains(local) {
                locals.push((local.clone(), LocalDeclaration::WideVector));
                continue;
            }
            // A call result is a stronger declaration fact than the
            // flow-insensitive TypeMap: call-result lifetime splitting normally
            // gives every call site a distinct value.
            let c_type = ids
                .call_result_types
                .get(local)
                .and_then(Option::as_ref)
                .cloned()
                .or_else(|| struct_pointer_types.get(local.as_str()).cloned())
                .unwrap_or_else(|| {
                    if is_promoted_local_in(local, source_locals) || is_high_variable(local) {
                        ctype_for(local, tm).to_string()
                    } else {
                        "long".to_string()
                    }
                });
            declared_ctypes.insert(local.clone(), c_type.clone());
            locals.push((local.clone(), LocalDeclaration::Scalar { c_type }));
        }

        Self {
            return_ctype,
            returns_void,
            parameters,
            parameter_names,
            variadic,
            pointer_parameters,
            locals,
            declared_ctypes,
            pointee_widths,
            integer_widths,
            integer_types,
            stack_objects: ids.stack_objects.keys().cloned().collect(),
            aggregate_value_widths: aggregate_value_widths.clone(),
            aggregate_parameters,
            source_locals: source_locals.clone(),
        }
    }

    /// The exact C return type this render declares.
    ///
    /// A `return` statement needs the same representation-boundary conversion
    /// as an assignment, so it consumes the declared spelling rather than
    /// independently guessing the signature.
    pub(super) fn return_ctype(&self) -> &str {
        &self.return_ctype
    }

    /// Whether the recovered source prototype is `void`.
    ///
    /// Unknown scalar output uses `return 0;` for a bare machine return; a
    /// proven void function must emit the distinct C statement `return;`.
    pub(super) fn returns_void(&self) -> bool {
        self.returns_void
    }

    /// Declared parameter types, in signature order.
    pub(super) fn parameters(&self) -> &[String] {
        &self.parameters
    }

    /// Source spelling selected for the parameter at `index`.
    pub(super) fn parameter_name(&self, index: usize) -> Option<&str> {
        self.parameter_names.get(index).map(String::as_str)
    }

    /// Source spelling for an internal `argN` role, when one was declared.
    pub(super) fn displayed_parameter(&self, role: &str) -> Option<&str> {
        parse_arg_index(role).and_then(|index| self.parameter_name(index))
    }

    /// Whether the authoritative declaration accepts an unnamed argument tail.
    pub(super) fn variadic(&self) -> bool {
        self.variadic
    }

    /// The declared type of `name` if it is a pointer-typed parameter.
    pub(super) fn pointer_parameter(&self, name: &str) -> Option<&str> {
        self.pointer_parameters.get(name).map(String::as_str)
    }

    /// Source aggregate and exact carrier width for an incoming ABI role.
    pub(super) fn aggregate_parameter(&self, name: &str) -> Option<(&str, u8)> {
        self.aggregate_parameters
            .get(name)
            .map(|(c_type, width)| (c_type.as_str(), *width))
    }

    /// Exact width of a complete by-value aggregate spelling.
    pub(super) fn aggregate_value_width(&self, c_type: &str) -> Option<u8> {
        self.aggregate_value_widths.get(c_type).copied()
    }

    /// The exact C type printed for a scalar local or argument.
    ///
    /// Type recovery can hold competing facts from different machine-value
    /// lifetimes that later share one rendered name; assignment conversion must
    /// consume the selected declaration rather than rescan those candidates.
    pub(super) fn declared_ctype(&self, displayed: &str) -> Option<&str> {
        self.declared_ctypes.get(displayed).map(String::as_str)
    }

    /// The pointee width of `name` if it is declared as a pointer.
    pub(super) fn pointee_width(&self, name: &str) -> Option<u8> {
        self.pointee_widths.get(name).copied()
    }

    /// The declared integer byte width of `name`.
    ///
    /// Consulted by the logical-shift render so `(unsigned)x >> k` on a 32-bit
    /// operand casts to `unsigned int` rather than a blanket `unsigned long`: a
    /// blanket 64-bit cast sign-extends a negative narrow value into the high
    /// half before the zero-filling shift, giving a different result than the
    /// original narrow shift.
    pub(super) fn integer_width(&self, name: &str) -> Option<u8> {
        self.integer_widths.get(name).copied()
    }

    /// The declared signedness and width of `name`.
    pub(super) fn integer_type(&self, name: &str) -> Option<(bool, u8)> {
        self.integer_types.get(name).copied()
    }

    /// Whether `displayed` was declared as a complete byte array because its
    /// address escapes.
    ///
    /// These are C lvalues but not assignable scalars: a machine store whose
    /// address is one of these names must remain a dereference rather than the
    /// promoted-local spelling `object = value`.
    pub(super) fn is_stack_object(&self, displayed: &str) -> bool {
        self.stack_objects.contains(displayed)
    }

    /// Whether `displayed` is an authoritative source-local spelling.
    ///
    /// These names have already passed the same type/renderability checks as
    /// synthetic promoted locals. Presentation decisions such as placing a
    /// proven first definition may therefore treat both namespaces alike.
    pub(super) fn is_source_local(&self, displayed: &str) -> bool {
        self.source_locals.contains(displayed)
    }

    /// Body-local declarations, in the order they must be emitted.
    pub(super) fn locals(&self) -> &[(String, LocalDeclaration)] {
        &self.locals
    }
}
