//! Python bindings for the LLIR (low-level IR) lifting pipeline.
//!
//! The IR is still young and likely to evolve, so rather than freeze a
//! PyO3 class per variant we expose a *dict-based* representation. Every
//! LLIR op becomes a small `dict` with a stable `kind` field plus kind-specific
//! payload fields. Python callers can pattern-match on `op["kind"]`.
//!
//! Stable shape (subject to additive changes):
//!
//! ```text
//! {
//!     "va": int,
//!     "kind": "assign" | "ite" | "bin" | "un" | "cmp"
//!           | "load" | "store" | "jump" | "cond_jump" | "call"
//!           | "return" | "nop" | "unknown",
//!     # additional kind-specific fields — see encode_op below.
//! }
//! ```
//!
//! `VReg`s are encoded as strings: physical registers as their raw name
//! (`"rax"`, `"x0"`), temporaries as `"%tN"`, and flags as `"%zf"`, `"%cf"`, …
//! This matches the Rust `Display` impl so the Python output round-trips
//! through tests.

mod callee_contracts;
mod dwarf_contracts;
mod session;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use callee_contracts::{
    apply_recovered_direct_callee_effects, recover_direct_callee_layouts, recovered_call_prototype,
    refine_passthrough_parameter_hints, DirectCalleeFacts,
};

#[cfg(test)]
use dwarf_contracts::dwarf_return_hint;
use dwarf_contracts::{
    calling_convention_pointer_width, dwarf_output_contracts, dwarf_render_prototype,
    dwarf_return_hint_with_env, dwarf_source_register_lifetimes, dwarf_stack_object_hints,
    merge_dwarf_register_local_facts, DwarfPrototypeContract,
};

use crate::ir::abi::machine_word_bytes;
use crate::ir::types::{BinOp, CallTarget, CmpOp, Flag, LlirInstr, MemOp, Op, UnOp, VReg, Value};
use crate::ir::{lift_arm64, lift_x86};

fn load_program_image(path: &str) -> PyResult<crate::program::image::ProgramImage> {
    use crate::program::image::{ProgramImage, ProgramImageError};

    ProgramImage::from_path(std::path::Path::new(path)).map_err(|error| match error {
        ProgramImageError::Io(error) => {
            pyo3::exceptions::PyIOError::new_err(format!("read error: {error}"))
        }
        ProgramImageError::Parse(error) => {
            pyo3::exceptions::PyValueError::new_err(format!("image parse failed: {error}"))
        }
    })
}

pub(super) fn load_program_session(
    path: &str,
) -> PyResult<crate::program::session::ProgramSession> {
    use crate::program::image::ProgramImageError;
    use crate::program::session::ProgramSession;

    ProgramSession::from_path(std::path::Path::new(path)).map_err(|error| match error {
        ProgramImageError::Io(error) => {
            pyo3::exceptions::PyIOError::new_err(format!("read error: {error}"))
        }
        ProgramImageError::Parse(error) => {
            pyo3::exceptions::PyValueError::new_err(format!("image parse failed: {error}"))
        }
    })
}

fn flag_repr(f: Flag) -> &'static str {
    match f {
        Flag::Z => "%zf",
        Flag::C => "%cf",
        Flag::Ule => "%ule",
        Flag::S => "%sf",
        Flag::Slt => "%slt",
        Flag::Sle => "%sle",
        Flag::O => "%of",
        Flag::P => "%pf",
        Flag::A => "%af",
        Flag::D => "%df",
        Flag::Bit => "%bitpred",
    }
}

fn vreg_to_str(v: &VReg) -> String {
    match v {
        VReg::Phys(n) => n.clone(),
        VReg::Temp(i) => format!("%t{}", i),
        VReg::Flag(f) => flag_repr(*f).to_string(),
        VReg::FlagValue { flag, version } => format!("{}#{}", flag_repr(*flag), version),
    }
}

fn value_to_pyobj(py: Python<'_>, v: &Value) -> PyResult<PyObject> {
    let d = PyDict::new(py);
    match v {
        Value::Reg(r) => {
            d.set_item("kind", "reg")?;
            d.set_item("name", vreg_to_str(r))?;
        }
        Value::Const(c) => {
            d.set_item("kind", "const")?;
            d.set_item("value", *c)?;
        }
        Value::Addr(a) => {
            d.set_item("kind", "addr")?;
            d.set_item("value", *a)?;
        }
    }
    Ok(d.into())
}

fn memop_to_pyobj(py: Python<'_>, m: &MemOp) -> PyResult<PyObject> {
    let d = PyDict::new(py);
    d.set_item("base", m.base.as_ref().map(vreg_to_str).unwrap_or_default())?;
    d.set_item(
        "index",
        m.index.as_ref().map(vreg_to_str).unwrap_or_default(),
    )?;
    d.set_item("scale", m.scale)?;
    d.set_item("disp", m.disp)?;
    d.set_item("size", m.size)?;
    Ok(d.into())
}

fn binop_str(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::Div => "div",
        BinOp::LogicalAnd => "logical_and",
        BinOp::LogicalOr => "logical_or",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Shl => "shl",
        BinOp::Shr => "shr",
        BinOp::Sar => "sar",
    }
}

fn unop_str(op: UnOp) -> &'static str {
    match op {
        UnOp::Not => "not",
        UnOp::Neg => "neg",
    }
}

fn cmpop_str(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "eq",
        CmpOp::Ne => "ne",
        CmpOp::Ult => "ult",
        CmpOp::Ule => "ule",
        CmpOp::Slt => "slt",
        CmpOp::Sle => "sle",
    }
}

fn encode_op(py: Python<'_>, va: u64, op: &Op) -> PyResult<PyObject> {
    let d = PyDict::new(py);
    d.set_item("va", va)?;
    match op {
        Op::Assign { dst, src } => {
            d.set_item("kind", "assign")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
        }
        Op::Undef { dst, reason } => {
            d.set_item("kind", "undef")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("reason", reason)?;
        }
        Op::Bin { dst, op, lhs, rhs } => {
            d.set_item("kind", "bin")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("op", binop_str(*op))?;
            d.set_item("lhs", value_to_pyobj(py, lhs)?)?;
            d.set_item("rhs", value_to_pyobj(py, rhs)?)?;
        }
        Op::Un { dst, op, src } => {
            d.set_item("kind", "un")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("op", unop_str(*op))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
        }
        Op::Cmp { dst, op, lhs, rhs } => {
            d.set_item("kind", "cmp")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("op", cmpop_str(*op))?;
            d.set_item("lhs", value_to_pyobj(py, lhs)?)?;
            d.set_item("rhs", value_to_pyobj(py, rhs)?)?;
        }
        Op::Load { dst, addr } => {
            d.set_item("kind", "load")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("addr", memop_to_pyobj(py, addr)?)?;
        }
        Op::CondLoad {
            dst,
            cond,
            inverted,
            addr,
            fallback,
        } => {
            d.set_item("kind", "cond_load")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("inverted", *inverted)?;
            d.set_item("addr", memop_to_pyobj(py, addr)?)?;
            d.set_item("fallback", value_to_pyobj(py, fallback)?)?;
        }
        Op::Store { addr, src } => {
            d.set_item("kind", "store")?;
            d.set_item("addr", memop_to_pyobj(py, addr)?)?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
        }
        Op::CondStore {
            cond,
            inverted,
            addr,
            src,
        } => {
            d.set_item("kind", "cond_store")?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("inverted", *inverted)?;
            d.set_item("addr", memop_to_pyobj(py, addr)?)?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
        }
        Op::Jump { target } => {
            d.set_item("kind", "jump")?;
            d.set_item("target", *target)?;
        }
        Op::IndirectJump { target, index } => {
            d.set_item("kind", "indirect_jump")?;
            d.set_item("target", value_to_pyobj(py, target)?)?;
            if let Some(index) = index {
                d.set_item("index", value_to_pyobj(py, index)?)?;
            }
        }
        Op::CondJump {
            cond,
            target,
            inverted,
        } => {
            d.set_item("kind", "cond_jump")?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("inverted", *inverted)?;
            d.set_item("target", *target)?;
        }
        Op::CondReturn { cond, inverted } => {
            d.set_item("kind", "cond_return")?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("inverted", *inverted)?;
        }
        Op::CondReturnValue {
            cond,
            inverted,
            value,
        } => {
            d.set_item("kind", "cond_return")?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("inverted", *inverted)?;
            d.set_item("value", value_to_pyobj(py, value)?)?;
        }
        Op::Call { target, .. } => {
            d.set_item("kind", "call")?;
            let tgt = PyDict::new(py);
            match target {
                CallTarget::Direct(a) => {
                    tgt.set_item("kind", "direct")?;
                    tgt.set_item("addr", *a)?;
                }
                CallTarget::Indirect(v) => {
                    tgt.set_item("kind", "indirect")?;
                    tgt.set_item("value", value_to_pyobj(py, v)?)?;
                }
            }
            d.set_item("target", tgt)?;
        }
        Op::Return => {
            d.set_item("kind", "return")?;
        }
        Op::ReturnValue { value } => {
            d.set_item("kind", "return")?;
            d.set_item("value", value_to_pyobj(py, value)?)?;
        }
        Op::Nop => {
            d.set_item("kind", "nop")?;
        }
        Op::ZExt {
            dst, src, from, to, ..
        } => {
            d.set_item("kind", "zext")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
            d.set_item("from", from.bits())?;
            d.set_item("to", to.bits())?;
        }
        Op::SExt {
            dst, src, from, to, ..
        } => {
            d.set_item("kind", "sext")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
            d.set_item("from", from.bits())?;
            d.set_item("to", to.bits())?;
        }
        Op::Trunc {
            dst, src, from, to, ..
        } => {
            d.set_item("kind", "trunc")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
            d.set_item("from", from.bits())?;
            d.set_item("to", to.bits())?;
        }
        Op::Extract { dst, src, hi, lo } => {
            d.set_item("kind", "extract")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
            d.set_item("hi", *hi)?;
            d.set_item("lo", *lo)?;
        }
        Op::Concat { dst, hi, lo } => {
            d.set_item("kind", "concat")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("hi", value_to_pyobj(py, hi)?)?;
            d.set_item("lo", value_to_pyobj(py, lo)?)?;
        }
        Op::Ite {
            dst, cond, t, e, ..
        } => {
            d.set_item("kind", "ite")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("t", value_to_pyobj(py, t)?)?;
            d.set_item("e", value_to_pyobj(py, e)?)?;
        }
        Op::Intrinsic {
            name,
            ins,
            outs,
            reads_mem,
            writes_mem,
        } => {
            d.set_item("kind", "intrinsic")?;
            d.set_item("name", name)?;
            let ins_list = pyo3::types::PyList::empty(py);
            for v in ins {
                ins_list.append(value_to_pyobj(py, v)?)?;
            }
            d.set_item("ins", ins_list)?;
            let outs_list = pyo3::types::PyList::empty(py);
            for (r, w) in outs {
                let o = PyDict::new(py);
                o.set_item("reg", vreg_to_str(r))?;
                o.set_item("width", w.bits())?;
                outs_list.append(o)?;
            }
            d.set_item("outs", outs_list)?;
            d.set_item("reads_mem", *reads_mem)?;
            d.set_item("writes_mem", *writes_mem)?;
        }
        Op::Unknown { mnemonic } => {
            d.set_item("kind", "unknown")?;
            d.set_item("mnemonic", mnemonic)?;
        }
    }
    Ok(d.into())
}

/// Dispatch lifting to the appropriate per-arch backend.
/// Replace calls to the compiler's division runtime helpers with the arithmetic
/// they perform (see [`crate::ir::soft_helpers`]).
///
/// Must run on the raw LLIR — before `abi::annotate_calls` and before SSA —
/// because the expansion is written in terms of the architectural argument
/// registers. Shared by every decompile entry point for the same reason
/// `run_ast_passes` is: a pass wired into one of the four and not the others is
/// a pass that silently does nothing in three of them.
fn inline_soft_helper_calls_in(
    lf: &mut crate::ir::types::LlirFunction,
    addr_map: &std::collections::HashMap<u64, String>,
) {
    crate::ir::soft_helpers::inline_soft_helper_calls(&mut lf.blocks, |va| {
        addr_map.get(&va).cloned()
    });
}

/// Attach convention-wide call effects, then narrow resolved library calls.
///
/// This must precede SSA and prototype recovery. Keeping the two layers in one
/// helper prevents an entry point from observing the ABI's conservative
/// six/eight-register approximation after another already applied the exact
/// program-level symbol contract.
fn annotate_calls_in(
    function: &mut crate::ir::types::LlirFunction,
    cc: crate::ir::call_args::CallConv,
    address_names: &std::collections::HashMap<u64, String>,
) {
    crate::ir::abi::annotate_calls(function, cc);
    crate::ir::call_contracts::apply_known_llir_call_contracts(function, cc, address_names);
}

/// THE AST pass pipeline. Every public decompile entry point runs exactly this.
///
/// It used to be copy-pasted into four functions — `decompile_at`, `decompile_range_at`,
/// `decompile_all`, `decompile_many` — with tests keeping the copies aligned by
/// convention and nothing enforcing it. That is not hypothetical drift: a loop-hoist
/// retry added during this work landed in one copy and silently did nothing in the other
/// three, which is exactly how a "fix" gets measured as ineffective.
///
/// Returns the recovered stack-slot sizes, which callers thread into type recovery.
///
/// (The sibling of this rule for the LLIR stage is `inline_soft_helper_calls_in`,
/// just above.)
///
/// The pass-by-pass AST dump (`GLAURUNG_DUMP_PASSES=1`) is read here, so EVERY entry
/// point gets identical diagnostics rather than only the one that happened to carry the
/// macro. Debugging `--all` used to produce no dump at all.
/// Constant-data facts for one image, with relocation-fixed storage interpreted
/// rather than read.
///
/// Read-only storage the loader fixes up holds references, not data: a
/// `static const char *const` table lands in `.data.rel.ro`, and reading its
/// bytes as integers yields an image address that the rebuilt unit does not
/// map. The canonical reference resolver is asked what each pointer-width slot
/// means before any pass can see those bytes at all. See
/// [`crate::program::references`].
fn readonly_data_for(
    session: &crate::program::session::ProgramSession,
    image: &crate::program::image::ProgramImage,
    str_pool: &std::collections::HashMap<u64, String>,
) -> crate::ir::readonly_fold::ReadonlyData {
    let mut readonly_data = crate::ir::readonly_fold::collect_readonly_data_from_image(image);
    let symbols = session.symbol_store();
    readonly_data.resolve_relocated_slots(
        image,
        &crate::program::references::ReferenceResolver::new(image, &symbols, str_pool),
    );
    readonly_data
}

fn run_ast_passes(
    f: &mut crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    cc: crate::ir::call_args::CallConv,
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    param_slots: &mut std::collections::HashSet<usize>,
    locked_parameter_count: Option<usize>,
    callee_facts: &DirectCalleeFacts,
    addr_map: &std::collections::HashMap<u64, String>,
    str_pool: &std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    stack_object_hints: &[crate::ir::stack_locals::StackObjectHint],
    got_targets: &std::collections::HashMap<u64, u64>,
) -> (
    crate::ir::stack_locals::StackLocalFacts,
    std::collections::HashMap<String, String>,
) {
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    let output_kind = prototype.map_or(
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
        crate::ir::types_recover::RecoveredPrototype::output_kind,
    );
    // A recovered variadic callee layout names only its fixed prefix. Passing
    // that prefix to the fixed-layout folder would truncate genuine optional
    // arguments already set up at this call site. Let the ordinary backward
    // call scan recover the actual argument count; the prototype applied in
    // the next pass preserves the fixed types and variadic tail.
    let reconstruction_layouts = callee_facts
        .layouts
        .iter()
        .filter(|(target, _)| {
            !callee_facts
                .prototypes
                .get(target)
                .is_some_and(|prototype| prototype.variadic)
        })
        .map(|(target, layout)| (*target, layout.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let parameter_roles = prototype
        .map(crate::ir::types_recover::RecoveredPrototype::parameter_role_map)
        .unwrap_or_default();
    if dump {
        eprintln!(
            "\n===== parameter evidence =====\nslots={param_slots:?}\nroles={parameter_roles:?}"
        );
        eprintln!("\n===== stack object hints =====\n{stack_object_hints:#?}");
    }
    macro_rules! pass {
        ($n:expr, $operation:expr) => {{
            let result = profiler.measure($n, || $operation);
            crate::ir::health::trace_pass($n, f, cfg_health);
            if dump {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(f));
            }
            result
        }};
    }
    crate::ir::health::trace_pass("ast_pipeline_entry", f, cfg_health);
    // Packed XMM moves use four scalar lane operations so arithmetic remains
    // analyzable.  Rejoin an untouched four-lane load/store pair before copy
    // propagation erases the common 16-byte transport identity.
    pass!(
        "recover_wide_copies",
        crate::ir::vector_copy::recover_wide_copies(f)
    );
    pass!("reconstruct", crate::ir::expr_reconstruct::reconstruct(f));
    pass!("fold_constants", crate::ir::const_fold::fold_constants(f));
    pass!(
        "fold_boolean_masks",
        crate::ir::select_fold::fold_boolean_masks(f)
    );
    // Per-definition first: it removes writes an unread overwrite supersedes, which the
    // per-name pass below cannot see (flags are un-versioned, so one read keeps every
    // write of that name alive).
    pass!("prune_dead_flags", {
        crate::ir::dce::prune_overwritten_flags(f);
        crate::ir::dce::prune_dead_flags(f);
    });
    // A direct jump into a PLT stub lowers to that stub's terminal GOT
    // dereference. Resolve the slot before argument reconstruction, then recover
    // only symbol-backed terminal jumps as tail calls so the ordinary call pass
    // can see their argument-register setup and returned value.
    // Before names are resolved, so a slot that `elf_got_map` also names is
    // replaced by the address it holds rather than by a symbol standing on a
    // linkage word. See `ir::got_fold`.
    pass!("fold_got_pointer_loads", {
        crate::ir::got_fold::fold_got_pointer_loads(f, got_targets);
    });
    pass!("recover_resolved_tail_calls", {
        crate::ir::name_resolve::resolve_names(f, addr_map);
        crate::ir::function_tables::resolve_function_table_entries(f, function_tables);
        crate::ir::call_args::recover_resolved_direct_tail_calls(f, cc, addr_map);
        crate::ir::call_args::recover_resolved_tail_calls(f, cc);
    });
    pass!("reconstruct_args", {
        crate::ir::call_args::reconstruct_args_with_layouts(
            f,
            cc,
            param_slots,
            &reconstruction_layouts,
            &callee_facts.table_entry_layouts,
        );
    });
    // ABI liveness supplies candidate call inputs/outputs; an authoritative
    // library prototype wins when one is known. This mirrors Ghidra's locked
    // FuncProto and angr's callee-prototype priority rather than asking the C
    // renderer to paper over a semantically impossible AST result.
    pass!("apply_known_call_contracts", {
        crate::ir::call_contracts::apply_recovered_callee_prototypes(f, &callee_facts.prototypes);
        crate::ir::call_contracts::apply_known_call_contracts(f);
    });
    pass!(
        "split_call_result_lifetimes",
        crate::ir::call_result_split::split_call_result_lifetimes(f, cc)
    );
    pass!("canary+strings", {
        crate::ir::strings_fold::fold_string_literals(f, str_pool);
        crate::ir::canary::recognise_canary(f);
    });
    // Stack-slot promotion runs before register renaming so the aliases (`stack_0`,
    // `local_0`, ...) it allocates cannot collide with the role names (`arg0`, `ret`,
    // `varN`) the naming pass introduces.
    let stack_facts = pass!(
        "promote_stack_locals",
        crate::ir::stack_locals::promote_stack_locals_with_facts(
            f,
            Some(cc),
            locked_parameter_count,
            stack_object_hints,
        )
    );
    // Frame-relative storage is source-level state; the push/mov/sub sequence
    // that establishes its machine frame is not.  Recognise the machine prologue
    // here, while stack promotion has made the storage identities explicit but
    // before dead-store elimination removes the now-unused `rbp = rsp` witness.
    // A second call after the remaining passes still handles epilogues exposed
    // by stack-op rematerialisation.
    pass!("recognise_machine_frame", recognise_machine_frame(f, cc));
    // Project a prototype-proven result while the raw ABI output register is
    // still present. ARM32/AArch64 reuse arg0's register for the result; the
    // following spill-role split must rename both its final definition and the
    // return use together, rather than orphaning the result as scratch.
    pass!("materialize_direct_output", {
        if output_kind == crate::ir::types_recover::RecoveredOutputKind::Direct {
            crate::ir::direct_output::materialize_prototype_output(f, cc, prototype);
        }
    });
    // Reconstructed expressions now carry their explicit machine width. Make
    // the dual-role decision here rather than at pipeline entry, where a wide
    // result may still be hidden behind widthless temporaries.
    let split_unspilled_dual_role =
        crate::ir::value_split::should_split_unspilled_dual_role(f, cc, prototype);
    if dump {
        eprintln!(
            "\n===== value-role evidence =====\n\
             split_unspilled_dual_role={split_unspilled_dual_role}"
        );
    }
    pass!(
        "split_argument_storage_reuse",
        crate::ir::value_split::split_argument_storage_reuse(f, cc, split_unspilled_dual_role)
    );
    let role_names = pass!(
        "apply_role_names",
        crate::ir::naming::apply_role_names_with_parameter_roles(
            f,
            cc,
            param_slots,
            &parameter_roles,
        )
    );
    // Dead-store elimination runs *after* naming so it sees the aliased return register
    // (`ret` / `arg0`) rather than the raw physical one; that removes the common pre-call
    // `%ret = 0` idiom entirely.
    pass!("eliminate_dead_stores", {
        crate::ir::canary::collapse_canary_save(f);
        if matches!(cc, crate::ir::call_args::CallConv::Aarch64) {
            crate::ir::arm64_prologue::recognise_arm64_prologue(f);
        }
        crate::ir::dead_stores::eliminate_dead_stores(f, cc);
    });
    pass!("stack_idiom+label_prune", {
        crate::ir::stack_idiom::rematerialise_stack_ops(f);
        crate::ir::label_prune::prune_unreferenced_labels(f);
    });
    (stack_facts, role_names)
}

/// Collapse architecture-specific machine frames after stack-slot promotion.
///
/// The pass is repeated after the common AST pipeline because stack-idiom
/// rematerialisation may expose a second canonical spelling. Each recogniser
/// is idempotent and fail-closed when the frame is not exactly balanced.
fn recognise_machine_frame(f: &mut crate::ir::ast::Function, cc: crate::ir::call_args::CallConv) {
    match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
            crate::ir::x86_prologue::recognise_x86_prologue(f);
        }
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            crate::ir::arm32_prologue::recognise_arm32_frame(f);
        }
        _ => {}
    }
    // Whatever the per-architecture recogniser could not attribute to a frame
    // pattern, the callee-saved spills themselves are still machine bookkeeping.
    // This runs for every convention, including AArch64, which has no dedicated
    // recogniser in this match.
    crate::ir::dead_stores::prune_callee_saved_spills(f, cc);
}

fn lift_for_arch(data: &[u8], start_va: u64, bits: u32, arch: &str) -> PyResult<Vec<LlirInstr>> {
    let a = arch.to_ascii_lowercase();
    let mut instructions = match a.as_str() {
        "x86" => lift_x86::lift_bytes(data, start_va, 32),
        "x86_64" | "x64" | "amd64" => lift_x86::lift_bytes(data, start_va, 64),
        "arm64" | "aarch64" => lift_arm64::lift_bytes(data, start_va),
        // If arch was omitted, fall back to bits= for x86 back-compat.
        "" => {
            if bits != 32 && bits != 64 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "bits must be 32 or 64 when arch is omitted",
                ));
            }
            lift_x86::lift_bytes(data, start_va, bits)
        }
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unsupported arch: {arch}"
            )))
        }
    };
    // This was the last path on which a footprint-declaring-nothing `Op::Unknown`
    // reached a consumer. `lift_function` lowers every residual `Unknown` to a
    // conservative `Op::Intrinsic` at the function boundary, but this entry point
    // calls the per-arch lifters directly and so skipped that migration — while
    // being a *public* API whose output a caller may build dataflow on. The
    // per-arch lifters keep emitting `Unknown` internally; their unit tests assert
    // on it. Nothing crossing into Python does.
    for instruction in &mut instructions {
        if let Op::Unknown { mnemonic } = &instruction.op {
            instruction.op = Op::opaque(mnemonic.clone());
        }
    }
    Ok(instructions)
}

/// Lift raw bytes into a list of LLIR op dicts.
///
/// `arch` selects the per-arch lifter (`"x86"`, `"x86_64"`, `"arm64"`).
/// For backwards compatibility, passing `arch=""` (the default) keeps the
/// original x86 lifter and uses `bits` to choose 32- vs 64-bit.
#[pyfunction]
#[pyo3(name = "lift_bytes")]
#[pyo3(signature = (data, start_va, bits=64u32, arch=""))]
fn lift_bytes_py(
    py: Python<'_>,
    data: &[u8],
    start_va: u64,
    bits: u32,
    arch: &str,
) -> PyResult<PyObject> {
    let ops = lift_for_arch(data, start_va, bits, arch)?;
    let list = PyList::empty(py);
    for i in &ops {
        list.append(encode_op(py, i.va, &i.op)?)?;
    }
    Ok(list.into())
}

/// Read a window at the given VA from `path` and lift it.
#[pyfunction]
#[pyo3(name = "lift_window_at")]
#[pyo3(signature = (path, start_va, window_bytes=512usize, bits=64u32, arch=""))]
fn lift_window_at_py(
    py: Python<'_>,
    path: String,
    start_va: u64,
    window_bytes: usize,
    bits: u32,
    arch: &str,
) -> PyResult<PyObject> {
    let image = load_program_image(&path)?;
    let data = image.bytes();
    let foff = image.va_to_code_file_offset(start_va).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("no mapping for VA 0x{:x}", start_va))
    })?;
    let end = foff.saturating_add(window_bytes).min(data.len());
    lift_bytes_py(py, &data[foff..end], start_va, bits, arch)
}

fn target_calling_convention(
    image: &crate::program::image::ProgramImage,
) -> PyResult<crate::ir::call_args::CallConv> {
    let target = image.target();
    let arch = target.architecture();
    if !crate::ir::lift_function::supports_arch(arch) {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "LLIR decompiler does not support target {arch:?}"
        )));
    }
    let cc = target.calling_convention().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "target {arch:?} has no supported calling convention"
        ))
    })?;
    Ok(cc)
}

/// Normalize proof-dead partial-register lanes before any consumer leaves SSA.
///
/// Exception edges participate in both SSA computations: the first supplies
/// reaching values to the bit-demand oracle and the second describes the
/// normalized LLIR consumed by region recovery and value numbering.  Keeping
/// this sequence in one helper prevents the four Python decompilation entry
/// points from drifting into different value models.
fn normalize_definedness_and_compute_ssa(
    function: &mut crate::ir::types::LlirFunction,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
) -> crate::ir::ssa::SsaInfo {
    let graph = crate::analysis::exception::with_exceptional_successors(function, exception_sites);
    let initial_ssa = crate::ir::ssa::compute_ssa(&graph);
    let oracle = crate::ir::definedness::BitDemandOracle::analyze(&graph, &initial_ssa, cc);
    if crate::ir::definedness::erase_unobserved_masked_inputs(function, &initial_ssa, &oracle) == 0
    {
        return initial_ssa;
    }
    let normalized_graph =
        crate::analysis::exception::with_exceptional_successors(function, exception_sites);
    crate::ir::ssa::compute_ssa(&normalized_graph)
}

/// One shared LLIR preparation pipeline for every decompilation entry point.
///
/// Prototype recovery needs initial SSA and parameter evidence. A proven direct
/// output then upgrades operand-free machine returns to explicit LLIR uses, so
/// SSA and the definedness oracle must run once more before value numbering and
/// structuring. Keeping that feedback edge here prevents `--all`, `--vas`, and
/// address/range decompilation from observing different return identities.
struct PreparedLlir {
    region: crate::ir::structure::Region,
    cfg_health: crate::ir::health::CfgHealth,
    numbered: crate::ir::types::LlirFunction,
    definition_widths: std::collections::HashMap<crate::ir::types::VReg, u8>,
    parameter_slots: std::collections::HashSet<usize>,
    prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
}

impl PreparedLlir {
    /// Verified typed MIR for this function, built on demand.
    ///
    /// Available for EVERY decompilation rather than only when
    /// `GLAURUNG_DUMP_PASSES` is set. It used to be computed inside the debug
    /// dump, printed and dropped, so the roadmap's "migrate a production
    /// consumer to verified MIR evidence" had nothing to migrate onto, and the
    /// analysis a consumer would trust existed only in debug runs — correctness
    /// must not depend on an environment variable.
    ///
    /// Computed here rather than stored on the struct because nothing consumes
    /// it yet: building it eagerly measured +13% on a whole-binary decompile
    /// (0.53 s -> 0.60 s on 09_memory_effects-clang-O2) for an artifact no
    /// caller reads. A consumer calls this when it needs the evidence.
    ///
    /// The `Err` is returned verbatim: an unavailable analysis must present as
    /// a typed reason, never as "no objects found".
    #[allow(dead_code)]
    fn mir(
        &self,
        image: &crate::program::image::ProgramImage,
    ) -> Result<crate::ir::mir::MirFunction, Vec<String>> {
        crate::ir::mir::lower_verified_with_image(&self.numbered, image)
    }
}

fn prepare_llir_for_lowering(
    function: &mut crate::ir::types::LlirFunction,
    image: &crate::program::image::ProgramImage,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
    recover_semantic_prototype: bool,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
    program_fact: Option<&crate::program::environment::FunctionPrototypeFact>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> PreparedLlir {
    let mut ssa = normalize_definedness_and_compute_ssa(function, exception_sites, cc);
    let provisional_slots = if recover_semantic_prototype {
        crate::ir::value_number::value_number_with_parameter_slots(function, &ssa, cc).2
    } else {
        crate::ir::value_number::live_in_arg_slots_llir(function, cc)
    };
    let prototype = recover_semantic_prototype.then(|| {
        let mut prototype = recover_decbench_prototype(
            function,
            &ssa,
            cc,
            &provisional_slots,
            arm_vfp_args,
            declared,
            type_env,
        );
        // Debug declarations remain the strongest source.  A registration API
        // supplies the missing contract only when local/debug recovery did not
        // already lock one, which keeps conflicting evidence fail-closed.
        if let Some(fact) = program_fact {
            if !prototype.parameter_arity_is_locked() {
                if fact.parameter_arity_is_exact {
                    prototype.apply_locked_parameters(cc, &fact.parameter_hints);
                } else {
                    prototype.apply_parameter_hints(&fact.parameter_hints);
                }
            }
            if !prototype.output_is_locked() {
                if let Some(output_kind) = fact.output_kind {
                    prototype.apply_locked_output(output_kind, None);
                }
            }
        }
        prototype
    });
    if prototype.as_ref().is_some_and(|prototype| {
        crate::ir::types_recover::materialize_return_values(function, cc, prototype) != 0
    }) {
        ssa = normalize_definedness_and_compute_ssa(function, exception_sites, cc);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== prototype-resolved LLIR =====");
        for block in &function.blocks {
            eprintln!("block 0x{:x} -> {:?}", block.start_va, block.succs);
            for instruction in &block.instrs {
                eprintln!("  0x{:x}: {}", instruction.va, instruction.op);
            }
        }
    }
    // What a relocation proves about each computed transfer. The image's slot
    // index is recovered once and shared, so this costs a def-use walk per
    // function and no extra object parse. It reaches only the terminal census;
    // no region decision depends on it.
    let indirect_destinations = crate::ir::indirect_targets::resolve_indirect_jumps(
        function,
        &ssa,
        &image.relocated_symbol_slots(),
    );
    let (region, cfg_health) = crate::ir::structure::recover_verified_with_health_and_destinations(
        function,
        &ssa,
        &indirect_destinations,
    );
    let (numbered, definition_widths, mut parameter_slots) = if recover_semantic_prototype {
        let source_lifetimes = dwarf_source_register_lifetimes(declared, cc);
        crate::ir::value_number::value_number_with_parameter_slots_and_lifetimes(
            function,
            &ssa,
            cc,
            &source_lifetimes,
        )
    } else {
        (
            function.clone(),
            std::collections::HashMap::new(),
            crate::ir::value_number::live_in_arg_slots_llir(function, cc),
        )
    };
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== prepared numbered LLIR =====");
        for block in &numbered.blocks {
            eprintln!("block 0x{:x} -> {:?}", block.start_va, block.succs);
            for instruction in &block.instrs {
                eprintln!("  0x{:x}: {}", instruction.va, instruction.op);
            }
        }
        match &crate::ir::mir::lower_verified_with_image(&numbered, image) {
            Ok(mir) => {
                eprintln!(
                    "\n===== verified typed MIR memory values =====\n{:#?}",
                    mir.memory_values()
                );
                eprintln!(
                    "\n===== typed MIR memory objects =====\n{:#?}",
                    mir.objects()
                );
            }
            Err(error) => {
                eprintln!("\n===== invalid typed MIR memory analysis =====\n{error:#?}");
            }
        }
    }
    lock_parameter_slots_from_prototype(prototype.as_ref(), &mut parameter_slots);
    PreparedLlir {
        region,
        cfg_health,
        numbered,
        definition_widths,
        parameter_slots,
        prototype,
    }
}

/// Run the full decompiler pipeline on the function whose entry is `func_va`
/// in `path`, returning the rendered pseudocode.
///
/// Pipeline: cfg discovery → per-function LLIR lift → SSA → structural
/// analysis → AST lowering → expression reconstruction. When `types=True`
/// (the default), the first-cut type-recovery pass runs and the output
/// carries `(u64*)`, `(bool)`, etc. annotations on classified registers.
/// When `style="c"`, the C-like renderer is used instead (strips `%`
/// prefixes and type annotations).
#[pyfunction]
#[pyo3(name = "decompile_at")]
#[pyo3(signature = (path, func_va, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", pdb_cache="", max_functions=1usize))]
fn decompile_at_py(
    py: Python<'_>,
    path: String,
    func_va: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
    max_functions: usize,
) -> PyResult<String> {
    let session = load_program_session(&path)?;
    decompile_at_session(
        py,
        &session,
        &path,
        func_va,
        max_blocks,
        max_instructions,
        timeout_ms,
        types,
        style,
        pdb_cache,
        max_functions,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decompile_at_session(
    py: Python<'_>,
    session: &crate::program::session::ProgramSession,
    path: &str,
    func_va: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
    max_functions: usize,
) -> PyResult<String> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_at");
    use crate::analysis::cfg::Budgets;
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::types_recover::recover_types_for;

    let image = session.image().clone();
    let data = image.bytes();
    // An ARM32 Thumb symbol's value carries the Thumb bit; the entry it denotes
    // is one lower. Anything resolving a callee through `.symtab` hands us that
    // value verbatim, and decoding one byte in recovers a body with no
    // parameters at all. See `arm32_mode::normalise_entry`.
    let func_va = image.normalize_function_entry(func_va);
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench" && types).then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let budgets = Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    // Whole-binary function discovery: seconds to minutes on a large image, and
    // the reason `Ctrl-C` used to do nothing until it finished. `data` is an
    // owned `Vec<u8>` and `Budgets` is `Copy`; no `Bound`/`Py` reference crosses
    // the closure boundary. See `python_bindings::analysis`.
    let funcs = py.detach(|| session.discover_functions(&budgets, &[func_va]));
    let func = funcs
        .iter()
        .find(|f| f.entry_point.value == func_va)
        .cloned()
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "no function at entry VA 0x{:x}",
                func_va
            ))
        })?;
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    // Build the address map first so we can apply a PDB public-symbol name
    // to the *outer* function header before lowering. The map already
    // includes PDB symbols when a cache is configured, plus exports / IAT
    // names that beat the CFG-pass heuristic on stripped Windows binaries.
    // It is also what tells `soft_helpers` which call targets are libgcc
    // division helpers, and that has to happen while the IR is still physical.
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &[func_va]));
    // The reason is the analyst-visible one. This used to blame the
    // architecture unconditionally, so an x86-64 function whose blocks were all
    // attributed to a neighbour reported "LLIR lifter does not support this
    // architecture" about a lifter that supports it perfectly well.
    let lf_raw = lift_function_from_image(&image, &func)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
    annotate_calls_in(&mut lf_raw, cc, &addr_map);
    // Recovered here rather than with the other AST-pass inputs below: a call
    // through one of these tables needs its entries' parameter storage, and
    // that is the same demand-driven callee analysis.
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    let mut callee_layout_cache = std::collections::HashMap::new();
    let callee_facts = recover_direct_callee_layouts(
        &image,
        &funcs,
        &lf_raw,
        cc,
        arm_vfp_args,
        &budgets,
        dwarf_outputs.as_ref(),
        dwarf_type_env.as_ref(),
        &mut addr_map,
        &function_tables,
        &mut callee_layout_cache,
    );
    apply_recovered_direct_callee_effects(&mut lf_raw, cc, &callee_facts);
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    // Live-in argument slots (authoritative parameter set) for the type-map
    // remap, so scratch reuse of an arg register never becomes a spurious `argN`.
    // Recover the semantic prototype while SSA value IDs are still available.
    // It survives the AST pipeline as an immutable companion object; naming is
    // now only a final projection (`value -> argN`), never a type-analysis key.
    let prepared_llir = prepare_llir_for_lowering(
        &mut lf_raw,
        &image,
        &exception_sites,
        cc,
        style == "decbench" && types,
        arm_vfp_args,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        program_environment
            .as_deref()
            .and_then(|environment| environment.prototype_for(func_va)),
        dwarf_type_env.as_ref(),
    );
    let PreparedLlir {
        region,
        cfg_health,
        numbered: lf,
        definition_widths,
        parameter_slots: mut param_slots,
        mut prototype,
        ..
    } = prepared_llir;
    if let Some(prototype) = prototype.as_mut() {
        let exact_ssa = crate::ir::ssa::compute_ssa(&lf_raw);
        refine_passthrough_parameter_hints(prototype, &lf_raw, &exact_ssa, &callee_facts);
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== recovered prototype =====\n{prototype:#?}");
    }
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
    let mut profiler = crate::decompile::profile::FunctionProfiler::from_env(&outer_name, func_va);
    let mut f = profiler.measure("lower", || lower(&lf, &region, outer_name));
    crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
    // Pass-by-pass AST dump for debugging the decbench lowering pipeline. Set
    // GLAURUNG_DUMP_PASSES=1 to print the rendered body after each pass to stderr
    // (bisect which pass corrupts a function). No-op otherwise.
    let dump_passes = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    macro_rules! dp {
        ($n:expr) => {
            crate::ir::health::trace_pass($n, &f, cfg_health);
            if dump_passes {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(&f));
            }
        };
    }
    dp!("lower");
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    let stack_object_hints = dwarf_stack_object_hints(
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        cc,
    );
    let (mut stack_facts, role_names) = run_ast_passes(
        &mut f,
        &mut profiler,
        cfg_health,
        cc,
        prototype.as_ref(),
        &mut param_slots,
        locked_parameter_count(prototype.as_ref()),
        &callee_facts,
        &addr_map,
        &str_pool,
        &function_tables,
        &stack_object_hints,
        &got_targets,
    );
    merge_dwarf_register_local_facts(
        &mut stack_facts,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        &lf,
        &role_names,
        arch,
        cc,
        dwarf_type_env.as_ref(),
    );
    if style == "decbench" {
        crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
        crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
        crate::ir::exception_recover::recover_throws(&mut f);
    }
    recognise_machine_frame(&mut f, cc);
    if let Some(field_map) = &field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
    }
    // Emit a `// PDB: <name>` provenance comment in C-style output when the
    // outer function name came from a PDB public symbol -- a hint that this
    // name is Microsoft-authoritative (and not LLM-proposed / FLIRT / CFG-
    // heuristic). The PDB name is the function's `f.name` after the
    // outer-name resolution above; we only emit when a PDB cache was
    // configured AND the cache map actually answered for this VA.
    let pdb_outer_name = pdb_cache
        .and_then(|cache_dir| {
            crate::ir::name_resolve::collect_pdb_public_symbol_map(&path, cache_dir)
                .get(&func_va)
                .cloned()
        })
        .filter(|name| !name.is_empty() && !name.starts_with("sub_"));
    Ok(if style == "decbench" {
        // DecBench wants concrete C types. Reuse the recovered TypeMap when it
        // was computed, else recover on demand, then remap raw-reg keys to the
        // AST's role names (`arg0`, `ret`, ...) before rendering.
        let maps = types.then(|| {
            decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("typed DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            )
        });
        let (decl, width, exact_value_widths) = match &maps {
            Some((d, w, exact)) => (Some(d), Some(w), Some(exact)),
            None => (None, None, None),
        };
        let declared_render = dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va))
            .and_then(dwarf_render_prototype);
        decbench_text(
            &f,
            &mut profiler,
            cfg_health,
            &exception_sites,
            decl,
            width,
            exact_value_widths,
            &readonly_data,
            prototype.as_ref(),
            declared_render.as_ref(),
            dwarf_types.as_deref().unwrap_or(&[]),
            &stack_facts.source_types,
            &stack_facts.source_names,
            cc,
            &addr_map,
            &callee_facts.env,
        )
    } else if style == "c" {
        let body = profiler.measure("render_c", || crate::ir::ast::render_c(&f));
        match pdb_outer_name {
            Some(name) => format!("// PDB: {}\n{}", name, body),
            None => body,
        }
    } else if types {
        // Plain-with-types style. Non-decbench paths skip `value_number`, so the
        // raw LLIR is the canonical one; remap the TypeMap keys from raw physical
        // regs into the role-based names the AST now uses.
        let renamed = remap_type_map(&recover_types_for(&lf_raw, cc), &f, cc, &param_slots);
        profiler.measure("render_with_types", || render_with_types(&f, &renamed))
    } else {
        profiler.measure("render", || render(&f))
    })
}

#[pyfunction]
#[pyo3(name = "decompile_range_at")]
#[pyo3(signature = (path, func_va, range_start, range_end, max_blocks=256usize, max_instructions=10_000usize, timeout_ms=500u64, types=true, style="", pdb_cache=""))]
fn decompile_range_at_py(
    path: String,
    func_va: u64,
    range_start: u64,
    range_end: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
) -> PyResult<String> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_range_at");
    use crate::core::address::{Address, AddressKind};
    use crate::core::address_range::AddressRange;
    use crate::core::basic_block::BasicBlock;
    use crate::core::function::{Function, FunctionKind};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::types_recover::recover_types_for;

    if range_end <= range_start {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range_end must be greater than range_start",
        ));
    }
    if func_va < range_start || func_va >= range_end {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "func_va must lie inside [range_start, range_end)",
        ));
    }
    if max_blocks == 0 || max_instructions == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "max_blocks and max_instructions must be non-zero",
        ));
    }
    let _ = timeout_ms;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let data = image.bytes();
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench" && types).then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    let bits = image.target().address_bits().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("target address width is unknown")
    })?;
    let max_bytes = (max_instructions as u64).saturating_mul(16).max(1);
    let capped_end = range_end.min(range_start.saturating_add(max_bytes));
    let entry = Address::new(AddressKind::VA, func_va, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let block_start = Address::new(AddressKind::VA, range_start, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let block_end = Address::new(AddressKind::VA, capped_end, bits, None, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let range = AddressRange::new(block_start.clone(), capped_end - range_start, None)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let mut func = Function::new(format!("sub_{:x}", func_va), entry, FunctionKind::Normal)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    func.range = Some(range.clone());
    func.size = Some(range.size);
    func.chunks.push(range);
    func.basic_blocks.push(BasicBlock::new(
        format!("bb_{:x}", range_start),
        block_start,
        block_end,
        1,
        Some(Vec::new()),
        Some(Vec::new()),
    ));

    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    let budgets = crate::analysis::cfg::Budgets {
        max_functions: 1,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &[func_va]));
    // The reason is the analyst-visible one. This used to blame the
    // architecture unconditionally, so an x86-64 function whose blocks were all
    // attributed to a neighbour reported "LLIR lifter does not support this
    // architecture" about a lifter that supports it perfectly well.
    let lf_raw = lift_function_from_image(&image, &func)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
    annotate_calls_in(&mut lf_raw, cc, &addr_map);
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    let prepared_llir = prepare_llir_for_lowering(
        &mut lf_raw,
        &image,
        &exception_sites,
        cc,
        style == "decbench" && types,
        arm_vfp_args,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        program_environment
            .as_deref()
            .and_then(|environment| environment.prototype_for(func_va)),
        dwarf_type_env.as_ref(),
    );
    let PreparedLlir {
        region,
        cfg_health,
        numbered: lf,
        definition_widths,
        parameter_slots: mut param_slots,
        prototype,
        ..
    } = prepared_llir;
    let mut profiler = crate::decompile::profile::FunctionProfiler::from_env(&func.name, func_va);
    let mut f = profiler.measure("lower", || lower(&lf, &region, func.name.clone()));
    crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
    // An explicit byte range has no discovered callee Function objects from
    // which to recover cross-function storage layouts.
    let callee_facts = DirectCalleeFacts::default();
    // Inputs the shared pipeline needs. These were interleaved BETWEEN passes here, which
    // is why the four copies could not simply be diffed against each other — the pass
    // list and the local setup were braided together. None of them touch `f`, so
    // hoisting them is order-preserving.
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    let stack_object_hints = dwarf_stack_object_hints(
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        cc,
    );
    let (mut stack_facts, role_names) = run_ast_passes(
        &mut f,
        &mut profiler,
        cfg_health,
        cc,
        prototype.as_ref(),
        &mut param_slots,
        locked_parameter_count(prototype.as_ref()),
        &callee_facts,
        &addr_map,
        &str_pool,
        &function_tables,
        &stack_object_hints,
        &got_targets,
    );
    merge_dwarf_register_local_facts(
        &mut stack_facts,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        &lf,
        &role_names,
        arch,
        cc,
        dwarf_type_env.as_ref(),
    );
    if style == "decbench" {
        crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
        crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
        crate::ir::exception_recover::recover_throws(&mut f);
    }
    recognise_machine_frame(&mut f, cc);
    if let Some(field_map) = &field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
    }
    Ok(if style == "decbench" {
        let maps = types.then(|| {
            decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("typed DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            )
        });
        let (decl, width, exact_value_widths) = match &maps {
            Some((d, w, exact)) => (Some(d), Some(w), Some(exact)),
            None => (None, None, None),
        };
        let declared_render = dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va))
            .and_then(dwarf_render_prototype);
        decbench_text(
            &f,
            &mut profiler,
            cfg_health,
            &exception_sites,
            decl,
            width,
            exact_value_widths,
            &readonly_data,
            prototype.as_ref(),
            declared_render.as_ref(),
            dwarf_types.as_deref().unwrap_or(&[]),
            &stack_facts.source_types,
            &stack_facts.source_names,
            cc,
            &addr_map,
            &callee_facts.env,
        )
    } else if style == "c" {
        profiler.measure("render_c", || crate::ir::ast::render_c(&f))
    } else if types {
        let renamed = remap_type_map(&recover_types_for(&lf_raw, cc), &f, cc, &param_slots);
        profiler.measure("render_with_types", || render_with_types(&f, &renamed))
    } else {
        profiler.measure("render", || render(&f))
    })
}

/// Fold recovered stack-slot sizes into a (already-remapped) TypeMap as
/// width-typed integers keyed by the promoted local name (`local_0`,
/// `stack_1`, …). `upsert_public` keeps any more-specific classification
/// (e.g. a pointer), so this only supplies a committed width where nothing
/// else typed the slot.
fn merge_slot_sizes(
    tm: &mut crate::ir::types_recover::TypeMap,
    sizes: &std::collections::HashMap<String, u8>,
    cc: crate::ir::call_args::CallConv,
) {
    let word = machine_word_bytes(cc);
    for (name, &size) in sizes {
        if size == 0 {
            continue;
        }
        // A machine-word-sized frame slot is a spill slot, and on a 32-bit
        // target a spilled POINTER lands in one exactly as often as a spilled
        // `int` does — `-O0` spills every parameter. Declaring it `int` there
        // truncated the pointer once the recovered C was rebuilt at the host
        // pointer width. A genuinely narrower slot still states its own width on
        // every target. Same rule as `merge_exact_definition_widths`, and gated
        // by the same predicate — see `word_width_implies_int`.
        if size >= word && !word_width_implies_int(cc) {
            continue;
        }
        tm.upsert_public(
            crate::ir::types::VReg::Phys(name.clone()),
            crate::ir::types_recover::TypeHint::Int {
                signed: true,
                width: size,
            },
        );
    }
}

/// Rebuild a TypeMap whose keys match the post-rename AST. We walk the
/// original physical-register TypeMap and, for each entry, look up the
/// alias the naming pass would have produced. Any remaining entries keep
/// their original names so the printer still has a chance to annotate.
fn remap_type_map(
    tm: &crate::ir::types_recover::TypeMap,
    _f: &crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
) -> crate::ir::types_recover::TypeMap {
    remap_type_map_impl(tm, cc, param_slots, true, None, false)
}

fn remap_type_map_impl(
    tm: &crate::ir::types_recover::TypeMap,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    include_parameters: bool,
    exact_roles: Option<&std::collections::HashMap<String, String>>,
    exact_integer_roles: bool,
) -> crate::ir::types_recover::TypeMap {
    // Reconstruct the alias table the naming pass used for arg/ret slots;
    // `varN` aliases are assigned by first-appearance order and we can't
    // trivially recover them here, so those keys survive untouched.
    let mut alias: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let arg_slots: &[&[&str]] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        crate::ir::call_args::CallConv::Win64 => &[
            &["rcx", "ecx", "cx", "cl"],
            &["rdx", "edx", "dx", "dl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        crate::ir::call_args::CallConv::Cdecl32 => &[],
        crate::ir::call_args::CallConv::Aarch64 => &[
            &["x0", "w0"],
            &["x1", "w1"],
            &["x2", "w2"],
            &["x3", "w3"],
            &["x4", "w4"],
            &["x5", "w5"],
            &["x6", "w6"],
            &["x7", "w7"],
        ],
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            &[&["r0"], &["r1"], &["r2"], &["r3"]]
        }
    };
    for (slot, names) in arg_slots.iter().enumerate() {
        // Only alias a slot's registers to `argN` when it is a genuine live-in
        // parameter. An argument-slot register reused as scratch (common at -O2,
        // e.g. `rdx`/`rcx`) must not become a spurious `argN` and inflate the
        // recovered arity/typing.
        if !include_parameters || !param_slots.contains(&slot) {
            continue;
        }
        for n in *names {
            alias
                .entry(n.to_string())
                .or_insert_with(|| format!("arg{}", slot));
        }
    }
    let ret_aliases: &[&str] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
            &["rax", "eax", "ax", "al"]
        }
        crate::ir::call_args::CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        crate::ir::call_args::CallConv::Aarch64 => &["x0", "w0"],
        crate::ir::call_args::CallConv::Arm | crate::ir::call_args::CallConv::ArmHardFloat => {
            &["r0", "s0", "d0"]
        }
    };
    for n in ret_aliases {
        alias
            .entry(n.to_string())
            .or_insert_with(|| "ret".to_string());
    }
    let mut out = crate::ir::types_recover::TypeMap::default();
    for (reg, hint) in tm.iter() {
        match reg {
            crate::ir::types::VReg::Phys(n) => {
                if matches!(hint, crate::ir::types_recover::TypeHint::Float { .. }) {
                    // Raw type recovery sees the architectural VFP register
                    // (`s15`), while value numbering deliberately splits its
                    // definitions (`s15#1`, `s15#2`, ...). Every such exact
                    // role carries the same scalar storage class; projecting
                    // only an exact bare-name match leaves merged values as
                    // `long` and silently truncates float arithmetic in C.
                    let mut projected = false;
                    if let Some(roles) = exact_roles {
                        for (storage, role) in roles {
                            if crate::ir::abi::ssa_base(storage) == n
                                && (include_parameters
                                    || crate::ir::ast::parse_arg_index(role).is_none())
                            {
                                out.upsert_public(
                                    crate::ir::types::VReg::Phys(role.clone()),
                                    *hint,
                                );
                                projected = true;
                            }
                        }
                    }
                    if projected {
                        continue;
                    }
                }
                // Exact first-appearance aliases are needed only for semantic
                // float storage: unlike broad scalar guesses, a typed VFP
                // intrinsic proves every operand's source class. Keeping this
                // projection narrow avoids letting flow-insensitive register
                // hints perturb unrelated call prototypes.
                let exact = (exact_integer_roles
                    || matches!(
                        hint,
                        crate::ir::types_recover::TypeHint::Float { .. }
                            | crate::ir::types_recover::TypeHint::Pointer { .. }
                    ))
                .then(|| exact_roles.and_then(|roles| roles.get(n)))
                .flatten()
                .filter(|role| {
                    include_parameters || crate::ir::ast::parse_arg_index(role).is_none()
                })
                .cloned();
                let new_name = exact
                    .or_else(|| alias.get(n).cloned())
                    .unwrap_or_else(|| n.clone());
                out.upsert_public(crate::ir::types::VReg::Phys(new_name), *hint);
            }
            _ => out.upsert_public(reg.clone(), *hint),
        }
    }
    out
}

/// Prepare, verify, and render one function as DecBench C.
///
/// The three stages are deliberately separate and in this order:
///
/// 1. [`crate::ir::ast::prepare_for_decbench`] performs the semantic AST
///    transformation (bare-return ABI register, parameter-spill coalescing,
///    copy-chain folding and source-level loop-form recovery) that used to happen
///    inside the renderer;
/// 2. [`crate::ir::guarded_switch::collapse_range_guards_with_types`] uses the
///    recovered integer widths to prove compiler range-check wrappers around
///    switches redundant when an untyped proof was deliberately insufficient;
/// 3. [`crate::ir::verify_defs::verify_before_render`] verifies the result — the
///    AST that is about to be printed, which is what makes the check trustworthy;
/// 4. the renderer formats it, and nothing else.
///
/// The verdict leaves the boundary through three channels, deliberately ranked by
/// how much they cost the consumer:
///
/// * ALWAYS: [`crate::ir::health::record_render_verification`] records it, so
///   `take_render_verification` can report an honest count for the run. The CLI
///   turns a non-empty report into one stderr line. Nothing about the emitted C
///   changes, which is why this channel can be unconditional.
/// * `GLAURUNG_PASS_HEALTH`: the same count appears as `undefined_uses` on the
///   `ready_to_render` event, beside the CFG fidelity counters.
/// * `GLAURUNG_VERIFY_DEFS`: each violation is spliced in as a
///   `// glaurung-verify:` comment line. Opt-in because the decbench render is an
///   artifact other tools parse and score.
///
/// Reporting rather than erroring is deliberate: a violation means the
/// decompilation of THAT function is untrustworthy, not that the analyst's whole
/// run should fail, and suppressing the body would destroy the only evidence of
/// what went wrong.
///
/// The type maps are computed by the caller from the UNPREPARED function, whose
/// names the recovered `TypeMap` keys were remapped against.
fn select_renderable_dwarf_local_facts(
    local_types: &std::collections::HashMap<String, String>,
    local_names: &std::collections::HashMap<String, String>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
) -> (
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
) {
    let type_env = crate::ir::dwarf_type_env::DwarfTypeEnv::new(dwarf_types);
    let selected_types = local_types
        .iter()
        .filter(|(_name, c_type)| {
            crate::ir::ast::dwarf_prototype_type_is_renderable(c_type, false, &type_env)
        })
        .map(|(name, c_type)| (name.clone(), c_type.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let selected_names = local_names
        .iter()
        .filter(|(internal_name, _source_name)| selected_types.contains_key(*internal_name))
        .map(|(internal_name, source_name)| (internal_name.clone(), source_name.clone()))
        .collect();
    (selected_types, selected_names)
}

fn decbench_text(
    f: &crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    decl: Option<&crate::ir::types_recover::TypeMap>,
    width: Option<&crate::ir::types_recover::TypeMap>,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
    readonly_data: &crate::ir::readonly_fold::ReadonlyData,
    recovered_prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    declared_prototype: Option<&crate::ir::call_contracts::CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    dwarf_local_types: &std::collections::HashMap<String, String>,
    dwarf_local_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
    addr_map: &std::collections::HashMap<u64, String>,
    symbol_env: &crate::ir::symbol_env::SymbolEnv,
) -> String {
    // Install the program-level callee records for this render, and clear them
    // when it ends. The renderer used to do the clearing, which made it the
    // owner of a thread-local it never installed: a formatting projection was
    // mutating caller state on the way out. Install and release now happen in
    // the same function, so the renderer's only remaining relationship with the
    // environment is to read it.
    crate::ir::symbol_env::install(symbol_env.clone());
    let text = decbench_text_with_installed_environment(
        f,
        profiler,
        cfg_health,
        exception_sites,
        decl,
        width,
        exact_value_widths,
        readonly_data,
        recovered_prototype,
        declared_prototype,
        dwarf_types,
        dwarf_local_types,
        dwarf_local_names,
        cc,
        addr_map,
    );
    crate::ir::symbol_env::clear();
    text
}

/// The prepare/verify/render body of [`decbench_text`], with the program-level
/// callee environment already installed by its caller.
#[allow(clippy::too_many_arguments)]
fn decbench_text_with_installed_environment(
    f: &crate::ir::ast::Function,
    profiler: &mut crate::decompile::profile::FunctionProfiler,
    cfg_health: crate::ir::health::CfgHealth,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    decl: Option<&crate::ir::types_recover::TypeMap>,
    width: Option<&crate::ir::types_recover::TypeMap>,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
    readonly_data: &crate::ir::readonly_fold::ReadonlyData,
    recovered_prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    declared_prototype: Option<&crate::ir::call_contracts::CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    dwarf_local_types: &std::collections::HashMap<String, String>,
    dwarf_local_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
    addr_map: &std::collections::HashMap<u64, String>,
) -> String {
    let output_kind = recovered_prototype.map_or(
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
        crate::ir::types_recover::RecoveredPrototype::output_kind,
    );
    let (dwarf_local_types, dwarf_local_names) =
        select_renderable_dwarf_local_facts(dwarf_local_types, dwarf_local_names, dwarf_types);
    let protected_locals = dwarf_local_names
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let mut prepared = profiler.measure("prepare_for_decbench", || {
        let mut prepared = crate::ir::ast::prepare_for_decbench_with_output_and_protected_locals(
            f,
            output_kind,
            &protected_locals,
            calling_convention_pointer_width(cc),
        );
        // Preparation deletes proof-dead caller-saved register zeroing from
        // hardened GCC epilogues.  Only at this point can the x86 frame owner
        // see the adjacent balanced x87 scrub and stack teardown as one exact
        // machine-only suffix.  Run the idempotent recogniser at this semantic
        // boundary, then repeat the narrow joined-return fold it may unblock.
        // The renderer below remains formatting-only.
        recognise_machine_frame(&mut prepared, cc);
        crate::ir::ast::fold_exhaustive_if_returns(&mut prepared);
        crate::ir::ast::remove_redundant_return_constant_assignments(&mut prepared.body);
        // Preparation is also where a PC-relative address arithmetic sequence
        // finally becomes an absolute address. On AArch64 the stack guard is reached
        // through its GOT slot (`adrp`/`ldr`/`ldr`), so at the earlier
        // `resolve_names` the slot was still `%x0 + 0xfd8` and no name could attach;
        // only now is it the constant an `R_AARCH64_GLOB_DAT` relocation names.
        // Re-resolve, then let the canary pass recognise it — without this the
        // guard renders as a portable zero-filled object that the recovered C
        // dereferences, and every `-fstack-protector` function takes SIGSEGV.
        //
        // Folding first is what makes the address a single constant: preparation is
        // where the `adrp` page and the `add` of the low 12 bits finally meet in one
        // expression, and until they are folded there is no VA for `resolve_names`
        // to look up and no address for the renderer to back with a portable object.
        // `read_counter` emitted `*(int *)(0x20000 + 28)` — a dereference of a raw
        // original-image address, which is a wild pointer once recompiled.
        crate::ir::const_fold::fold_constants(&mut prepared);
        crate::ir::name_resolve::resolve_names(&mut prepared, addr_map);
        crate::ir::canary::recognise_canary(&mut prepared);
        // Source-level preparation folds GCC's multi-statement reload/sub/flag
        // sequence into a direct comparison of the promoted canary slot. Re-run
        // the idempotent canary pass here so the earlier collapsed save cannot
        // leave that now-recognisable check reading an uninitialised C local.
        crate::ir::canary::collapse_canary_save(&mut prepared);
        prepared
    });
    // From here to the verification boundary every semantic step is a NAMED pass.
    //
    // Naming is not cosmetic. `run_ast_passes` has always announced each of its
    // passes; this tail did not, so seventeen AST-mutating transforms ran between
    // `prepare_for_decbench` and `ready_to_render` with no boundary between them.
    // The consequence is concrete: `tools/pass_health_report.py` attributes the
    // FIRST pass at which a counter moves, so a newly introduced undefined read
    // anywhere in this tail was reported against `ready_to_render` — the boundary
    // that observes the damage rather than the pass that caused it. With the
    // passes named, the same report blames the transform.
    //
    // `pass!` is for a transform that rewrites the AST: it is profiled, dumped
    // under `GLAURUNG_DUMP_PASSES`, and health-traced. `refine!` is for a
    // transform that only sharpens a `TypeMap` — the AST is unchanged, so a health
    // event would repeat the previous one, and only the timing is worth recording.
    macro_rules! pass {
        ($name:expr, $operation:expr) => {{
            let result = profiler.measure($name, || $operation);
            if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
                eprintln!(
                    "\n===== after {} =====\n{}",
                    $name,
                    crate::ir::ast::render(&prepared)
                );
            }
            crate::ir::health::trace_pass($name, &prepared, cfg_health);
            result
        }};
    }
    macro_rules! refine {
        ($name:expr, $operation:expr) => {
            profiler.measure($name, || $operation)
        };
    }

    if std::env::var_os("GLAURUNG_DUMP_PASSES").is_some() {
        eprintln!(
            "\n===== after prepare_for_decbench =====\n{}",
            crate::ir::ast::render(&prepared)
        );
    }
    crate::ir::health::trace_pass("prepare_for_decbench", &prepared, cfg_health);
    // Preparation exposes the actual expression dataflow (notably parameter
    // spill coalescing and folded returns), so only now can high-half uses and
    // wide return definitions safely override a misleading narrow sub-register
    // type hint.
    let mut refined_decl = decl.cloned();
    let mut refined_width = width.cloned();
    if let Some(tm) = refined_decl.as_mut() {
        refine!("refine_decbench_abi_widths", {
            crate::ir::ast::refine_decbench_abi_widths_with_value_widths(
                &prepared,
                tm,
                exact_value_widths,
            );
            crate::ir::high_variables::refine_pointer_high_variables(&prepared, tm);
        });
    }
    if let Some(tm) = refined_decl.as_mut() {
        pass!(
            "coalesce_loop_entry_copies",
            crate::ir::latch_predicate::coalesce_loop_entry_copies(
                &mut prepared,
                &protected_locals,
                tm,
            )
        );
        pass!(
            "coalesce_source_loop_updates",
            crate::ir::latch_predicate::coalesce_source_loop_updates(
                &mut prepared,
                &protected_locals,
                tm,
                exact_value_widths,
            )
        );
    }
    if let Some(tm) = refined_width.as_mut() {
        refine!(
            "refine_decbench_abi_widths_for_width_map",
            crate::ir::ast::refine_decbench_abi_widths_with_value_widths(
                &prepared,
                tm,
                exact_value_widths,
            )
        );
    }
    if let Some(tm) = refined_decl.as_ref() {
        pass!(
            "propagate_adjacent_typed_promoted_values",
            crate::ir::copy_prop::propagate_adjacent_typed_promoted_values(&mut prepared, tm)
        );
        pass!(
            "fold_typed_declared_views",
            crate::ir::const_fold::fold_typed_declared_views(&mut prepared, tm)
        );
        pass!(
            "fold_consumed_extensions",
            crate::ir::typed_simplify::fold_consumed_extensions(&mut prepared, tm)
        );
        pass!(
            "fold_typed_comparison_extensions",
            crate::ir::const_fold::fold_typed_comparison_extensions(&mut prepared, tm)
        );
        pass!(
            "fold_constants_after_typed_folds",
            crate::ir::const_fold::fold_constants(&mut prepared)
        );
    }
    pass!("fold_guarded_readonly_lookups", {
        crate::ir::readonly_fold::fold_guarded_readonly_lookups(&mut prepared, readonly_data);
        // Read-only folding can turn an image load into a literal after the main
        // expression pipeline has already run. Re-propagate and fold immediately so
        // consumers such as packed byte-table permutations see the literal index
        // rather than rendering a dynamic 16-way lookup for a compiler-emitted mask.
        crate::ir::copy_prop::propagate_copies(&mut prepared);
        crate::ir::const_fold::fold_constants(&mut prepared);
    });
    if let Some(tm) = refined_decl.as_ref() {
        pass!(
            "collapse_range_guards_with_types",
            crate::ir::guarded_switch::collapse_range_guards_with_types(&mut prepared, tm)
        );
    }
    // A typed range proof may have synthesized an exhaustive switch default,
    // exposing the same exact switch-result join as the untyped preparation
    // path. Fold it before verification and rendering as well.
    pass!(
        "fold_exhaustive_switch_returns",
        crate::ir::ast::fold_exhaustive_switch_returns(&mut prepared)
    );
    if let Some(tm) = refined_decl.as_ref() {
        pass!(
            "fold_typed_return_abi_extensions",
            crate::ir::ast::fold_typed_return_abi_extensions(&mut prepared, tm)
        );
        // Declarations are recovered at true machine width, so a value read in a
        // wider context needs the extension the hardware performed made explicit.
        // Runs before verification and rendering; it changes no definition, use,
        // or value identity.
        pass!(
            "insert_widening_casts_for_machine_width",
            crate::ir::widen::insert_widening_casts_for_machine_width(
                &mut prepared,
                tm,
                machine_word_bytes(cc),
            )
        );
    }
    let decl = refined_decl.as_ref();
    let width = refined_width.as_ref();
    // Call specifications belong to concrete AST calls, not to renderer-local
    // symbol guesses. Refresh them after every expression/type refinement so
    // string folding, promoted objects, and pointer facts are represented on
    // the exact call boundary the verifier and C renderer consume.
    pass!(
        "refine_call_site_specs",
        crate::ir::call_contracts::refine_call_site_specs(&mut prepared, decl)
    );
    let mut dwarf_pointer_types = pass!(
        "annotate_function_fields",
        crate::ir::dwarf_fields::annotate_function_fields(
            &mut prepared,
            declared_prototype,
            dwarf_types,
            calling_convention_pointer_width(cc),
        )
    );
    for (internal_name, source_name) in &dwarf_local_names {
        let internal = crate::ir::types::VReg::phys(internal_name);
        if let Some(pointer_type) = dwarf_pointer_types.remove(&internal) {
            dwarf_pointer_types.insert(crate::ir::types::VReg::phys(source_name), pointer_type);
        }
    }
    pass!(
        "apply_authoritative_local_names",
        crate::ir::naming::apply_authoritative_local_names(&mut prepared, &dwarf_local_names)
    );
    let rendered_local_types = dwarf_local_types
        .iter()
        .map(|(internal_name, c_type)| {
            (
                dwarf_local_names
                    .get(internal_name)
                    .unwrap_or(internal_name)
                    .clone(),
                c_type.clone(),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    pass!(
        "recover_typed_handlers",
        crate::ir::exception_recover::recover_typed_handlers(&mut prepared, exception_sites)
    );
    pass!(
        "recover_throws",
        crate::ir::exception_recover::recover_throws(&mut prepared)
    );
    pass!(
        "prune_unobserved_promoted_object_stores",
        crate::ir::dead_stores::prune_unobserved_promoted_object_stores(&mut prepared)
    );
    crate::ir::health::trace_pass("ready_to_render", &prepared, cfg_health);
    // THE pre-render verification boundary. Every semantic transform is behind us
    // and the renderer below is formatting-only, so this AST is exactly what is
    // printed. The verdict is RECORDED, not merely computed: an undefined read
    // means the emitted C reads a value the machine never produced, and a proof
    // that fails into a dropped `Vec` is a wrong-code bug nobody can count.
    let verification = profiler.measure("verify_before_render", || {
        crate::ir::verify_defs::verify_before_render(&prepared)
    });
    crate::ir::health::record_render_verification(&verification);
    let violations = verification.violations;
    let recovered_render_prototype = if declared_prototype.is_none() {
        recovered_prototype.and_then(|prototype| {
            let mut machine_prototype = recovered_call_prototype(prototype, cc);
            machine_prototype.return_type =
                if output_kind == crate::ir::types_recover::RecoveredOutputKind::Void {
                    "void"
                } else {
                    crate::ir::ast::infer_return_ctype(&prepared.body, decl)
                }
                .to_string();
            if let Some(types) = decl {
                for (slot, c_type) in machine_prototype.parameter_types.iter_mut().enumerate() {
                    if let Some(hint) =
                        types.get(&crate::ir::types::VReg::phys(format!("arg{slot}")))
                    {
                        *c_type = crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                            hint,
                            calling_convention_pointer_width(cc),
                        )
                        .to_string();
                    }
                }
            }
            let refined = crate::ir::call_contracts::refine_opaque_parameter_types_from_calls(
                &prepared,
                &machine_prototype,
            );
            (refined != machine_prototype).then_some(refined)
        })
    } else {
        None
    };
    let render_prototype = declared_prototype.or(recovered_render_prototype.as_ref());
    let body = profiler.measure("render_decbench", || {
        crate::ir::ast::render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types(
            &prepared,
            decl,
            width,
            output_kind,
            render_prototype,
            dwarf_types,
            calling_convention_pointer_width(cc),
            &dwarf_pointer_types,
            &rendered_local_types,
        )
    });
    if violations.is_empty() {
        return body;
    }
    tracing::debug!(
        function = %prepared.name,
        count = violations.len(),
        "def-before-use verification found violations"
    );
    // The comments are INSTRUMENTATION, not decompiler output, so they are opt-in.
    // Emitted unconditionally they end up in whatever consumes this render — including
    // the artifact submitted to an external benchmark, where each one is a note
    // announcing our own bug inside the C we are asking someone to score. The fixture
    // gate's structural lane opts in (see `structural.decompile_all`) so its ratchet
    // still sees every violation.
    if std::env::var_os("GLAURUNG_VERIFY_DEFS").is_none() {
        return body;
    }
    crate::ir::verify_defs::splice_verify_comments(&body, &violations)
}

/// Recover machine-code prototype facts, then apply a stronger declared output
/// contract when one exists. Stripped binaries pass `None` and retain the
/// existing Ghidra/Kuna-style only-use inference unchanged.
fn recover_decbench_prototype(
    lf_raw: &crate::ir::types::LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
    type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) -> crate::ir::types_recover::RecoveredPrototype {
    use crate::debug::dwarf::{DwarfParameterType, DwarfReturnType};
    use crate::ir::types_recover::RecoveredOutputKind;

    let mut prototype = crate::ir::types_recover::recover_prototype_with_arm_vfp_args(
        lf_raw,
        ssa,
        cc,
        param_slots,
        arm_vfp_args,
    );
    if let Some(declared) = declared {
        let parameter_hints = declared
            .parameter_types
            .iter()
            .map(|parameter| match parameter {
                DwarfParameterType::Type(c_type) => {
                    dwarf_return_hint_with_env(c_type, cc, type_env)
                }
                DwarfParameterType::Unknown => None,
            })
            .collect::<Vec<_>>();
        prototype.apply_locked_parameters(cc, &parameter_hints);
    }
    match declared.map(|contract| &contract.return_type) {
        Some(DwarfReturnType::Void) => {
            prototype.apply_locked_output(RecoveredOutputKind::Void, None);
        }
        Some(DwarfReturnType::Type(c_type)) => {
            prototype.apply_locked_output(
                RecoveredOutputKind::Direct,
                dwarf_return_hint_with_env(c_type, cc, type_env),
            );
        }
        Some(DwarfReturnType::Unknown) | None => {}
    }
    prototype
}

fn lock_parameter_slots_from_prototype(
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    param_slots: &mut std::collections::HashSet<usize>,
) {
    let Some(prototype) = prototype.filter(|prototype| prototype.parameter_arity_is_locked())
    else {
        return;
    };
    param_slots.clear();
    param_slots.extend(
        prototype
            .parameters()
            .iter()
            .map(|parameter| parameter.slot),
    );
}

fn locked_parameter_count(
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
) -> Option<usize> {
    prototype
        .filter(|prototype| prototype.parameter_arity_is_locked())
        .map(|prototype| prototype.parameters().len())
}

fn float_expression_width(
    expression: &crate::ir::ast::Expr,
    types: &crate::ir::types_recover::TypeMap,
) -> Option<u8> {
    use crate::ir::ast::Expr;
    use crate::ir::types_recover::TypeHint;

    match expression {
        Expr::Reg(register) => match types.get(register) {
            Some(TypeHint::Float { width }) => Some(width),
            _ => None,
        },
        Expr::FloatConst { width, .. } => Some(*width),
        Expr::Un { src, .. } => float_expression_width(src, types),
        Expr::Bin { lhs, rhs, .. } => {
            float_expression_width(lhs, types).or_else(|| float_expression_width(rhs, types))
        }
        Expr::Select {
            if_true, if_false, ..
        } => float_expression_width(if_true, types)
            .or_else(|| float_expression_width(if_false, types)),
        _ => None,
    }
}

/// Carry semantic float facts through the source-level copies introduced by
/// stack promotion and SSA-merge lowering.
///
/// The raw LLIR map proves that `s0`/`s15` carry floats, but a promoted stack
/// slot is named only later (`local_c`). Treating its four-byte extent as an
/// integer changes a numeric float copy into a C conversion. This small fixed
/// point preserves the already-proven class without guessing from width alone.
///
/// The loop terminates because progress is measured by what the map ACTUALLY
/// holds afterwards, never by whether the proposed hint was adopted.
/// `TypeMap::refine_from_value` is a lattice join with the right to decline —
/// it is a no-op on a locked register, and `(Float{8}, Float{4})` falls through
/// to its conservative arm — so "the destination does not equal the hint I want"
/// is a condition a re-run cannot clear. Reporting that as progress spun
/// `172_float_double_widths:gcc:O2:accumulate_wide` forever (a `double`
/// accumulator fed by a `float` term is exactly the declined join), and because
/// the spin is inside one pass, no `timeout_ms` between passes could cap it.
fn refine_float_copy_types(
    body: &[crate::ir::ast::Stmt],
    types: &mut crate::ir::types_recover::TypeMap,
) {
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::{VReg, VReg::Phys};
    use crate::ir::types_recover::TypeHint;

    fn refine(
        destination: &VReg,
        source: &Expr,
        types: &mut crate::ir::types_recover::TypeMap,
        changed: &mut bool,
    ) {
        let Some(width) = float_expression_width(source, types) else {
            return;
        };
        let hint = TypeHint::Float { width };
        let before = types.get(destination);
        if before == Some(hint) {
            return;
        }
        types.refine_from_value(destination.clone(), hint);
        if types.get(destination) != before {
            *changed = true;
        }
    }

    fn visit(body: &[Stmt], types: &mut crate::ir::types_recover::TypeMap, changed: &mut bool) {
        for statement in body {
            match statement {
                Stmt::Assign { dst, src } => refine(dst, src, types, changed),
                Stmt::Store {
                    addr: Expr::Reg(destination @ Phys(name)),
                    src,
                    ..
                } if name.starts_with("local_") || name.starts_with("stack_") => {
                    refine(destination, src, types, changed);
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    visit(then_body, types, changed);
                    if let Some(else_body) = else_body {
                        visit(else_body, types, changed);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    visit(body, types, changed)
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    visit(std::slice::from_ref(init.as_ref()), types, changed);
                    visit(body, types, changed);
                    visit(std::slice::from_ref(step.as_ref()), types, changed);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        visit(case_body, types, changed);
                    }
                    if let Some(default) = default {
                        visit(default, types, changed);
                    }
                }
                _ => {}
            }
        }
    }

    // Every reported round strictly changes at least one entry, and the join
    // only ever moves a register from "no fact"/integer-ish to float, so the
    // number of rounds is bounded by the number of float-typed destinations.
    // The cap is a backstop against a future non-monotone edit to the lattice:
    // it fails loudly in debug builds rather than hanging a release gate.
    const MAX_ROUNDS: usize = 512;
    let mut rounds = 0;
    loop {
        let mut changed = false;
        visit(body, types, &mut changed);
        rounds += 1;
        if !changed {
            break;
        }
        if rounds >= MAX_ROUNDS {
            debug_assert!(
                false,
                "refine_float_copy_types did not reach a fixed point in {MAX_ROUNDS} rounds"
            );
            break;
        }
    }
}

/// Build the `(declaration, width)` type-map pair the DecBench renderer needs.
///
/// Machine-width facts come from the PRE-canonicalisation LLIR (`lf_raw`), the only
/// place each operand's true machine width survives (`edi`=4; canonicalisation folds
/// it into `rdi`). That width is what the declaration should state — DWARF's
/// `dispatch(int,int,int)`, not a blanket `long` — and what the logical-shift cast
/// needs. Parameter facts are projected from the pre-lowering `RecoveredPrototype`,
/// which retains exact SSA live-in identity. Only non-parameter roles are remapped
/// from storage names; both maps are then augmented with promoted-slot sizes.
/// Whether a MACHINE-WORD-sized definition or frame slot should be read as
/// evidence that the value is an `int` of that width.
///
/// True on the 64-bit conventions, where writing `edi` instead of `rdi` is a
/// narrowing the compiler chose and is *the* -O0 type-recovery signal.
///
/// False on cdecl32, where four bytes is the whole register and the same fact is
/// equally consistent with `int`, `long` and a pointer. Recording it as `int`
/// truncated every pointer that flowed through a machine register or a spill
/// slot once the recovered C was rebuilt at the host pointer width, which was
/// 50 of i386's 110 execution failures.
///
/// Deliberately still TRUE for the 32-bit ARM conventions. They have the same
/// ambiguity but not the same balance: the ARM32 lifter has no sub-register
/// spellings, so its machine registers are already declared `long` and this rule
/// would only change FRAME SLOTS. Measured on `tools/arch_roundtrip.py`, doing
/// that costs armv7 two functions and gains none —
/// `03_loop_shapes:O0:dowhile_recompute` (`t >>= 8` on a `long` no longer wraps
/// at 32 bits, so the loop runs eight times instead of four) and
/// `11_call_shapes:O0:call_result_drives_branch` (a 32-bit call result widened
/// to `long` acquires the callee's undefined high half, inverting a sign test).
/// Both are the cost side of the same trade i386 wins on.
///
/// The durable fix for both is to propagate POINTER types through copies rather
/// than inferring a type from storage width at all; until that exists, this
/// records exactly where the trade has been measured to pay.
fn word_width_implies_int(cc: crate::ir::call_args::CallConv) -> bool {
    !matches!(cc, crate::ir::call_args::CallConv::Cdecl32)
}

fn merge_exact_definition_widths(
    tm: &mut crate::ir::types_recover::TypeMap,
    definition_widths: &std::collections::HashMap<crate::ir::types::VReg, u8>,
    role_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
) {
    let word = machine_word_bytes(cc);
    for (storage, &exact_width) in definition_widths {
        // A full-width machine-register definition on a 32-bit target is not a
        // narrowing and therefore not evidence of an `int`. Recording it as one
        // declares every machine word `int`, and the DecBench C is rebuilt at the
        // HOST pointer width — so a recovered `var = p; var = var + 4;` chain
        // truncated the pointer to 32 bits and faulted, and an assignment from
        // such an `int` into a `long` role acquired a `(unsigned long)(unsigned
        // int)` conversion that did the same. Narrower definitions (a byte or a
        // halfword) remain genuine narrowing evidence on every target. Gated by
        // `word_width_implies_int`, which records where the trade measures out.
        if exact_width >= word && !word_width_implies_int(cc) {
            continue;
        }
        let crate::ir::types::VReg::Phys(storage_name) = storage else {
            continue;
        };
        let Some(role_name) = role_names.get(storage_name) else {
            continue;
        };
        // A later use of an ABI argument register is a new value, not new
        // evidence about the function's entry parameter.  In particular,
        // `mov esi, 1` before a recursive call must not narrow an entry `%rsi`
        // that was spilled, reloaded, and compared as a 64-bit parameter.
        // Parameter widths come from `RecoveredPrototype`'s exact SSA live-in;
        // this legacy storage-name projection is only valid for non-parameter
        // roles whose definition identity the naming pass retained.
        if crate::ir::ast::parse_arg_index(role_name).is_some() {
            continue;
        }
        let role = crate::ir::types::VReg::phys(role_name);
        // An exact SSA value used as an address is stronger than its register
        // storage width. On 32-bit ARM both facts are four bytes, but projecting
        // the latter as `int` truncates the former when DecBench recompiles the
        // recovered C on a 64-bit host (`var = p; *(var + 4)`).
        if matches!(
            tm.get(&role),
            Some(
                crate::ir::types_recover::TypeHint::Pointer { .. }
                    | crate::ir::types_recover::TypeHint::CodePointer
            )
        ) {
            continue;
        }
        let signed = match tm.get(&role) {
            Some(crate::ir::types_recover::TypeHint::Int { signed, .. }) => signed,
            // The definition map proves storage width, not source-language
            // signedness. Preserve richer evidence when present and otherwise
            // keep the renderer's conservative signed-integer default.
            _ => true,
        };
        tm.refine_from_value(
            role,
            crate::ir::types_recover::TypeHint::Int {
                signed,
                width: exact_width,
            },
        );
    }
}

fn decbench_type_maps(
    f: &crate::ir::ast::Function,
    lf_raw: &crate::ir::types::LlirFunction,
    lf_numbered: &crate::ir::types::LlirFunction,
    prototype: &crate::ir::types_recover::RecoveredPrototype,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    slot_sizes: &std::collections::HashMap<String, u8>,
    source_types: &std::collections::HashMap<String, String>,
    source_names: &std::collections::HashMap<String, String>,
    dwarf_type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
    role_names: &std::collections::HashMap<String, String>,
    definition_widths: &std::collections::HashMap<crate::ir::types::VReg, u8>,
) -> (
    crate::ir::types_recover::TypeMap,
    crate::ir::types_recover::TypeMap,
    std::collections::HashMap<String, u8>,
) {
    use crate::ir::types_recover::recover_types_for;
    let raw = recover_types_for(lf_raw, cc);
    let numbered = remap_type_map_impl(
        &recover_types_for(lf_numbered, cc),
        cc,
        param_slots,
        false,
        Some(role_names),
        true,
    );
    let mut decl = remap_type_map_impl(&raw, cc, param_slots, false, Some(role_names), false);
    let live_ins = prototype.parameter_type_map();
    let result = prototype.result_type_map();
    if let Some(hint) = result.get(&crate::ir::types::VReg::phys("ret")) {
        if prototype.output_is_locked() {
            decl.apply_locked_fact(crate::ir::types::VReg::phys("ret"), hint);
        } else {
            decl.refine_from_value(crate::ir::types::VReg::phys("ret"), hint);
        }
    }
    // Only entry values with the qualified spill/reload/dereference proof are
    // allowed to refine a rendered role. The complete version-zero map remains
    // available to analysis, but prototype recovery is not yet a fixed point
    // with function boundaries and direct-callee types.
    for parameter in prototype.parameters() {
        let role = crate::ir::types::VReg::Phys(format!("arg{}", parameter.slot));
        let hint = live_ins.get(&role).or_else(|| {
            prototype.parameter_arity_is_locked().then_some(
                crate::ir::types_recover::TypeHint::Int {
                    signed: true,
                    width: crate::ir::abi::machine_word_bytes(cc),
                },
            )
        });
        if let Some(hint) = hint {
            if prototype.parameter_is_locked(parameter.slot) {
                decl.apply_locked_fact(role, hint);
            } else {
                decl.refine_from_value(role, hint);
            }
        }
    }
    merge_slot_sizes(&mut decl, slot_sizes, cc);
    apply_stack_source_types(&mut decl, source_types, source_names, cc, dwarf_type_env);
    merge_exact_definition_widths(&mut decl, definition_widths, role_names, cc);
    crate::ir::call_contracts::refine_call_result_types(f, &mut decl);
    refine_float_copy_types(&f.body, &mut decl);
    for (role, hint) in numbered.iter() {
        refine_numbered_declaration(&mut decl, role, hint);
    }
    let mut width = remap_type_map_impl(&raw, cc, param_slots, false, Some(role_names), false);
    if let Some(hint) = result.get(&crate::ir::types::VReg::phys("ret")) {
        if prototype.output_is_locked() {
            width.apply_locked_fact(crate::ir::types::VReg::phys("ret"), hint);
        } else {
            width.refine_from_value(crate::ir::types::VReg::phys("ret"), hint);
        }
    }
    for parameter in prototype.parameters() {
        let role = crate::ir::types::VReg::Phys(format!("arg{}", parameter.slot));
        let hint = live_ins.get(&role).or_else(|| {
            prototype.parameter_arity_is_locked().then_some(
                crate::ir::types_recover::TypeHint::Int {
                    signed: true,
                    width: crate::ir::abi::machine_word_bytes(cc),
                },
            )
        });
        if let Some(hint) = hint {
            if prototype.parameter_is_locked(parameter.slot) {
                width.apply_locked_fact(role, hint);
            } else {
                width.refine_from_value(role, hint);
            }
        }
    }
    merge_slot_sizes(&mut width, slot_sizes, cc);
    apply_stack_source_types(&mut width, source_types, source_names, cc, dwarf_type_env);
    merge_exact_definition_widths(&mut width, definition_widths, role_names, cc);
    crate::ir::call_contracts::refine_call_result_types(f, &mut width);
    refine_float_copy_types(&f.body, &mut width);
    for (role, hint) in numbered.iter() {
        match hint {
            crate::ir::types_recover::TypeHint::Pointer { pointee_width } => {
                width.refine_from_value(
                    role.clone(),
                    crate::ir::types_recover::TypeHint::Pointer {
                        pointee_width: *pointee_width,
                    },
                );
            }
            crate::ir::types_recover::TypeHint::Int {
                signed,
                width: exact_width,
            } if matches!(
                width.get(role),
                Some(crate::ir::types_recover::TypeHint::Int { .. })
            ) =>
            {
                // This companion map governs expression casts, not storage
                // declarations. Per-value SSA evidence therefore owns both
                // width and signedness: raw-register recovery routinely sees a
                // zero-extended move before the same value's signed wide use.
                width.force_int_width(role.clone(), *exact_width);
                width.force_int_signedness(role.clone(), *signed);
            }
            _ => {}
        }
    }
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== exact role names =====\n{role_names:#?}");
        eprintln!("\n===== numbered value types =====\n{numbered:#?}");
        eprintln!("\n===== recovered declaration types =====\n{decl:#?}");
        eprintln!("\n===== recovered expression-width types =====\n{width:#?}");
    }
    let exact_value_widths = integer_widths_by_role(&width);
    (decl, width, exact_value_widths)
}

fn apply_stack_source_types(
    types: &mut crate::ir::types_recover::TypeMap,
    source_types: &std::collections::HashMap<String, String>,
    source_names: &std::collections::HashMap<String, String>,
    cc: crate::ir::call_args::CallConv,
    dwarf_type_env: Option<&crate::ir::dwarf_type_env::DwarfTypeEnv<'_>>,
) {
    for (internal_name, c_type) in source_types {
        let Some(hint) = dwarf_return_hint_with_env(c_type, cc, dwarf_type_env) else {
            continue;
        };
        types.apply_locked_fact(crate::ir::types::VReg::phys(internal_name), hint);
        if let Some(source_name) = source_names.get(internal_name) {
            types.apply_locked_fact(crate::ir::types::VReg::phys(source_name), hint);
        }
    }
}

/// Extract scalar widths from the final per-value expression map.
///
/// This map has already combined raw operation evidence with exact numbered
/// identities. It intentionally excludes pointers and floats: declaration-kind
/// recovery owns those, while this companion only answers integer expression
/// width after prepared AST copies have hidden the original storage spelling.
fn integer_widths_by_role(
    widths: &crate::ir::types_recover::TypeMap,
) -> std::collections::HashMap<String, u8> {
    widths
        .iter()
        .filter_map(|(role, hint)| match (role, hint) {
            (
                crate::ir::types::VReg::Phys(role),
                crate::ir::types_recover::TypeHint::Int { width, .. },
            ) => Some((role.clone(), *width)),
            _ => None,
        })
        .collect()
}

/// Apply per-value SSA evidence without discarding a previously proven pointer.
fn refine_numbered_declaration(
    decl: &mut crate::ir::types_recover::TypeMap,
    role: &crate::ir::types::VReg,
    hint: &crate::ir::types_recover::TypeHint,
) {
    match hint {
        crate::ir::types_recover::TypeHint::Pointer { pointee_width } => {
            decl.refine_from_value(
                role.clone(),
                crate::ir::types_recover::TypeHint::Pointer {
                    pointee_width: *pointee_width,
                },
            );
        }
        // Register width alone does not prove a source integer declaration.
        // This is especially important when a 32-bit pointer is transported
        // through a full-width GPR and the recovered C is rebuilt on a 64-bit
        // host. Prepared-AST definition widths refine genuine wide scalars
        // later, with enough context to distinguish those cases.
        crate::ir::types_recover::TypeHint::Int { .. } => {}
        _ => {}
    }
}

/// Decompile the first `limit` discovered functions. Returns a list of
/// `(func_name, entry_va, pseudocode)` triples.
///
/// Default `limit=30000` matches the function-discovery cap so the
/// `--all` flag really does emit every function unless the user
/// explicitly opts back into a smaller window.
#[pyfunction]
#[pyo3(name = "decompile_all")]
#[pyo3(signature = (path, limit=30_000usize, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=10_000u64, pdb_cache="", style=""))]
fn decompile_all_py(
    py: Python<'_>,
    path: String,
    limit: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    pdb_cache: &str,
    style: &str,
) -> PyResult<PyObject> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_all");
    use crate::analysis::cfg::Budgets;
    use crate::ir::ast::{lower, render};
    use crate::ir::lift_function::lift_function_from_image;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let data = image.bytes();
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench").then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    let budgets = Budgets {
        max_functions: limit.max(1),
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    // Whole-binary function discovery: seconds to minutes on a large image, and
    // the reason `Ctrl-C` used to do nothing until it finished. `data` is an
    // owned `Vec<u8>` and `Budgets` is `Copy`; no `Bound`/`Py` reference crosses
    // the closure boundary. See `python_bindings::analysis`.
    let funcs = py.detach(|| session.discover_functions(&budgets, &[]));
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    let environment_targets = funcs
        .iter()
        .take(limit)
        .map(|function| function.entry_point.value)
        .collect::<Vec<_>>();
    let program_environment = (style == "decbench")
        .then(|| session.environment(&budgets, cc, &addr_map, &environment_targets));
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    let mut callee_layout_cache = std::collections::HashMap::new();
    let list = PyList::empty(py);
    for func in funcs.iter().take(limit) {
        // The GIL is held across the per-function lifting work (the loop builds
        // a `PyList` as it goes), so CPython never re-enters its eval loop and
        // never notices a signal. This is the supported way to stay
        // interruptible without releasing: it raises `KeyboardInterrupt` here.
        py.check_signals()?;
        let Ok(lf_raw) = lift_function_from_image(&image, func) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
        annotate_calls_in(&mut lf_raw, cc, &addr_map);
        let callee_facts = recover_direct_callee_layouts(
            &image,
            &funcs,
            &lf_raw,
            cc,
            arm_vfp_args,
            &budgets,
            dwarf_outputs.as_ref(),
            dwarf_type_env.as_ref(),
            &mut addr_map,
            &function_tables,
            &mut callee_layout_cache,
        );
        apply_recovered_direct_callee_effects(&mut lf_raw, cc, &callee_facts);
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let prepared_llir = prepare_llir_for_lowering(
            &mut lf_raw,
            &image,
            &exception_sites,
            cc,
            style == "decbench",
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
            program_environment
                .as_deref()
                .and_then(|environment| environment.prototype_for(func.entry_point.value)),
            dwarf_type_env.as_ref(),
        );
        let PreparedLlir {
            region,
            cfg_health,
            numbered: lf,
            definition_widths,
            parameter_slots: mut param_slots,
            mut prototype,
            ..
        } = prepared_llir;
        if let Some(prototype) = prototype.as_mut() {
            let exact_ssa = crate::ir::ssa::compute_ssa(&lf_raw);
            refine_passthrough_parameter_hints(prototype, &lf_raw, &exact_ssa, &callee_facts);
        }
        let outer_name = resolve_outer_function_name(&func.name, func.entry_point.value, &addr_map);
        let mut profiler = crate::decompile::profile::FunctionProfiler::from_env(
            &outer_name,
            func.entry_point.value,
        );
        let mut f = profiler.measure("lower", || lower(&lf, &region, outer_name.clone()));
        crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
        // One pass list, shared with every other entry point — see `run_ast_passes`.
        // This site used to run dead-flag pruning before constant folding and never
        // pruned unreferenced labels, so `--all` produced different output from `--vas`
        // for the same function, and the fixture gate's structural lane measured a
        // different pipeline from its execution lane. It cannot drift again.
        let stack_object_hints = dwarf_stack_object_hints(
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
            cc,
        );
        let (mut stack_facts, role_names) = run_ast_passes(
            &mut f,
            &mut profiler,
            cfg_health,
            cc,
            prototype.as_ref(),
            &mut param_slots,
            locked_parameter_count(prototype.as_ref()),
            &callee_facts,
            &addr_map,
            &str_pool,
            &function_tables,
            &stack_object_hints,
            &got_targets,
        );
        merge_dwarf_register_local_facts(
            &mut stack_facts,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
            &lf,
            &role_names,
            arch,
            cc,
            dwarf_type_env.as_ref(),
        );
        if style == "decbench" {
            crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
            crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
            crate::ir::exception_recover::recover_throws(&mut f);
        }
        recognise_machine_frame(&mut f, cc);
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let text = if style == "decbench" {
            let (decl, width, exact_value_widths) = decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            );
            let declared_render = dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value))
                .and_then(dwarf_render_prototype);
            decbench_text(
                &f,
                &mut profiler,
                cfg_health,
                &exception_sites,
                Some(&decl),
                Some(&width),
                Some(&exact_value_widths),
                &readonly_data,
                prototype.as_ref(),
                declared_render.as_ref(),
                dwarf_types.as_deref().unwrap_or(&[]),
                &stack_facts.source_types,
                &stack_facts.source_names,
                cc,
                &addr_map,
                &callee_facts.env,
            )
        } else {
            profiler.measure("render", || render(&f))
        };
        list.append((outer_name, func.entry_point.value, text))?;
    }
    Ok(list.into())
}

#[pyfunction]
#[pyo3(name = "decompile_many")]
#[pyo3(signature = (path, func_vas, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", pdb_cache="", max_functions=0usize))]
#[allow(clippy::too_many_arguments)]
fn decompile_many_py(
    py: Python<'_>,
    path: String,
    func_vas: Vec<u64>,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
    pdb_cache: &str,
    max_functions: usize,
) -> PyResult<PyObject> {
    let _run_profile = crate::decompile::profile::RunProfiler::from_env("decompile_many");
    // Decompile an arbitrary SUBSET of functions in a SINGLE analysis pass.
    //
    // `decompile_at` re-runs `analyze_functions_bytes` (and the PDB/addr-map
    // build) on every call, so decompiling N scattered functions in a large
    // binary (e.g. the 18 MB mpengine.dll, ~30k functions) costs N full
    // analyses. This amortises that fixed cost across the whole requested set:
    // analyse once, then run the same per-function pipeline as `decompile_at`
    // for each requested VA. Returns a list of (name, va, c_or_ir_text) for
    // every requested VA that resolves to a known function.
    use crate::analysis::cfg::Budgets;
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_image;
    use crate::ir::types_recover::recover_types_for;
    use std::collections::HashSet;

    let image = load_program_image(&path)?;
    let session = crate::program::session::ProgramSession::from_image(image);
    let image = session.image().clone();
    let data = image.bytes();
    // See `decompile_at`: an ARM32 Thumb `.symtab` value carries the Thumb bit.
    let func_vas: Vec<u64> = func_vas
        .into_iter()
        .map(|va| image.normalize_function_entry(va))
        .collect();
    let exception_sites = image.exception_call_sites();
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&image));
    let dwarf_types = (style == "decbench").then(|| session.debug_types());
    let dwarf_type_env = dwarf_types
        .as_deref()
        .map(crate::ir::dwarf_type_env::DwarfTypeEnv::new);
    // Zero is the public address-scoped default: process exactly the unique
    // requested entries. Direct-callee prototype evidence is recovered lazily
    // by `recover_direct_callee_layouts`, so unrelated automatic seeds never
    // need to consume this worklist merely to render one call accurately.
    let requested_function_limit = if max_functions == 0 {
        func_vas
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1)
    } else {
        max_functions
    };
    let budgets = Budgets {
        max_functions: requested_function_limit,
        max_blocks,
        max_instructions,
        timeout_ms,
        total_timeout_ms: 0,
    };
    // --- one-time analysis + name/field/string maps -----------------------
    // Whole-binary function discovery: seconds to minutes on a large image, and
    // the reason `Ctrl-C` used to do nothing until it finished. `data` is an
    // owned `Vec<u8>` and `Budgets` is `Copy`; no `Bound`/`Py` reference crosses
    // the closure boundary. See `python_bindings::analysis`.
    let funcs = py.detach(|| session.discover_functions(&budgets, &func_vas));
    let cc = target_calling_convention(&image)?;
    let arch = image.target().architecture();
    let arm_vfp_args = image.arm_hard_float();
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    let program_environment = (style == "decbench" && types)
        .then(|| session.environment(&budgets, cc, &addr_map, &func_vas));
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool_from_image(&image);
    let readonly_data = readonly_data_for(&session, &image, &str_pool);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    // Slot -> the in-image address the loader stores there, so a `-fPIC` read
    // of a locally-defined global folds to that global instead of dereferencing
    // an unrelocated linkage word. See `ir::got_fold`.
    let got_targets: std::collections::HashMap<u64, u64> =
        crate::analysis::elf_got::elf_got_target_map(&data)
            .into_iter()
            .collect();
    let mut callee_layout_cache = std::collections::HashMap::new();
    // PDB-only public-symbol map for the `// PDB:` provenance comment; built
    // once, empty for non-PE inputs (so it never fires on ELF/Mach-O).
    let pdb_public_map = pdb_cache
        .map(|cache_dir| crate::ir::name_resolve::collect_pdb_public_symbol_map(&path, cache_dir))
        .unwrap_or_default();

    let wanted: HashSet<u64> = func_vas.iter().copied().collect();
    let list = PyList::empty(py);

    // The rendering loop deliberately has NO wall clock, and `timeout_ms`
    // stays what `Budgets` documents: the per-function CFG-walk budget.
    //
    // A clock here was tried and measured. `tools/diff_decompile.decompiled_many_c`
    // calls this with no `timeout_ms`, so it takes the 5 s default; under CPU
    // load the budget expired mid-set and the unrendered functions came back as
    // an explanatory stub. That stub is a correct report and a wrong ANSWER:
    // the harness compiled it, found no definition, and reported
    // `151_wide_branch_ladder:clang:O0:big151_flat_cascade` as
    // `undefined symbol: big151_flat_cascade` — a semantic failure verdict
    // manufactured by how busy the machine was. Same build, same seed: passes
    // idle, fails under sixteen spinners.
    //
    // Exceeding a wall clock is not evidence that a decompilation is wrong, and
    // a pass that fails to terminate is a correctness bug to fix in that pass,
    // not something a clock between passes could have caught anyway — the spin
    // that motivated this was inside `refine_float_copy_types`, where no
    // between-pass check could reach it. See its fixed-point proof.
    for func in funcs.iter() {
        // See `decompile_all_py`: keeps a long multi-function decompile
        // interruptible while the GIL is held for the `PyList` it is building.
        py.check_signals()?;
        let func_va = func.entry_point.value;
        if !wanted.contains(&func_va) {
            continue;
        }
        let Ok(lf_raw) = lift_function_from_image(&image, func) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
        annotate_calls_in(&mut lf_raw, cc, &addr_map);
        let callee_facts = recover_direct_callee_layouts(
            &image,
            &funcs,
            &lf_raw,
            cc,
            arm_vfp_args,
            &budgets,
            dwarf_outputs.as_ref(),
            dwarf_type_env.as_ref(),
            &mut addr_map,
            &function_tables,
            &mut callee_layout_cache,
        );
        apply_recovered_direct_callee_effects(&mut lf_raw, cc, &callee_facts);
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let prepared_llir = prepare_llir_for_lowering(
            &mut lf_raw,
            &image,
            &exception_sites,
            cc,
            style == "decbench",
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
            program_environment
                .as_deref()
                .and_then(|environment| environment.prototype_for(func_va)),
            dwarf_type_env.as_ref(),
        );
        let PreparedLlir {
            region,
            cfg_health,
            numbered: lf,
            definition_widths,
            parameter_slots: mut param_slots,
            mut prototype,
            ..
        } = prepared_llir;
        if let Some(prototype) = prototype.as_mut() {
            let exact_ssa = crate::ir::ssa::compute_ssa(&lf_raw);
            refine_passthrough_parameter_hints(prototype, &lf_raw, &exact_ssa, &callee_facts);
        }
        let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
        let mut profiler =
            crate::decompile::profile::FunctionProfiler::from_env(&outer_name, func_va);
        let mut f = profiler.measure("lower", || lower(&lf, &region, outer_name));
        crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
        // One pass list, shared with every other entry point — see `run_ast_passes`.
        // This site used to run dead-flag pruning before constant folding and never
        // pruned unreferenced labels, so `--all` produced different output from `--vas`
        // for the same function, and the fixture gate's structural lane measured a
        // different pipeline from its execution lane. It cannot drift again.
        // Type recovery runs on the pre-canonicalisation LLIR and does not touch `f`,
        // so it is hoisted above the shared pipeline rather than braided into it.
        let tm = if types {
            Some(recover_types_for(&lf_raw, cc))
        } else {
            None
        };
        let stack_object_hints = dwarf_stack_object_hints(
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
            cc,
        );
        let (mut stack_facts, role_names) = run_ast_passes(
            &mut f,
            &mut profiler,
            cfg_health,
            cc,
            prototype.as_ref(),
            &mut param_slots,
            locked_parameter_count(prototype.as_ref()),
            &callee_facts,
            &addr_map,
            &str_pool,
            &function_tables,
            &stack_object_hints,
            &got_targets,
        );
        merge_dwarf_register_local_facts(
            &mut stack_facts,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
            &lf,
            &role_names,
            arch,
            cc,
            dwarf_type_env.as_ref(),
        );
        if style == "decbench" {
            crate::ir::exception_recover::recover_typed_handlers(&mut f, &exception_sites);
            crate::ir::exception_recover::mark_int_throws_with_address_map(&mut f, &addr_map);
            crate::ir::exception_recover::recover_throws(&mut f);
        }
        recognise_machine_frame(&mut f, cc);
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let pdb_outer_name = pdb_public_map
            .get(&func_va)
            .filter(|name| !name.is_empty() && !name.starts_with("sub_"))
            .cloned();
        let text = if style == "decbench" {
            let (decl, width, exact_value_widths) = decbench_type_maps(
                &f,
                &lf_raw,
                &lf,
                prototype.as_ref().expect("DecBench prototype"),
                cc,
                &param_slots,
                &stack_facts.sizes,
                &stack_facts.source_types,
                &stack_facts.source_names,
                dwarf_type_env.as_ref(),
                &role_names,
                &definition_widths,
            );
            let declared_render = dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va))
                .and_then(dwarf_render_prototype);
            decbench_text(
                &f,
                &mut profiler,
                cfg_health,
                &exception_sites,
                Some(&decl),
                Some(&width),
                Some(&exact_value_widths),
                &readonly_data,
                prototype.as_ref(),
                declared_render.as_ref(),
                dwarf_types.as_deref().unwrap_or(&[]),
                &stack_facts.source_types,
                &stack_facts.source_names,
                cc,
                &addr_map,
                &callee_facts.env,
            )
        } else if style == "c" {
            let body = profiler.measure("render_c", || crate::ir::ast::render_c(&f));
            match pdb_outer_name {
                Some(name) => format!("// PDB: {}\n{}", name, body),
                None => body,
            }
        } else {
            match tm {
                Some(tm) => {
                    let renamed = remap_type_map(&tm, &f, cc, &param_slots);
                    profiler.measure("render_with_types", || render_with_types(&f, &renamed))
                }
                None => profiler.measure("render", || render(&f)),
            }
        };
        let name = resolve_outer_function_name(&func.name, func_va, &addr_map);
        list.append((name, func_va, text))?;
    }
    Ok(list.into())
}

use crate::ir::name_resolve::resolve_outer_function_name;

/// Drain and return the definition-before-use verdicts recorded since the last call.
///
/// The dictionary carries `verified_functions`, `unverified_functions`,
/// `undefined_uses`, `dropped_verdicts`, and `unverified` — a list of
/// `{"function", "entry_va", "undefined_uses", "violations": [{"name", "kind"}]}`
/// ordered by entry address.
///
/// A non-empty `unverified` list means the recovered C for those functions reads a
/// value the machine never produced. Draining rather than peeking is deliberate:
/// the caller that asks is the caller that reports, and the next question should
/// be about the next run.
#[pyfunction]
#[pyo3(name = "take_render_verification")]
fn take_render_verification_py(py: Python<'_>) -> PyResult<Py<pyo3::PyAny>> {
    use pyo3::types::{PyDict, PyList};

    let report = crate::ir::health::take_render_verification();
    let out = PyDict::new(py);
    out.set_item("verified_functions", report.verified_functions)?;
    out.set_item("unverified_functions", report.unverified_functions)?;
    out.set_item("undefined_uses", report.undefined_uses)?;
    out.set_item("dropped_verdicts", report.dropped_verdicts)?;
    let unverified = PyList::empty(py);
    for verdict in &report.unverified {
        let entry = PyDict::new(py);
        entry.set_item("function", &verdict.function)?;
        entry.set_item("entry_va", &verdict.entry_va)?;
        entry.set_item("undefined_uses", verdict.undefined_uses)?;
        let violations = PyList::empty(py);
        for violation in &verdict.violations {
            let item = PyDict::new(py);
            item.set_item("name", &violation.name)?;
            item.set_item("kind", violation.kind)?;
            violations.append(item)?;
        }
        entry.set_item("violations", violations)?;
        unverified.append(entry)?;
    }
    out.set_item("unverified", unverified)?;
    Ok(out.into())
}

/// Register LLIR-related Python bindings under the `ir` submodule.
pub fn register_ir_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let ir_mod = pyo3::types::PyModule::new(py, "ir")?;
    ir_mod.add_class::<session::PyDecompilerSession>()?;
    ir_mod.add_function(wrap_pyfunction!(lift_bytes_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(lift_window_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_range_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_all_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_many_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(take_render_verification_py, &ir_mod)?)?;
    m.add_submodule(&ir_mod)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Verified typed MIR must be built for every decompilation, not only when
    /// `GLAURUNG_DUMP_PASSES` happens to be set.
    ///
    /// It was previously computed inside the debug-dump block, printed, and
    /// dropped. That left the roadmap's "migrate a production consumer to
    /// verified MIR evidence" with nothing to migrate onto, and made the
    /// artifact's health visible only to a human reading stderr. It also broke
    /// the rule that correctness must not depend on an environment variable —
    /// the analysis a consumer would trust existed only in debug runs.
    ///
    /// The env var is explicitly cleared here so the test cannot pass by
    /// inheriting a debug-enabled environment.
    #[test]
    fn verified_mir_is_prepared_without_the_debug_environment_variable() {
        let directory = tempfile::tempdir().expect("temporary fixture directory");
        let source = directory.path().join("mir_available.c");
        let executable = directory.path().join("mir_available");
        std::fs::write(
            &source,
            "__attribute__((noinline)) int mir_target(int *values, int count) {\n\
                 int total = 0;\n\
                 for (int index = 0; index < count; ++index) {\n\
                     total += values[index];\n\
                 }\n\
                 return total;\n\
             }\n\
             int main(void) { int v[4] = {1,2,3,4}; return mir_target(v, 4); }\n",
        )
        .expect("write real fixture");
        let built = std::process::Command::new("cc")
            .args(["-g", "-O0", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("host C compiler is available");
        assert!(
            built.status.success(),
            "compile fixture: {}",
            String::from_utf8_lossy(&built.stderr)
        );

        let session = crate::program::session::ProgramSession::from_path(&executable)
            .expect("fixture is a real object");
        let image = session.image();
        let entry = image
            .defined_text_symbol_address("mir_target")
            .expect("fixture target symbol");

        // SAFETY: single-threaded test; the variable is only read by the dump
        // block this test exists to prove is not required.
        unsafe { std::env::remove_var("GLAURUNG_DUMP_PASSES") };

        let discovered = session.discover_functions(
            &crate::analysis::cfg::Budgets {
                max_functions: 1,
                max_blocks: 256,
                max_instructions: 16_384,
                timeout_ms: 10_000,
                total_timeout_ms: 0,
            },
            &[entry],
        );
        let target = discovered
            .iter()
            .find(|candidate| candidate.entry_point.value == entry)
            .expect("the fixture function is discovered");
        let mut function = crate::ir::lift_function::lift_function_from_image(image, target)
            .expect("the fixture function lifts");
        let prepared = super::prepare_llir_for_lowering(
            &mut function,
            image,
            &[],
            CallConv::SysVAmd64,
            true,
            false,
            None,
            None,
            None,
        );

        let mir = prepared
            .mir(image)
            .expect("verified MIR must be available without GLAURUNG_DUMP_PASSES");
        assert!(
            !mir.values().is_empty(),
            "a real counted loop must produce MIR values"
        );
    }

    use super::{
        dwarf_return_hint, dwarf_return_hint_with_env, dwarf_stack_object_hints,
        integer_widths_by_role, merge_dwarf_register_local_facts, merge_exact_definition_widths,
        refine_float_copy_types, refine_numbered_declaration, select_renderable_dwarf_local_facts,
        DwarfPrototypeContract,
    };
    use crate::debug::dwarf::{DwarfReturnType, DwarfStackBase, DwarfStackObject};
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::call_args::CallConv;
    use crate::ir::types::VReg;
    use crate::ir::types_recover::{TypeHint, TypeMap};
    use std::collections::HashMap;

    #[test]
    fn float_copy_refinement_terminates_when_the_join_declines_the_hint() {
        // `double total = ...; total += (double)step;` with a `float` term:
        // the destination already holds `Float{8}` and the source proposes
        // `Float{4}`, which `refine_from_value` is entitled to decline. The
        // fixed point must observe that the map did not move, not that its
        // proposal was not adopted — the latter never becomes false, which is
        // how `172_float_double_widths:gcc:O2:accumulate_wide` hung forever.
        let accumulator = VReg::phys("local_8");
        let mut types = TypeMap::default();
        types.upsert_public(accumulator.clone(), TypeHint::Float { width: 8 });
        let body = vec![Stmt::Assign {
            dst: accumulator.clone(),
            src: Expr::FloatConst { bits: 0, width: 4 },
        }];

        refine_float_copy_types(&body, &mut types);

        assert_eq!(types.get(&accumulator), Some(TypeHint::Float { width: 8 }));
    }

    #[test]
    fn float_copy_refinement_still_propagates_onto_an_untyped_slot() {
        let slot = VReg::phys("local_c");
        let source = VReg::phys("s0");
        let mut types = TypeMap::default();
        types.upsert_public(source.clone(), TypeHint::Float { width: 4 });
        let body = vec![Stmt::Assign {
            dst: slot.clone(),
            src: Expr::Reg(source),
        }];

        refine_float_copy_types(&body, &mut types);

        assert_eq!(types.get(&slot), Some(TypeHint::Float { width: 4 }));
    }

    #[test]
    fn source_local_rename_requires_a_renderable_authoritative_type() {
        use crate::debug::dwarf::{DwarfType, DwarfTypeKind};

        let dwarf_types = [DwarfType {
            kind: DwarfTypeKind::Typedef,
            name: "COLUMN".to_string(),
            byte_size: 0,
            fields: Vec::new(),
            variants: Vec::new(),
            typedef_target: Some("struct column".to_string()),
            source_file: Some("locals.c".to_string()),
        }];
        let local_types = HashMap::from([
            ("local_4".to_string(), "uch".to_string()),
            ("local_8".to_string(), "unsigned int".to_string()),
            ("local_10".to_string(), "COLUMN *".to_string()),
        ]);
        let local_names = HashMap::from([
            ("local_4".to_string(), "byte".to_string()),
            ("local_8".to_string(), "count".to_string()),
            ("local_10".to_string(), "column".to_string()),
        ]);

        let (selected_types, selected_names) =
            select_renderable_dwarf_local_facts(&local_types, &local_names, &dwarf_types);

        assert!(!selected_types.contains_key("local_4"));
        assert!(!selected_names.contains_key("local_4"));
        assert_eq!(
            selected_names.get("local_8").map(String::as_str),
            Some("count")
        );
        assert_eq!(
            selected_names.get("local_10").map(String::as_str),
            Some("column")
        );
    }

    #[test]
    fn semantic_value_widths_exclude_non_integer_kinds() {
        let mut widths = TypeMap::default();
        widths.upsert_public(
            VReg::phys("var0"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        widths.upsert_public(VReg::phys("var1"), TypeHint::Pointer { pointee_width: 8 });

        assert_eq!(
            integer_widths_by_role(&widths),
            HashMap::from([("var0".to_string(), 4)])
        );
    }

    #[test]
    fn later_subregister_definition_does_not_narrow_a_parameter_prototype() {
        let argument = VReg::phys("arg1");
        let mut types = TypeMap::default();
        types.upsert_public(
            argument.clone(),
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );
        let definition_widths = HashMap::from([(VReg::phys("esi"), 4)]);
        let role_names = HashMap::from([("esi".to_string(), "arg1".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::SysVAmd64,
        );

        assert_eq!(
            types.get(&argument),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    /// On x86-64 a 32-bit definition is a deliberate narrowing (`edi`, not
    /// `rdi`) and remains the -O0 type-recovery signal.
    #[test]
    fn a_narrowing_definition_still_types_a_local_on_a_sixty_four_bit_target() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        let definition_widths = HashMap::from([(VReg::phys("eax#1"), 4)]);
        let role_names = HashMap::from([("eax#1".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::SysVAmd64,
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn a_storage_width_does_not_overwrite_an_exact_pointer_role() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        types.upsert_public(role.clone(), TypeHint::Pointer { pointee_width: 4 });
        let definition_widths = HashMap::from([(VReg::phys("r3#2"), 4)]);
        let role_names = HashMap::from([("r3#2".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::ArmHardFloat,
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn numbered_integer_evidence_does_not_overwrite_a_proven_pointer() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        types.refine_from_value(role.clone(), TypeHint::Pointer { pointee_width: 4 });

        refine_numbered_declaration(
            &mut types,
            &role,
            &TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn numbered_register_width_does_not_retype_a_prepared_scalar_declaration() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        types.refine_from_value(
            role.clone(),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        refine_numbered_declaration(
            &mut types,
            &role,
            &TypeHint::Int {
                signed: true,
                width: 8,
            },
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    /// The same 4-byte definition on i386 is the WHOLE register — there is no
    /// wider spelling the compiler declined to use — so it proves nothing, and
    /// declaring the role `int` truncates any pointer that flows through it once
    /// the recovered C is rebuilt at the host pointer width.
    #[test]
    fn a_full_width_definition_is_not_int_evidence_on_a_thirty_two_bit_target() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        let definition_widths = HashMap::from([(VReg::phys("eax#1"), 4)]);
        let role_names = HashMap::from([("eax#1".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::Cdecl32,
        );

        assert_eq!(types.get(&role), None);
    }

    /// A byte-wide definition is a narrowing on every target, 32-bit included.
    #[test]
    fn a_sub_word_definition_is_still_evidence_on_a_thirty_two_bit_target() {
        let role = VReg::phys("var0");
        let mut types = TypeMap::default();
        let definition_widths = HashMap::from([(VReg::phys("al#1"), 1)]);
        let role_names = HashMap::from([("al#1".to_string(), "var0".to_string())]);

        merge_exact_definition_widths(
            &mut types,
            &definition_widths,
            &role_names,
            CallConv::Cdecl32,
        );

        assert_eq!(
            types.get(&role),
            Some(TypeHint::Int {
                signed: true,
                width: 1,
            })
        );
    }

    /// A four-byte frame slot on x86-64 is a genuine 32-bit local and keeps
    /// stating its width; the same slot on i386 is a machine word that a
    /// spilled pointer occupies just as readily.
    #[test]
    fn word_sized_frame_slots_only_declare_int_where_the_word_is_wider() {
        let slot = VReg::phys("local_c");
        let sizes = HashMap::from([("local_c".to_string(), 4u8)]);

        let mut sixty_four = TypeMap::default();
        super::merge_slot_sizes(&mut sixty_four, &sizes, CallConv::SysVAmd64);
        assert_eq!(
            sixty_four.get(&slot),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );

        let mut thirty_two = TypeMap::default();
        super::merge_slot_sizes(&mut thirty_two, &sizes, CallConv::Cdecl32);
        assert_eq!(thirty_two.get(&slot), None);

        // A byte-wide slot is narrower than the word on both.
        let narrow = HashMap::from([("local_1".to_string(), 1u8)]);
        let mut narrow_map = TypeMap::default();
        super::merge_slot_sizes(&mut narrow_map, &narrow, CallConv::Cdecl32);
        assert_eq!(
            narrow_map.get(&VReg::phys("local_1")),
            Some(TypeHint::Int {
                signed: true,
                width: 1,
            })
        );
    }

    #[test]
    fn machine_word_is_four_bytes_on_every_thirty_two_bit_convention() {
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Cdecl32), 4);
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Arm), 4);
        assert_eq!(
            crate::ir::abi::machine_word_bytes(CallConv::ArmHardFloat),
            4
        );
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::SysVAmd64), 8);
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Win64), 8);
        assert_eq!(crate::ir::abi::machine_word_bytes(CallConv::Aarch64), 8);
    }

    /// The ambiguity rule is applied where it has been MEASURED to pay, and only
    /// there. See `word_width_implies_int` for the armv7 evidence.
    #[test]
    fn word_width_stops_implying_int_only_on_cdecl32() {
        assert!(!super::word_width_implies_int(CallConv::Cdecl32));
        assert!(super::word_width_implies_int(CallConv::Arm));
        assert!(super::word_width_implies_int(CallConv::ArmHardFloat));
        assert!(super::word_width_implies_int(CallConv::SysVAmd64));
        assert!(super::word_width_implies_int(CallConv::Win64));
        assert!(super::word_width_implies_int(CallConv::Aarch64));
    }

    #[test]
    fn dwarf_long_return_width_follows_the_platform_data_model() {
        assert_eq!(
            dwarf_return_hint("long", CallConv::SysVAmd64),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
        assert_eq!(
            dwarf_return_hint("long", CallConv::Win64),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
        assert_eq!(
            dwarf_return_hint("unsigned long long", CallConv::Win64),
            Some(TypeHint::Int {
                signed: false,
                width: 8,
            })
        );
    }

    #[test]
    fn dwarf_named_pointer_return_is_locked_as_a_pointer() {
        assert_eq!(
            dwarf_return_hint("struct node *", CallConv::SysVAmd64),
            Some(TypeHint::Pointer { pointee_width: 1 })
        );
        assert_eq!(
            dwarf_return_hint("const unsigned int *", CallConv::SysVAmd64),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
    }

    #[test]
    fn dwarf_fixed_width_integer_aliases_keep_their_exact_widths() {
        assert_eq!(
            dwarf_return_hint("uint32_t", CallConv::SysVAmd64),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );
        assert_eq!(
            dwarf_return_hint("const int32_t *", CallConv::SysVAmd64),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert_eq!(
            dwarf_return_hint("int64_t", CallConv::Win64),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn dwarf_enum_typedef_keeps_its_measured_scalar_abi() {
        use crate::debug::dwarf::{DwarfEnumVariant, DwarfType, DwarfTypeKind};
        use crate::ir::dwarf_type_env::DwarfTypeEnv;

        let types = vec![
            DwarfType {
                kind: DwarfTypeKind::Typedef,
                name: "Status".to_string(),
                byte_size: 0,
                fields: Vec::new(),
                variants: Vec::new(),
                typedef_target: Some("enum Status_".to_string()),
                source_file: None,
            },
            DwarfType {
                kind: DwarfTypeKind::Enum,
                name: "Status_".to_string(),
                byte_size: 4,
                fields: Vec::new(),
                variants: vec![DwarfEnumVariant {
                    name: "ERROR".to_string(),
                    value: -1,
                }],
                typedef_target: None,
                source_file: None,
            },
        ];
        let env = DwarfTypeEnv::new(&types);

        assert_eq!(
            dwarf_return_hint_with_env("Status", CallConv::SysVAmd64, Some(&env)),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
    }

    #[test]
    fn dwarf_arm_frame_registers_map_to_stack_object_hints() {
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            register_locals: Vec::new(),
            stack_objects: vec![
                DwarfStackObject {
                    base: DwarfStackBase::Register(11),
                    offset: -24,
                    byte_size: 16,
                    aggregate: true,
                    source_name: None,
                    c_type: None,
                },
                DwarfStackObject {
                    base: DwarfStackBase::Register(7),
                    offset: -8,
                    byte_size: 8,
                    aggregate: true,
                    source_name: None,
                    c_type: None,
                },
            ],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Arm);

        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].base, "fp");
        assert_eq!(hints[0].disp, -24);
        assert_eq!(hints[0].size, 16);
        assert_eq!(hints[1].base, "fp");
        assert_eq!(hints[1].disp, -8);
        assert_eq!(hints[1].size, 8);
    }

    #[test]
    fn dwarf_aarch64_cfa_maps_to_the_entry_stack_coordinate() {
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -40,
                byte_size: 16,
                aggregate: true,
                source_name: None,
                c_type: None,
            }],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Aarch64);

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].base, "entry_sp");
        assert_eq!(hints[0].disp, -40);
        assert_eq!(hints[0].size, 16);
    }

    #[test]
    fn dwarf_arm_cfa_maps_to_the_entry_stack_coordinate() {
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -24,
                byte_size: 8,
                aggregate: true,
                source_name: None,
                c_type: None,
            }],
        };

        for cc in [CallConv::Arm, CallConv::ArmHardFloat] {
            let hints = dwarf_stack_object_hints(Some(&contract), cc);

            assert_eq!(hints.len(), 1);
            assert_eq!(hints[0].base, "entry_sp");
            assert_eq!(hints[0].disp, -24);
            assert_eq!(hints[0].size, 8);
        }
    }

    #[test]
    fn dwarf_scalar_stack_objects_retain_their_authoritative_coordinate() {
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            register_locals: Vec::new(),
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -12,
                byte_size: 4,
                aggregate: false,
                source_name: Some("reg32".to_string()),
                c_type: Some("int".to_string()),
            }],
        };

        let hints = dwarf_stack_object_hints(Some(&contract), CallConv::Arm);

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].base, "entry_sp");
        assert_eq!(hints[0].disp, -12);
        assert_eq!(hints[0].size, 4);
        assert!(!hints[0].aggregate);
        assert_eq!(hints[0].source_name.as_deref(), Some("reg32"));
        assert_eq!(hints[0].c_type.as_deref(), Some("int"));
    }

    #[test]
    fn dwarf_register_range_selects_the_numbered_value_role() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "i".to_string(),
                c_type: "unsigned int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x105,
                    end: 0x110,
                    register: 4,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x108,
                    op: Op::Assign {
                        dst: VReg::phys("r0#1"),
                        src: Value::Reg(VReg::phys("r4#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &std::collections::HashMap::from([("r4#1".to_string(), "var1".to_string())]),
            Arch::ARM,
            crate::ir::call_args::CallConv::Arm,
            None,
        );

        assert_eq!(
            facts.source_names.get("var1").map(String::as_str),
            Some("i")
        );
        assert_eq!(
            facts.source_types.get("var1").map(String::as_str),
            Some("unsigned int")
        );
    }

    #[test]
    fn dwarf_register_family_with_reused_role_becomes_declaration_only() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "i".to_string(),
                c_type: "int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x100,
                    end: 0x110,
                    register: 0,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x80,
            blocks: vec![LlirBlock {
                start_va: 0x80,
                end_va: 0x110,
                instrs: vec![
                    LlirInstr {
                        va: 0x90,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#1"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x104,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#3"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x108,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#2"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([
            ("rax#1".to_string(), "ret".to_string()),
            ("rax#2".to_string(), "var4".to_string()),
        ]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert!(facts.source_names.is_empty());
        assert_eq!(facts.source_types.get("i").map(String::as_str), Some("int"));
    }

    /// One machine value serving two source locals of different widths must be
    /// declared at the WIDER one. gcc `-O2` does exactly this for
    /// `dp190_mul_both_halves`: `product` (uint64_t) and `low` (uint32_t) both
    /// live in `rsi` over the same range because `low` is `product`'s
    /// truncation. Binding the narrow claimant makes `product >> 32`
    /// identically zero, so the high half of the widening multiply is lost.
    /// Declaration order is not evidence, and the loser here is deliberately
    /// listed FIRST so the test fails against first-claimant-wins.
    #[test]
    fn dwarf_register_widest_claimant_owns_a_shared_recovered_value() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let at_rsi = |name: &str, c_type: &str| DwarfRegisterLocal {
            source_name: name.to_string(),
            c_type: c_type.to_string(),
            locations: vec![DwarfRegisterLocation {
                start: 0x100,
                end: 0x110,
                register: 4,
            }],
        };
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![at_rsi("low", "uint32_t"), at_rsi("product", "uint64_t")],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x104,
                    op: Op::Assign {
                        dst: VReg::phys("rax#1"),
                        src: Value::Reg(VReg::phys("rsi#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([("rsi#1".to_string(), "var2".to_string())]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert_eq!(
            facts.source_names.get("var2").map(String::as_str),
            Some("product")
        );
        assert_eq!(
            facts.source_types.get("var2").map(String::as_str),
            Some("uint64_t")
        );
    }

    /// Equal widths carry no preference, so the established order still decides
    /// and the rule above must not fire.
    #[test]
    fn dwarf_register_equal_width_claimants_keep_the_established_order() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let at_rsi = |name: &str| DwarfRegisterLocal {
            source_name: name.to_string(),
            c_type: "uint32_t".to_string(),
            locations: vec![DwarfRegisterLocation {
                start: 0x100,
                end: 0x110,
                register: 4,
            }],
        };
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![at_rsi("first"), at_rsi("second")],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x104,
                    op: Op::Assign {
                        dst: VReg::phys("rax#1"),
                        src: Value::Reg(VReg::phys("rsi#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([("rsi#1".to_string(), "var2".to_string())]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert_eq!(
            facts.source_names.get("var2").map(String::as_str),
            Some("first")
        );
    }

    #[test]
    fn dwarf_register_unique_winner_survives_a_reused_sibling_role() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "i".to_string(),
                c_type: "int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x100,
                    end: 0x110,
                    register: 0,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x80,
            blocks: vec![LlirBlock {
                start_va: 0x80,
                end_va: 0x110,
                instrs: vec![
                    LlirInstr {
                        va: 0x90,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#1"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x104,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#2"),
                            src: Value::Reg(VReg::phys("rax#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x108,
                        op: Op::Bin {
                            dst: VReg::phys("rcx#3"),
                            op: crate::ir::types::BinOp::Add,
                            lhs: Value::Reg(VReg::phys("rax#2")),
                            rhs: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                    LlirInstr {
                        va: 0x10c,
                        op: Op::Assign {
                            dst: VReg::phys("rcx#4"),
                            src: Value::Reg(VReg::phys("rax#2")),
                        },
                    },
                ],
                succs: Vec::new(),
            }],
        };
        let roles = std::collections::HashMap::from([
            ("rax#1".to_string(), "ret".to_string()),
            ("rax#2".to_string(), "var4".to_string()),
        ]);
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &roles,
            Arch::X86_64,
            crate::ir::call_args::CallConv::SysVAmd64,
            None,
        );

        assert_eq!(
            facts.source_names.get("var4").map(String::as_str),
            Some("i")
        );
        assert_eq!(
            facts.source_types.get("var4").map(String::as_str),
            Some("int")
        );
    }

    #[test]
    fn dwarf_register_name_rejects_a_role_used_outside_the_source_lifetime() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "result".to_string(),
                c_type: "struct sensor *".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x105,
                    end: 0x110,
                    register: 4,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x80,
            blocks: vec![LlirBlock {
                start_va: 0x80,
                end_va: 0x110,
                instrs: vec![
                    LlirInstr {
                        va: 0x90,
                        op: Op::Assign {
                            dst: VReg::phys("r0#1"),
                            src: Value::Reg(VReg::phys("r4#1")),
                        },
                    },
                    LlirInstr {
                        va: 0x108,
                        op: Op::Assign {
                            dst: VReg::phys("r1#1"),
                            src: Value::Reg(VReg::phys("r4#1")),
                        },
                    },
                ],
                succs: Vec::new(),
            }],
        };
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &std::collections::HashMap::from([("r4#1".to_string(), "var1".to_string())]),
            Arch::ARM,
            crate::ir::call_args::CallConv::Arm,
            None,
        );

        assert!(facts.source_names.is_empty());
        assert!(facts.source_types.is_empty());
    }

    #[test]
    fn dwarf_register_name_rejects_an_unsafe_source_identifier() {
        use crate::core::binary::Arch;
        use crate::debug::dwarf::{DwarfRegisterLocal, DwarfRegisterLocation};
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: Vec::new(),
            register_locals: vec![DwarfRegisterLocal {
                source_name: "return".to_string(),
                c_type: "int".to_string(),
                locations: vec![DwarfRegisterLocation {
                    start: 0x100,
                    end: 0x110,
                    register: 4,
                }],
            }],
        };
        let numbered = LlirFunction {
            entry_va: 0x100,
            blocks: vec![LlirBlock {
                start_va: 0x100,
                end_va: 0x110,
                instrs: vec![LlirInstr {
                    va: 0x108,
                    op: Op::Assign {
                        dst: VReg::phys("r0#1"),
                        src: Value::Reg(VReg::phys("r4#1")),
                    },
                }],
                succs: Vec::new(),
            }],
        };
        let mut facts = crate::ir::stack_locals::StackLocalFacts::default();

        merge_dwarf_register_local_facts(
            &mut facts,
            Some(&contract),
            &numbered,
            &std::collections::HashMap::from([("r4#1".to_string(), "var1".to_string())]),
            Arch::ARM,
            crate::ir::call_args::CallConv::Arm,
            None,
        );

        assert!(facts.source_names.is_empty());
        assert!(facts.source_types.is_empty());
    }
}
