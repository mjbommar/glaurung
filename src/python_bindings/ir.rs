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

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::ir::abi::machine_word_bytes;
use crate::ir::types::{BinOp, CallTarget, CmpOp, Flag, LlirInstr, MemOp, Op, UnOp, VReg, Value};
use crate::ir::{lift_arm64, lift_x86};

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
fn run_ast_passes(
    f: &mut crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
    prototype: Option<&crate::ir::types_recover::RecoveredPrototype>,
    param_slots: &mut std::collections::HashSet<usize>,
    locked_parameter_count: Option<usize>,
    callee_facts: &DirectCalleeFacts,
    addr_map: &std::collections::HashMap<u64, String>,
    str_pool: &std::collections::HashMap<u64, String>,
    function_tables: &[crate::ir::function_tables::FunctionPointerTable],
    stack_object_hints: &[crate::ir::stack_locals::StackObjectHint],
) -> (
    std::collections::HashMap<String, u8>,
    std::collections::HashMap<String, String>,
) {
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    let output_kind = prototype.map_or(
        crate::ir::types_recover::RecoveredOutputKind::Unknown,
        crate::ir::types_recover::RecoveredPrototype::output_kind,
    );
    let parameter_roles = prototype
        .map(crate::ir::types_recover::RecoveredPrototype::parameter_role_map)
        .unwrap_or_default();
    if dump {
        eprintln!(
            "\n===== parameter evidence =====\nslots={param_slots:?}\nroles={parameter_roles:?}"
        );
        eprintln!("\n===== stack object hints =====\n{stack_object_hints:#?}");
    }
    macro_rules! dp {
        ($n:expr) => {
            if dump {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(f));
            }
        };
    }
    // Packed XMM moves use four scalar lane operations so arithmetic remains
    // analyzable.  Rejoin an untouched four-lane load/store pair before copy
    // propagation erases the common 16-byte transport identity.
    crate::ir::vector_copy::recover_wide_copies(f);
    dp!("recover_wide_copies");
    crate::ir::expr_reconstruct::reconstruct(f);
    dp!("reconstruct");
    crate::ir::const_fold::fold_constants(f);
    dp!("fold_constants");
    crate::ir::select_fold::fold_boolean_masks(f);
    dp!("fold_boolean_masks");
    // Per-definition first: it removes writes an unread overwrite supersedes, which the
    // per-name pass below cannot see (flags are un-versioned, so one read keeps every
    // write of that name alive).
    crate::ir::dce::prune_overwritten_flags(f);
    crate::ir::dce::prune_dead_flags(f);
    dp!("prune_dead_flags");
    // A direct jump into a PLT stub lowers to that stub's terminal GOT
    // dereference. Resolve the slot before argument reconstruction, then recover
    // only symbol-backed terminal jumps as tail calls so the ordinary call pass
    // can see their argument-register setup and returned value.
    crate::ir::name_resolve::resolve_names(f, addr_map);
    crate::ir::function_tables::resolve_function_table_entries(f, function_tables);
    crate::ir::call_args::recover_resolved_direct_tail_calls(f, cc, addr_map);
    crate::ir::call_args::recover_resolved_tail_calls(f, cc);
    dp!("recover_resolved_tail_calls");
    crate::ir::call_args::reconstruct_args_with_params_and_callee_layouts(
        f,
        cc,
        param_slots,
        &callee_facts.layouts,
    );
    dp!("reconstruct_args");
    crate::ir::call_contracts::apply_recovered_callee_prototypes(f, &callee_facts.prototypes);
    // ABI liveness supplies candidate call inputs/outputs; an authoritative
    // library prototype wins when one is known. This mirrors Ghidra's locked
    // FuncProto and angr's callee-prototype priority rather than asking the C
    // renderer to paper over a semantically impossible AST result.
    crate::ir::call_contracts::apply_known_call_contracts(f);
    dp!("apply_known_call_contracts");
    crate::ir::call_result_split::split_call_result_lifetimes(f, cc);
    dp!("split_call_result_lifetimes");
    crate::ir::strings_fold::fold_string_literals(f, str_pool);
    crate::ir::canary::recognise_canary(f);
    dp!("canary+strings");
    // Stack-slot promotion runs before register renaming so the aliases (`stack_0`,
    // `local_0`, ...) it allocates cannot collide with the role names (`arg0`, `ret`,
    // `varN`) the naming pass introduces.
    let slot_sizes =
        crate::ir::stack_locals::promote_stack_locals_typed_with_parameter_count_and_objects(
            f,
            Some(cc),
            locked_parameter_count,
            stack_object_hints,
        );
    dp!("promote_stack_locals");
    // Frame-relative storage is source-level state; the push/mov/sub sequence
    // that establishes its machine frame is not.  Recognise the machine prologue
    // here, while stack promotion has made the storage identities explicit but
    // before dead-store elimination removes the now-unused `rbp = rsp` witness.
    // A second call after the remaining passes still handles epilogues exposed
    // by stack-op rematerialisation.
    recognise_machine_frame(f, cc);
    dp!("recognise_machine_frame");
    // Project a prototype-proven result while the raw ABI output register is
    // still present. ARM32/AArch64 reuse arg0's register for the result; the
    // following spill-role split must rename both its final definition and the
    // return use together, rather than orphaning the result as scratch.
    if output_kind == crate::ir::types_recover::RecoveredOutputKind::Direct {
        crate::ir::direct_output::materialize_prototype_output(f, cc, prototype);
    }
    dp!("materialize_direct_output");
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
    crate::ir::value_split::split_argument_storage_reuse(f, cc, split_unspilled_dual_role);
    dp!("split_argument_storage_reuse");
    let role_names = crate::ir::naming::apply_role_names_with_parameter_roles(
        f,
        cc,
        param_slots,
        &parameter_roles,
    );
    dp!("apply_role_names");
    crate::ir::canary::collapse_canary_save(f);
    if matches!(cc, crate::ir::call_args::CallConv::Aarch64) {
        crate::ir::arm64_prologue::recognise_arm64_prologue(f);
    }
    // Dead-store elimination runs *after* naming so it sees the aliased return register
    // (`ret` / `arg0`) rather than the raw physical one; that removes the common pre-call
    // `%ret = 0` idiom entirely.
    crate::ir::dead_stores::eliminate_dead_stores(f, cc);
    dp!("eliminate_dead_stores");
    crate::ir::stack_idiom::rematerialise_stack_ops(f);
    crate::ir::label_prune::prune_unreferenced_labels(f);
    dp!("stack_idiom+label_prune");
    (slot_sizes, role_names)
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
    crate::ir::dead_stores::prune_callee_saved_spills(f);
}

fn lift_for_arch(data: &[u8], start_va: u64, bits: u32, arch: &str) -> PyResult<Vec<LlirInstr>> {
    let a = arch.to_ascii_lowercase();
    match a.as_str() {
        "x86" => Ok(lift_x86::lift_bytes(data, start_va, 32)),
        "x86_64" | "x64" | "amd64" => Ok(lift_x86::lift_bytes(data, start_va, 64)),
        "arm64" | "aarch64" => Ok(lift_arm64::lift_bytes(data, start_va)),
        // If arch was omitted, fall back to bits= for x86 back-compat.
        "" => {
            if bits != 32 && bits != 64 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "bits must be 32 or 64 when arch is omitted",
                ));
            }
            Ok(lift_x86::lift_bytes(data, start_va, bits))
        }
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unsupported arch: {arch}"
        ))),
    }
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
    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let foff =
        crate::analysis::entry::va_to_code_file_offset(&data, start_va).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("no mapping for VA 0x{:x}", start_va))
        })?;
    let end = foff.saturating_add(window_bytes).min(data.len());
    lift_bytes_py(py, &data[foff..end], start_va, bits, arch)
}

fn detect_arch_and_call_conv(
    data: &[u8],
) -> (crate::core::binary::Arch, crate::ir::call_args::CallConv) {
    use crate::core::binary::Arch as BArch;

    let mut is_pe = false;
    let arch = if let Ok(obj) = object::read::File::parse(data) {
        use object::Object;
        is_pe = obj.format() == object::BinaryFormat::Pe;
        match obj.architecture() {
            object::Architecture::I386 => BArch::X86,
            object::Architecture::X86_64 => BArch::X86_64,
            object::Architecture::Aarch64 => BArch::AArch64,
            object::Architecture::Arm => BArch::ARM,
            _ => BArch::X86_64,
        }
    } else {
        BArch::X86_64
    };

    let cc = match (arch, is_pe) {
        (BArch::AArch64, _) => crate::ir::call_args::CallConv::Aarch64,
        (BArch::ARM, _) if arm_uses_vfp_arguments(data) => {
            crate::ir::call_args::CallConv::ArmHardFloat
        }
        (BArch::ARM, _) => crate::ir::call_args::CallConv::Arm,
        (BArch::X86, _) => crate::ir::call_args::CallConv::Cdecl32,
        (BArch::X86_64, true) => crate::ir::call_args::CallConv::Win64,
        _ => crate::ir::call_args::CallConv::SysVAmd64,
    };
    (arch, cc)
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
    numbered: crate::ir::types::LlirFunction,
    definition_widths: std::collections::HashMap<crate::ir::types::VReg, u8>,
    parameter_slots: std::collections::HashSet<usize>,
    prototype: Option<crate::ir::types_recover::RecoveredPrototype>,
}

fn prepare_llir_for_lowering(
    function: &mut crate::ir::types::LlirFunction,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    cc: crate::ir::call_args::CallConv,
    recover_semantic_prototype: bool,
    arm_vfp_args: bool,
    declared: Option<&DwarfPrototypeContract>,
) -> PreparedLlir {
    let mut ssa = normalize_definedness_and_compute_ssa(function, exception_sites, cc);
    let provisional_slots = if recover_semantic_prototype {
        crate::ir::value_number::value_number_with_parameter_slots(function, &ssa, cc).2
    } else {
        crate::ir::value_number::live_in_arg_slots_llir(function, cc)
    };
    let prototype = recover_semantic_prototype.then(|| {
        recover_decbench_prototype(
            function,
            &ssa,
            cc,
            &provisional_slots,
            arm_vfp_args,
            declared,
        )
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
    let region = crate::ir::structure::recover_verified(function, &ssa);
    let (numbered, definition_widths, mut parameter_slots) = if recover_semantic_prototype {
        crate::ir::value_number::value_number_with_parameter_slots(function, &ssa, cc)
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
    }
    lock_parameter_slots_from_prototype(prototype.as_ref(), &mut parameter_slots);
    PreparedLlir {
        region,
        numbered,
        definition_widths,
        parameter_slots,
        prototype,
    }
}

fn arm_uses_vfp_arguments(data: &[u8]) -> bool {
    use object::Object;

    let Ok(file) = object::read::File::parse(data) else {
        return false;
    };
    if file.architecture() != object::Architecture::Arm {
        return false;
    }
    matches!(
        file.flags(),
        object::FileFlags::Elf { e_flags, .. }
            if e_flags & object::elf::EF_ARM_ABI_FLOAT_HARD != 0
    )
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
    use crate::analysis::cfg::{analyze_functions_bytes_with_seeds, Budgets};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::types_recover::recover_types_for;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    // An ARM32 Thumb symbol's value carries the Thumb bit; the entry it denotes
    // is one lower. Anything resolving a callee through `.symtab` hands us that
    // value verbatim, and decoding one byte in recovers a body with no
    // parameters at all. See `arm32_mode::normalise_entry`.
    let func_va = crate::analysis::arm32_mode::normalise_entry(&data, func_va);
    let exception_sites = crate::analysis::exception::extract_exception_call_sites(&data);
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&data));
    let dwarf_types =
        (style == "decbench" && types).then(|| crate::debug::dwarf::extract_dwarf_types(&data));
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
    let (funcs, _cg) =
        py.detach(|| analyze_functions_bytes_with_seeds(&data, &budgets, &[func_va]));
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
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let arm_vfp_args = arm_uses_vfp_arguments(&data);
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
    let lf_raw = lift_function_from_bytes(&data, &func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("LLIR lifter does not support this architecture")
    })?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
    crate::ir::abi::annotate_calls(&mut lf_raw, cc);
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
        &exception_sites,
        cc,
        style == "decbench" && types,
        arm_vfp_args,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
    );
    let PreparedLlir {
        region,
        numbered: lf,
        definition_widths,
        parameter_slots: mut param_slots,
        prototype,
    } = prepared_llir;
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== recovered prototype =====\n{prototype:#?}");
    }
    let mut callee_layout_cache = std::collections::HashMap::new();
    let callee_facts = recover_direct_callee_layouts(
        &data,
        &funcs,
        &lf_raw,
        arch,
        cc,
        arm_vfp_args,
        &budgets,
        dwarf_outputs.as_ref(),
        &mut addr_map,
        &mut callee_layout_cache,
    );
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
    let mut f = lower(&lf, &region, outer_name);
    crate::ir::exception_recover::mark_landing_pads(&mut f, &exception_sites);
    // Pass-by-pass AST dump for debugging the decbench lowering pipeline. Set
    // GLAURUNG_DUMP_PASSES=1 to print the rendered body after each pass to stderr
    // (bisect which pass corrupts a function). No-op otherwise.
    let dump_passes = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    macro_rules! dp {
        ($n:expr) => {
            if dump_passes {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(&f));
            }
        };
    }
    dp!("lower");
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let readonly_data = crate::ir::readonly_fold::collect_readonly_data(&data);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    let stack_object_hints = dwarf_stack_object_hints(
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        cc,
    );
    let (slot_sizes, role_names) = run_ast_passes(
        &mut f,
        cc,
        prototype.as_ref(),
        &mut param_slots,
        locked_parameter_count(prototype.as_ref()),
        &callee_facts,
        &addr_map,
        &str_pool,
        &function_tables,
        &stack_object_hints,
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
                &slot_sizes,
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
            &exception_sites,
            decl,
            width,
            exact_value_widths,
            &readonly_data,
            prototype.as_ref().map_or(
                crate::ir::types_recover::RecoveredOutputKind::Unknown,
                |p| p.output_kind(),
            ),
            declared_render.as_ref(),
            dwarf_types.as_deref().unwrap_or(&[]),
            cc,
            &addr_map,
        )
    } else if style == "c" {
        let body = crate::ir::ast::render_c(&f);
        match pdb_outer_name {
            Some(name) => format!("// PDB: {}\n{}", name, body),
            None => body,
        }
    } else if types {
        // Plain-with-types style. Non-decbench paths skip `value_number`, so the
        // raw LLIR is the canonical one; remap the TypeMap keys from raw physical
        // regs into the role-based names the AST now uses.
        let renamed = remap_type_map(&recover_types_for(&lf_raw, cc), &f, cc, &param_slots);
        render_with_types(&f, &renamed)
    } else {
        render(&f)
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
    use crate::core::address::{Address, AddressKind};
    use crate::core::address_range::AddressRange;
    use crate::core::basic_block::BasicBlock;
    use crate::core::function::{Function, FunctionKind};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_bytes;
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

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let exception_sites = crate::analysis::exception::extract_exception_call_sites(&data);
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&data));
    let dwarf_types =
        (style == "decbench" && types).then(|| crate::debug::dwarf::extract_dwarf_types(&data));
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let arm_vfp_args = arm_uses_vfp_arguments(&data);
    let bits = match arch {
        crate::core::binary::Arch::X86 | crate::core::binary::Arch::ARM => 32,
        crate::core::binary::Arch::X86_64 | crate::core::binary::Arch::AArch64 => 64,
        _ => 64,
    };
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
    let lf_raw = lift_function_from_bytes(&data, &func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("LLIR lifter does not support this architecture")
    })?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
    crate::ir::abi::annotate_calls(&mut lf_raw, cc);
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    let prepared_llir = prepare_llir_for_lowering(
        &mut lf_raw,
        &exception_sites,
        cc,
        style == "decbench" && types,
        arm_vfp_args,
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
    );
    let PreparedLlir {
        region,
        numbered: lf,
        definition_widths,
        parameter_slots: mut param_slots,
        prototype,
    } = prepared_llir;
    let mut f = lower(&lf, &region, func.name.clone());
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
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let readonly_data = crate::ir::readonly_fold::collect_readonly_data(&data);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    let stack_object_hints = dwarf_stack_object_hints(
        dwarf_outputs
            .as_ref()
            .and_then(|outputs| outputs.get(&func_va)),
        cc,
    );
    let (slot_sizes, role_names) = run_ast_passes(
        &mut f,
        cc,
        prototype.as_ref(),
        &mut param_slots,
        locked_parameter_count(prototype.as_ref()),
        &callee_facts,
        &addr_map,
        &str_pool,
        &function_tables,
        &stack_object_hints,
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
                &slot_sizes,
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
            &exception_sites,
            decl,
            width,
            exact_value_widths,
            &readonly_data,
            prototype.as_ref().map_or(
                crate::ir::types_recover::RecoveredOutputKind::Unknown,
                |p| p.output_kind(),
            ),
            declared_render.as_ref(),
            dwarf_types.as_deref().unwrap_or(&[]),
            cc,
            &addr_map,
        )
    } else if style == "c" {
        crate::ir::ast::render_c(&f)
    } else if types {
        let renamed = remap_type_map(&recover_types_for(&lf_raw, cc), &f, cc, &param_slots);
        render_with_types(&f, &renamed)
    } else {
        render(&f)
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
/// 3. [`crate::ir::verify_defs::check`] verifies the result — the AST that is
///    about to be printed, which is what makes the check trustworthy;
/// 4. the renderer formats it, and nothing else.
///
/// Violations are reported as `// glaurung-verify:` comment lines ahead of the
/// code. They are comments, so the emitted C is unchanged for recompilation, and
/// the structural lane records them per function against a committed baseline —
/// known ones stay visible, a new one fails the gate. Reporting rather than
/// erroring is deliberate: a violation means the decompilation of THAT function is
/// untrustworthy, not that the analyst's whole run should fail.
///
/// The type maps are computed by the caller from the UNPREPARED function, whose
/// names the recovered `TypeMap` keys were remapped against.
fn decbench_text(
    f: &crate::ir::ast::Function,
    exception_sites: &[crate::analysis::exception::ExceptionCallSite],
    decl: Option<&crate::ir::types_recover::TypeMap>,
    width: Option<&crate::ir::types_recover::TypeMap>,
    exact_value_widths: Option<&std::collections::HashMap<String, u8>>,
    readonly_data: &crate::ir::readonly_fold::ReadonlyData,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    declared_prototype: Option<&crate::ir::call_contracts::CallPrototype>,
    dwarf_types: &[crate::debug::dwarf::DwarfType],
    cc: crate::ir::call_args::CallConv,
    addr_map: &std::collections::HashMap<u64, String>,
) -> String {
    let mut prepared = crate::ir::ast::prepare_for_decbench_with_output(f, output_kind);
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
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "\n===== after prepare_for_decbench =====\n{}",
            crate::ir::ast::render(&prepared)
        );
    }
    // Preparation exposes the actual expression dataflow (notably parameter
    // spill coalescing and folded returns), so only now can high-half uses and
    // wide return definitions safely override a misleading narrow sub-register
    // type hint.
    let mut refined_decl = decl.cloned();
    let mut refined_width = width.cloned();
    if let Some(tm) = refined_decl.as_mut() {
        crate::ir::ast::refine_decbench_abi_widths_with_value_widths(
            &prepared,
            tm,
            exact_value_widths,
        );
        crate::ir::high_variables::refine_pointer_high_variables(&prepared, tm);
    }
    if let Some(tm) = refined_width.as_mut() {
        crate::ir::ast::refine_decbench_abi_widths_with_value_widths(
            &prepared,
            tm,
            exact_value_widths,
        );
    }
    if let Some(tm) = refined_decl.as_ref() {
        crate::ir::copy_prop::propagate_adjacent_typed_promoted_values(&mut prepared, tm);
        crate::ir::const_fold::fold_typed_declared_views(&mut prepared, tm);
        crate::ir::typed_simplify::fold_consumed_extensions(&mut prepared, tm);
        crate::ir::const_fold::fold_typed_comparison_extensions(&mut prepared, tm);
        crate::ir::const_fold::fold_constants(&mut prepared);
    }
    crate::ir::readonly_fold::fold_guarded_readonly_lookups(&mut prepared, readonly_data);
    // Read-only folding can turn an image load into a literal after the main
    // expression pipeline has already run. Re-propagate and fold immediately so
    // consumers such as packed byte-table permutations see the literal index
    // rather than rendering a dynamic 16-way lookup for a compiler-emitted mask.
    crate::ir::copy_prop::propagate_copies(&mut prepared);
    crate::ir::const_fold::fold_constants(&mut prepared);
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!(
            "\n===== after fold_guarded_readonly_lookups =====\n{}",
            crate::ir::ast::render(&prepared)
        );
    }
    if let Some(tm) = refined_decl.as_ref() {
        crate::ir::guarded_switch::collapse_range_guards_with_types(&mut prepared, tm);
    }
    // A typed range proof may have synthesized an exhaustive switch default,
    // exposing the same exact switch-result join as the untyped preparation
    // path. Fold it before verification and rendering as well.
    crate::ir::ast::fold_exhaustive_switch_returns(&mut prepared);
    let decl = refined_decl.as_ref();
    let width = refined_width.as_ref();
    if let Some(tm) = decl {
        crate::ir::ast::fold_typed_return_abi_extensions(&mut prepared, tm);
    }
    // Declarations are recovered at true machine width, so a value read in a wider
    // context needs the extension the hardware performed made explicit. Runs before
    // verification and rendering; it changes no definition, use, or value identity.
    if let Some(tm) = decl {
        crate::ir::widen::insert_widening_casts_for_machine_width(
            &mut prepared,
            tm,
            machine_word_bytes(cc),
        );
    }
    // Call specifications belong to concrete AST calls, not to renderer-local
    // symbol guesses. Refresh them after every expression/type refinement so
    // string folding, promoted objects, and pointer facts are represented on
    // the exact call boundary the verifier and C renderer consume.
    crate::ir::call_contracts::refine_call_site_specs(&mut prepared, decl);
    let dwarf_pointer_types = crate::ir::dwarf_fields::annotate_function_fields(
        &mut prepared,
        declared_prototype,
        dwarf_types,
        calling_convention_pointer_width(cc),
    );
    crate::ir::exception_recover::recover_typed_handlers(&mut prepared, exception_sites);
    crate::ir::exception_recover::recover_throws(&mut prepared);
    let violations = crate::ir::verify_defs::check(&prepared);
    let body = crate::ir::ast::render_decbench_typed_with_output_and_prototype_and_dwarf_types(
        &prepared,
        decl,
        width,
        output_kind,
        declared_prototype,
        dwarf_types,
        calling_convention_pointer_width(cc),
        &dwarf_pointer_types,
    );
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

/// Index authoritative DWARF prototype contracts once per binary analysis.
///
/// Batch decompilation must not reparse debug sections for every function.
/// The CFG analyser already consumes DWARF for boundaries and names; this
/// compact companion map carries parameter and output facts to typed recovery.
#[derive(Debug, Clone)]
struct DwarfPrototypeContract {
    /// Whether the producer marked this as a complete function prototype.
    /// This distinguishes `f(void)` from an old-style `f()` when both have no
    /// formal-parameter DIEs.
    prototyped: bool,
    parameter_types: Vec<crate::debug::dwarf::DwarfParameterType>,
    return_type: crate::debug::dwarf::DwarfReturnType,
    stack_objects: Vec<crate::debug::dwarf::DwarfStackObject>,
}

fn dwarf_output_contracts(data: &[u8]) -> std::collections::HashMap<u64, DwarfPrototypeContract> {
    crate::debug::dwarf::extract_dwarf_functions(data)
        .into_iter()
        .map(|function| {
            (
                function.entry_va,
                DwarfPrototypeContract {
                    prototyped: function.prototyped,
                    parameter_types: function.parameter_types,
                    return_type: function.return_type,
                    stack_objects: function.stack_objects,
                },
            )
        })
        .collect()
}

fn dwarf_stack_object_hints(
    contract: Option<&DwarfPrototypeContract>,
    cc: crate::ir::call_args::CallConv,
) -> Vec<crate::ir::stack_locals::StackObjectHint> {
    use crate::debug::dwarf::DwarfStackBase;
    use crate::ir::call_args::CallConv;

    let Some(contract) = contract else {
        return Vec::new();
    };
    contract
        .stack_objects
        .iter()
        .filter(|object| object.aggregate)
        .filter_map(|object| {
            let (base, adjustment) = match (cc, object.base) {
                (CallConv::SysVAmd64 | CallConv::Win64, DwarfStackBase::Register(6)) => ("rbp", 0),
                (CallConv::SysVAmd64 | CallConv::Win64, DwarfStackBase::CallFrameCfa) => {
                    ("rbp", 16)
                }
                (CallConv::Cdecl32, DwarfStackBase::Register(5)) => ("ebp", 0),
                (CallConv::Cdecl32, DwarfStackBase::CallFrameCfa) => ("ebp", 8),
                (CallConv::Aarch64, DwarfStackBase::Register(29)) => ("x29", 0),
                // DW_OP_fbreg is relative to the call-frame address, which is
                // the architectural entry SP. The stack-local pass retains
                // this coordinate for proven aggregates and reconciles it with
                // the current-SP delta without globally rebasing AArch64's
                // ordinary own-frame slots.
                (CallConv::Aarch64, DwarfStackBase::CallFrameCfa) => ("entry_sp", 0),
                (CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::Register(11 | 7)) => {
                    ("fp", 0)
                }
                (CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::CallFrameCfa) => {
                    ("entry_sp", 0)
                }
                _ => return None,
            };
            Some(crate::ir::stack_locals::StackObjectHint {
                base: base.to_string(),
                disp: object.offset.checked_add(adjustment)?,
                size: object.byte_size,
            })
        })
        .collect()
}

fn calling_convention_pointer_width(cc: crate::ir::call_args::CallConv) -> u8 {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => 4,
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Aarch64 => 8,
    }
}

/// Translate only DWARF scalar spellings that the current renderer can express
/// exactly. An unrepresentable declared type still locks the output as non-void;
/// it simply leaves machine-code recovery responsible for the concrete C type.
fn dwarf_return_hint(
    c_type: &str,
    cc: crate::ir::call_args::CallConv,
) -> Option<crate::ir::types_recover::TypeHint> {
    use crate::ir::types_recover::TypeHint;

    let normalized = c_type
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>()
        .join(" ");
    let c_long_width = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Aarch64 => 8,
        crate::ir::call_args::CallConv::Win64
        | crate::ir::call_args::CallConv::Cdecl32
        | crate::ir::call_args::CallConv::Arm
        | crate::ir::call_args::CallConv::ArmHardFloat => 4,
    };
    if let Some(pointee) = normalized.strip_suffix('*').map(str::trim) {
        let pointee_width = match dwarf_return_hint(pointee, cc) {
            Some(TypeHint::Int { width, .. } | TypeHint::Float { width }) => width,
            Some(TypeHint::BoolLike) => 1,
            Some(TypeHint::Pointer { .. } | TypeHint::CodePointer) => c_long_width,
            None => 1,
        };
        return Some(TypeHint::Pointer { pointee_width });
    }
    match normalized.as_str() {
        "_Bool" | "bool" => Some(TypeHint::BoolLike),
        "char" | "signed char" | "int8_t" => Some(TypeHint::Int {
            signed: true,
            width: 1,
        }),
        "unsigned char" | "uint8_t" => Some(TypeHint::Int {
            signed: false,
            width: 1,
        }),
        "short" | "short int" | "signed short" | "signed short int" | "int16_t" => {
            Some(TypeHint::Int {
                signed: true,
                width: 2,
            })
        }
        "unsigned short" | "unsigned short int" | "uint16_t" => Some(TypeHint::Int {
            signed: false,
            width: 2,
        }),
        "int" | "signed" | "signed int" | "int32_t" => Some(TypeHint::Int {
            signed: true,
            width: 4,
        }),
        "unsigned" | "unsigned int" | "uint32_t" => Some(TypeHint::Int {
            signed: false,
            width: 4,
        }),
        "long" | "long int" | "signed long" | "signed long int" => Some(TypeHint::Int {
            signed: true,
            width: c_long_width,
        }),
        "unsigned long" | "unsigned long int" | "long unsigned" | "long unsigned int" => {
            Some(TypeHint::Int {
                signed: false,
                width: c_long_width,
            })
        }
        "long long" | "long long int" | "signed long long" | "signed long long int" | "int64_t" => {
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        }
        "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "uint64_t" => Some(TypeHint::Int {
            signed: false,
            width: 8,
        }),
        "float" => Some(TypeHint::Float { width: 4 }),
        "double" => Some(TypeHint::Float { width: 8 }),
        _ => None,
    }
}

fn dwarf_render_prototype(
    declared: &DwarfPrototypeContract,
) -> Option<crate::ir::call_contracts::CallPrototype> {
    use crate::debug::dwarf::{DwarfParameterType, DwarfReturnType};
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};

    let return_type = match &declared.return_type {
        DwarfReturnType::Void => "void".to_string(),
        DwarfReturnType::Type(c_type) => c_type.clone(),
        DwarfReturnType::Unknown => return None,
    };
    let parameter_types = declared
        .parameter_types
        .iter()
        .map(|parameter| match parameter {
            DwarfParameterType::Type(c_type) => Some(c_type.clone()),
            DwarfParameterType::Unknown => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(CallPrototype {
        return_type,
        parameter_types,
        variadic: false,
        authority: CallPrototypeAuthority::Authoritative,
    })
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
                DwarfParameterType::Type(c_type) => dwarf_return_hint(c_type, cc),
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
            prototype
                .apply_locked_output(RecoveredOutputKind::Direct, dwarf_return_hint(c_type, cc));
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

#[derive(Debug, Default)]
struct DirectCalleeFacts {
    layouts: std::collections::HashMap<u64, Vec<crate::ir::types::VReg>>,
    prototypes: std::collections::HashMap<u64, crate::ir::call_contracts::CallPrototype>,
}

fn imported_symbol_base(name: &str) -> &str {
    name.strip_suffix("@plt")
        .or_else(|| name.strip_suffix(".plt"))
        .unwrap_or(name)
}

fn defined_text_symbol_address(data: &[u8], name: &str) -> Option<u64> {
    use object::{Object, ObjectSymbol};

    let object = object::read::File::parse(data).ok()?;
    object
        .symbols()
        .chain(object.dynamic_symbols())
        .find(|symbol| {
            symbol.is_definition()
                && symbol.kind() == object::SymbolKind::Text
                && symbol.name().is_ok_and(|symbol_name| symbol_name == name)
        })
        .map(|symbol| symbol.address())
}

/// Fixed Itanium C++ runtime layouts whose imported PLT stubs have no body from
/// which parameter liveness can be recovered.
///
/// In particular, `__cxa_throw(object, typeinfo, destructor)` must retain all
/// three setup registers. Without this layout x1/x2 are dead before final
/// exception recovery, `_ZTIi` disappears, and the ABI call cannot become a
/// source-level `throw int`.
fn itanium_runtime_layout(
    name: &str,
    cc: crate::ir::call_args::CallConv,
) -> Option<Vec<crate::ir::types::VReg>> {
    let clean = imported_symbol_base(name);
    let arity = match clean {
        "__cxa_allocate_exception" | "__cxa_begin_catch" => 1,
        "__cxa_throw" => 3,
        "__cxa_end_catch" => 0,
        _ => return None,
    };
    if cc == crate::ir::call_args::CallConv::Cdecl32 {
        // cdecl arguments are reconstructed from stack pushes, not registers.
        return None;
    }
    Some(
        crate::ir::abi::argument_slots(cc)
            .iter()
            .take(arity)
            .map(|slot| crate::ir::types::VReg::phys(slot[0]))
            .collect(),
    )
}

fn recovered_call_prototype(
    prototype: &crate::ir::types_recover::RecoveredPrototype,
    cc: crate::ir::call_args::CallConv,
) -> crate::ir::call_contracts::CallPrototype {
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority};
    use crate::ir::types::VReg;
    use crate::ir::types_recover::RecoveredOutputKind;

    fn storage_fallback(register: &VReg) -> &'static str {
        match register {
            VReg::Phys(name) if name.starts_with('s') => "float",
            VReg::Phys(name) if name.starts_with('d') => "double",
            _ => "long",
        }
    }

    let parameter_types = prototype
        .parameters()
        .iter()
        .map(|parameter| {
            parameter
                .hint
                .map(|hint| {
                    crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                        hint,
                        calling_convention_pointer_width(cc),
                    )
                })
                .unwrap_or_else(|| storage_fallback(&parameter.value.base))
                .to_string()
        })
        .collect();
    let return_type = match prototype.output_kind() {
        RecoveredOutputKind::Void => "void",
        RecoveredOutputKind::Direct => prototype
            .result()
            .and_then(|result| result.hint)
            .map(|hint| {
                crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                    hint,
                    calling_convention_pointer_width(cc),
                )
            })
            .or_else(|| {
                prototype
                    .result()
                    .and_then(|result| result.values.first())
                    .map(|value| storage_fallback(&value.base))
            })
            .unwrap_or("long"),
        RecoveredOutputKind::Unknown | RecoveredOutputKind::HiddenReturn => "long",
    };
    CallPrototype {
        return_type: return_type.to_string(),
        parameter_types,
        variadic: false,
        authority: CallPrototypeAuthority::Recovered,
    }
}

/// Whether a direct callee's empty recovered argument layout is authoritative.
///
/// Machine-code liveness can miss parameters, so an empty inferred layout is
/// normally not safe to impose on a caller. A DWARF `DW_AT_prototyped` function
/// with no formal parameters is different: it proves a genuine `f(void)`
/// declaration, and its return contract must not be discarded merely because
/// there are no argument registers to record.
fn retain_empty_direct_callee_layout(declared: Option<&DwarfPrototypeContract>) -> bool {
    declared.is_some_and(|contract| contract.prototyped && contract.parameter_types.is_empty())
}

/// Recover the source-ordered physical parameter storage and prototype of direct callees.
///
/// This is intentionally demand-driven and cached. AAPCS-VFP callsites need
/// cross-function prototype evidence to interleave core and VFP registers; the
/// other conventions need the same callee-local evidence for parameter types
/// that a forwarding caller cannot prove itself. Lifting every discovered
/// function up front would double the dominant cost of large-binary
/// decompilation, so only callees of the function currently being rendered are
/// analyzed and repeated callees in batch modes reuse the result.
fn recover_direct_callee_layouts(
    data: &[u8],
    functions: &[crate::core::function::Function],
    caller: &crate::ir::types::LlirFunction,
    arch: crate::core::binary::Arch,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, DwarfPrototypeContract>>,
    address_names: &mut std::collections::HashMap<u64, String>,
    cache: &mut std::collections::HashMap<
        u64,
        Option<(
            Vec<crate::ir::types::VReg>,
            crate::ir::call_contracts::CallPrototype,
            String,
        )>,
    >,
) -> DirectCalleeFacts {
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;

    let mut facts = DirectCalleeFacts::default();
    let callees: std::collections::BTreeSet<u64> = caller
        .blocks
        .iter()
        .flat_map(|block| block.instrs.iter())
        .filter_map(|instruction| match instruction.op {
            crate::ir::types::Op::Call {
                target: crate::ir::types::CallTarget::Direct(address),
                ..
            } => Some(address),
            _ => None,
        })
        .collect();
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    if dump {
        eprintln!("\n===== direct callee candidates =====\n{callees:#x?}");
    }
    for callee_va in callees {
        if let Some(layout) = address_names
            .get(&callee_va)
            .and_then(|name| itanium_runtime_layout(name, cc))
        {
            facts.layouts.insert(callee_va, layout);
            continue;
        }
        // PIC code commonly calls a local exported definition through its PLT
        // entry.  The stub has no parameter evidence, but the same binary's
        // real `signed_step`/etc. body does. Resolve that body by the imported
        // symbol name while keeping facts keyed by the call instruction's
        // actual target address.
        let body_va = address_names
            .get(&callee_va)
            .map(|name| imported_symbol_base(name))
            .and_then(|name| {
                defined_text_symbol_address(data, name).or_else(|| {
                    functions
                        .iter()
                        .find(|function| {
                            let entry = function.entry_point.value;
                            function.name == name
                                || [entry, entry | 1].into_iter().any(|address| {
                                    address_names.get(&address).is_some_and(|resolved| {
                                        imported_symbol_base(resolved) == name
                                    })
                                })
                        })
                        .map(|function| function.entry_point.value)
                })
            })
            .unwrap_or(callee_va);
        let body_va = crate::analysis::arm32_mode::normalise_entry(data, body_va);
        if dump {
            eprintln!(
                "callee 0x{callee_va:x} {:?} -> body 0x{body_va:x}",
                address_names.get(&callee_va)
            );
        }
        let recovered = cache
            .entry(callee_va)
            .or_insert_with(|| {
                let targeted;
                let callee = match functions
                    .iter()
                    .find(|function| function.entry_point.value == body_va)
                {
                    Some(callee) => callee,
                    None => {
                        targeted = crate::analysis::cfg::discover_function_bytes_at(
                            data, budgets, body_va,
                        )?;
                        &targeted
                    }
                };
                let mut lifted = lift_function_from_bytes(data, callee, arch)?;
                inline_soft_helper_calls_in(&mut lifted, &*address_names);
                crate::ir::abi::annotate_calls(&mut lifted, cc);
                let ssa = compute_ssa(&lifted);
                let parameter_slots = crate::ir::value_number::live_in_arg_slots_llir(&lifted, cc);
                let prototype = recover_decbench_prototype(
                    &lifted,
                    &ssa,
                    cc,
                    &parameter_slots,
                    arm_vfp_args,
                    dwarf_outputs.and_then(|outputs| outputs.get(&body_va)),
                );
                let layout: Vec<crate::ir::types::VReg> = prototype
                    .parameters()
                    .iter()
                    .map(|parameter| parameter.value.base.clone())
                    .collect();
                let call_prototype = recovered_call_prototype(&prototype, cc);
                let declared = dwarf_outputs.and_then(|outputs| outputs.get(&body_va));
                (!layout.is_empty() || retain_empty_direct_callee_layout(declared))
                    .then(|| (layout, call_prototype, callee.name.clone()))
            })
            .clone();
        if let Some((layout, prototype, name)) = recovered {
            if dump {
                eprintln!("callee 0x{callee_va:x}: recovered layout {layout:?}");
            }
            match address_names.entry(callee_va) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(name);
                }
                std::collections::hash_map::Entry::Occupied(mut entry)
                    if entry.get().starts_with("sub_") && !name.starts_with("sub_") =>
                {
                    entry.insert(name);
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
            facts.layouts.insert(callee_va, layout);
            facts.prototypes.insert(callee_va, prototype);
        } else if dump {
            eprintln!("callee 0x{callee_va:x}: no recovered layout");
        }
    }
    facts
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
        if types.get(destination) != Some(hint) {
            types.refine_from_value(destination.clone(), hint);
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

    loop {
        let mut changed = false;
        visit(body, types, &mut changed);
        if !changed {
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
        if let Some(hint) = live_ins.get(&role) {
            if prototype.parameter_is_locked(parameter.slot) {
                decl.apply_locked_fact(role, hint);
            } else {
                decl.refine_from_value(role, hint);
            }
        }
    }
    merge_slot_sizes(&mut decl, slot_sizes, cc);
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
        if let Some(hint) = live_ins.get(&role) {
            if prototype.parameter_is_locked(parameter.slot) {
                width.apply_locked_fact(role, hint);
            } else {
                width.refine_from_value(role, hint);
            }
        }
    }
    merge_slot_sizes(&mut width, slot_sizes, cc);
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
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use crate::ir::ast::{lower, render};
    use crate::ir::lift_function::lift_function_from_bytes;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let exception_sites = crate::analysis::exception::extract_exception_call_sites(&data);
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&data));
    let dwarf_types =
        (style == "decbench").then(|| crate::debug::dwarf::extract_dwarf_types(&data));
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
    let (funcs, _cg) = py.detach(|| analyze_functions_bytes(&data, &budgets));
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let arm_vfp_args = arm_uses_vfp_arguments(&data);
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let readonly_data = crate::ir::readonly_fold::collect_readonly_data(&data);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    let mut callee_layout_cache = std::collections::HashMap::new();
    let list = PyList::empty(py);
    for func in funcs.iter().take(limit) {
        // The GIL is held across the per-function lifting work (the loop builds
        // a `PyList` as it goes), so CPython never re-enters its eval loop and
        // never notices a signal. This is the supported way to stay
        // interruptible without releasing: it raises `KeyboardInterrupt` here.
        py.check_signals()?;
        let Some(lf_raw) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
        crate::ir::abi::annotate_calls(&mut lf_raw, cc);
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let prepared_llir = prepare_llir_for_lowering(
            &mut lf_raw,
            &exception_sites,
            cc,
            style == "decbench",
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value)),
        );
        let PreparedLlir {
            region,
            numbered: lf,
            definition_widths,
            parameter_slots: mut param_slots,
            prototype,
        } = prepared_llir;
        let outer_name = resolve_outer_function_name(&func.name, func.entry_point.value, &addr_map);
        let mut f = lower(&lf, &region, outer_name.clone());
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
        let callee_facts = recover_direct_callee_layouts(
            &data,
            &funcs,
            &lf_raw,
            arch,
            cc,
            arm_vfp_args,
            &budgets,
            dwarf_outputs.as_ref(),
            &mut addr_map,
            &mut callee_layout_cache,
        );
        let (slot_sizes, role_names) = run_ast_passes(
            &mut f,
            cc,
            prototype.as_ref(),
            &mut param_slots,
            locked_parameter_count(prototype.as_ref()),
            &callee_facts,
            &addr_map,
            &str_pool,
            &function_tables,
            &stack_object_hints,
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
                &slot_sizes,
                &role_names,
                &definition_widths,
            );
            let declared_render = dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func.entry_point.value))
                .and_then(dwarf_render_prototype);
            decbench_text(
                &f,
                &exception_sites,
                Some(&decl),
                Some(&width),
                Some(&exact_value_widths),
                &readonly_data,
                prototype
                    .as_ref()
                    .expect("DecBench prototype")
                    .output_kind(),
                declared_render.as_ref(),
                dwarf_types.as_deref().unwrap_or(&[]),
                cc,
                &addr_map,
            )
        } else {
            render(&f)
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
    // Decompile an arbitrary SUBSET of functions in a SINGLE analysis pass.
    //
    // `decompile_at` re-runs `analyze_functions_bytes` (and the PDB/addr-map
    // build) on every call, so decompiling N scattered functions in a large
    // binary (e.g. the 18 MB mpengine.dll, ~30k functions) costs N full
    // analyses. This amortises that fixed cost across the whole requested set:
    // analyse once, then run the same per-function pipeline as `decompile_at`
    // for each requested VA. Returns a list of (name, va, c_or_ir_text) for
    // every requested VA that resolves to a known function.
    use crate::analysis::cfg::{analyze_functions_bytes_with_seeds, Budgets};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::types_recover::recover_types_for;
    use std::collections::HashSet;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    // See `decompile_at`: an ARM32 Thumb `.symtab` value carries the Thumb bit.
    let func_vas: Vec<u64> = func_vas
        .into_iter()
        .map(|va| crate::analysis::arm32_mode::normalise_entry(&data, va))
        .collect();
    let exception_sites = crate::analysis::exception::extract_exception_call_sites(&data);
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&data));
    let dwarf_types =
        (style == "decbench").then(|| crate::debug::dwarf::extract_dwarf_types(&data));
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
    let (funcs, _cg) = py.detach(|| analyze_functions_bytes_with_seeds(&data, &budgets, &func_vas));
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let arm_vfp_args = arm_uses_vfp_arguments(&data);
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let readonly_data = crate::ir::readonly_fold::collect_readonly_data(&data);
    let function_tables = crate::ir::function_tables::collect_function_pointer_tables(&data);
    let mut callee_layout_cache = std::collections::HashMap::new();
    // PDB-only public-symbol map for the `// PDB:` provenance comment; built
    // once, empty for non-PE inputs (so it never fires on ELF/Mach-O).
    let pdb_public_map = pdb_cache
        .map(|cache_dir| crate::ir::name_resolve::collect_pdb_public_symbol_map(&path, cache_dir))
        .unwrap_or_default();

    let wanted: HashSet<u64> = func_vas.iter().copied().collect();
    let list = PyList::empty(py);

    for func in funcs.iter() {
        // See `decompile_all_py`: keeps a long multi-function decompile
        // interruptible while the GIL is held for the `PyList` it is building.
        py.check_signals()?;
        let func_va = func.entry_point.value;
        if !wanted.contains(&func_va) {
            continue;
        }
        let Some(lf_raw) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        inline_soft_helper_calls_in(&mut lf_raw, &addr_map);
        crate::ir::abi::annotate_calls(&mut lf_raw, cc);
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let prepared_llir = prepare_llir_for_lowering(
            &mut lf_raw,
            &exception_sites,
            cc,
            style == "decbench",
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
        );
        let PreparedLlir {
            region,
            numbered: lf,
            definition_widths,
            parameter_slots: mut param_slots,
            prototype,
        } = prepared_llir;
        let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
        let mut f = lower(&lf, &region, outer_name);
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
        let callee_facts = recover_direct_callee_layouts(
            &data,
            &funcs,
            &lf_raw,
            arch,
            cc,
            arm_vfp_args,
            &budgets,
            dwarf_outputs.as_ref(),
            &mut addr_map,
            &mut callee_layout_cache,
        );
        let (slot_sizes, role_names) = run_ast_passes(
            &mut f,
            cc,
            prototype.as_ref(),
            &mut param_slots,
            locked_parameter_count(prototype.as_ref()),
            &callee_facts,
            &addr_map,
            &str_pool,
            &function_tables,
            &stack_object_hints,
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
                &slot_sizes,
                &role_names,
                &definition_widths,
            );
            let declared_render = dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va))
                .and_then(dwarf_render_prototype);
            decbench_text(
                &f,
                &exception_sites,
                Some(&decl),
                Some(&width),
                Some(&exact_value_widths),
                &readonly_data,
                prototype
                    .as_ref()
                    .expect("DecBench prototype")
                    .output_kind(),
                declared_render.as_ref(),
                dwarf_types.as_deref().unwrap_or(&[]),
                cc,
                &addr_map,
            )
        } else if style == "c" {
            let body = crate::ir::ast::render_c(&f);
            match pdb_outer_name {
                Some(name) => format!("// PDB: {}\n{}", name, body),
                None => body,
            }
        } else {
            match tm {
                Some(tm) => {
                    let renamed = remap_type_map(&tm, &f, cc, &param_slots);
                    render_with_types(&f, &renamed)
                }
                None => render(&f),
            }
        };
        let name = resolve_outer_function_name(&func.name, func_va, &addr_map);
        list.append((name, func_va, text))?;
    }
    Ok(list.into())
}

use crate::ir::name_resolve::resolve_outer_function_name;

/// Register LLIR-related Python bindings under the `ir` submodule.
pub fn register_ir_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let ir_mod = pyo3::types::PyModule::new(py, "ir")?;
    ir_mod.add_function(wrap_pyfunction!(lift_bytes_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(lift_window_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_range_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_all_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_many_py, &ir_mod)?)?;
    m.add_submodule(&ir_mod)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        dwarf_return_hint, dwarf_stack_object_hints, imported_symbol_base, integer_widths_by_role,
        merge_exact_definition_widths, refine_numbered_declaration,
        retain_empty_direct_callee_layout, DwarfPrototypeContract,
    };
    use crate::debug::dwarf::{DwarfReturnType, DwarfStackBase, DwarfStackObject};
    use crate::ir::call_args::CallConv;
    use crate::ir::types::VReg;
    use crate::ir::types_recover::{TypeHint, TypeMap};
    use std::collections::HashMap;

    #[test]
    fn a_plt_target_can_be_matched_to_its_local_definition() {
        assert_eq!(imported_symbol_base("signed_step@plt"), "signed_step");
        assert_eq!(imported_symbol_base("signed_step.plt"), "signed_step");
        assert_eq!(imported_symbol_base("signed_step"), "signed_step");
    }

    #[test]
    fn only_a_complete_void_parameter_list_authorizes_an_empty_callee_layout() {
        let complete = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Type("int".to_string()),
            stack_objects: Vec::new(),
        };
        let old_style = DwarfPrototypeContract {
            prototyped: false,
            ..complete.clone()
        };

        assert!(retain_empty_direct_callee_layout(Some(&complete)));
        assert!(!retain_empty_direct_callee_layout(Some(&old_style)));
        assert!(!retain_empty_direct_callee_layout(None));
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

    #[test]
    fn itanium_throw_runtime_has_a_fixed_three_register_layout() {
        assert_eq!(
            super::itanium_runtime_layout("__cxa_throw@plt", CallConv::Aarch64),
            Some(vec![VReg::phys("x0"), VReg::phys("x1"), VReg::phys("x2")])
        );
        assert_eq!(
            super::itanium_runtime_layout("__cxa_allocate_exception@plt", CallConv::SysVAmd64),
            Some(vec![VReg::phys("rdi")])
        );
        assert_eq!(
            super::itanium_runtime_layout("ordinary_function", CallConv::Aarch64),
            None
        );
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
    fn dwarf_arm_frame_registers_map_to_stack_object_hints() {
        let contract = DwarfPrototypeContract {
            prototyped: true,
            parameter_types: Vec::new(),
            return_type: DwarfReturnType::Void,
            stack_objects: vec![
                DwarfStackObject {
                    base: DwarfStackBase::Register(11),
                    offset: -24,
                    byte_size: 16,
                    aggregate: true,
                },
                DwarfStackObject {
                    base: DwarfStackBase::Register(7),
                    offset: -8,
                    byte_size: 8,
                    aggregate: true,
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
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -40,
                byte_size: 16,
                aggregate: true,
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
            stack_objects: vec![DwarfStackObject {
                base: DwarfStackBase::CallFrameCfa,
                offset: -24,
                byte_size: 8,
                aggregate: true,
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
}
