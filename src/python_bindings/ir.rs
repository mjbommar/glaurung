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
//!     "kind": "assign" | "cond_assign" | "bin" | "un" | "cmp"
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
        Op::CondAssign { dst, cond, src } => {
            d.set_item("kind", "cond_assign")?;
            d.set_item("dst", vreg_to_str(dst))?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
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
        Op::Store { addr, src } => {
            d.set_item("kind", "store")?;
            d.set_item("addr", memop_to_pyobj(py, addr)?)?;
            d.set_item("src", value_to_pyobj(py, src)?)?;
        }
        Op::Jump { target } => {
            d.set_item("kind", "jump")?;
            d.set_item("target", *target)?;
        }
        Op::IndirectJump { target } => {
            d.set_item("kind", "indirect_jump")?;
            d.set_item("target", value_to_pyobj(py, target)?)?;
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
/// The pass-by-pass AST dump (`GLAURUNG_DUMP_PASSES=1`) is read here, so EVERY entry
/// point gets identical diagnostics rather than only the one that happened to carry the
/// macro. Debugging `--all` used to produce no dump at all.
fn run_ast_passes(
    f: &mut crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
    param_slots: &std::collections::HashSet<usize>,
    parameter_roles: &std::collections::HashMap<String, usize>,
    callee_layouts: &std::collections::HashMap<u64, Vec<crate::ir::types::VReg>>,
    addr_map: &std::collections::HashMap<u64, String>,
    str_pool: &std::collections::HashMap<u64, String>,
) -> (
    std::collections::HashMap<String, u8>,
    std::collections::HashMap<String, String>,
) {
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    macro_rules! dp {
        ($n:expr) => {
            if dump {
                eprintln!("\n===== after {} =====\n{}", $n, crate::ir::ast::render(f));
            }
        };
    }
    crate::ir::expr_reconstruct::reconstruct(f);
    dp!("reconstruct");
    crate::ir::const_fold::fold_constants(f);
    dp!("fold_constants");
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
    crate::ir::call_args::recover_resolved_direct_tail_calls(f, cc, addr_map);
    crate::ir::call_args::recover_resolved_tail_calls(f, cc);
    dp!("recover_resolved_tail_calls");
    crate::ir::call_args::reconstruct_args_with_params_and_callee_layouts(
        f,
        cc,
        param_slots,
        callee_layouts,
    );
    dp!("reconstruct_args");
    // ABI liveness supplies candidate call inputs/outputs; an authoritative
    // library prototype wins when one is known. This mirrors Ghidra's locked
    // FuncProto and angr's callee-prototype priority rather than asking the C
    // renderer to paper over a semantically impossible AST result.
    crate::ir::call_contracts::apply_known_call_contracts(f);
    dp!("apply_known_call_contracts");
    crate::ir::strings_fold::fold_string_literals(f, str_pool);
    crate::ir::canary::recognise_canary(f);
    dp!("canary+strings");
    // Stack-slot promotion runs before register renaming so the aliases (`stack_0`,
    // `local_0`, ...) it allocates cannot collide with the role names (`arg0`, `ret`,
    // `varN`) the naming pass introduces.
    let slot_sizes = crate::ir::stack_locals::promote_stack_locals_typed(f, Some(cc));
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
        crate::ir::ast::materialize_direct_output(f);
    }
    crate::ir::value_split::split_spilled_arg_reuse(f, cc);
    dp!("split_spilled_arg_reuse");
    let role_names = crate::ir::naming::apply_role_names_with_parameter_roles(
        f,
        cc,
        param_slots,
        parameter_roles,
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
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover_verified;
    use crate::ir::types_recover::recover_types_for;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&data));
    let budgets = Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    let (funcs, _cg) = analyze_functions_bytes_with_seeds(&data, &budgets, &[func_va]);
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
    let lf_raw = lift_function_from_bytes(&data, &func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("LLIR lifter does not support this architecture")
    })?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    crate::ir::abi::annotate_calls(&mut lf_raw, cc);
    let ssa = compute_ssa(&lf_raw);
    let region = recover_verified(&lf_raw, &ssa);
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    let lf = if style == "decbench" {
        crate::ir::value_number::value_number(&lf_raw, &ssa, cc)
    } else {
        lf_raw.clone()
    };
    // Live-in argument slots (authoritative parameter set) for the type-map
    // remap, so scratch reuse of an arg register never becomes a spurious `argN`.
    let param_slots = crate::ir::value_number::live_in_arg_slots_llir(&lf, cc);
    // Recover the semantic prototype while SSA value IDs are still available.
    // It survives the AST pipeline as an immutable companion object; naming is
    // now only a final projection (`value -> argN`), never a type-analysis key.
    let prototype = (style == "decbench" && types).then(|| {
        recover_decbench_prototype(
            &lf_raw,
            &ssa,
            cc,
            &param_slots,
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
        )
    });
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== recovered prototype =====\n{prototype:#?}");
    }
    // Build the address map first so we can apply a PDB public-symbol name
    // to the *outer* function header before lowering. The map already
    // includes PDB symbols when a cache is configured, plus exports / IAT
    // names that beat the CFG-pass heuristic on stripped Windows binaries.
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    crate::ir::name_resolve::add_referenced_function_names(&mut addr_map, &funcs);
    let mut callee_layout_cache = std::collections::HashMap::new();
    let callee_layouts = recover_direct_callee_layouts(
        &data,
        &funcs,
        &func,
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
    let parameter_roles = prototype
        .as_ref()
        .map(|prototype| prototype.parameter_role_map())
        .unwrap_or_default();
    let (slot_sizes, role_names) = run_ast_passes(
        &mut f,
        cc,
        prototype.as_ref().map_or(
            crate::ir::types_recover::RecoveredOutputKind::Unknown,
            |prototype| prototype.output_kind(),
        ),
        &param_slots,
        &parameter_roles,
        &callee_layouts,
        &addr_map,
        &str_pool,
    );
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
                prototype.as_ref().expect("typed DecBench prototype"),
                cc,
                &param_slots,
                &slot_sizes,
                &role_names,
            )
        });
        let (decl, width) = match &maps {
            Some((d, w)) => (Some(d), Some(w)),
            None => (None, None),
        };
        decbench_text(
            &f,
            decl,
            width,
            prototype.as_ref().map_or(
                crate::ir::types_recover::RecoveredOutputKind::Unknown,
                |p| p.output_kind(),
            ),
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
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover_verified;
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
    let dwarf_outputs = (style == "decbench" && types).then(|| dwarf_output_contracts(&data));
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

    let lf_raw = lift_function_from_bytes(&data, &func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("LLIR lifter does not support this architecture")
    })?;
    // The ABI's call effects, recorded on the calls themselves, BEFORE SSA — so a
    // call participates in def/use like any other instruction instead of every later
    // pass having to special-case it (see `ir::abi`).
    let mut lf_raw = lf_raw;
    crate::ir::abi::annotate_calls(&mut lf_raw, cc);
    let ssa = compute_ssa(&lf_raw);
    let region = recover_verified(&lf_raw, &ssa);
    // `value_number` canonicalises sub-registers to their 64-bit parent (`edi`
    // -> `rdi`) so def/use versions line up for value correctness. But the
    // register sub-name width (`edi`=4) is *the* -O0 type-recovery signal, and
    // canonicalisation erases it. So type recovery runs on `lf_raw` (widths
    // intact) while everything downstream uses the canonicalised `lf`; the
    // remap merges the raw `edi`/`rdi` keys into one `argN` slot, keeping the
    // narrower width.
    let lf = if style == "decbench" {
        crate::ir::value_number::value_number(&lf_raw, &ssa, cc)
    } else {
        lf_raw.clone()
    };
    let param_slots = crate::ir::value_number::live_in_arg_slots_llir(&lf, cc);
    let prototype = (style == "decbench" && types).then(|| {
        recover_decbench_prototype(
            &lf_raw,
            &ssa,
            cc,
            &param_slots,
            arm_vfp_args,
            dwarf_outputs
                .as_ref()
                .and_then(|outputs| outputs.get(&func_va)),
        )
    });
    let mut f = lower(&lf, &region, func.name.clone());
    // An explicit byte range has no discovered callee Function objects from
    // which to recover cross-function storage layouts.
    let callee_layouts = std::collections::HashMap::new();
    // Inputs the shared pipeline needs. These were interleaved BETWEEN passes here, which
    // is why the four copies could not simply be diffed against each other — the pass
    // list and the local setup were braided together. None of them touch `f`, so
    // hoisting them is order-preserving.
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let parameter_roles = prototype
        .as_ref()
        .map(|prototype| prototype.parameter_role_map())
        .unwrap_or_default();
    let (slot_sizes, role_names) = run_ast_passes(
        &mut f,
        cc,
        prototype.as_ref().map_or(
            crate::ir::types_recover::RecoveredOutputKind::Unknown,
            |prototype| prototype.output_kind(),
        ),
        &param_slots,
        &parameter_roles,
        &callee_layouts,
        &addr_map,
        &str_pool,
    );
    recognise_machine_frame(&mut f, cc);
    if let Some(field_map) = &field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
    }
    Ok(if style == "decbench" {
        let maps = types.then(|| {
            decbench_type_maps(
                &f,
                &lf_raw,
                prototype.as_ref().expect("typed DecBench prototype"),
                cc,
                &param_slots,
                &slot_sizes,
                &role_names,
            )
        });
        let (decl, width) = match &maps {
            Some((d, w)) => (Some(d), Some(w)),
            None => (None, None),
        };
        decbench_text(
            &f,
            decl,
            width,
            prototype.as_ref().map_or(
                crate::ir::types_recover::RecoveredOutputKind::Unknown,
                |p| p.output_kind(),
            ),
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
) {
    for (name, &size) in sizes {
        if size == 0 {
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
    remap_type_map_impl(tm, cc, param_slots, true, None)
}

fn remap_type_map_impl(
    tm: &crate::ir::types_recover::TypeMap,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    include_parameters: bool,
    exact_roles: Option<&std::collections::HashMap<String, String>>,
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
                let exact = matches!(hint, crate::ir::types_recover::TypeHint::Float { .. })
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
    decl: Option<&crate::ir::types_recover::TypeMap>,
    width: Option<&crate::ir::types_recover::TypeMap>,
    output_kind: crate::ir::types_recover::RecoveredOutputKind,
) -> String {
    let mut prepared = crate::ir::ast::prepare_for_decbench_with_output(f, output_kind);
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
        crate::ir::ast::refine_decbench_abi_widths(&prepared, tm);
        crate::ir::high_variables::refine_pointer_high_variables(&prepared, tm);
    }
    if let Some(tm) = refined_width.as_mut() {
        crate::ir::ast::refine_decbench_abi_widths(&prepared, tm);
    }
    if let Some(tm) = refined_decl.as_ref() {
        crate::ir::const_fold::fold_typed_declared_views(&mut prepared, tm);
        crate::ir::const_fold::fold_typed_comparison_extensions(&mut prepared, tm);
        crate::ir::const_fold::fold_constants(&mut prepared);
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
        crate::ir::widen::insert_widening_casts(&mut prepared, tm);
    }
    // Call specifications belong to concrete AST calls, not to renderer-local
    // symbol guesses. Refresh them after every expression/type refinement so
    // string folding, promoted objects, and pointer facts are represented on
    // the exact call boundary the verifier and C renderer consume.
    crate::ir::call_contracts::refine_call_site_specs(&mut prepared, decl);
    let violations = crate::ir::verify_defs::check(&prepared);
    let body =
        crate::ir::ast::render_decbench_typed_with_output(&prepared, decl, width, output_kind);
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

/// Index authoritative DWARF output contracts once per binary analysis.
///
/// Batch decompilation must not reparse debug sections for every function.
/// The CFG analyser already consumes DWARF for boundaries and names; this
/// compact companion map carries the output fact to typed prototype recovery.
fn dwarf_output_contracts(
    data: &[u8],
) -> std::collections::HashMap<u64, crate::debug::dwarf::DwarfReturnType> {
    crate::debug::dwarf::extract_dwarf_functions(data)
        .into_iter()
        .map(|function| (function.entry_va, function.return_type))
        .collect()
}

/// Translate only DWARF scalar spellings that the current renderer can express
/// exactly. An unrepresentable declared type still locks the output as non-void;
/// it simply leaves machine-code recovery responsible for the concrete C type.
fn dwarf_return_hint(c_type: &str) -> Option<crate::ir::types_recover::TypeHint> {
    use crate::ir::types_recover::TypeHint;

    let normalized = c_type
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>()
        .join(" ");
    match normalized.as_str() {
        "_Bool" | "bool" => Some(TypeHint::BoolLike),
        "char" | "signed char" => Some(TypeHint::Int {
            signed: true,
            width: 1,
        }),
        "unsigned char" => Some(TypeHint::Int {
            signed: false,
            width: 1,
        }),
        "short" | "short int" | "signed short" | "signed short int" => Some(TypeHint::Int {
            signed: true,
            width: 2,
        }),
        "unsigned short" | "unsigned short int" => Some(TypeHint::Int {
            signed: false,
            width: 2,
        }),
        "int" | "signed" | "signed int" => Some(TypeHint::Int {
            signed: true,
            width: 4,
        }),
        "unsigned" | "unsigned int" => Some(TypeHint::Int {
            signed: false,
            width: 4,
        }),
        "float" => Some(TypeHint::Float { width: 4 }),
        "double" => Some(TypeHint::Float { width: 8 }),
        _ => None,
    }
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
    declared_return: Option<&crate::debug::dwarf::DwarfReturnType>,
) -> crate::ir::types_recover::RecoveredPrototype {
    use crate::debug::dwarf::DwarfReturnType;
    use crate::ir::types_recover::RecoveredOutputKind;

    let mut prototype = crate::ir::types_recover::recover_prototype_with_arm_vfp_args(
        lf_raw,
        ssa,
        cc,
        param_slots,
        arm_vfp_args,
    );
    match declared_return {
        Some(DwarfReturnType::Void) => {
            prototype.apply_locked_output(RecoveredOutputKind::Void, None);
        }
        Some(DwarfReturnType::Type(c_type)) => {
            prototype.apply_locked_output(RecoveredOutputKind::Direct, dwarf_return_hint(c_type));
        }
        Some(DwarfReturnType::Unknown) | None => {}
    }
    prototype
}

/// Recover the source-ordered physical parameter storage of direct callees.
///
/// This is intentionally demand-driven and cached. AAPCS-VFP callsites need
/// cross-function prototype evidence to interleave core and VFP registers, but
/// lifting every discovered function up front would double the dominant cost
/// of large-binary decompilation. Only callees of the function currently being
/// rendered are analyzed, and repeated callees in batch modes reuse the result.
fn recover_direct_callee_layouts(
    data: &[u8],
    functions: &[crate::core::function::Function],
    caller: &crate::core::function::Function,
    arch: crate::core::binary::Arch,
    cc: crate::ir::call_args::CallConv,
    arm_vfp_args: bool,
    budgets: &crate::analysis::cfg::Budgets,
    dwarf_outputs: Option<&std::collections::HashMap<u64, crate::debug::dwarf::DwarfReturnType>>,
    address_names: &mut std::collections::HashMap<u64, String>,
    cache: &mut std::collections::HashMap<u64, Option<(Vec<crate::ir::types::VReg>, String)>>,
) -> std::collections::HashMap<u64, Vec<crate::ir::types::VReg>> {
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;

    if cc != crate::ir::call_args::CallConv::ArmHardFloat {
        return std::collections::HashMap::new();
    }

    let mut layouts = std::collections::HashMap::new();
    for callee_address in &caller.callees {
        let callee_va = callee_address.value;
        let recovered = cache
            .entry(callee_va)
            .or_insert_with(|| {
                let targeted;
                let callee = match functions
                    .iter()
                    .find(|function| function.entry_point.value == callee_va)
                {
                    Some(callee) => callee,
                    None => {
                        targeted = crate::analysis::cfg::discover_function_bytes_at(
                            data, budgets, callee_va,
                        )?;
                        &targeted
                    }
                };
                let mut lifted = lift_function_from_bytes(data, callee, arch)?;
                crate::ir::abi::annotate_calls(&mut lifted, cc);
                let ssa = compute_ssa(&lifted);
                let parameter_slots = crate::ir::value_number::live_in_arg_slots_llir(&lifted, cc);
                let prototype = recover_decbench_prototype(
                    &lifted,
                    &ssa,
                    cc,
                    &parameter_slots,
                    arm_vfp_args,
                    dwarf_outputs.and_then(|outputs| outputs.get(&callee_va)),
                );
                let layout: Vec<crate::ir::types::VReg> = prototype
                    .parameters()
                    .iter()
                    .map(|parameter| parameter.value.base.clone())
                    .collect();
                (!layout.is_empty()).then(|| (layout, callee.name.clone()))
            })
            .clone();
        if let Some((layout, name)) = recovered {
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
            layouts.insert(callee_va, layout);
        }
    }
    layouts
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
fn decbench_type_maps(
    f: &crate::ir::ast::Function,
    lf_raw: &crate::ir::types::LlirFunction,
    prototype: &crate::ir::types_recover::RecoveredPrototype,
    cc: crate::ir::call_args::CallConv,
    param_slots: &std::collections::HashSet<usize>,
    slot_sizes: &std::collections::HashMap<String, u8>,
    role_names: &std::collections::HashMap<String, String>,
) -> (
    crate::ir::types_recover::TypeMap,
    crate::ir::types_recover::TypeMap,
) {
    use crate::ir::types_recover::recover_types_for;
    let raw = recover_types_for(lf_raw, cc);
    let mut decl = remap_type_map_impl(&raw, cc, param_slots, false, Some(role_names));
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
            decl.refine_from_value(role, hint);
        }
    }
    merge_slot_sizes(&mut decl, slot_sizes);
    refine_float_copy_types(&f.body, &mut decl);
    let mut width = remap_type_map_impl(&raw, cc, param_slots, false, Some(role_names));
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
            width.refine_from_value(role, hint);
        }
    }
    merge_slot_sizes(&mut width, slot_sizes);
    refine_float_copy_types(&f.body, &mut width);
    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
        eprintln!("\n===== exact role names =====\n{role_names:#?}");
        eprintln!("\n===== recovered declaration types =====\n{decl:#?}");
    }
    (decl, width)
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
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover_verified;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&data));
    let budgets = Budgets {
        max_functions: limit.max(1),
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
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
    let mut callee_layout_cache = std::collections::HashMap::new();
    let list = PyList::empty(py);
    for func in funcs.iter().take(limit) {
        let Some(lf_raw) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        crate::ir::abi::annotate_calls(&mut lf_raw, cc);
        let ssa = compute_ssa(&lf_raw);
        let region = recover_verified(&lf_raw, &ssa);
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let lf = if style == "decbench" {
            crate::ir::value_number::value_number(&lf_raw, &ssa, cc)
        } else {
            lf_raw.clone()
        };
        let param_slots = crate::ir::value_number::live_in_arg_slots_llir(&lf, cc);
        let prototype = (style == "decbench").then(|| {
            recover_decbench_prototype(
                &lf_raw,
                &ssa,
                cc,
                &param_slots,
                arm_vfp_args,
                dwarf_outputs
                    .as_ref()
                    .and_then(|outputs| outputs.get(&func.entry_point.value)),
            )
        });
        let outer_name = resolve_outer_function_name(&func.name, func.entry_point.value, &addr_map);
        let mut f = lower(&lf, &region, outer_name.clone());
        // One pass list, shared with every other entry point — see `run_ast_passes`.
        // This site used to run dead-flag pruning before constant folding and never
        // pruned unreferenced labels, so `--all` produced different output from `--vas`
        // for the same function, and the fixture gate's structural lane measured a
        // different pipeline from its execution lane. It cannot drift again.
        let parameter_roles = prototype
            .as_ref()
            .map(|prototype| prototype.parameter_role_map())
            .unwrap_or_default();
        let callee_layouts = recover_direct_callee_layouts(
            &data,
            &funcs,
            func,
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
            prototype.as_ref().map_or(
                crate::ir::types_recover::RecoveredOutputKind::Unknown,
                |prototype| prototype.output_kind(),
            ),
            &param_slots,
            &parameter_roles,
            &callee_layouts,
            &addr_map,
            &str_pool,
        );
        recognise_machine_frame(&mut f, cc);
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let text = if style == "decbench" {
            let (decl, width) = decbench_type_maps(
                &f,
                &lf_raw,
                prototype.as_ref().expect("DecBench prototype"),
                cc,
                &param_slots,
                &slot_sizes,
                &role_names,
            );
            decbench_text(
                &f,
                Some(&decl),
                Some(&width),
                prototype
                    .as_ref()
                    .expect("DecBench prototype")
                    .output_kind(),
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
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover_verified;
    use crate::ir::types_recover::recover_types_for;
    use std::collections::HashSet;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let dwarf_outputs = (style == "decbench").then(|| dwarf_output_contracts(&data));
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
    };
    // --- one-time analysis + name/field/string maps -----------------------
    let (funcs, _cg) = analyze_functions_bytes_with_seeds(&data, &budgets, &func_vas);
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
    let mut callee_layout_cache = std::collections::HashMap::new();
    // PDB-only public-symbol map for the `// PDB:` provenance comment; built
    // once, empty for non-PE inputs (so it never fires on ELF/Mach-O).
    let pdb_public_map = pdb_cache
        .map(|cache_dir| crate::ir::name_resolve::collect_pdb_public_symbol_map(&path, cache_dir))
        .unwrap_or_default();

    let wanted: HashSet<u64> = func_vas.iter().copied().collect();
    let list = PyList::empty(py);

    for func in funcs.iter() {
        let func_va = func.entry_point.value;
        if !wanted.contains(&func_va) {
            continue;
        }
        let Some(lf_raw) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        // See `ir::abi`: the ABI's call effects go on the calls before SSA.
        let mut lf_raw = lf_raw;
        crate::ir::abi::annotate_calls(&mut lf_raw, cc);
        let ssa = compute_ssa(&lf_raw);
        let region = recover_verified(&lf_raw, &ssa);
        // Recover types on the pre-canonicalisation LLIR (sub-register widths
        // intact); see the note in `decompile_at`.
        let lf = if style == "decbench" {
            crate::ir::value_number::value_number(&lf_raw, &ssa, cc)
        } else {
            lf_raw.clone()
        };
        let param_slots = crate::ir::value_number::live_in_arg_slots_llir(&lf, cc);
        let prototype = (style == "decbench").then(|| {
            recover_decbench_prototype(
                &lf_raw,
                &ssa,
                cc,
                &param_slots,
                arm_vfp_args,
                dwarf_outputs
                    .as_ref()
                    .and_then(|outputs| outputs.get(&func_va)),
            )
        });
        let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
        let mut f = lower(&lf, &region, outer_name);
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
        let parameter_roles = prototype
            .as_ref()
            .map(|prototype| prototype.parameter_role_map())
            .unwrap_or_default();
        let callee_layouts = recover_direct_callee_layouts(
            &data,
            &funcs,
            func,
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
            prototype.as_ref().map_or(
                crate::ir::types_recover::RecoveredOutputKind::Unknown,
                |prototype| prototype.output_kind(),
            ),
            &param_slots,
            &parameter_roles,
            &callee_layouts,
            &addr_map,
            &str_pool,
        );
        recognise_machine_frame(&mut f, cc);
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let pdb_outer_name = pdb_public_map
            .get(&func_va)
            .filter(|name| !name.is_empty() && !name.starts_with("sub_"))
            .cloned();
        let text = if style == "decbench" {
            let (decl, width) = decbench_type_maps(
                &f,
                &lf_raw,
                prototype.as_ref().expect("DecBench prototype"),
                cc,
                &param_slots,
                &slot_sizes,
                &role_names,
            );
            decbench_text(
                &f,
                Some(&decl),
                Some(&width),
                prototype
                    .as_ref()
                    .expect("DecBench prototype")
                    .output_kind(),
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
