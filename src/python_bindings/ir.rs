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
//!     "kind": "assign" | "bin" | "un" | "cmp" | "load" | "store"
//!           | "jump"   | "cond_jump" | "call" | "return" | "nop" | "unknown",
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

use crate::ir::{lift_arm64, lift_x86};
use crate::ir::types::{BinOp, CallTarget, CmpOp, Flag, LlirInstr, MemOp, Op, UnOp, VReg, Value};

fn flag_repr(f: Flag) -> &'static str {
    match f {
        Flag::Z => "%zf",
        Flag::C => "%cf",
        Flag::S => "%sf",
        Flag::Slt => "%slt",
        Flag::Sle => "%sle",
        Flag::O => "%of",
        Flag::P => "%pf",
        Flag::A => "%af",
    }
}

fn vreg_to_str(v: &VReg) -> String {
    match v {
        VReg::Phys(n) => n.clone(),
        VReg::Temp(i) => format!("%t{}", i),
        VReg::Flag(f) => flag_repr(*f).to_string(),
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
    d.set_item(
        "base",
        m.base.as_ref().map(vreg_to_str).unwrap_or_default(),
    )?;
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
        Op::Bin {
            dst,
            op,
            lhs,
            rhs,
        } => {
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
        Op::Cmp {
            dst,
            op,
            lhs,
            rhs,
        } => {
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
        Op::CondJump { cond, target } => {
            d.set_item("kind", "cond_jump")?;
            d.set_item("cond", vreg_to_str(cond))?;
            d.set_item("target", *target)?;
        }
        Op::Call { target } => {
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
        Op::Unknown { mnemonic } => {
            d.set_item("kind", "unknown")?;
            d.set_item("mnemonic", mnemonic)?;
        }
    }
    Ok(d.into())
}

/// Dispatch lifting to the appropriate per-arch backend.
fn lift_for_arch(
    data: &[u8],
    start_va: u64,
    bits: u32,
    arch: &str,
) -> PyResult<Vec<LlirInstr>> {
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
    let foff = crate::analysis::entry::va_to_file_offset(&data, start_va).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("no mapping for VA 0x{:x}", start_va))
    })?;
    let end = foff.saturating_add(window_bytes).min(data.len());
    lift_bytes_py(py, &data[foff..end], start_va, bits, arch)
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
#[pyo3(signature = (path, func_va, max_blocks=256usize, max_instructions=10_000usize, timeout_ms=500u64, types=true, style=""))]
fn decompile_at_py(
    path: String,
    func_va: u64,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    types: bool,
    style: &str,
) -> PyResult<String> {
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use crate::core::binary::Arch as BArch;
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::expr_reconstruct::reconstruct;
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types_recover::recover_types;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let budgets = Budgets {
        max_functions: 256,
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
    let func = funcs
        .iter()
        .find(|f| f.entry_point.value == func_va)
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "no function at entry VA 0x{:x}",
                func_va
            ))
        })?;
    // Best-effort arch detection (x86-64 vs aarch64) from the object format.
    let arch = if let Ok(obj) = object::read::File::parse(&data[..]) {
        use object::Object;
        match obj.architecture() {
            object::Architecture::I386 => BArch::X86,
            object::Architecture::X86_64 => BArch::X86_64,
            object::Architecture::Aarch64 => BArch::AArch64,
            _ => BArch::X86_64,
        }
    } else {
        BArch::X86_64
    };
    let lf = lift_function_from_bytes(&data, func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(
            "LLIR lifter does not support this architecture",
        )
    })?;
    let ssa = compute_ssa(&lf);
    let region = recover(&lf, &ssa);
    let mut f = lower(&lf, &region, func.name.clone());
    reconstruct(&mut f);
    crate::ir::const_fold::fold_constants(&mut f);
    crate::ir::dce::prune_dead_flags(&mut f);
    let cc = match arch {
        BArch::AArch64 => crate::ir::call_args::CallConv::Aarch64,
        _ => crate::ir::call_args::CallConv::SysVAmd64,
    };
    crate::ir::call_args::reconstruct_args(&mut f, cc);
    let addr_map = crate::ir::name_resolve::collect_address_map(&data, &path);
    crate::ir::name_resolve::resolve_names(&mut f, &addr_map);
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    crate::ir::strings_fold::fold_string_literals(&mut f, &str_pool);
    crate::ir::canary::recognise_canary(&mut f);
    // Stack-slot promotion runs before register renaming so the aliases
    // (`stack_0`, `local_0`, ...) it allocates don't collide with the role
    // names (`arg0`, `ret`, `varN`) that the naming pass introduces.
    crate::ir::stack_locals::promote_stack_locals(&mut f);
    // Type recovery runs on the raw LLIR (before register renaming) so we
    // can cross-reference the renamed AST against the recovered types.
    let tm = if types {
        Some(recover_types(&lf))
    } else {
        None
    };
    crate::ir::naming::apply_role_names(&mut f, cc);
    crate::ir::canary::collapse_canary_save(&mut f);
    if matches!(cc, crate::ir::call_args::CallConv::Aarch64) {
        crate::ir::arm64_prologue::recognise_arm64_prologue(&mut f);
    }
    // Run dead-store elimination *after* naming so the pass sees the
    // aliased return register (`ret` / `arg0`) rather than the raw
    // physical register. This removes the common pre-call `%ret = 0`
    // idiom entirely.
    crate::ir::dead_stores::eliminate_dead_stores(&mut f, cc);
    crate::ir::stack_idiom::rematerialise_stack_ops(&mut f);
    crate::ir::label_prune::prune_unreferenced_labels(&mut f);
    if matches!(cc, crate::ir::call_args::CallConv::SysVAmd64) {
        crate::ir::x86_prologue::recognise_x86_prologue(&mut f);
    }
    Ok(if style == "c" {
        crate::ir::ast::render_c(&f)
    } else {
        match tm {
            Some(tm) => {
                // Remap the TypeMap keys from raw physical regs into the
                // role-based names the AST now uses.
                let renamed = remap_type_map(&tm, &f, cc);
                render_with_types(&f, &renamed)
            }
            None => render(&f),
        }
    })
}

/// Rebuild a TypeMap whose keys match the post-rename AST. We walk the
/// original physical-register TypeMap and, for each entry, look up the
/// alias the naming pass would have produced. Any remaining entries keep
/// their original names so the printer still has a chance to annotate.
fn remap_type_map(
    tm: &crate::ir::types_recover::TypeMap,
    _f: &crate::ir::ast::Function,
    cc: crate::ir::call_args::CallConv,
) -> crate::ir::types_recover::TypeMap {
    // Reconstruct the alias table the naming pass used for arg/ret slots;
    // `varN` aliases are assigned by first-appearance order and we can't
    // trivially recover them here, so those keys survive untouched.
    let mut alias: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let arg_slots: &[&[&str]] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
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
    };
    for (slot, names) in arg_slots.iter().enumerate() {
        for n in *names {
            alias.entry(n.to_string()).or_insert_with(|| format!("arg{}", slot));
        }
    }
    let ret_aliases: &[&str] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 => &["rax", "eax", "ax", "al"],
        crate::ir::call_args::CallConv::Aarch64 => &["x0", "w0"],
    };
    for n in ret_aliases {
        alias.entry(n.to_string()).or_insert_with(|| "ret".to_string());
    }
    let mut out = crate::ir::types_recover::TypeMap::default();
    for (reg, hint) in tm.iter() {
        match reg {
            crate::ir::types::VReg::Phys(n) => {
                let new_name = alias.get(n).cloned().unwrap_or_else(|| n.clone());
                out.upsert_public(
                    crate::ir::types::VReg::Phys(new_name),
                    *hint,
                );
            }
            _ => out.upsert_public(reg.clone(), *hint),
        }
    }
    out
}

/// Decompile the first `limit` discovered functions. Returns a list of
/// `(func_name, entry_va, pseudocode)` triples.
#[pyfunction]
#[pyo3(name = "decompile_all")]
#[pyo3(signature = (path, limit=8usize, max_blocks=256usize, max_instructions=10_000usize, timeout_ms=500u64))]
fn decompile_all_py(
    py: Python<'_>,
    path: String,
    limit: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
) -> PyResult<PyObject> {
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use crate::core::binary::Arch as BArch;
    use crate::ir::ast::{lower, render};
    use crate::ir::expr_reconstruct::reconstruct;
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let budgets = Budgets {
        max_functions: limit.max(1),
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
    let arch = if let Ok(obj) = object::read::File::parse(&data[..]) {
        use object::Object;
        match obj.architecture() {
            object::Architecture::I386 => BArch::X86,
            object::Architecture::X86_64 => BArch::X86_64,
            object::Architecture::Aarch64 => BArch::AArch64,
            _ => BArch::X86_64,
        }
    } else {
        BArch::X86_64
    };
    let addr_map = crate::ir::name_resolve::collect_address_map(&data, &path);
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let cc = match arch {
        BArch::AArch64 => crate::ir::call_args::CallConv::Aarch64,
        _ => crate::ir::call_args::CallConv::SysVAmd64,
    };
    let list = PyList::empty(py);
    for func in funcs.iter().take(limit) {
        let Some(lf) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        let mut f = lower(&lf, &region, func.name.clone());
        reconstruct(&mut f);
        crate::ir::dce::prune_dead_flags(&mut f);
        crate::ir::const_fold::fold_constants(&mut f);
        crate::ir::call_args::reconstruct_args(&mut f, cc);
        crate::ir::name_resolve::resolve_names(&mut f, &addr_map);
        crate::ir::strings_fold::fold_string_literals(&mut f, &str_pool);
        crate::ir::canary::recognise_canary(&mut f);
        crate::ir::stack_locals::promote_stack_locals(&mut f);
        crate::ir::naming::apply_role_names(&mut f, cc);
        crate::ir::canary::collapse_canary_save(&mut f);
        if matches!(cc, crate::ir::call_args::CallConv::Aarch64) {
            crate::ir::arm64_prologue::recognise_arm64_prologue(&mut f);
        }
        crate::ir::dead_stores::eliminate_dead_stores(&mut f, cc);
        crate::ir::stack_idiom::rematerialise_stack_ops(&mut f);
        if matches!(cc, crate::ir::call_args::CallConv::SysVAmd64) {
            crate::ir::x86_prologue::recognise_x86_prologue(&mut f);
        }
        let text = render(&f);
        list.append((func.name.clone(), func.entry_point.value, text))?;
    }
    Ok(list.into())
}

/// Register LLIR-related Python bindings under the `ir` submodule.
pub fn register_ir_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let ir_mod = pyo3::types::PyModule::new(py, "ir")?;
    ir_mod.add_function(wrap_pyfunction!(lift_bytes_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(lift_window_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_at_py, &ir_mod)?)?;
    ir_mod.add_function(wrap_pyfunction!(decompile_all_py, &ir_mod)?)?;
    m.add_submodule(&ir_mod)?;
    Ok(())
}
