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
    let foff = crate::analysis::entry::va_to_file_offset(&data, start_va).ok_or_else(|| {
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
            _ => BArch::X86_64,
        }
    } else {
        BArch::X86_64
    };

    let cc = match (arch, is_pe) {
        (BArch::AArch64, _) => crate::ir::call_args::CallConv::Aarch64,
        (BArch::X86_64, true) => crate::ir::call_args::CallConv::Win64,
        _ => crate::ir::call_args::CallConv::SysVAmd64,
    };
    (arch, cc)
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
#[pyo3(signature = (path, func_va, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", pdb_cache="", max_functions=30_000usize))]
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
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::expr_reconstruct::reconstruct;
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types_recover::recover_types;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let budgets = Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
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
    let lf = lift_function_from_bytes(&data, &func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("LLIR lifter does not support this architecture")
    })?;
    let ssa = compute_ssa(&lf);
    let region = recover(&lf, &ssa);
    // Build the address map first so we can apply a PDB public-symbol name
    // to the *outer* function header before lowering. The map already
    // includes PDB symbols when a cache is configured, plus exports / IAT
    // names that beat the CFG-pass heuristic on stripped Windows binaries.
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
    let mut f = lower(&lf, &region, outer_name);
    reconstruct(&mut f);
    crate::ir::const_fold::fold_constants(&mut f);
    crate::ir::dce::prune_dead_flags(&mut f);
    crate::ir::call_args::reconstruct_args(&mut f, cc);
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
    if matches!(
        cc,
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64
    ) {
        crate::ir::x86_prologue::recognise_x86_prologue(&mut f);
    }
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
        .and_then(|_| addr_map.get(&func_va))
        .filter(|name| !name.is_empty() && !name.starts_with("sub_"))
        .cloned();
    Ok(if style == "c" {
        let body = crate::ir::ast::render_c(&f);
        match pdb_outer_name {
            Some(name) => format!("// PDB: {}\n{}", name, body),
            None => body,
        }
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
    use crate::ir::expr_reconstruct::reconstruct;
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types_recover::recover_types;

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
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let bits = match arch {
        crate::core::binary::Arch::X86 => 32,
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

    let lf = lift_function_from_bytes(&data, &func, arch).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("LLIR lifter does not support this architecture")
    })?;
    let ssa = compute_ssa(&lf);
    let region = recover(&lf, &ssa);
    let mut f = lower(&lf, &region, func.name.clone());
    reconstruct(&mut f);
    crate::ir::const_fold::fold_constants(&mut f);
    crate::ir::dce::prune_dead_flags(&mut f);
    crate::ir::call_args::reconstruct_args(&mut f, cc);
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    crate::ir::name_resolve::resolve_names(&mut f, &addr_map);
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    crate::ir::strings_fold::fold_string_literals(&mut f, &str_pool);
    crate::ir::canary::recognise_canary(&mut f);
    crate::ir::stack_locals::promote_stack_locals(&mut f);
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
    crate::ir::dead_stores::eliminate_dead_stores(&mut f, cc);
    crate::ir::stack_idiom::rematerialise_stack_ops(&mut f);
    crate::ir::label_prune::prune_unreferenced_labels(&mut f);
    if matches!(
        cc,
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64
    ) {
        crate::ir::x86_prologue::recognise_x86_prologue(&mut f);
    }
    if let Some(field_map) = &field_map {
        crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
    }
    Ok(if style == "c" {
        crate::ir::ast::render_c(&f)
    } else {
        match tm {
            Some(tm) => {
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
            alias
                .entry(n.to_string())
                .or_insert_with(|| format!("arg{}", slot));
        }
    }
    let ret_aliases: &[&str] = match cc {
        crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64 => {
            &["rax", "eax", "ax", "al"]
        }
        crate::ir::call_args::CallConv::Aarch64 => &["x0", "w0"],
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
                let new_name = alias.get(n).cloned().unwrap_or_else(|| n.clone());
                out.upsert_public(crate::ir::types::VReg::Phys(new_name), *hint);
            }
            _ => out.upsert_public(reg.clone(), *hint),
        }
    }
    out
}

/// Decompile the first `limit` discovered functions. Returns a list of
/// `(func_name, entry_va, pseudocode)` triples.
///
/// Default `limit=30000` matches the function-discovery cap so the
/// `--all` flag really does emit every function unless the user
/// explicitly opts back into a smaller window.
#[pyfunction]
#[pyo3(name = "decompile_all")]
#[pyo3(signature = (path, limit=30_000usize, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=10_000u64, pdb_cache=""))]
fn decompile_all_py(
    py: Python<'_>,
    path: String,
    limit: usize,
    max_blocks: usize,
    max_instructions: usize,
    timeout_ms: u64,
    pdb_cache: &str,
) -> PyResult<PyObject> {
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
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
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);
    let list = PyList::empty(py);
    for func in funcs.iter().take(limit) {
        let Some(lf) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        let outer_name = resolve_outer_function_name(&func.name, func.entry_point.value, &addr_map);
        let mut f = lower(&lf, &region, outer_name.clone());
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
        if matches!(
            cc,
            crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64
        ) {
            crate::ir::x86_prologue::recognise_x86_prologue(&mut f);
        }
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let text = render(&f);
        list.append((outer_name, func.entry_point.value, text))?;
    }
    Ok(list.into())
}

#[pyfunction]
#[pyo3(name = "decompile_many")]
#[pyo3(signature = (path, func_vas, max_blocks=4096usize, max_instructions=200_000usize, timeout_ms=5000u64, types=true, style="", pdb_cache="", max_functions=30_000usize))]
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
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use crate::ir::ast::{lower, render, render_with_types};
    use crate::ir::expr_reconstruct::reconstruct;
    use crate::ir::lift_function::lift_function_from_bytes;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types_recover::recover_types;
    use std::collections::HashSet;

    let data = std::fs::read(&path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("read error: {}", e)))?;
    let budgets = Budgets {
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
    };
    // --- one-time analysis + name/field/string maps -----------------------
    let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
    let (arch, cc) = detect_arch_and_call_conv(&data);
    let pdb_cache = (!pdb_cache.is_empty()).then(|| std::path::Path::new(pdb_cache));
    let mut addr_map =
        crate::ir::name_resolve::collect_address_map_with_pdb_cache(&data, &path, pdb_cache);
    crate::ir::name_resolve::add_discovered_function_names(&mut addr_map, &funcs);
    let field_map =
        pdb_cache.map(|cache_dir| crate::ir::pdb_fields::collect_pdb_field_map(&path, cache_dir));
    let str_pool = crate::ir::strings_fold::collect_string_pool(&data);

    let wanted: HashSet<u64> = func_vas.iter().copied().collect();
    let list = PyList::empty(py);

    for func in funcs.iter() {
        let func_va = func.entry_point.value;
        if !wanted.contains(&func_va) {
            continue;
        }
        let Some(lf) = lift_function_from_bytes(&data, func, arch) else {
            continue;
        };
        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        let outer_name = resolve_outer_function_name(&func.name, func_va, &addr_map);
        let mut f = lower(&lf, &region, outer_name);
        reconstruct(&mut f);
        crate::ir::const_fold::fold_constants(&mut f);
        crate::ir::dce::prune_dead_flags(&mut f);
        crate::ir::call_args::reconstruct_args(&mut f, cc);
        crate::ir::name_resolve::resolve_names(&mut f, &addr_map);
        crate::ir::strings_fold::fold_string_literals(&mut f, &str_pool);
        crate::ir::canary::recognise_canary(&mut f);
        crate::ir::stack_locals::promote_stack_locals(&mut f);
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
        crate::ir::dead_stores::eliminate_dead_stores(&mut f, cc);
        crate::ir::stack_idiom::rematerialise_stack_ops(&mut f);
        crate::ir::label_prune::prune_unreferenced_labels(&mut f);
        if matches!(
            cc,
            crate::ir::call_args::CallConv::SysVAmd64 | crate::ir::call_args::CallConv::Win64
        ) {
            crate::ir::x86_prologue::recognise_x86_prologue(&mut f);
        }
        if let Some(field_map) = &field_map {
            crate::ir::pdb_fields::annotate_function_fields(&mut f, field_map);
        }
        let pdb_outer_name = pdb_cache
            .and_then(|_| addr_map.get(&func_va))
            .filter(|name| !name.is_empty() && !name.starts_with("sub_"))
            .cloned();
        let text = if style == "c" {
            let body = crate::ir::ast::render_c(&f);
            match pdb_outer_name {
                Some(name) => format!("// PDB: {}\n{}", name, body),
                None => body,
            }
        } else {
            match tm {
                Some(tm) => {
                    let renamed = remap_type_map(&tm, &f, cc);
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

/// Pick the best name for the outer function being decompiled.
///
/// `discovered_name` is whatever the CFG discovery pass produced
/// (`sub_<va>` for stripped binaries, a real symbol when one was available
/// at scan time). `addr_map` has been overlaid with PE/PDB public symbols
/// when a `--pdb-cache` was supplied, so this gives the PDB name priority
/// over the placeholder `sub_<va>` -- the exact scenario Phase F2 / A3
/// targets. When `discovered_name` already looks real (anything other than
/// `sub_<hex>`) we keep it so we don't trample a stronger DWARF / FLIRT /
/// IAT label that the CFG pass already applied.
fn resolve_outer_function_name(
    discovered_name: &str,
    func_va: u64,
    addr_map: &std::collections::HashMap<u64, String>,
) -> String {
    if !discovered_name.starts_with("sub_") {
        return discovered_name.to_string();
    }
    match addr_map.get(&func_va) {
        Some(name) if !name.is_empty() && !name.starts_with("sub_") => name.clone(),
        _ => discovered_name.to_string(),
    }
}

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
