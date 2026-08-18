//! Lifting raw bytes into LLIR, and encoding LLIR ops as Python dicts.
//!
//! The dict shape produced here is the one the parent module's header
//! documents; `encode_op` is the function that header points at.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use super::load_program_image;
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
pub(super) fn lift_bytes_py(
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
pub(super) fn lift_window_at_py(
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
