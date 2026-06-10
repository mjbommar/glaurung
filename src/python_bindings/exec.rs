//! Python bindings for the native execution engine (concrete emulator).
//!
//! Dict-based surface (like `ir`), since the engine is young and evolving.
//! `emulate_function(path, entry_va, arch=…, max_steps=…)` discovers + lifts the
//! function at `entry_va`, runs it on the concrete emulator, and returns a dict:
//!
//! ```text
//! { "outcome": "returned" | "called_out" | "halted" | "budget_exhausted"
//!            | "no_block",
//!   "detail": str | None,     # e.g. unresolved call target / halt reason
//!   "steps": int,             # instructions retired
//!   "regs": { "rax": int, ... } }
//! ```

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
use crate::core::binary::Arch;
use crate::exec::{Budget, Concrete, Domain, Machine, Outcome, RegArch};
use crate::ir::lift_function::lift_function_from_bytes;
use crate::ir::types::{VReg, Width};

/// Map an arch string to `(Arch, RegArch)` and the registers to report.
fn arch_for(name: &str) -> PyResult<(Arch, RegArch, &'static [&'static str])> {
    const X86_64_REGS: &[&str] = &[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "rip",
    ];
    const ARM64_REGS: &[&str] = &[
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "x29", "x30", "sp",
    ];
    match name.to_ascii_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => Ok((Arch::X86_64, RegArch::X86_64, X86_64_REGS)),
        "arm64" | "aarch64" => Ok((Arch::AArch64, RegArch::AArch64, ARM64_REGS)),
        other => Err(PyValueError::new_err(format!(
            "unsupported arch for emulation: {:?} (use x86_64 or arm64)",
            other
        ))),
    }
}

#[pyfunction]
#[pyo3(name = "emulate_function")]
#[pyo3(signature = (binary_path, entry_va, arch="x86_64", max_steps=100_000))]
fn emulate_function_py(
    py: Python<'_>,
    binary_path: &str,
    entry_va: u64,
    arch: &str,
    max_steps: u64,
) -> PyResult<Py<PyDict>> {
    let (cfg_arch, reg_arch, regs) = arch_for(arch)?;

    let data = std::fs::read(binary_path)
        .map_err(|e| PyValueError::new_err(format!("read {}: {}", binary_path, e)))?;

    let (funcs, _cg) = analyze_functions_bytes(
        &data,
        &Budgets {
            max_functions: 256,
            max_blocks: 1024,
            max_instructions: 100_000,
            timeout_ms: 5000,
        },
    );
    let func = funcs
        .iter()
        .find(|f| f.entry_point.value == entry_va)
        .ok_or_else(|| PyValueError::new_err(format!("no function discovered at {:#x}", entry_va)))?;

    let lf = lift_function_from_bytes(&data, func, cfg_arch)
        .ok_or_else(|| PyValueError::new_err("failed to lift function (unsupported arch?)"))?;

    let mut m = Machine::new_with_arch(Concrete, reg_arch);
    // A sane, aligned stack pointer so push/pop/[sp+d] land in plausible memory.
    let sp_name = if reg_arch == RegArch::AArch64 { "sp" } else { "rsp" };
    let sp = m.dom.constant(Width::W64, 0x7fff_ffff_0000);
    m.regs.write(&mut m.dom, &VReg::phys(sp_name), sp);

    let mut budget = Budget::new(max_steps);
    let outcome = m.run_function(&lf, &mut budget);

    let (kind, detail): (&str, Option<String>) = match &outcome {
        Outcome::Returned => ("returned", None),
        Outcome::CalledOut(t) => ("called_out", t.map(|a| format!("{:#x}", a))),
        Outcome::Halted(h) => ("halted", Some(format!("{:?}", h))),
        Outcome::BudgetExhausted => ("budget_exhausted", None),
        Outcome::NoBlock(a) => ("no_block", Some(format!("{:#x}", a))),
    };

    let out = PyDict::new(py);
    out.set_item("outcome", kind)?;
    out.set_item("detail", detail)?;
    out.set_item("steps", budget.spent())?;
    let regs_dict = PyDict::new(py);
    for name in regs {
        let v = m.regs.read(&mut m.dom, &VReg::phys(*name));
        regs_dict.set_item(*name, v)?;
    }
    out.set_item("regs", regs_dict)?;
    Ok(out.into())
}

pub fn register_exec_bindings(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Exposed to Python as `glaurung.engine` (avoids shadowing the `exec`
    // builtin).
    let engine_mod = PyModule::new(py, "engine")?;
    engine_mod.add_function(wrap_pyfunction!(emulate_function_py, &engine_mod)?)?;
    m.add_submodule(&engine_mod)?;
    Ok(())
}
