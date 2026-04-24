use glaurung::ir::ast::{lower, render};
use glaurung::ir::expr_reconstruct::reconstruct;
use glaurung::ir::ssa::compute_ssa;
use glaurung::ir::structure::recover;
use glaurung::ir::lift_function::lift_function_from_bytes;
use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::core::binary::Arch;
use glaurung::ir::arm64_prologue::recognise_arm64_prologue;
use glaurung::ir::naming::apply_role_names;
use glaurung::ir::call_args::CallConv;

fn main() {
    let data = std::fs::read("samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc").unwrap();
    let (funcs, _) = analyze_functions_bytes(&data, &Budgets::default());
    let main = funcs.iter().find(|f| f.entry_point.value == 0x700).unwrap();
    let lf = lift_function_from_bytes(&data, main, Arch::AArch64).unwrap();
    let ssa = compute_ssa(&lf);
    let r = recover(&lf, &ssa);
    let mut f = lower(&lf, &r, main.name.clone());
    reconstruct(&mut f);
    glaurung::ir::stack_locals::promote_stack_locals(&mut f);
    apply_role_names(&mut f, CallConv::Aarch64);
    println!("Body after stack_locals+naming, before arm64_prologue:");
    for (i, s) in f.body.iter().take(8).enumerate() {
        println!("  [{i}] {s:?}");
    }
    recognise_arm64_prologue(&mut f);
    println!("\nAfter arm64_prologue (first 5):");
    for (i, s) in f.body.iter().take(5).enumerate() {
        println!("  [{i}] {s:?}");
    }
    println!("\nLast 10 stmts:");
    let len = f.body.len();
    for (i, s) in f.body.iter().enumerate().skip(len.saturating_sub(10)) {
        println!("  [{i}] {s:?}");
    }
}
