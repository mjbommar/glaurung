//! Render the pseudocode AST for the first few discovered functions in a
//! binary. Run with: `cargo run --release --example ast_demo -- <path>`.
//!
//! Useful for eyeballing the quality of LLIR lifting + structural analysis +
//! AST lowering end-to-end.

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::core::binary::Arch;
use glaurung::ir::{ast, lift_function::lift_function_from_bytes, ssa, structure};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2".to_string()
    });
    let data = std::fs::read(&path).expect("read sample");
    let (funcs, _) = analyze_functions_bytes(&data, &Budgets::default());
    for f in &funcs[..funcs.len().min(4)] {
        if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
            let sinfo = ssa::compute_ssa(&lf);
            let r = structure::recover(&lf, &sinfo);
            let astf = ast::lower(&lf, &r, f.name.clone());
            println!("{}", ast::render(&astf));
        }
    }
}
