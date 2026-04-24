use glaurung::ir::ast::{lower, render};
use glaurung::ir::expr_reconstruct::reconstruct;
use glaurung::ir::ssa::compute_ssa;
use glaurung::ir::structure::recover;
use glaurung::ir::lift_function::lift_function_from_bytes;
use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::core::binary::Arch;
use glaurung::ir::naming::apply_role_names;
use glaurung::ir::call_args::CallConv;
use glaurung::ir::{const_fold, dce, dead_stores, canary, name_resolve, strings_fold, stack_locals};

fn main() {
    let data = std::fs::read("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2").unwrap();
    let (funcs, _) = analyze_functions_bytes(&data, &Budgets::default());
    let main_fn = funcs.iter().find(|f| f.entry_point.value == 0x10c0).unwrap();
    let lf = lift_function_from_bytes(&data, main_fn, Arch::X86_64).unwrap();
    let ssa = compute_ssa(&lf);
    let r = recover(&lf, &ssa);
    let mut f = lower(&lf, &r, main_fn.name.clone());
    reconstruct(&mut f);
    const_fold::fold_constants(&mut f);
    dce::prune_dead_flags(&mut f);
    let cc = CallConv::SysVAmd64;
    glaurung::ir::call_args::reconstruct_args(&mut f, cc);
    let addr_map = name_resolve::collect_address_map(&data, "");
    name_resolve::resolve_names(&mut f, &addr_map);
    let sp = strings_fold::collect_string_pool(&data);
    strings_fold::fold_string_literals(&mut f, &sp);
    canary::recognise_canary(&mut f);
    stack_locals::promote_stack_locals(&mut f);
    apply_role_names(&mut f, cc);

    // Before canary::collapse_canary_save — print positions around reload.
    println!("=== Before collapse_canary_save ===");
    for (i, s) in f.body.iter().enumerate() {
        let text = format!("{:?}", s);
        if text.contains("stack_0") || text.contains("canary") {
            println!("  [{i}] {text}");
        }
    }

    // Before calling collapse_canary_save, examine the neighbourhood of
    // the reload in full detail.
    let mut reload_idx = None;
    for (i, s) in f.body.iter().enumerate() {
        if format!("{:?}", s).contains("src: Reg(Phys(\"stack_0\"))") {
            reload_idx = Some(i);
            break;
        }
    }
    if let Some(ri) = reload_idx {
        println!("\n=== Reload ±3 shape (before collapse_canary_save) ===");
        let lo = ri.saturating_sub(2);
        let hi = (ri + 3).min(f.body.len() - 1);
        for j in lo..=hi {
            println!("  [{j}] {:?}", f.body[j]);
        }
    }

    canary::collapse_canary_save(&mut f);
    println!("\n=== After collapse_canary_save ===");
    for (i, s) in f.body.iter().enumerate() {
        let text = format!("{:?}", s);
        if text.contains("stack_0") || text.contains("canary") || text.contains("Comment") {
            println!("  [{i}] {text}");
        }
    }
    let _ = render(&f);
    // Also: apply dead_stores + label_prune like the full pipeline, then
    // see if the shape got lost.
    dead_stores::eliminate_dead_stores(&mut f, cc);
    println!("\n=== After dead_stores ===");
    for (i, s) in f.body.iter().enumerate() {
        let text = format!("{:?}", s);
        if text.contains("stack_0") || text.contains("canary") || text.contains("Comment") {
            println!("  [{i}] {text}");
        }
    }
}
