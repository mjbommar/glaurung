use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::core::binary::Arch;
use glaurung::ir::ast::{lower_with_identities, render};
use glaurung::ir::call_args::CallConv;
use glaurung::ir::expr_reconstruct::reconstruct;
use glaurung::ir::lift_function::lift_function_from_bytes;
use glaurung::ir::naming::{role_named_render_view, role_names_with_identities};
use glaurung::ir::ssa::compute_ssa;
use glaurung::ir::structure::recover;
use glaurung::ir::value_number::value_number_with_parameter_slots_lifetimes_and_identities;
use glaurung::ir::{
    canary, const_fold, dce, dead_stores, name_resolve, stack_locals, strings_fold,
};

fn main() {
    let data =
        std::fs::read("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/c2_demo-gcc-O2")
            .unwrap();
    let (funcs, _) = analyze_functions_bytes(&data, &Budgets::default());
    let main_fn = funcs
        .iter()
        .find(|f| f.entry_point.value == 0x10c0)
        .unwrap();
    let lf = lift_function_from_bytes(&data, main_fn, Arch::X86_64).unwrap();
    let cc = CallConv::SysVAmd64;
    let ssa = compute_ssa(&lf);
    let r = recover(&lf, &ssa);
    let (numbered, _widths, param_slots, identities) =
        value_number_with_parameter_slots_lifetimes_and_identities(&lf, &ssa, cc, &[]);
    let mut f = lower_with_identities(&numbered, &r, main_fn.name.clone(), &identities);
    reconstruct(&mut f);
    const_fold::fold_constants_with_identities(&mut f, &identities);
    dce::prune_dead_flags(&mut f);
    glaurung::ir::call_args::reconstruct_args(&mut f, cc);
    let addr_map = name_resolve::collect_address_map(&data, "");
    name_resolve::resolve_names(&mut f, &addr_map);
    let sp = strings_fold::collect_string_pool(&data);
    strings_fold::fold_string_literals(&mut f, &sp);
    canary::recognise_canary(&mut f);
    stack_locals::promote_stack_locals(&mut f);

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
    let empty_roles = std::collections::HashMap::new();
    let roles = role_names_with_identities(
        &f,
        cc,
        &param_slots,
        &empty_roles,
        &empty_roles,
        &identities,
    );
    let _ = render(&role_named_render_view(&f, &roles));
    // Also: apply dead_stores + label_prune like the full pipeline, then
    // see if the shape got lost.
    dead_stores::eliminate_dead_stores_with_identities(&mut f, cc, &identities);
    println!("\n=== After dead_stores ===");
    for (i, s) in f.body.iter().enumerate() {
        let text = format!("{:?}", s);
        if text.contains("stack_0") || text.contains("canary") || text.contains("Comment") {
            println!("  [{i}] {text}");
        }
    }
}
