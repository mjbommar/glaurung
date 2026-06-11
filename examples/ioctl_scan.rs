//! Minimal end-to-end IOCTLance-style scan of a real Windows driver `.sys`.
//!
//! This is the *first slice* of the PE→handler bridge: it does **not** yet do
//! precise DriverEntry→MajorFunction[14] dispatch discovery. Instead it lifts
//! every discovered function, seeds each with a symbolic IRP (per the WDM ABI),
//! resolves the driver's IAT imports to API summaries, and runs the symbolic sink
//! detectors. Non-handler functions seldom chase the IRP, so the dispatch handler
//! is where attacker-tainted sinks light up.
//!
//! Run: `cargo run --release --features solver-z3 --example ioctl_scan -- <file.sys>`

use std::collections::{BTreeMap, BTreeSet};

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::analysis::pe_iat::pe_iat_map;
use glaurung::core::binary::Arch;
use glaurung::ir::lift_function::lift_function_from_bytes;
use glaurung::symbolic::{
    driver_api_model, find_function_sinks_with_apis, find_ioctl_sinks_with_apis, SinkKind,
};

fn kind_str(k: SinkKind) -> &'static str {
    match k {
        SinkKind::ControlledWrite => "arbitrary-write",
        SinkKind::ControlledRead => "arbitrary-read",
        SinkKind::NullDeref => "null-deref",
        SinkKind::StackOverflow => "stack-overflow",
        SinkKind::UseAfterFree => "use-after-free",
        SinkKind::DoubleFree => "double-free",
        SinkKind::IntegerOverflow => "integer-overflow",
        SinkKind::DoubleFetch => "double-fetch",
        SinkKind::Shellcode => "shellcode",
        SinkKind::FormatString => "format-string",
        SinkKind::PhysicalMemory => "physical-memory",
        SinkKind::ProbeBypass => "probe-bypass",
        SinkKind::ProcessTermination => "process-termination",
        SinkKind::FileOperation => "file-operation",
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: ioctl_scan <driver.sys>");
    let data = std::fs::read(&path).expect("read file");

    let (funcs, _cg) = analyze_functions_bytes(&data, &Budgets::default());

    // IAT slot VA -> import name -> API summary. `call [rip+disp]` lifts to
    // Indirect(Addr(slot)), which the engine resolves against this model.
    let iat = pe_iat_map(&data);
    let mut imports: BTreeMap<String, u64> = BTreeMap::new();
    for (slot, name) in &iat {
        imports.insert(name.clone(), *slot);
    }
    let model = driver_api_model(&imports);

    eprintln!(
        "[{}] functions={} imports={} modeled_apis={}",
        path,
        funcs.len(),
        iat.len(),
        model.len()
    );

    let mut total = 0usize;
    for f in &funcs {
        let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) else {
            continue;
        };
        // Two seeds: the dispatcher's symbolic IRP, and assume-tainted-entry for
        // the per-IOCTL helper functions the dispatcher delegates to.
        let mut sinks = find_ioctl_sinks_with_apis(&lf, &model, 4000);
        sinks.extend(find_function_sinks_with_apis(&lf, &model, 4000));
        if sinks.is_empty() {
            continue;
        }
        let mut seen = BTreeSet::new();
        for s in &sinks {
            if !seen.insert((kind_str(s.kind), s.va)) {
                continue;
            }
            total += 1;
            println!(
                "  {:>18}  va={:#010x}  fn={} @ {:#x}  severity={:?}  taint={:?}",
                kind_str(s.kind),
                s.va,
                f.name,
                f.entry_point.value,
                s.severity,
                s.tainted_by,
            );
        }
    }
    eprintln!("[{}] total unique sinks: {}", path, total);
}
