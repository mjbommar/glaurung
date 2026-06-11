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
use glaurung::ir::types::{CallTarget, LlirFunction, Op, Value};
use glaurung::symbolic::{
    driver_api_model, find_function_sinks_with_apis, find_function_stateful_sinks,
    find_ioctl_sinks_with_apis, set_solver_budget, set_time_budget, ApiSummary, SinkKind,
};
use rayon::prelude::*;

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

    // IAT slots that free a heap block — the stateful (cross-invocation) sweep is
    // only meaningful for functions that can reach one.
    let free_slots: BTreeSet<u64> = model
        .iter()
        .filter(|(_, s)| matches!(s, ApiSummary::Free { .. }))
        .map(|(va, _)| *va)
        .collect();

    // Lift all functions in parallel (lifting is pure and thread-safe), then run
    // the symbolic passes sequentially — the z3 backend is not safe under
    // concurrent solving. Two cheap passes always; the 4-round stateful sweep only
    // where a free is reachable.
    let t_lift = std::time::Instant::now();
    let lifted: Vec<(&_, LlirFunction)> = funcs
        .par_iter()
        .filter_map(|f| lift_function_from_bytes(&data, f, Arch::X86_64).map(|lf| (f, lf)))
        .collect();
    eprintln!(
        "[lift] {} functions in {:?}",
        lifted.len(),
        t_lift.elapsed()
    );
    let t_sym = std::time::Instant::now();

    // Per-function safety caps so no single (e.g. obfuscated) function can stall
    // the scan: a solver-call / timeout budget, plus a wall-clock deadline that
    // catches functions whose solves are slow-but-not-timing-out.
    set_solver_budget(4000, 16);
    set_time_budget(Some(std::time::Duration::from_secs(2)));

    // State caps bound the worst-case (a few functions explode); the synthetic
    // handlers and the real arbitrary-write sites are found well within these.
    const BROAD_STATES: usize = 300;
    const STATEFUL_STATES: usize = 1200;
    // Skip only genuinely huge functions; the solver budget handles the rest.
    const MAX_BLOCKS: usize = 200;

    // Global scan deadline: even with per-function caps, a large corpus of
    // individually-slow functions can add up, so bound the whole scan and report
    // partial results rather than run unboundedly.
    let scan_deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(scan_budget_secs());

    // Cheap obfuscation indicator: fraction of functions that are loop-heavy.
    let loopy = lifted.iter().filter(|(_, lf)| back_edges(lf) >= 4).count();
    eprintln!(
        "[obfuscation] {}/{} functions are loop-heavy (>=4 back-edges)",
        loopy,
        lifted.len()
    );

    let mut skipped = 0usize;
    let mut budget_cut = 0usize;
    let mut lines: Vec<String> = Vec::new();
    for (f, lf) in &lifted {
        if std::time::Instant::now() >= scan_deadline {
            budget_cut += 1;
            continue;
        }
        if lf.blocks.len() > MAX_BLOCKS {
            skipped += 1;
            continue;
        }
        if std::env::var_os("IOCTL_SCAN_TRACE").is_some() {
            let n_ins: usize = lf.blocks.iter().map(|b| b.instrs.len()).sum();
            eprintln!(
                "[fn] {} @ {:#x} blocks={} ins={}",
                f.name,
                f.entry_point.value,
                lf.blocks.len(),
                n_ins
            );
        }
        // The IRP-seed pass only matters for the dispatch handler, recognized by
        // its chase of Irp->CurrentStackLocation (offset 0xB8). Every other
        // function is covered by the assume-tainted-entry pass alone.
        let mut sinks = if references_irp(lf) {
            find_ioctl_sinks_with_apis(lf, &model, BROAD_STATES)
        } else {
            Vec::new()
        };
        sinks.extend(find_function_sinks_with_apis(lf, &model, BROAD_STATES));
        if references_free(lf, &free_slots) {
            sinks.extend(find_function_stateful_sinks(lf, &model, STATEFUL_STATES, 4));
        }
        let mut seen = BTreeSet::new();
        for s in &sinks {
            if !seen.insert((kind_str(s.kind), s.va)) {
                continue;
            }
            // (severity rank, kind, va) prefix sorts high-signal findings first.
            let rank = match s.severity {
                glaurung::symbolic::Severity::Arbitrary => 0,
                glaurung::symbolic::Severity::Constrained => 1,
            };
            lines.push(format!(
                "{}\t  {:>18}  va={:#010x}  fn={} @ {:#x}  severity={:?}  taint={:?}",
                rank,
                kind_str(s.kind),
                s.va,
                f.name,
                f.entry_point.value,
                s.severity,
                s.tainted_by,
            ));
        }
    }

    eprintln!("[symbolic] {:?}", t_sym.elapsed());
    lines.sort();
    for l in &lines {
        // strip the sort-key prefix before printing
        println!("{}", l.splitn(2, '\t').nth(1).unwrap_or(l));
    }
    eprintln!(
        "[{}] total unique sinks: {} (skipped {} oversized, {} past scan budget)",
        path,
        lines.len(),
        skipped,
        budget_cut
    );
}

/// Count a function's CFG back-edges — a successor that targets a block at or
/// before the current block's start. Many back-edges (loops) is the cheap
/// obfuscation signal: control-flow-flattened / VM-obfuscated code is loop-heavy,
/// and the symbolic engine's loop bound (not this count) is what keeps it cheap.
/// Surfacing the count lets a scan flag "this driver looks obfuscated".
fn back_edges(lf: &LlirFunction) -> usize {
    lf.blocks
        .iter()
        .flat_map(|b| b.succs.iter().map(move |&t| (b.start_va, t)))
        .filter(|&(start, target)| target <= start)
        .count()
}

/// Whole-scan wall-clock budget in seconds (override with `IOCTL_SCAN_BUDGET`).
fn scan_budget_secs() -> u64 {
    std::env::var("IOCTL_SCAN_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90)
}

/// True if `lf` chases `Irp->Tail.Overlay.CurrentStackLocation` (offset 0xB8) —
/// the distinctive move of an IOCTL dispatch handler, used to gate the (more
/// expensive) IRP-seed pass to plausible handlers.
fn references_irp(lf: &LlirFunction) -> bool {
    lf.blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .any(|ins| matches!(&ins.op, Op::Load { addr, .. } if addr.disp == 0xB8))
}

/// True if any op in `lf` references a free-summarized IAT slot — either a
/// `call [rip+slot]` (`Indirect(Addr)`) or the `mov reg,[slot]; call reg` form
/// (a `Load` whose displacement is the slot). Cheap gate for the stateful sweep.
fn references_free(lf: &LlirFunction, free_slots: &BTreeSet<u64>) -> bool {
    if free_slots.is_empty() {
        return false;
    }
    lf.blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .any(|ins| match &ins.op {
            Op::Load { addr, .. } => free_slots.contains(&(addr.disp as u64)),
            Op::Call {
                target: CallTarget::Indirect(Value::Addr(va)),
            }
            | Op::Call {
                target: CallTarget::Direct(va),
            } => free_slots.contains(va),
            _ => false,
        })
}
