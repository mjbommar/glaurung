//! Dispatch-aware ioctlance-style scanner for Windows drivers.
//!
//! Combines native IOCTL dispatch discovery (analysis::ioctl_surface) with the
//! symbolic IRP sink detectors. Unlike examples/ioctl_scan.rs (which lifts every
//! function and assumes rcx/rdx are attacker-controlled everywhere -> a flood of
//! null-deref false positives), this seeds analysis ONLY at the real dispatch
//! handlers recovered from the binary, then follows the call graph a bounded
//! number of hops. That is the precision the assume-tainted-everywhere model
//! lacks: a sink only counts if it sits in code reachable from an IOCTL handler.
//!
//! Run: cargo run --release --features solver-z3 --example ioctlance -- <file.sys>

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::analysis::ioctl_surface::map_ioctl_surface;
use glaurung::analysis::pe_iat::pe_iat_map;
use glaurung::core::binary::Arch;
use glaurung::ir::lift_function::lift_function_from_bytes;
use glaurung::ir::types::{CallTarget, LlirFunction, Op, Value};
use glaurung::symbolic::{
    driver_api_model, find_function_sinks_with_apis, find_function_stateful_sinks,
    find_ioctl_sinks_with_apis, set_solver_budget, set_time_budget, ApiSummary, SinkKind,
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
        SinkKind::ArbitraryMsrWrite => "arbitrary-wrmsr",
        SinkKind::ArbitraryMsrRead => "arbitrary-rdmsr",
        SinkKind::PortAccess => "arbitrary-portio",
    }
}

/// True if the taint set names a genuine attacker source (an IRP buffer /
/// IoControlCode / *attacker), as opposed to a bare "ArgN" register from the
/// assume-tainted-entry model. A dereference of a raw parameter pointer (ArgN)
/// is normal code; an IRP-buffer-derived one is attacker-controlled.
fn is_attacker_real(taint: &[String]) -> bool {
    taint.iter().any(|t| {
        let t = t.trim_start_matches('*');
        let is_argn = t.len() > 3
            && t.starts_with("Arg")
            && t[3..].chars().all(|c| c.is_ascii_digit());
        !is_argn
    })
}

/// Write-class primitives -- a write-what-where / UAF / overflow is worth
/// surfacing even when only ArgN-tainted, because the engine's intra-procedural
/// model loses IRP-content taint across the dispatcher->handler call. Reads and
/// null-derefs are excluded here: they are far noisier under the ArgN model.
fn is_write_class(k: SinkKind) -> bool {
    matches!(
        k,
        SinkKind::ControlledWrite
            | SinkKind::UseAfterFree
            | SinkKind::DoubleFree
            | SinkKind::DoubleFetch
            | SinkKind::IntegerOverflow
            | SinkKind::PhysicalMemory
            | SinkKind::Shellcode
            | SinkKind::ProbeBypass
            | SinkKind::FormatString
            | SinkKind::ArbitraryMsrWrite
            | SinkKind::PortAccess
    )
}

/// Confidence gate. Only genuine IRP-buffer taint (UserBuffer/SystemBuffer/
/// *attacker/Type3InputBuffer) is reliable: the assume-tainted-entry model labels
/// every parameter ArgN, so a memory op through a param pointer reads as an
/// "Arbitrary" primitive (read OR write) even in ordinary code. Empirically,
/// keeping ArgN write-class findings re-floods (afd 343, qcwlan 793), so we gate
/// strictly on real attacker taint. NOTE: this bounds RECALL -- a handler-internal
/// bug whose IRP taint the intra-procedural engine lost across the dispatcher
/// call (e.g. mlx4_bus) is not recovered. Interprocedural IRP-taint propagation
/// in the symbolic engine is the real fix; see the engine TODO.
fn is_high_confidence(_kind: SinkKind, taint: &[String], _role: &str) -> bool {
    is_attacker_real(taint)
}

fn references_irp(lf: &LlirFunction) -> bool {
    lf.blocks
        .iter()
        .flat_map(|b| &b.instrs)
        .any(|ins| matches!(&ins.op, Op::Load { addr, .. } if addr.disp == 0xB8))
}

/// True if the function calls a pool-free API (direct or via an IAT thunk slot).
/// Gates the expensive stateful multi-round pass to free-touching functions only.
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

fn reach_hops() -> usize {
    std::env::var("IOCTLANCE_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4)
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: ioctlance <driver.sys>");
    let data = std::fs::read(&path).expect("read file");

    // 1) Native dispatch discovery: the precise IOCTL entry set.
    let surface = map_ioctl_surface(&data, 2, false);
    let mut roots: BTreeSet<u64> = BTreeSet::new();
    for d in &surface.dispatchers {
        roots.insert(d.va);
        for h in d.jump_table.values() {
            roots.insert(*h);
        }
        for (h, _) in &d.handlers {
            roots.insert(*h);
        }
        for c in &d.cmp_codes {
            if let Some(h) = c.handler_va {
                roots.insert(h);
            }
        }
    }
    // KMDF callback roots (EvtIoDeviceControl & friends, reached via the WDF function
    // table): seed analysis here and treat them as dispatch entries so the engine applies
    // full request/IRP taint -- otherwise pure-KMDF drivers are analysed not-at-all.
    for r in &surface.callback_roots {
        roots.insert(*r);
    }
    let mut dispatch_vas: BTreeSet<u64> = surface.dispatchers.iter().map(|d| d.va).collect();
    dispatch_vas.extend(surface.callback_roots.iter().copied());

    // 2) Call graph -> reachable set from the dispatch roots (bounded hops).
    let (funcs, _cg) = analyze_functions_bytes(&data, &Budgets::default());
    let by_va: BTreeMap<u64, &_> = funcs.iter().map(|f| (f.entry_point.value, f)).collect();
    let hops = reach_hops();
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    let mut q: VecDeque<(u64, usize)> = roots.iter().map(|&r| (r, 0)).collect();
    while let Some((va, d)) = q.pop_front() {
        if !reachable.insert(va) || d >= hops {
            continue;
        }
        if let Some(f) = by_va.get(&va) {
            for callee in &f.callees {
                if !reachable.contains(&callee.value) {
                    q.push_back((callee.value, d + 1));
                }
            }
        }
    }

    let iat = pe_iat_map(&data);
    let imports: BTreeMap<String, u64> = iat.iter().map(|(s, n)| (n.clone(), *s)).collect();
    let mut model = driver_api_model(&imports);
    // Alias import call-stub thunks to their target IAT slot's summary, so a direct
    // `call <thunk>` (the non-dllimport form the compiler emits for memcpy/sprintf
    // and friends) is recognised the same as `call *[__imp_x]`. Without this, a
    // CopyMemory/format-string/etc. reached through a thunk is invisible.
    for (&thunk_va, &slot_va) in &surface.import_thunks {
        if let Some(summary) = model.get(&slot_va).copied() {
            model.insert(thunk_va, summary);
        }
    }
    // IAT slots of the pool-free APIs: gate the stateful pass on functions that
    // actually free (the alloc->free->free / alloc->free->use lifecycle bugs a
    // single-path run structurally cannot see -- they span IOCTL command branches
    // with the pointer persisted in a global).
    let free_slots: BTreeSet<u64> = model
        .iter()
        .filter(|(_, s)| matches!(s, ApiSummary::Free { .. }))
        .map(|(va, _)| *va)
        .collect();

    eprintln!(
        "[{}] dispatchers={} kmdf-roots={} dispatch-roots={} reachable-fns={} (of {}) imports={}",
        path,
        surface.dispatchers.len(),
        surface.callback_roots.len(),
        roots.len(),
        reachable.len(),
        funcs.len(),
        iat.len(),
    );

    set_solver_budget(4000, 16);
    set_time_budget(Some(std::time::Duration::from_secs(2)));
    const STATES: usize = 300;
    const MAX_BLOCKS: usize = 200;

    // 3) Symbolic sinks, only over dispatch-reachable functions.
    let show_all = std::env::var_os("IOCTLANCE_ALL").is_some();
    let t = std::time::Instant::now();
    // Global per-driver wall-clock budget. A batch analysis tool must never hang on a
    // single driver: a KMDF driver with thousands of address-taken callbacks can seed a
    // huge reachable set (rtwlanu: 1552 reachable fns), and analysing them all blows any
    // sweep timeout. Once the budget is hit we stop opening NEW functions and report the
    // coverage honestly (analysed/reachable), rather than being SIGKILLed with no output.
    let deadline = std::time::Duration::from_secs(
        std::env::var("IOCTLANCE_DEADLINE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(150),
    );
    let mut lines: Vec<String> = Vec::new();
    let mut raw = 0usize;
    let mut suppressed = 0usize;
    let mut analyzed = 0usize;
    let mut deadline_hit = false;
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in &funcs {
        let va = f.entry_point.value;
        if !reachable.contains(&va) {
            continue;
        }
        if t.elapsed() > deadline {
            deadline_hit = true;
            break;
        }
        analyzed += 1;
        let lf = match lift_function_from_bytes(&data, f, Arch::X86_64) {
            Some(lf) => lf,
            None => continue,
        };
        if lf.blocks.len() > MAX_BLOCKS {
            continue;
        }
        // Dispatchers / IRP-chasers get the IRP-seeded pass; handlers and their
        // callees (reached from a handler, so called with attacker IRP buffers)
        // get the tainted-args pass.
        let mut sinks = if dispatch_vas.contains(&va) || references_irp(&lf) {
            find_ioctl_sinks_with_apis(&lf, &model, STATES)
        } else {
            Vec::new()
        };
        sinks.extend(find_function_sinks_with_apis(&lf, &model, STATES));
        // Cross-invocation lifecycle pass (UAF / double-free): only on free-touching
        // functions, carrying heap/global state forward across rounds. This pass is
        // multiplicative in cost (states x rounds), so bound it: alloc/free/use
        // lifecycle bugs sit in focused command handlers, not giant (>STATEFUL_MAX_BLOCKS)
        // dispatch monoliths. Skipping those keeps WiFi-class drivers (many large
        // free-touching handlers) from blowing the time budget -- rtwlane/rtwlanu went
        // 110s -> >180s without this cap. The bounded pass still fires on every real
        // lifecycle control we have. Tunable via IOCTLANCE_STATEFUL_BLOCKS.
        const STATEFUL_MAX_BLOCKS: usize = 48;
        let stateful_cap = std::env::var("IOCTLANCE_STATEFUL_BLOCKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(STATEFUL_MAX_BLOCKS);
        if lf.blocks.len() <= stateful_cap && references_free(&lf, &free_slots) {
            sinks.extend(find_function_stateful_sinks(&lf, &model, STATES * 2, 3));
        }
        let mut seen = BTreeSet::new();
        for s in &sinks {
            if !seen.insert((kind_str(s.kind), s.va)) {
                continue;
            }
            raw += 1;
            let role = if dispatch_vas.contains(&va) {
                "dispatch"
            } else if roots.contains(&va) {
                "handler"
            } else {
                "callee"
            };
            // Precision gate: keep genuine attacker-tainted sinks and write-class
            // primitives in handlers; drop bare ArgN read/null-deref noise.
            if !show_all && !is_high_confidence(s.kind, &s.tainted_by, role) {
                suppressed += 1;
                continue;
            }
            *by_kind.entry(kind_str(s.kind)).or_insert(0) += 1;
            // sort key: write-class first, then severity, then va
            let rank = (
                if is_write_class(s.kind) { 0 } else { 1 },
                match s.severity {
                    glaurung::symbolic::Severity::Arbitrary => 0,
                    glaurung::symbolic::Severity::Constrained => 1,
                },
            );
            lines.push(format!(
                "{}{}\t  {:>16}  va={:#010x}  [{}] fn={} @ {:#x}  sev={:?}  taint={:?}",
                rank.0,
                rank.1,
                kind_str(s.kind),
                s.va,
                role,
                f.name,
                va,
                s.severity,
                s.tainted_by,
            ));
        }
    }
    eprintln!(
        "[symbolic] {:?}  raw={} high-confidence={} suppressed={} (ArgN pointer-deref noise)  analyzed={}/{}{}",
        t.elapsed(),
        raw,
        lines.len(),
        suppressed,
        analyzed,
        reachable.len(),
        if deadline_hit {
            " DEADLINE-HIT (coverage bounded; raise IOCTLANCE_DEADLINE_SECS)"
        } else {
            ""
        },
    );
    eprintln!("[by-kind] {:?}", by_kind);
    lines.sort();
    for l in &lines {
        println!("{}", l.splitn(2, '\t').nth(1).unwrap_or(l));
    }
}
