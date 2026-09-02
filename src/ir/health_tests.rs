use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::health::{measure, snapshot, AstHealth, CfgHealth};
use crate::ir::structure_accounting::AccountError;
use crate::ir::types::{BinOp, VReg};

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

#[test]
fn health_counts_nested_output_risks_without_parsing_rendered_c() {
    let function = Function {
        name: "health_canary".into(),
        entry_va: 0x1000,
        body: vec![
            Stmt::Assign {
                dst: reg("var0"),
                src: Expr::Reg(reg("arg0")),
            },
            Stmt::Assign {
                dst: reg("var2"),
                src: Expr::Reg(reg("var1")),
            },
            Stmt::Store {
                addr: Expr::Bin {
                    op: BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rbp"))),
                    rhs: Box::new(Expr::Const(32)),
                },
                src: Expr::Reg(reg("var0")),
                size: 8,
            },
            Stmt::If {
                cond: Expr::Reg(reg("var0")),
                then_body: vec![Stmt::Goto { target: 0x1010 }],
                else_body: Some(vec![Stmt::IndirectGoto {
                    target: Expr::Reg(reg("var0")),
                }]),
            },
            Stmt::Unknown("mystery".into()),
            Stmt::Label(0x1010),
        ],
    };

    assert_eq!(
        measure(&function),
        AstHealth {
            parameters: 1,
            declarations: 4,
            temporaries: 3,
            physical_registers: 1,
            undefined_uses: 2,
            gotos: 1,
            uncovered_cfg_edges: 0,
            invented_cfg_edges: 0,
            structure_fallbacks: 0,
            unknown_cfg_edges: 0,
            terminal_edges: 0,
            unknown_terminal_edges: 0,
            unresolved_indirect_edges: 0,
            indirect_symbol_edges: 0,
            indirect_slot_edges: 0,
            unresolved_transfers: 2,
            statements: 8,
        }
    );
}

#[test]
fn cfg_health_distinguishes_output_edge_defects_from_safety_fallbacks() {
    let findings = vec![
        AccountError::EdgeUnaccounted {
            from: 1,
            to: 2,
            kind: crate::ir::cfg_edges::EdgeKind::Taken,
        },
        AccountError::BackEdgeUnowned { from: 4, to: 1 },
        AccountError::ImpliedEdgeAbsent { from: 2, to: 7 },
        AccountError::EdgeViaGoto {
            from: 3,
            to: 8,
            kind: crate::ir::cfg_edges::EdgeKind::Jump,
        },
    ];

    assert_eq!(
        crate::ir::health::cfg_health_from_accounting(&findings, false),
        CfgHealth {
            uncovered_cfg_edges: 1,
            invented_cfg_edges: 1,
            structure_fallbacks: 0,
            ..CfgHealth::default()
        }
    );
    assert_eq!(
        crate::ir::health::cfg_health_from_accounting(&[], true),
        CfgHealth {
            uncovered_cfg_edges: 0,
            invented_cfg_edges: 0,
            structure_fallbacks: 1,
            ..CfgHealth::default()
        }
    );
}

#[test]
fn machine_register_detection_covers_every_lifted_family_without_roles() {
    for name in [
        "rax", "edi", "xmm15", "st7", "k3", "rflags", "r11", "sp", "lr", "ip", "cpsr", "x29", "w8",
        "xzr", "wzr", "v31", "h4", "eip",
    ] {
        assert!(crate::ir::health::is_machine_register(name), "{name}");
    }
    for name in ["arg0", "var12", "local_8", "stack_16", "ret", "zf_3"] {
        assert!(!crate::ir::health::is_machine_register(name), "{name}");
    }
}

#[test]
fn pass_snapshot_is_stable_machine_readable_evidence() {
    let function = Function {
        name: "trace_me".into(),
        entry_va: 0x401000,
        body: vec![Stmt::Return {
            value: Some(Expr::Reg(reg("arg1"))),
        }],
    };

    let event = snapshot("lower", &function);
    let json = serde_json::to_value(&event).expect("health event serializes");

    assert_eq!(json["schema"], "glaurung-pass-health-v1");
    assert_eq!(json["pass"], "lower");
    assert_eq!(json["function"], "trace_me");
    assert_eq!(json["entry_va"], "0x401000");
    assert_eq!(json["health"]["parameters"], 2);
    assert_eq!(json["health"]["statements"], 1);
}

#[test]
fn pass_snapshot_names_definition_violations_not_only_their_count() {
    let function = Function {
        name: "broken".into(),
        entry_va: 0x402000,
        body: vec![Stmt::Return {
            value: Some(Expr::Reg(reg("var9"))),
        }],
    };

    let event = snapshot("ready_to_render", &function);

    assert_eq!(event.health.undefined_uses, 1);
    assert_eq!(event.violations.len(), 1);
    assert_eq!(event.violations[0].name, "var9");
    assert_eq!(event.violations[0].kind, "never_defined");
}

// --- pre-render verification ledger ----------------------------------------
//
// The ledger is process-global by design (function lowering runs on its own
// spawned stack, so a thread-local one would record nothing). Only these tests
// drain it, so they serialise against each other; they assert about the verdicts
// they themselves recorded and ignore anything a concurrently running
// decompilation test contributed.

static LEDGER_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ledger_guard() -> std::sync::MutexGuard<'static, ()> {
    LEDGER_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn reads_undefined(name: &str, entry_va: u64) -> Function {
    Function {
        name: name.into(),
        entry_va,
        body: vec![Stmt::Return {
            value: Some(Expr::Reg(reg("var9"))),
        }],
    }
}

fn defines_what_it_reads(name: &str, entry_va: u64) -> Function {
    Function {
        name: name.into(),
        entry_va,
        body: vec![
            Stmt::Assign {
                dst: reg("var9"),
                src: Expr::Reg(reg("arg0")),
            },
            Stmt::Return {
                value: Some(Expr::Reg(reg("var9"))),
            },
        ],
    }
}

#[test]
fn a_failed_pre_render_proof_is_recorded_rather_than_dropped() {
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();

    let function = reads_undefined("ledger_broken", 0x4a1000);
    let verification = crate::ir::verify_defs::verify_before_render(&function);
    assert!(!verification.verified());
    crate::ir::health::record_render_verification(&verification);

    let report = crate::ir::health::take_render_verification();
    let recorded = report
        .unverified
        .iter()
        .find(|verdict| verdict.function == "ledger_broken")
        .expect("the failing function is named in the report");
    assert_eq!(recorded.entry_va, "0x4a1000");
    assert_eq!(recorded.undefined_uses, 1);
    assert_eq!(recorded.violations[0].name, "var9");
    assert_eq!(recorded.violations[0].kind, "never_defined");
    assert!(report.undefined_uses >= 1);
}

#[test]
fn a_verified_function_is_counted_but_not_listed_as_a_defect() {
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();

    let function = defines_what_it_reads("ledger_clean", 0x4a2000);
    let verification = crate::ir::verify_defs::verify_before_render(&function);
    assert!(verification.verified());
    crate::ir::health::record_render_verification(&verification);

    let report = crate::ir::health::take_render_verification();
    assert!(report.verified_functions >= 1);
    assert!(
        !report
            .unverified
            .iter()
            .any(|verdict| verdict.function == "ledger_clean"),
        "a function that verifies must not be reported as a defect: {report:?}"
    );
}

#[test]
fn draining_the_ledger_resets_it_so_the_next_run_reports_its_own_functions() {
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();

    let function = reads_undefined("ledger_drained", 0x4a3000);
    crate::ir::health::record_render_verification(&crate::ir::verify_defs::verify_before_render(
        &function,
    ));
    let first = crate::ir::health::take_render_verification();
    assert!(first
        .unverified
        .iter()
        .any(|verdict| verdict.function == "ledger_drained"));

    let second = crate::ir::health::take_render_verification();
    assert!(
        !second
            .unverified
            .iter()
            .any(|verdict| verdict.function == "ledger_drained"),
        "a drained verdict must not be reported twice: {second:?}"
    );
}

#[test]
fn recording_one_function_twice_counts_it_once() {
    // The same function can be re-rendered inside one run (multi-`--vas`, a
    // session replay). Two entries for one defect would inflate every count the
    // ratchet reads, so the ledger is keyed rather than appended to.
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();

    let function = reads_undefined("ledger_repeat", 0x4a4000);
    let verification = crate::ir::verify_defs::verify_before_render(&function);
    crate::ir::health::record_render_verification(&verification);
    crate::ir::health::record_render_verification(&verification);

    let report = crate::ir::health::take_render_verification();
    assert_eq!(
        report
            .unverified
            .iter()
            .filter(|verdict| verdict.function == "ledger_repeat")
            .count(),
        1
    );
}

#[test]
fn the_report_is_ordered_by_entry_address_so_parallel_and_serial_runs_agree() {
    // Design rule 12: serial and parallel analysis must produce identical facts.
    // Renders complete in whatever order the scheduler picks, so insertion order
    // is not a reportable order.
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();

    for entry_va in [0x4a7000u64, 0x4a5000, 0x4a6000] {
        let function = reads_undefined(&format!("ledger_order_{entry_va:x}"), entry_va);
        crate::ir::health::record_render_verification(
            &crate::ir::verify_defs::verify_before_render(&function),
        );
    }

    let report = crate::ir::health::take_render_verification();
    let ours = report
        .unverified
        .iter()
        .filter(|verdict| verdict.function.starts_with("ledger_order_"))
        .map(|verdict| verdict.entry_va.clone())
        .collect::<Vec<_>>();
    assert_eq!(ours, vec!["0x4a5000", "0x4a6000", "0x4a7000"]);
}

fn prototype(
    return_type: &str,
    params: &[&str],
    variadic: bool,
) -> crate::ir::call_contracts::CallPrototype {
    crate::ir::call_contracts::CallPrototype::from_analyst(
        return_type,
        &params
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        variadic,
    )
}

#[test]
fn prototype_conflicts_retain_each_candidate_source_in_stable_order() {
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();
    let authoritative = prototype("long", &["short"], true);
    let dwarf = prototype("int", &["int"], false);
    let inferred = prototype("int", &["unsigned int"], false);

    crate::ir::health::record_prototype_conflict(
        "declared",
        0x4a8000,
        "analyst",
        &authoritative,
        "inferred",
        &inferred,
    );
    crate::ir::health::record_prototype_conflict(
        "declared",
        0x4a8000,
        "analyst",
        &authoritative,
        "dwarf",
        &dwarf,
    );

    let report = crate::ir::health::take_render_verification();
    assert_eq!(report.prototype_conflict_count, 2);
    assert_eq!(
        report
            .prototype_conflicts
            .iter()
            .map(|conflict| conflict.candidate_source.as_str())
            .collect::<Vec<_>>(),
        vec!["dwarf", "inferred"]
    );
}

#[test]
fn an_identical_prototype_is_not_a_conflict() {
    let _serialised = ledger_guard();
    let _ = crate::ir::health::take_render_verification();
    let same = prototype("int", &["int"], false);

    crate::ir::health::record_prototype_conflict(
        "agrees", 0x4a9000, "dwarf", &same, "inferred", &same,
    );

    assert_eq!(
        crate::ir::health::take_render_verification().prototype_conflict_count,
        0
    );
}
