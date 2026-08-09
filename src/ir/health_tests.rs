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
        }
    );
    assert_eq!(
        crate::ir::health::cfg_health_from_accounting(&[], true),
        CfgHealth {
            uncovered_cfg_edges: 0,
            invented_cfg_edges: 0,
            structure_fallbacks: 1,
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
