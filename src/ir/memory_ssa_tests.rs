use super::{compute_memory_ssa, MemoryAccess, MemoryAccessKind, MemoryRegion, MemoryVersionId};
use crate::ir::types::{
    CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value, Width,
};
use crate::ir::use_def::InstrAddr;

fn reg(name: &str) -> VReg {
    VReg::phys(name)
}

fn mem(base: &str, disp: i64, size: u8) -> MemOp {
    MemOp::plain(Some(reg(base)), None, 0, disp, size)
}

fn instruction(va: u64, op: Op) -> LlirInstr {
    LlirInstr { va, op }
}

fn block(start_va: u64, instrs: Vec<LlirInstr>, succs: Vec<u64>) -> LlirBlock {
    LlirBlock {
        start_va,
        end_va: start_va + 4,
        instrs,
        succs,
    }
}

fn function(blocks: Vec<LlirBlock>) -> LlirFunction {
    LlirFunction {
        entry_va: blocks.first().map_or(0, |block| block.start_va),
        blocks,
    }
}

#[test]
fn straight_line_accesses_read_and_define_exact_memory_versions() {
    let function = function(vec![block(
        0x1000,
        vec![
            instruction(
                0x1000,
                Op::Load {
                    dst: reg("rax"),
                    addr: mem("rbx", 0, 8),
                },
            ),
            instruction(
                0x1001,
                Op::Store {
                    addr: mem("rbx", 4, 4),
                    src: Value::Const(7),
                },
            ),
            instruction(
                0x1002,
                Op::Load {
                    dst: reg("rcx"),
                    addr: mem("rbx", 4, 4),
                },
            ),
        ],
        vec![],
    )]);

    let memory = compute_memory_ssa(&function);
    let first = memory
        .access_at(InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        })
        .expect("first load");
    let store = memory
        .access_at(InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        })
        .expect("store");
    let second = memory
        .access_at(InstrAddr {
            block_idx: 0,
            instr_idx: 2,
        })
        .expect("second load");

    assert_eq!(first.kind, MemoryAccessKind::Read);
    assert_eq!(first.region, MemoryRegion::Unknown);
    assert_eq!(first.input, MemoryVersionId::ENTRY);
    assert_eq!(first.output, None);
    assert_eq!(store.kind, MemoryAccessKind::Write);
    assert_eq!(store.input, MemoryVersionId::ENTRY);
    assert_ne!(store.output, None);
    assert_eq!(second.input, store.output.expect("store definition"));
    assert_eq!(memory.entry_version(0), Some(MemoryVersionId::ENTRY));
    assert_eq!(memory.exit_version(0), store.output);
    assert_eq!(memory.verify(&function), Ok(()));
}

#[test]
fn diamond_join_has_a_memory_phi_with_both_reaching_states() {
    let function = function(vec![
        block(0x1000, vec![], vec![0x1010, 0x1020]),
        block(
            0x1010,
            vec![instruction(
                0x1010,
                Op::Store {
                    addr: mem("rbx", 0, 4),
                    src: Value::Const(1),
                },
            )],
            vec![0x1030],
        ),
        block(0x1020, vec![], vec![0x1030]),
        block(
            0x1030,
            vec![instruction(
                0x1030,
                Op::Load {
                    dst: reg("rax"),
                    addr: mem("rbx", 0, 4),
                },
            )],
            vec![],
        ),
    ]);

    let memory = compute_memory_ssa(&function);
    let phi = memory.phi_for_block(3).expect("join phi");
    let incoming = phi
        .incoming
        .iter()
        .map(|incoming| (incoming.predecessor, incoming.version))
        .collect::<Vec<_>>();
    assert_eq!(incoming.len(), 2);
    assert!(incoming.contains(&(Some(1), memory.exit_version(1).expect("left exit"))));
    assert!(incoming.contains(&(Some(2), MemoryVersionId::ENTRY)));
    assert_eq!(
        memory
            .access_at(InstrAddr {
                block_idx: 3,
                instr_idx: 0,
            })
            .expect("join load")
            .input,
        phi.version
    );
    assert_eq!(memory.verify(&function), Ok(()));
}

#[test]
fn loop_header_phi_connects_entry_and_backedge_memory() {
    let function = function(vec![
        block(0x1000, vec![], vec![0x1010]),
        block(
            0x1010,
            vec![
                instruction(
                    0x1010,
                    Op::Load {
                        dst: reg("rax"),
                        addr: mem("rbx", 0, 4),
                    },
                ),
                instruction(
                    0x1011,
                    Op::Store {
                        addr: mem("rbx", 0, 4),
                        src: Value::Reg(reg("rax")),
                    },
                ),
            ],
            vec![0x1010, 0x1020],
        ),
        block(0x1020, vec![instruction(0x1020, Op::Return)], vec![]),
    ]);

    let memory = compute_memory_ssa(&function);
    let phi = memory.phi_for_block(1).expect("loop phi");
    assert!(phi.incoming.iter().any(|incoming| {
        incoming.predecessor == Some(0) && incoming.version == MemoryVersionId::ENTRY
    }));
    assert!(phi.incoming.iter().any(|incoming| {
        incoming.predecessor == Some(1) && Some(incoming.version) == memory.exit_version(1)
    }));
    assert_eq!(
        memory
            .access_at(InstrAddr {
                block_idx: 1,
                instr_idx: 0,
            })
            .expect("loop load")
            .input,
        phi.version
    );
    assert_eq!(memory.verify(&function), Ok(()));
}

#[test]
fn calls_are_conservative_memory_clobbers() {
    let function = function(vec![block(
        0x1000,
        vec![
            instruction(
                0x1000,
                Op::Call {
                    target: CallTarget::Direct(0x2000),
                    effects: None,
                },
            ),
            instruction(
                0x1001,
                Op::Load {
                    dst: reg("rax"),
                    addr: mem("rbx", 0, 8),
                },
            ),
        ],
        vec![],
    )]);

    let memory = compute_memory_ssa(&function);
    let call = memory
        .access_at(InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        })
        .expect("call memory effect");
    let load = memory
        .access_at(InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        })
        .expect("load");

    assert_eq!(call.kind, MemoryAccessKind::Clobber);
    assert_ne!(call.output, None);
    assert_eq!(load.input, call.output.expect("call definition"));
    assert_eq!(memory.verify(&function), Ok(()));
}

#[test]
fn declared_and_unknown_effects_define_only_the_memory_states_they_claim() {
    let function = function(vec![block(
        0x1000,
        vec![
            instruction(
                0x1000,
                Op::Intrinsic {
                    name: "read_only".into(),
                    ins: vec![],
                    outs: vec![(reg("rax"), Width::W64)],
                    reads_mem: true,
                    writes_mem: false,
                },
            ),
            instruction(
                0x1001,
                Op::Intrinsic {
                    name: "write_only".into(),
                    ins: vec![],
                    outs: vec![],
                    reads_mem: false,
                    writes_mem: true,
                },
            ),
            instruction(
                0x1002,
                Op::CondStore {
                    cond: reg("zf"),
                    inverted: false,
                    addr: mem("rbx", 0, 4),
                    src: Value::Const(1),
                },
            ),
            instruction(
                0x1003,
                Op::Unknown {
                    mnemonic: "opaque".into(),
                },
            ),
        ],
        vec![],
    )]);

    let memory = compute_memory_ssa(&function);
    let accesses = (0..4)
        .map(|instr_idx| {
            memory
                .access_at(InstrAddr {
                    block_idx: 0,
                    instr_idx,
                })
                .expect("memory effect")
        })
        .collect::<Vec<_>>();

    assert_eq!(accesses[0].kind, MemoryAccessKind::Read);
    assert_eq!(accesses[0].output, None);
    assert_eq!(accesses[1].kind, MemoryAccessKind::Write);
    assert_ne!(accesses[1].output, None);
    assert_eq!(accesses[2].kind, MemoryAccessKind::Write);
    assert_ne!(accesses[2].output, None);
    assert_eq!(accesses[3].kind, MemoryAccessKind::Clobber);
    assert_ne!(accesses[3].output, None);
    assert_eq!(memory.verify(&function), Ok(()));
}

#[test]
fn verifier_rejects_an_orphaned_access_record() {
    let function = function(vec![block(0x1000, vec![], vec![])]);
    let mut memory = compute_memory_ssa(&function);
    memory.accesses.insert(
        InstrAddr {
            block_idx: 99,
            instr_idx: 0,
        },
        MemoryAccess {
            kind: MemoryAccessKind::Read,
            region: MemoryRegion::Unknown,
            input: MemoryVersionId::ENTRY,
            output: None,
        },
    );

    assert!(memory.verify(&function).is_err());
}
