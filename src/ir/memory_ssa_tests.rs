use super::{compute_memory_ssa, MemoryAccess, MemoryAccessKind, MemoryRegion, MemoryVersionId};
use crate::ir::types::{
    CallTarget, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value, Width,
};
use crate::ir::use_def::InstrAddr;
use crate::program::image::ProgramImage;

fn x86_image() -> ProgramImage {
    ProgramImage::from_path(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"),
    )
    .expect("index real x86-64 ELF")
}

fn arm32_image() -> ProgramImage {
    ProgramImage::from_path(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc"),
    )
    .expect("index real ARM32 ELF")
}

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

    let image = x86_image();
    let memory = compute_memory_ssa(&function, &image);
    let first = memory
        .access_at(
            InstrAddr {
                block_idx: 0,
                instr_idx: 0,
            },
            MemoryRegion::HeapUnknown,
        )
        .expect("first load");
    let store = memory
        .access_at(
            InstrAddr {
                block_idx: 0,
                instr_idx: 1,
            },
            MemoryRegion::HeapUnknown,
        )
        .expect("store");
    let second = memory
        .access_at(
            InstrAddr {
                block_idx: 0,
                instr_idx: 2,
            },
            MemoryRegion::HeapUnknown,
        )
        .expect("second load");

    assert_eq!(first.kind, MemoryAccessKind::Read);
    assert_eq!(first.region, MemoryRegion::HeapUnknown);
    assert_eq!(
        first.input,
        MemoryVersionId::entry(MemoryRegion::HeapUnknown)
    );
    assert_eq!(first.output, None);
    assert_eq!(store.kind, MemoryAccessKind::Write);
    assert_eq!(
        store.input,
        MemoryVersionId::entry(MemoryRegion::HeapUnknown)
    );
    assert_ne!(store.output, None);
    assert_eq!(second.input, store.output.expect("store definition"));
    assert_eq!(
        memory.entry_version(0, MemoryRegion::HeapUnknown),
        Some(MemoryVersionId::entry(MemoryRegion::HeapUnknown))
    );
    assert_eq!(
        memory.exit_version(0, MemoryRegion::HeapUnknown),
        store.output
    );
    assert_eq!(memory.verify(&function, &image), Ok(()));
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

    let image = x86_image();
    let memory = compute_memory_ssa(&function, &image);
    let phi = memory
        .phi_for_block(3, MemoryRegion::HeapUnknown)
        .expect("join phi");
    let incoming = phi
        .incoming
        .iter()
        .map(|incoming| (incoming.predecessor, incoming.version))
        .collect::<Vec<_>>();
    assert_eq!(incoming.len(), 2);
    assert!(incoming.contains(&(
        Some(1),
        memory
            .exit_version(1, MemoryRegion::HeapUnknown)
            .expect("left exit")
    )));
    assert!(incoming.contains(&(Some(2), MemoryVersionId::entry(MemoryRegion::HeapUnknown))));
    assert_eq!(
        memory
            .access_at(
                InstrAddr {
                    block_idx: 3,
                    instr_idx: 0,
                },
                MemoryRegion::HeapUnknown
            )
            .expect("join load")
            .input,
        phi.version
    );
    assert_eq!(memory.verify(&function, &image), Ok(()));
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

    let image = x86_image();
    let memory = compute_memory_ssa(&function, &image);
    let phi = memory
        .phi_for_block(1, MemoryRegion::HeapUnknown)
        .expect("loop phi");
    assert!(phi.incoming.iter().any(|incoming| {
        incoming.predecessor == Some(0)
            && incoming.version == MemoryVersionId::entry(MemoryRegion::HeapUnknown)
    }));
    assert!(phi.incoming.iter().any(|incoming| {
        incoming.predecessor == Some(1)
            && Some(incoming.version) == memory.exit_version(1, MemoryRegion::HeapUnknown)
    }));
    assert_eq!(
        memory
            .access_at(
                InstrAddr {
                    block_idx: 1,
                    instr_idx: 0,
                },
                MemoryRegion::HeapUnknown
            )
            .expect("loop load")
            .input,
        phi.version
    );
    assert_eq!(memory.verify(&function, &image), Ok(()));
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

    let image = x86_image();
    let memory = compute_memory_ssa(&function, &image);
    let call = memory
        .access_at(
            InstrAddr {
                block_idx: 0,
                instr_idx: 0,
            },
            MemoryRegion::HeapUnknown,
        )
        .expect("call memory effect");
    let load = memory
        .access_at(
            InstrAddr {
                block_idx: 0,
                instr_idx: 1,
            },
            MemoryRegion::HeapUnknown,
        )
        .expect("load");

    assert_eq!(call.kind, MemoryAccessKind::Clobber);
    assert_ne!(call.output, None);
    assert_eq!(load.input, call.output.expect("call definition"));
    assert_eq!(memory.verify(&function, &image), Ok(()));
}

#[test]
fn target_and_image_facts_split_stack_global_readonly_heap_and_unknown_regions() {
    let image = x86_image();
    let writable = image
        .sections()
        .find(|section| section.name() == ".data")
        .expect("real ELF has .data")
        .address();
    let readonly = image
        .sections()
        .find(|section| section.name() == ".rodata")
        .expect("real ELF has .rodata")
        .address();
    let direct = |address: u64, size: u8| {
        MemOp::plain(
            None,
            None,
            0,
            i64::try_from(address).expect("fixture VA fits LLIR displacement"),
            size,
        )
    };
    let function = function(vec![block(
        0x1000,
        vec![
            instruction(
                0x1000,
                Op::Store {
                    addr: mem("rsp", 8, 8),
                    src: Value::Const(1),
                },
            ),
            instruction(
                0x1001,
                Op::Store {
                    addr: direct(writable, 4),
                    src: Value::Const(2),
                },
            ),
            instruction(
                0x1002,
                Op::Load {
                    dst: reg("rax"),
                    addr: direct(readonly, 4),
                },
            ),
            instruction(
                0x1003,
                Op::Load {
                    dst: reg("rcx"),
                    addr: mem("rbx", 0, 8),
                },
            ),
            instruction(
                0x1004,
                Op::Call {
                    target: CallTarget::Direct(0x2000),
                    effects: None,
                },
            ),
        ],
        vec![],
    )]);

    let memory = compute_memory_ssa(&function, &image);
    let address = |instr_idx| InstrAddr {
        block_idx: 0,
        instr_idx,
    };
    let stack_store = memory
        .access_at(address(0), MemoryRegion::Stack)
        .expect("target stack role");
    let global_store = memory
        .access_at(address(1), MemoryRegion::KnownGlobal)
        .expect("writable mapped global");
    let readonly_load = memory
        .access_at(address(2), MemoryRegion::ReadOnlyImage)
        .expect("readonly mapped image");
    let heap_load = memory
        .access_at(address(3), MemoryRegion::HeapUnknown)
        .expect("pointer-based heap/unknown access");

    assert_ne!(stack_store.output, None);
    assert_ne!(global_store.output, None);
    assert_eq!(
        global_store.input,
        MemoryVersionId::entry(MemoryRegion::KnownGlobal),
        "a proven stack write must not advance the global state"
    );
    assert_eq!(readonly_load.output, None);
    assert_eq!(
        readonly_load.input,
        MemoryVersionId::entry(MemoryRegion::ReadOnlyImage)
    );
    assert_eq!(heap_load.output, None);
    assert_eq!(
        memory.accesses_at(address(4)).count(),
        MemoryRegion::ALL.len(),
        "an unknown call observes every region and clobbers every mutable region"
    );
    for region in [
        MemoryRegion::Stack,
        MemoryRegion::KnownGlobal,
        MemoryRegion::HeapUnknown,
        MemoryRegion::FullyUnknown,
    ] {
        let call = memory.access_at(address(4), region).expect("call clobber");
        assert_eq!(call.kind, MemoryAccessKind::Clobber);
        assert_ne!(call.output, None);
    }
    assert_eq!(
        memory
            .access_at(address(4), MemoryRegion::Stack)
            .expect("call stack clobber")
            .input,
        stack_store.output.expect("stack definition")
    );
    assert_eq!(
        memory
            .access_at(address(4), MemoryRegion::KnownGlobal)
            .expect("call global clobber")
            .input,
        global_store.output.expect("global definition")
    );
    let call_readonly = memory
        .access_at(address(4), MemoryRegion::ReadOnlyImage)
        .expect("call readonly observation");
    assert_eq!(call_readonly.kind, MemoryAccessKind::Read);
    assert_eq!(call_readonly.output, None);
    assert_eq!(memory.verify(&function, &image), Ok(()));
}

#[test]
fn arm32_frame_roles_are_stack_and_target_mismatches_fail_verification() {
    let function = function(vec![block(
        0x1000,
        vec![instruction(
            0x1000,
            Op::Load {
                dst: reg("r0"),
                addr: mem("r11", -8, 4),
            },
        )],
        vec![],
    )]);
    let arm = arm32_image();
    let x86 = x86_image();
    let address = InstrAddr {
        block_idx: 0,
        instr_idx: 0,
    };

    let arm_memory = compute_memory_ssa(&function, &arm);
    assert_eq!(arm_memory.accesses_at(address).count(), 1);
    assert_eq!(
        arm_memory
            .access_at(address, MemoryRegion::Stack)
            .expect("AAPCS r11 frame coordinate")
            .kind,
        MemoryAccessKind::Read
    );
    assert_eq!(arm_memory.verify(&function, &arm), Ok(()));
    assert!(
        arm_memory.verify(&function, &x86).is_err(),
        "a sidecar must not be reused under a different target classifier"
    );
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

    let image = x86_image();
    let memory = compute_memory_ssa(&function, &image);
    let accesses = (0..4)
        .map(|instr_idx| {
            memory
                .access_at(
                    InstrAddr {
                        block_idx: 0,
                        instr_idx,
                    },
                    MemoryRegion::HeapUnknown,
                )
                .expect("memory effect")
        })
        .collect::<Vec<_>>();

    assert_eq!(accesses[0].kind, MemoryAccessKind::Read);
    assert_eq!(accesses[0].output, None);
    assert_eq!(accesses[1].kind, MemoryAccessKind::Clobber);
    assert_ne!(accesses[1].output, None);
    assert_eq!(accesses[2].kind, MemoryAccessKind::Write);
    assert_ne!(accesses[2].output, None);
    assert_eq!(accesses[3].kind, MemoryAccessKind::Clobber);
    assert_ne!(accesses[3].output, None);
    assert_eq!(memory.verify(&function, &image), Ok(()));
}

#[test]
fn verifier_rejects_an_orphaned_access_record() {
    let function = function(vec![block(0x1000, vec![], vec![])]);
    let image = x86_image();
    let mut memory = compute_memory_ssa(&function, &image);
    memory.accesses.insert(
        (
            InstrAddr {
                block_idx: 99,
                instr_idx: 0,
            },
            MemoryRegion::HeapUnknown,
        ),
        MemoryAccess {
            kind: MemoryAccessKind::Read,
            region: MemoryRegion::HeapUnknown,
            input: MemoryVersionId::entry(MemoryRegion::HeapUnknown),
            output: None,
        },
    );

    assert!(memory.verify(&function, &image).is_err());
}
