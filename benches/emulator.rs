//! Benchmarks for the concrete emulator hot path.
//!
//! Run with: `cargo bench --features exec --bench emulator`. These measure
//! whole-function execution throughput so register-file / memory / dispatch
//! optimizations can be compared against a baseline.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use glaurung::exec::{Budget, Concrete, Machine};
use glaurung::ir::types::{
    BinOp, CmpOp, Flag, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value,
};

fn instr(va: u64, op: Op) -> LlirInstr {
    LlirInstr { va, op }
}

/// A countdown loop: `rax += rcx; rcx -= 1; while rcx != 0`. ~4 ops × `iters`
/// instructions — register/arith/branch heavy (stresses the register file).
fn arith_loop(iters: i64) -> LlirFunction {
    LlirFunction {
        entry_va: 0x1000,
        blocks: vec![
            LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    instr(
                        0x1000,
                        Op::Assign {
                            dst: VReg::phys("rax"),
                            src: Value::Const(0),
                        },
                    ),
                    instr(
                        0x1004,
                        Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Const(iters),
                        },
                    ),
                ],
                succs: vec![0x1008],
            },
            LlirBlock {
                start_va: 0x1008,
                end_va: 0x1018,
                instrs: vec![
                    instr(
                        0x1008,
                        Op::Bin {
                            dst: VReg::phys("rax"),
                            op: BinOp::Add,
                            lhs: Value::Reg(VReg::phys("rax")),
                            rhs: Value::Reg(VReg::phys("rcx")),
                        },
                    ),
                    instr(
                        0x100c,
                        Op::Bin {
                            dst: VReg::phys("rcx"),
                            op: BinOp::Sub,
                            lhs: Value::Reg(VReg::phys("rcx")),
                            rhs: Value::Const(1),
                        },
                    ),
                    instr(
                        0x1010,
                        Op::Cmp {
                            dst: VReg::Flag(Flag::Z),
                            op: CmpOp::Eq,
                            lhs: Value::Reg(VReg::phys("rcx")),
                            rhs: Value::Const(0),
                        },
                    ),
                    instr(
                        0x1014,
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: 0x1008,
                            inverted: true,
                        },
                    ),
                ],
                succs: vec![0x1008, 0x1018],
            },
            LlirBlock {
                start_va: 0x1018,
                end_va: 0x101c,
                instrs: vec![instr(0x1018, Op::Return)],
                succs: vec![],
            },
        ],
    }
}

/// A memory-heavy loop: store/load through a register each iteration.
fn mem_loop(iters: i64) -> LlirFunction {
    LlirFunction {
        entry_va: 0x1000,
        blocks: vec![
            LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![
                    instr(
                        0x1000,
                        Op::Assign {
                            dst: VReg::phys("rbx"),
                            src: Value::Const(0x5000),
                        },
                    ),
                    instr(
                        0x1004,
                        Op::Assign {
                            dst: VReg::phys("rcx"),
                            src: Value::Const(iters),
                        },
                    ),
                ],
                succs: vec![0x1008],
            },
            LlirBlock {
                start_va: 0x1008,
                end_va: 0x101c,
                instrs: vec![
                    instr(
                        0x1008,
                        Op::Store {
                            addr: MemOp::plain(Some(VReg::phys("rbx")), None, 1, 0, 8),
                            src: Value::Reg(VReg::phys("rcx")),
                        },
                    ),
                    instr(
                        0x100c,
                        Op::Load {
                            dst: VReg::phys("rax"),
                            addr: MemOp::plain(Some(VReg::phys("rbx")), None, 1, 0, 8),
                        },
                    ),
                    instr(
                        0x1010,
                        Op::Bin {
                            dst: VReg::phys("rcx"),
                            op: BinOp::Sub,
                            lhs: Value::Reg(VReg::phys("rcx")),
                            rhs: Value::Const(1),
                        },
                    ),
                    instr(
                        0x1014,
                        Op::Cmp {
                            dst: VReg::Flag(Flag::Z),
                            op: CmpOp::Eq,
                            lhs: Value::Reg(VReg::phys("rcx")),
                            rhs: Value::Const(0),
                        },
                    ),
                    instr(
                        0x1018,
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: 0x1008,
                            inverted: true,
                        },
                    ),
                ],
                succs: vec![0x1008, 0x101c],
            },
            LlirBlock {
                start_va: 0x101c,
                end_va: 0x1020,
                instrs: vec![instr(0x101c, Op::Return)],
                succs: vec![],
            },
        ],
    }
}

fn bench_emulator(c: &mut Criterion) {
    let arith = arith_loop(1000);
    c.bench_function("emulator/arith_loop_1000", |b| {
        b.iter(|| {
            let mut m = Machine::new(Concrete);
            let mut budget = Budget::new(10_000_000);
            black_box(m.run_function(black_box(&arith), &mut budget));
        });
    });

    let mem = mem_loop(1000);
    c.bench_function("emulator/mem_loop_1000", |b| {
        b.iter(|| {
            let mut m = Machine::new(Concrete);
            let mut budget = Budget::new(10_000_000);
            black_box(m.run_function(black_box(&mem), &mut budget));
        });
    });
}

criterion_group!(benches, bench_emulator);
criterion_main!(benches);
