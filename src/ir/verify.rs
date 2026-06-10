//! LLIR well-formedness verifier.
//!
//! Phase 0 of the execution-engine plan hardens the LLIR into a *total, typed,
//! executable* IR. This module is the machine-checkable safety net for that
//! contract: it walks an [`LlirFunction`] and reports structural problems that
//! would make execution unsound. See
//! `docs/design/execution-engine/02-architecture/executable-llir.md`.
//!
//! Checks (v1):
//! 1. **Width-change invariants** — `ZExt`/`SExt` widen (`to >= from`), `Trunc`
//!    narrows (`to <= from`), `Extract` has `hi > lo`.
//! 2. **Temp definedness** — every [`VReg::Temp`] that is *read* must be *written*
//!    somewhere in the same function (temporaries are function-local and have no
//!    cross-function meaning). Physical registers may be read without a prior def
//!    (they are function inputs / ABI state).
//! 3. **Memory access size** — `MemOp.size` must be a supported power-of-two byte
//!    count.
//! 4. **Residual `Unknown`** — reported separately (not a hard malformation)
//!    so the lifter migration to [`Op::Intrinsic`] (task 0.7) can be tracked: a
//!    fully-migrated lifter emits zero of these.

use std::collections::HashSet;

use crate::ir::types::{LlirFunction, MemOp, Op, VReg};
use crate::ir::use_def::def_uses;

/// A single well-formedness problem found in an [`LlirFunction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// A width-change op violates its monotonicity / range invariant.
    BadWidthChange { va: u64, detail: String },
    /// A temporary VReg is read but never defined in this function.
    UndefinedTemp { va: u64, temp: u32 },
    /// A memory access has an unsupported size (not a power-of-two byte count).
    BadMemSize { va: u64, size: u8 },
    /// An un-migrated [`Op::Unknown`] remains (tracked, not fatal, during the
    /// lifter migration).
    ResidualUnknown { va: u64, mnemonic: String },
}

impl VerifyError {
    /// True for problems that make execution unsound (everything except the
    /// tracked-but-tolerated [`VerifyError::ResidualUnknown`]).
    pub fn is_fatal(&self) -> bool {
        !matches!(self, VerifyError::ResidualUnknown { .. })
    }
}

fn mem_size_ok(size: u8) -> bool {
    matches!(size, 1 | 2 | 4 | 8 | 16 | 32 | 64)
}

fn check_memop(va: u64, m: &MemOp, out: &mut Vec<VerifyError>) {
    if !mem_size_ok(m.size) {
        out.push(VerifyError::BadMemSize { va, size: m.size });
    }
}

/// Verify a function, returning every problem found (empty == well-formed,
/// modulo any tolerated [`VerifyError::ResidualUnknown`]).
pub fn verify_function(lf: &LlirFunction) -> Vec<VerifyError> {
    let mut errors = Vec::new();

    // Pass 1: collect every VReg ever written in this function.
    let mut defined: HashSet<VReg> = HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            let (def, _) = def_uses(&ins.op);
            if let Some(d) = def {
                defined.insert(d);
            }
            // Intrinsics may define more than the one def def_uses reports.
            if let Op::Intrinsic { outs, .. } = &ins.op {
                for (r, _) in outs {
                    defined.insert(r.clone());
                }
            }
        }
    }

    // Pass 2: per-op structural + definedness checks.
    for block in &lf.blocks {
        for ins in &block.instrs {
            let va = ins.va;
            match &ins.op {
                Op::ZExt { from, to, .. } | Op::SExt { from, to, .. } => {
                    if to.bits() < from.bits() {
                        errors.push(VerifyError::BadWidthChange {
                            va,
                            detail: format!("extend narrows: {} -> {}", from, to),
                        });
                    }
                }
                Op::Trunc { from, to, .. } => {
                    if to.bits() > from.bits() {
                        errors.push(VerifyError::BadWidthChange {
                            va,
                            detail: format!("trunc widens: {} -> {}", from, to),
                        });
                    }
                }
                Op::Extract { hi, lo, .. } => {
                    if hi <= lo {
                        errors.push(VerifyError::BadWidthChange {
                            va,
                            detail: format!("extract has hi <= lo: [{}:{}]", hi, lo),
                        });
                    }
                }
                Op::Load { addr, .. } | Op::Store { addr, .. } => {
                    check_memop(va, addr, &mut errors)
                }
                Op::Unknown { mnemonic } => errors.push(VerifyError::ResidualUnknown {
                    va,
                    mnemonic: mnemonic.clone(),
                }),
                _ => {}
            }

            // Temp definedness: a read of an undefined temp is malformed.
            let (_, uses) = def_uses(&ins.op);
            for u in uses {
                if let VReg::Temp(id) = u {
                    if !defined.contains(&VReg::Temp(id)) {
                        errors.push(VerifyError::UndefinedTemp { va, temp: id });
                    }
                }
            }
        }
    }

    errors
}

/// Convenience: the fatal subset of [`verify_function`] (excludes tolerated
/// residual `Unknown`s).
pub fn verify_fatal(lf: &LlirFunction) -> Vec<VerifyError> {
    verify_function(lf)
        .into_iter()
        .filter(|e| e.is_fatal())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, CallTarget, Flag, LlirBlock, LlirInstr, Op, VReg, Value, Width};

    fn func(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + ops.len() as u64 * 4,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(i, op)| LlirInstr {
                        va: 0x1000 + i as u64 * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn well_formed_function_has_no_errors() {
        let lf = func(vec![
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Const(1),
            },
            Op::Bin {
                dst: VReg::phys("rax"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Reg(VReg::phys("rdi")), // rdi is an input → ok undefined
            },
            Op::Return,
        ]);
        assert!(verify_function(&lf).is_empty());
    }

    #[test]
    fn detects_undefined_temp() {
        // Reads %t5 which is never written.
        let lf = func(vec![Op::Assign {
            dst: VReg::phys("rax"),
            src: Value::Reg(VReg::Temp(5)),
        }]);
        let errs = verify_function(&lf);
        assert_eq!(
            errs,
            vec![VerifyError::UndefinedTemp {
                va: 0x1000,
                temp: 5
            }]
        );
    }

    #[test]
    fn defined_temp_is_ok() {
        let lf = func(vec![
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Const(7),
            },
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::Temp(0)),
            },
        ]);
        assert!(verify_function(&lf).is_empty());
    }

    #[test]
    fn detects_bad_width_change() {
        let lf = func(vec![Op::ZExt {
            dst: VReg::phys("eax"),
            src: Value::Reg(VReg::phys("rax")),
            from: Width::W64,
            to: Width::W32, // narrowing via ZExt → malformed
        }]);
        let errs = verify_function(&lf);
        assert_eq!(errs.len(), 1);
        assert!(matches!(errs[0], VerifyError::BadWidthChange { .. }));
    }

    #[test]
    fn detects_bad_mem_size() {
        let lf = func(vec![Op::Store {
            addr: MemOp {
                base: Some(VReg::phys("rsp")),
                index: None,
                scale: 1,
                disp: 0,
                size: 3, // not a power of two
                ..Default::default()
            },
            src: Value::Const(0),
        }]);
        let errs = verify_function(&lf);
        assert_eq!(
            errs,
            vec![VerifyError::BadMemSize {
                va: 0x1000,
                size: 3
            }]
        );
    }

    #[test]
    fn residual_unknown_is_tracked_but_not_fatal() {
        let lf = func(vec![Op::Unknown {
            mnemonic: "vpbroadcastb".into(),
        }]);
        let all = verify_function(&lf);
        assert_eq!(all.len(), 1);
        assert!(!all[0].is_fatal());
        assert!(verify_fatal(&lf).is_empty());
    }

    #[test]
    fn intrinsic_outputs_count_as_defined() {
        let lf = func(vec![
            Op::Intrinsic {
                name: "rdtsc".into(),
                ins: vec![],
                outs: vec![(VReg::Temp(3), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            },
            Op::Assign {
                dst: VReg::phys("rax"),
                src: Value::Reg(VReg::Temp(3)),
            },
        ]);
        assert!(verify_function(&lf).is_empty());
    }

    #[test]
    fn real_lifted_functions_have_no_fatal_errors() {
        // Exit criterion for Phase 0 task 0.6: the verifier passes (no fatal
        // malformations) over real lifted functions. Residual `Unknown`s are
        // tolerated until the lifter migration (task 0.7) completes.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 64,
                max_blocks: 256,
                max_instructions: 20_000,
                timeout_ms: 2000,
            },
        );
        let mut checked = 0;
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let fatal = verify_fatal(&lf);
                assert!(
                    fatal.is_empty(),
                    "fatal verify errors in function @ {:#x}: {:?}",
                    f.entry_point.value,
                    fatal
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "expected to lift+verify at least one function");
    }

    #[test]
    fn ite_and_call_are_well_formed() {
        let lf = func(vec![
            Op::Assign {
                dst: VReg::Temp(0),
                src: Value::Const(1),
            },
            Op::Ite {
                dst: VReg::phys("rax"),
                cond: VReg::Flag(Flag::Z),
                t: Value::Reg(VReg::Temp(0)),
                e: Value::Const(0),
                width: Width::W64,
            },
            Op::Call {
                target: CallTarget::Direct(0x2000),
            },
        ]);
        assert!(verify_function(&lf).is_empty());
    }
}
