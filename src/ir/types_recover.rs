//! First-cut type recovery for VRegs in an [`LlirFunction`].
//!
//! v0 scope — deliberately tiny, but useful:
//!
//! * Registers used as the base of a `Load`/`Store` memory operand are
//!   classified as **pointers**. The inferred pointee width comes from the
//!   memory access size.
//! * Registers compared against zero with `CmpOp::Eq` are tagged
//!   **boolean-ish** (likely hold a truth value).
//! * Registers used solely as shift counts are tagged **unsigned integer**.
//! * Registers that flow into a `CallTarget::Direct` as the first argument
//!   register (by convention x86-64 SysV: `rdi`, AArch64: `x0`) keep their
//!   inferred type if one was set earlier — this is just a pass-through
//!   hook for future argument-type inference.
//!
//! The output is a [`TypeMap`] keyed by [`VReg`]. Later passes can refine
//! it; the AST printer can consume it to print `int`/`char*`/`bool` instead
//! of raw register names.
//!
//! This pass reads only the LLIR — it does not require SSA form — which
//! keeps it cheap and composable. Passes that need SSA precision can
//! consume [`crate::ir::ssa::SsaInfo`] and re-run on a per-version basis.

use std::collections::HashMap;

use crate::ir::types::{BinOp, CmpOp, LlirFunction, Op, VReg, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeHint {
    /// A pointer; `width` records the access size of the last memory
    /// operation performed through it (1/2/4/8 bytes).
    Pointer { pointee_width: u8 },
    /// Signed/unsigned integer — distinguished by context (shifts tagged
    /// unsigned, arithmetic compared against signed constants tagged signed).
    Int { signed: bool, width: u8 },
    /// Value used as a 0/1 boolean (compared equal to zero).
    BoolLike,
    /// The value is used by [`Op::Call`] as an indirect call target, so it
    /// is likely a code pointer.
    CodePointer,
}

#[derive(Debug, Default, Clone)]
pub struct TypeMap {
    inner: HashMap<VReg, TypeHint>,
}

impl TypeMap {
    pub fn get(&self, v: &VReg) -> Option<TypeHint> {
        self.inner.get(v).copied()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&VReg, &TypeHint)> {
        self.inner.iter()
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Public wrapper around [`Self::upsert`] so other modules (e.g. the
    /// Python binding's type-map remapper) can build a `TypeMap`
    /// incrementally from outside this crate's module.
    pub fn upsert_public(&mut self, reg: VReg, new: TypeHint) {
        self.upsert(reg, new)
    }

    /// Union-style update: only overwrite when `new` is strictly more
    /// specific than the current entry. Pointers beat ints; specific widths
    /// beat zero-width entries; bool beats nothing.
    fn upsert(&mut self, reg: VReg, new: TypeHint) {
        let cur = self.inner.get(&reg).copied();
        let keep = match (cur, new) {
            (None, _) => new,
            // Pointer wins over non-pointer.
            (Some(TypeHint::Int { .. }), TypeHint::Pointer { .. }) => new,
            (Some(TypeHint::BoolLike), TypeHint::Pointer { .. }) => new,
            // CodePointer wins over Int.
            (Some(TypeHint::Int { .. }), TypeHint::CodePointer) => new,
            // Wider pointee replaces narrower pointee.
            (
                Some(TypeHint::Pointer { pointee_width: a }),
                TypeHint::Pointer { pointee_width: b },
            ) if b > a => new,
            _ => cur.unwrap_or(new),
        };
        self.inner.insert(reg, keep);
    }
}

fn classify_int_default() -> TypeHint {
    TypeHint::Int {
        signed: true,
        width: 8,
    }
}

/// Produce a [`TypeMap`] for all register VRegs touched by `lf`.
pub fn recover_types(lf: &LlirFunction) -> TypeMap {
    let mut tm = TypeMap::default();

    // First pass: gather registers that ever receive a plain constant
    // assignment (`%rax = 0`, `%rdi = 42`, …). Any such register cannot be
    // a stable pointer or code-pointer — the pointer classification is
    // noise from an unrelated use-site and would produce `(fnptr)%ret = 0;`
    // style output. We'll use this to post-process the map below.
    let mut gets_const: std::collections::HashSet<VReg> =
        std::collections::HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Assign {
                dst,
                src: Value::Const(_),
            } = &ins.op
            {
                gets_const.insert(dst.clone());
            }
        }
    }

    for block in &lf.blocks {
        for ins in &block.instrs {
            match &ins.op {
                // Any register used as the base of a memory op is a pointer.
                Op::Load { addr, .. } | Op::Store { addr, .. } => {
                    if let Some(b) = &addr.base {
                        tm.upsert(
                            b.clone(),
                            TypeHint::Pointer {
                                pointee_width: addr.size.max(1),
                            },
                        );
                    }
                    if let Some(i) = &addr.index {
                        // Index registers are integers (array index counts).
                        tm.upsert(
                            i.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: 8,
                            },
                        );
                    }
                }
                // Shift counts are unsigned integers.
                Op::Bin {
                    op: BinOp::Shl | BinOp::Shr | BinOp::Sar,
                    rhs,
                    ..
                } => {
                    if let Value::Reg(r) = rhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: 1,
                            },
                        );
                    }
                }
                // Compared against zero → likely boolean.
                Op::Cmp {
                    op: CmpOp::Eq,
                    lhs: Value::Reg(r),
                    rhs: Value::Const(0),
                    ..
                }
                | Op::Cmp {
                    op: CmpOp::Eq,
                    lhs: Value::Const(0),
                    rhs: Value::Reg(r),
                    ..
                } => {
                    tm.upsert(r.clone(), TypeHint::BoolLike);
                }
                // Indirect call target → code pointer.
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Reg(r)),
                } => {
                    tm.upsert(r.clone(), TypeHint::CodePointer);
                }
                // Default: arithmetic-producing binops leave the result a
                // generic signed 8-byte int unless something more specific
                // promotes it later.
                Op::Bin { dst, .. } => {
                    if let VReg::Phys(_) = dst {
                        tm.upsert(dst.clone(), classify_int_default());
                    }
                }
                _ => {}
            }
        }
    }

    // Demote pointer / code-pointer classifications for regs that get a
    // constant assignment. They end up as generic ints — which the printer
    // leaves uncluttered.
    let to_demote: Vec<VReg> = tm
        .inner
        .iter()
        .filter(|(k, v)| {
            gets_const.contains(k)
                && matches!(v, TypeHint::Pointer { .. } | TypeHint::CodePointer)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for k in to_demote {
        tm.inner.insert(
            k,
            TypeHint::Int {
                signed: true,
                width: 8,
            },
        );
    }

    tm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};

    fn mk_block(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn load_base_tagged_pointer() {
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rbp")),
                index: None,
                scale: 0,
                disp: -8,
                size: 8,
                ..Default::default()
            },
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rbp")),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
    }

    #[test]
    fn wider_pointee_overwrites_narrower() {
        // First use: u8 pointer. Second use: u64 pointer. Result: 8.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 1,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 8,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rbx")),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
    }

    #[test]
    fn index_tagged_unsigned_int() {
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rdi")),
                index: Some(VReg::phys("rcx")),
                scale: 4,
                disp: 0,
                size: 4,
                ..Default::default()
            },
        }]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rcx")),
            Some(TypeHint::Int { signed: false, .. })
        ));
    }

    #[test]
    fn cmp_eq_zero_marks_bool() {
        use crate::ir::types::{CmpOp, Flag};
        let lf = mk_block(vec![Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(0),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(tm.get(&VReg::phys("rax")), Some(TypeHint::BoolLike));
    }

    #[test]
    fn indirect_call_target_is_code_pointer() {
        use crate::ir::types::CallTarget;
        let lf = mk_block(vec![Op::Call {
            target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(tm.get(&VReg::phys("rax")), Some(TypeHint::CodePointer));
    }

    #[test]
    fn shift_count_tagged_unsigned() {
        use crate::ir::types::BinOp;
        let lf = mk_block(vec![Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Shl,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Reg(VReg::phys("rcx")),
        }]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rcx")),
            Some(TypeHint::Int { signed: false, .. })
        ));
    }

    #[test]
    fn pointer_beats_int_promotion_order() {
        // First: rbx used as arithmetic result (int). Second: rbx used as
        // pointer base. Final type must be pointer.
        use crate::ir::types::BinOp;
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("rbx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rbx")),
                rhs: Value::Const(1),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rbx")),
            Some(TypeHint::Pointer { .. })
        ));
    }

    #[test]
    fn const_assignment_demotes_pointer_classification() {
        // `%rax = load [rax+0]; %rax = 0;` — the load marks %rax as pointer
        // (actually rax is the *dst*, but let's instead use a different
        // reg as a base). Here the scenario is: `rbp` is used as a pointer
        // base in a load, then gets a constant assignment. The constant
        // assignment should demote it.
        use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Load {
                            dst: VReg::phys("rax"),
                            addr: MemOp {
                                base: Some(VReg::phys("rbp")),
                                index: None,
                                scale: 0,
                                disp: 0,
                                size: 8,
                                ..Default::default()
                            },
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rbp"),
                            src: Value::Const(0),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let tm = recover_types(&lf);
        // rbp was seen as a pointer base AND as the target of a const
        // assignment — must be demoted to Int.
        match tm.get(&VReg::phys("rbp")) {
            Some(TypeHint::Int { .. }) | None => {}
            other => panic!("expected Int for demoted rbp; got {:?}", other),
        }
        // Keep the suppress-unused ref to BinOp away from warnings.
        let _ = BinOp::Add;
    }

    #[test]
    fn real_binary_produces_non_empty_type_map() {
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
        let (funcs, _) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
            },
        );
        let mut saw_pointer = false;
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let tm = recover_types(&lf);
                if tm
                    .iter()
                    .any(|(_, t)| matches!(t, TypeHint::Pointer { .. }))
                {
                    saw_pointer = true;
                }
            }
        }
        assert!(
            saw_pointer,
            "expected at least one pointer classification across discovered functions"
        );
    }
}
