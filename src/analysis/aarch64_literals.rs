//! AArch64 PC-relative literal reconstruction.
//!
//! On AArch64 a pointer to a string/global is commonly materialized in two
//! (or more) instructions. The canonical pair is:
//!
//! ```text
//!     adrp x0, #PAGE      ; x0 <- (PC & ~0xFFF) + imm<<12
//!     add  x0, x0, #OFF   ; x0 <- x0 + imm (low 12 bits)
//! ```
//!
//! Capstone already folds the PC arithmetic into ADRP's immediate operand, so
//! the ADRP operand is the page VA directly. The ADD's last immediate is the
//! within-page offset. Combined, they give the final VA.
//!
//! Also handles the load/store form where the low 12 bits come from a
//! `ldr`/`str` with `[base, #off]` immediately following the ADRP.

use crate::core::instruction::{Instruction, Operand, OperandKind};

/// Resolved literal produced by an ADRP+X pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLiteral {
    /// Index within the input slice of the instruction that *completes* the
    /// literal (the ADD / LDR / STR that adds the low 12 bits).
    pub instr_index: usize,
    /// Fully reconstructed target VA.
    pub target_va: u64,
}

fn first_register_name(op: &Operand) -> Option<&str> {
    match &op.kind {
        OperandKind::Register => op.register.as_deref(),
        OperandKind::Memory => op.base.as_deref(),
        _ => None,
    }
}

fn adrp_page_and_dest(ins: &Instruction) -> Option<(String, u64)> {
    if !ins.mnemonic.eq_ignore_ascii_case("adrp") {
        return None;
    }
    if ins.operands.len() < 2 {
        return None;
    }
    let dest = first_register_name(&ins.operands[0])?.to_string();
    let page = ins.operands[1].immediate?;
    Some((dest, page as u64))
}

/// Scan a slice of decoded AArch64 instructions and return resolved literals.
///
/// Conservative: only walks the immediate next instruction and only matches
/// when the destination register of the ADRP appears on both the source and
/// destination sides of the completing op. No full register flow analysis.
pub fn resolve_literals(insns: &[Instruction]) -> Vec<ResolvedLiteral> {
    let mut out = Vec::new();
    if insns.len() < 2 {
        return out;
    }

    for i in 0..insns.len() - 1 {
        let Some((page_reg, page_va)) = adrp_page_and_dest(&insns[i]) else {
            continue;
        };
        let next = &insns[i + 1];
        let mnem = next.mnemonic.to_ascii_lowercase();

        // Pattern: add <dst>, <page_reg>, #imm   (dst often == page_reg)
        if mnem == "add" && next.operands.len() >= 3 {
            let src_reg = first_register_name(&next.operands[1]);
            let off = next.operands[2].immediate;
            if src_reg.map(|s| s.eq_ignore_ascii_case(&page_reg)) == Some(true) {
                if let Some(off) = off {
                    let target = page_va.wrapping_add(off as u64);
                    out.push(ResolvedLiteral {
                        instr_index: i + 1,
                        target_va: target,
                    });
                    continue;
                }
            }
        }

        // Pattern: ldr <dst>, [<page_reg>, #imm]  (memory operand carries the disp)
        // Also str/ldrb/ldrh variants.
        if matches!(
            mnem.as_str(),
            "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "str" | "strb" | "strh"
        ) {
            for op in &next.operands {
                if !matches!(op.kind, OperandKind::Memory) {
                    continue;
                }
                let base_matches = op
                    .base
                    .as_deref()
                    .map(|b| b.eq_ignore_ascii_case(&page_reg))
                    == Some(true);
                if !base_matches {
                    continue;
                }
                let disp = op.displacement.unwrap_or(0);
                let target = page_va.wrapping_add(disp as u64);
                out.push(ResolvedLiteral {
                    instr_index: i + 1,
                    target_va: target,
                });
                break;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};
    use crate::core::instruction::{Access, Operand};

    fn va(v: u64) -> Address {
        Address::new(AddressKind::VA, v, 64, None, None).unwrap()
    }

    fn reg_operand(name: &str) -> Operand {
        Operand::register(name.to_string(), 0, Access::Read)
    }

    fn imm_operand(v: i64) -> Operand {
        Operand::immediate(v, 0)
    }

    fn mem_operand(base: &str, disp: i64) -> Operand {
        Operand::memory(0, Access::Read, Some(disp), Some(base.to_string()), None, None)
    }

    fn mk(mnem: &str, addr: u64, ops: Vec<Operand>) -> Instruction {
        Instruction {
            address: va(addr),
            bytes: vec![0; 4],
            mnemonic: mnem.to_string(),
            operands: ops,
            length: 4,
            arch: "ARM64".to_string(),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        }
    }

    #[test]
    fn adrp_add_resolves_to_page_plus_offset() {
        // adrp x0, #0x12000
        // add  x0, x0, #0x456    ; -> 0x12456
        let insns = vec![
            mk("adrp", 0x1000, vec![reg_operand("x0"), imm_operand(0x12000)]),
            mk(
                "add",
                0x1004,
                vec![reg_operand("x0"), reg_operand("x0"), imm_operand(0x456)],
            ),
        ];
        let res = resolve_literals(&insns);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].instr_index, 1);
        assert_eq!(res[0].target_va, 0x12456);
    }

    #[test]
    fn adrp_ldr_resolves_via_memory_displacement() {
        // adrp x1, #0x20000
        // ldr  w2, [x1, #0x10]   ; -> 0x20010
        let insns = vec![
            mk("adrp", 0x2000, vec![reg_operand("x1"), imm_operand(0x20000)]),
            mk(
                "ldr",
                0x2004,
                vec![reg_operand("w2"), mem_operand("x1", 0x10)],
            ),
        ];
        let res = resolve_literals(&insns);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].target_va, 0x20010);
    }

    #[test]
    fn register_mismatch_does_not_resolve() {
        // adrp x0, #0x3000
        // add  x1, x2, #0x10   ; unrelated to x0 — must not resolve
        let insns = vec![
            mk("adrp", 0x3000, vec![reg_operand("x0"), imm_operand(0x3000)]),
            mk(
                "add",
                0x3004,
                vec![reg_operand("x1"), reg_operand("x2"), imm_operand(0x10)],
            ),
        ];
        assert!(resolve_literals(&insns).is_empty());
    }

    #[test]
    fn isolated_adrp_does_not_resolve() {
        let insns = vec![mk(
            "adrp",
            0x4000,
            vec![reg_operand("x0"), imm_operand(0x4000)],
        )];
        assert!(resolve_literals(&insns).is_empty());
    }
}
