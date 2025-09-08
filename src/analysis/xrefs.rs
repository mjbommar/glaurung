//! Cross-reference helpers (MVP).
//!
//! This module provides minimal routines to compute code→data xrefs by scanning
//! discovered instructions for immediate operands that fall within known data
//! sections. It is intentionally conservative and budgeted.

use crate::core::address::{Address, AddressKind};
use crate::core::instruction::Instruction;

#[derive(Debug, Clone)]
pub struct Xref {
    pub from: Address,
    pub to: Address,
}

/// Given instructions and a set of data ranges (VA start,end), produce xrefs where
/// an instruction contains an immediate in one of the ranges. Best-effort MVP.
pub fn code_to_data_xrefs(
    insns: &[Instruction],
    data_ranges: &[(u64, u64)],
    bits: u8,
    max_xrefs: usize,
) -> Vec<Xref> {
    let mut out = Vec::new();
    for ins in insns {
        if out.len() >= max_xrefs {
            break;
        }
        if let Some(imm) = ins.operands.iter().find_map(|op| op.immediate) {
            let v = imm as u64;
            if data_ranges.iter().any(|(s, e)| v >= *s && v < *e) {
                if let (Ok(from), Ok(to)) = (
                    Address::new(AddressKind::VA, ins.address.value, bits, None, None),
                    Address::new(AddressKind::VA, v, bits, None, None),
                ) {
                    out.push(Xref { from, to });
                }
            }
        }
    }
    out
}
