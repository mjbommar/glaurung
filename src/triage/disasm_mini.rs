//! Minimal, budgeted x86/x64 instruction probe for entry-point heuristics.
//!
//! This does NOT attempt full disassembly. It recognizes a handful of common
//! single-byte or simple multi-byte opcodes (jmp/call/ret/nop) to approximate
//! control-flow density. It is safe, bounded, and architecture-agnostic to a degree.

use serde::{Deserialize, Serialize};

/// Summary statistics from a mini disassembly probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MiniDisasmSummary {
    pub bytes_scanned: usize,
    pub instructions_seen: usize,
    pub jumps: usize,
    pub calls: usize,
    pub rets: usize,
    pub nops: usize,
}

/// Probe x86/x86_64 bytes and compute coarse control-flow statistics.
/// - max_instructions bounds runtime; scanning stops if limit reached or bytes exhausted
/// - This is purely heuristic and does not validate prefixes or ModRM thoroughly.
pub fn probe_x86_entry(bytes: &[u8], max_instructions: usize) -> MiniDisasmSummary {
    let mut i = 0usize;
    let mut seen = 0usize;
    let mut out = MiniDisasmSummary::default();
    while i < bytes.len() && seen < max_instructions {
        let _ = bytes[i];
        // Very rough handling of prefixes: skip up to 4 common prefixes
        let mut p = i;
        let mut prefix_count = 0usize;
        while p < bytes.len() && prefix_count < 4 {
            match bytes[p] {
                0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {
                    p += 1;
                    prefix_count += 1;
                }
                0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                    p += 1;
                    prefix_count += 1;
                }
                0x40..=0x4F => {
                    p += 1;
                    prefix_count += 1;
                } // REX
                _ => break,
            }
        }
        if p >= bytes.len() {
            break;
        }
        let opcode = bytes[p];
        // Recognize a small set of opcodes
        match opcode {
            0xE9 | 0xEB => {
                // jmp rel32/rel8
                out.jumps += 1;
                // approximate length: opcode + imm
                i = p + if opcode == 0xE9 { 5 } else { 2 };
            }
            0xE8 => {
                // call rel32
                out.calls += 1;
                i = p + 5;
            }
            0xC3 | 0xC2 | 0xCB | 0xCA => {
                // ret
                out.rets += 1;
                i = p + if opcode == 0xC2 || opcode == 0xCA {
                    3
                } else {
                    1
                };
            }
            0x90 => {
                // nop
                out.nops += 1;
                i = p + 1;
            }
            0x0F => {
                // two-byte opcode prefix; handle a couple of common branches
                if p + 1 < bytes.len() {
                    let op2 = bytes[p + 1];
                    // jcc rel32
                    if (0x80..=0x8F).contains(&op2) {
                        out.jumps += 1;
                        i = p + 6;
                    } else {
                        // unknown two-byte opcode; advance conservatively
                        i = p + 2;
                    }
                } else {
                    break;
                }
            }
            _ => {
                // Unknown: advance by 1 conservatively
                i = p + 1;
            }
        }
        seen += 1;
    }
    out.bytes_scanned = i.min(bytes.len());
    out.instructions_seen = seen;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_counts_basic_control_flow() {
        // A simple sequence: nop; call; jmp; ret
        let data = vec![0x90, 0xE8, 0, 0, 0, 0, 0xE9, 0, 0, 0, 0, 0xC3];
        let sum = probe_x86_entry(&data, 16);
        assert!(sum.nops >= 1);
        assert!(sum.calls >= 1);
        assert!(sum.jumps >= 1);
        assert!(sum.rets >= 1);
        assert!(sum.instructions_seen >= 4);
    }
}
