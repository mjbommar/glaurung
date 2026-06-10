//! DEV-ONLY differential oracle — validate the emulator against Unicorn.
//!
//! Gated by the `dev-oracle` feature (links system libunicorn; **never shipped**
//! — see `docs/design/execution-engine/04-testing/differential-oracle.md`).
//! Given an initial register state and a block of real x86-64 machine code,
//! [`diff_x86_64`] runs it on both our emulator (decode→lift→`run_block`) and
//! Unicorn, then reports any GPR that disagrees. This is how we *know* the
//! emulator's instruction semantics are correct, and how coverage gaps surface.
//!
//! Flags are intentionally not compared: we model condition-code flags, not raw
//! EFLAGS, so they are not bit-comparable to Unicorn.

use unicorn_engine::{Arch, Mode, Prot, RegisterX86, Unicorn};

use crate::exec::{Concrete, Domain, Flow, Machine};
use crate::ir::lift_x86;
use crate::ir::types::{LlirBlock, VReg, Width};

const BASE: u64 = 0x1000;

/// The x86-64 general-purpose registers compared by the oracle.
const GPRS: &[(&str, RegisterX86)] = &[
    ("rax", RegisterX86::RAX),
    ("rbx", RegisterX86::RBX),
    ("rcx", RegisterX86::RCX),
    ("rdx", RegisterX86::RDX),
    ("rsi", RegisterX86::RSI),
    ("rdi", RegisterX86::RDI),
    ("rbp", RegisterX86::RBP),
    ("r8", RegisterX86::R8),
    ("r9", RegisterX86::R9),
    ("r10", RegisterX86::R10),
    ("r11", RegisterX86::R11),
    ("r12", RegisterX86::R12),
    ("r13", RegisterX86::R13),
    ("r14", RegisterX86::R14),
    ("r15", RegisterX86::R15),
];

/// A single register disagreement between our emulator and Unicorn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    pub reg: &'static str,
    pub ours: u64,
    pub unicorn: u64,
}

/// Outcome of a differential run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOutcome {
    /// All compared GPRs agree.
    Match,
    /// One or more registers disagree.
    Diverged(Vec<Divergence>),
    /// Our emulator did not run the block to completion (e.g. an unmodelled
    /// instruction halted it) — a coverage gap, not a semantic divergence.
    OurRunIncomplete(String),
}

/// Run `code` (linear x86-64, no control flow) on both engines from identical
/// `init` register state and compare the GPRs.
pub fn diff_x86_64(code: &[u8], init: &[(&str, u64)]) -> DiffOutcome {
    // --- Unicorn reference ---
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).expect("unicorn new");
    uc.mem_map(BASE, 0x1000, Prot::ALL).expect("mem_map");
    uc.mem_write(BASE, code).expect("mem_write");
    for (name, val) in init {
        if let Some((_, reg)) = GPRS.iter().find(|(n, _)| n == name) {
            uc.reg_write(*reg, *val).expect("reg_write");
        }
    }
    uc.emu_start(BASE, BASE + code.len() as u64, 0, 0)
        .expect("emu_start");

    // --- Our emulator ---
    let mut m = Machine::new(Concrete);
    for (name, val) in init {
        let v = m.dom.constant(Width::W64, *val as u128);
        m.regs.write(&mut m.dom, &VReg::phys(*name), v);
    }
    let instrs = lift_x86::lift_bytes(code, BASE, 64);
    let blk = LlirBlock {
        start_va: BASE,
        end_va: BASE + code.len() as u64,
        instrs,
        succs: vec![],
    };
    match m.run_block(&blk) {
        Flow::Next => {}
        Flow::Halt(h) => return DiffOutcome::OurRunIncomplete(format!("{:?}", h)),
        other => return DiffOutcome::OurRunIncomplete(format!("{:?}", other)),
    }

    // --- Compare GPRs ---
    let mut diffs = Vec::new();
    for (name, reg) in GPRS {
        let unicorn = uc.reg_read(*reg).expect("reg_read");
        let ours = m.regs.read(&mut m.dom, &VReg::phys(*name)) as u64;
        if ours != unicorn {
            diffs.push(Divergence {
                reg: name,
                ours,
                unicorn,
            });
        }
    }
    if diffs.is_empty() {
        DiffOutcome::Match
    } else {
        DiffOutcome::Diverged(diffs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_unicorn_on_32bit_arithmetic() {
        // mov eax,10 ; mov ecx,3 ; add eax,ecx ; sub eax,1   → eax = 12
        let code = [
            0xB8, 0x0A, 0x00, 0x00, 0x00, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x01, 0xC8, 0x83, 0xE8,
            0x01,
        ];
        assert_eq!(diff_x86_64(&code, &[]), DiffOutcome::Match);
    }

    #[test]
    fn matches_unicorn_on_64bit_ops_with_inputs() {
        // add rax, rbx ; xor rcx, rcx ; sub rdx, rsi  (REX.W forms)
        let code = [
            0x48, 0x01, 0xD8, // add rax, rbx
            0x48, 0x31, 0xC9, // xor rcx, rcx
            0x48, 0x29, 0xF2, // sub rdx, rsi
        ];
        let init = [
            ("rax", 0x1000u64),
            ("rbx", 0x0337u64),
            ("rcx", 0xdead_beefu64),
            ("rdx", 100u64),
            ("rsi", 40u64),
        ];
        assert_eq!(diff_x86_64(&code, &init), DiffOutcome::Match);
    }

    #[test]
    fn matches_unicorn_on_logical_and_shifts() {
        // and rax, rbx ; shl rax, 4 ; or rax, rcx
        let code = [
            0x48, 0x21, 0xD8, // and rax, rbx
            0x48, 0xC1, 0xE0, 0x04, // shl rax, 4
            0x48, 0x09, 0xC8, // or rax, rcx
        ];
        let init = [("rax", 0xff0fu64), ("rbx", 0x0ff0u64), ("rcx", 0x3u64)];
        assert_eq!(diff_x86_64(&code, &init), DiffOutcome::Match);
    }

    #[test]
    fn inventory_coverage_against_unicorn() {
        // Common linear instructions, cross-checked against Unicorn.
        // MATCH = validated semantic; GAP = unmodelled (tolerated, backlog);
        // DIVERGED = real bug (fails the test).
        #[rustfmt::skip]
        let cases: &[(&str, &[u8], &[(&str, u64)])] = &[
            ("mov rax,rbx",          &[0x48,0x89,0xD8], &[("rbx", 0x1234)]),
            ("lea rax,[rbx+rcx*2+8]",&[0x48,0x8D,0x44,0x4B,0x08], &[("rbx",0x100),("rcx",0x10)]),
            ("movzx eax,bl",         &[0x0F,0xB6,0xC3], &[("rbx", 0xff)]),
            ("movsx rax,bl",         &[0x48,0x0F,0xBE,0xC3], &[("rbx", 0x80)]),
            ("movsxd rax,ebx",       &[0x48,0x63,0xC3], &[("rbx", 0x8000_0000)]),
            ("imul rax,rbx",         &[0x48,0x0F,0xAF,0xC3], &[("rax",7),("rbx",6)]),
            ("imul rax,rbx,imm",     &[0x48,0x6B,0xC3,0x05], &[("rbx",6)]),
            ("inc rax",              &[0x48,0xFF,0xC0], &[("rax", 0xff)]),
            ("dec rax",              &[0x48,0xFF,0xC8], &[("rax", 0x100)]),
            ("neg rax",              &[0x48,0xF7,0xD8], &[("rax", 5)]),
            ("not rax",              &[0x48,0xF7,0xD0], &[("rax", 0xff)]),
            ("xchg rax,rbx",         &[0x48,0x87,0xD8], &[("rax",1),("rbx",2)]),
            ("test+sete",            &[0x48,0x85,0xC0,0x0F,0x94,0xC0], &[("rax",0)]),
            ("cmp+setl",             &[0x48,0x39,0xD8,0x0F,0x9C,0xC0], &[("rax",1),("rbx",2)]),
            ("shl rax,cl",           &[0x48,0xD3,0xE0], &[("rax",1),("rcx",8)]),
            ("shr rax,imm",          &[0x48,0xC1,0xE8,0x04], &[("rax",0xff0)]),
            ("sar rax,imm",          &[0x48,0xC1,0xF8,0x04], &[("rax",0xffff_ffff_ffff_ff00)]),
            ("rol eax,imm",          &[0xC1,0xC0,0x08], &[("rax",0x1234_5678)]),
            ("ror eax,imm",          &[0xC1,0xC8,0x08], &[("rax",0x1234_5678)]),
            ("add eax,imm32",        &[0x05,0x10,0x00,0x00,0x00], &[("rax",1)]),
            ("and rax,imm8",         &[0x48,0x83,0xE0,0x0F], &[("rax",0xff)]),
            ("bswap eax",            &[0x0F,0xC8], &[("rax",0x1234_5678)]),
            ("cmovz rbx,rcx",        &[0x48,0x85,0xC0,0x48,0x0F,0x44,0xD9], &[("rax",0),("rbx",1),("rcx",0x55)]),
            ("mul rbx",              &[0x48,0xF7,0xE3], &[("rax",0x10),("rbx",0x20)]),
            ("xadd rax,rbx",         &[0x48,0x0F,0xC1,0xD8], &[("rax",1),("rbx",2)]),
            ("bt+setc",              &[0x48,0x0F,0xA3,0xD8,0x0F,0x92,0xC1], &[("rax",0b1000),("rbx",3)]),
        ];
        let (mut matched, mut gaps, mut diverged) = (0u32, Vec::new(), Vec::new());
        for (name, code, init) in cases {
            match diff_x86_64(code, init) {
                DiffOutcome::Match => {
                    matched += 1;
                    eprintln!("  MATCH      {}", name);
                }
                DiffOutcome::OurRunIncomplete(why) => {
                    gaps.push(*name);
                    eprintln!("  GAP        {}  ({})", name, why);
                }
                DiffOutcome::Diverged(d) => {
                    diverged.push(*name);
                    eprintln!("  DIVERGED   {}  {:?}", name, d);
                }
            }
        }
        eprintln!(
            "  ---- {}/{} match, {} gap(s), {} diverged ----",
            matched,
            cases.len(),
            gaps.len(),
            diverged.len()
        );
        assert!(
            diverged.is_empty(),
            "semantic divergences from Unicorn (real bugs): {:?}",
            diverged
        );
    }
}
