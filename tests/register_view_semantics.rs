//! Register-view semantics: what the LIFTER produces must mean what the
//! architecture says when EXECUTED.
//!
//! `src/exec/state.rs` owns the canonical register-view layout (canonical parent,
//! bit offset, view width, 32-bit zero-extension, partial-write preservation,
//! x86 high bytes, AArch64 `xN`/`wN`) and unit-tests it directly. Those tests
//! cover the register file. They cannot catch a LIFTER that models a sub-register
//! write against the wrong parent or with a too-narrow mask, because the lifter
//! never consults that layout.
//!
//! So these tests close the loop end to end: lift real machine code, run it on
//! the concrete machine, and assert the resulting 64-bit parent. Written against
//! the architecture, not against the current implementation.
//!
//! Reference (Intel SDM Vol. 1 3.4.1.1 / AMD64 APM Vol. 1 3.1):
//!   * writing a 64-bit GPR replaces all 64 bits;
//!   * writing a 32-bit view (`eax`) ZEROES bits 32..63 of the parent;
//!   * writing a 16-bit (`ax`) or 8-bit (`al`, `ah`) view PRESERVES every other
//!     bit of the 64-bit parent — including bits 32..63.
//! AArch64 (ARM DDI 0487, B1.2.1): writing `wN` zero-extends into `xN`.
//!
//! Requires the `exec` feature (the concrete machine); that is the feature set
//! the Python extension ships, so `cargo test --features exec` is what CI runs.
#![cfg(feature = "exec")]

use glaurung::exec::{Concrete, Flow, Machine, RegArch};
use glaurung::ir::lift_arm64;
use glaurung::ir::lift_x86;
use glaurung::ir::types::{LlirBlock, VReg};

const BASE: u64 = 0x1000;

/// A 64-bit pattern whose every byte is distinct, so a clobbered field is
/// obvious and no two lanes can be confused.
const PATTERN: u64 = 0x1122_3344_5566_7788;

fn run_x86(code: &[u8]) -> Machine<Concrete> {
    let mut m = Machine::new(Concrete);
    let instrs = lift_x86::lift_bytes(code, BASE, 64);
    assert!(
        !instrs.is_empty(),
        "lifter produced no instructions for {code:02x?}"
    );
    for i in &instrs {
        assert!(
            !matches!(i.op, glaurung::ir::types::Op::Unknown { .. }),
            "instruction at {:#x} did not lift ({:?}) — the test would assert \
             nothing",
            i.va,
            i.op
        );
    }
    let blk = LlirBlock {
        start_va: BASE,
        end_va: BASE + code.len() as u64,
        instrs,
        succs: vec![],
    };
    match m.run_block(&blk) {
        Flow::Next => m,
        other => panic!("block did not run to completion: {other:?}"),
    }
}

fn run_arm64(code: &[u8]) -> Machine<Concrete> {
    let mut m = Machine::new_with_arch(Concrete, RegArch::AArch64);
    let instrs = lift_arm64::lift_bytes(code, BASE);
    assert!(!instrs.is_empty(), "lifter produced no instructions");
    let blk = LlirBlock {
        start_va: BASE,
        end_va: BASE + code.len() as u64,
        instrs,
        succs: vec![],
    };
    match m.run_block(&blk) {
        Flow::Next => m,
        other => panic!("block did not run to completion: {other:?}"),
    }
}

fn reg(m: &mut Machine<Concrete>, name: &str) -> u64 {
    m.regs.read(&mut m.dom, &VReg::phys(name)) as u64
}

/// `movabs $imm64, %rax`
fn movabs_rax(v: u64) -> Vec<u8> {
    let mut out = vec![0x48, 0xB8];
    out.extend_from_slice(&v.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// parent write, then narrower reads
// ---------------------------------------------------------------------------

#[test]
fn parent_write_is_visible_through_every_narrower_view() {
    let mut m = run_x86(&movabs_rax(PATTERN));
    assert_eq!(reg(&mut m, "rax"), PATTERN);
    assert_eq!(reg(&mut m, "eax"), 0x5566_7788, "eax = low 32 of rax");
    assert_eq!(reg(&mut m, "ax"), 0x7788, "ax = low 16 of rax");
    assert_eq!(reg(&mut m, "al"), 0x88, "al = low 8 of rax");
    assert_eq!(reg(&mut m, "ah"), 0x77, "ah = bits 8..16 of rax");
}

// ---------------------------------------------------------------------------
// narrow write, then parent read  (the partial-write preservation contract)
// ---------------------------------------------------------------------------

#[test]
fn al_write_preserves_all_other_bits_of_the_parent() {
    // movabs $PATTERN,%rax ; mov $0xAA,%al
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0xB0, 0xAA]);
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0x1122_3344_5566_77AA,
        "writing %al must preserve bits 8..63 of %rax — including the high 32, \
         which a 32-bit parent/mask model silently clears"
    );
}

#[test]
fn al_write_of_zero_preserves_all_other_bits_of_the_parent() {
    // The `mov $0,%al` idiom collapses to a mask-only rewrite; the mask must
    // still be 64-bit wide.
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0xB0, 0x00]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x1122_3344_5566_7700);
}

#[test]
fn ax_write_preserves_all_other_bits_of_the_parent() {
    // movabs $PATTERN,%rax ; mov $0xBBAA,%ax
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x66, 0xB8, 0xAA, 0xBB]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x1122_3344_5566_BBAA);
}

#[test]
fn ah_write_targets_bits_8_to_15_and_preserves_the_rest() {
    // movabs $PATTERN,%rax ; mov $0xAA,%ah  — a HIGH-byte partial write.
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0xB4, 0xAA]);
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0x1122_3344_5566_AA88,
        "%ah is bits 8..16: the low byte 0x88 and everything above bit 16 stay"
    );
}

#[test]
fn eax_write_zeroes_the_upper_half_of_the_parent() {
    // movabs $PATTERN,%rax ; mov $0xDDCCBBAA,%eax
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0xB8, 0xAA, 0xBB, 0xCC, 0xDD]);
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0xDDCC_BBAA,
        "a 32-bit write zero-extends: bits 32..63 of %rax become 0"
    );
}

#[test]
fn partial_write_from_a_register_source_preserves_the_parent() {
    // movabs $PATTERN,%rax ; mov $0xFFAA,%bx ; mov %bl,%al
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x66, 0xBB, 0xAA, 0xFF]); // mov $0xFFAA,%bx
    code.extend_from_slice(&[0x88, 0xD8]); // mov %bl,%al
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0x1122_3344_5566_77AA,
        "only the low byte of the source lands, and only in %al"
    );
}

#[test]
fn r8b_write_preserves_the_upper_bits_of_r8() {
    // movabs $PATTERN,%r8 ; mov $0xAA,%r8b
    let mut code = vec![0x49, 0xB8];
    code.extend_from_slice(&PATTERN.to_le_bytes());
    code.extend_from_slice(&[0x41, 0xB0, 0xAA]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "r8"), 0x1122_3344_5566_77AA);
}

#[test]
fn a_partial_write_does_not_disturb_a_different_register_family() {
    // movabs $PATTERN,%rax ; movabs $PATTERN,%rbx ; mov $0xAA,%al
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x48, 0xBB]);
    code.extend_from_slice(&PATTERN.to_le_bytes());
    code.extend_from_slice(&[0xB0, 0xAA]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x1122_3344_5566_77AA);
    assert_eq!(reg(&mut m, "rbx"), PATTERN, "%rbx must be untouched");
}

// ---------------------------------------------------------------------------
// ALU operations whose destination is a partial view
// ---------------------------------------------------------------------------

#[test]
fn xor_of_a_high_byte_with_itself_clears_only_that_byte() {
    // movabs $PATTERN,%rax ; xor %ah,%ah
    // gcc's byte-lane clear (`v & 0xFFFF00FF`). Lifted as a write to a register
    // named `ah`, the clear reached nothing that a later read of `eax` could see
    // (fixture `deposit_byte1`); it must be a read-modify-write of `rax`.
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x30, 0xE4]);
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0x1122_3344_5566_0088,
        "clearing %ah must clear bits 8..15 of %rax and nothing else"
    );
    assert_eq!(reg(&mut m, "eax"), 0x5566_0088, "the 32-bit view sees the clear");
}

#[test]
fn xor_of_a_low_byte_with_itself_clears_only_that_byte() {
    // movabs $PATTERN,%rax ; xor %al,%al
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x30, 0xC0]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x1122_3344_5566_7700);
}

#[test]
fn add_into_a_low_byte_wraps_within_the_byte() {
    // movabs $PATTERN,%rax ; add $0x80,%al   (0x88 + 0x80 = 0x08 with carry out)
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x04, 0x80]);
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0x1122_3344_5566_7708,
        "8-bit arithmetic must not carry into bit 8 of the parent"
    );
}

#[test]
fn or_into_a_high_byte_reads_that_byte_not_the_parent() {
    // movabs $PATTERN,%rax ; or $0x11,%ah   (0x77 | 0x11 = 0x77)
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x80, 0xCC, 0x11]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x1122_3344_5566_7788);
    // and a value that actually changes it: or $0x88,%ah -> 0x77|0x88 = 0xFF
    let mut code2 = movabs_rax(PATTERN);
    code2.extend_from_slice(&[0x80, 0xCC, 0x88]);
    let mut m2 = run_x86(&code2);
    assert_eq!(reg(&mut m2, "rax"), 0x1122_3344_5566_FF88);
}

#[test]
fn an_alu_op_between_two_partial_views_uses_both_view_values() {
    // movabs $PATTERN,%rax ; add %ah,%al   (0x88 + 0x77 = 0xFF)
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x00, 0xE0]);
    let mut m = run_x86(&code);
    assert_eq!(
        reg(&mut m, "rax"),
        0x1122_3344_5566_77FF,
        "%ah must contribute its own byte, not the whole parent"
    );
}

#[test]
fn a_16_bit_alu_destination_preserves_the_upper_48_bits() {
    // movabs $PATTERN,%rax ; add $0x1,%ax  (0x7788 + 1)
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x66, 0x83, 0xC0, 0x01]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x1122_3344_5566_7789);
}

#[test]
fn a_32_bit_alu_destination_still_zero_extends() {
    // movabs $PATTERN,%rax ; add $0x1,%eax — a 32-bit write clears bits 32..63.
    let mut code = movabs_rax(PATTERN);
    code.extend_from_slice(&[0x83, 0xC0, 0x01]);
    let mut m = run_x86(&code);
    assert_eq!(reg(&mut m, "rax"), 0x5566_7789);
}

// ---------------------------------------------------------------------------
// AArch64: wN writes zero-extend into xN
// ---------------------------------------------------------------------------

#[test]
fn aarch64_w0_write_zero_extends_into_x0() {
    // movz x0, #0x1122, lsl #48 ; movk x0, #0x3344, lsl #32 ; mov w0, #0xAA
    //   d2e22440  movz x0, #0x1122, lsl #48
    //   f2c66880  movk x0, #0x3344, lsl #32
    //   52801540  mov  w0, #0xaa
    let code = [
        0x40, 0x24, 0xE2, 0xD2, // movz x0, #0x1122, lsl #48
        0x80, 0x68, 0xC6, 0xF2, // movk x0, #0x3344, lsl #32
        0x40, 0x15, 0x80, 0x52, // mov  w0, #0xaa
    ];
    let mut m = run_arm64(&code);
    assert_eq!(
        reg(&mut m, "x0"),
        0xAA,
        "writing w0 must zero-extend, clearing bits 32..63 of x0"
    );
    assert_eq!(reg(&mut m, "w0"), 0xAA);
}

// ---------------------------------------------------------------------------
// the shared descriptor is the single source of view layout
// ---------------------------------------------------------------------------

#[test]
fn view_widths_come_from_the_shared_descriptor() {
    use glaurung::ir::regview::{Arch, view};
    for (name, parent, offset, width) in [
        ("rax", "rax", 0, 64),
        ("eax", "rax", 0, 32),
        ("ax", "rax", 0, 16),
        ("al", "rax", 0, 8),
        ("ah", "rax", 8, 8),
        ("r8", "r8", 0, 64),
        ("r8d", "r8", 0, 32),
        ("r8w", "r8", 0, 16),
        ("r8b", "r8", 0, 8),
    ] {
        let v = view(Arch::X86_64, name).unwrap_or_else(|| panic!("no view for {name}"));
        assert_eq!(v.parent, parent, "parent of {name}");
        assert_eq!(v.offset, offset, "offset of {name}");
        assert_eq!(v.width, width, "width of {name}");
    }
    let w0 = view(Arch::AArch64, "w0").expect("w0");
    assert_eq!((w0.parent, w0.offset, w0.width), ("x0", 0, 32));
    assert!(w0.zero_extends(), "a 32-bit AArch64 write zero-extends");
    assert!(
        view(Arch::X86_64, "eax").unwrap().zero_extends(),
        "a 32-bit x86-64 write zero-extends"
    );
    assert!(
        !view(Arch::X86_64, "al").unwrap().zero_extends(),
        "an 8-bit x86-64 write preserves the other bits"
    );
}
