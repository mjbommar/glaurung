//! Exhaustive conformance table for [`crate::target::TargetSpec`].
//!
//! # Why this file exists
//!
//! `src/target/` had **one** test across four files, and it is the module that
//! answers "how wide is a pointer here", "which way round are the bytes", and
//! "which calling convention do I assume" for everything downstream of it. A
//! wrong answer from this layer does not fail loudly: a flipped pointer width
//! silently changes every recovered prototype, and a flipped calling
//! convention silently changes every recovered argument. The decompiler keeps
//! emitting plausible C.
//!
//! # What this is, and what it deliberately is not
//!
//! The expectations below are a **hand-written table**, not a second copy of
//! the implementation's control flow. They are written as literal data --
//! architecture facts (width, default encoding, register spellings), container
//! facts (which OS ABI a format establishes), and the calling-convention
//! matrix -- so that a future edit to `spec.rs` cannot make this file agree
//! with it by construction. If a row here and the implementation disagree,
//! exactly one of them is wrong and a human has to decide which.
//!
//! The driver walks the **entire** cross product of
//! `Arch x Format x Endianness x arm_hard_float` (396 specs at the time of
//! writing), so a newly added `Arch` or `Format` variant fails here with a
//! "no expectation row" message rather than defaulting into whatever the
//! nearest match happens to be.

use super::*;
use crate::core::binary::{Arch, Endianness, Format};

/// Every `Arch` variant. Kept explicit rather than derived so that adding a
/// variant to `core::binary::Arch` breaks this list at review time.
const ALL_ARCHES: &[Arch] = &[
    Arch::X86,
    Arch::X86_64,
    Arch::ARM,
    Arch::AArch64,
    Arch::MIPS,
    Arch::MIPS64,
    Arch::PPC,
    Arch::PPC64,
    Arch::RISCV,
    Arch::RISCV64,
    Arch::Unknown,
];

/// Every `Format` variant, same reasoning as [`ALL_ARCHES`].
const ALL_FORMATS: &[Format] = &[
    Format::ELF,
    Format::PE,
    Format::MachO,
    Format::Wasm,
    Format::PythonBytecode,
    Format::Dex,
    Format::COFF,
    Format::Raw,
    Format::Unknown,
];

const ALL_ENDIAN: &[Endianness] = &[Endianness::Little, Endianness::Big];

/// Every `CodeMode` variant.
const ALL_MODES: &[CodeMode] = &[
    CodeMode::X86_32,
    CodeMode::X86_64,
    CodeMode::AArch64,
    CodeMode::ArmA32,
    CodeMode::ArmThumb,
];

/// Hand-written per-architecture expectations.
///
/// Fields, in order: the architecture; the decompiler target identity it maps
/// to (`None` means "must be `TargetId::Unsupported(this arch)`"); the address
/// and pointer width in bits; the default instruction encoding; and the
/// accepted stack-pointer / frame-pointer / link-register / program-counter
/// spellings in canonical-first order.
struct ArchRow {
    arch: Arch,
    id: Option<TargetId>,
    bits: Option<u8>,
    default_mode: Option<CodeMode>,
    stack_pointer: &'static [&'static str],
    frame_pointer: &'static [&'static str],
    link_register: &'static [&'static str],
    program_counter: &'static [&'static str],
}

const ARCH_ROWS: &[ArchRow] = &[
    ArchRow {
        arch: Arch::X86,
        id: Some(TargetId::X86_32),
        bits: Some(32),
        default_mode: Some(CodeMode::X86_32),
        stack_pointer: &["rsp", "esp"],
        frame_pointer: &["rbp", "ebp"],
        link_register: &[],
        program_counter: &["rip", "eip"],
    },
    ArchRow {
        arch: Arch::X86_64,
        id: Some(TargetId::X86_64),
        bits: Some(64),
        default_mode: Some(CodeMode::X86_64),
        stack_pointer: &["rsp", "esp"],
        frame_pointer: &["rbp", "ebp"],
        link_register: &[],
        program_counter: &["rip", "eip"],
    },
    ArchRow {
        arch: Arch::ARM,
        id: Some(TargetId::Arm32),
        bits: Some(32),
        default_mode: Some(CodeMode::ArmA32),
        stack_pointer: &["sp", "r13"],
        frame_pointer: &["r11", "r7", "fp"],
        link_register: &["lr", "r14"],
        program_counter: &["pc", "r15"],
    },
    ArchRow {
        arch: Arch::AArch64,
        id: Some(TargetId::AArch64),
        bits: Some(64),
        default_mode: Some(CodeMode::AArch64),
        stack_pointer: &["sp"],
        frame_pointer: &["x29", "fp"],
        link_register: &["x30", "lr"],
        program_counter: &["pc"],
    },
    // The ISAs the program layer parses but the LLIR decompiler does not
    // lift. They still have a defensible pointer width, and reporting one is
    // the point: triage prints it even when decompilation is impossible.
    ArchRow {
        arch: Arch::MIPS,
        id: None,
        bits: Some(32),
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
    ArchRow {
        arch: Arch::MIPS64,
        id: None,
        bits: Some(64),
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
    ArchRow {
        arch: Arch::PPC,
        id: None,
        bits: Some(32),
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
    ArchRow {
        arch: Arch::PPC64,
        id: None,
        bits: Some(64),
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
    ArchRow {
        arch: Arch::RISCV,
        id: None,
        bits: Some(32),
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
    ArchRow {
        arch: Arch::RISCV64,
        id: None,
        bits: Some(64),
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
    // Unknown must not acquire a width by accident. A `Some(64)` here would
    // be the single most damaging default in the module: every unrecognised
    // ISA would silently be treated as 64-bit.
    ArchRow {
        arch: Arch::Unknown,
        id: None,
        bits: None,
        default_mode: None,
        stack_pointer: &[],
        frame_pointer: &[],
        link_register: &[],
        program_counter: &[],
    },
];

/// Which OS ABI each container format establishes.
///
/// `COFF` is the interesting row and the reason the module's one pre-existing
/// test exists: a bare COFF object is not evidence of Windows, so it must not
/// pull in the Win64 convention.
const FORMAT_ROWS: &[(Format, OsAbi)] = &[
    (Format::ELF, OsAbi::SystemV),
    (Format::PE, OsAbi::Windows),
    (Format::MachO, OsAbi::Darwin),
    (Format::Wasm, OsAbi::Unknown),
    (Format::PythonBytecode, OsAbi::Unknown),
    (Format::Dex, OsAbi::Unknown),
    (Format::COFF, OsAbi::Unknown),
    (Format::Raw, OsAbi::Unknown),
    (Format::Unknown, OsAbi::Unknown),
];

/// The full calling-convention matrix: `(arch, os_abi, arm_hard_float)`.
///
/// Only architectures with a supported target identity appear; everything
/// else must report `None` and is checked by the driver. Written out in full
/// rather than as a `match` because a `match` here would just be `spec.rs`
/// again -- and the x86-64 rows are precisely where a one-line edit ("PE means
/// Win64") could quietly reclassify Darwin or COFF.
const CALL_CONV_ROWS: &[(Arch, OsAbi, bool, CallConv)] = &[
    // 32-bit x86 is cdecl everywhere we model; hard-float is an ARM concept
    // and must not leak into it.
    (Arch::X86, OsAbi::SystemV, false, CallConv::Cdecl32),
    (Arch::X86, OsAbi::SystemV, true, CallConv::Cdecl32),
    (Arch::X86, OsAbi::Windows, false, CallConv::Cdecl32),
    (Arch::X86, OsAbi::Windows, true, CallConv::Cdecl32),
    (Arch::X86, OsAbi::Darwin, false, CallConv::Cdecl32),
    (Arch::X86, OsAbi::Darwin, true, CallConv::Cdecl32),
    (Arch::X86, OsAbi::Unknown, false, CallConv::Cdecl32),
    (Arch::X86, OsAbi::Unknown, true, CallConv::Cdecl32),
    // x86-64: Windows and only Windows is Win64. Darwin and an unestablished
    // ABI both fall back to System V, which is the correct guess for both.
    (Arch::X86_64, OsAbi::SystemV, false, CallConv::SysVAmd64),
    (Arch::X86_64, OsAbi::SystemV, true, CallConv::SysVAmd64),
    (Arch::X86_64, OsAbi::Windows, false, CallConv::Win64),
    (Arch::X86_64, OsAbi::Windows, true, CallConv::Win64),
    (Arch::X86_64, OsAbi::Darwin, false, CallConv::SysVAmd64),
    (Arch::X86_64, OsAbi::Darwin, true, CallConv::SysVAmd64),
    (Arch::X86_64, OsAbi::Unknown, false, CallConv::SysVAmd64),
    (Arch::X86_64, OsAbi::Unknown, true, CallConv::SysVAmd64),
    // AArch64 has one procedure-call standard regardless of container.
    (Arch::AArch64, OsAbi::SystemV, false, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::SystemV, true, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::Windows, false, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::Windows, true, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::Darwin, false, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::Darwin, true, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::Unknown, false, CallConv::Aarch64),
    (Arch::AArch64, OsAbi::Unknown, true, CallConv::Aarch64),
    // ARM32 is the only architecture where the hard-float flag selects, and
    // it must select on every container.
    (Arch::ARM, OsAbi::SystemV, false, CallConv::Arm),
    (Arch::ARM, OsAbi::SystemV, true, CallConv::ArmHardFloat),
    (Arch::ARM, OsAbi::Windows, false, CallConv::Arm),
    (Arch::ARM, OsAbi::Windows, true, CallConv::ArmHardFloat),
    (Arch::ARM, OsAbi::Darwin, false, CallConv::Arm),
    (Arch::ARM, OsAbi::Darwin, true, CallConv::ArmHardFloat),
    (Arch::ARM, OsAbi::Unknown, false, CallConv::Arm),
    (Arch::ARM, OsAbi::Unknown, true, CallConv::ArmHardFloat),
];

/// Per-encoding facts: which target owns the mode, the minimum alignment of an
/// instruction start, and how the architectural PC reads.
///
/// The ARM biases are the load-bearing numbers: A32 reads PC as
/// `current + 8` and Thumb as `current + 4`. Swapping them makes every
/// PC-relative literal pool load off by four bytes, which decompiles to a
/// wrong constant rather than to an error.
const MODE_ROWS: &[(CodeMode, TargetId, u8, PcRule)] = &[
    (
        CodeMode::X86_32,
        TargetId::X86_32,
        1,
        PcRule::NextInstruction,
    ),
    (
        CodeMode::X86_64,
        TargetId::X86_64,
        1,
        PcRule::NextInstruction,
    ),
    (
        CodeMode::AArch64,
        TargetId::AArch64,
        4,
        PcRule::NotGeneralPurpose,
    ),
    (CodeMode::ArmA32, TargetId::Arm32, 4, PcRule::CurrentPlus(8)),
    (
        CodeMode::ArmThumb,
        TargetId::Arm32,
        2,
        PcRule::CurrentPlus(4),
    ),
];

fn arch_row(arch: Arch) -> &'static ArchRow {
    ARCH_ROWS
        .iter()
        .find(|r| r.arch == arch)
        .unwrap_or_else(|| {
            panic!(
                "no expectation row for {arch:?}; a variant was added to \
                 core::binary::Arch without deciding its pointer width, default \
                 encoding and register roles. Add a row to ARCH_ROWS in \
                 src/target/conformance.rs."
            )
        })
}

fn expected_os_abi(format: Format) -> OsAbi {
    FORMAT_ROWS
        .iter()
        .find(|(f, _)| *f == format)
        .map(|(_, abi)| *abi)
        .unwrap_or_else(|| {
            panic!(
                "no expectation row for {format:?}; a variant was added to \
                 core::binary::Format without deciding which OS ABI it \
                 establishes. Add a row to FORMAT_ROWS in \
                 src/target/conformance.rs."
            )
        })
}

fn expected_call_conv(arch: Arch, os_abi: OsAbi, hard_float: bool) -> Option<CallConv> {
    CALL_CONV_ROWS
        .iter()
        .find(|(a, o, hf, _)| *a == arch && *o == os_abi && *hf == hard_float)
        .map(|(_, _, _, cc)| *cc)
}

/// Walk the whole `Arch x Format x Endianness x hard_float` cross product.
///
/// Every assertion names the exact spec that produced it, because a failure
/// here arrives as one row out of several hundred and the first question is
/// always "which target".
#[test]
fn every_target_spec_matches_the_hand_written_table() {
    let mut cases = 0usize;

    for &arch in ALL_ARCHES {
        let row = arch_row(arch);
        for &format in ALL_FORMATS {
            let want_abi = expected_os_abi(format);
            for &endianness in ALL_ENDIAN {
                for &hard_float in &[false, true] {
                    cases += 1;
                    let spec =
                        TargetSpec::from_image_metadata(arch, endianness, format, hard_float);
                    let what = format!(
                        "TargetSpec::from_image_metadata({arch:?}, {endianness:?}, \
                         {format:?}, hard_float={hard_float})"
                    );

                    // Identity. `None` in the table means the ISA is parsed
                    // but not lifted, and the spec must SAY so rather than
                    // silently substituting a supported target.
                    let want_id = row.id.unwrap_or(TargetId::Unsupported(arch));
                    assert_eq!(spec.id(), want_id, "{what}: wrong TargetId");

                    // Facts that must survive unchanged from the parse.
                    assert_eq!(
                        spec.architecture(),
                        arch,
                        "{what}: architecture() must echo the parsed Arch"
                    );
                    assert_eq!(
                        spec.endianness(),
                        endianness,
                        "{what}: endianness() must echo the parsed byte order"
                    );
                    assert_eq!(
                        spec.format(),
                        format,
                        "{what}: format() must echo the parsed container"
                    );

                    // Data layout. Address and pointer widths are separate
                    // accessors, and a target where they disagree would be a
                    // real thing (segmented, or a 32-bit ABI on a 64-bit ISA)
                    // -- none of the targets modelled here is one, so pin it.
                    assert_eq!(spec.address_bits(), row.bits, "{what}: wrong address width");
                    assert_eq!(spec.pointer_bits(), row.bits, "{what}: wrong pointer width");

                    // ABI.
                    assert_eq!(spec.os_abi(), want_abi, "{what}: wrong OS ABI");
                    assert_eq!(
                        spec.calling_convention(),
                        expected_call_conv(arch, want_abi, hard_float),
                        "{what}: wrong default calling convention"
                    );

                    // Instruction encoding.
                    assert_eq!(
                        spec.default_code_mode(),
                        row.default_mode,
                        "{what}: wrong default code mode"
                    );

                    // Register roles are target-qualified precisely because
                    // `sp` and `pc` mean different registers on different
                    // ISAs; an x86 spec answering to `sp` would be a bug.
                    let regs = spec.registers();
                    assert_eq!(
                        regs.stack_pointer(),
                        row.stack_pointer,
                        "{what}: wrong stack-pointer spellings"
                    );
                    assert_eq!(
                        regs.frame_pointer(),
                        row.frame_pointer,
                        "{what}: wrong frame-pointer spellings"
                    );
                    assert_eq!(
                        regs.link_register(),
                        row.link_register,
                        "{what}: wrong link-register spellings"
                    );
                    assert_eq!(
                        regs.program_counter(),
                        row.program_counter,
                        "{what}: wrong program-counter spellings"
                    );
                    for name in row.stack_pointer {
                        assert!(
                            regs.is_stack_pointer(name),
                            "{what}: is_stack_pointer({name:?}) disagrees with \
                             the list it is supposed to search"
                        );
                    }
                    for name in row.frame_pointer {
                        assert!(
                            regs.is_frame_pointer(name),
                            "{what}: is_frame_pointer({name:?}) disagrees with \
                             the list it is supposed to search"
                        );
                    }

                    // Per-function ARM encoding selection. A Thumb marker on a
                    // non-ARM target is a caller bug and must be rejected, not
                    // rounded to the default.
                    let want_thumb = match row.id {
                        Some(TargetId::Arm32) => Some(CodeMode::ArmThumb),
                        _ => None,
                    };
                    assert_eq!(
                        spec.code_mode_for_function(true),
                        want_thumb,
                        "{what}: code_mode_for_function(is_thumb=true)"
                    );
                    let want_a32 = match row.id {
                        Some(TargetId::Arm32) => Some(CodeMode::ArmA32),
                        _ => row.default_mode,
                    };
                    assert_eq!(
                        spec.code_mode_for_function(false),
                        want_a32,
                        "{what}: code_mode_for_function(is_thumb=false)"
                    );

                    // Mode-qualified facts, checked against EVERY mode rather
                    // than only the target's own: answering for a foreign mode
                    // is how an ARM alignment rule reaches an x86 spec.
                    for &(mode, owner, align, pc_rule) in MODE_ROWS {
                        let owned = want_id == owner;
                        assert_eq!(
                            spec.instruction_alignment(mode),
                            owned.then_some(align),
                            "{what}: instruction_alignment({mode:?})"
                        );
                        assert_eq!(
                            spec.pc_rule(mode),
                            owned.then_some(pc_rule),
                            "{what}: pc_rule({mode:?})"
                        );
                    }
                }
            }
        }
    }

    // A loop over an accidentally empty product would pass every assertion
    // above without executing one of them. Pin the exact size of the space.
    let expected = ALL_ARCHES.len() * ALL_FORMATS.len() * ALL_ENDIAN.len() * 2;
    assert_eq!(
        cases, expected,
        "the cross product changed size; update the count deliberately"
    );
    assert_eq!(
        cases, 396,
        "this table covered 396 specs when written. A different number means a \
         variant was added to Arch or Format -- add its expectation row and \
         update this number in the same commit."
    );
}

/// Unsupported ISAs must decline everything rather than guess.
///
/// Split out from the sweep above because it is the property most likely to
/// be broken by a well-meaning "sensible default" patch, and it deserves a
/// test name that says what was lost.
#[test]
fn unsupported_architectures_decline_every_mode_qualified_answer() {
    let mut checked = 0usize;
    for &arch in ALL_ARCHES {
        if arch_row(arch).id.is_some() {
            continue;
        }
        for &format in ALL_FORMATS {
            let spec = TargetSpec::from_image_metadata(arch, Endianness::Little, format, false);
            checked += 1;
            assert_eq!(spec.id(), TargetId::Unsupported(arch));
            assert_eq!(
                spec.default_code_mode(),
                None,
                "{arch:?}/{format:?} claims a default instruction encoding"
            );
            assert_eq!(
                spec.calling_convention(),
                None,
                "{arch:?}/{format:?} claims a default calling convention; a \
                 wrong convention silently rewrites every recovered signature"
            );
            for &mode in ALL_MODES {
                assert_eq!(
                    spec.instruction_alignment(mode),
                    None,
                    "{arch:?}/{format:?} answered instruction_alignment({mode:?})"
                );
                assert_eq!(
                    spec.pc_rule(mode),
                    None,
                    "{arch:?}/{format:?} answered pc_rule({mode:?})"
                );
            }
            assert_eq!(spec.code_mode_for_function(false), None);
            assert_eq!(spec.code_mode_for_function(true), None);
        }
    }
    assert!(
        checked >= 7 * ALL_FORMATS.len(),
        "only {checked} unsupported-arch specs were reachable; the loop found \
         nothing to test, which is a vacuous pass"
    );
}

/// The register-role lists must not overlap between roles on one target.
///
/// A spelling that answers to two roles makes `is_stack_pointer` and
/// `is_frame_pointer` both true, and the stack-frame recovery pass that asks
/// those two questions in sequence takes the first branch forever.
#[test]
fn register_roles_do_not_overlap_within_a_target() {
    for row in ARCH_ROWS {
        let spec =
            TargetSpec::from_image_metadata(row.arch, Endianness::Little, Format::ELF, false);
        let regs = spec.registers();
        let roles: [(&str, &[&str]); 4] = [
            ("stack_pointer", regs.stack_pointer()),
            ("frame_pointer", regs.frame_pointer()),
            ("link_register", regs.link_register()),
            ("program_counter", regs.program_counter()),
        ];
        for (i, (name_a, list_a)) in roles.iter().enumerate() {
            for (name_b, list_b) in roles.iter().skip(i + 1) {
                for spelling in list_a.iter() {
                    assert!(
                        !list_b.contains(spelling),
                        "{:?}: {spelling:?} is listed as both {name_a} and \
                         {name_b}; role queries on this target are ambiguous",
                        row.arch
                    );
                }
            }
        }
        // And no duplicates inside one role list, which would make the
        // "canonical-first order" contract meaningless.
        for (name, list) in roles {
            for (i, spelling) in list.iter().enumerate() {
                assert!(
                    !list[i + 1..].contains(spelling),
                    "{:?}: {spelling:?} appears twice in {name}",
                    row.arch
                );
            }
        }
    }
}
