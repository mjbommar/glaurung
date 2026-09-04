use std::path::PathBuf;

use super::image::{ImageMemoryKind, ProgramImage, ProgramImageError};
use crate::core::binary::{Arch, Format};
use crate::ir::call_args::CallConv;
use crate::target::{CodeMode, OsAbi, PcRule, TargetId};
use object::{Object, ObjectSection};

fn hello_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0")
}

#[test]
fn one_owned_image_answers_target_entry_and_address_queries_without_reparsing() {
    let image = ProgramImage::from_path(&hello_binary()).expect("parse real ELF");

    assert_eq!(image.format(), Format::ELF);
    assert_eq!(image.arch(), Arch::X86_64);
    assert_eq!(image.entry_va(), 0x2460);
    assert_eq!(image.defined_text_symbol_address("main"), Some(0x2549));
    assert_eq!(image.defined_symbol_name_at(0x2549), Some("main"));
    assert_eq!(image.va_to_code_file_offset(0x2549), Some(0x2549));
    assert_eq!(image.va_to_file_offset(0x2549), Some(0x2549));
    assert!(image
        .executable_ranges()
        .any(|range| range.contains(&0x2549)));
    assert_eq!(image.bytes(), std::fs::read(hello_binary()).unwrap());

    let target = image.target();
    assert_eq!(target.id(), TargetId::X86_64);
    assert_eq!(target.architecture(), Arch::X86_64);
    assert_eq!(target.address_bits(), Some(64));
    assert_eq!(target.pointer_bits(), Some(64));
    assert_eq!(target.default_code_mode(), Some(CodeMode::X86_64));
    assert_eq!(target.calling_convention(), Some(CallConv::SysVAmd64));
    assert_eq!(target.os_abi(), OsAbi::SystemV);
    assert_eq!(target.instruction_alignment(CodeMode::X86_64), Some(1));
    assert_eq!(
        target.pc_rule(CodeMode::X86_64),
        Some(PcRule::NextInstruction)
    );
    assert_eq!(target.registers().stack_pointer(), &["rsp", "esp"]);
}

#[test]
fn a_text_symbol_name_at_multiple_addresses_is_not_a_unique_identity() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/decompiler_fixtures/build/166_rust_generics-rustc-O0.so");
    if !binary.is_file() {
        crate::testing::missing_fixture("166_rust_generics-rustc-O0.so");
        return;
    }
    let image = ProgramImage::from_path(&binary).expect("parse real Rust fixture");
    let duplicate = "_ZN4core3ptr28drop_in_place$LT$$RF$str$GT$17h230fbaafe2cfecddE";

    assert!(image.defined_text_symbol_address(duplicate).is_some());
    assert_eq!(image.unique_defined_text_symbol_address(duplicate), None);
    assert_eq!(
        image.unique_defined_text_symbol_address("rust_generic_i32"),
        Some(0x7c20)
    );
}

#[test]
fn one_owned_image_reuses_exact_unwind_function_extents() {
    let data = std::fs::read(hello_binary()).expect("read real ELF");
    let expected = crate::analysis::exception::eh_frame_functions(&data);
    let image = ProgramImage::from_bytes(data).expect("parse real ELF");

    assert!(!expected.is_empty());
    assert_eq!(image.eh_frame_functions(), expected);
}

#[test]
fn malformed_input_fails_closed_instead_of_creating_an_unknown_image() {
    let error = ProgramImage::from_bytes(vec![0xde, 0xad, 0xbe, 0xef])
        .expect_err("invalid image must be rejected");

    assert!(matches!(error, ProgramImageError::Parse(_)));
}

#[test]
fn unmapped_addresses_do_not_wrap_or_alias_file_offsets() {
    let image = ProgramImage::from_path(&hello_binary()).expect("parse real ELF");

    assert_eq!(image.va_to_file_offset(u64::MAX), None);
    assert_eq!(image.va_to_code_file_offset(u64::MAX), None);
}

#[test]
fn legacy_entry_helpers_and_program_image_queries_have_exact_parity() {
    let data = std::fs::read(hello_binary()).unwrap();
    let image = ProgramImage::from_bytes(data.clone()).expect("parse real ELF");
    let entry = crate::analysis::entry::detect_entry_in(&image);

    assert_eq!(entry, crate::analysis::entry::detect_entry(&data));
    for va in [0, image.entry_va(), 0x2549, u64::MAX] {
        assert_eq!(
            crate::analysis::entry::va_to_file_offset_in(&image, va),
            crate::analysis::entry::va_to_file_offset(&data, va)
        );
        assert_eq!(
            crate::analysis::entry::va_to_code_file_offset_in(&image, va),
            crate::analysis::entry::va_to_code_file_offset(&data, va)
        );
    }
}

#[test]
fn address_index_matches_legacy_translation_on_arm32_and_pe() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binaries = [
        root.join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc"),
        root.join(
            "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
        ),
    ];

    for binary in binaries {
        let data = std::fs::read(&binary).expect("read checked-in binary");
        let image = ProgramImage::from_bytes(data.clone()).expect("index checked-in binary");
        let entry = image.entry_va();
        assert_eq!(
            crate::analysis::entry::detect_entry_in(&image),
            crate::analysis::entry::detect_entry(&data),
            "{}",
            binary.display()
        );
        for va in [entry, entry.saturating_add(1), u64::MAX] {
            assert_eq!(
                image.va_to_file_offset(va),
                crate::analysis::entry::va_to_file_offset(&data, va),
                "{} at {va:#x}",
                binary.display()
            );
            assert_eq!(
                image.va_to_code_file_offset(va),
                crate::analysis::entry::va_to_code_file_offset(&data, va),
                "{} at {va:#x}",
                binary.display()
            );
        }
    }
}

#[test]
fn arm32_function_entries_are_normalized_from_indexed_target_metadata() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc");
    let image = ProgramImage::from_path(&binary).expect("index armhf ELF");

    assert_eq!(image.arch(), Arch::ARM);
    assert_eq!(image.normalize_function_entry(0x46d), 0x46c);
    assert_eq!(image.normalize_function_entry(0x4c8), 0x4c8);
    assert!(image.arm_hard_float());

    let target = image.target();
    assert_eq!(target.id(), TargetId::Arm32);
    assert_eq!(target.address_bits(), Some(32));
    assert_eq!(target.pointer_bits(), Some(32));
    assert_eq!(target.default_code_mode(), Some(CodeMode::ArmA32));
    assert_eq!(target.code_mode_for_function(false), Some(CodeMode::ArmA32));
    assert_eq!(
        target.code_mode_for_function(true),
        Some(CodeMode::ArmThumb)
    );
    assert_eq!(target.calling_convention(), Some(CallConv::ArmHardFloat));
    assert_eq!(target.instruction_alignment(CodeMode::ArmA32), Some(4));
    assert_eq!(target.instruction_alignment(CodeMode::ArmThumb), Some(2));
    assert_eq!(
        target.pc_rule(CodeMode::ArmA32),
        Some(PcRule::CurrentPlus(8))
    );
    assert_eq!(
        target.pc_rule(CodeMode::ArmThumb),
        Some(PcRule::CurrentPlus(4))
    );
    assert_eq!(target.registers().stack_pointer(), &["sp", "r13"]);
    assert_eq!(target.registers().frame_pointer(), &["r11", "r7", "fp"]);
    assert_eq!(target.registers().link_register(), &["lr", "r14"]);
}

#[test]
fn target_spec_is_exact_across_real_aarch64_and_windows_images() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let aarch64 = ProgramImage::from_path(
        &root.join("samples/binaries/platforms/linux/arm64/export/native/gcc/O0/hello-c-gcc-O0"),
    )
    .expect("index real AArch64 ELF");
    assert_eq!(aarch64.target().id(), TargetId::AArch64);
    assert_eq!(
        aarch64.target().default_code_mode(),
        Some(CodeMode::AArch64)
    );
    assert_eq!(
        aarch64.target().calling_convention(),
        Some(CallConv::Aarch64)
    );
    assert_eq!(aarch64.target().os_abi(), OsAbi::SystemV);
    assert_eq!(
        aarch64.target().instruction_alignment(CodeMode::AArch64),
        Some(4)
    );
    assert_eq!(aarch64.target().registers().stack_pointer(), &["sp"]);
    assert_eq!(aarch64.target().registers().frame_pointer(), &["x29", "fp"]);

    let pe32 = ProgramImage::from_path(&root.join(
        "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
    ))
    .expect("index real PE32");
    assert_eq!(pe32.target().id(), TargetId::X86_32);
    assert_eq!(pe32.target().default_code_mode(), Some(CodeMode::X86_32));
    assert_eq!(pe32.target().calling_convention(), Some(CallConv::Cdecl32));
    assert_eq!(pe32.target().os_abi(), OsAbi::Windows);
    assert_eq!(pe32.target().pointer_bits(), Some(32));

    let pe64 = ProgramImage::from_path(&root.join(
        "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe",
    ))
    .expect("index real PE64");
    assert_eq!(pe64.target().id(), TargetId::X86_64);
    assert_eq!(pe64.target().calling_convention(), Some(CallConv::Win64));
    assert_eq!(pe64.target().os_abi(), OsAbi::Windows);

    let riscv64 = ProgramImage::from_path(
        &root.join("samples/binaries/platforms/linux/amd64/cross/riscv64/hello-riscv64-gcc"),
    )
    .expect("index real RISC-V ELF");
    assert_eq!(riscv64.target().id(), TargetId::Unsupported(Arch::RISCV64));
    assert_eq!(riscv64.target().address_bits(), Some(64));
    assert_eq!(riscv64.target().default_code_mode(), None);
    assert_eq!(riscv64.target().calling_convention(), None);
}

#[test]
fn cfg_discovery_accepts_the_same_owned_image_without_changing_results() {
    let data = std::fs::read(hello_binary()).unwrap();
    let image = ProgramImage::from_bytes(data.clone()).expect("parse real ELF");
    let budgets = crate::analysis::cfg::Budgets {
        max_functions: 2,
        max_blocks: 256,
        max_instructions: 10_000,
        timeout_ms: 1_000,
        total_timeout_ms: 0,
    };

    let (legacy, _) =
        crate::analysis::cfg::analyze_functions_bytes_with_seeds(&data, &budgets, &[0x2549]);
    let (indexed, _) =
        crate::analysis::cfg::analyze_functions_image_with_seeds(&image, &budgets, &[0x2549]);

    assert_eq!(indexed, legacy);
}

#[test]
fn llir_lifting_reuses_the_owned_image_without_changing_instructions() {
    let data = std::fs::read(hello_binary()).unwrap();
    let image = ProgramImage::from_bytes(data.clone()).expect("parse real ELF");
    let budgets = crate::analysis::cfg::Budgets {
        max_functions: 1,
        max_blocks: 256,
        max_instructions: 10_000,
        timeout_ms: 1_000,
        total_timeout_ms: 0,
    };
    let (functions, _) =
        crate::analysis::cfg::analyze_functions_image_with_seeds(&image, &budgets, &[0x2549]);
    let function = functions
        .iter()
        .find(|function| function.entry_point.value == 0x2549)
        .expect("discover main");

    let legacy = crate::ir::lift_function::lift_function_from_bytes(&data, function, Arch::X86_64);
    let indexed = crate::ir::lift_function::lift_function_from_image(&image, function);

    assert_eq!(indexed, legacy);

    let mut contradictory = function.clone();
    contradictory.add_flag(crate::core::function::FunctionFlags::IS_THUMB);
    assert!(
        crate::ir::lift_function::lift_function_from_image(&image, &contradictory).is_err(),
        "a per-function mode marker must belong to the image target"
    );
}

#[test]
fn indexed_sections_reuse_exact_file_backed_rodata_without_reparsing() {
    let data = std::fs::read(hello_binary()).expect("read real ELF");
    let object = crate::decompile::profile::parse_object(&data).expect("parse control ELF");
    let expected = object
        .sections()
        .find(|section| section.name() == Ok(".rodata"))
        .expect("control ELF has .rodata");
    let expected_address = expected.address();
    let expected_data = expected.data().expect("read control .rodata").to_vec();
    drop(object);

    let image = ProgramImage::from_bytes(data).expect("index real ELF");
    let actual = image
        .sections()
        .find(|section| section.name() == ".rodata")
        .expect("indexed image retains .rodata");

    assert_eq!(actual.address(), expected_address);
    assert_eq!(actual.data(), expected_data);
}

#[test]
fn indexed_section_bytes_match_the_parser_across_object_formats() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binaries = [
        hello_binary(),
        root.join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc"),
        root.join(
            "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
        ),
        root.join("samples/binaries/platforms/darwin/amd64/export/native/multi_import-macho"),
    ];

    for binary in binaries {
        let data = std::fs::read(&binary).expect("read checked-in object");
        let object = crate::decompile::profile::parse_object(&data).expect("parse control object");
        let expected = object
            .sections()
            .filter_map(|section| {
                let (offset, size) = section.file_range()?;
                let end = offset.checked_add(size)?;
                (end <= data.len() as u64).then(|| {
                    (
                        section.name().unwrap_or("").to_string(),
                        section.address(),
                        section.data().expect("read control section").to_vec(),
                    )
                })
            })
            .collect::<Vec<_>>();
        drop(object);

        let image = ProgramImage::from_bytes(data).expect("index checked-in object");
        let actual = image
            .sections()
            .map(|section| {
                (
                    section.name().to_string(),
                    section.address(),
                    section.data().to_vec(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(actual, expected, "{}", binary.display());
    }
}

#[test]
fn image_memory_classification_keeps_readonly_writable_and_bss_distinct() {
    let data = std::fs::read(hello_binary()).expect("read real ELF");
    let object = crate::decompile::profile::parse_object(&data).expect("parse real ELF");
    let section_address = |name: &str| {
        object
            .sections()
            .find(|section| section.name() == Ok(name))
            .filter(|section| section.size() != 0)
            .map(|section| section.address())
            .unwrap_or_else(|| panic!("real ELF has nonempty {name}"))
    };
    let rodata = section_address(".rodata");
    let data_va = section_address(".data");
    let bss = section_address(".bss");
    drop(object);

    let image = ProgramImage::from_bytes(data).expect("index real ELF");
    assert_eq!(
        image.memory_kind_at(rodata),
        Some(ImageMemoryKind::ReadOnly)
    );
    assert_eq!(
        image.memory_kind_at(data_va),
        Some(ImageMemoryKind::Writable)
    );
    assert_eq!(
        image.memory_kind_at(bss),
        Some(ImageMemoryKind::Writable),
        "uninitialized image storage must be indexed even without file bytes"
    );
    assert_eq!(image.memory_kind_at(u64::MAX), None);
}

/// A packed file must index into the program, not into the decompressor stub.
///
/// `analyze_functions_path` unpacks, so it hands back the ORIGINAL program's
/// addresses. Anything built on a `ProgramImage` of the same file — the
/// decompiler, the symbol store, the call graph — has to be looking at the same
/// bytes, or a function discovered one moment cannot be decompiled the next.
#[test]
fn indexing_a_packed_file_from_a_path_indexes_the_program_it_hides() {
    let build = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/realistic_corpus/build");
    let (Ok(packed_bytes), Ok(original_bytes)) = (
        std::fs::read(build.join("corpus.upx")),
        std::fs::read(build.join("corpus.strip")),
    ) else {
        return; // corpus not built in this checkout
    };

    let packed = ProgramImage::from_path(&build.join("corpus.upx")).expect("index packed image");
    let original =
        ProgramImage::from_path(&build.join("corpus.strip")).expect("index original image");

    assert_ne!(
        packed.bytes(),
        packed_bytes.as_slice(),
        "the packed file's own bytes were indexed, so every query below answers \
         about the UPX stub"
    );
    assert_eq!(packed.bytes(), original_bytes.as_slice());
    assert_eq!(packed.entry_va(), original.entry_va());
    assert_eq!(
        packed.executable_ranges().collect::<Vec<_>>(),
        original.executable_ranges().collect::<Vec<_>>()
    );
}
