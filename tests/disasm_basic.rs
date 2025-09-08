use glaurung::core::address::{Address, AddressKind};
use glaurung::core::binary::Endianness;
use glaurung::core::disassembler::Architecture;
use glaurung::core::disassembler::Disassembler;
use glaurung::disasm::registry::{for_arch_with, BackendKind};

#[test]
fn decode_x86_64_minimal() {
    // xor rax, rax; ret
    let bytes: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];
    let arch = Architecture::X86_64;
    let backend = glaurung::disasm::registry::for_arch(arch, Endianness::Little).expect("backend");
    let addr = Address::new(AddressKind::VA, 0x401000, 64, None, None).unwrap();
    let ins1 = backend
        .disassemble_instruction(&addr, &bytes)
        .expect("insn");
    assert!(ins1.mnemonic.to_ascii_lowercase().starts_with("xor"));
    assert_eq!(ins1.length as usize, 3);
    let addr2 = Address::new(AddressKind::VA, 0x401003, 64, None, None).unwrap();
    let ins2 = backend
        .disassemble_instruction(&addr2, &bytes[3..])
        .expect("insn2");
    assert!(ins2.mnemonic.to_ascii_lowercase().contains("ret"));
}

#[test]
fn decode_arm64_minimal() {
    // mov x0, #1; ret
    let bytes: [u8; 8] = [0x20, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6];
    let arch = Architecture::ARM64;
    let backend = glaurung::disasm::registry::for_arch(arch, Endianness::Little).expect("backend");
    let addr = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
    let ins1 = backend
        .disassemble_instruction(&addr, &bytes)
        .expect("arm64 insn1");
    assert!(ins1.mnemonic.to_ascii_lowercase().contains("mov"));
    let addr2 = Address::new(AddressKind::VA, 0x1004, 64, None, None).unwrap();
    let ins2 = backend
        .disassemble_instruction(&addr2, &bytes[4..])
        .expect("arm64 insn2");
    assert!(ins2.mnemonic.to_ascii_lowercase().contains("ret"));
}

#[test]
fn iced_rejects_arm64() {
    let arch = Architecture::ARM64;
    let res = for_arch_with(arch, Endianness::Little, Some(BackendKind::Iced));
    assert!(res.is_err(), "iced should not support ARM64");
}
