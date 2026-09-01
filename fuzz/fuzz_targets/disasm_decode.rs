//! The instruction decoders, over arbitrary bytes.
//!
//! Nothing fuzzed the disassembler before this. It is the first consumer of
//! attacker-controlled bytes past triage, it runs per-instruction over
//! whatever the CFG walker decided was code, and a panic in it takes down the
//! whole analysis of a sample -- which for a tool whose input is malware is a
//! denial of service on the analyst.
//!
//! The decode loop mirrors the real one: step by the reported length, stop on
//! a zero length (which would otherwise spin), and bound the instruction count
//! so a long buffer does not merely measure throughput.
#![no_main]
use glaurung::core::address::{Address, AddressKind};
use glaurung::core::binary::Endianness;
use glaurung::core::disassembler::{Architecture, Disassembler};
use libfuzzer_sys::fuzz_target;

const MAX_INSTRUCTIONS: usize = 256;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects the architecture, so one corpus exercises every
    // decoder rather than needing one corpus per backend.
    let (selector, bytes) = data.split_at(1);
    let arch = match selector[0] % 4 {
        0 => Architecture::X86,
        1 => Architecture::X86_64,
        2 => Architecture::ARM64,
        _ => Architecture::ARM,
    };
    let Some(backend) = glaurung::disasm::registry::for_arch(arch, Endianness::Little) else {
        return;
    };
    let bits = arch.address_bits();
    let mut offset = 0usize;
    for _ in 0..MAX_INSTRUCTIONS {
        if offset >= bytes.len() {
            break;
        }
        let Ok(address) = Address::new(AddressKind::VA, offset as u64, bits, None, None) else {
            break;
        };
        match backend.disassemble_instruction(&address, &bytes[offset..]) {
            Ok(instruction) => {
                if instruction.length == 0 {
                    break;
                }
                offset += instruction.length as usize;
            }
            // An undecodable byte is an ordinary answer, not a failure: step
            // one byte and keep going, exactly as linear sweep does.
            Err(_) => offset += 1,
        }
    }
});
