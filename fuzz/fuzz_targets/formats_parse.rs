//! Container parsing past the header check.
//!
//! Broader than `headers_validate`, which stops at validation: overlay
//! detection walks to the end of the last section, so an impossible size
//! field or a section table pointing past EOF reaches arithmetic that would
//! index on it. Glaurung is pointed at hostile binaries by design, and this
//! is among the first code they meet.
#![no_main]
use glaurung::core::binary::Format;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = glaurung::triage::parsers::parse(data);
    // Every format, not just the one a sniffer would pick: claiming to be a PE
    // and being an ELF is exactly what an adversarial sample does.
    for format in [Format::ELF, Format::PE, Format::MachO] {
        let _ = glaurung::triage::overlay::detect_overlay(data, format);
    }
});
