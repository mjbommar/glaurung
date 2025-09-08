//! Disassembly engines and registry, exposed to Rust and Python.
//!
//! Always-on adapters:
//! - iced-x86 for x86/x64
//! - capstone for ARM/AArch64, MIPS, PPC, RISC-V (and fallback)

pub mod capstone;
pub mod iced;
pub mod registry;

#[cfg(feature = "python-ext")]
pub mod py_api;
