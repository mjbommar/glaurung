#![cfg(feature = "python-ext")]
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::core::address::Address;
use crate::core::disassembler::{Architecture, Disassembler, DisassemblerConfig};

#[pyclass(unsendable)]
pub struct PyDisassembler {
    backend: super::registry::Backend,
}

#[pymethods]
impl PyDisassembler {
    #[new]
    #[pyo3(signature = (config))]
    pub fn new(config: DisassemblerConfig) -> PyResult<Self> {
        let arch = config.architecture;
        let end = config.endianness;
        let prefer = config
            .options
            .get("engine")
            .map(|s| s.to_ascii_lowercase())
            .and_then(|s| match s.as_str() {
                "iced" => Some(super::registry::BackendKind::Iced),
                "capstone" => Some(super::registry::BackendKind::Capstone),
                _ => None,
            });
        let backend = super::registry::for_arch_with(arch, end, prefer)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{:}", e)))?;
        Ok(Self { backend })
    }

    #[pyo3(name = "disassemble_bytes")]
    #[pyo3(signature = (address, data, max_instructions=128, max_time_ms=10))]
    pub fn disassemble_bytes(
        &self,
        address: Address,
        data: Vec<u8>,
        max_instructions: usize,
        max_time_ms: u64,
    ) -> PyResult<Vec<crate::core::instruction::Instruction>> {
        let mut out = Vec::new();
        let mut off = 0usize;
        let t0 = std::time::Instant::now();
        for _ in 0..max_instructions {
            if off >= data.len() {
                break;
            }
            if t0.elapsed().as_millis() as u64 > max_time_ms {
                break;
            }
            let bits = self.backend.architecture().address_bits();
            let cur = crate::core::address::Address::new(
                crate::core::address::AddressKind::VA,
                address.value.saturating_add(off as u64),
                bits,
                None,
                None,
            )
            .map_err(|e| PyValueError::new_err(e))?;
            let slice = &data[off..];
            match self.backend.disassemble_instruction(&cur, slice) {
                Ok(ins) => {
                    off += ins.length as usize;
                    out.push(ins);
                }
                Err(_) => break,
            }
        }
        Ok(out)
    }

    #[pyo3(name = "engine")]
    pub fn engine(&self) -> String {
        self.backend.name().to_string()
    }

    #[pyo3(name = "arch")]
    pub fn arch(&self) -> Architecture {
        self.backend.architecture()
    }
}

#[pyfunction]
#[pyo3(name = "disassembler_for_path")]
pub fn disassembler_for_path_py(path: String) -> PyResult<PyDisassembler> {
    use crate::triage::io::IOLimits;
    // Use default limits similar to analyze_path_py convenience
    let limits = IOLimits {
        max_read_bytes: 10_485_760,
        max_file_size: 104_857_600,
    };
    let art = crate::triage::api::analyze_path(&path, &limits)
        .map_err(|e| PyValueError::new_err(format!("triage analyze_path error: {}", e)))?;
    // Prefer header-validated verdicts; fallback to heuristics if absent
    let arch_guess = art
        .verdicts
        .first()
        .map(|v| v.arch)
        .or_else(|| {
            art.heuristic_arch
                .as_ref()
                .and_then(|v| v.first().map(|(a, _)| *a))
        })
        .unwrap_or(crate::core::binary::Arch::Unknown);
    let end_guess = art
        .heuristic_endianness
        .map(|(e, _)| e)
        .unwrap_or(crate::core::binary::Endianness::Little);
    let darch: Architecture = arch_guess.into();
    let backend = super::registry::for_arch_with(darch, end_guess, None)
        .map_err(|e| PyValueError::new_err(format!("{:}", e)))?;
    Ok(PyDisassembler { backend })
}

#[pyfunction]
#[pyo3(name = "disassemble_window")]
#[pyo3(signature = (path, window_bytes=512usize, max_instructions=32usize, max_time_ms=10u64))]
pub fn disassemble_window_py(
    path: String,
    window_bytes: usize,
    max_instructions: usize,
    max_time_ms: u64,
) -> PyResult<Vec<crate::core::instruction::Instruction>> {
    use std::io::Read;
    let d = disassembler_for_path_py(path.clone())?;
    let mut f = std::fs::File::open(&path)
        .map_err(|e| PyValueError::new_err(format!("open error: {}", e)))?;
    let mut buf = vec![0u8; window_bytes];
    let n = f
        .read(&mut buf)
        .map_err(|e| PyValueError::new_err(format!("read error: {}", e)))?;
    buf.truncate(n);
    let bits = d.backend.architecture().address_bits();
    let addr = crate::core::address::Address::new(
        crate::core::address::AddressKind::VA,
        0,
        bits,
        None,
        None,
    )
    .map_err(PyValueError::new_err)?;
    // Reuse the method logic
    let mut out = Vec::new();
    let mut off = 0usize;
    let t0 = std::time::Instant::now();
    for _ in 0..max_instructions {
        if off >= buf.len() {
            break;
        }
        if t0.elapsed().as_millis() as u64 > max_time_ms {
            break;
        }
        let cur = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            addr.value.saturating_add(off as u64),
            bits,
            None,
            None,
        )
        .map_err(PyValueError::new_err)?;
        match d.backend.disassemble_instruction(&cur, &buf[off..]) {
            Ok(ins) => {
                if ins.length == 0 {
                    break;
                }
                off += ins.length as usize;
                out.push(ins);
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

#[pyfunction]
#[pyo3(name = "disassemble_window_at")]
#[pyo3(signature = (path, start_va, window_bytes=512usize, max_instructions=32usize, max_time_ms=10u64))]
pub fn disassemble_window_at_py(
    path: String,
    start_va: u64,
    window_bytes: usize,
    max_instructions: usize,
    max_time_ms: u64,
) -> PyResult<Vec<crate::core::instruction::Instruction>> {
    let d = disassembler_for_path_py(path.clone())?;
    // Read full file and map VA->file offset via shared helper
    let data =
        std::fs::read(&path).map_err(|e| PyValueError::new_err(format!("read error: {}", e)))?;
    let foff = match crate::analysis::entry::va_to_file_offset(&data, start_va) {
        Some(v) => v,
        None => {
            return Err(PyValueError::new_err(format!(
                "no mapping for VA 0x{:x}",
                start_va
            )))
        }
    };
    let end = std::cmp::min(data.len(), foff.saturating_add(window_bytes));
    let buf = data[foff..end].to_vec();
    let bits = d.backend.architecture().address_bits();
    let addr = crate::core::address::Address::new(
        crate::core::address::AddressKind::VA,
        start_va,
        bits,
        None,
        None,
    )
    .map_err(PyValueError::new_err)?;
    // Reuse the method logic
    let mut out = Vec::new();
    let mut off = 0usize;
    let t0 = std::time::Instant::now();
    for _ in 0..max_instructions {
        if off >= buf.len() {
            break;
        }
        if t0.elapsed().as_millis() as u64 > max_time_ms {
            break;
        }
        let cur = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            addr.value.saturating_add(off as u64),
            bits,
            None,
            None,
        )
        .map_err(PyValueError::new_err)?;
        match d.backend.disassemble_instruction(&cur, &buf[off..]) {
            Ok(ins) => {
                if ins.length == 0 {
                    break;
                }
                off += ins.length as usize;
                out.push(ins);
            }
            Err(_) => break,
        }
    }
    Ok(out)
}
