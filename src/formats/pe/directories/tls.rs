//! TLS directory parsing.
//!
//! Walks `IMAGE_TLS_DIRECTORY` (32- or 64-bit) and the callback VA
//! list it points at. The callback array is a real pre-DriverEntry /
//! pre-DllMain execution surface; several Windows-kernel CVE classes
//! (driver init-time UAF, TLS-callback hidden code) require the
//! callback VA list to reason about attacker reachability.
//!
//! Closes the last sub-item of #199 (PE format hardening); pairs
//! with the existing import/export/resource/delay-import walkers.

use crate::formats::pe::sections::SectionTable;
use crate::formats::pe::types::*;
use crate::formats::pe::utils::ReadExt;

/// Hard cap on the callback array walk to bound parse cost on
/// malformed / hostile PEs.
const MAX_CALLBACKS: usize = 1024;

/// Parsed TLS directory + walked callback list.
#[derive(Debug, Clone, Default)]
pub struct TlsDirectory {
    /// `IMAGE_TLS_DIRECTORY::StartAddressOfRawData` (VA).
    pub raw_data_start_va: u64,
    /// `IMAGE_TLS_DIRECTORY::EndAddressOfRawData` (VA).
    pub raw_data_end_va: u64,
    /// `IMAGE_TLS_DIRECTORY::AddressOfIndex` (VA where the loader
    /// writes the per-image TLS slot index).
    pub address_of_index: u64,
    /// `IMAGE_TLS_DIRECTORY::AddressOfCallBacks` (VA of the
    /// null-terminated callback function-pointer array).
    pub address_of_callbacks: u64,
    /// `IMAGE_TLS_DIRECTORY::SizeOfZeroFill`.
    pub size_of_zero_fill: u32,
    /// `IMAGE_TLS_DIRECTORY::Characteristics`.
    pub characteristics: u32,
    /// Callback VAs (PE-format absolute addresses).
    pub callbacks: Vec<u64>,
    /// Callback RVAs (VA minus ImageBase). Same length as
    /// `callbacks` when every entry has `VA > ImageBase`; entries
    /// below ImageBase are skipped from this list but kept in
    /// `callbacks`.
    pub callback_rvas: Vec<u32>,
    /// True if the walk hit `MAX_CALLBACKS` before finding a null
    /// terminator. The callback list is then a prefix of the real
    /// PE state.
    pub truncated: bool,
    /// Free-form reasons the walk stopped (truncated header,
    /// unmapped RVA, etc.). Empty on a clean PE.
    pub stop_reasons: Vec<&'static str>,
}

impl TlsDirectory {
    /// Empty directory (no TLS data directory entry, or `parse_tls`
    /// disabled).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of callbacks found.
    pub fn callback_count(&self) -> usize {
        self.callbacks.len()
    }

    /// `true` if at least one callback VA was found.
    pub fn has_callbacks(&self) -> bool {
        !self.callbacks.is_empty()
    }

    /// `true` if the TLS data directory was populated (header
    /// parsed at all). Distinguishes "PE has no TLS" from "PE has
    /// TLS but no callback array".
    pub fn has_tls_header(&self) -> bool {
        self.raw_data_start_va != 0
            || self.raw_data_end_va != 0
            || self.address_of_index != 0
            || self.address_of_callbacks != 0
            || self.size_of_zero_fill != 0
            || self.characteristics != 0
    }
}

/// Parse the PE TLS directory and walk its callback array.
///
/// Returns an empty `TlsDirectory` when `parse_tls` is disabled in
/// `options`, or when the TLS data directory entry is missing. Any
/// soft errors (truncated header, unmapped RVA, hit `MAX_CALLBACKS`)
/// land in `stop_reasons` rather than aborting.
pub fn parse_tls(
    data: &[u8],
    sections: &SectionTable,
    tls_dir: &DataDirectory,
    image_base: u64,
    is_64bit: bool,
    options: &ParseOptions,
) -> Result<TlsDirectory> {
    let mut td = TlsDirectory::empty();

    if !options.parse_tls || tls_dir.virtual_address == 0 || tls_dir.size == 0 {
        return Ok(td);
    }

    let tls_off = match sections.rva_to_offset(tls_dir.virtual_address) {
        Some(o) => o,
        None => {
            td.stop_reasons.push("tls_rva_unmapped");
            return Ok(td);
        }
    };

    // IMAGE_TLS_DIRECTORY32: 6 * u32 + 2 * u32 = 24 bytes total
    //   u32 StartAddressOfRawData
    //   u32 EndAddressOfRawData
    //   u32 AddressOfIndex
    //   u32 AddressOfCallBacks
    //   u32 SizeOfZeroFill
    //   u32 Characteristics
    //
    // IMAGE_TLS_DIRECTORY64: 4 * u64 + 2 * u32 = 40 bytes total
    //   u64 StartAddressOfRawData
    //   u64 EndAddressOfRawData
    //   u64 AddressOfIndex
    //   u64 AddressOfCallBacks
    //   u32 SizeOfZeroFill
    //   u32 Characteristics
    let header_size = if is_64bit { 40 } else { 24 };
    if tls_off + header_size > data.len() {
        td.stop_reasons.push("tls_header_truncated");
        return Ok(td);
    }

    if is_64bit {
        td.raw_data_start_va = data
            .read_u64_le_at(tls_off)
            .ok_or(PeError::InvalidOffset { offset: tls_off })?;
        td.raw_data_end_va = data
            .read_u64_le_at(tls_off + 8)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 8,
            })?;
        td.address_of_index = data
            .read_u64_le_at(tls_off + 16)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 16,
            })?;
        td.address_of_callbacks =
            data.read_u64_le_at(tls_off + 24)
                .ok_or(PeError::InvalidOffset {
                    offset: tls_off + 24,
                })?;
        td.size_of_zero_fill = data
            .read_u32_le_at(tls_off + 32)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 32,
            })?;
        td.characteristics = data
            .read_u32_le_at(tls_off + 36)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 36,
            })?;
    } else {
        td.raw_data_start_va =
            data.read_u32_le_at(tls_off)
                .ok_or(PeError::InvalidOffset { offset: tls_off })? as u64;
        td.raw_data_end_va = data
            .read_u32_le_at(tls_off + 4)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 4,
            })? as u64;
        td.address_of_index = data
            .read_u32_le_at(tls_off + 8)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 8,
            })? as u64;
        td.address_of_callbacks =
            data.read_u32_le_at(tls_off + 12)
                .ok_or(PeError::InvalidOffset {
                    offset: tls_off + 12,
                })? as u64;
        td.size_of_zero_fill = data
            .read_u32_le_at(tls_off + 16)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 16,
            })?;
        td.characteristics = data
            .read_u32_le_at(tls_off + 20)
            .ok_or(PeError::InvalidOffset {
                offset: tls_off + 20,
            })?;
    }

    if td.address_of_callbacks == 0 {
        td.stop_reasons.push("no_callbacks_va");
        return Ok(td);
    }

    let callbacks_rva = td.address_of_callbacks.saturating_sub(image_base) as u32;
    let mut cb_off = match sections.rva_to_offset(callbacks_rva) {
        Some(o) => o,
        None => {
            td.stop_reasons.push("callbacks_rva_unmapped");
            return Ok(td);
        }
    };

    let step = if is_64bit { 8 } else { 4 };
    let mut i = 0usize;
    while i < MAX_CALLBACKS {
        if cb_off + step > data.len() {
            td.stop_reasons.push("callbacks_truncated");
            break;
        }
        let val = if is_64bit {
            data.read_u64_le_at(cb_off)
                .ok_or(PeError::InvalidOffset { offset: cb_off })?
        } else {
            data.read_u32_le_at(cb_off)
                .ok_or(PeError::InvalidOffset { offset: cb_off })? as u64
        };
        if val == 0 {
            break;
        }
        td.callbacks.push(val);
        if val > image_base {
            td.callback_rvas.push((val - image_base) as u32);
        }
        cb_off += step;
        i += 1;
    }
    if i == MAX_CALLBACKS {
        td.truncated = true;
        td.stop_reasons.push("callbacks_max_reached");
    }

    Ok(td)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tls_directory_round_trip() {
        let td = TlsDirectory::empty();
        assert_eq!(td.callback_count(), 0);
        assert!(!td.has_callbacks());
        assert!(!td.has_tls_header());
        assert!(td.stop_reasons.is_empty());
        assert!(!td.truncated);
    }

    #[test]
    fn parse_tls_returns_empty_when_disabled() {
        let dd = DataDirectory {
            virtual_address: 0x1000,
            size: 24,
        };
        let mut opts = ParseOptions::default();
        opts.parse_tls = false;
        let sections = SectionTable::new(Vec::new());
        let td = parse_tls(&[], &sections, &dd, 0x140000000, true, &opts).unwrap();
        assert!(!td.has_tls_header());
        assert_eq!(td.callback_count(), 0);
    }

    #[test]
    fn parse_tls_returns_empty_on_missing_directory() {
        let dd = DataDirectory {
            virtual_address: 0,
            size: 0,
        };
        let opts = ParseOptions::default();
        let sections = SectionTable::new(Vec::new());
        let td = parse_tls(&[], &sections, &dd, 0, true, &opts).unwrap();
        assert!(!td.has_tls_header());
        assert!(td.stop_reasons.is_empty());
    }
}
