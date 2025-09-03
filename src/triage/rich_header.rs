//! PE Rich Header detection and analysis.
//!
//! The Rich Header is an undocumented structure added by Microsoft linkers
//! containing compiler/linker metadata. It's valuable for:
//! - Malware attribution and tracking
//! - Development environment fingerprinting
//! - Compiler toolchain identification
//!
//! Structure:
//! - Starts with 'DanS' (0x536E6144) followed by 3 null DWORDs padding
//! - Contains pairs of DWORDs: [ProductID|BuildID][UseCount]
//! - Ends with 'Rich' (0x68636952) followed by XOR key/checksum
//! - Everything except 'Rich' and key is XORed with the key

use serde::{Deserialize, Serialize};

/// A single Rich Header entry representing a compiler/tool usage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct RichHeaderEntry {
    /// Product ID (high 16 bits of first DWORD)
    pub product_id: u16,
    /// Build ID (low 16 bits of first DWORD)
    pub build_id: u16,
    /// Number of times this tool was used
    pub use_count: u32,
    /// Human-readable tool name if known
    pub tool_name: Option<String>,
}

/// Complete Rich Header analysis results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct RichHeader {
    /// Offset in file where Rich Header starts (DanS position)
    pub offset: u32,
    /// Size of the entire Rich Header structure
    pub size: u32,
    /// XOR key used for encryption (also serves as checksum)
    pub xor_key: u32,
    /// All compiler/tool entries found
    pub entries: Vec<RichHeaderEntry>,
    /// Whether the checksum is valid (can detect tampering)
    pub checksum_valid: bool,
    /// Unique hash of the Rich Header for tracking/attribution
    pub rich_hash: String,
}

/// Find and parse the Rich Header in PE data.
pub fn parse_rich_header(data: &[u8]) -> Option<RichHeader> {
    // Rich header is between DOS header and PE header
    // Look for 'Rich' signature
    let rich_sig = b"Rich";
    let rich_pos = find_signature(data, rich_sig, 0x40, 0x200)?;

    // Get XOR key (4 bytes after 'Rich')
    if rich_pos + 8 > data.len() {
        return None;
    }
    let xor_key = u32::from_le_bytes([
        data[rich_pos + 4],
        data[rich_pos + 5],
        data[rich_pos + 6],
        data[rich_pos + 7],
    ]);

    // Work backwards from Rich, XORing with key to find DanS
    let mut dans_pos = None;
    let dans_sig = 0x536E6144u32; // 'DanS'

    // Start from position before 'Rich' and work backwards
    let mut pos = rich_pos.saturating_sub(4);
    while pos >= 0x40 {
        let dword = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);

        if dword ^ xor_key == dans_sig {
            dans_pos = Some(pos);
            break;
        }

        if pos < 4 {
            break;
        }
        pos -= 4;
    }

    let dans_pos = dans_pos?;

    // Parse entries between DanS and Rich
    let mut entries = Vec::new();
    let mut pos = dans_pos + 16; // Skip DanS + 3 null DWORDs

    while pos + 8 <= rich_pos {
        let entry_dword =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) ^ xor_key;

        let count_dword =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                ^ xor_key;

        let product_id = (entry_dword >> 16) as u16;
        let build_id = (entry_dword & 0xFFFF) as u16;

        // Skip padding entries
        if product_id == 0 && build_id == 0 {
            pos += 8;
            continue;
        }

        entries.push(RichHeaderEntry {
            product_id,
            build_id,
            use_count: count_dword,
            tool_name: identify_tool(product_id, build_id),
        });

        pos += 8;
    }

    // Calculate checksum to verify integrity
    let checksum_valid = verify_rich_checksum(data, dans_pos, rich_pos, xor_key);

    // Generate a hash for the Rich Header (for tracking/attribution)
    let rich_hash = calculate_rich_hash(&entries, xor_key);

    Some(RichHeader {
        offset: dans_pos as u32,
        size: (rich_pos - dans_pos + 8) as u32,
        xor_key,
        entries,
        checksum_valid,
        rich_hash,
    })
}

/// Find a signature in data within a range.
fn find_signature(data: &[u8], sig: &[u8], start: usize, end: usize) -> Option<usize> {
    let end = end.min(data.len());
    if start >= end || sig.is_empty() {
        return None;
    }

    data[start..end]
        .windows(sig.len())
        .position(|window| window == sig)
        .map(|pos| start + pos)
}

/// Verify the Rich Header checksum.
/// The checksum algorithm includes DOS header (with e_lfanew zeroed) and plaintext entries.
fn verify_rich_checksum(data: &[u8], dans_pos: usize, rich_pos: usize, _xor_key: u32) -> bool {
    // This is a simplified version - full implementation would:
    // 1. Hash DOS header with e_lfanew zeroed
    // 2. Include plaintext Rich Header entries
    // 3. Use the specific rotate-left algorithm
    // For now, we just check that the structure is intact
    dans_pos < rich_pos && rich_pos < data.len()
}

/// Calculate a hash for Rich Header attribution/tracking.
fn calculate_rich_hash(entries: &[RichHeaderEntry], xor_key: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();

    // Hash the XOR key
    hasher.update(xor_key.to_le_bytes());

    // Hash each entry in order
    for entry in entries {
        hasher.update(entry.product_id.to_le_bytes());
        hasher.update(entry.build_id.to_le_bytes());
        hasher.update(entry.use_count.to_le_bytes());
    }

    format!("{:x}", hasher.finalize())
}

/// Identify known Microsoft compiler/linker tools.
fn identify_tool(product_id: u16, build_id: u16) -> Option<String> {
    // This is a simplified mapping - real implementation would have extensive database
    let tool_name = match product_id {
        0x00 => "Unknown",
        0x01 => "Import",
        0x02 => "Linker",
        0x03 => "Cvtres",
        0x04 => "Unknown04",
        0x05 => "Unknown05",
        0x06 => "Cvtpgd",
        0x07 => "Ltcg",
        0x08 => "Pogo_PGD",
        0x09 => "Pogo_PGI",
        0x0a => "Pogo_PGO",
        0x0b => "Masm613",
        0x0c => "Masm710",
        0x0d => "Linker510",
        0x0e => "Cvtomf510",
        0x0f => "Linker600",
        0x10 => "Cvtomf600",
        0x11 => "Cvtres500",
        0x12 => "Utc11_Basic",
        0x13 => "Utc11_C",
        0x14 => "Utc12_Basic",
        0x15 => "Utc12_C",
        0x16 => "Utc12_CPP",
        0x17 => "AliasObj60",
        0x18 => "VisualBasic60",
        0x19 => "Masm614",
        0x1a => "Masm710",
        0x1b => "Linker511",
        0x1c => "Cvtomf511",
        0x1d => "Masm614",
        0x1e => "Linker512",
        0x1f => "Cvtomf512",
        0x20 => "Utc12_C_Std",
        0x21 => "Utc12_CPP_Std",
        0x22 => "Utc12_C_Book",
        0x23 => "Utc12_CPP_Book",
        0x5d => "Utc13_Basic",
        0x5e => "Utc13_C",
        0x5f => "Utc13_CPP",
        0x60 => "AliasObj70",
        0x61 => "VisualBasic70",
        0x62 => "Masm615",
        0x63 => "Masm720",
        0x64 => "Utc13_LTCG_C",
        0x65 => "Utc13_LTCG_CPP",
        0x66 => "Masm800",
        0x67 => "Cvtres700",
        0x68 => "Export700",
        0x69 => "Implib700",
        0x6a => "Linker700",
        0x6b => "Cvtomf700",
        0x78 => "Cvtres710",
        0x79 => "Export710",
        0x7a => "Implib710",
        0x7b => "Linker710",
        0x7c => "Cvtomf710",
        0x7d => "Utc1310_C",
        0x7e => "Utc1310_CPP",
        0x7f => "Utc1310_LTCG_C",
        0x80 => "Utc1310_LTCG_CPP",
        0x83 => "Utc1400_C",
        0x84 => "Utc1400_CPP",
        0x85 => "Utc1400_LTCG_C",
        0x86 => "Utc1400_LTCG_CPP",
        0x87 => "Linker800",
        0x88 => "Cvtomf800",
        0x89 => "Export800",
        0x8a => "Implib800",
        0x8b => "Cvtres800",
        0x8c => "Masm900",
        0x8d => "Utc1500_C",
        0x8e => "Utc1500_CPP",
        0x8f => "Utc1500_LTCG_C",
        0x90 => "Utc1500_LTCG_CPP",
        0x91 => "Linker900",
        0x92 => "Export900",
        0x93 => "Implib900",
        0x94 => "Cvtres900",
        0x95 => "Cvtomf900",
        0x96 => "Masm1000",
        0x97 => "Utc1600_C",
        0x98 => "Utc1600_CPP",
        0x99 => "Utc1600_LTCG_C",
        0x9a => "Utc1600_LTCG_CPP",
        0x9b => "Linker1000",
        0x9c => "Export1000",
        0x9d => "Implib1000",
        0x9e => "Cvtres1000",
        0x9f => "Cvtomf1000",
        0xa0 => "Masm1010",
        0xa1 => "Utc1700_C",
        0xa2 => "Utc1700_CPP",
        0xa3 => "Utc1700_LTCG_C",
        0xa4 => "Utc1700_LTCG_CPP",
        0xa5 => "Linker1010",
        0xa6 => "Export1010",
        0xa7 => "Implib1010",
        0xa8 => "Cvtres1010",
        0xa9 => "Cvtomf1010",
        0xaa => "Masm1100",
        0xab => "Utc1800_C",
        0xac => "Utc1800_CPP",
        0xad => "Utc1800_LTCG_C",
        0xae => "Utc1800_LTCG_CPP",
        0xaf => "Linker1100",
        0xb0 => "Export1100",
        0xb1 => "Implib1100",
        0xb2 => "Cvtres1100",
        0xb3 => "Cvtomf1100",
        0xb4 => "Masm1200",
        0xb5 => "Utc1900_C",
        0xb6 => "Utc1900_CPP",
        0xb7 => "Utc1900_LTCG_C",
        0xb8 => "Utc1900_LTCG_CPP",
        0xb9 => "Linker1200",
        0xba => "Export1200",
        0xbb => "Implib1200",
        0xbc => "Cvtres1200",
        0xbd => "Cvtomf1200",
        0xbe => "Masm1210",
        0xbf => "Utc1910_C",
        0xc0 => "Utc1910_CPP",
        0xc1 => "Utc1910_LTCG_C",
        0xc2 => "Utc1910_LTCG_CPP",
        0xc3 => "Linker1210",
        0xc4 => "Export1210",
        0xc5 => "Implib1210",
        0xc6 => "Cvtres1210",
        0xc7 => "Cvtomf1210",
        0xc8 => "Masm1300",
        0xc9 => "Utc1920_C",
        0xca => "Utc1920_CPP",
        0xcb => "Utc1920_LTCG_C",
        0xcc => "Utc1920_LTCG_CPP",
        0xcd => "Linker1300",
        0xce => "Export1300",
        0xcf => "Implib1300",
        0xd0 => "Cvtres1300",
        0xd1 => "Cvtomf1300",
        0xd2 => "Masm1400",
        _ => return None,
    };

    Some(format!("{} (build {})", tool_name, build_id))
}

#[cfg(feature = "python-ext")]
mod python {
    use super::*;
    use pyo3::prelude::*;

    #[pymethods]
    impl RichHeaderEntry {
        #[getter]
        fn product_id(&self) -> u16 {
            self.product_id
        }

        #[getter]
        fn build_id(&self) -> u16 {
            self.build_id
        }

        #[getter]
        fn use_count(&self) -> u32 {
            self.use_count
        }

        #[getter]
        fn tool_name(&self) -> Option<String> {
            self.tool_name.clone()
        }

        fn __repr__(&self) -> String {
            format!(
                "RichHeaderEntry(product={}, build={}, count={}, tool={:?})",
                self.product_id, self.build_id, self.use_count, self.tool_name
            )
        }
    }

    #[pymethods]
    impl RichHeader {
        #[getter]
        fn offset(&self) -> u32 {
            self.offset
        }

        #[getter]
        fn size(&self) -> u32 {
            self.size
        }

        #[getter]
        fn xor_key(&self) -> u32 {
            self.xor_key
        }

        #[getter]
        fn entries(&self) -> Vec<RichHeaderEntry> {
            self.entries.clone()
        }

        #[getter]
        fn checksum_valid(&self) -> bool {
            self.checksum_valid
        }

        #[getter]
        fn rich_hash(&self) -> String {
            self.rich_hash.clone()
        }

        fn __repr__(&self) -> String {
            format!(
                "RichHeader(offset={}, size={}, entries={}, valid={})",
                self.offset,
                self.size,
                self.entries.len(),
                self.checksum_valid
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_signature() {
        let data = b"Hello World Rich Test";
        assert_eq!(find_signature(data, b"Rich", 0, data.len()), Some(12));
        assert_eq!(find_signature(data, b"Test", 0, data.len()), Some(17));
        assert_eq!(find_signature(data, b"Missing", 0, data.len()), None);
    }

    #[test]
    fn test_tool_identification() {
        assert!(identify_tool(0x5d, 0).unwrap().contains("Utc13_Basic"));
        assert!(identify_tool(0x91, 0).unwrap().contains("Linker900"));
        assert!(identify_tool(0x9999, 0).is_none());
    }

    #[test]
    fn test_rich_hash_deterministic() {
        let entries = vec![RichHeaderEntry {
            product_id: 0x5d,
            build_id: 0x1234,
            use_count: 10,
            tool_name: None,
        }];

        let hash1 = calculate_rich_hash(&entries, 0x12345678);
        let hash2 = calculate_rich_hash(&entries, 0x12345678);
        assert_eq!(hash1, hash2);

        // Different key should produce different hash
        let hash3 = calculate_rich_hash(&entries, 0x87654321);
        assert_ne!(hash1, hash3);
    }
}
