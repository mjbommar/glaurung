# Detailed Implementation Plans for Critical Features

## 1. Overlay Data Handling

### Overview
Implement detection and extraction of overlay data (data appended after the official end of PE/ELF files).

### Reference Files to Study
- **LIEF Implementation**:
  - `reference/LIEF/src/PE/Parser.cpp` (lines 1178-1197) - `parse_overlay()` method
  - `reference/LIEF/src/PE/Binary.cpp` - overlay access methods
  - `reference/LIEF/include/LIEF/PE/Binary.hpp` - overlay data structures
  - `reference/LIEF/src/PE/Builder.cpp` - `build_overlay()` for rebuilding

### Implementation Plan

#### Step 1: Create Data Structures
**File**: `src/triage/overlay.rs`

```rust
use crate::core::binary::Format;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct OverlayAnalysis {
    /// Offset in file where overlay starts
    pub offset: u64,
    
    /// Size of overlay data in bytes
    pub size: u64,
    
    /// Shannon entropy of overlay data
    pub entropy: f32,
    
    /// First 256 bytes for quick analysis
    pub header: Vec<u8>,
    
    /// Detected format of overlay (if recognizable)
    pub detected_format: Option<OverlayFormat>,
    
    /// If overlay contains digital signature
    pub has_signature: bool,
    
    /// If overlay appears to be an archive
    pub is_archive: bool,
    
    /// Hash of overlay data
    pub sha256: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub enum OverlayFormat {
    ZIP,
    CAB,
    SevenZip,
    RAR,
    NSIS,
    InnoSetup,
    Certificate,
    Unknown,
}
```

#### Step 2: Implement PE Overlay Detection
**Algorithm from LIEF**:

```rust
impl PEOverlayDetector {
    pub fn detect_overlay(data: &[u8], pe: &object::pe::PeFile) -> Option<OverlayAnalysis> {
        // Step 1: Find the end of the last section
        // Based on LIEF's approach in Parser.cpp
        let last_section_end = pe.sections()
            .map(|section| {
                let offset = section.pointer_to_raw_data.get() as u64;
                let size = section.size_of_raw_data.get() as u64;
                offset + size
            })
            .max()
            .unwrap_or(0);
        
        // Step 2: Check if there's data after last section
        let file_size = data.len() as u64;
        if last_section_end >= file_size {
            return None;
        }
        
        // Step 3: Extract overlay data
        let overlay_offset = last_section_end;
        let overlay_size = file_size - overlay_offset;
        let overlay_data = &data[overlay_offset as usize..];
        
        // Step 4: Analyze overlay
        Some(OverlayAnalysis {
            offset: overlay_offset,
            size: overlay_size,
            entropy: calculate_entropy(overlay_data),
            header: overlay_data[..256.min(overlay_data.len())].to_vec(),
            detected_format: detect_overlay_format(overlay_data),
            has_signature: check_for_signature(overlay_data),
            is_archive: check_if_archive(overlay_data),
            sha256: calculate_sha256(overlay_data),
        })
    }
}
```

#### Step 3: Implement ELF Overlay Detection
```rust
impl ELFOverlayDetector {
    pub fn detect_overlay(data: &[u8], elf: &object::elf::ElfFile) -> Option<OverlayAnalysis> {
        // Similar to PE but using ELF sections
        // Find max(section_offset + section_size)
    }
}
```

#### Step 4: Format Detection
```rust
fn detect_overlay_format(data: &[u8]) -> Option<OverlayFormat> {
    // Check magic bytes
    match &data[..4.min(data.len())] {
        b"PK\x03\x04" => Some(OverlayFormat::ZIP),
        b"MSCF" => Some(OverlayFormat::CAB),
        b"7z\xBC\xAF" => Some(OverlayFormat::SevenZip),
        b"Rar!" => Some(OverlayFormat::RAR),
        _ => {
            // Check for NSIS/InnoSetup patterns
            if data.windows(4).any(|w| w == b"NSIS") {
                Some(OverlayFormat::NSIS)
            } else if data.windows(8).any(|w| w == b"Inno Setup") {
                Some(OverlayFormat::InnoSetup)
            } else {
                None
            }
        }
    }
}
```

#### Step 5: Integration with Triage
**File**: `src/triage/api.rs`

```rust
// Add to triage_with_config
if let Some(overlay) = detect_overlay(data, &format) {
    artifact.overlay = Some(overlay);
    
    // Add confidence signal if overlay detected
    if overlay.size > 0 {
        artifact.add_signal(ConfidenceSignal {
            name: "overlay_present".to_string(),
            score: 0.3, // Adjust based on context
            notes: Some(format!("{}KB overlay detected", overlay.size / 1024)),
        });
    }
}
```

### Testing Strategy
1. Create test files with known overlays (self-extracting archives)
2. Test with signed PE files (certificates in overlay)
3. Test with installers (NSIS, InnoSetup)
4. Verify no false positives on normal binaries

---

## 2. Rich Header Analysis (PE)

### Overview
Parse and analyze the undocumented Rich Header in PE files containing compiler/linker metadata.

### Reference Files to Study
- **LIEF Implementation**:
  - `reference/LIEF/include/LIEF/PE/RichHeader.hpp` - Data structures and constants
  - `reference/LIEF/include/LIEF/PE/RichEntry.hpp` - Individual entry structure
  - `reference/LIEF/src/PE/Parser.cpp` (search for "parse_rich_header") - Parsing logic
  - `reference/LIEF/src/PE/RichHeader.cpp` - Methods and generation
- **Additional References**:
  - Look for RetDec's comprehensive ProductID mappings in comments

### Implementation Plan

#### Step 1: Define Constants and Structures
**File**: `src/triage/rich_header.rs`

```rust
// Magic constants from LIEF
const RICH_MAGIC: u32 = 0x68636952; // "Rich"
const DANS_MAGIC: u32 = 0x536E6144; // "DanS"

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct RichHeader {
    /// XOR key used to encrypt the header
    pub xor_key: u32,
    
    /// List of compiler/tool entries
    pub entries: Vec<RichEntry>,
    
    /// Raw decrypted data
    pub raw_data: Vec<u8>,
    
    /// Hash of the rich header (for clustering)
    pub hash: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct RichEntry {
    /// Product/Compiler ID (e.g., 0x5F for VS2005)
    pub product_id: u16,
    
    /// Build number/version
    pub build_id: u16,
    
    /// Number of times used
    pub count: u32,
    
    /// Human-readable product name
    pub product_name: String,
}
```

#### Step 2: Implement Parsing Algorithm
**Based on LIEF's parse_rich_header**:

```rust
impl RichHeaderParser {
    pub fn parse(dos_stub: &[u8]) -> Option<RichHeader> {
        // Step 1: Find "Rich" signature
        let rich_pos = dos_stub.windows(4)
            .position(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == RICH_MAGIC)?;
        
        // Step 2: Extract XOR key (follows "Rich")
        let xor_key = u32::from_le_bytes(
            dos_stub[rich_pos + 4..rich_pos + 8].try_into().ok()?
        );
        
        // Step 3: Work backwards to find DanS signature
        let mut entries = Vec::new();
        let mut pos = rich_pos - 4;
        
        while pos >= 16 { // Need at least DanS + padding
            let encrypted = u32::from_le_bytes(
                dos_stub[pos..pos + 4].try_into().ok()?
            );
            let decrypted = encrypted ^ xor_key;
            
            if decrypted == DANS_MAGIC {
                // Found the start!
                break;
            }
            
            // Decrypt entry
            let count_encrypted = u32::from_le_bytes(
                dos_stub[pos - 4..pos].try_into().ok()?
            );
            let count = count_encrypted ^ xor_key;
            
            // Skip padding entries (0, 0)
            if decrypted != 0 || count != 0 {
                let product_id = ((decrypted >> 16) & 0xFFFF) as u16;
                let build_id = (decrypted & 0xFFFF) as u16;
                
                entries.push(RichEntry {
                    product_id,
                    build_id,
                    count,
                    product_name: identify_product(product_id, build_id),
                });
            }
            
            pos -= 8; // Move to next entry
        }
        
        // Reverse entries (we parsed backwards)
        entries.reverse();
        
        Some(RichHeader {
            xor_key,
            entries,
            raw_data: dos_stub[pos..rich_pos + 8].to_vec(),
            hash: calculate_rich_hash(&entries, xor_key),
        })
    }
}
```

#### Step 3: Product Identification
**Based on RetDec/Ghidra mappings**:

```rust
fn identify_product(product_id: u16, build_id: u16) -> String {
    match product_id {
        0x00..=0x01 => "Import0".to_string(),
        0x02..=0x05 => format!("Linker {}.x", product_id + 4),
        0x06 => "Cvtres (resource converter)".to_string(),
        0x07..=0x18 => "UTC compiler".to_string(),
        0x19..=0x3C => format!("MASM {}", masm_version(product_id)),
        0x5D => "Visual C++ 13.00 (VS2003)".to_string(),
        0x5E => "Visual C++ 13.10 (VS2003 SP1)".to_string(),
        0x5F => "Visual C++ 14.00 (VS2005)".to_string(),
        0x6D => "Visual C++ 14.00 (VS2008)".to_string(),
        0x78 => "Visual C++ 14.10 (VS2010)".to_string(),
        0x83 => "Visual C++ 15.00 (VS2012)".to_string(),
        0x91 => "Visual C++ 16.00 (VS2013)".to_string(),
        0x9D => "Visual C++ 19.00 (VS2015)".to_string(),
        0xAA => "Visual C++ 19.10 (VS2017)".to_string(),
        0xDB => "Visual C++ 19.20 (VS2019)".to_string(),
        0x100..=0x10F => format!("Visual C++ 19.30+ (VS2022) build {}", build_id),
        _ => format!("Unknown (0x{:02X})", product_id),
    }
}
```

#### Step 4: Rich Hash Calculation
**For malware clustering**:

```rust
fn calculate_rich_hash(entries: &[RichEntry], xor_key: u32) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    
    // Hash XOR key
    hasher.update(xor_key.to_le_bytes());
    
    // Hash sorted entries (for consistency)
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by_key(|e| (e.product_id, e.build_id));
    
    for entry in sorted_entries {
        hasher.update(entry.product_id.to_le_bytes());
        hasher.update(entry.build_id.to_le_bytes());
        hasher.update(entry.count.to_le_bytes());
    }
    
    format!("{:x}", hasher.finalize())
}
```

#### Step 5: Integration
```rust
// In triage/api.rs
if format == Format::PE {
    if let Some(rich_header) = parse_rich_header(data) {
        artifact.rich_header = Some(rich_header);
        
        // Add build environment signal
        artifact.add_signal(ConfidenceSignal {
            name: "rich_header_present".to_string(),
            score: 0.1,
            notes: Some(format!("{} compiler entries", rich_header.entries.len())),
        });
    }
}
```

### Testing Strategy
1. Test with various Visual Studio compiled binaries
2. Verify XOR decryption
3. Test malware samples with known rich headers
4. Validate product identification

---

## 3. Certificate/Authenticode Validation

### Overview
Implement comprehensive PE authenticode signature validation including certificate chain verification.

### Reference Files to Study
- **LIEF Implementation**:
  - `reference/LIEF/src/PE/Parser.cpp` - `parse_signature()` method
  - `reference/LIEF/src/PE/signature/SignatureParser.cpp` - PKCS#7 parsing
  - `reference/LIEF/src/PE/signature/Signature.cpp` - `check()` validation method
  - `reference/LIEF/include/LIEF/PE/signature/x509.hpp` - Certificate structure
  - `reference/LIEF/include/LIEF/PE/signature/types.hpp` - Enums and types
  - `reference/LIEF/src/PE/signature/attributes/` - Authenticode attributes

### Implementation Plan

#### Step 1: Core Data Structures
**File**: `src/triage/certificate.rs`

```rust
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct CertificateAnalysis {
    /// Is the file signed?
    pub is_signed: bool,
    
    /// Is the signature valid?
    pub is_valid: bool,
    
    /// Verification errors (if any)
    pub verification_errors: Vec<VerificationError>,
    
    /// Primary signer certificate
    pub signer_cert: Option<X509Certificate>,
    
    /// Full certificate chain
    pub cert_chain: Vec<X509Certificate>,
    
    /// Timestamp information
    pub timestamp: Option<TimestampInfo>,
    
    /// Signature anomalies detected
    pub anomalies: Vec<SignatureAnomaly>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub struct X509Certificate {
    /// Certificate version (1, 2, or 3)
    pub version: u32,
    
    /// Serial number (hex string)
    pub serial_number: String,
    
    /// Issuer Distinguished Name
    pub issuer: String,
    
    /// Subject Distinguished Name
    pub subject: String,
    
    /// Certificate validity start
    pub not_before: DateTime<Utc>,
    
    /// Certificate validity end
    pub not_after: DateTime<Utc>,
    
    /// Signature algorithm (e.g., "sha256WithRSAEncryption")
    pub signature_algorithm: String,
    
    /// Public key type (RSA, ECDSA)
    pub key_type: String,
    
    /// Public key size in bits
    pub key_size: u32,
    
    /// SHA-256 thumbprint
    pub thumbprint: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub enum VerificationError {
    InvalidSignature,
    CertificateExpired,
    CertificateNotYetValid,
    UntrustedRoot,
    CertificateRevoked,
    DigestMismatch,
    MissingSignerCertificate,
    InvalidTimestamp,
    WeakHashAlgorithm,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "python-ext", pyo3::pyclass)]
pub enum SignatureAnomaly {
    SelfSigned,
    WeakKeySize(u32),
    SuspiciousSigner(String),
    InvalidChain,
    DuplicateCertificate,
    MismatchedDigestAlgorithm,
    StolenCertificateKnown(String),
}
```

#### Step 2: Certificate Table Parsing
**Based on LIEF's parse_signature()**:

```rust
impl CertificateParser {
    pub fn parse_certificates(data: &[u8], pe: &object::pe::PeFile) -> Option<Vec<WinCertificate>> {
        // Step 1: Get certificate table from data directory
        let cert_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)?;
        
        // Note: cert_dir.virtual_address is actually a file offset for certificates!
        let cert_offset = cert_dir.virtual_address as usize;
        let cert_size = cert_dir.size as usize;
        
        if cert_offset + cert_size > data.len() {
            return None;
        }
        
        // Step 2: Parse WIN_CERTIFICATE structures
        let mut certificates = Vec::new();
        let mut offset = cert_offset;
        
        while offset < cert_offset + cert_size {
            // Parse WIN_CERTIFICATE header
            let length = u32::from_le_bytes(
                data[offset..offset + 4].try_into().ok()?
            ) as usize;
            let revision = u16::from_le_bytes(
                data[offset + 4..offset + 6].try_into().ok()?
            );
            let cert_type = u16::from_le_bytes(
                data[offset + 6..offset + 8].try_into().ok()?
            );
            
            // Extract certificate data (PKCS#7 SignedData)
            let cert_data = &data[offset + 8..offset + length];
            
            certificates.push(WinCertificate {
                revision,
                cert_type,
                data: cert_data.to_vec(),
            });
            
            // Move to next certificate (8-byte aligned)
            offset += (length + 7) & !7;
        }
        
        Some(certificates)
    }
}
```

#### Step 3: PKCS#7 Parsing
**Simplified version using x509-parser crate**:

```rust
use x509_parser::prelude::*;
use der_parser::ber::*;

impl Pkcs7Parser {
    pub fn parse_signed_data(pkcs7_data: &[u8]) -> Result<SignedData> {
        // Parse PKCS#7 ContentInfo
        let (_, content_info) = parse_der(pkcs7_data)?;
        
        // Verify it's SignedData (OID 1.2.840.113549.1.7.2)
        verify_signed_data_oid(&content_info)?;
        
        // Extract SignedData structure
        let signed_data = extract_signed_data(&content_info)?;
        
        // Parse components
        Ok(SignedData {
            version: signed_data.version,
            digest_algorithms: parse_digest_algorithms(&signed_data)?,
            content_info: parse_content_info(&signed_data)?,
            certificates: parse_certificates(&signed_data)?,
            signer_infos: parse_signer_infos(&signed_data)?,
        })
    }
}
```

#### Step 4: Signature Verification
**Based on LIEF's Signature::check()**:

```rust
impl SignatureVerifier {
    pub fn verify_signature(
        pe_data: &[u8],
        signed_data: &SignedData,
    ) -> Result<CertificateAnalysis> {
        let mut errors = Vec::new();
        
        // Step 1: Find signer certificate
        let signer_info = &signed_data.signer_infos[0]; // Authenticode has only one
        let signer_cert = find_signer_certificate(
            &signed_data.certificates,
            &signer_info.issuer,
            &signer_info.serial_number
        )?;
        
        // Step 2: Verify certificate validity
        let now = Utc::now();
        if now < signer_cert.not_before {
            errors.push(VerificationError::CertificateNotYetValid);
        }
        if now > signer_cert.not_after {
            errors.push(VerificationError::CertificateExpired);
        }
        
        // Step 3: Calculate PE hash (excluding certificate table and checksum)
        let pe_hash = calculate_authenticode_hash(pe_data, &signed_data.digest_algorithm)?;
        
        // Step 4: Verify signature
        if signer_info.authenticated_attributes.is_some() {
            // Verify against authenticated attributes
            let auth_attrs_hash = hash_authenticated_attributes(
                &signer_info.authenticated_attributes,
                &signed_data.digest_algorithm
            )?;
            
            if !verify_rsa_signature(
                &auth_attrs_hash,
                &signer_info.encrypted_digest,
                &signer_cert.public_key
            )? {
                errors.push(VerificationError::InvalidSignature);
            }
            
            // Verify PE hash matches message digest attribute
            let message_digest = extract_message_digest(&signer_info.authenticated_attributes)?;
            if pe_hash != message_digest {
                errors.push(VerificationError::DigestMismatch);
            }
        } else {
            // Direct signature verification
            if !verify_rsa_signature(
                &pe_hash,
                &signer_info.encrypted_digest,
                &signer_cert.public_key
            )? {
                errors.push(VerificationError::InvalidSignature);
            }
        }
        
        // Step 5: Check for timestamp (counter-signature)
        let timestamp = extract_timestamp_info(&signer_info)?;
        
        // Step 6: Detect anomalies
        let anomalies = detect_signature_anomalies(&signed_data, &signer_cert)?;
        
        Ok(CertificateAnalysis {
            is_signed: true,
            is_valid: errors.is_empty(),
            verification_errors: errors,
            signer_cert: Some(convert_to_x509_certificate(&signer_cert)),
            cert_chain: extract_cert_chain(&signed_data.certificates),
            timestamp,
            anomalies,
        })
    }
}
```

#### Step 5: Authenticode Hash Calculation
**Critical for verification**:

```rust
fn calculate_authenticode_hash(pe_data: &[u8], algorithm: &DigestAlgorithm) -> Vec<u8> {
    use sha2::{Sha256, Sha1, Digest};
    
    // Step 1: Parse PE headers
    let pe = object::pe::PeFile::parse(pe_data).unwrap();
    
    // Step 2: Create hasher based on algorithm
    let mut hasher: Box<dyn DynDigest> = match algorithm {
        DigestAlgorithm::SHA1 => Box::new(Sha1::new()),
        DigestAlgorithm::SHA256 => Box::new(Sha256::new()),
        _ => panic!("Unsupported algorithm"),
    };
    
    // Step 3: Hash according to Authenticode spec
    // Hash from start to checksum field
    hasher.update(&pe_data[..checksum_offset]);
    
    // Skip checksum (4 bytes)
    
    // Hash from after checksum to certificate table entry
    hasher.update(&pe_data[checksum_offset + 4..cert_table_offset]);
    
    // Skip certificate table entry (8 bytes)
    
    // Hash from after cert table to start of certificate data
    hasher.update(&pe_data[cert_table_offset + 8..cert_data_offset]);
    
    // Stop - don't hash certificate data itself
    
    hasher.finalize().to_vec()
}
```

#### Step 6: Integration
```rust
// In triage/api.rs
if format == Format::PE {
    if let Some(cert_analysis) = analyze_certificates(data) {
        artifact.certificate = Some(cert_analysis);
        
        // Add signature signals
        if cert_analysis.is_signed {
            artifact.add_signal(ConfidenceSignal {
                name: "digitally_signed".to_string(),
                score: if cert_analysis.is_valid { -0.3 } else { 0.2 },
                notes: Some(format!(
                    "Signed by: {}",
                    cert_analysis.signer_cert.as_ref()
                        .map(|c| &c.subject)
                        .unwrap_or(&"Unknown".to_string())
                )),
            });
        }
        
        // Flag suspicious signers
        for anomaly in &cert_analysis.anomalies {
            if let SignatureAnomaly::StolenCertificateKnown(cert) = anomaly {
                artifact.add_signal(ConfidenceSignal {
                    name: "stolen_certificate".to_string(),
                    score: 0.9,
                    notes: Some(cert.clone()),
                });
            }
        }
    }
}
```

### Testing Strategy
1. Test with legitimately signed Windows binaries
2. Test with self-signed certificates
3. Test with expired certificates
4. Test with known malware using stolen certificates
5. Verify timestamp validation

---

## Integration with Core Triage

### Update TriagedArtifact
**File**: `src/core/triage.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct TriagedArtifact {
    // Existing fields...
    
    /// Overlay analysis results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<OverlayAnalysis>,
    
    /// Rich header information (PE only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_header: Option<RichHeader>,
    
    /// Certificate/signature analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateAnalysis>,
}
```

### Python Bindings
**File**: `src/lib.rs`

```rust
#[cfg(feature = "python-ext")]
#[pymodule]
fn triage(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add new classes
    m.add_class::<OverlayAnalysis>()?;
    m.add_class::<OverlayFormat>()?;
    m.add_class::<RichHeader>()?;
    m.add_class::<RichEntry>()?;
    m.add_class::<CertificateAnalysis>()?;
    m.add_class::<X509Certificate>()?;
    m.add_class::<VerificationError>()?;
    m.add_class::<SignatureAnomaly>()?;
    Ok(())
}
```

### Python Stub Updates
**File**: `python/glaurung/triage.pyi`

```python
class OverlayAnalysis:
    offset: int
    size: int
    entropy: float
    header: bytes
    detected_format: Optional[OverlayFormat]
    has_signature: bool
    is_archive: bool
    sha256: str

class RichHeader:
    xor_key: int
    entries: List[RichEntry]
    raw_data: bytes
    hash: str

class CertificateAnalysis:
    is_signed: bool
    is_valid: bool
    verification_errors: List[VerificationError]
    signer_cert: Optional[X509Certificate]
    cert_chain: List[X509Certificate]
    timestamp: Optional[TimestampInfo]
    anomalies: List[SignatureAnomaly]

class TriagedArtifact:
    # Existing fields...
    overlay: Optional[OverlayAnalysis]
    rich_header: Optional[RichHeader]
    certificate: Optional[CertificateAnalysis]
```

## Dependencies to Add

```toml
# Cargo.toml
[dependencies]
# For certificate parsing
x509-parser = "0.16"
der-parser = "9.0"
ring = "0.17"  # For crypto operations
chrono = "0.4"  # For date/time handling

# Existing dependencies we'll use
object = { version = "0.36", features = ["all"] }
sha2 = "0.10"
```

## Testing Plan

### Rust Tests
```rust
// tests/test_overlay.rs
#[test]
fn test_pe_overlay_detection() {
    let data = include_bytes!("../samples/signed_with_overlay.exe");
    let overlay = detect_overlay(data, Format::PE).unwrap();
    assert!(overlay.size > 0);
    assert_eq!(overlay.detected_format, Some(OverlayFormat::Certificate));
}

// tests/test_rich_header.rs
#[test]
fn test_rich_header_parsing() {
    let data = include_bytes!("../samples/vs2019_compiled.exe");
    let rich = parse_rich_header(data).unwrap();
    assert!(rich.entries.iter().any(|e| e.product_name.contains("VS2019")));
}

// tests/test_certificate.rs
#[test]
fn test_valid_signature() {
    let data = include_bytes!("../samples/windows_signed.exe");
    let cert = analyze_certificates(data).unwrap();
    assert!(cert.is_signed);
    assert!(cert.is_valid);
}
```

### Python Tests
```python
# python/tests/test_new_features.py
def test_overlay_detection():
    data = Path("samples/installer.exe").read_bytes()
    artifact = glaurung.analyze_bytes(data)
    assert artifact.overlay is not None
    assert artifact.overlay.size > 0

def test_rich_header():
    data = Path("samples/vs_compiled.exe").read_bytes()
    artifact = glaurung.analyze_bytes(data)
    assert artifact.rich_header is not None
    assert len(artifact.rich_header.entries) > 0

def test_certificate():
    data = Path("samples/signed.exe").read_bytes()
    artifact = glaurung.analyze_bytes(data)
    assert artifact.certificate is not None
    assert artifact.certificate.is_signed
```

## Performance Considerations

1. **Overlay**: Only read first 256 bytes for header analysis
2. **Rich Header**: Cache product name lookups
3. **Certificate**: Use lazy parsing, only verify if requested

## Security Considerations

1. **Overlay**: Size limits to prevent memory exhaustion
2. **Rich Header**: Validate offsets before accessing
3. **Certificate**: Time limits on crypto operations

This implementation plan provides a complete roadmap for adding these three critical features, with extensive references to the LIEF implementation for guidance.