# Archive Format Parser Documentation

## Overview

Archive formats are container formats that bundle multiple files and directories into a single file. GLAURUNG's archive parser handles various formats including ZIP, TAR, AR, CPIO, and others, providing safe extraction and analysis capabilities.

## Format Specifications

### Primary References
- **ZIP Format**: `/reference/specifications/archive/ZIP_APPNOTE.TXT`
- **TAR Format**: `/reference/specifications/archive/tar_format.html`
- **PAX Format**: `/reference/specifications/archive/pax_format.html`
- **libarchive Headers**: `/reference/specifications/archive/archive.h`
- **Magic Signatures**: `/reference/specifications/archive/magic_archive_signatures.txt`

## Supported Archive Formats

### ZIP Archives
```
┌─────────────────┐
│ Local Headers   │  File entries with metadata
├─────────────────┤
│ File Data       │  Compressed or stored files
├─────────────────┤
│ Central Dir     │  Archive catalog
├─────────────────┤
│ End Record      │  Archive terminator
└─────────────────┘
```

### TAR Archives
```
┌─────────────────┐
│ File Header 1   │  512-byte header
├─────────────────┤
│ File Data 1     │  Padded to 512 bytes
├─────────────────┤
│ File Header 2   │  Next file
├─────────────────┤
│ File Data 2     │  ...
└─────────────────┘
```

### AR Archives
```
┌─────────────────┐
│ Global Header   │  "!<arch>\n"
├─────────────────┤
│ File Header 1   │  60-byte header
├─────────────────┤
│ File Data 1     │  2-byte aligned
├─────────────────┤
│ File Header 2   │  ...
└─────────────────┘
```

## Parser Implementation

### Phase 1: Format Detection
- [ ] Magic signature identification
- [ ] Format-specific header validation
- [ ] Compression method detection
- [ ] Archive integrity check

### Phase 2: Metadata Extraction
- [ ] File listing enumeration
- [ ] Directory structure reconstruction
- [ ] Timestamps and permissions
- [ ] Compression ratios

### Phase 3: Content Analysis
- [ ] Selective extraction
- [ ] Nested archive detection
- [ ] Malware scanning hooks
- [ ] Entropy analysis

### Phase 4: Security Validation
- [ ] Path traversal prevention
- [ ] Zip bomb detection
- [ ] Resource limit enforcement
- [ ] Symlink validation

## Data Model

```rust
pub struct Archive {
    pub format: ArchiveFormat,
    pub entries: Vec<ArchiveEntry>,
    pub total_size: u64,
    pub compressed_size: u64,
    pub metadata: ArchiveMetadata,
}

pub struct ArchiveEntry {
    pub path: PathBuf,
    pub size: u64,
    pub compressed_size: u64,
    pub timestamp: DateTime<Utc>,
    pub permissions: u32,
    pub is_directory: bool,
    pub compression: CompressionMethod,
}
```

## Security Considerations

### Archive Bombs
- Zip bombs (high compression ratio)
- Quines (self-extracting recursion)
- Excessive file counts
- Deep nesting

### Path Traversal
- "../" sequences
- Absolute paths
- Symlink attacks
- Case sensitivity issues

## Testing Coverage

### Test Samples
- Standard archives: Various formats
- Nested archives: Archives within archives
- Malformed samples: Corrupted headers
- Edge cases: Empty, single file, maximum size

## Future Enhancements

- [ ] RAR format support
- [ ] 7-Zip format support
- [ ] ISO/DMG image support
- [ ] Self-extracting archive detection
- [ ] Partial extraction optimization
- [ ] Streaming decompression

## References

- [PKWare ZIP Specification](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT)
- [GNU tar Manual](https://www.gnu.org/software/tar/manual/)
- [libarchive Documentation](https://www.libarchive.org/)