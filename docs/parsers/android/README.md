# Android DEX/APK Parser Documentation

## Overview

Android applications are distributed as APK (Android Package) files, which are ZIP archives containing DEX (Dalvik Executable) files with compiled bytecode for the Android Runtime (ART) or legacy Dalvik VM. GLAURUNG's Android parser handles APK packages, DEX bytecode, and provides deep analysis capabilities for Android malware detection.

## Format Specifications

### APK Structure (ZIP Archive)

```
┌─────────────────┐
│ AndroidManifest │  Binary XML with app metadata
├─────────────────┤
│   classes.dex   │  Primary DEX file with bytecode
├─────────────────┤
│  classes2.dex   │  Additional DEX (multidex)
├─────────────────┤
│      lib/       │  Native libraries per ABI
├─────────────────┤
│   resources/    │  App resources and assets
├─────────────────┤
│  META-INF/      │  Signatures and certificates
└─────────────────┘
```

### DEX File Structure

```
┌─────────────────┐
│   DEX Header    │  Magic "dex\n", version, checksums
├─────────────────┤
│   String IDs    │  String pool references
├─────────────────┤
│    Type IDs     │  Type descriptors
├─────────────────┤
│   Proto IDs     │  Method prototypes
├─────────────────┤
│   Field IDs     │  Field references
├─────────────────┤
│   Method IDs    │  Method references
├─────────────────┤
│   Class Defs    │  Class definitions
├─────────────────┤
│   Call Sites    │  Invoke-dynamic (DEX 038+)
├─────────────────┤
│  Method Handles │  MethodHandle (DEX 039+)
├─────────────────┤
│      Data       │  Bytecode and data
├─────────────────┤
│   Link Data     │  Optional linking data
└─────────────────┘
```

## Parser Implementation

### Phase 1: APK Analysis
- [ ] ZIP structure validation
- [ ] AndroidManifest.xml parsing (AXML format)
- [ ] Certificate extraction and validation
- [ ] Resource table parsing
- [ ] Native library enumeration

### Phase 2: DEX Header Parsing
- [ ] Magic number verification ("dex\n035", "dex\n037", etc.)
- [ ] Checksum validation (adler32, SHA-1)
- [ ] Version detection (035, 037, 038, 039, 040)
- [ ] Section offsets and sizes

### Phase 3: DEX Data Structures
- [ ] String pool extraction
- [ ] Type descriptor parsing
- [ ] Method prototype resolution
- [ ] Field and method indexing
- [ ] Class hierarchy reconstruction

### Phase 4: Bytecode Analysis
- [ ] Dalvik bytecode disassembly
- [ ] Method body parsing
- [ ] Register allocation analysis
- [ ] Exception handler mapping
- [ ] Debug information extraction

### Phase 5: Advanced Features
- [ ] Multidex support
- [ ] OAT file parsing (ART compiled)
- [ ] ODEX file support (optimized DEX)
- [ ] R8/ProGuard deobfuscation
- [ ] Native code correlation

## Data Model

```rust
pub struct ApkFile {
    pub manifest: AndroidManifest,
    pub dex_files: Vec<DexFile>,
    pub resources: ResourceTable,
    pub native_libs: HashMap<String, Vec<NativeLib>>,
    pub certificates: Vec<Certificate>,
    pub assets: Vec<Asset>,
}

pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub types: Vec<TypeDescriptor>,
    pub prototypes: Vec<ProtoId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassDef>,
}

pub struct ClassDef {
    pub class_type: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub annotations: Vec<Annotation>,
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

pub struct EncodedMethod {
    pub method_id: u32,
    pub access_flags: u32,
    pub code: Option<CodeItem>,
}

pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info: Option<DebugInfo>,
    pub insns: Vec<u8>,  // Dalvik bytecode
    pub handlers: Vec<ExceptionHandler>,
}
```

## Dalvik Bytecode

### Instruction Format
- **OP**: Single opcode byte
- **Register-based**: Up to 65536 registers per method
- **Variable width**: 2, 4, 6, 8, or 10 bytes

### Major Opcode Categories
- **Move**: move, move-wide, move-object
- **Return**: return, return-void, return-wide
- **Const**: const/4, const/16, const-string
- **Monitor**: monitor-enter, monitor-exit
- **Check/Cast**: check-cast, instance-of
- **Array**: aget, aput, array-length
- **Throw**: throw
- **Goto**: goto, goto/16, goto/32
- **Compare**: cmpl, cmpg, cmp-long
- **If**: if-eq, if-ne, if-lt, if-ge
- **Invoke**: invoke-virtual, invoke-static, invoke-direct

## Security Considerations

### Common Android Malware Techniques
- **Repackaging**: Legitimate apps with malicious code
- **Update attacks**: Benign initially, downloads payload
- **Drive-by downloads**: Exploits browser vulnerabilities
- **SMS fraud**: Premium SMS sending
- **Banking trojans**: Overlay attacks, credential theft
- **Spyware**: Call recording, location tracking
- **Ransomware**: Device locking, file encryption
- **Cryptominers**: Background mining

### Obfuscation Methods
- **ProGuard/R8**: Name obfuscation, code optimization
- **DexGuard**: Commercial obfuscator
- **String encryption**: Runtime decryption
- **Class encryption**: Dynamic DEX loading
- **Native packing**: DEX in native code
- **Control flow obfuscation**: Opaque predicates

### Permissions Analysis
- Dangerous permissions flagging
- Permission escalation detection
- Runtime permission requests
- Custom permission analysis

## Testing Coverage

### Test Samples
- Minimal APK: Basic valid structure
- System apps: AOSP samples
- Malware samples: Known families
- Obfuscated apps: Various obfuscators
- Multi-dex apps: Large applications

### Validation Tests
- [ ] APK structure integrity
- [ ] DEX checksum verification
- [ ] Bytecode disassembly accuracy
- [ ] Resource parsing completeness
- [ ] Certificate chain validation

## Android Versions and DEX Formats

| Android Version | API Level | DEX Version | Features |
|----------------|-----------|-------------|----------|
| 14 | 34 | 040 | Latest |
| 13 | 33 | 039 | |
| 12 | 31-32 | 039 | |
| 11 | 30 | 039 | |
| 10 | 29 | 039 | |
| 9 | 28 | 039 | MethodHandles |
| 8 | 26-27 | 038 | InvokeDynamic |
| 7 | 24-25 | 037 | Default methods |
| 6 | 23 | 037 | |
| 5 | 21-22 | 035 | ART default |
| 4.4 | 19-20 | 035 | ART preview |

## ART vs Dalvik

### OAT Files (Optimized ART)
- Ahead-of-time compilation
- Native code with DEX embedded
- Platform-specific optimization

### ODEX Files (Optimized DEX)
- Dalvik optimization
- Device-specific
- Stripped DEX format

## Integration Points

### With Triage Pipeline
- APK/ZIP detection
- DEX magic verification
- Architecture detection from native libs

### With String Extractor
- String pool extraction
- Resource strings
- Manifest strings

### With Native Code Analyzer
- JNI correlation
- Native library analysis
- SO file parsing

## Anti-Analysis Techniques

### Detection
- Emulator detection
- Debugger detection
- Root detection
- Frida/Xposed detection
- Tampering detection

### Evasion
- Time-based triggers
- Geofencing
- C&C activation
- Staged payloads
- Reflection abuse

## Future Enhancements

- [ ] Full Android manifest parsing
- [ ] Resource decompilation
- [ ] Smali assembly output
- [ ] DEX to Java decompilation hints
- [ ] AAB (Android App Bundle) support
- [ ] VDEX/CDEX format support
- [ ] ART runtime format parsing
- [ ] Component interaction analysis
- [ ] Data flow analysis
- [ ] Taint tracking

## References

- [Dalvik Executable Format](https://source.android.com/docs/core/runtime/dex-format)
- [Android Open Source Project](https://source.android.com/)
- [APK Format](https://developer.android.com/guide/components/fundamentals)
- [ART and Dalvik](https://source.android.com/docs/core/runtime)
- [JADX Decompiler](https://github.com/skylot/jadx)
- [Apktool](https://github.com/iBotPeaches/Apktool)