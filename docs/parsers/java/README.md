# Java Class File Parser Documentation

## Overview

Java class files (.class) contain Java bytecode that runs on the Java Virtual Machine (JVM). GLAURUNG's Java parser handles class files, JAR archives, and provides analysis capabilities for JVM-based applications including Kotlin, Scala, and other JVM languages.

## Planning

- [JVM and Java Agentic Analysis Plan](./JVM_AGENTIC_ANALYSIS_PLAN.md) - detailed plan for class/JAR parsing, JVM bytecode analysis, decompilation, Minecraft mappings, runtime JVM debugging, and pydantic-ai tool integration.

## Format Specifications

### Primary References
- **JVM Specification**: The Java Virtual Machine Specification
- **Class File Constants**: `/reference/specifications/java/jvm_classfile_constants.h`
- **JAR Specification**: Extension of ZIP format with manifest

## Class File Structure

```
┌─────────────────┐
│   Magic Number  │  0xCAFEBABE
├─────────────────┤
│     Version     │  Minor and major version
├─────────────────┤
│  Constant Pool  │  Strings, class refs, method refs
├─────────────────┤
│   Access Flags  │  public, final, abstract, etc.
├─────────────────┤
│    This Class   │  Current class reference
├─────────────────┤
│   Super Class   │  Parent class reference
├─────────────────┤
│   Interfaces    │  Implemented interfaces
├─────────────────┤
│     Fields      │  Class and instance variables
├─────────────────┤
│     Methods     │  Functions with bytecode
├─────────────────┤
│   Attributes    │  Metadata and annotations
└─────────────────┘
```

## Parser Implementation

### Current Implementation Status

Implemented pieces now include:

- Rust classfile parsing for magic/version, constant-pool names, class/super names,
  fields, methods, descriptors, `Code` attribute metadata, `LineNumberTable`
  entries, and lightweight method-level bytecode xrefs for invokes, fields, class
  refs, and loaded strings.
- Python binding `g.analysis.parse_java_class_bytes(data)` for in-memory `.class`
  parsing without extracting JAR entries to temporary files.
- CLI JAR/class summarization through `glaurung classfile`.
- Agent memory tools:
  - `java_index_archive`
  - `java_detect_obfuscation`
  - `java_detect_security_sensitive_behavior`
  - `java_detect_entrypoints`
  - `java_extract_config_surface`
  - `java_view_class`
  - `java_annotate_mappings`
  - `java_lookup_mapping`
  - `java_audit_archive_set`
  - `java_trace_to_sink`
  - `java_detect_secrets`
  - `minecraft_detect_archive`
  - `minecraft_fetch_mappings`
  - `minecraft_extract_bundled_server`
- Ask-command Java seeding for archive summaries, obfuscation annotations, and
  Minecraft loader/version/mapping hints.
- Descriptor-aware deobfuscation annotations on sensitive-behavior findings,
  including mapped class names and mapped method names/signatures when a
  ProGuard/Mojang mapping file is supplied.
- Archive-set auditing for modpack-style directories, combining Minecraft metadata
  and security-sensitive sink summaries across many JARs.
- Initial trace-to-sink evidence around sensitive calls, joining the selected sink
  finding with method-local constants, nearby xrefs, mappings, and explicit stop
  reasons where precise dataflow/call graph support is not available yet. When
  `LineNumberTable` data exists, trace results include source-line anchors for the
  sink, constants, and neighboring xrefs.
- Initial redacted secret detection across method string constants and text
  resources. Findings store category, source location, length, context with the
  candidate replaced, and stable hashes, not raw values.
- Safe tests using vendored `HelloWorld` LFS samples and generated synthetic JAR,
  mapping, and Minecraft-bundler fixtures. Real Minecraft client/server/Forge
  jars remain in ignored `tmp/` for smoke tests only.

Not yet implemented:

- Full JVM instruction listing, bytecode CFG, advanced Java xrefs, and call graph.
- Full attribute parsing for local variables, annotations, modules, records, sealed
  classes, nestmates, bootstrap methods, and stack maps.
- Decompiler helper integration with Vineflower/CFR.
- Clean source-project recovery: dependency inference, source tree emission, build
  file generation, compilation, compiler-diagnostic repair, and ABI/resource
  validation.
- Remaining generic static behavior audit: source-to-sink slicing, deeper config
  correlation, secret scanning beyond config values, risk ranking, and directory-level
  archive scans.

### Phase 1: Header Validation
- [x] Magic number (0xCAFEBABE)
- [x] Version extraction
- [ ] Version compatibility policy
- [ ] File size validation

### Phase 2: Constant Pool
- [x] Core entry type parsing
- [x] UTF-8 string extraction
- [x] Class/name/descriptor resolution
- [ ] Full method/field reference graph

### Phase 3: Class Structure
- [x] Access flag extraction
- [x] Superclass extraction
- [ ] Interface implementation
- [ ] Inner class detection

### Phase 4: Member Analysis
- [x] Field enumeration
- [x] Method signature parsing
- [x] `Code` attribute metadata
- [x] `LineNumberTable` parsing
- [x] Lightweight bytecode xref extraction for invokes, fields, classes, and strings
- [ ] Bytecode instruction decode
- [ ] Annotation processing

### Phase 5: JAR Processing
- [x] Manifest parsing
- [x] Archive/resource indexing
- [x] Minecraft metadata detection
- [x] Mojang mapping fetch/cache/hash verification
- [x] ProGuard/Mojang mapping annotation coverage
- [x] Targeted ProGuard/Mojang mapping lookup
- [x] Descriptor-aware mapped class/member view annotations
- [x] Vanilla server bundler extraction
- [ ] Multi-release JAR support
- [ ] Signed JAR validation

### Phase 6: Decompilation and Source Recovery
- [ ] Java helper project with ASM, Vineflower, CFR, and JavaParser
- [ ] `java_decompile_class`
- [ ] `java_decompile_method`
- [ ] `java_decompile_archive`
- [ ] Source/bytecode line correlation
- [ ] Dependency inference from manifest, modules, Maven metadata, `jdeps`, and xrefs
- [ ] Source tree reconstruction under `src/main/java` and `src/main/resources`
- [ ] Manifest, module, ServiceLoader, framework metadata, and resource preservation
- [ ] Build system inference for plain `javac`, Maven, and Gradle
- [ ] Structured compiler diagnostics for `javac`, Maven, and Gradle
- [ ] Agentic compile-repair loop for decompiler syntax and build/classpath failures
- [ ] ABI/API comparison between original and rebuilt classes
- [ ] Recovered application validation report

### Phase 7: Static Behavior Audit and Risk Reporting
- [ ] Sensitive API rule packs for process execution, filesystem mutation,
  networking, local servers, native loading, reflection, class loading,
  serialization, crypto, credentials, scripting, unsafe APIs, and scheduling.
- [x] Initial archive-wide `java_detect_security_sensitive_behavior` with class, method,
  descriptor, bytecode index, matched instruction, rule ID, severity, confidence,
  and evidence IDs.
- [x] Initial `java_extract_config_surface` for embedded resources plus caller-supplied
  config roots using properties, TOML, JSON, XML, service descriptors, and manifests.
- [x] Initial `java_detect_entrypoints` for main classes, agents, ServiceLoader providers,
  static initializers, and scheduled job registrations.
- [x] Initial `java_trace_to_sink` for bounded method-local evidence from a
  sensitive call to constants, environment/system property strings, nearby xrefs,
  mapping context, and trace stop reasons.
- [ ] Full source-to-sink slicing across CFG blocks, callers/callees, config reads,
  argument builders, and entrypoints.
- [ ] `java_correlate_behavior_config` to distinguish capability, configured
  behavior, enabled behavior, dormant behavior, and unknown behavior.
- [x] Initial `java_detect_secrets` with strict redaction, value hashing,
  entropy/context evidence, and no default raw secret output.
- [x] Initial `java_audit_archive_set` for directory-level audit summaries across
  large JAR sets.
- [ ] `java_risk_report` with reachability/config correlation and ranked findings.
- [ ] Agent prompt and Pydantic models for cited audit findings rather than
  free-form security claims.

## Data Model

```rust
pub struct ClassFile {
    pub version: ClassVersion,
    pub constant_pool: ConstantPool,
    pub access_flags: u16,
    pub this_class: String,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<Field>,
    pub methods: Vec<Method>,
    pub attributes: Vec<Attribute>,
}

pub struct Method {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
    pub bytecode: Option<Vec<u8>>,
    pub exceptions: Vec<String>,
    pub annotations: Vec<Annotation>,
}

pub struct JavaXref {
    pub source_method: String,
    pub kind: String,
    pub target: String,
    pub bci: Option<u32>,
    pub constant_pool_index: Option<u16>,
}

pub struct JavaLineNumber {
    pub start_pc: u16,
    pub line_number: u16,
}

pub struct JavaSensitiveFinding {
    pub finding_id: String,
    pub archive_sha256: String,
    pub rule_id: String,
    pub sink_kind: String,
    pub severity: String,
    pub confidence: f32,
    pub class_internal_name: String,
    pub mapped_class_name: Option<String>,
    pub method_name: String,
    pub mapped_method_names: Vec<String>,
    pub method_descriptor: String,
    pub bci: Option<u32>,
    pub matched_symbol: String,
    pub evidence_ids: Vec<String>,
}

pub struct JavaConfigBinding {
    pub config_path: String,
    pub key: String,
    pub value_kind: String,
    pub redacted_value_hash: Option<String>,
    pub evidence_id: String,
}
```

## JVM Version History

| Major | Minor | Java Version | Release Year |
|-------|-------|--------------|--------------|
| 65    | 0     | Java 21      | 2023         |
| 64    | 0     | Java 20      | 2023         |
| 63    | 0     | Java 19      | 2022         |
| 61    | 0     | Java 17 LTS  | 2021         |
| 55    | 0     | Java 11 LTS  | 2018         |
| 52    | 0     | Java 8       | 2014         |

## Security Considerations

### Malicious Bytecode
- Stack manipulation attacks
- Type confusion
- Reflection abuse
- ClassLoader exploits

### JAR Security
- Unsigned code execution
- Manifest manipulation
- Resource exhaustion
- Zip slip vulnerability

### Static Behavior Audit
- Never execute target Java code while answering static audit questions.
- Classify sensitive behavior by evidence-backed sink category, not by vague
  "suspicious" labels.
- Distinguish code capability from configured or reachable behavior. A mod that
  contains HTTP code is different from one that has a current config enabling it.
- Redact tokens, session IDs, API keys, OAuth secrets, and high-entropy credential
  candidates by default. Store hashes and context instead of raw values.
- Correlate sinks to entrypoints, scheduler callbacks, service providers, framework
  lifecycle hooks, and configuration keys before assigning high confidence.
- Treat deobfuscation and string decoding as bounded analysis. Report transforms,
  byte counts, and confidence, and preserve original bytecode evidence.

## Testing Coverage

### Test Samples
- Simple class files: Various Java versions
- Complex inheritance: Multiple interfaces
- JAR files: With dependencies
- Obfuscated code: ProGuard/R8 processed
- Source recovery fixtures: resources, services, inner classes, enums, records,
  lambdas, generics, checked exceptions, and small multi-JAR classpaths
- Static audit fixtures: safe generated classes that reference process execution,
  filesystem writes/deletes, HTTP and socket APIs, local server APIs, reflection,
  custom class loaders, serialization, crypto, scheduled executors, environment
  reads, system properties, and config-driven branches without executing them
- Local-only smoke tests: Minecraft client/server/Forge JARs in ignored `tmp/`

## Future Enhancements

- [ ] Bytecode disassembly
- [ ] Control flow graph generation
- [ ] Dependency analysis
- [ ] Clean compilable source project recovery
- [ ] Source-to-sink behavior slicing
- [ ] Config-aware risk reporting for JAR sets and modpacks
- [ ] Android DEX support
- [ ] Kotlin metadata parsing
- [ ] GraalVM native image support

## References

- [JVM Specification](https://docs.oracle.com/javase/specs/jvms/)
- [JAR File Specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/)
- [ASM Framework](https://asm.ow2.io/)
