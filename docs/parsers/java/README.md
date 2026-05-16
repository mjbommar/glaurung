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
  fields, methods, descriptors, `SourceFile`, method `Exceptions`, `Code` attribute
  metadata, `LineNumberTable`, `LocalVariableTable`, `LocalVariableTypeTable`, JVM
  exception handler tables, runtime-visible/runtime-invisible class/member
  annotations, structural class attributes (`InnerClasses`, `EnclosingMethod`,
  `NestHost`, `NestMembers`, `Record`), instruction listings, and lightweight
  method-level bytecode xrefs for invokes, fields, class refs, and loaded strings.
- Rust central-directory JAR indexing for bounded archive metadata: entry counts,
  compressed/uncompressed sizes, nested JAR/ZIP entries, multi-release class variants,
  signed-JAR metadata, Maven metadata paths, ServiceLoader descriptors,
  `module-info.class`, zip-slip path detection, and truncation state.
- Opt-in recursive nested archive indexing in `java_index_archive`, producing bounded
  summaries for selected nested JAR/ZIP payloads without extracting or executing
  archive code.
- Manifest-aware multi-release selection in `java_index_archive`, reporting which
  base or `META-INF/versions/<N>/` class entry is selected for a requested Java
  target version.
- Python binding `g.analysis.parse_java_class_bytes(data)` for in-memory `.class`
  parsing without extracting JAR entries to temporary files.
- CLI JAR/class summarization through `glaurung classfile`.
- Agent memory tools:
  - `java_index_archive`
  - `java_detect_obfuscation`
  - `java_detect_security_sensitive_behavior`
  - `java_detect_entrypoints`
  - `java_detect_frameworks`
  - `java_extract_config_surface`
  - `java_view_class`
  - `java_annotate_mappings`
  - `java_lookup_mapping`
  - `java_list_classes`
  - `java_list_methods`
  - `java_audit_archive_set`
  - `java_trace_to_sink`
  - `java_reachability`
  - `java_detect_secrets`
  - `java_detect_suspicious_blobs`
  - `java_verify_signatures`
  - `java_infer_dependencies`
  - `java_infer_build_system`
  - `java_compile_recovered_project`
  - `java_reconstruct_source_tree`
  - `java_compare_rebuilt_abi`
  - `java_validate_recovered_application`
  - `java_view_bytecode`
  - `java_cfg`
  - `java_xrefs_from`
  - `java_xrefs_to`
  - `java_call_graph`
  - `java_correlate_behavior_config`
  - `java_risk_report`
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
- Initial entrypoint-to-target reachability through `java_reachability`, using
  detected entrypoints and the bounded constant-pool call graph to find paths to a
  requested method or external sink. Reachability queries can now optionally pin the
  target to a specific source class, source method descriptor, and BCI so reports can
  distinguish one call site from another call to the same API.
- Initial bytecode viewing for selected methods, exposing BCI, opcode, mnemonic,
  normalized operands, line anchors, local-variable scopes, xrefs, bounded windows,
  and mapping context.
- Initial class listing through `java_list_classes`, exposing bounded package/name
  and access-flag filters, superclass/interface/member counts, optional annotation
  descriptors, `SourceFile` metadata, inner/nest/record summary counts, optional
  ProGuard/Mojang mapped names, and `java_class` KB evidence.
- Initial method listing through `java_list_methods`, exposing bounded method
  summaries with class/name/descriptor filters, code-size metadata, line-number
  counts/ranges, decoded parameter/return types, `SourceFile` metadata, optional
  annotation descriptors, optional ProGuard/Mojang mapped names, and `java_method`
  KB evidence.
- Initial bytecode CFG construction for selected methods, exposing basic blocks,
  conditional/goto/fallthrough/default-switch/exception edges, line anchors,
  exception handler ranges, stop reasons, and KB `java_cfg` nodes.
- Initial normalized xref queries through `java_xrefs_from` and `java_xrefs_to`,
  exposing source class/method, BCI, line anchors, target owner/name/descriptor,
  xref kind, optional mapping-aware source/target annotations, and KB `java_xref`
  nodes.
- Initial constant-pool call graph construction through `java_call_graph`, exposing
  method invocation edges, invoke kinds, source BCI/line anchors, defined-vs-external
  target classification, optional mapping-aware source/target annotations, and KB
  `java_call_graph` nodes.
- Initial redacted secret detection across method string constants and text
  resources. Findings store category, source location, length, context with the
  candidate replaced, and stable hashes, not raw values.
- Initial signed-JAR cryptographic validation through `java_verify_signatures`,
  using `jarsigner -verify` when available and reporting signed/unsigned/invalid
  state, warning counts, signed-entry counts, signature metadata entries, bounded
  output excerpts, and KB evidence without executing archive code.
- Initial dependency inference through `java_infer_dependencies`, combining manifest
  `Class-Path`, Maven `pom.properties`, nested JAR paths, and bytecode external
  package references, plus optional bounded `jdeps -verbose:package` evidence, into
  `java_dependency` KB nodes without downloading code.
- Initial build-system inference through `java_infer_build_system`, selecting
  `javac`, Maven, or Gradle from recovered source-root build files, embedded Maven
  metadata, Gradle/plugin metadata, Minecraft mod metadata, classfile Java release,
  and dependency evidence. It emits build-control files and `java_build_system` KB
  nodes without fetching dependencies.
- Initial recovered-project compilation through `java_compile_recovered_project`,
  supporting bounded `javac` execution for generated source trees and argfiles,
  automatic `sources.txt` population, timeout handling, structured diagnostics, and
  `java_compile_result` KB nodes.
- Initial source-tree reconstruction through `java_reconstruct_source_tree`,
  creating `src/main/java` and `src/main/resources` scaffolds, preserving runtime
  resources and metadata, skipping signed-JAR signature files, tracking classes that
  still need decompilation, and emitting explicit generated stubs only when requested.
- Initial ABI comparison through `java_compare_rebuilt_abi`, comparing original and
  rebuilt JARs or class directories by class names, field descriptors, method
  descriptors, access flags, selected `all`/`package_api`/`public_api` scope, and
  optional class/member annotation fingerprints, with `java_abi_comparison` KB
  evidence.
- Initial recovered-application validation through
  `java_validate_recovered_application`, orchestrating bounded `javac`
  compilation, rebuilt ABI comparison, original archive resource parity against
  `src/main/resources`, generated-stub rejection unless explicitly allowed, and
  `java_recovery_validation` KB evidence.
- Initial behavior/config correlation that joins sensitive sink findings, method-local
  trace constants, and embedded or caller-supplied config keys to classify
  `capability_only`, `configured_enabled`, `configured_disabled`, or
  `configured_unknown`.
- Initial generic framework and metadata detection through `java_detect_frameworks`,
  covering manifest applications/agents, ServiceLoader, Maven coordinates, JPMS
  modules, OSGi bundles, Spring Boot, Forge/NeoForge/Fabric/Quilt mods, and
  Bukkit/Paper/Velocity-style plugin descriptors.
- Initial generic risk reporting that rolls up sensitive behavior, config
  correlation, exact call-site reachability, entrypoints, and redacted secret
  candidates into ranked `java_risk_finding` evidence nodes.
- Safe tests using vendored `HelloWorld` LFS samples and generated synthetic JAR,
  mapping, and Minecraft-bundler fixtures. Real Minecraft client/server/Forge
  jars remain in ignored `tmp/` for smoke tests only.

Not yet implemented:

- Stack/local frames, interprocedural xrefs, and advanced call graphs such as
  CHA/RTA with precise virtual dispatch candidates.
- Full attribute parsing for parameter annotations, annotation defaults, modules,
  records, sealed classes, nestmates, bootstrap methods, stack maps, and
  runtime-visible metadata beyond the initial source/debug and class/member
  annotation attributes.
- Decompiler helper integration with Vineflower/CFR.
- Clean source-project recovery after the initial dependency/build/scaffold/compile,
  ABI-comparison, and validation-report layers: dependency resolution policy,
  decompiler source emission, Maven/Gradle execution, compiler-diagnostic repair,
  annotation/module parity, and richer resource policy.
- Remaining generic static behavior audit: source-to-sink slicing, deeper config
  correlation, framework-aware reachability, and richer directory-level risk
  reporting.

### Current Roadmap Adjustment

Recent Minecraft and BMC4 mod smoke tests changed the order of work. The parser and
agent tools are now strong enough for evidence-backed static triage, so the next
priority is not another broad scanner. The next priority is structure:

1. Harden JAR indexing for nested archives, multi-release variants, signed metadata,
   module/Maven/service metadata, and budget reporting.
2. Build bytecode CFG, normalized xrefs, and an initial call graph.
3. Expand framework/mod-loader lifecycle reachability beyond the initial
   annotation-based Forge/NeoForge constructors and event subscribers so findings
   can move from "capability" to "reachable from lifecycle callback" when evidence
   supports it.
4. Calibrate risk reports, especially secret false positives and config semantics.
5. Add ASM/Vineflower/CFR helper tooling for decompiler output and source/bytecode
   correlation.
6. Start clean source recovery: extend dependency/build inference, emit
   source/resources, compile, repair diagnostics, compare rebuilt ABI/resources,
   and summarize whether the recovered application is currently acceptable.

Important lessons:

- Mojang/ProGuard mappings are mandatory for readable answers on obfuscated jars.
- Minecraft debug tables can provide useful line/local-scope anchors even when names
  remain obfuscated or synthetic.
- Config correlation should stay conservative; exact matches are reliable but miss
  framework defaults and indirect key construction.
- Risk reports must keep capability, reachability, configured state, and observed
  runtime behavior separate.
- Signature metadata and nested archive state are separate evidence dimensions:
  Minecraft 1.20.1 client smoke tests show a Mojang-signed client JAR
  (`MOJANGCS.SF/RSA`), while the server launcher/bundler JAR is unsigned and wraps
  nested server payloads.

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
- [x] Initial inner class, enclosing method, and nest metadata detection

### Phase 4: Member Analysis
- [x] Field enumeration
- [x] Method signature parsing
- [x] Initial JVM descriptor decoding for field types and method parameter/return
  types
- [x] `Code` attribute metadata
- [x] `SourceFile`, `Exceptions`, `LocalVariableTable`, and `LocalVariableTypeTable`
  parsing
- [x] `LineNumberTable` parsing
- [x] Lightweight bytecode xref extraction for invokes, fields, classes, and strings
- [x] Initial normalized xref queries via `java_xrefs_from` and `java_xrefs_to`
- [x] Mapping-aware xref and call graph annotations for ProGuard/Mojang names
- [x] Initial bytecode instruction decode and `java_view_bytecode`
- [x] Initial bounded class listing with package/name/access filters, class
  summaries, `SourceFile`, annotations, and mapping names
- [x] Initial bounded method listing with filters, code and line-table summaries,
  decoded parameter/return types, `SourceFile`, annotations, and mapping names
- [x] Initial bytecode CFG via `java_cfg`
- [x] Initial constant-pool call graph via `java_call_graph`
- [x] Exception-handler table parsing and CFG exception edges
- [x] Initial runtime-visible/runtime-invisible class/member annotation parsing
- [x] Initial record component parsing and class-view surfacing
- [ ] Stack/local frame analysis
- [ ] Parameter annotations, annotation defaults, and richer framework annotation
  semantics

### Phase 5: JAR Processing
- [x] Manifest parsing
- [x] Archive/resource indexing
- [x] Initial native central-directory JAR indexing with nested archive,
  multi-release, signed metadata, Maven metadata, ServiceLoader, module-info, and
  zip-slip detection.
- [x] Optional nested JAR/ZIP index summaries through `java_index_archive`
- [x] Minecraft metadata detection
- [x] Mojang mapping fetch/cache/hash verification
- [x] ProGuard/Mojang mapping annotation coverage
- [x] Targeted ProGuard/Mojang mapping lookup
- [x] Descriptor-aware mapped class/member view annotations
- [x] Vanilla server bundler extraction
- [x] Initial multi-release JAR variant detection
- [x] Manifest-aware multi-release target class selection
- [x] Initial signed JAR metadata detection
- [x] Initial signed JAR cryptographic validation via `java_verify_signatures`

### Phase 6: Decompilation and Source Recovery
- [ ] Java helper project with ASM, Vineflower, CFR, and JavaParser
- [ ] `java_decompile_class`
- [ ] `java_decompile_method`
- [ ] `java_decompile_archive`
- [ ] Source/bytecode line correlation
- [x] Initial `java_infer_dependencies` from manifest `Class-Path`, Maven metadata,
  nested archives, bytecode external package references, and optional `jdeps`
  package evidence
- [ ] Dependency resolution from modules, supplied classpaths, and missing class
  diagnostics
- [x] Initial source tree scaffold under `src/main/java` and `src/main/resources`
- [x] Initial manifest, ServiceLoader, framework metadata, and resource preservation
- [ ] Decompiled source emission, module source recovery, and semantic source/resource
  validation
- [x] Initial build system inference for plain `javac`, Maven, and Gradle
- [ ] Build-system refinement for module paths, annotation processors, loader-specific
  Minecraft build plugins, and resolver/cache policy
- [x] Initial bounded `javac` compilation and structured diagnostics
- [ ] Maven/Gradle compile execution and richer structured diagnostics
- [ ] Agentic compile-repair loop for decompiler syntax and build/classpath failures
- [x] Initial ABI/API comparison between original and rebuilt classes
- [x] Initial scoped ABI filtering for all, package, and public/protected API
- [x] Initial resource validation between original archives and recovered
  `src/main/resources`
- [x] Optional class/member annotation parity in ABI validation
- [ ] Parameter annotation/default and module validation between original and rebuilt
  artifacts
- [x] Initial recovered application validation report

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
  static initializers, scheduled job registrations, Forge/NeoForge `@Mod`
  constructors, and Forge/NeoForge event subscriber methods.
- [x] Initial `java_detect_frameworks` for generic JVM framework/mod/plugin metadata.
- [x] Initial `java_trace_to_sink` for bounded method-local evidence from a
  sensitive call to constants, environment/system property strings, nearby xrefs,
  mapping context, and trace stop reasons.
- [x] Initial `java_reachability` for bounded entrypoint-to-target call graph paths,
  including exact source call-site filters for risk-report evidence.
- [ ] Full source-to-sink slicing across CFG blocks, callers/callees, config reads,
  argument builders, and entrypoints.
- [x] Initial `java_correlate_behavior_config` to distinguish capability-only,
  configured enabled, configured disabled, and configured unknown behavior using
  exact config-key evidence.
- [ ] Broader framework-aware config correlation for lifecycle hooks, default
  config generation, policy files, and indirect key construction.
- [x] Initial `java_detect_secrets` with strict redaction, value hashing,
  entropy/context evidence, and no default raw secret output.
- [x] Initial `java_detect_suspicious_blobs` for encoded class/string constants,
  same-method decoder-to-sink correlation, hidden class/native/archive resources,
  compressed blobs, high-entropy resource blobs, redacted hashes, and
  `java_suspicious_blob` KB nodes.
- [x] Initial `java_audit_archive_set` for directory-level audit summaries across
  large JAR sets.
- [x] Initial `java_risk_report` with config correlation, exact call-site
  reachability states, entrypoint/secret counts, ranked findings, and
  `java_risk_finding` KB nodes.
- [ ] Framework lifecycle reachability and dynamic observation states for
  `java_risk_report`.
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
    pub source_file: Option<String>,
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
    pub instructions: Vec<JavaInstruction>,
    pub exceptions: Vec<String>,
    pub local_variables: Vec<JavaLocalVariable>,
    pub annotations: Vec<Annotation>,
}

pub struct JavaInstruction {
    pub bci: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub length: u32,
}

pub struct JavaLocalVariable {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub descriptor: String,
    pub index: u16,
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

- [x] Initial bytecode disassembly
- [x] Initial control flow graph generation
- [x] Initial dependency inference
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
