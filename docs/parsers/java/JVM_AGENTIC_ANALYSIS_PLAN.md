# JVM and Java Agentic Analysis Plan

Status: active implementation plan
Owner area: Java/JVM parser, archive analysis, LLM tools, and runtime analysis
Primary fixtures: `tmp/minecraft-jars/` copied from local and `w1` Minecraft installs

## Purpose

This document describes how to make Glaurung useful for Java and JVM reverse
engineering in the same spirit that it handles ELF, PE, Mach-O, C, and C++
binaries today.

The target workflow is:

1. Point Glaurung at a `.jar`, `.class`, Minecraft client/server JAR, Forge/Fabric
   mod, agent JAR, or JVM application archive.
2. Build a durable index of packages, classes, methods, fields, resources,
   dependencies, xrefs, bytecode, decompiled source, mappings, and runtime
   observations.
3. Let a pydantic-ai agent use precise Java tools to answer debugging and reverse
   engineering questions with cited evidence.
4. Recover a clean source project when requested: decompile, preserve resources,
   infer dependencies/build metadata, compile, repair compiler failures, and verify
   the rebuilt artifact against bytecode evidence.
5. Support static analysis first, source recovery second, dynamic JVM debugging third,
   and bytecode patching/transformation fourth.

The plan is intentionally broader than the existing classfile parser. The current
implementation is a useful starting point, but it does not yet model JVM method
bodies, bytecode control flow, class hierarchy, call graph, decompiler output, Java
source ASTs, dependency classpaths, compilable source project reconstruction,
mappings, or runtime behavior.

## Current State

Glaurung already has a growing Java path:

- `src/analysis/java_class.rs` parses a `.class` header, constant-pool names, class
  name, superclass, interfaces, fields, method descriptors, `Code` metadata, and
  source/debug attributes (`SourceFile`, method `Exceptions`, `LineNumberTable`,
  `LocalVariableTable`, and `LocalVariableTypeTable`), exception handler tables, plus
  class/member `Signature` attributes, runtime-visible/runtime-invisible class/member
  annotations, `MethodParameters`, runtime-visible/runtime-invisible parameter
  annotations, method `AnnotationDefault` values, initial JVM instruction listings,
  structural class attributes (`InnerClasses`, `EnclosingMethod`, `NestHost`,
  `NestMembers`, `Record`, `PermittedSubclasses`, JPMS `Module`), raw
  class/member/code attribute names, `ModulePackages`, `ModuleMainClass`,
  runtime-visible/runtime-invisible type annotation counts, `Deprecated`/`Synthetic`
  markers, field `ConstantValue` constants, `SourceDebugExtension` length/hash metadata,
  constant-pool histograms, bootstrap method references, instruction metrics, and
  lightweight method-level bytecode xrefs for invokes, fields, class refs, and
  loaded strings.
  Method code summaries include `StackMapTable` verifier frame counts when present.
- `src/python_bindings/analysis.rs` exposes path-based and bytes-based class parsing.
- `src/analysis/java_jar.rs` and the Python bindings expose bounded central-directory
  JAR metadata, including nested archive entries, multi-release class variants,
  signed-JAR metadata, Maven/service metadata paths, `module-info.class`, zip-slip
  path detection, and truncation state without extracting archive contents.
- `java_index_archive` can now optionally recurse into selected nested JAR/ZIP entries
  and return bounded inner archive summaries without writing the nested payloads to
  disk.
- `java_index_archive` can now apply manifest-aware multi-release selection for a
  requested Java target version, so agents can distinguish detected versioned class
  entries from the class entry that the JVM would actually load.
- Python tools now share classfile version/size policy normalization, reporting Java
  release labels, preview classfiles, future classfile versions newer than Java SE
  26, unusual minor versions, and large/tiny classfile entries.
- Parser-facing Python tools now expose JPMS `module-info.class` summaries,
  including module name, requires, exports, opens, uses, provides, module packages,
  and module main class.
- Parser-facing Python tools now expose normalized class kinds (`module`,
  `annotation`, `interface`, `enum`, `record`, `class`) plus boolean kind helpers.
- Class listing and class viewing tools now emit KB `extends` and `implements`
  edges to placeholder `java_class` nodes so hierarchy traversal does not require
  every target class to be returned in the same result window.
- Method and class-view code summaries now expose bytecode xref count buckets:
  total, method/interface-method, field, class, string, and dynamic/invokedynamic.
- Method, class-listing, and class-view summaries now expose local-variable
  summaries, line/code rollups, stack-map and exception-handler counts, type
  annotation counts, and generic instruction category buckets for branches, switches,
  invokes, field/type refs, constant loads, strings, dynamic calls, returns, throws,
  monitors, and allocations.
- Parser-facing class summaries now expose `BootstrapMethods` counts plus
  method-handle owner/name/descriptor and argument summaries for quick lambda,
  string-concat, and invokedynamic triage.
- Python memory tools can now list package-level archive summaries with
  `java_list_packages`, including class kind counts, public class counts,
  method/field/code totals, classfile Java release sets, bootstrap-method totals,
  optional resource samples, bounded prefix filtering, and `java_package` evidence
  nodes.
- Python memory tools now provide foundational archive navigation:
  `java_list_resources` for resource path/size/compression/magic and
  manifest/service/signature/multi-release flags, `java_view_manifest` for
  continuation-aware launch/agent/class-path/multi-release/sealed/signature/build
  attributes, `java_list_services` for ServiceLoader descriptors,
  `java_detect_duplicate_classes` for duplicate class definitions with
  same/different hashes and multi-release awareness, and
  `java_list_string_constants` for bounded LDC and field string constant evidence
  with hashes and optional raw values.
- Python memory tools can now list candidate fields with `java_list_fields`,
  including descriptor/generic type decoding, constant values, raw attribute names,
  `Deprecated`/`Synthetic` markers, optional annotation descriptors, optional
  ProGuard/Mojang mapped names, and `java_field` evidence nodes.
- Python memory tools can now list archive annotations with
  `java_list_annotations`, including descriptor counts, class/field/method/record
  component occurrences, package-info counts, and `java_annotation` evidence nodes.
- `python/glaurung/cli/commands/classfile.py` provides `glaurung classfile` for
  `.class` and `.jar` inputs.
- Python memory tools can index JARs, assess obfuscation, annotate ProGuard/Mojang
  mappings, look up mapping entries, detect Minecraft archives, fetch Mojang mappings,
  extract vanilla bundled server JARs, and detect security-sensitive Java API sinks
  with optional ProGuard/Mojang class-name and descriptor-aware method-name
  annotations.
- Python memory tools can now detect initial Java entrypoints from manifests, main
  methods, agent manifests, ServiceLoader descriptors, static initializers,
  scheduler registrations, Forge/NeoForge `@Mod` constructors, and Forge/NeoForge
  event subscriber methods.
- Python memory tools can now detect generic framework and metadata context from
  manifests, ServiceLoader descriptors, Maven coordinates, JPMS modules, OSGi bundles,
  Spring Boot metadata, Minecraft mod-loader metadata, and plugin descriptors.
- Python memory tools can now extract an initial config/resource surface from
  manifests, ServiceLoader descriptors, embedded properties/JSON/TOML/XML resources,
  external config roots, and redacted sensitive config values.
- Python memory tools can now run an initial archive-set audit over JAR files or
  directories, aggregating Minecraft metadata and sensitive sink categories for
  modpack-style review.
- Python memory tools can now trace a selected sensitive sink to method-local
  constants, nearby bytecode xrefs, mapping-aware names, source-line anchors from
  `LineNumberTable`, and explicit stop reasons for unavailable
  CFG/call-graph/dataflow precision.
- Python memory tools can now find initial bounded call-graph reachability paths from
  detected entrypoints to a requested method or external sink target.
- Python memory tools can now view a selected method's JVM bytecode with BCI, opcode,
  mnemonic, operands, source-line anchors, xrefs, bounded windows, and mapping context.
- Python memory tools can now build an initial bytecode CFG for a selected method,
  with basic blocks, conditional/goto/fallthrough/default-switch/exception edges,
  line anchors, exception handler ranges, and explicit stop reasons for missing frame
  analysis.
- Python memory tools can now query normalized bytecode xrefs from a selected source
  class/method or to a selected target owner/name/descriptor, emitting `java_xref`
  evidence nodes with optional ProGuard/Mojang mapping-aware source and target
  annotations.
- Python memory tools can now build an initial constant-pool call graph from method
  invocation xrefs, including invoke kinds, source BCI/line anchors, and
  defined-vs-external target classification, with optional mapping-aware source and
  target annotations.
- Python memory tools can now detect likely secrets in class string constants and
  text resources while redacting raw values and emitting stable hashes.
- Python memory tools can now verify JAR signatures with `jarsigner -verify` when
  available, reporting signed/unsigned/invalid state, signed-entry counts, warnings,
  signature metadata entries, bounded output excerpts, and KB evidence without
  executing archive code.
- Python memory tools can now infer an initial dependency/classpath profile from
  manifest `Class-Path`, Maven `pom.properties`, nested JAR paths, bytecode external
  package references, and optional bounded `jdeps -verbose:package` output, emitting
  `java_dependency` evidence nodes without downloading dependencies.
- Python memory tools can now infer an initial source-recovery build plan with
  `java_infer_build_system`, selecting `javac`, Maven, or Gradle from recovered
  source-root build files, embedded Maven/Gradle/plugin metadata, Minecraft mod
  metadata, classfile Java release, and dependency evidence while emitting
  `java_build_system` evidence nodes.
- Python memory tools can now compile recovered Java source trees with bounded
  `javac`, Maven, and Gradle execution through
  `java_compile_recovered_project`, including generated `sources.txt` population,
  nested argfile expansion, timeout handling, structured diagnostics, rebuilt
  JAR/class-directory reporting, and `java_compile_result` evidence nodes.
- Glaurung now has a local JVM helper project under `java/glaurung-jvm-tools` that
  packages ASM, CFR, Vineflower, and JavaParser behind a JSON CLI. Python tools call
  this helper for bytecode summaries, decompiled source, and AST summaries without
  executing recovered application code.
- Python memory tools can now decompile one class with `java_decompile_class`,
  decompile bounded archive slices with `java_decompile_archive`, and parse
  recovered source with `java_parse_decompiled_source`, emitting
  `java_decompile_unit` and `java_decompile_archive` evidence nodes. Archive
  decompilation includes package/glob filters, CFR/Vineflower fallback scoring,
  explicit inner-class `skip`/`companion` policy, inner/anonymous/lambda grouping,
  mapping-aware filters/metadata, optional mapped source-name rewriting, optional
  compile-candidate scoring, source emission, and source/bytecode correlation
  anchors.
- Python memory tools can now create an initial recovered source-project scaffold
  with `java_reconstruct_source_tree`, preserving runtime resources and metadata
  under `src/main/resources`, creating `src/main/java`, skipping signed-JAR signature
  files, optionally emitting CFR/Vineflower decompiled top-level source files,
  generating minimal `sources.txt`, `javac.args`, `pom.xml`, and
  `.glaurung/recovery.json` files, tracking classes that still require
  decompilation, and emitting marked stubs only when explicitly requested.
- Python memory tools can now run an initial compile-repair loop through
  `java_repair_decompiled_source`, applying safe mechanical javac-diagnostic repairs
  and recompiling. Repair classes now cover public Java types emitted into the wrong
  filename, dotted inner companion declarations, unique missing imports resolved to
  local source types, and missing dependencies satisfied by local `libs/*.jar` or
  `lib/*.jar` files; repairs update `sources.txt` or `javac.args` as needed and
  emit `java_repair_result` evidence.
- Python memory tools can now compare original and rebuilt Java ABI surfaces with
  `java_compare_rebuilt_abi`, checking class presence, field/method descriptors,
  access flags, selected `all`/`package_api`/`public_api` scope, and optional
  class/member annotation fingerprints across JARs, class directories, or single
  class files while emitting `java_abi_comparison` evidence nodes.
- Python memory tools can now emit an initial recovered-application validation report
  with `java_validate_recovered_application`, orchestrating bounded `javac`
  compilation, rebuilt ABI comparison, original archive resource parity against
  `src/main/resources`, generated-stub rejection unless explicitly allowed, and
  `java_recovery_validation` evidence nodes. Validation output includes explicit
  checks, blocking issue counts, manifest/ServiceLoader/module metadata parity,
  `clean_enough`/`not_clean_enough` summaries, and next-action hints.
- Python memory tools can now run an initial end-to-end recovery flow with
  `java_recover_project`, preserving resources/build metadata, decompiling bounded
  archive slices, refreshing build files, persisting JavaParser AST evidence,
  compiling, optionally repairing, and validating the recovered project.
- Python memory tools can now list candidate classes with `java_list_classes`,
  exposing bounded package/name/access-flag filtering, superclass/interface/member
  counts, `SourceFile` metadata, optional annotation descriptors, optional
  ProGuard/Mojang mapped names, and `java_class` evidence nodes.
- Python memory tools can now list candidate fields with `java_list_fields`,
  exposing bounded class/name/descriptor/access filtering, decoded field types,
  readable generic field signatures, constant values, raw attribute names,
  `Deprecated`/`Synthetic` markers, optional annotation descriptors, optional
  ProGuard/Mojang mapped names, and `java_field` evidence nodes.
- Python memory tools can now list candidate methods with `java_list_methods`,
  exposing bounded class/name/descriptor filtering, code-size summaries,
  line-number counts/ranges, decoded parameter/return types, raw and readable generic
  signatures, `SourceFile` metadata, `MethodParameters` names, parameter annotation
  counts, annotation defaults, optional annotation descriptors, optional
  ProGuard/Mojang mapped names, and `java_method` evidence nodes.
- Python memory tools can now list archive annotations with
  `java_list_annotations`, exposing descriptor counts and class, field, method,
  record-component, and `package-info` occurrences with `java_annotation` evidence
  nodes.
- Python memory tools can now correlate sensitive sink findings with method-local
  constants and extracted configuration keys, producing initial config states for
  behavior claims.
- Python memory tools can now build an initial generic Java risk report that ranks
  sensitive behavior, config correlation, entrypoint counts, and redacted secret
  candidates into `java_risk_finding` evidence nodes.
- Existing archive tools can enumerate and extract JAR contents because JAR is a ZIP
  container.
- `glaurung ask` can seed Java archive summaries and Minecraft mapping hints.

Known limitations:

- The Rust parser still needs deeper JVM attribute semantics beyond the parsed
  structural subset, including full type-annotation target/value decoding, complete
  stack-map frame bodies, richer bootstrap argument typing, richer module/annotation
  parity, and bytecode verifier frame modeling.
- There is no stack/local frame model, advanced Java xref model, CHA/RTA call graph,
  decompiler helper, or JVM runtime tool surface.
- There is initial dependency inference, build-system inference, source-tree
  scaffolding, bounded `javac` compile diagnostics, ABI comparison, resource parity
  checking, and a validation rollup, but no dependency resolver, Java decompiler
  source emitter, Maven/Gradle compile execution, repair loop, annotation/module
  parity, or mature recovered-artifact compatibility scoring.
- The generic static-audit layer now has initial sensitive sinks, entrypoints,
  config/resource extraction, config correlation, redacted secret scanning,
  archive-set summaries, and per-archive risk reports. It still lacks precise
  reachability, interprocedural source-to-sink slicing, framework-aware config
  semantics, dynamic observation, and mature risk calibration.
- The current memory agent mostly registers hand-written wrappers instead of using
  `tool_to_pyd_ai`, which means many tool calls bypass generic evidence logging.
- Local JDK availability can vary. Dynamic, decompiler, compiler, and JDK-tool
  integration must detect usable `java`, `javac`, `jar`, `jdeps`, `jcmd`, and `jfr`
  rather than assuming a single PATH layout.

Copied Minecraft fixtures currently include:

- `tmp/minecraft-jars/w1-client/minecraft-client-1.20.1.jar`
- `tmp/minecraft-jars/w1-client/minecraft-client-1.21.11.jar`
- `tmp/minecraft-jars/w1-client/forge-1.20.1-47.4.18-client.jar`
- `tmp/minecraft-jars/local-server/minecraft-server-1.20.1.jar`
- `tmp/minecraft-jars/local-server/forge-1.20.1-47.4.18-server.jar`
- `tmp/minecraft-jars/local-server/forge-1.20.1-47.4.18-universal.jar`
- `tmp/minecraft-jars/local-server/server-starter-server.jar`

These are ignored by git and should remain in `tmp/`.

## Findings From Implementation and Smoke Tests

These observations should steer the next execution steps.

- Minecraft and Forge/Fabric/modpack JARs are useful stress tests because they combine
  obfuscation, mappings, debug metadata, nested packaging, service metadata,
  reflection, config resources, and large archive sizes.
- Mojang mappings are essential for useful human explanations. Raw bytecode remains
  the source of truth, but names such as `enn#s()V` only become actionable when the
  tool can also report `net.minecraft.client.Minecraft#tick()V`.
- Debug metadata is present in some Minecraft client classes, but it is not clean
  source recovery metadata. `LineNumberTable` and local-variable slot scopes are
  valuable; `SourceFile` may be generic and local names may be synthetic or obfuscated
  (`$$0`, `$$1`, etc.).
- Config correlation must remain conservative. Exact key matching prevents false
  claims like "this behavior is enabled", but it misses indirect key construction,
  framework default config generation, and policy/lifecycle semantics.
- Secret detection is useful as a redacted signal, but high-entropy strings in
  manifests, rendering constants, mod metadata, and generated identifiers can dominate
  risk reports. Ranking needs stronger context filters and category-specific
  suppression before secrets should drive top-level severity.
- The current risk-report state is "capability plus local evidence", not full
  exploitability. Risk answers must continue to distinguish capability, entrypoint or
  framework reachability, configured/enabled state, and dynamic observation.
- Vanilla server and launcher-style artifacts can hide the real target JAR inside
  nested or versioned entries. Native JAR indexing needs first-class nested archive,
  multi-release, and signed-JAR handling.
- Signed metadata and cryptographic verification are distinct: smoke tests showed
  Minecraft 1.20.1 client as Mojang-signed (`MOJANGCS.SF/RSA`) with verifier
  warnings, while the 1.20.1 server launcher/bundler is unsigned and contains many
  nested payload entries.
- Nested archive indexing changes the apparent size of launcher-style JARs. The
  Minecraft 1.20.1 server launcher has only a few outer bundler classes, but nested
  indexing reveals the actual gameplay server payload plus large libraries such as
  `fastutil`.
- Multi-release policy must check the manifest, not just the presence of
  `META-INF/versions/*`. Minecraft smoke tests found Java 9 class variants in nested
  dependencies such as SLF4J, Log4j, and Gson, while Kotlin-for-Forge contains
  versioned entries without a multi-release manifest flag.
- Source recovery will need both bytecode truth and decompiler output. The parser
  now captures the source/debug anchors needed to compare and repair decompiled code,
  but it does not yet produce a compilable project.

## Near-Term Execution Order

The next work should happen in this order unless a specific investigation requires a
detour:

1. **JAR index hardening follow-through**: recurse into selected nested archives,
   model multi-release class selection policy, parse Maven/service metadata contents
   at scale, and use `java_verify_signatures` where cryptographic signature state
   matters. Initial nested archive summaries and signature verification now exist;
   initial multi-release target selection, resource listing, manifest viewing,
   ServiceLoader listing, duplicate-class detection, and string-constant listing now
   exist; remaining work should focus on policy, rollups, and classpath/dependency
   use across nested archives.
2. **Bytecode CFG and xrefs**: basic blocks, branch/switch/exception edges, normalized
   xref tables, `java_xrefs_from`, `java_xrefs_to`, and a first call graph.
3. **Reachability and framework context**: connect entrypoints, ServiceLoader,
   Forge/Fabric/NeoForge metadata, schedulers, thread starts, static initializers, and
   mod lifecycle hooks to sensitive behavior.
4. **Risk report calibration**: reduce secret false positives, add policy/suppression
   hooks, separate capability/reachable/configured/observed states in every ranked
   item, and make archive-set reports consume per-archive `java_risk_report` output.
5. **Decompiler helper**: add the Java helper project with ASM first, then
   Vineflower/CFR wrappers and source/bytecode correlation.
6. **Clean source recovery loop**: emit source/resources, infer dependencies/build
   metadata, compile with `javac`/Maven/Gradle, parse diagnostics, repair, and compare
   rebuilt ABI/resources against the original archive.
7. **Opt-in runtime observation**: bounded JDI/JFR/javaagent tooling only after static
   evidence and source recovery have enough structure to constrain what is executed.

## Gap Coverage Matrix

This table keeps the source-recovery target explicit. If a gap is not represented
here, it is probably not represented strongly enough in the plan.

| Gap | Planned coverage |
| --- | --- |
| JVM instruction decode | Initial Rust decoder and `java_view_bytecode` exist; expand with ASM frames and exception context |
| Bytecode CFG, xrefs, and call graph | Initial `java_cfg`, exception edges, `java_xrefs_from`, `java_xrefs_to`, and `java_call_graph` exist; continue with frame analysis, interprocedural xrefs, and CHA/RTA dispatch |
| Descriptors and generic signatures | Initial erased JVM descriptor decoding exists for field types and method parameter/return types in class/method tools; class/member `Signature` attributes are preserved and decoded into readable class/field/method generic summaries; continue type-use annotations and bridge/synthetic correlation |
| Attributes and annotations | Initial `SourceFile`, `Exceptions`, line table, local-variable table, runtime-visible/runtime-invisible class/member and parameter annotation support, type-annotation counts, method parameters, annotation defaults, inner/enclosing/nest metadata, record components, permitted subclasses, and JPMS module extras exist; continue full type-annotation decoding, stack-map bodies, and richer framework semantics |
| Archive/resource navigation | Initial `java_list_resources`, `java_view_manifest`, `java_list_services`, `java_detect_duplicate_classes`, and `java_list_string_constants` exist; continue with nested-archive rollups, Maven metadata content parsing, policy scoring, and resource/string correlation |
| Decompiler integration | Initial JVM helper, `java_decompile_class`, `java_decompile_archive`, and `java_parse_decompiled_source` exist with CFR/Vineflower fallback scoring, compile-candidate scoring, inner grouping, AST evidence, and source/bytecode anchors; continue with `java_decompile_method`, richer line correlation, and project-classpath-aware fallback compilation |
| Mapping/de-obfuscation | Initial `java_annotate_mappings`, `java_lookup_mapping`, mapping-aware `java_view_bytecode`, `java_xrefs_from`, `java_xrefs_to`, `java_call_graph`, and mapped source-name rewrite exist; continue with `minecraft_apply_mappings`, Tiny mappings, descriptor-aware source/tree remapping, and collision handling |
| Dependency and classpath recovery | Initial `java_infer_dependencies`, `java_infer_build_system`, and local `libs/*.jar` compile repair exist for manifest class paths, Maven identity metadata, nested archive coordinates, bytecode external packages, optional `jdeps` package evidence, Java release, and `javac`/Maven/Gradle planning; continue with module `requires`, supplied classpath comparison, remote resolver/cache policy, and annotation processors |
| Signed archive validation | Initial `java_verify_signatures` exists using `jarsigner -verify`; continue with policy scoring, certificate/timestamp summaries, and archive-set rollups |
| Source tree/project reconstruction | Initial `java_reconstruct_source_tree`, `java_infer_build_system`, and `java_recover_project` exist for resource/metadata preservation, explicit stubs, generated source/build files, build planning, opt-in decompiled source emission, compile/repair/validate orchestration, and AST evidence; continue with module source recovery and stronger source/resource validation |
| Compile diagnostics | `java_compile_recovered_project` |
| Agentic compile-repair loop | Initial `java_repair_decompiled_source` exists with compile iteration budgets, public-type filename repair, companion inner declaration repair, unique missing-import repair, and local classpath repair; continue with richer decompiler syntax, signature, ambiguous import, dependency/build, and module repair classes |
| ABI/API and resource validation | Initial `java_compare_rebuilt_abi` and `java_validate_recovered_application` exist for descriptor/access ABI checks, public/package/all scope filtering, optional class/member annotation parity, resource parity, manifest/ServiceLoader/module metadata parity, compile status, generated-stub policy, quality summaries, and next actions; continue with parameter/default/module validation and richer compatibility scoring |
| Runtime behavior validation | `java_launch_target`, JDI/JFR/javaagent tools, opt-in smoke profile |
| Sensitive Java behavior detection | Initial `java_detect_security_sensitive_behavior` exists; expand sink rule packs and config correlation in Phase 3.5 |
| Entrypoint and reachability context | Initial `java_detect_entrypoints`, `java_detect_frameworks`, `java_reachability`, and method-local `java_trace_to_sink` exist; expand framework hooks and interprocedural source-to-sink traces |
| Config/resource correlation | Initial `java_extract_config_surface` and `java_correlate_behavior_config` exist; expand framework-aware and indirect-key correlation |
| Secret and token handling | Initial `java_detect_secrets` exists with redacted value hashes and no raw output by default |
| Directory/modpack risk review | Initial `java_audit_archive_set` and `java_risk_report` exist; expand framework-aware reachability and multi-archive reporting |
| Deobfuscated behavior annotation | Initial mapped class/method sensitive-sink annotations exist; continue with mapping tools, string/constant evidence, sink annotations, and agent enrichment |

## Design Goals

- Treat JVM bytecode as a first-class program representation, not as generic archive
  contents.
- Use stable Java locators instead of native VAs.
- Preserve bytecode-level truth even when decompiled Java is imperfect.
- Treat decompiled Java as an intermediate artifact. A recovered source application is
  not "clean" until it compiles and its rebuilt classes/resources match the original
  ABI and archive contract closely enough for the requested task.
- Make every LLM answer cite tool evidence: class, method descriptor, bytecode index,
  source line, resource path, runtime event, or mapping source.
- Prefer real integration tests over fabricated fixtures.
- Avoid executing untrusted Java unless the user or caller explicitly enables dynamic
  analysis.
- Make static security and behavior audit a first-class workflow. The agent should be
  able to explain process, filesystem, network, native, reflection, class-loading,
  serialization, crypto, credential, and scheduler behavior without custom one-off
  grep commands.
- Distinguish four states in audit answers: code is capable of a behavior, code is
  reachable from an entrypoint, behavior is configured/enabled by current config, and
  behavior has been observed dynamically.
- Redact sensitive values by default and cite context, hashes, and locators instead
  of raw secrets.
- Keep the Python interface typed with Pydantic models and use the existing
  `MemoryTool` contract.
- Keep Rust responsible for fast safe parsing and indexing; use Java libraries where
  the ecosystem is clearly stronger.

## Non-Goals for the First Implementation

- Full Java verifier implementation.
- Perfect decompilation.
- Bit-for-bit recreation of the original source repository, formatting, comments, or
  build system.
- Guaranteed source recovery for hostile or intentionally invalid classfiles.
- Full symbolic execution of JVM bytecode.
- Android DEX support. DEX should remain a related but separate parser/tool track.
- Running arbitrary Minecraft clients interactively. Initial runtime work should be
  headless, bounded, and opt-in.

## Conceptual Mapping from Native RE to JVM RE

Native Glaurung concepts map naturally to JVM concepts, but names and identifiers
must change.

| Native binary concept | JVM concept |
| --- | --- |
| File format parser | JAR/CLASS/module parser |
| Section | JAR entry, class attribute, Code attribute |
| VA/RVA/file offset | Class entry path plus bytecode index (BCI) |
| Function | Method: class name + method name + descriptor |
| Symbol table | Classes, fields, methods, module metadata, manifest, mappings |
| Disassembly | JVM bytecode listing with BCI and operands |
| CFG | Basic blocks over bytecode offsets plus exception-handler edges |
| Imports | Constant-pool refs, dependencies, services, module requires, manifest class path |
| Xrefs | Invoke, field access, type refs, annotations, string/resource refs |
| Decompiler output | Java source from Vineflower/CFR plus bytecode/source correlation |
| Recovered source tree | Decompiled `.java`, copied resources, inferred build files, local libraries |
| Compile/verify loop | `javac`/Maven/Gradle diagnostics plus ABI/resource comparison |
| Dynamic trace | JDI/JDWP events, JFR events, javaagent method probes |
| Sensitive sink | Process/network/filesystem/native/reflection/classloader/secret API call |
| Config source | Embedded resource, external config file, manifest, module, service metadata |
| Source-to-sink slice | Bounded backward/forward bytecode and source evidence around a behavior |
| Risk finding | Evidence-backed report item with rule ID, severity, confidence, and state |
| Patch | ASM bytecode transform or source recompile plus class replacement |

## Stable Identifiers

Use explicit JVM locators everywhere tools cross boundaries.

Examples:

```text
jar://sha256:abc123...!/net/minecraft/client/Minecraft.class
java://sha256:abc123.../net.minecraft.client.Minecraft
java://sha256:abc123.../net.minecraft.client.Minecraft#run()V
java://sha256:abc123.../net.minecraft.client.Minecraft#tick()V@bci=42
resource://sha256:abc123...!/assets/minecraft/lang/en_us.json
mapping://mojang/1.21.11/client/net.minecraft.client.Minecraft#tick()V
source://sha256:abc123.../project/src/main/java/net/minecraft/client/Minecraft.java
compile://sha256:abc123.../recovery/run/4/diagnostic/17
runtime://pid/12345/thread/37/event/98765
sink://sha256:abc123.../rule/java.network.http/openConnection/net.example.Mod#send()V@bci=73
config://sha256:abc123...!/config/example.toml?key=telemetry.enabled
risk://sha256:abc123.../finding/java.network.http/00017
```

The minimum method identity is:

```text
archive_sha256
entry_path
class_internal_name
method_name
method_descriptor
optional_bci
```

Do not rely on source line alone. Many targets are obfuscated or compiled without
debug line tables.

## Architecture

### Layer 1: Rust Native Parser and Indexer

Rust should own fast bounded parsing and safe JAR walking.

Implement:

- `src/analysis/java_class.rs`: replace or augment the hand parser with a full
  classfile parser.
- `src/analysis/java_jar.rs`: native JAR indexer with ZIP safety checks.
- `src/python_bindings/analysis.rs`: expose bytes-based and archive-based bindings.

Rust outputs should be serializable structs, not display strings.

Rust responsibilities:

- Parse classfile major/minor version and preview marker.
- Parse constant pool with resolved values.
- Parse fields, methods, descriptors, generic signatures, access flags.
- Parse attributes:
  - `Code`
  - `LineNumberTable`
  - `LocalVariableTable`
  - `LocalVariableTypeTable`
  - `StackMapTable`
  - `Exceptions`
  - `InnerClasses`
  - `EnclosingMethod`
- `RuntimeVisibleAnnotations`
- `RuntimeInvisibleAnnotations`
- `RuntimeVisibleParameterAnnotations`
- `RuntimeInvisibleParameterAnnotations`
- `AnnotationDefault`
  - `BootstrapMethods`
  - `MethodParameters`
  - `Module`
  - `ModulePackages`
  - `ModuleMainClass`
  - `NestHost`
  - `NestMembers`
  - `Record`
  - `PermittedSubclasses`
- Decode descriptors into structured parameter and return types. Initial erased
  descriptor decoding is implemented in Python tools. Initial generic `Signature`
  decoding is implemented for class, field, and method summaries; continue type
  annotations and bridge/synthetic correlation.
- Extract method bytecode, max stack, max locals, exception table.
- Build lightweight per-method xrefs from bytecode operands and constant-pool refs.
- Decode enough JVM instructions to recover invoke, field, type, string, method
  handle, method type, `invokedynamic`, constant-load, branch, switch, and exception
  handler evidence without needing decompiler output.
- Extract resource-like and endpoint-like constants: URLs, hostnames, IP literals,
  file paths, service names, config keys, system property names, environment variable
  names, and suspicious encoded blobs. Keep this as evidence, not as a verdict.
- Preserve `BootstrapMethods` and method-handle references so lambdas, string
  concatenation, dynamic constants, and `invokedynamic` call sites are auditable.
- Identify nested archives and embedded dependency metadata such as
  `META-INF/maven/**`, `META-INF/services/**`, `module-info.class`, Forge/Fabric
  metadata, and shaded library package roots.
- Identify multi-release JAR class variants under `META-INF/versions/<n>/`.
- Identify signed JAR metadata under `META-INF/*.SF`, `*.RSA`, `*.DSA`, `*.EC`.
- Enforce archive budgets and prevent zip slip.

Recommended Rust dependencies:

| Crate | Use | Notes |
| --- | --- | --- |
| `zip` | JAR/ZIP reading and safe extraction | Supports modern ZIP compression formats and metadata. |
| `ristretto_classfile` | Read/write/verify class files through Java 25 | Better long-term fit than maintaining a full hand parser. |
| `petgraph` | Optional JVM CFG/call graph internals | Use only if existing graph types are insufficient. |
| `semver` | Optional manifest/module version parsing | Useful for dependencies and mod metadata. |
| `toml` | Optional Forge `mods.toml` parsing in Rust | Python stdlib `tomllib` may be enough if metadata parsing stays in Python. |

Avoid depending on a Rust crate that only supports old classfile versions unless it
is isolated behind a feature flag. Java 21+ and Java 25 classfile support matter for
modern Minecraft and current JDKs.

### Layer 2: Java Helper Tooling

Some JVM analysis is much better in Java because mature libraries already exist.
Add a small Java helper project rather than embedding a JVM inside Python initially.

Proposed path:

```text
java/glaurung-jvm-tools/
  pom.xml
  src/main/java/com/glaurung/jvmtool/Main.java
  src/main/java/com/glaurung/jvmtool/*.java
  src/test/java/com/glaurung/jvmtool/*.java
```

The helper should be a deterministic JSON CLI:

```bash
java -jar target/glaurung-jvm-tools-0.1.0-all.jar version
java -jar target/glaurung-jvm-tools-0.1.0-all.jar bytecode --jar target.jar --class a/b/C
java -jar target/glaurung-jvm-tools-0.1.0-all.jar decompile --jar target.jar --class a/b/C --engine vineflower
java -jar target/glaurung-jvm-tools-0.1.0-all.jar parse-source --source recovered/src/main/java/a/b/C.java
```

JSON schema stability matters more than pretty console output. Python tools can wrap
the helper with `subprocess.run([...], timeout=..., capture_output=True, text=True)`
without shell interpolation.

Recommended Java dependencies:

| Dependency | Use | Initial role |
| --- | --- | --- |
| `org.ow2.asm:asm` | Class reading/writing | Core bytecode access. |
| `org.ow2.asm:asm-tree` | Mutable class/method AST | Easier CFG and transforms. |
| `org.ow2.asm:asm-analysis` | Frames, stack/local analysis | Required for bytecode reasoning and patch validation. |
| `org.ow2.asm:asm-util` | Textifier/ASMifier output | Human-readable bytecode. |
| `org.vineflower:vineflower` | Decompiler | Primary modern decompiler. |
| `org.benf:cfr` | Decompiler fallback | Decompiler diversity; useful when Vineflower fails. |
| `com.github.javaparser:javaparser-core` | Parse decompiled Java | Source AST and method slicing. |
| `com.github.javaparser:javaparser-symbol-solver-core` | Optional source symbol resolution | Useful if reconstructed source trees are used. |
| Maven Resolver | Dependency metadata and artifact resolution | Optional resolver path for recovered Maven projects. |
| Gradle Tooling API | Inspect or invoke Gradle builds | Optional; prefer subprocess Gradle wrapper when present. |
| Eclipse JDT compiler | Structured Java compile diagnostics | Optional fallback if `javac` diagnostics are insufficient. |
| `net.bytebuddy:byte-buddy` | Runtime instrumentation | Dynamic trace/patch agent. |
| `net.bytebuddy:byte-buddy-agent` | Attach helper | Dynamic instrumentation. |
| `org.tomlj:tomlj` | Forge TOML metadata | If parsing mod metadata in Java helper. |
| `org.yaml:snakeyaml` | YAML config resources | Optional config-surface parser. |
| `com.fasterxml.jackson.core:jackson-databind` | JSON output | Stable helper output. |

Optional research-grade dependencies:

| Dependency | Use | When to add |
| --- | --- | --- |
| Soot/SootUp | Jimple IR, dataflow, call graph | Add after ASM-based CFG/xrefs work. |
| WALA | Class hierarchy, pointer analysis, slicing | Add for advanced interprocedural analysis. |
| Checker Framework Dataflow | Java source/CFG dataflow | Add if source-level dataflow is needed. |
| Spoon | Source transformation and analysis | Add only if decompiled source rewriting becomes central. |

Prefer ASM for the first production path. Soot/WALA are powerful but heavier and
should be isolated as optional engines.

### Layer 3: Python and Pydantic Models

Python should expose user-facing tools and preserve evidence. Add modules like:

```text
python/glaurung/java/
  __init__.py
  ids.py
  models.py
  jdk.py
  helper.py
  mappings.py
  minecraft.py

python/glaurung/llm/tools/
  java_index_archive.py
  java_view_class.py
  java_view_bytecode.py
  java_cfg.py
  java_xrefs_from.py
  java_xrefs_to.py
  java_risk_report.py
  java_decompile.py
  java_source_recovery.py
  java_dependencies.py
  java_compile.py
  java_call_graph.py
  java_runtime.py
  java_minecraft.py
```

Python responsibilities:

- Provide Pydantic input/output models for each agent tool.
- Call Rust bindings for cheap static parsing.
- Call Java helper subprocess for decompilation, ASM frames, CFG, remapping, and
  transformations.
- Invoke `javac`, Maven, Gradle, or Java helper compile commands with structured
  diagnostic capture when source recovery is requested.
- Normalize all results into stable locators and evidence IDs.
- Cache expensive helper outputs under a project cache or temporary cache keyed by
  JAR SHA-256, helper version, options, and Java version.
- Own the generic sensitive-behavior rule packs, severity mapping, confidence
  scoring, redaction policy, and report shaping. Rust/Java helpers should emit
  facts; Python should turn those facts into auditable findings.
- Parse caller-supplied config roots and embedded resources, then correlate config
  keys and values to bytecode constants, framework metadata, and sink traces.
- Provide bounded source-to-sink workflows that combine xrefs, CFG, call graph,
  decompiled source slices, mappings, and config evidence.
- Aggregate archive-level findings into directory or application reports without
  requiring Minecraft-specific logic.
- Gate dynamic execution, dependency downloads, source repair, and runtime smoke tests
  behind explicit context/tool flags.

Recommended Python dependencies:

| Package | Use | Recommendation |
| --- | --- | --- |
| `jpype1` | In-process Java API access | Optional extra only; do not use in phase 1. |
| `tomli-w` | TOML writing if needed | Reading can use stdlib `tomllib` on Python 3.11+. |
| `networkx` | Optional graph export/debugging | Avoid in core unless needed; current KB graph may suffice. |
| `pyyaml` | YAML config parsing | Optional; needed for config-surface coverage beyond stdlib formats. |
| `detect-secrets` | Secret candidate plugins and redaction helpers | Optional audit extra; use as a signal source, not as the only detector. |
| `yara-python` | Optional signature/rule matching over resources and strings | Audit extra only; may require native libyara. |

Do not add a Python Java source parser as the primary path. `javalang` is Java 8
oriented and useful for lightweight experiments, but modern Java source parsing is
better delegated to JavaParser in the helper.

### Layer 4: Knowledge Base and Evidence

Extend the KB with JVM-specific node kinds or typed properties.

Suggested node kinds:

- `java_archive`
- `java_class`
- `java_method`
- `java_field`
- `java_package`
- `java_resource`
- `java_annotation`
- `java_module`
- `java_mapping`
- `java_runtime_event`
- `java_decompile_unit`
- `java_dependency`
- `java_build_system`
- `java_source_project`
- `java_source_file`
- `java_source_tree`
- `java_compile_result`
- `java_compile_diagnostic`
- `java_rebuild_artifact`
- `java_abi_comparison`
- `java_recovery_validation`
- `java_entrypoint`
- `java_sensitive_sink`
- `java_config_key`
- `java_external_endpoint`
- `java_secret_candidate`
- `java_suspicious_blob`
- `java_risk_finding`
- `java_rule`

Suggested edge kinds:

- `contains`
- `extends`
- `implements`
- `declares_method`
- `declares_field`
- `invokes`
- `reads_field`
- `writes_field`
- `references_type`
- `references_string`
- `references_resource`
- `annotated_with`
- `loads_service`
- `mapped_to`
- `runtime_called`
- `throws`
- `catches`
- `depends_on`
- `decompiled_from`
- `emits_source`
- `has_diagnostic`
- `repairs`
- `compiles_to`
- `abi_compared_to`
- `entrypoint_to`
- `calls_sensitive_api`
- `flows_to`
- `configured_by`
- `enabled_by`
- `opens_endpoint`
- `uses_secret_candidate`
- `scheduled_by`
- `reported_as`

Evidence location fields should support non-native addresses:

```text
archive_sha256
entry_path
class_internal_name
method_name
method_descriptor
bci_start
bci_end
source_file
source_line_start
source_line_end
resource_path
mapping_namespace
source_project_root
compile_iteration
diagnostic_id
rebuilt_artifact_path
runtime_pid
runtime_thread_id
runtime_timestamp
rule_id
sink_kind
risk_score
severity
confidence
config_path
config_key
endpoint
redacted_value_hash
entrypoint_kind
reachability_state
```

Use `tool_to_pyd_ai()` for all new Java tools so each invocation gets captured in
the generic evidence log. If the agent registration path remains hand-written,
wrap the Java tools explicitly or refactor `register_analysis_tools()` to accept a
list of `MemoryTool` instances.

## Tool Catalog

### Archive and Class Indexing

`java_index_archive`

Inputs:

- `path`
- `java_version: int | None`
- `include_resources: bool`
- `max_classes`
- `max_resources`

Outputs:

- Archive hash and size.
- Entry counts.
- Class count.
- Per-class Java release labels, classfile version labels, preview/future-version
  state, size categories, and classfile policy warnings.
- Package summary.
- Multi-release variants.
- Manifest fields.
- Main class.
- Agent classes.
- Module info.
- JPMS requires/exports/opens/uses/provides details when `module-info.class` is
  present.
- Signed JAR metadata.
- Mod metadata summary.
- Truncation flags.

Use this as the default first-touch tool for JARs.

`java_list_packages`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_package` KB nodes and `contains_package` edges from a
  `java_archive` evidence node.
- Scans JAR/ZIP class entries with the Rust class parser and aggregates package
  structure without decompilation or execution.
- Supports dotted or internal package-prefix filtering, class/resource scan
  budgets, result limits, and bounded class/resource samples.
- Reports per-package class counts, public class counts, normalized class kind
  counts, method/field/code totals, bootstrap-method totals, classfile byte totals,
  resource byte totals, Java release sets, and optional resource samples.

Inputs:

- `package_prefix`
- `include_resources`
- `max_classes_scan`
- `max_resources_scan`
- `limit`
- `classes_sample_limit`
- `resources_sample_limit`

Outputs:

- Package internal and dotted names.
- Class, public class, interface, annotation, enum, record, sealed, and module
  counts.
- Method, field, methods-with-code, and bootstrap-method totals.
- Class kind distribution, classfile major versions, Java release labels, and sample
  classes.
- Optional resource counts, byte totals, and sample resource entries.
- Scan counts, parse-error counts, truncation flags, and stop reasons.

Use this as the low-cost archive navigation layer before drilling into classes,
methods, bytecode, or decompiler output.

`java_list_resources`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_resource` KB nodes for returned entries.
- Lists non-class resources by default, with optional class inclusion.
- Supports prefix, extension, substring, scan-budget, result-limit, and bounded
  magic-read filters.
- Reports entry path, directory, file name, extension, size, compressed size,
  compression method, CRC-32, SHA-256, magic classification, manifest/service/
  signature/multi-release flags, classfile-like resources, and extension-vs-magic
  mismatches.

Use this when an agent needs to inspect archive contents, identify hidden classes,
native blobs, config/resource payloads, or suspicious mismatched resources before
deeper scanning.

`java_view_manifest`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits a `java_resource` KB node for the manifest.
- Parses JAR manifest continuation lines and sections.
- Reports main attributes, named sections, `Main-Class`, `Premain-Class`,
  `Agent-Class`, `Launcher-Agent-Class`, `Class-Path`, `Multi-Release`, `Sealed`,
  signature/digest attributes, and build attributes.

Use this as the direct manifest inspection layer for launch behavior, agents,
multi-release policy, signing evidence, and classpath hints.

`java_list_services`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_resource` KB nodes for `META-INF/services/*` descriptors.
- Parses providers with comment/blank-line handling and returns internal and dotted
  provider names.
- Supports service and provider substring filters.

Use this to identify ServiceLoader entrypoints and framework/provider wiring.

`java_detect_duplicate_classes`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_class` KB evidence for duplicate class groups.
- Groups base and `META-INF/versions/<N>/` class entries by parsed class name.
- Reports entry paths, multi-release versions, sizes, hashes, identical-vs-divergent
  byte definitions, and multi-release-only duplicates.

Use this to catch shaded dependency collisions, repeated classes, and versioned class
variants before source recovery or classpath reconstruction.

`java_list_string_constants`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits generic `string` KB nodes for returned constants.
- Lists bounded string constants from field `ConstantValue` attributes and method
  LDC bytecode xrefs.
- Reports class/method/field locators, source kind, BCI where present, length,
  preview, SHA-256, and optional raw values when explicitly requested.

Use this for low-cost endpoint/config/error-message triage without running a broad
secret scanner.

`java_list_fields`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_field` KB nodes for returned fields.
- Scans JAR/ZIP class entries with the Rust class parser.
- Supports class, field-name, descriptor, access-flag all/any/none,
  constants-only, scan-budget, and result-limit filtering.
- Reports class/source metadata, raw and decoded field descriptors, readable generic
  field signatures, field constant values, raw attribute names,
  `Deprecated`/`Synthetic` markers, optional annotation descriptors, optional
  ProGuard/Mojang mapped names, and classfile policy metadata.

Use this before decompilation when an agent needs constants, config key fields,
serial/version identifiers, public API fields, enum-like static finals, or
obfuscation evidence.

`java_list_annotations`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_annotation` KB nodes for returned annotation occurrences.
- Scans JAR/ZIP class entries with the Rust class parser.
- Supports descriptor and class filters, member inclusion, scan budgets, and result
  limits.
- Reports descriptor counts, package-info counts, class annotations, field
  annotations, method annotations, and record-component annotations.

Use this for quick framework/domain discovery before deeper framework-specific
analysis.

`java_list_classes`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_class` KB nodes for returned classes.
- Scans JAR/ZIP class entries with the Rust class parser.
- Supports package-prefix, class-name, access-flag all/any/none, scan-budget, and
  result-limit filtering.
- Reports class locators, internal/dotted/mapped names, package/simple names,
  superclasses, `SourceFile`, interfaces, JVM version, method counts, field counts,
  raw access flags, decoded access-flag names, normalized Java/classfile version
  labels, preview/future-version/size warnings, methods with code,
  inner/nest/record/sealed summary counts, and optional class annotation
  descriptors.
- Supports optional ProGuard/Mojang mapped class names when a mapping file is
  supplied.

Inputs:

- `package_prefix`
- `name_filter`
- `access_flags_all`
- `access_flags_any`
- `access_flags_none`
- Optional mapping path/namespace.
- `include_annotations`
- `limit`

Outputs:

- Class locators, names, superclasses, `SourceFile`, interface counts, method counts,
  field counts, JVM version, raw and decoded access flags, Java release labels,
  classfile size categories, classfile policy warnings, inner/nest/record/sealed
  summary counts, normalized class kind, mapped names, and optional annotation
  descriptors.

`java_view_class`

Inputs:

- `class_locator`
- Optional mapping path/namespace.
- `include_members`
- `include_annotations`
- `include_attributes`

Outputs:

- Full class declaration metadata, including `SourceFile`, `InnerClasses`,
  `EnclosingMethod`, `NestHost`, `NestMembers`, and `Record` components.
- Raw and decoded class, field, method, inner-class, and method-parameter access
  flags.
- Normalized Java/classfile version labels, preview/future-version state,
  classfile size category, and policy warnings.
- Sealed-class `PermittedSubclasses` lists.
- JPMS module summary when viewing `module-info.class`.
- Normalized class kind and kind booleans.
- Fields.
- Methods with code-size and line-number range summaries where available.
- Descriptor-aware mapped official/obfuscated names for classes and members when
  mappings are loaded.
- Annotations.
- Inner/nest/record/sealed/module data.

### Methods, Bytecode, and CFG

`java_list_methods`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_method` KB nodes for returned methods.
- Scans JAR/ZIP class entries with the Rust class parser.
- Supports class, method-name, and descriptor substring filters.
- Supports constructor inclusion/exclusion, result limits, code-size summaries, and
  line-number counts/ranges when `LineNumberTable` data exists.
- Reports decoded erased parameter and return types from JVM method descriptors.
- Reports generic `Signature` attributes and readable decoded generic
  parameter/return/type summaries when present.
- Reports `MethodParameters` names, parameter annotation counts, and annotation
  defaults when present.
- Reports class-level `SourceFile` metadata on returned methods when present.
- Reports raw method access flags and decoded access-flag names.
- Reports containing-class Java/classfile version labels, classfile size category,
  and classfile policy warnings for each method.
- Reports `StackMapTable` verifier frame counts for method code when present.
- Supports optional method annotation descriptors.
- Supports optional ProGuard/Mojang mapped class and method names when a mapping file
  is supplied.

Inputs:

- `class_filter`
- `name_filter`
- `descriptor_filter`
- Optional mapping path/namespace.
- `include_constructors`
- `include_annotations`
- `limit`

Outputs:

- Method locators.
- Raw and decoded access flags.
- Containing-class Java/classfile version labels and policy warnings.
- Descriptor, decoded erased parameter/return types, generic signatures, and mapped
  names/signatures when available.
- Readable decoded generic parameter/return/type summaries when `Signature`
  attributes are present.
- Method parameter names, parameter annotation counts, and annotation default values.
- Code size, max stack, max locals.
- `StackMapTable` verifier frame count.
- Line table availability and first/last source line when present.
- Annotation descriptors when requested.

`java_view_bytecode`

Inputs:

- `path`
- `class_name`
- `method_name`
- `method_descriptor`
- `mapping_path`
- `include_xrefs`
- `bci_start`
- `bci_end`
- `max_classes_scan`
- `max_instructions`

Outputs:

- Bytecode listing with BCI.
- Operands resolved to constant-pool refs.
- Opcode and mnemonic for decoded JVM instructions.
- Line table mapping when debug metadata exists.
- Local-variable and local-variable-type scopes when debug metadata exists.
- Exception handler table ranges and catch types.
- Optional method xrefs at matching BCI offsets.
- Descriptor-aware mapping context where ProGuard/Mojang mappings are supplied.
- Stack/local frame snapshots in a later ASM-backed revision.

`java_cfg`

Inputs:

- `method_locator`
- `include_exception_edges`
- `include_switch_edges`

Outputs:

- Basic blocks with BCI ranges, instruction counts, line anchors, and terminators.
- Conditional true/false, goto, fallthrough, default-switch, and exception edges.
- Exception handler ranges and catch types.
- Dominator-friendly block IDs.
- Stop reasons for missing stack/local frame analysis.
- Loop hints in a later revision.

Implementation notes:

- Use ASM to identify instruction boundaries and successors.
- Treat exception handlers as explicit CFG edges.
- Preserve BCI ranges so bytecode, decompiler source, and runtime traces can join.

### Xrefs and Call Graph

`java_xrefs_from`

Inputs:

- `path`
- `class_name`
- `method_name`
- `method_descriptor`
- `kind`
- budgets

Outputs:

- Normalized xrefs emitted by a source class or method.
- Source class, source method, descriptor, BCI, and line anchor.
- Target owner, name, descriptor, xref kind, and loaded string value where present.
- Optional mapped source class/method names and mapped target owner/member names
  when a ProGuard/Mojang mapping file is supplied.

`java_xrefs_to`

Inputs:

- `path`
- `target_owner`
- `target_name`
- `target_descriptor`
- `kind`
- budgets

Outputs:

- Normalized callers/references to the requested target.
- Source class/method/BCI/line anchors for each reference.
- `java_xref` KB nodes for evidence-backed agent answers.
- Official mapped target names can be used as query inputs when mappings are supplied.

`java_call_graph`

Inputs:

- `path`
- `class_name`
- `method_name`
- `method_descriptor`
- `mode: "constant_pool"` initially; later `"cha"` and `"rta"`
- `include_external`
- `max_classes`
- `max_edges`

Outputs:

- Method nodes and invocation edges.
- Invoke kind (`invokestatic`, `invokevirtual`, `invokeinterface`, etc.).
- Source BCI and source-line anchors when `LineNumberTable` exists.
- Defined-vs-external target classification.
- Optional mapped source class/method names and mapped target owner/member names
  when a ProGuard/Mojang mapping file is supplied.
- Dynamic-dispatch edge counts and stop reasons.
- Later revisions should add unresolved virtual call candidate sets, interface
  dispatch candidates, reflection warnings, CHA/RTA reachability, and entrypoint
  slicing.

Initial modes:

- `constant_pool`: cheap syntactic invokes.
- `cha`: class hierarchy analysis using parsed inheritance.
- `rta`: instantiated-class constrained approximation.

Later modes:

- Soot/SootUp or WALA pointer-analysis-backed call graph.

### Decompilation and Source Analysis

`java_decompile_class`

Inputs:

- `class_locator`
- `engine: "vineflower" | "cfr" | "auto"`
- `mapping_namespace`
- `timeout_seconds`

Outputs:

- Decompiled source.
- Engine metadata.
- Warnings/errors.
- Source line map if available.
- Evidence references to class and bytecode.

`java_decompile_method`

Inputs:

- `method_locator`
- `engine`
- `include_bytecode_context`

Outputs:

- Method source slice.
- Enclosing class context if needed.
- Bytecode BCI/source-line hints.

`java_parse_decompiled_source`

Initial Python/Java helper implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Uses JavaParser through the JVM helper.
- Reports package, imports, types, modifiers, annotations, fields, constructors,
  methods, parameters, thrown exceptions, and parse problems.

Inputs:

- `class_locator`
- `source`

Outputs:

- JavaParser AST summary.
- Imports.
- Method declarations.
- Field declarations.
- Comments if preserved.
- Parse errors.

Use decompiled source as a convenience layer, not the source of truth. If bytecode
and decompiler disagree, bytecode wins.

`java_decompile_archive`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_decompile_archive` KB nodes.
- Uses the JVM helper per class with CFR/Vineflower fallback scoring.
- Supports package filters, class glob filters, max-class budgets, per-class source
  truncation budgets, explicit inner-class `skip` or `$` companion emission policy,
  inner/anonymous/lambda grouping metadata, mapping-aware filters/metadata, optional
  mapped source-name rewriting, optional per-candidate `javac` scoring, optional
  `src/main/java` source emission, and optional source/bytecode correlation anchors.

Inputs:

- JAR path.
- Engine: `vineflower`, `cfr`, or `auto`.
- Optional mapping path/namespace.
- Output/cache directory.
- Include/exclude package filters.

Outputs:

- Per-class decompile status.
- Source root path.
- Warnings/errors by class.
- Decompiler version/options.
- Mapping namespace used.
- Cache key.

This is still not equivalent to source recovery. It only produces decompiler output.
The recovered application workflow below must decide how to organize, compile, repair,
and validate that output.

### Dependency, Build, and Source Recovery

The goal of this tool family is a clean, compilable source application, not just a
pile of `.java` files. It should mirror the native recovery discipline: lift/decompile,
compile, inspect failures, patch, and verify against original evidence.

`java_infer_dependencies`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_dependency` KB nodes.
- Combines manifest `Class-Path`, Maven `pom.properties`, nested JAR/ZIP path
  coordinates, and bytecode references to packages not defined in the archive.
- Normalizes JVM array descriptors before dependency grouping and collapses common
  Java/game libraries such as Guava, Gson, Netty, fastutil, JOML, LWJGL, OSHI,
  SLF4J, jopt-simple, ICU4J, Forge/Fabric/Mixin, and loader-provided Minecraft APIs.
- Does not download dependencies, execute archive code, or trust guessed coordinates
  as ground truth.

Inputs:

- JAR path.
- Optional classpath roots.
- Optional package ownership hints.
- `include_jdeps: bool`
- `java_home`
- `jdeps_timeout_seconds`
- `jdeps_multi_release`
- `include_maven_metadata: bool`

Outputs:

- Manifest `Class-Path` entries.
- Module `requires` entries.
- `META-INF/maven/**/pom.xml` and `pom.properties` dependencies.
- ServiceLoader providers/consumers.
- External package refs derived from constant-pool and bytecode refs.
- Optional `jdeps -verbose:package` package edges and resolved module/not-found
  status.
- Missing classes/packages after comparing archive contents and supplied classpath.
- Suggested Maven coordinates when metadata is available.
- Confidence per dependency source.

Implementation notes:

- Initial Python implementation uses bounded `jdeps -verbose:package` as optional
  evidence, records `jdeps_package` dependencies, preserves the target module name
  or `not found` state, and adds timeout/failure stop reasons.
- Use `jdeps` as optional evidence, not the only dependency source.
- Treat shaded dependencies carefully: classes present in the JAR should not become
  external dependencies just because their package normally belongs to a library.
- For Minecraft and mod loaders, dependency inference must account for loader-provided
  libraries, nested server bundles, mixins, access transformers, and remapped names.
- Continue by comparing inferred external packages against caller-supplied
  classpaths, parsing JPMS `module-info` dependencies, and turning compiler missing
  class diagnostics into dependency repair actions.

`java_reconstruct_source_tree`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_source_tree` KB nodes.
- Creates `src/main/java` and `src/main/resources` under caller-provided output
  roots. It does not choose an output path implicitly.
- Copies runtime resources according to a bounded resource policy, preserves
  manifest, ServiceLoader, Maven/framework metadata, and license/notice files, and
  skips signed-JAR signature files by default.
- Tracks classes requiring decompilation. Generated Java stubs are emitted only when
  `emit_stub_sources=True`, and those files are explicitly marked as generated
  stubs.
- Emits minimal recovered-project build files: `sources.txt`, `javac.args`,
  `pom.xml`, and `.glaurung/recovery.json`.
- Minecraft smoke tests showed the 1.20.1 server launcher has only four outer
  classes and a small metadata/resource layer including `META-INF/libraries.list`,
  while the 1.21.11 client immediately exposes shader include resources such as
  `projection.glsl`, `fog.glsl`, and `matrix.glsl`.

Inputs:

- JAR path.
- Decompile cache/source root.
- Mapping namespace/path.
- Output directory.
- Resource policy: `copy_all`, `copy_runtime`, or `none`.
- Include/exclude package filters.

Outputs:

- Source project root.
- Java source file list.
- Resource file list.
- Manifest/service/module files preserved.
- Classes that failed to decompile.
- Classes requiring stubs.
- Synthetic/bridge/anonymous-class handling notes.

Responsibilities:

- Place source under `src/main/java` using package declarations, not JAR entry names
  alone.
- Copy resources under `src/main/resources` while preserving paths.
- Preserve `META-INF/services/**`, module metadata, manifests, license notices, and
  framework metadata that can affect runtime behavior.
- Keep signed-JAR signature files out of rebuilt artifacts by default; signatures
  should be reported as invalidated rather than copied blindly.
- Emit stubs only with explicit marking and evidence when a class cannot be
  decompiled.
- Continue by wiring decompiler output into `src/main/java`, preserving module source
  metadata, and validating copied resources against the original archive.

`java_recover_project`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_recovery_project` KB nodes.
- Runs a bounded end-to-end recovery flow:
  `java_reconstruct_source_tree` -> `java_decompile_archive` ->
  JavaParser AST persistence -> `java_compile_recovered_project` ->
  optional `java_repair_decompiled_source` -> `java_validate_recovered_application`.
- Refreshes `sources.txt` and `javac.args` after archive decompilation so the
  compile step sees the emitted source files.
- Carries resource/build metadata, compile status, repair status, validation status,
  quality summaries, stop reasons, and warnings in one result object.
- Uses safe vendored fixture sources in tests and reserves Minecraft/mod JARs for
  ignored local smoke tests.

Inputs:

- Original JAR path.
- Output project root.
- Resource policy.
- Decompiler engine and budgets.
- Mapping path and mapped source rewrite toggle.
- Java release.
- Repair and validation toggles.

Outputs:

- Recovered source project root.
- Nested reconstruct/decompile/compile/repair/validation results.
- Generated source/resource/build counts.
- Parsed AST count.
- `clean_enough`/`not_clean_enough` quality summary.

Continue by making the orchestrator dependency-aware, classpath-aware for fallback
candidate compilation, module-aware, and resumable from cached intermediate results.

`java_infer_build_system`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_build_system` KB nodes.
- Selects `javac`, Maven, or Gradle from optional recovered source-root build files,
  embedded Maven `pom.xml`/`pom.properties`, Gradle plugin descriptors, Minecraft
  mod metadata, inferred dependencies, and classfile Java release.
- Generates build-control files only: `pom.xml`, `build.gradle`, `javac.args`, and
  `sources.txt` placeholders. It does not write source files, fetch dependencies,
  or execute archive code.
- Minecraft smoke tests show 1.20.1 client/server classfiles require Java 17
  (major 61), while the copied 1.21.11 client requires Java 21 (major 65).

Inputs:

- JAR path.
- Source project root.
- Dependency inference output.
- Preferred build tool: `auto`, `maven`, `gradle`, or `javac`.

Outputs:

- Selected build tool and rationale.
- Generated or recovered `pom.xml`, `build.gradle(.kts)`, or `javac` argfile.
- Source/target Java release.
- Module path/classpath.
- Local library paths.
- Annotation processor hints.
- Unsupported feature warnings.

Selection rules:

- Prefer recovering existing Maven/Gradle metadata when it is embedded and coherent.
- Prefer plain `javac` for single-JAR fixtures and tests where no dependency metadata
  exists.
- Use a local `libs/` directory for unresolved dependency JARs supplied by the user.
- Never fetch arbitrary dependencies during planning without an explicit network/cache
  policy.
- Continue by adding module-path inference, annotation processor detection,
  loader-specific Minecraft build plugin templates, and resolver/cache policy hooks.

`java_compile_recovered_project`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_compile_result` KB nodes.
- Supports bounded `javac` compilation for recovered `src/main/java` trees.
- Populates empty/missing `sources.txt`, expands nested javac argfiles, writes
  classes under `build/classes`, and reports stdout/stderr excerpts without running
  recovered application code.
- Parses initial javac diagnostics into categories such as missing classpath
  dependency, syntax/decompiler reconstruction error, duplicate class/package,
  visibility mismatch, generic/signature mismatch, and module/processor issues.
- Minecraft smoke tests used the inferred Java release from the copied jars and
  confirmed the local JDK can compile tiny recovered-style projects at Java 17 for
  Minecraft 1.20.1 client/server and Java 21 for the copied 1.21.11 client.

Inputs:

- Source project root.
- Build tool selection.
- Java home/release.
- Classpath/module path.
- `max_diagnostics`
- `timeout_seconds`

Outputs:

- Exit status.
- Compiler/build command.
- Structured diagnostics: file, line, column, error code/category, message, symbol,
  package/class/member when extractable.
- Generated classes directory.
- Rebuilt JAR path if packaging succeeded.
- Build logs path/cache key.

Diagnostic categories:

- Missing classpath dependency.
- Bad decompiler syntax.
- Missing import.
- Generic/signature mismatch.
- Enum/record/sealed reconstruction error.
- Lambda/anonymous class reconstruction error.
- Access/visibility mismatch.
- Duplicate class or package conflict.
- Annotation processor or module-path issue.

Implementation notes:

- Keep execution bounded and static: compile recovered source, but do not run the
  rebuilt application.
- Maven/Gradle execution exists with bounded subprocesses. Continue with richer
  Maven/Gradle diagnostics and resolver/cache policy.
- Feed diagnostics into `java_repair_decompiled_source`; prefer dependency/build
  fixes over source edits for missing package/class errors.

`java_repair_decompiled_source`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_repair_result` KB nodes.
- Runs a bounded `java_compile_recovered_project` loop and records every compile
  result plus every attempted repair.
- Applies safe mechanical repair classes:
  `rename_public_type_file`, `rewrite_inner_companion_declaration`,
  `add_missing_import`, and `add_local_classpath_jar`.
- Rewrites `sources.txt` and `javac.args` after applied repairs and recompiles to
  prove the fix.
- Supports dry-run mode, repair budgets, compile iteration budgets, and timeout
  propagation.

Inputs:

- Source project root.
- Structured diagnostics from `java_compile_recovered_project`.
- Bytecode/class evidence for affected classes.
- Repair budget.
- Allowed repair classes: imports, syntax, stubs, generics, visibility, build metadata.

Outputs:

- Patch list.
- Files changed.
- Diagnostics addressed.
- Diagnostics deferred.
- Confidence and evidence IDs.

Repair rules:

- Prefer build/classpath fixes over source edits when the error is a missing external
  dependency.
- Prefer bytecode evidence over decompiler output when reconstructing signatures,
  thrown exceptions, annotations, enum constants, records, or bridge methods.
- Mechanical source-layout fixes and local classpath additions may be applied
  automatically when compiler diagnostics and filesystem state make the repair
  unambiguous.
- Missing imports may be added automatically only when exactly one local source type
  matches the unresolved simple name.
- Mark stubs and semantic guesses explicitly.
- Do not simplify behavior merely to make compilation pass.
- Keep repairs narrow and re-run compilation after each batch.

`java_compare_rebuilt_abi`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_abi_comparison` KB nodes.
- Compares original and rebuilt JARs, class directories, or single `.class` files
  using the Rust class parser exposed through Python.
- Reports missing/extra classes, fields, and methods by descriptor, plus class/member
  access-flag differences. The `scope` option can compare every class/member,
  non-private package API, or public/protected API only. When `include_annotations`
  is enabled, it also reports missing, extra, and changed class/member annotations
  using descriptor, visibility, and redacted element fingerprints. It does not yet
  compare parameter annotations, annotation defaults, resources, module metadata, or
  byte-for-byte classfile equivalence.
- Minecraft smoke tests showed the 1.20.1 server wrapper self-comparing at four
  class ABI surfaces, the 1.20.1 client self-comparing at 7,436 class ABI surfaces,
  and the copied 1.21.11 client exposing 10,291 class ABI surfaces.

Inputs:

- Original JAR.
- Rebuilt classes directory or rebuilt JAR.
- Scope: `all`, `package_api`, or `public_api`.
- Include class/member annotations: bool.
- Include resources: bool, planned for richer validation only.

Outputs:

- Missing/extra classes.
- Missing/extra fields and methods by descriptor.
- Access flag differences.
- Annotation differences.
- Resource differences.
- Manifest/service/module differences.
- Compatibility score and blocking mismatches.

This is the Java equivalent of checking recovered C/C++ output against the binary
surface. The first goal is ABI/API compatibility, not byte-for-byte classfile
equivalence.

Continue by adding parameter annotation/default parity, module/service metadata
validation, richer resource policy, and compatibility scoring that weights public
breaks, package breaks, private implementation drift, and generated stubs.

`java_validate_recovered_application`

Initial Python implementation status:

- Implemented as a pydantic memory tool registered on the memory agent.
- Emits `java_recovery_validation` KB nodes.
- Runs bounded `javac` through `java_compile_recovered_project` when requested.
- Uses `java_compare_rebuilt_abi` against the generated classes directory or a
  caller-supplied rebuilt JAR/classes path for `abi` and `full_static` profiles.
  Callers can set `abi_scope` and can opt into class/member annotation parity with
  `include_annotations`.
- Compares original archive resources against recovered `src/main/resources`,
  skipping `.class` and signature metadata while reporting missing, extra, and
  changed resources with SHA-256 evidence.
- Separately reports manifest, ServiceLoader provider, and module-info metadata
  parity so runtime-affecting metadata drift is visible even when resource
  differences are noisy.
- Rejects `GLAURUNG GENERATED STUB` sources unless the caller explicitly allows
  generated stubs.
- Reports explicit pass/fail/skip checks, blocking issue counts,
  `clean_enough`/`not_clean_enough` quality summaries, and next-action hints.
- Current status values are `valid`, `invalid`, `partial`, and `unsupported`.

Remaining work:

- Add parameter annotation/default and richer module-info semantic comparison beyond
  the initial manifest, service, and module descriptor presence/content checks.
- Add compatibility scores and selected-scope policy such as public API only,
  package-visible API, or all implementation classes.
- Add richer Maven/Gradle build-log parsing and resolver/cache policy.
- Add optional runtime smoke validation behind strict execution gates.

Inputs:

- Original JAR.
- Source project root.
- Rebuilt JAR/classes.
- Validation profile: `compile_only`, `abi`, `resources`, `full_static`, later
  `smoke_runtime`.

Outputs:

- Compile status.
- ABI status.
- Resource/manifest preservation status.
- Optional isolated runtime smoke status.
- Final recovery score.
- Remaining risks.

Acceptance for a "clean" recovered source project:

- The project compiles without source stubs unless the caller explicitly permits
  marked stubs.
- Public/protected class, method, and field descriptors match the original for the
  selected scope.
- Resources needed by manifests, services, modules, and frameworks are preserved.
- Decompiler failures and repairs are documented as evidence nodes.
- The rebuilt artifact is written to a caller-provided or ignored output directory,
  never over the original JAR.

### Framework, Obfuscation, and Static Behavior Audit

This tool family is what should make questions like "which of these JARs do network
or filesystem things?" answerable inside the normal Rust/Python/agent flow. It must
be generic enough for Minecraft mods, desktop applications, server applications,
agents, command-line tools, and shaded libraries.

`java_detect_frameworks`

Inputs:

- JAR path or archive locator.
- `include_resources: bool`
- `include_nested_jars: bool`
- Optional package/resource filters.

Detect:

- Forge/NeoForge from `META-INF/mods.toml`.
- Fabric/Quilt from `fabric.mod.json` and `quilt.mod.json`.
- Sponge Mixin.
- Java agents (`Premain-Class`, `Agent-Class`).
- `Main-Class` applications.
- ServiceLoader providers.
- Maven coordinates from `META-INF/maven/**/pom.properties`.
- JPMS modules from `module-info.class`.
- OSGi bundles from manifest headers.
- Spring Boot from manifest headers and executable-JAR layout.
- Bukkit/Paper/Velocity-style plugin descriptors.
- Spring and other application frameworks.
- Logging frameworks and risky logging versions when metadata is available.
- JNI/JNA/FFM/native libraries.
- Serialization frameworks.
- Reflection-heavy libraries.
- Shaded dependency roots.

Outputs:

- Framework IDs, versions when extractable, confidence, and evidence locators.
- Entrypoint resource paths and class/method locators.
- Loader-provided dependency assumptions, especially for mod loaders.
- Initial implementation emits `java_framework` KB nodes for the generic metadata
  categories above; lifecycle method expansion remains future work.

`java_detect_obfuscation`

Inputs:

- JAR path or archive locator.
- Optional mapping path/namespace.
- Optional package filters.

Signals:

- High short-name density.
- Low dictionary-like class/member name density.
- Missing line/local variable tables.
- Heavy `invokedynamic` usage.
- Reflection/string construction.
- Encrypted, compressed, or base64-like string tables.
- Control-flow flattening patterns.
- Suspicious classloader usage.
- Invalid or adversarial classfile patterns.
- Decompiler disagreement across Vineflower/CFR.
- Mapping coverage and unmapped hot spots.

Outputs:

- Archive and package-level obfuscation scores.
- Per-class signals and evidence IDs.
- Mapping recommendations before decompilation or audit.

`java_detect_suspicious_blobs`

Inputs:

- JAR path or archive locator.
- `include_class_constants: bool`
- `include_methods: bool`
- `include_resources: bool`
- `include_benign_resource_like: bool = False`
- Class/resource/finding budgets.

Initial signals:

- Base64, URL-safe Base64, and hex-looking class string constants.
- Decoded constant magic for Java classfiles, ZIP/gzip/zlib blobs, and native
  ELF/PE/Mach-O payloads.
- Same-method decoder/deobfuscation APIs such as `Base64$Decoder.decode`,
  `HexFormat.parseHex`, `Inflater`, `GZIPInputStream`, `Cipher.doFinal`, and
  `SecretKeySpec`.
- Same-method sink correlation from decoder APIs into `ClassLoader#defineClass`,
  `MethodHandles.Lookup#defineClass`, `URLClassLoader`, `System.load`,
  `System.loadLibrary`, `ProcessBuilder`, `Runtime.exec`, socket/URL APIs, and
  selected file-write APIs.
- Archive/resource anomalies such as hidden classfile bytes under non-`.class`
  paths, nested compressed/archive blobs, native-looking resources, and
  high-entropy non-media resources.

Current output states:

- `benign_resource_like`
- `encoded_constant`
- `compressed_blob`
- `encrypted_or_random_blob`
- `decoder_nearby`
- `decoded_to_file`
- `decoded_to_classloader`
- `decoded_to_native_load`
- `decoded_to_process_or_network`

Implementation status:

- Initial Python memory tool exists and emits `java_suspicious_blob` KB nodes with
  raw values redacted by default.
- Named `.jar`, `.zip`, and `.gz` resources are treated as benign resource-like by
  default to keep standard dependency bundling from drowning out hidden or
  misleadingly named blobs. Callers can enable benign-resource output when they
  need dependency packaging evidence.
- The first implementation is deliberately method-local. Interprocedural taint
  from encoded constants/resources through helper methods into loaders, native
  calls, filesystem writes, processes, or network sinks remains future work.
- It should be integrated into `java_risk_report` and archive-set rollups after
  calibration against large real-world JARs to avoid language/resource false
  positives.

`java_verify_signatures`

Inputs:

- JAR path or archive locator.
- `timeout_seconds`
- `max_output_chars`

Signals:

- Signature metadata entries under `META-INF/*.SF`, `*.RSA`, `*.DSA`, and `*.EC`.
- `jarsigner -verify -certs -verbose` exit state and bounded output.
- Signed and unsigned entry counts from verifier output.
- Verification warnings such as self-signed, untrusted, expired, or untimestamped
  certificate chains.
- Invalid, unsigned, missing-tool, timeout, and non-ZIP states.

Outputs:

- `verified`, `verified_with_warnings`, `unsigned`, `invalid`, `tool_missing`,
  `timeout`, `not_zip`, or `error`.
- Signature metadata summaries, warning/error summaries, signed/unsigned entry
  counts, bounded output excerpts, and KB evidence nodes.
- Raw values are not sensitive here, but verifier output remains bounded so very
  large archives cannot flood agent context.

Implementation status:

- Initial Python memory tool exists and uses local JDK `jarsigner` when present.
- Tests generate a tiny signed fixture with `keytool`/`jarsigner` and an unsigned
  fixture at test time; no signed third-party JAR is vendored for the test.
- Minecraft smoke tests show why this is separate from metadata indexing: the client
  JAR can be signed by Mojang while the server launcher/bundler is unsigned but
  contains many nested payloads.
- Future work: parse certificate owner/issuer/timestamp summaries into structured
  fields, add policy modes, and roll signature state into archive-set and risk
  reports.

`java_detect_entrypoints`

Inputs:

- JAR path or archive locator.
- Framework detection output, optional.
- Mapping namespace/path, optional.
- `include_schedulers: bool`
- `include_service_loader: bool`

Entrypoint categories:

- `public static void main(String[])`.
- Manifest `Main-Class`.
- Java agent `premain` and `agentmain`.
- ServiceLoader providers.
- Servlet, Spring, Micronaut, Quarkus, and similar framework lifecycle hooks.
- Forge/NeoForge/Fabric/Quilt mod entrypoints and event subscribers.
- Sponge Mixin targets and injection handlers.
- Scheduled executors, timers, thread starts, callbacks, and listener registrations.
- Static initializers with non-trivial side effects.

Outputs:

- `java_entrypoint` nodes with class, method, descriptor, category, framework,
  confidence, evidence IDs, and mapped names when available.
- Edges from entrypoints to reachable methods when a cheap call graph is available.

`java_detect_security_sensitive_behavior`

Inputs:

- JAR path or archive locator.
- `ruleset: "default" | "strict" | "network" | "filesystem" | "credentials" | path`
- `include_config_correlation: bool`
- `include_entrypoint_context: bool`
- `include_nested_jars: bool`
- `severity_threshold`
- `max_findings`
- Optional package/class filters.
- Optional mapping path/namespace.

Rule taxonomy:

- Process execution:
  - `java.lang.Runtime.exec`
  - `java.lang.ProcessBuilder`
  - shell command builders
- Filesystem:
  - reads, writes, deletes, recursive walking, temp-file creation, path traversal
  - NIO watch services and permission changes
- Networking:
  - `java.net.Socket`, `ServerSocket`, `DatagramSocket`
  - `HttpURLConnection`, `java.net.http.HttpClient`, WebSocket APIs
  - common HTTP clients when dependency metadata or call targets are available
  - DNS lookups and proxy configuration
- Local servers and IPC:
  - embedded HTTP servers, Netty servers, RMI, JMX, Unix/domain sockets when visible
- Native and unsafe:
  - `System.load`, `System.loadLibrary`
  - JNI/JNA/FFM symbols
  - `sun.misc.Unsafe`, `jdk.internal.misc.Unsafe`
- Reflection and class loading:
  - `setAccessible(true)`, `MethodHandle` lookups, `Class.forName`
  - custom `ClassLoader`, `defineClass`, instrumentation transforms
- Serialization and deserialization:
  - `ObjectInputStream`, XML decoders, YAML/XML/JSON polymorphic deserializers
  - gadget-prone framework entrypoints when dependencies are known
- Scripting and expression engines:
  - JSR-223, Java compiler API, Janino, MVEL, OGNL, SpEL
- Crypto and credentials:
  - keystore reads, password/token constants, OAuth/API token patterns
  - weak crypto modes and custom trust managers
- Persistence and exfiltration helpers:
  - clipboard, desktop/browser launch, system properties, environment variables
  - scheduled background jobs and thread pools

Outputs:

- `java_sensitive_sink` and `java_risk_finding` nodes.
- For each finding:
  - finding ID and stable `sink://` locator
  - rule ID, category, severity, confidence, and rationale
  - class, method, descriptor, BCI, source line if available
  - matched owner/name/descriptor or resource path
  - constants and config keys involved, redacted when needed
  - mapped class/member names when mappings are available
  - entrypoint and reachability state: `unknown`, `direct_entrypoint`, `reachable`,
    `library_only`, or `dead_code_candidate`
  - config state: `not_checked`, `no_config`, `configured_enabled`,
    `configured_disabled`, `configured_value_unknown`, or `default_only`
  - evidence IDs for bytecode, xref, config, resource, decompiler, and mapping data

Rule pack implementation:

- Store initial rules as versioned Python data files so they can be tested without a
  Java helper rebuild.
- Each rule should declare sink owner/name/descriptor patterns, category, default
  severity, confidence base, summary text, safe examples, and false-positive notes.
- Support framework-specific context rules that lower or raise severity. For example,
  a mod loader may legitimately open files in its config directory, while process
  execution from a client-side mod remains high-risk.
- Rules should operate on normalized xrefs and constants rather than source text
  wherever possible.

`java_extract_config_surface`

Inputs:

- JAR path or archive locator.
- `config_roots: list[path]` for caller-supplied external config directories.
- `include_embedded_resources: bool`
- `include_manifests: bool`
- `include_service_descriptors: bool`
- `include_framework_metadata: bool`
- `max_config_files`
- `max_value_chars`

Supported formats:

- Java properties.
- TOML.
- JSON and JSON5 where supported by an optional parser.
- YAML.
- XML.
- INI-like simple key/value files.
- Manifests, module metadata, ServiceLoader descriptors, Forge/Fabric metadata,
  mixin configs, access wideners/transformers, and embedded defaults.

Outputs:

- `java_config_key` nodes with path, key, value kind, redacted value hash, source
  type, parser, line/column when available, and evidence IDs.
- Framework metadata summaries.
- Environment variable names and system property names referenced by code.
- Constants that look like config keys but were not found in supplied config roots.

Redaction policy:

- Store raw boolean, enum-like, numeric, and low-risk short values when safe.
- Redact likely tokens, session IDs, credentials, private keys, URLs containing user
  info, and high-entropy values.
- Emit a stable hash plus length/category for redacted values.

`java_trace_to_sink`

Inputs:

- Sink locator or finding ID.
- JAR path/archive locator if not embedded in the sink locator.
- `direction: "backward" | "forward" | "both"`
- `max_depth`
- `include_callers: bool`
- `include_config: bool`
- `include_constants: bool`
- `include_decompiled_source: bool`
- Optional mapping path/namespace.

Outputs:

- Bounded trace graph with method nodes, CFG blocks, BCI ranges, call edges, field
  reads/writes, constants, config keys, environment/system property reads, string
  concat sites, and entrypoints.
- Reasons where tracing stopped: budget, unresolved virtual call, reflection,
  native method, missing dependency, decompiler failure, or obfuscation.
- Confidence per edge.

`java_reachability`

Inputs:

- JAR path/archive locator.
- Optional mapping path/namespace.
- Target owner, method name, and optional descriptor.
- Optional target source class, source method, source descriptor, and BCI for exact
  call-site reachability.
- Optional entrypoint category filters.
- `max_depth`, `max_edges`, `max_entrypoints`, and `max_paths`.

Outputs:

- Bounded call-graph paths from detected entrypoint methods to the requested target,
  optionally narrowed to one source call site.
- Edge evidence with source method, target method, invoke kind, BCI, and source-line
  anchors where available.
- Target match counts and stop reasons for truncated call graphs, truncated
  entrypoints, missing target input, or no reached target.
- Initial implementation uses constant-pool call graph edges only; CHA/RTA dispatch,
  config/dataflow argument slicing, and framework lifecycle expansion remain future
  work.

`java_correlate_behavior_config`

Inputs:

- Sensitive findings from `java_detect_security_sensitive_behavior`.
- Config surface output.
- Optional framework detection output.
- Optional user policy such as allowed domains, allowed directories, or expected
  framework behaviors.

Outputs:

- Finding state updates:
  - `capability_only`
  - `reachable_unconfigured`
  - `configured_enabled`
  - `configured_disabled`
  - `configured_unknown`
  - `observed_dynamic` when a runtime trace later confirms it
- Config keys and paths that influence the behavior.
- Explanatory evidence suitable for agent answers.

`java_detect_secrets`

Inputs:

- JAR path/archive locator.
- `include_resources: bool`
- `include_strings: bool`
- `include_config: bool`
- `max_candidates`
- `allow_raw_values: bool = False`

Outputs:

- Secret candidates with type, source, context, length, entropy band, redacted hash,
  severity, confidence, and evidence IDs.
- No raw secret values unless an explicit local-only debugging flag permits it.

Implementation notes:

- Combine regex/context rules, entropy checks, known token prefixes, certificate/key
  structure checks, and optional `detect-secrets` plugins.
- Treat false positives conservatively. Mark constants like public URLs or UUID-like
  identifiers as low confidence unless context indicates credentials.

`java_risk_report`

Inputs:

- `path`
- `config_roots`
- `mapping_path`
- `max_classes`
- `max_findings`
- `max_risk_items`
- `max_secret_candidates`
- `include_secrets`
- `include_entrypoints`
- `include_reachability`
- `max_reachability_targets`
- `max_reachability_depth`
- `max_reachability_edges`
- `max_reachability_paths`
- `max_reachability_entrypoints`

Outputs:

- Archive-level report with ranked risk items.
- Sensitive finding count, config correlation count, config binding count, redacted
  secret candidate count, entrypoint count, and reachability analysis count.
- Summary counts by category, config state, and reachability state.
- Per-risk reachability state: `not_analyzed`, `unknown`, `direct_entrypoint`,
  `reachable`, `library_only`, or `dead_code_candidate`.
- Dynamic observation state placeholder, currently `not_analyzed` until runtime
  observation tooling is implemented.
- Highest severity and max risk score.
- Evidence IDs and locators for every claim.
- A clear distinction between "this code can do X" and "this JAR is configured or
  observed to do X"; reachability is computed against the exact sensitive call site
  when source method and BCI evidence are available.
- `java_risk_finding` KB nodes for each ranked item.

Current limitations:

- The implementation ranks a single archive and uses config state plus bounded
  constant-pool reachability as context. Framework lifecycle hooks, policy files,
  dynamic observation, deeper source-to-sink slicing, and multi-archive rollups are
  planned follow-on work.

`java_audit_archive_set`

Inputs:

- Directory path or explicit JAR list.
- Include/exclude glob patterns.
- `include_nested_jars: bool`
- Optional shared config roots.
- Optional policy file.
- Per-archive and total budgets.

Outputs:

- One `java_risk_report` summary per archive.
- Cross-archive ranking by severity and confidence.
- Shared endpoint/config/secret candidates deduplicated by redacted hash or locator.
- Archive identity: path, SHA-256, manifest name/version, framework/mod metadata.

Use this for modpack/application directories. It should be generic; Minecraft-specific
labels can be extra annotations, not the core data model.

### Minecraft-Specific Tools

`minecraft_detect_archive`

Inputs:

- JAR path.

Outputs:

- Minecraft version hints.
- Client/server side.
- Loader: vanilla, Forge, NeoForge, Fabric, Quilt.
- Mod metadata.
- Mixin configs.
- Access wideners/transformers.
- Mappings namespace hints.

`minecraft_fetch_mappings`

Inputs:

- `version`
- `side: "client" | "server"`
- `source: "mojang" | "yarn" | "intermediary" | "auto"`

Outputs:

- Mapping file path/cache key.
- Mapping format.
- Class/method/field counts.
- SHA-256.

For Mojang official mappings, use the version manifest and per-version metadata.
Do not guess URLs.

`minecraft_apply_mappings`

Inputs:

- JAR path.
- Mapping path.
- Source namespace.
- Target namespace.

Outputs:

- Remapped JAR path.
- Remap stats.
- Unmapped classes/members.

Use Tiny Remapper for Tiny mappings and either a small parser or existing tooling for
ProGuard-style Mojang mappings.

`mixin_index_targets`

Inputs:

- JAR path.
- Mapping namespace.

Outputs:

- Mixin config files.
- Target classes.
- Inject/redirect/overwrite methods.
- BCI/source target hints where resolvable.

`minecraft_compare_client_server`

Inputs:

- Client JAR.
- Server JAR.
- Version.
- Mapping namespace.

Outputs:

- Shared classes.
- Side-only classes.
- Shared method differences.
- Resource differences.
- Protocol/package hotspots.

### Runtime and Debugging Tools

Dynamic tools must be opt-in and budgeted.

`java_launch_target`

Inputs:

- `jar`
- `classpath`
- `main_class`
- `args`
- `jvm_args`
- `working_dir`
- `timeout_seconds`

Outputs:

- PID.
- Command line.
- stdout/stderr path.
- exit status if completed.

Safety:

- Disabled unless `allow_expensive` or a more specific `allow_java_execute` flag is
  true.
- Default to no network assumptions. If sandboxing is added later, use it here.
- Redact obvious tokens from logs.

`java_jcmd`

Inputs:

- `pid`
- `command`

Supported initial commands:

- `VM.command_line`
- `VM.version`
- `VM.classloaders`
- `VM.classloader_stats`
- `Thread.print`
- `JFR.start`
- `JFR.dump`
- `JFR.stop`

`java_jfr_summary`

Inputs:

- `.jfr` path.

Outputs:

- Event counts.
- Hot methods.
- Exceptions.
- Allocation hotspots.
- Thread activity.

`java_jdi_debug`

Initial capabilities:

- Launch with JDWP.
- Attach to JDWP.
- Set breakpoint at method entry or BCI.
- Step bytecode/source line when available.
- Read stack frames, locals, and object summaries.
- Record exception events.

Use JDI rather than hand-writing JDWP packets for the first version.

`java_trace_methods`

Implement with a Byte Buddy/ASM Java agent.

Inputs:

- Target class/method filters.
- Include args/return summaries.
- Include exceptions.
- Duration threshold.

Outputs:

- Runtime call events with method locators.
- Thread ID/name.
- Start/end timestamps.
- Duration.
- Exception type.
- Optional argument/return type summaries.

Avoid logging full object contents by default.

### Patching and Verification

`java_patch_class`

Inputs:

- Class locator.
- Transform spec.
- Output JAR path.

Transform types:

- Rename class/member.
- Replace method body with generated bytecode.
- Insert logging probe.
- Toggle conditional branch.
- Replace constant.

`java_verify_class`

Inputs:

- Class bytes or path.
- Target Java version.

Outputs:

- Classfile parse status.
- ASM CheckClassAdapter output.
- Optional JVM load test in isolated process.

`java_verify_runtime`

Inputs:

- Original JAR.
- Patched JAR.
- Launch args.
- Input scenario.

Outputs:

- Exit codes.
- stdout/stderr diff.
- Runtime exceptions.
- Optional JFR or trace diff.

Patching should not be considered complete unless verification passes or the failure
is documented.

## Pydantic-AI Integration

### Tool Registration

All new Java tools should implement `MemoryTool[Args, Result]` and use
`tool_to_pyd_ai()`.

Do this:

```python
from glaurung.llm.tools.base import tool_to_pyd_ai
from glaurung.llm.tools.java_index_archive import build_tool as build_java_index_archive

agent.toolset_or_tool_registration(... tool_to_pyd_ai(build_java_index_archive()) ...)
```

Avoid adding more hand-written wrappers that call `tool.run()` directly unless the
wrapper also records `_tool_calls` and evidence consistently.

### Tool Discovery and Size Control

Java support will add many tools. To keep agent prompts manageable:

- Put Java tools in a Java-specific toolset.
- Expose only first-touch tools by default:
  - `java_index_archive`
  - `java_list_packages`
  - `java_list_classes`
  - `java_list_fields`
  - `java_list_methods`
  - `java_list_annotations`
  - `java_view_class`
  - `java_decompile_method`
  - `java_xrefs_to`
  - `java_xrefs_from`
- Defer advanced tools:
  - `java_call_graph`
  - `java_reachability`
  - `java_decompile_archive`
  - `java_reconstruct_source_tree`
  - `java_compile_recovered_project`
  - `java_repair_decompiled_source`
  - `java_compare_rebuilt_abi`
  - `java_validate_recovered_application`
  - `java_detect_entrypoints`
  - `java_detect_security_sensitive_behavior`
  - `java_extract_config_surface`
  - `java_trace_to_sink`
  - `java_reachability`
  - `java_risk_report`
  - `java_audit_archive_set`
  - `java_jdi_debug`
  - `java_trace_methods`
  - `java_patch_class`
  - `minecraft_apply_mappings`
- For security or behavior-audit questions, expose the audit subset instead of the
  decompiler/source-recovery subset:
  - `java_index_archive`
  - `java_detect_frameworks`
  - `java_detect_obfuscation`
  - `java_detect_entrypoints`
  - `java_detect_security_sensitive_behavior`
  - `java_extract_config_surface`
  - `java_trace_to_sink`
  - `java_risk_report`
  - `java_audit_archive_set`
- Use pydantic-ai tool metadata/tags for filtering once the agent registration is
  refactored.

### Context Budgets

Extend `Budgets` or add a JVM-specific budget model:

```python
class JavaBudgets(BaseModel):
    max_classes: int = 20_000
    max_methods: int = 200_000
    max_resources: int = 10_000
    max_source_files: int = 20_000
    max_decompile_chars: int = 200_000
    max_bytecode_instructions: int = 50_000
    max_call_graph_nodes: int = 10_000
    max_call_graph_edges: int = 50_000
    max_compile_diagnostics: int = 500
    max_compile_repair_iterations: int = 5
    max_sensitive_findings: int = 500
    max_secret_candidates: int = 200
    max_config_files: int = 2_000
    max_config_value_chars: int = 512
    max_trace_depth: int = 8
    max_archive_set_jars: int = 2_000
    max_decoded_string_bytes: int = 2_000_000
    helper_timeout_seconds: float = 30.0
    compile_timeout_seconds: float = 120.0
    dynamic_timeout_seconds: float = 10.0
```

Add flags:

```python
allow_java_execute: bool = False
allow_java_attach: bool = False
allow_java_patch: bool = False
allow_java_dependency_network: bool = False
allow_java_source_repair: bool = False
allow_java_runtime_smoke: bool = False
allow_java_raw_secret_output: bool = False
allow_java_string_deobfuscation: bool = True
allow_java_archive_set_scan: bool = True
```

Do not use `allow_expensive` alone for operations that execute target code. Dynamic
execution and attach deserve separate gates.

Raw secret output should remain false for normal agent runs. The default audit path
may report redacted hashes, value categories, and context, but not credential values.

### Agent Prompts

Add JVM-specific guidance to the memory/foundation prompt:

- For JARs and classfiles, start with `java_index_archive`, not native
  `list_functions`.
- Treat decompiled Java as a hypothesis. Verify key behavior with bytecode/xrefs.
- Cite methods by class, name, descriptor, and BCI when possible.
- If names are obfuscated, ask for mappings or use mapping tools before broad
  semantic claims.
- Do not call decompiled Java a recovered application until source files are emitted,
  dependencies are inferred, compilation succeeds, and ABI/resource validation has
  been run.
- When compilation fails, inspect structured diagnostics first. Fix classpath/build
  metadata before editing decompiled source.
- For Minecraft, detect loader and mappings before explaining gameplay behavior.
- For Java security/audit questions, start with index, framework detection,
  entrypoints, sensitive behavior detection, config extraction, and then trace only
  the highest-value findings.
- Separate capability, reachability, configured state, and dynamic observation in
  every audit answer.
- Never label a behavior malicious solely because it uses networking, files, crypto,
  reflection, or class loading. Use rule severity, framework context, config state,
  and evidence.
- Never print raw secrets or session tokens. Cite redacted hashes and locations.
- Do not launch or attach to Java processes unless the user asked for dynamic
  analysis and the context allows it.

### Enrichment Workflow

For each interesting Java method, produce structured LLM enrichment:

```python
class JavaMethodInsight(BaseModel):
    method_locator: str
    short_name: str | None
    purpose: str
    inputs: list[str]
    outputs: list[str]
    state_reads: list[str]
    state_writes: list[str]
    calls: list[str]
    exceptions: list[str]
    side_effects: list[str]
    security_relevance: list[str]
    minecraft_relevance: list[str]
    confidence: float
    evidence_ids: list[str]
```

Store these as KB notes or typed annotations connected to `java_method` nodes.

For audit workflows, use a separate finding model so the agent can rank and explain
behavior without flattening everything into prose:

```python
class JavaRiskFinding(BaseModel):
    finding_id: str
    archive_sha256: str
    title: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    sink_locator: str | None
    method_locator: str | None
    mapped_symbol: str | None
    reachability_state: str
    config_state: str
    config_keys: list[str]
    redacted_value_hashes: list[str]
    summary: str
    false_positive_notes: list[str]
    next_tools: list[str]
    evidence_ids: list[str]
```

## CLI Integration

Add a `glaurung java` command group:

```bash
glaurung java index target.jar --format json
glaurung java class target.jar net/minecraft/client/Minecraft --format json
glaurung java methods target.jar --class net/minecraft/client/Minecraft
glaurung java bytecode target.jar --method 'net/minecraft/client/Minecraft#tick()V'
glaurung java decompile target.jar --class net/minecraft/client/Minecraft
glaurung java decompile-archive target.jar --out tmp/recovered/decompiled
glaurung java recover-source target.jar --out tmp/recovered/project --build-tool auto
glaurung java compile-project tmp/recovered/project
glaurung java compare-abi target.jar tmp/recovered/project/build/libs/recovered.jar
glaurung java xrefs target.jar --to 'net/minecraft/client/Minecraft#tick()V'
glaurung java minecraft-info target.jar
glaurung java frameworks target.jar --format json
glaurung java entrypoints target.jar --format json
glaurung java sensitive target.jar --rules default --format json
glaurung java config-surface target.jar --config-root config/ --format json
glaurung java trace-sink target.jar --sink sink://sha256:.../rule/... --format json
glaurung java risk-report target.jar --config-root config/ --format markdown
glaurung java audit-dir mods/ --config-root config/ --format json
```

Keep `glaurung classfile` as a compatibility command, but make it call the same
backend as `glaurung java class`.

Update `glaurung ask`:

- If triage detects `.jar`, `.war`, `.ear`, `.class`, or MIME `application/java-archive`,
  seed the KB with `java_index_archive`.
- Do not call native function analysis on JARs unless the JAR contains native
  libraries and the question asks for them.

## Build and Test Workflow

Follow the repository's required workflow:

```bash
uv sync
maturin develop
cargo test java
uv run pytest python/tests/test_java_*.py -xvs
uvx ruff check python/
uvx ty check python/
```

When the Java helper exists:

```bash
cd java/glaurung-jvm-tools
mvn -q test package
```

End-to-end smoke commands:

```bash
uv run glaurung java index tmp/minecraft-jars/w1-client/minecraft-client-1.20.1.jar --format json
uv run glaurung java class tmp/minecraft-jars/w1-client/minecraft-client-1.20.1.jar <class> --format json
uv run glaurung java decompile tmp/minecraft-jars/w1-client/minecraft-client-1.20.1.jar --class <class>
uv run glaurung java recover-source samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar --out tmp/java-recovery/helloworld
uv run glaurung java compile-project tmp/java-recovery/helloworld
uv run glaurung java sensitive tmp/minecraft-jars/w1-client/minecraft-client-1.20.1.jar --rules network
uv run glaurung java audit-dir /home/mjbommar/minecraft/modded/bmc4 --config-root /home/mjbommar/minecraft/modded/bmc4/config
```

Tests should use real data:

- Small Java fixtures generated by `javac` in test setup when a full JDK exists.
- Small source-recovery fixtures that compile with plain `javac`.
- Fixture JARs with resources, service descriptors, inner classes, enums, records,
  lambdas, and checked exceptions.
- Fixture JARs for static audit:
  - process execution references that are never executed by the test
  - filesystem write/delete/read references
  - HTTP client, socket, and local server references
  - reflection and custom classloader references
  - serialization/deserialization references
  - scheduled executor and timer callbacks
  - config-driven enabled/disabled branches
  - environment and system property reads
  - token-looking constants and resources that must be redacted
- Checked-in minimal `.class` byte arrays only when licensing and provenance are clear.
- Minecraft JAR tests gated behind `tmp/minecraft-jars` availability.
- No mocked parser outputs.

## Phased Implementation Plan

### Phase 0: Environment and Baseline

Goals:

- Confirm a full JDK is installed.
- Keep copied Minecraft JARs in `tmp/`.
- Add a fixture manifest for local-only integration tests.

Tasks:

- Install or expose full JDK tools: `javap`, `jdeps`, `jar`, `jcmd`, `jfr`.
- Add `python/tests/test_java_minecraft_fixtures.py` that skips if
  `tmp/minecraft-jars` is absent.
- Assert SHA-256 metadata and class counts for copied JARs.
- Document how to refresh the local corpus without committing JARs.

Acceptance:

- `java -version`, `javap -version`, `jdeps --version`, `jar --version`, and `jcmd -h`
  work.
- Minecraft fixture tests either pass or skip cleanly.

### Phase 1: Native Class and JAR Model

Goals:

- Stop writing JAR entries to `/tmp` just to parse classes.
- Parse method `Code` attributes and essential JVM metadata.

Tasks:

- Add Rust bytes binding: `parse_java_class_bytes`.
- Add Rust JAR indexer binding: `java_index_jar_path`.
- Parse `Code`, exception table, line table, local variables, annotations, bootstrap
  methods, module info, records, nestmates, sealed classes.
- Return structured JSON-compatible objects.
- Update `glaurung classfile` to use bytes/native JAR index path.

Acceptance:

- `cargo test java_class` passes on real/generated fixtures.
- `uv run pytest python/tests/test_classfile.py`.
- `glaurung classfile <minecraft-client.jar>` can summarize without temp class files.

### Phase 2: Java Helper MVP

Goals:

- Add ASM-powered bytecode listing, CFG, xrefs, and decompiler wrappers.

Tasks:

- Create `java/glaurung-jvm-tools`.
- Add Gradle build with ASM, Vineflower, CFR, Jackson.
- Implement JSON commands:
  - `index`
  - `bytecode`
  - `cfg`
  - `xrefs`
  - `decompile`
- Add tests using generated Java classes and a small JAR.
- Add Python wrapper in `python/glaurung/java/helper.py`.

Acceptance:

- `./gradlew test` passes.
- Helper returns stable JSON for a generated fixture and Minecraft sample class.
- Python wrapper enforces timeout and no-shell execution.

### Phase 3: LLM Tool Surface

Goals:

- Make JVM analysis available to pydantic-ai with evidence logging.

Tasks:

- Add Java `MemoryTool` modules.
- Register via `tool_to_pyd_ai`.
- Extend KB import with Java nodes/edges.
- Add `java_index_archive` seeding in `glaurung ask`.
- Add tool tests for schemas, evidence log entries, and budget truncation.

Acceptance:

- Agent can answer "what classes/methods are in this JAR?" using Java tools.
- Tool calls appear in `_tool_calls` and persistent evidence logs.
- No native disassembly/function tools are used for plain JARs during first-touch
  ask seeding.
- Initial method-level bytecode xrefs expose invoke, field, class, and loaded-string
  evidence to Python tools.
- Initial `java_view_bytecode` exposes selected method instructions with BCI,
  mnemonic, operands, line anchors, xrefs, bounded windows, and mapping context.

### Phase 3.5: Sensitive Behavior, Config, and Deobfuscation-Aware Annotation

Goals:

- Make static audit questions work without bespoke shell searches.
- Annotate deobfuscated or mapped Java facts with sensitive behavior findings.
- Distinguish capability, reachability, configured state, and dynamic observation.

Tasks:

- Expand the initial versioned sensitive API rule packs and unit tests for rule
  matching.
- Implement `java_detect_frameworks` output as reusable context for audit tools.
  Initial metadata detection exists for manifests, ServiceLoader, Maven, JPMS, OSGi,
  Spring Boot, Forge/NeoForge/Fabric/Quilt, and common plugin descriptors.
- Extend `java_detect_entrypoints` for common frameworks, mod loaders, thread starts,
  and richer lifecycle metadata. The initial version detects manifest main classes,
  Java agents, `public static main`, ServiceLoader providers, static initializers, and
  scheduler registrations; it also promotes Forge/NeoForge `@Mod` constructors and
  Forge/NeoForge event subscriber methods from annotation metadata into entrypoints.
- Extend `java_detect_security_sensitive_behavior` over normalized xrefs and bytecode
  operands. The initial version detects process, filesystem, network, reflection,
  classloading, native loading, serialization, crypto, scheduler, and environment
  sinks with class/method/descriptor/BCI evidence.
- Extend `java_extract_config_surface` for embedded resources and external config
  roots. The initial version parses manifests, ServiceLoader descriptors, properties,
  JSON, TOML, XML, and redacts sensitive config values.
- Implement `java_detect_secrets` with redaction and stable hashes.
- Implement `java_trace_to_sink` for bounded source-to-sink evidence.
- Implement `java_reachability` for bounded entrypoint-to-target call graph paths.
  Initial constant-pool call graph reachability exists, including exact source
  call-site filters for risk-report evidence; framework lifecycle expansion and
  source-to-sink argument slicing remain future work.
- Implement `java_correlate_behavior_config`.
- Implement `java_risk_report` and `java_audit_archive_set`. Initial versions exist:
  `java_risk_report` ranks sensitive behavior/config correlations plus redacted
  secrets, exact call-site reachability states, and entrypoint counts for a single
  archive; `java_audit_archive_set` summarizes sensitive categories across archive
  sets.
- Connect findings to KB nodes and agent evidence logs through `tool_to_pyd_ai`.
- Add deobfuscation-aware annotations so mapped names appear in findings when
  mappings are available.

Safe fixture requirements:

- Generate fixture JARs from source during tests when a JDK exists.
- Keep fixture code inert: tests inspect bytecode references but do not execute
  process, network, filesystem mutation, or local server behavior.
- Include config files that mark the same behavior enabled, disabled, and absent.
- Include token-looking constants/resources and assert redaction.
- Include obfuscated/mapped test classes so audit findings preserve both original
  and mapped names.

Acceptance:

- A generated fixture containing `ProcessBuilder`, HTTP client, filesystem delete,
  reflection, custom classloader, scheduled executor, and secret-looking constants
  produces categorized findings with class, method, descriptor, BCI, rule ID,
  severity, confidence, and evidence IDs.
- Config correlation reports `configured_enabled`, `configured_disabled`, and
  `capability_only` correctly on safe fixtures.
- Secret findings never expose raw values by default.
- Archive-set audit ranks multiple fixture JARs and deduplicates repeated endpoint
  or secret candidates.
- On Minecraft client/server or mod JARs in ignored `tmp/`, smoke tests can show at
  least one interesting static finding with mapped names when mappings are available,
  while skipping cleanly if the local corpus is absent.

### Phase 4: Decompiler and Source Enrichment

Goals:

- Let the agent reason over decompiled Java while staying grounded in bytecode.

Tasks:

- Implement `java_decompile_class`.
- Implement `java_decompile_method`.
- Add JavaParser AST summary command.
- Add method source slicing.
- Add source/bytecode correlation where line tables exist.
- Add `JavaMethodInsight` enrichment.

Acceptance:

- For a generated fixture, decompiled method source maps back to method locator.
- For Minecraft sample classes, decompiler failures are captured as structured
  warnings, not tool crashes.
- Agent cites both decompiled source and bytecode/xrefs for non-trivial claims.

### Phase 5: Compilable Source Recovery

Goals:

- Recover a clean source project from a JAR when the user asks for source, not just
  decompiled snippets.
- Build an agentic compile-repair loop analogous to native decompile/verify flows.

Tasks:

- Continue `java_decompile_archive` beyond the implemented bounded archive slices
  with richer cache keys, archive-wide scheduling, and method-level source slicing.
- Extend `java_infer_dependencies` with supplied-classpath comparison, module
  `requires`, optional `jdeps` evidence, and missing-class diagnostics.
- Extend `java_reconstruct_source_tree` beyond the implemented opt-in top-level
  decompiler source emission with module source recovery, source remapping, and
  richer resource validation.
- Extend `java_infer_build_system` with module paths, annotation processors,
  loader-specific Minecraft plugin templates, and resolver/cache policy.
- Extend `java_compile_recovered_project` beyond the implemented Maven/Gradle
  execution with richer structured diagnostics, resolver/cache policy, and build-log
  cache keys.
- Extend the implemented `java_repair_decompiled_source` beyond filename, companion
  inner declaration, and local classpath repair with narrow, evidence-grounded
  patches for syntax, signatures, imports, dependency/build metadata,
  enum/record/sealed reconstruction, and module issues.
- Extend `java_compare_rebuilt_abi` with parameter annotation/default validation,
  module validation, and public-vs-private compatibility scoring.
- Extend `java_validate_recovered_application` beyond the implemented quality
  summary and next-action report with manifest/service/module semantic validation,
  compatibility scoring, and optional runtime smoke profiles.
- Add fixtures for:
  - single-class application
  - resources and `META-INF/services`
  - inner/anonymous classes
  - enum and record classes
  - lambdas and `invokedynamic`
  - generic signatures and checked exceptions
  - small multi-jar classpath

Acceptance:

- A generated single-JAR application recovers into a source tree that compiles with
  plain `javac`.
- A generated Maven-style fixture recovers into a project whose `pom.xml` or generated
  javac argfile includes the required dependencies.
- Compiler diagnostics are structured and tied to source files plus original class
  evidence.
- The initial repair loop can fix public-type filename recovery failures, companion
  inner declaration failures, and local classpath failures; next it must fix at
  least one real signature/import/enum/record reconstruction failure without broad
  rewrites.
- `java_compare_rebuilt_abi` reports public class/method/field descriptor parity for
  recovered fixtures.
- Resource files are preserved or explicitly reported as omitted by the initial
  validation report; manifest, service, and module semantic validation is added next.
- The final recovery report distinguishes:
  - compiles cleanly
  - compiles with marked stubs
  - does not compile
  - compiles but ABI/resource validation failed

### Phase 6: Minecraft and Mapping Support

Goals:

- Make the copied Minecraft JARs useful for reverse engineering game behavior.

Tasks:

- Parse Forge `META-INF/mods.toml`.
- Parse Fabric `fabric.mod.json` and mixin configs.
- Fetch Mojang mappings from version metadata.
- Support ProGuard mapping application.
- Add Tiny mapping support and Tiny Remapper integration for Yarn/Intermediary.
- Add Minecraft-specific entrypoint and side detection.
- Add client/server comparison.

Acceptance:

- `minecraft_detect_archive` identifies vanilla client/server and Forge jars.
- Mapping fetch verifies hashes/cache metadata.
- Mapped names appear in class/method search and decompiler output where available.

### Phase 7: Runtime Observation

Goals:

- Support debugging behavior that static analysis cannot answer.

Tasks:

- Add full JDK detection.
- Add `java_launch_target` with strict gates.
- Add `java_jcmd` and JFR summary tooling.
- Add JDI attach/launch prototype.
- Add Byte Buddy javaagent for method trace.
- Correlate runtime events to method locators.

Acceptance:

- A small generated Java app can be launched, traced, and stopped.
- Method trace events link to static method nodes.
- Dynamic tools refuse to run without explicit permission flags.

### Phase 8: Patching and Semantic Verification

Goals:

- Support controlled bytecode patching and validation.

Tasks:

- Implement constant replacement.
- Implement branch toggle.
- Implement method-entry probe insertion.
- Verify stack frames with ASM.
- Write patched class/JAR.
- Add runtime comparison harness.

Acceptance:

- Patching generated fixtures works and verifies.
- Invalid transforms fail safely with structured diagnostics.
- Patched artifacts are written only to caller-specified output paths or ignored temp
  paths.

### Phase 9: Advanced Analysis Engines

Goals:

- Add higher-precision analysis when ASM approximations are not enough.

Candidates:

- Soot/SootUp for Jimple IR, dataflow, and interprocedural analysis.
- WALA for class hierarchy, pointer analysis, slicing, and call graph.
- Checker Framework Dataflow for source-level dataflow when source is available.

Acceptance:

- Engines are optional and independently tested.
- Tool outputs declare engine, assumptions, and confidence.
- Agent can compare cheap ASM results with heavy engine results.

## Security and Safety Requirements

- Never execute target Java code during static analysis.
- Never attach to an existing JVM unless explicitly requested and permitted.
- Validate JAR paths and entry paths; prevent zip slip.
- Bound class count, resource count, decompressed size, decompiler output, and helper
  runtime.
- Treat classfiles as hostile input.
- Treat decompiler crashes as data, not fatal analysis failures.
- Treat compiler failures as data, not fatal source-recovery failures.
- Treat sensitive-behavior findings as hypotheses until backed by bytecode evidence,
  reachability, config state, or dynamic observation.
- Never infer malicious intent from a sink alone. Report the sink, context, and
  confidence separately.
- Never output raw secret candidates, tokens, session IDs, private keys, or
  credentials unless an explicit local-only debugging flag enables it.
- Bound string decoding and deobfuscation attempts by byte count, recursion depth,
  helper timeout, and transform count.
- Directory/archive-set scans must obey per-archive and total budgets and should
  produce partial reports with truncation flags instead of failing the whole run.
- Never fetch dependencies from the network during source recovery unless the caller
  explicitly enables dependency resolution and accepts the cache/output location.
- Never edit recovered source outside the caller-provided or ignored recovery
  directory.
- Redact access tokens, session IDs, and common secret formats from runtime logs.
- Redact sensitive values from static config/resource reports as well as runtime logs.
- Keep patched artifacts out of source-controlled paths unless the user explicitly
  asks.
- Preserve source JARs unchanged.

## Performance Strategy

- Hash archives once and use SHA-256 as cache key.
- Separate cheap index data from expensive decompiler/source data.
- Cache decompiler output by `(archive_sha256, class, engine, mapping_namespace,
  helper_version)`.
- Cache recovered source projects by `(archive_sha256, decompiler_engine,
  mapping_namespace, dependency_policy, helper_version)`.
- Cache compiler diagnostics by source tree hash, build metadata hash, Java home, and
  release target.
- Keep large source/bytecode bodies out of default agent context; expose them through
  focused tools.
- Use streaming or paginated outputs for JARs with tens of thousands of classes.
- For Minecraft, index packages and class summaries first, then map/decompile only
  requested areas.
- For audit scans, index and match sinks first, then run decompiler/config/tracing
  tools only for top findings.
- For archive sets, cache each archive report independently so one large or damaged
  JAR does not force rescanning the directory.
- Run compile-repair loops in small batches and persist each iteration's diagnostics
  and patch summary.

## Documentation Updates

As implementation proceeds, update:

- `docs/parsers/java/README.md`
- `docs/analysis/interpreted/README.md`
- `docs/llm/TOOLS.md`
- `docs/llm/RE_TOOLS_OVERVIEW.md`
- `docs/llm/JAVA_SECURITY_AUDIT_TOOLS.md` for rule packs, finding schemas, and
  agent prompt expectations
- `docs/tutorial/03-walkthroughs/04-jvm-classfile.md`
- `docs/development/setup.md` for full JDK requirements

## Source References

Primary specifications and tools:

- JVM classfile format: https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html
- `javap`: https://docs.oracle.com/en/java/javase/25/docs/specs/man/javap.html
- `jdeps`: https://docs.oracle.com/en/java/javase/24/docs/specs/man/jdeps.html
- `jar`: https://docs.oracle.com/en/java/javase/25/docs/specs/man/jar.html
- `jcmd`: https://docs.oracle.com/en/java/javase/25/docs/specs/man/jcmd.html
- Java Instrumentation API: https://docs.oracle.com/en/java/javase/25/docs/api/java.instrument/java/lang/instrument/package-summary.html
- Attach API: https://docs.oracle.com/en/java/javase/25/docs/api/jdk.attach/com/sun/tools/attach/package-summary.html
- JVMTI: https://docs.oracle.com/en/java/javase/25/docs/specs/jvmti.html
- JDWP: https://docs.oracle.com/en/java/javase/25/docs/specs/jdwp/jdwp-spec.html
- JDI: https://docs.oracle.com/en/java/javase/25/docs/api/jdk.jdi/com/sun/jdi/package-summary.html
- JFR API: https://docs.oracle.com/en/java/javase/25/docs/api/jdk.jfr/jdk/jfr/package-summary.html

Libraries:

- Rust `zip`: https://docs.rs/zip
- Rust `ristretto_classfile`: https://docs.rs/ristretto_classfile/latest/ristretto_classfile/
- Rust `cafebabe`: https://docs.rs/cafebabe/latest/cafebabe/
- ASM: https://projects.ow2.org/view/asm/
- Vineflower: https://vineflower.org/
- CFR: https://www.benf.org/other/cfr/
- JavaParser: https://javaparser.org/
- Byte Buddy: https://bytebuddy.net/
- Soot: https://soot-oss.github.io/soot/
- WALA: https://github.com/wala/WALA
- Javassist: https://www.javassist.org/
- Recaf: https://github.com/Col-E/Recaf
- detect-secrets: https://github.com/Yelp/detect-secrets
- yara-python: https://github.com/VirusTotal/yara-python
- SnakeYAML: https://bitbucket.org/snakeyaml/snakeyaml

Minecraft ecosystem:

- Fabric docs: https://docs.fabricmc.net/
- Fabric `fabric.mod.json`: https://docs.fabricmc.net/develop/getting-started/project-structure
- Forge `mods.toml`: https://docs.minecraftforge.net/en/latest/gettingstarted/modfiles/
- Tiny Remapper: https://github.com/FabricMC/tiny-remapper
- Mojang version manifest: https://piston-meta.mojang.com/mc/game/version_manifest_v2.json

Pydantic-AI:

- Toolsets: https://pydantic.dev/docs/ai/api/pydantic-ai/toolsets/
- Native tools: https://pydantic.dev/docs/ai/tools-toolsets/native-tools/
