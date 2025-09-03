# GLAURUNG Data Model Proposal - CLAUDE

## Notes
- This proposal emphasizes knowledge graph construction, AI-assisted analysis, and multi-modal binary exploration
- Supports incremental analysis with confidence scoring and provenance tracking throughout
- Designed for extensibility with plugin architecture and custom analyzers
- Types use simple names; exact Rust/Python representations will be refined during implementation

---

# Address

## Purpose
Universal representation of locations within binary address spaces, supporting multiple addressing schemes and symbolic resolution.

## Fields
- `value`: Unsigned 64-bit integer value
- `space`: Address space identifier (e.g., `default`, `ram`, `rom`, `io`, `overlay`)
- `kind`: One of `Virtual`, `Physical`, `Relative`, `FileOffset`, `Symbolic`
- `width`: Bit width (16, 32, 64)
- `symbol_ref?`: Optional reference to associated Symbol
- `confidence`: Float 0.0-1.0 for address resolution confidence

---

# AddressRange

## Purpose
Defines contiguous memory regions with optional metadata about content and purpose.

## Fields
- `start`: Starting Address (inclusive)
- `end`: Ending Address (exclusive)
- `size`: Size in bytes
- `attributes`: Map of key-value attributes (e.g., `entropy`, `compression_ratio`)
- `tags`: List of semantic tags (e.g., `encrypted`, `packed`, `obfuscated`)
- `confidence`: Float 0.0-1.0 for range validity

---

# Binary

## Purpose
Root container for analyzed binary with comprehensive metadata and analysis state.

## Fields
- `id`: Stable UUID derived from content hash
- `path`: Filesystem path
- `format`: One of `ELF`, `PE`, `MachO`, `COFF`, `Wasm`, `Raw`, `Unknown`
- `architecture`: Target architecture descriptor
- `endianness`: `Little` or `Big`
- `entry_points`: List of Address (multiple for drivers, libraries)
- `metadata`: Extensible metadata map
- `hashes`: Map of algorithm to hash value
- `signatures`: List of detected signatures/patterns
- `analysis_state`: Current analysis phase and coverage metrics
- `knowledge_graph_ref`: Reference to associated KnowledgeGraph

---

# Segment

## Purpose
Load-time memory mapping unit with permissions and mapping information.

## Fields
- `id`: Stable identifier
- `name?`: Optional name
- `virtual_range`: AddressRange in virtual space
- `file_range`: AddressRange in file
- `permissions`: Set of `Read`, `Write`, `Execute`
- `type`: One of `Code`, `Data`, `Stack`, `Heap`, `Mapped`
- `compression?`: Optional compression metadata
- `encryption?`: Optional encryption metadata

---

# Section

## Purpose
Format-specific organizational unit with semantic type information.

## Fields
- `id`: Stable identifier
- `name`: Section name
- `range`: AddressRange
- `type`: Section type (format-specific)
- `flags`: Format-specific flags
- `entropy`: Shannon entropy value
- `hashes`: Map of hash algorithm to value
- `characteristics`: List of detected characteristics

---

# Symbol

## Purpose
Named entity with rich metadata about origin and confidence.

## Fields
- `id`: Stable identifier
- `name`: Symbol name (mangled)
- `demangled?`: Optional demangled name
- `address?`: Optional Address
- `type`: One of `Function`, `Data`, `Import`, `Export`, `Debug`, `Synthetic`
- `size?`: Optional size in bytes
- `visibility`: One of `Public`, `Private`, `Protected`, `Hidden`
- `source`: Origin (e.g., `SymbolTable`, `DWARF`, `PDB`, `AI_Inferred`)
- `confidence`: Float 0.0-1.0
- `attributes`: Extensible attribute map

---

# Instruction

## Purpose
Decoded instruction with semantic information and control flow metadata.

## Fields
- `address`: Instruction Address
- `bytes`: Raw instruction bytes
- `mnemonic`: Instruction mnemonic
- `operands`: List of Operand objects
- `length`: Instruction length in bytes
- `semantics?`: Optional semantic descriptor
- `side_effects`: List of side effects (e.g., `MemoryWrite`, `RegisterModify`)
- `prefixes`: List of instruction prefixes
- `groups`: List of instruction groups (e.g., `branch`, `crypto`, `simd`)

---

# Operand

## Purpose
Structured representation of instruction operands with type information.

## Fields
- `type`: One of `Register`, `Immediate`, `Memory`, `Displacement`, `Relative`
- `value`: Type-specific value representation
- `size`: Size in bits
- `access`: One of `Read`, `Write`, `ReadWrite`
- `segment?`: Optional segment override
- `scale?`: Optional scale for SIB addressing
- `base?`: Optional base register
- `index?`: Optional index register

---

# BasicBlock

## Purpose
Fundamental CFG unit with comprehensive flow analysis metadata.

## Fields
- `id`: Stable identifier
- `address_range`: AddressRange covered by block
- `instructions`: Ordered list of Instructions
- `predecessors`: List of predecessor block IDs
- `successors`: List of successor block IDs with edge types
- `dominators`: Set of dominator block IDs
- `loop_header?`: Optional reference if this is a loop header
- `exception_handlers`: List of exception handler references
- `complexity_metrics`: Cyclomatic complexity and other metrics

---

# Function

## Purpose
High-level function representation with signature analysis and call information.

## Fields
- `id`: Stable identifier
- `name?`: Optional function name
- `entry`: Entry Address
- `exits`: List of exit/return Addresses
- `basic_blocks`: List of BasicBlock IDs
- `parameters`: List of Parameter objects
- `local_variables`: List of Variable objects
- `calling_convention?`: Detected or specified calling convention
- `return_type?`: Optional return type
- `stack_frame_size?`: Optional stack frame size
- `cyclomatic_complexity`: Complexity metric
- `is_thunk`: Boolean for thunk detection
- `is_library`: Boolean for library function detection
- `confidence`: Float 0.0-1.0 for function boundary confidence

---

# Variable

## Purpose
Represents variables with type inference and liveness information.

## Fields
- `id`: Stable identifier
- `name?`: Optional variable name
- `type`: DataType reference
- `storage`: One of `Register`, `Stack`, `Heap`, `Global`
- `location`: Location descriptor (register name, stack offset, address)
- `liveness_range?`: Optional AddressRange where variable is live
- `source`: One of `Debug`, `Decompiler`, `AI_Inferred`
- `confidence`: Float 0.0-1.0

---

# DataType

## Purpose
Type system representation supporting complex and inferred types.

## Fields
- `id`: Stable identifier
- `name`: Type name
- `kind`: One of `Primitive`, `Pointer`, `Array`, `Struct`, `Union`, `Enum`, `Function`, `Typedef`
- `size`: Size in bytes
- `alignment`: Alignment requirement
- `fields?`: For composite types, list of Field objects
- `base_type?`: For derived types, reference to base type
- `attributes`: Type attributes (e.g., `const`, `volatile`)
- `source`: Origin of type information
- `confidence`: Float 0.0-1.0 for inferred types

---

# StringLiteral

## Purpose
Extracted string with encoding detection and reference tracking.

## Fields
- `id`: Stable identifier
- `address`: String location Address
- `value`: Decoded string value
- `raw_bytes`: Original bytes
- `encoding`: Detected encoding (e.g., `ASCII`, `UTF8`, `UTF16LE`, `Base64`)
- `length`: String length in characters
- `byte_length`: String length in bytes
- `references`: List of Address where string is referenced
- `language_hint?`: Optional detected natural language
- `classification?`: Optional classification (e.g., `URL`, `Path`, `Email`, `Key`)
- `entropy`: Shannon entropy of the string

---

# Pattern

## Purpose
Represents detected patterns, signatures, and anomalies in the binary.

## Fields
- `id`: Stable identifier
- `type`: Pattern type (e.g., `Cryptographic`, `Packer`, `AntiDebug`, `Exploit`)
- `name`: Pattern name
- `addresses`: List of Address where pattern occurs
- `confidence`: Float 0.0-1.0
- `severity?`: Optional severity level for security patterns
- `description`: Human-readable description
- `references`: External references (CVE, technique IDs)
- `metadata`: Pattern-specific metadata

---

# KnowledgeGraph

## Purpose
RDF-inspired semantic graph for representing binary analysis knowledge with ontological reasoning support.

## Fields
- `id`: Stable identifier
- `ontology`: Reference to BinaryOntology
- `triples`: List of Triple objects (subject-predicate-object)
- `named_graphs`: Map of context-specific subgraphs
- `prefixes`: Namespace prefix definitions
- `inference_rules`: List of reasoning rules (SWRL-like)
- `materialized_triples`: Inferred triples from reasoning

---

# BinaryOntology

## Purpose
OWL-inspired ontology defining classes, properties, and constraints for binary analysis domain.

## Fields
- `id`: Stable identifier
- `version`: Ontology version
- `classes`: Hierarchy of ontology classes (e.g., `Instruction`, `CryptoRoutine < Function`)
- `object_properties`: Relations between entities (e.g., `calls`, `allocates`, `encrypts`)
- `data_properties`: Attributes of entities (e.g., `hasEntropy`, `hasSize`, `isObfuscated`)
- `individuals`: Named instances in the ontology
- `axioms`: Logical axioms and constraints
- `imports`: List of imported ontologies (e.g., STIX, MAEC)

---

# OntologyClass

## Purpose
Class definition in the binary analysis ontology with hierarchical relationships.

## Fields
- `iri`: Internationalized Resource Identifier
- `label`: Human-readable label
- `parent_classes`: List of superclass IRIs
- `disjoint_with`: List of disjoint class IRIs
- `equivalent_to`: List of equivalent class expressions
- `restrictions`: Property restrictions on the class
- `annotations`: Metadata annotations (comments, see_also, etc.)

---

# Triple

## Purpose
RDF triple representing a single fact in the knowledge graph.

## Fields
- `subject`: Resource (IRI or blank node)
- `predicate`: Property/relation IRI
- `object`: Resource or literal value
- `graph_context?`: Optional named graph this triple belongs to
- `confidence`: Float 0.0-1.0
- `provenance`: Provenance information (who/what/when asserted)
- `valid_time?`: Optional temporal validity range
- `reification_id?`: Optional ID for reified statements

---

# Resource

## Purpose
RDF resource representing an entity in the knowledge graph.

## Fields
- `iri`: Internationalized Resource Identifier
- `type`: List of ontology class IRIs (rdf:type)
- `labels`: Multi-language labels (rdfs:label)
- `same_as`: List of equivalent resource IRIs (owl:sameAs)
- `different_from`: List of distinct resource IRIs (owl:differentFrom)

---

# Literal

## Purpose
RDF literal value with datatype and optional language tag.

## Fields
- `value`: The literal value
- `datatype`: XSD datatype IRI (e.g., xsd:integer, xsd:hexBinary)
- `language?`: Optional language tag for strings

---

# Property

## Purpose
RDF property (predicate) definition with domain/range constraints.

## Fields
- `iri`: Property IRI
- `type`: One of `ObjectProperty`, `DataProperty`, `AnnotationProperty`
- `domain`: List of class IRIs this property applies to
- `range`: List of class IRIs or datatypes for property values
- `characteristics`: Set of `Functional`, `InverseFunctional`, `Transitive`, `Symmetric`, `Asymmetric`, `Reflexive`, `Irreflexive`
- `inverse_of?`: Optional inverse property IRI
- `sub_property_of`: List of parent property IRIs

---

# InferenceRule

## Purpose
SWRL-like rule for reasoning over the knowledge graph.

## Fields
- `id`: Rule identifier
- `name`: Rule name
- `antecedent`: List of rule atoms (if conditions)
- `consequent`: List of rule atoms (then assertions)
- `confidence`: Confidence in rule application
- `priority`: Rule priority for conflict resolution

---

# RuleAtom

## Purpose
Atomic formula in inference rules.

## Fields
- `type`: One of `Class`, `Property`, `SameAs`, `DifferentFrom`, `BuiltIn`
- `arguments`: List of variables or constants
- `predicate`: Predicate IRI or built-in function

---

# NamedGraph

## Purpose
Context-specific subgraph for organizing triples by analysis phase or confidence level.

## Fields
- `iri`: Graph IRI
- `description`: Graph purpose/context
- `metadata`: Graph-level metadata
- `triple_count`: Number of triples in graph
- `confidence_threshold?`: Minimum confidence for triples in this graph

---

# SPARQLQuery

## Purpose
Stored SPARQL query for knowledge graph interrogation.

## Fields
- `id`: Query identifier
- `name`: Query name
- `description`: What the query finds
- `query_string`: SPARQL query text
- `parameters`: List of query parameters
- `result_type`: Expected result type

---

# SemanticPattern

## Purpose
Complex graph pattern for semantic matching using SPARQL-like syntax.

## Fields
- `id`: Pattern identifier
- `name`: Pattern name
- `graph_pattern`: SPARQL graph pattern
- `bindings`: Variable bindings
- `filters`: FILTER constraints
- `severity?`: For security patterns
- `cwe_id?`: Common Weakness Enumeration reference
- `mitre_attack?`: MITRE ATT&CK technique reference

---

# AnalysisArtifact

## Purpose
Container for analysis results with full provenance and versioning.

## Fields
- `id`: Stable identifier
- `type`: Artifact type identifier
- `tool`: Tool that produced the artifact
- `version`: Tool version
- `timestamp`: Creation timestamp
- `dependencies`: List of input artifact IDs
- `confidence`: Overall confidence score
- `data`: Artifact-specific data payload
- `metadata`: Extensible metadata
- `validation_status`: One of `Valid`, `Invalid`, `Unchecked`

---

# SteganographicContent

## Purpose
Represents potential hidden or embedded content within the binary.

## Fields
- `id`: Stable identifier
- `location`: AddressRange where content is hidden
- `method`: Detection method used
- `content_type`: Type of hidden content
- `extracted_data?`: Optional extracted payload
- `confidence`: Float 0.0-1.0
- `indicators`: List of indicators that suggested hidden content
- `entropy_analysis`: Entropy-based anomaly metrics

---

# AIInsight

## Purpose
AI-generated analysis insights with explanations and confidence.

## Fields
- `id`: Stable identifier
- `type`: Insight type (e.g., `Vulnerability`, `Behavior`, `Similarity`, `Anomaly`)
- `description`: Human-readable insight description
- `entities`: List of related entity IDs
- `confidence`: Float 0.0-1.0
- `model`: AI model identifier used
- `reasoning?`: Optional explanation of reasoning
- `suggested_actions`: List of recommended follow-up analyses
- `false_positive_score`: Likelihood of false positive

---

# CallGraph

## Purpose
Inter-procedural call relationships with indirect call resolution.

## Fields
- `nodes`: List of Function IDs
- `edges`: List of CallEdge objects
- `indirect_calls`: List of unresolved indirect calls
- `virtual_calls`: List of virtual/dynamic dispatch sites
- `call_chains`: Identified call chain patterns
- `recursion_points`: Detected recursive call patterns

---

# CallEdge

## Purpose
Edge in call graph with call site information.

## Fields
- `caller`: Function ID of caller
- `callee`: Function ID of callee
- `call_sites`: List of Address where calls occur
- `call_type`: One of `Direct`, `Indirect`, `Virtual`, `Tail`
- `confidence`: Float 0.0-1.0 for indirect/virtual calls

---

# Embedding

## Purpose
Vector embeddings for similarity analysis and ML applications.

## Fields
- `id`: Stable identifier
- `entity_type`: Type of embedded entity
- `entity_id`: Reference to entity
- `vector`: Numeric vector representation
- `dimension`: Vector dimension
- `model`: Model used to generate embedding
- `timestamp`: Generation timestamp

---

# Similarity

## Purpose
Similarity relationships between entities for clone detection and matching.

## Fields
- `id`: Stable identifier
- `entity1_id`: First entity reference
- `entity2_id`: Second entity reference
- `similarity_type`: Type of similarity (e.g., `Syntactic`, `Semantic`, `Structural`)
- `score`: Similarity score 0.0-1.0
- `method`: Method used for comparison
- `details?`: Optional detailed comparison results

---

# DynamicTrace

## Purpose
Dynamic execution trace information for runtime analysis integration.

## Fields
- `id`: Stable identifier
- `trace_type`: Type of trace (e.g., `Instruction`, `API`, `System`)
- `events`: List of TraceEvent objects
- `coverage`: Code coverage information
- `input_vector?`: Optional input that generated trace
- `timestamp`: Trace collection timestamp

---

# TraceEvent

## Purpose
Individual event in a dynamic trace.

## Fields
- `sequence_number`: Event sequence number
- `timestamp`: Event timestamp
- `address?`: Optional Address where event occurred
- `event_type`: Type of event
- `data`: Event-specific data
- `thread_id?`: Optional thread identifier
- `process_id?`: Optional process identifier

---

# Comment

## Purpose
User or AI-generated annotations and notes.

## Fields
- `id`: Stable identifier
- `address?`: Optional Address for location-specific comments
- `entity_id?`: Optional reference to any entity
- `text`: Comment text
- `author`: Author identifier (user or AI model)
- `timestamp`: Creation timestamp
- `type`: One of `Note`, `Warning`, `TODO`, `Analysis`
- `priority?`: Optional priority level

---

# Workspace

## Purpose
Project workspace configuration and analysis session management.

## Fields
- `id`: Stable identifier
- `name`: Workspace name
- `root_path`: Filesystem root
- `binaries`: List of Binary IDs in workspace
- `active_binary?`: Currently active Binary ID
- `analysis_profiles`: List of analysis configuration profiles
- `plugins`: List of loaded plugins
- `settings`: Workspace-specific settings
- `history`: Analysis action history

---

# AnalysisProfile

## Purpose
Configuration profile for analysis passes and tool settings.

## Fields
- `id`: Stable identifier
- `name`: Profile name
- `description`: Profile description
- `tools`: List of tools and their configurations
- `passes`: Ordered list of analysis passes
- `confidence_thresholds`: Minimum confidence levels
- `performance_hints`: Performance tuning parameters

---

# Example Ontology Usage

## Sample Triple Representations

```turtle
# Function calls another function
<binary:0x401000> rdf:type glaurung:Function ;
    glaurung:calls <binary:0x401100> ;
    glaurung:hasEntropy 7.2 ;
    glaurung:usesAlgorithm glaurung:AES .

# Pattern detection with confidence
<pattern:crypto_001> rdf:type glaurung:CryptographicPattern ;
    glaurung:detectedAt <binary:0x401000> ;
    glaurung:hasConfidence 0.95 ;
    glaurung:indicatesAlgorithm "AES-256-CBC" .

# Semantic inference rule
Rule: CryptoFunction(?f) ∧ calls(?f, ?g) ∧ CryptoFunction(?g) → CryptoChain(?f, ?g)
```

## Ontology Class Hierarchy Example

```
Thing
├── BinaryEntity
│   ├── Instruction
│   │   ├── BranchInstruction
│   │   ├── CallInstruction
│   │   └── CryptoInstruction
│   ├── Function
│   │   ├── ExportedFunction
│   │   ├── ImportedFunction
│   │   ├── CryptographicFunction
│   │   └── VulnerableFunction
│   └── DataStructure
│       ├── String
│       │   ├── URL
│       │   ├── FilePath
│       │   └── CryptoKey
│       └── BinaryBlob
├── SecurityConcept
│   ├── Vulnerability
│   ├── Exploit
│   └── Mitigation
└── AnalysisConcept
    ├── Pattern
    ├── Anomaly
    └── Signature
```

---

# Summary

This data model proposal emphasizes:

1. **Semantic Web Foundation**: Full RDF/OWL-inspired knowledge representation with:
   - Triple-based fact storage (subject-predicate-object)
   - Ontological class hierarchies and property definitions
   - SPARQL query support for complex graph interrogation
   - SWRL-like inference rules for automated reasoning

2. **Ontological Reasoning**: Rich semantic capabilities including:
   - Class inheritance and restrictions
   - Property characteristics (transitive, symmetric, etc.)
   - Named graphs for context separation
   - Temporal and confidence-based reasoning

3. **Standards Interoperability**: 
   - Compatible with existing security ontologies (STIX, MAEC)
   - RDF/OWL standard compliance for tool ecosystem
   - SPARQL for standardized querying
   - Import/export to standard formats

4. **AI-Powered Analysis**: AIInsight, Embedding, and semantic patterns for ML integration

5. **Multi-Modal Analysis**: Static, dynamic, and hybrid analysis with full provenance

6. **Advanced Pattern Recognition**: Semantic patterns using SPARQL graph patterns

The RDF/OWL-inspired approach provides several advantages:
- **Reasoning**: Automatic inference of new facts from existing knowledge
- **Interoperability**: Integration with semantic web tools and existing ontologies
- **Flexibility**: Easy extension through ontology evolution
- **Queryability**: Powerful SPARQL queries for complex analysis
- **Explainability**: Clear semantic relationships for AI explanation

This semantic foundation makes Glaurung not just a binary analysis tool, but a knowledge discovery platform that can reason about binaries, discover hidden relationships, and integrate with the broader security knowledge ecosystem.