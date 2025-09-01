# Java Class File Parser Documentation

## Overview

Java class files (.class) contain Java bytecode that runs on the Java Virtual Machine (JVM). GLAURUNG's Java parser handles class files, JAR archives, and provides analysis capabilities for JVM-based applications including Kotlin, Scala, and other JVM languages.

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

### Phase 1: Header Validation
- [ ] Magic number (0xCAFEBABE)
- [ ] Version compatibility check
- [ ] File size validation

### Phase 2: Constant Pool
- [ ] Entry type parsing
- [ ] UTF-8 string extraction
- [ ] Class/method references
- [ ] Symbol resolution

### Phase 3: Class Structure
- [ ] Access modifier parsing
- [ ] Inheritance hierarchy
- [ ] Interface implementation
- [ ] Inner class detection

### Phase 4: Member Analysis
- [ ] Field enumeration
- [ ] Method signature parsing
- [ ] Bytecode extraction
- [ ] Annotation processing

### Phase 5: JAR Processing
- [ ] Manifest parsing
- [ ] Multi-release JAR support
- [ ] Signed JAR validation
- [ ] Resource extraction

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

## Testing Coverage

### Test Samples
- Simple class files: Various Java versions
- Complex inheritance: Multiple interfaces
- JAR files: With dependencies
- Obfuscated code: ProGuard/R8 processed

## Future Enhancements

- [ ] Bytecode disassembly
- [ ] Control flow graph generation
- [ ] Dependency analysis
- [ ] Android DEX support
- [ ] Kotlin metadata parsing
- [ ] GraalVM native image support

## References

- [JVM Specification](https://docs.oracle.com/javase/specs/jvms/)
- [JAR File Specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/)
- [ASM Framework](https://asm.ow2.io/)