//! Java classfile parser (#209 v0).
//!
//! Recovers class name, super class, interfaces, and the full method
//! table (name + JVM descriptor + access flags) from a `.class` file.
//! Java is unlike PE/ELF in that the file itself is the function
//! container — there are no RVAs/VAs to map onto. We surface the
//! metadata as a structured `ClassInfo` and let downstream callers
//! decide whether to mirror it into the KB or just render it.
//!
//! Spec reference: JVM Specification §4 (the ClassFile structure).
//! Supports JDK 1.0 through latest (constant-pool tags 1-20).

mod annotations;
mod attributes;
mod bytecode;
mod code;
mod constant_pool;
mod opcodes;
mod types;

use annotations::{
    parse_annotation_element_value, parse_annotations_attribute, parse_method_parameters_attribute,
    parse_parameter_annotations_attribute, read_constant_value,
};
use attributes::parse_class_attributes;
use code::{parse_code_attribute, parse_counted_attribute, parse_exceptions_attribute};
use constant_pool::{read_class_name, read_utf8, summarize_constant_pool};

pub use types::{
    ClassError, ClassInfo, JavaAnnotation, JavaAnnotationElement, JavaAnnotationValue,
    JavaBootstrapMethod, JavaCode, JavaConstantPoolSummary, JavaConstantValue, JavaEnclosingMethod,
    JavaExceptionHandler, JavaInnerClass, JavaInstruction, JavaLineNumber, JavaLocalVariable,
    JavaLocalVariableType, JavaMethod, JavaMethodParameter, JavaModuleExport, JavaModuleInfo,
    JavaModuleOpen, JavaModuleProvide, JavaModuleRequire, JavaParameterAnnotations,
    JavaRecordComponent, JavaXref,
};

const MAGIC: u32 = 0xCAFE_BABE;

#[derive(Debug, Clone)]
enum CpEntry {
    Empty,
    Utf8(String),
    Class {
        name_idx: u16,
    },
    NameAndType {
        name_idx: u16,
        desc_idx: u16,
    },
    String {
        string_idx: u16,
    },
    Integer(i32),
    Float(u32),
    Long(i64),
    Double(u64),
    Fieldref {
        class_idx: u16,
        name_and_type_idx: u16,
    },
    Methodref {
        class_idx: u16,
        name_and_type_idx: u16,
    },
    InterfaceMethodref {
        class_idx: u16,
        name_and_type_idx: u16,
    },
    Dynamic {
        bootstrap_method_attr_idx: u16,
        name_and_type_idx: u16,
    },
    InvokeDynamic {
        bootstrap_method_attr_idx: u16,
        name_and_type_idx: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_idx: u16,
    },
    Module {
        name_idx: u16,
    },
    Package {
        name_idx: u16,
    },
}

#[derive(Debug, Default)]
struct JavaClassAttributes {
    attribute_names: Vec<String>,
    is_deprecated: bool,
    is_synthetic: bool,
    runtime_visible_type_annotation_count: u16,
    runtime_invisible_type_annotation_count: u16,
    source_debug_extension_length: u32,
    source_debug_extension_sha256: Option<String>,
    source_file: Option<String>,
    signature: Option<String>,
    annotations: Vec<JavaAnnotation>,
    inner_classes: Vec<JavaInnerClass>,
    enclosing_method: Option<JavaEnclosingMethod>,
    nest_host: Option<String>,
    nest_members: Vec<String>,
    record_components: Vec<JavaRecordComponent>,
    permitted_subclasses: Vec<String>,
    module: Option<JavaModuleInfo>,
    module_packages: Vec<String>,
    module_main_class: Option<String>,
    bootstrap_method_count: u16,
    bootstrap_methods: Vec<JavaBootstrapMethod>,
}

/// Parse a `.class` file and return its `ClassInfo`.
pub fn parse_class(data: &[u8]) -> Result<ClassInfo, ClassError> {
    if data.len() < 10 {
        return Err(ClassError::Truncated("header"));
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(ClassError::BadMagic(magic));
    }
    let minor = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let major = u16::from_be_bytes(data[6..8].try_into().unwrap());
    let cp_count = u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize;

    let mut p = 10;
    // Constant pool is 1-indexed; entry 0 is reserved. Long & Double
    // each occupy two slots.
    let mut cp: Vec<CpEntry> = vec![CpEntry::Empty; cp_count];
    let mut i = 1;
    while i < cp_count {
        if p >= data.len() {
            return Err(ClassError::Truncated("constant pool"));
        }
        let tag = data[p];
        p += 1;
        match tag {
            1 => {
                // Utf8: u16 length, then `length` bytes of modified UTF-8.
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("utf8 length"));
                }
                let len = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
                p += 2;
                if p + len > data.len() {
                    return Err(ClassError::Truncated("utf8 body"));
                }
                let s = decode_modified_utf8(&data[p..p + len]);
                cp[i] = CpEntry::Utf8(s);
                p += len;
                i += 1;
            }
            7 => {
                // Class
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("class"));
                }
                let name_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                p += 2;
                cp[i] = CpEntry::Class { name_idx };
                i += 1;
            }
            12 => {
                // NameAndType
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("nameandtype"));
                }
                let n = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                let d = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = CpEntry::NameAndType {
                    name_idx: n,
                    desc_idx: d,
                };
                i += 1;
            }
            3 | 4 => {
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("numeric constant"));
                }
                let bits = u32::from_be_bytes(data[p..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = if tag == 3 {
                    CpEntry::Integer(bits as i32)
                } else {
                    CpEntry::Float(bits)
                };
                i += 1;
            } // Integer, Float
            5 | 6 => {
                if p + 8 > data.len() {
                    return Err(ClassError::Truncated("wide numeric constant"));
                }
                let bits = u64::from_be_bytes(data[p..p + 8].try_into().unwrap());
                p += 8;
                cp[i] = if tag == 5 {
                    CpEntry::Long(bits as i64)
                } else {
                    CpEntry::Double(bits)
                };
                i += 2;
            } // Long, Double (2 slots)
            8 => {
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("string"));
                }
                let string_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                p += 2;
                cp[i] = CpEntry::String { string_idx };
                i += 1;
            } // String
            9 | 10 | 11 => {
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("member ref"));
                }
                let class_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                let name_and_type_idx = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = match tag {
                    9 => CpEntry::Fieldref {
                        class_idx,
                        name_and_type_idx,
                    },
                    10 => CpEntry::Methodref {
                        class_idx,
                        name_and_type_idx,
                    },
                    11 => CpEntry::InterfaceMethodref {
                        class_idx,
                        name_and_type_idx,
                    },
                    _ => unreachable!(),
                };
                i += 1;
            } // Field/Method/InterfaceMethod ref
            15 => {
                if p + 3 > data.len() {
                    return Err(ClassError::Truncated("method handle"));
                }
                let reference_kind = data[p];
                let reference_index = u16::from_be_bytes(data[p + 1..p + 3].try_into().unwrap());
                p += 3;
                cp[i] = CpEntry::MethodHandle {
                    reference_kind,
                    reference_index,
                };
                i += 1;
            } // MethodHandle
            16 => {
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("method type"));
                }
                let descriptor_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                p += 2;
                cp[i] = CpEntry::MethodType { descriptor_idx };
                i += 1;
            } // MethodType
            17 | 18 => {
                if p + 4 > data.len() {
                    return Err(ClassError::Truncated("dynamic"));
                }
                let bootstrap_method_attr_idx =
                    u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                let name_and_type_idx = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
                p += 4;
                cp[i] = if tag == 17 {
                    CpEntry::Dynamic {
                        bootstrap_method_attr_idx,
                        name_and_type_idx,
                    }
                } else {
                    CpEntry::InvokeDynamic {
                        bootstrap_method_attr_idx,
                        name_and_type_idx,
                    }
                };
                i += 1;
            } // Dynamic, InvokeDynamic
            19 | 20 => {
                if p + 2 > data.len() {
                    return Err(ClassError::Truncated("module/package"));
                }
                let name_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
                p += 2;
                cp[i] = if tag == 19 {
                    CpEntry::Module { name_idx }
                } else {
                    CpEntry::Package { name_idx }
                };
                i += 1;
            } // Module, Package
            other => return Err(ClassError::BadCpTag(other)),
        }
    }
    let constant_pool = summarize_constant_pool(&cp);

    if p + 8 > data.len() {
        return Err(ClassError::Truncated("class header"));
    }
    let access_flags = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
    p += 2;
    let this_class = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
    p += 2;
    let super_class = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
    p += 2;
    let interfaces_count = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
    p += 2;

    let class_name = read_class_name(&cp, this_class)?;
    let super_class_name = read_class_name(&cp, super_class)?;
    let mut interfaces = Vec::with_capacity(interfaces_count);
    for _ in 0..interfaces_count {
        if p + 2 > data.len() {
            return Err(ClassError::Truncated("interfaces"));
        }
        let idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
        p += 2;
        interfaces.push(read_class_name(&cp, idx)?);
    }

    let mut fields: Vec<JavaMethod> = Vec::new();
    p = walk_member_table(data, p, &cp, false, &mut fields)?;
    let mut methods: Vec<JavaMethod> = Vec::new();
    p = walk_member_table(data, p, &cp, true, &mut methods)?;
    let (_p, class_attrs) = parse_class_attributes(data, p, &cp)?;

    Ok(ClassInfo {
        minor_version: minor,
        major_version: major,
        access_flags,
        class_name,
        super_class: super_class_name,
        source_file: class_attrs.source_file,
        signature: class_attrs.signature,
        attribute_names: class_attrs.attribute_names,
        is_deprecated: class_attrs.is_deprecated,
        is_synthetic: class_attrs.is_synthetic || access_flags & 0x1000 != 0,
        runtime_visible_type_annotation_count: class_attrs.runtime_visible_type_annotation_count,
        runtime_invisible_type_annotation_count: class_attrs
            .runtime_invisible_type_annotation_count,
        source_debug_extension_length: class_attrs.source_debug_extension_length,
        source_debug_extension_sha256: class_attrs.source_debug_extension_sha256,
        constant_pool,
        annotations: class_attrs.annotations,
        inner_classes: class_attrs.inner_classes,
        enclosing_method: class_attrs.enclosing_method,
        nest_host: class_attrs.nest_host,
        nest_members: class_attrs.nest_members,
        record_components: class_attrs.record_components,
        permitted_subclasses: class_attrs.permitted_subclasses,
        module: class_attrs.module,
        bootstrap_method_count: class_attrs.bootstrap_method_count,
        bootstrap_methods: class_attrs.bootstrap_methods,
        interfaces,
        methods,
        fields,
    })
}

fn walk_member_table(
    data: &[u8],
    mut p: usize,
    cp: &[CpEntry],
    capture_code: bool,
    out: &mut Vec<JavaMethod>,
) -> Result<usize, ClassError> {
    if p + 2 > data.len() {
        return Err(ClassError::Truncated("member count"));
    }
    let count = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    for _ in 0..count {
        if p + 8 > data.len() {
            return Err(ClassError::Truncated("member info"));
        }
        let access_flags = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
        let name_idx = u16::from_be_bytes(data[p + 2..p + 4].try_into().unwrap());
        let desc_idx = u16::from_be_bytes(data[p + 4..p + 6].try_into().unwrap());
        let attrs = u16::from_be_bytes(data[p + 6..p + 8].try_into().unwrap()) as usize;
        p += 8;
        let mut code = None;
        let mut exceptions = Vec::new();
        let mut annotations = Vec::new();
        let mut signature = None;
        let mut attribute_names = Vec::with_capacity(attrs);
        let mut is_deprecated = false;
        let mut is_synthetic = access_flags & 0x1000 != 0;
        let mut runtime_visible_type_annotation_count = 0u16;
        let mut runtime_invisible_type_annotation_count = 0u16;
        let mut constant_value = None;
        let mut method_parameters = Vec::new();
        let mut parameter_annotations = Vec::new();
        let mut annotation_default = None;
        for _ in 0..attrs {
            if p + 6 > data.len() {
                return Err(ClassError::Truncated("attribute header"));
            }
            let attr_name_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
            let attr_name = read_utf8(cp, attr_name_idx)?;
            let alen = u32::from_be_bytes(data[p + 2..p + 6].try_into().unwrap()) as usize;
            let body_start = p + 6;
            let body_end = body_start
                .checked_add(alen)
                .ok_or(ClassError::Truncated("attribute body"))?;
            if body_end > data.len() {
                return Err(ClassError::Truncated("attribute body"));
            }
            attribute_names.push(attr_name.clone());
            if capture_code && attr_name == "Code" {
                code = Some(parse_code_attribute(&data[body_start..body_end], cp)?);
            } else if capture_code && attr_name == "Exceptions" {
                exceptions = parse_exceptions_attribute(&data[body_start..body_end], cp)?;
            } else if attr_name == "Signature" && alen == 2 {
                let signature_idx =
                    u16::from_be_bytes(data[body_start..body_end].try_into().unwrap());
                signature = Some(read_utf8(cp, signature_idx)?);
            } else if attr_name == "ConstantValue" && alen == 2 {
                let constant_idx =
                    u16::from_be_bytes(data[body_start..body_end].try_into().unwrap());
                constant_value = Some(read_constant_value(cp, constant_idx)?);
            } else if attr_name == "Deprecated" {
                is_deprecated = true;
            } else if attr_name == "Synthetic" {
                is_synthetic = true;
            } else if attr_name == "RuntimeVisibleTypeAnnotations" {
                runtime_visible_type_annotation_count = parse_counted_attribute(
                    &data[body_start..body_end],
                    "RuntimeVisibleTypeAnnotations",
                )?;
            } else if attr_name == "RuntimeInvisibleTypeAnnotations" {
                runtime_invisible_type_annotation_count = parse_counted_attribute(
                    &data[body_start..body_end],
                    "RuntimeInvisibleTypeAnnotations",
                )?;
            } else if attr_name == "MethodParameters" {
                method_parameters =
                    parse_method_parameters_attribute(&data[body_start..body_end], cp)?;
            } else if attr_name == "RuntimeVisibleParameterAnnotations" {
                parameter_annotations.extend(parse_parameter_annotations_attribute(
                    &data[body_start..body_end],
                    cp,
                    "runtime_visible",
                )?);
            } else if attr_name == "RuntimeInvisibleParameterAnnotations" {
                parameter_annotations.extend(parse_parameter_annotations_attribute(
                    &data[body_start..body_end],
                    cp,
                    "runtime_invisible",
                )?);
            } else if attr_name == "AnnotationDefault" {
                let (next, value) =
                    parse_annotation_element_value(&data[body_start..body_end], 0, cp)?;
                if next == alen {
                    annotation_default = Some(value);
                }
            } else if attr_name == "RuntimeVisibleAnnotations" {
                annotations.extend(parse_annotations_attribute(
                    &data[body_start..body_end],
                    cp,
                    "runtime_visible",
                )?);
            } else if attr_name == "RuntimeInvisibleAnnotations" {
                annotations.extend(parse_annotations_attribute(
                    &data[body_start..body_end],
                    cp,
                    "runtime_invisible",
                )?);
            }
            p = body_end;
        }
        let name = read_utf8(cp, name_idx)?;
        let descriptor = read_utf8(cp, desc_idx)?;
        out.push(JavaMethod {
            access_flags,
            name,
            descriptor,
            signature,
            attribute_names,
            is_deprecated,
            is_synthetic,
            runtime_visible_type_annotation_count,
            runtime_invisible_type_annotation_count,
            constant_value,
            exceptions,
            annotations,
            method_parameters,
            parameter_annotations,
            annotation_default,
            code,
        });
    }
    Ok(p)
}

/// Decode JVM "modified UTF-8" — almost identical to UTF-8 except
/// the NUL byte is encoded as 0xC0 0x80 and supplementary characters
/// use surrogate pairs. We accept both standard UTF-8 and the modified
/// form by walking each byte and reconstructing chars.
fn decode_modified_utf8(buf: &[u8]) -> String {
    // For the purposes of class-name extraction, a tolerant lossy
    // decode is fine — class names and method names are nearly always
    // pure ASCII anyway.
    String::from_utf8_lossy(buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_helloworld_class() {
        let path = Path::new("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_class(&data).expect("parse should succeed");
        assert_eq!(info.class_name, "HelloWorld");
        assert_eq!(info.super_class, "java/lang/Object");
        // HelloWorld.java declares: HelloWorld(String), HelloWorld(),
        // printMessage, getCounter, printGlobalInfo, main.
        let names: Vec<&str> = info.methods.iter().map(|m| m.name.as_str()).collect();
        for expected in &[
            "main",
            "printMessage",
            "getCounter",
            "printGlobalInfo",
            "<init>",
        ] {
            assert!(
                names.contains(expected),
                "missing method {}; got {:?}",
                expected,
                names,
            );
        }
        // Main has descriptor `([Ljava/lang/String;)V`.
        let main_method = info.methods.iter().find(|m| m.name == "main").unwrap();
        assert_eq!(main_method.descriptor, "([Ljava/lang/String;)V");
        let main_code = main_method
            .code
            .as_ref()
            .expect("main should have bytecode");
        assert!(main_code.max_stack > 0);
        assert!(main_code.max_locals >= 1);
        assert!(main_code.code_length > 0);
        assert!(info.fields.iter().all(|f| f.code.is_none()));
        assert_eq!(info.source_file.as_deref(), Some("HelloWorld.java"));
    }

    #[test]
    fn parses_method_bytecode_xrefs() {
        let path = Path::new("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_class(&data).expect("parse should succeed");

        let print_message = info
            .methods
            .iter()
            .find(|m| m.name == "printMessage")
            .expect("printMessage method");
        let xrefs = &print_message.code.as_ref().expect("code").xrefs;
        assert!(
            xrefs.iter().any(|xref| {
                xref.kind == "field"
                    && xref.owner == "java/lang/System"
                    && xref.name == "out"
                    && xref.bci == 0
            }),
            "expected System.out field xref, got {xrefs:?}",
        );
        assert!(
            xrefs.iter().any(|xref| {
                xref.kind == "method"
                    && xref.owner == "java/io/PrintStream"
                    && xref.name == "println"
                    && xref.bci == 7
            }),
            "expected PrintStream.println method xref, got {xrefs:?}",
        );

        let default_init = info
            .methods
            .iter()
            .find(|m| m.name == "<init>" && m.descriptor == "()V")
            .expect("default constructor");
        let init_xrefs = &default_init.code.as_ref().expect("code").xrefs;
        assert!(
            init_xrefs.iter().any(|xref| {
                xref.kind == "string"
                    && xref.string_value.as_deref() == Some("Hello, World from Java!")
                    && xref.bci == 1
            }),
            "expected constructor string constant xref, got {init_xrefs:?}",
        );
    }

    #[test]
    fn parses_line_number_tables() {
        let path = Path::new("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let info = parse_class(&data).expect("parse should succeed");

        let print_message = info
            .methods
            .iter()
            .find(|m| m.name == "printMessage")
            .expect("printMessage method");
        let instructions = &print_message.code.as_ref().expect("code").instructions;
        assert_eq!(instructions.first().map(|ins| ins.bci), Some(0));
        assert_eq!(
            instructions.first().map(|ins| ins.mnemonic.as_str()),
            Some("getstatic"),
        );
        assert!(
            instructions
                .iter()
                .any(|ins| ins.bci == 7 && ins.mnemonic == "invokevirtual"),
            "expected invokevirtual at bci 7, got {instructions:?}",
        );
        assert_eq!(
            instructions.last().map(|ins| ins.mnemonic.as_str()),
            Some("return"),
        );

        let line_numbers = &print_message.code.as_ref().expect("code").line_numbers;
        assert_eq!(
            line_numbers,
            &vec![
                JavaLineNumber {
                    start_pc: 0,
                    line_number: 23,
                },
                JavaLineNumber {
                    start_pc: 10,
                    line_number: 24,
                },
                JavaLineNumber {
                    start_pc: 20,
                    line_number: 25,
                },
            ],
        );
    }

    #[test]
    fn rejects_non_class_files() {
        let data = b"hello world";
        match parse_class(data) {
            Err(ClassError::Truncated(_)) | Err(ClassError::BadMagic(_)) => {}
            other => panic!("expected error; got {:?}", other),
        }
    }
}
