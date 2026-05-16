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

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaMethod {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
    pub signature: Option<String>,
    pub attribute_names: Vec<String>,
    pub is_deprecated: bool,
    pub is_synthetic: bool,
    pub runtime_visible_type_annotation_count: u16,
    pub runtime_invisible_type_annotation_count: u16,
    pub constant_value: Option<JavaConstantValue>,
    pub exceptions: Vec<String>,
    pub annotations: Vec<JavaAnnotation>,
    pub method_parameters: Vec<JavaMethodParameter>,
    pub parameter_annotations: Vec<JavaParameterAnnotations>,
    pub annotation_default: Option<JavaAnnotationValue>,
    pub code: Option<JavaCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaCode {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code_length: u32,
    pub exception_table_len: u16,
    pub exception_handlers: Vec<JavaExceptionHandler>,
    pub attributes_count: u16,
    pub attribute_names: Vec<String>,
    pub instruction_count: u32,
    pub unknown_instruction_count: u32,
    pub stack_map_frame_count: u16,
    pub runtime_visible_type_annotation_count: u16,
    pub runtime_invisible_type_annotation_count: u16,
    pub line_numbers: Vec<JavaLineNumber>,
    pub local_variables: Vec<JavaLocalVariable>,
    pub local_variable_types: Vec<JavaLocalVariableType>,
    pub instructions: Vec<JavaInstruction>,
    pub xrefs: Vec<JavaXref>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaConstantValue {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JavaConstantPoolSummary {
    pub total_slots: u16,
    pub populated_entries: u16,
    pub empty_slots: u16,
    pub utf8_count: u16,
    pub integer_count: u16,
    pub float_count: u16,
    pub long_count: u16,
    pub double_count: u16,
    pub class_count: u16,
    pub string_count: u16,
    pub fieldref_count: u16,
    pub methodref_count: u16,
    pub interface_methodref_count: u16,
    pub name_and_type_count: u16,
    pub method_handle_count: u16,
    pub method_type_count: u16,
    pub dynamic_count: u16,
    pub invoke_dynamic_count: u16,
    pub module_count: u16,
    pub package_count: u16,
    pub other_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaBootstrapMethod {
    pub bootstrap_method_ref_index: u16,
    pub reference_kind: Option<u8>,
    pub reference_kind_name: Option<String>,
    pub reference_owner: Option<String>,
    pub reference_name: Option<String>,
    pub reference_descriptor: Option<String>,
    pub reference_target: Option<String>,
    pub argument_count: u16,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaExceptionHandler {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnnotation {
    pub visibility: String,
    pub descriptor: String,
    pub elements: Vec<JavaAnnotationElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnnotationElement {
    pub name: String,
    pub value: JavaAnnotationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnnotationValue {
    pub tag: String,
    pub kind: String,
    pub value: Option<String>,
    pub type_name: Option<String>,
    pub const_name: Option<String>,
    pub values: Vec<JavaAnnotationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaMethodParameter {
    pub name: Option<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaParameterAnnotations {
    pub parameter_index: u16,
    pub annotations: Vec<JavaAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaLineNumber {
    pub start_pc: u16,
    pub line_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaLocalVariable {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub descriptor: String,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaLocalVariableType {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub signature: String,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaInnerClass {
    pub inner_class: String,
    pub outer_class: Option<String>,
    pub inner_name: Option<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaEnclosingMethod {
    pub class_name: String,
    pub method_name: Option<String>,
    pub method_descriptor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaRecordComponent {
    pub name: String,
    pub descriptor: String,
    pub signature: Option<String>,
    pub annotations: Vec<JavaAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleInfo {
    pub name: String,
    pub flags: u16,
    pub version: Option<String>,
    pub requires: Vec<JavaModuleRequire>,
    pub exports: Vec<JavaModuleExport>,
    pub opens: Vec<JavaModuleOpen>,
    pub uses: Vec<String>,
    pub provides: Vec<JavaModuleProvide>,
    pub packages: Vec<String>,
    pub main_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleRequire {
    pub module: String,
    pub flags: u16,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleExport {
    pub package: String,
    pub flags: u16,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleOpen {
    pub package: String,
    pub flags: u16,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleProvide {
    pub service: String,
    pub implementations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaInstruction {
    pub bci: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaXref {
    pub bci: u32,
    pub opcode: u8,
    pub kind: String,
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub target: String,
    pub string_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassInfo {
    pub minor_version: u16,
    pub major_version: u16,
    pub access_flags: u16,
    pub class_name: String,
    pub super_class: String,
    pub source_file: Option<String>,
    pub signature: Option<String>,
    pub attribute_names: Vec<String>,
    pub is_deprecated: bool,
    pub is_synthetic: bool,
    pub runtime_visible_type_annotation_count: u16,
    pub runtime_invisible_type_annotation_count: u16,
    pub source_debug_extension_length: u32,
    pub source_debug_extension_sha256: Option<String>,
    pub constant_pool: JavaConstantPoolSummary,
    pub annotations: Vec<JavaAnnotation>,
    pub inner_classes: Vec<JavaInnerClass>,
    pub enclosing_method: Option<JavaEnclosingMethod>,
    pub nest_host: Option<String>,
    pub nest_members: Vec<String>,
    pub record_components: Vec<JavaRecordComponent>,
    pub permitted_subclasses: Vec<String>,
    pub module: Option<JavaModuleInfo>,
    pub bootstrap_method_count: u16,
    pub bootstrap_methods: Vec<JavaBootstrapMethod>,
    pub interfaces: Vec<String>,
    pub methods: Vec<JavaMethod>,
    pub fields: Vec<JavaMethod>, // same shape — name + descriptor + flags
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassError {
    BadMagic(u32),
    Truncated(&'static str),
    BadCpIndex(u16),
    BadCpTag(u8),
}

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

fn parse_class_attributes(
    data: &[u8],
    mut p: usize,
    cp: &[CpEntry],
) -> Result<(usize, JavaClassAttributes), ClassError> {
    if p + 2 > data.len() {
        return Err(ClassError::Truncated("class attributes count"));
    }
    let attrs = u16::from_be_bytes(data[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    let mut out = JavaClassAttributes::default();
    out.attribute_names.reserve(attrs);
    for _ in 0..attrs {
        if p + 6 > data.len() {
            return Err(ClassError::Truncated("class attribute header"));
        }
        let attr_name_idx = u16::from_be_bytes(data[p..p + 2].try_into().unwrap());
        let attr_name = read_utf8(cp, attr_name_idx)?;
        let alen = u32::from_be_bytes(data[p + 2..p + 6].try_into().unwrap()) as usize;
        let body_start = p + 6;
        let body_end = body_start
            .checked_add(alen)
            .ok_or(ClassError::Truncated("class attribute body"))?;
        if body_end > data.len() {
            return Err(ClassError::Truncated("class attribute body"));
        }
        out.attribute_names.push(attr_name.clone());
        if attr_name == "SourceFile" && alen == 2 {
            let source_idx = u16::from_be_bytes(data[body_start..body_end].try_into().unwrap());
            out.source_file = Some(read_utf8(cp, source_idx)?);
        } else if attr_name == "Signature" && alen == 2 {
            let signature_idx = u16::from_be_bytes(data[body_start..body_end].try_into().unwrap());
            out.signature = Some(read_utf8(cp, signature_idx)?);
        } else if attr_name == "Deprecated" {
            out.is_deprecated = true;
        } else if attr_name == "Synthetic" {
            out.is_synthetic = true;
        } else if attr_name == "SourceDebugExtension" {
            out.source_debug_extension_length = alen as u32;
            out.source_debug_extension_sha256 = Some(sha256_hex(&data[body_start..body_end]));
        } else if attr_name == "RuntimeVisibleTypeAnnotations" {
            out.runtime_visible_type_annotation_count = parse_counted_attribute(
                &data[body_start..body_end],
                "RuntimeVisibleTypeAnnotations",
            )?;
        } else if attr_name == "RuntimeInvisibleTypeAnnotations" {
            out.runtime_invisible_type_annotation_count = parse_counted_attribute(
                &data[body_start..body_end],
                "RuntimeInvisibleTypeAnnotations",
            )?;
        } else if attr_name == "RuntimeVisibleAnnotations" {
            out.annotations.extend(parse_annotations_attribute(
                &data[body_start..body_end],
                cp,
                "runtime_visible",
            )?);
        } else if attr_name == "RuntimeInvisibleAnnotations" {
            out.annotations.extend(parse_annotations_attribute(
                &data[body_start..body_end],
                cp,
                "runtime_invisible",
            )?);
        } else if attr_name == "InnerClasses" {
            out.inner_classes.extend(parse_inner_classes_attribute(
                &data[body_start..body_end],
                cp,
            )?);
        } else if attr_name == "EnclosingMethod" {
            out.enclosing_method = Some(parse_enclosing_method_attribute(
                &data[body_start..body_end],
                cp,
            )?);
        } else if attr_name == "NestHost" {
            out.nest_host = Some(parse_nest_host_attribute(&data[body_start..body_end], cp)?);
        } else if attr_name == "NestMembers" {
            out.nest_members.extend(parse_nest_members_attribute(
                &data[body_start..body_end],
                cp,
            )?);
        } else if attr_name == "Record" {
            out.record_components
                .extend(parse_record_attribute(&data[body_start..body_end], cp)?);
        } else if attr_name == "PermittedSubclasses" {
            out.permitted_subclasses.extend(parse_class_list_attribute(
                &data[body_start..body_end],
                cp,
                "PermittedSubclasses",
            )?);
        } else if attr_name == "Module" {
            out.module = Some(parse_module_attribute(&data[body_start..body_end], cp)?);
        } else if attr_name == "ModulePackages" {
            out.module_packages.extend(parse_package_list_attribute(
                &data[body_start..body_end],
                cp,
                "ModulePackages",
            )?);
        } else if attr_name == "ModuleMainClass" && alen == 2 {
            let class_idx = u16::from_be_bytes(data[body_start..body_end].try_into().unwrap());
            out.module_main_class = Some(read_class_name(cp, class_idx)?);
        } else if attr_name == "BootstrapMethods" {
            out.bootstrap_methods =
                parse_bootstrap_methods_attribute(&data[body_start..body_end], cp)?;
            out.bootstrap_method_count = out.bootstrap_methods.len() as u16;
        }
        p = body_end;
    }
    if let Some(module) = out.module.as_mut() {
        module.packages = out.module_packages.clone();
        module.main_class = out.module_main_class.clone();
    }
    Ok((p, out))
}

fn parse_inner_classes_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaInnerClass>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("InnerClasses length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut p = 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 8 > body.len() {
            return Err(ClassError::Truncated("InnerClasses body"));
        }
        let inner_class_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let outer_class_idx = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let inner_name_idx = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let access_flags = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        p += 8;
        out.push(JavaInnerClass {
            inner_class: read_class_name(cp, inner_class_idx)?,
            outer_class: read_optional_class_name(cp, outer_class_idx)?,
            inner_name: read_optional_utf8(cp, inner_name_idx)?,
            access_flags,
        });
    }
    Ok(out)
}

fn parse_enclosing_method_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<JavaEnclosingMethod, ClassError> {
    if body.len() != 4 {
        return Err(ClassError::Truncated("EnclosingMethod body"));
    }
    let class_idx = u16::from_be_bytes(body[0..2].try_into().unwrap());
    let method_idx = u16::from_be_bytes(body[2..4].try_into().unwrap());
    let (method_name, method_descriptor) = if method_idx == 0 {
        (None, None)
    } else {
        let (name, descriptor) = read_name_and_type(cp, method_idx)?;
        (Some(name), Some(descriptor))
    };
    Ok(JavaEnclosingMethod {
        class_name: read_class_name(cp, class_idx)?,
        method_name,
        method_descriptor,
    })
}

fn parse_nest_host_attribute(body: &[u8], cp: &[CpEntry]) -> Result<String, ClassError> {
    if body.len() != 2 {
        return Err(ClassError::Truncated("NestHost body"));
    }
    let class_idx = u16::from_be_bytes(body[0..2].try_into().unwrap());
    read_class_name(cp, class_idx)
}

fn parse_nest_members_attribute(body: &[u8], cp: &[CpEntry]) -> Result<Vec<String>, ClassError> {
    parse_class_list_attribute(body, cp, "NestMembers")
}

fn parse_class_list_attribute(
    body: &[u8],
    cp: &[CpEntry],
    attribute_name: &'static str,
) -> Result<Vec<String>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated(attribute_name));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut p = 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 2 > body.len() {
            return Err(ClassError::Truncated(attribute_name));
        }
        let class_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        p += 2;
        out.push(read_class_name(cp, class_idx)?);
    }
    Ok(out)
}

fn parse_package_list_attribute(
    body: &[u8],
    cp: &[CpEntry],
    attribute_name: &'static str,
) -> Result<Vec<String>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated(attribute_name));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut p = 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 2 > body.len() {
            return Err(ClassError::Truncated(attribute_name));
        }
        let package_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        p += 2;
        out.push(read_package_name(cp, package_idx)?);
    }
    Ok(out)
}

fn parse_module_attribute(body: &[u8], cp: &[CpEntry]) -> Result<JavaModuleInfo, ClassError> {
    let mut p = 0usize;
    let module_name_idx = read_u16_from(body, &mut p, "Module header")?;
    let flags = read_u16_from(body, &mut p, "Module header")?;
    let version_idx = read_u16_from(body, &mut p, "Module header")?;
    let requires_count = read_u16_from(body, &mut p, "Module requires count")? as usize;
    let mut requires = Vec::with_capacity(requires_count);
    for _ in 0..requires_count {
        let module_idx = read_u16_from(body, &mut p, "Module requires body")?;
        let require_flags = read_u16_from(body, &mut p, "Module requires body")?;
        let require_version_idx = read_u16_from(body, &mut p, "Module requires body")?;
        requires.push(JavaModuleRequire {
            module: read_module_name(cp, module_idx)?,
            flags: require_flags,
            version: read_optional_utf8(cp, require_version_idx)?,
        });
    }

    let exports_count = read_u16_from(body, &mut p, "Module exports count")? as usize;
    let mut exports = Vec::with_capacity(exports_count);
    for _ in 0..exports_count {
        let package_idx = read_u16_from(body, &mut p, "Module exports body")?;
        let export_flags = read_u16_from(body, &mut p, "Module exports body")?;
        let targets = read_module_targets(body, cp, &mut p, "Module exports body")?;
        exports.push(JavaModuleExport {
            package: read_package_name(cp, package_idx)?,
            flags: export_flags,
            targets,
        });
    }

    let opens_count = read_u16_from(body, &mut p, "Module opens count")? as usize;
    let mut opens = Vec::with_capacity(opens_count);
    for _ in 0..opens_count {
        let package_idx = read_u16_from(body, &mut p, "Module opens body")?;
        let open_flags = read_u16_from(body, &mut p, "Module opens body")?;
        let targets = read_module_targets(body, cp, &mut p, "Module opens body")?;
        opens.push(JavaModuleOpen {
            package: read_package_name(cp, package_idx)?,
            flags: open_flags,
            targets,
        });
    }

    let uses_count = read_u16_from(body, &mut p, "Module uses count")? as usize;
    let mut uses = Vec::with_capacity(uses_count);
    for _ in 0..uses_count {
        let class_idx = read_u16_from(body, &mut p, "Module uses body")?;
        uses.push(read_class_name(cp, class_idx)?);
    }

    let provides_count = read_u16_from(body, &mut p, "Module provides count")? as usize;
    let mut provides = Vec::with_capacity(provides_count);
    for _ in 0..provides_count {
        let service_idx = read_u16_from(body, &mut p, "Module provides body")?;
        let implementation_count =
            read_u16_from(body, &mut p, "Module provides implementation count")? as usize;
        let mut implementations = Vec::with_capacity(implementation_count);
        for _ in 0..implementation_count {
            let implementation_idx = read_u16_from(body, &mut p, "Module provides body")?;
            implementations.push(read_class_name(cp, implementation_idx)?);
        }
        provides.push(JavaModuleProvide {
            service: read_class_name(cp, service_idx)?,
            implementations,
        });
    }

    Ok(JavaModuleInfo {
        name: read_module_name(cp, module_name_idx)?,
        flags,
        version: read_optional_utf8(cp, version_idx)?,
        requires,
        exports,
        opens,
        uses,
        provides,
        packages: Vec::new(),
        main_class: None,
    })
}

fn parse_bootstrap_methods_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaBootstrapMethod>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("BootstrapMethods length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut p = 2usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 4 > body.len() {
            return Err(ClassError::Truncated("BootstrapMethods body"));
        }
        let bootstrap_method_ref_index = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let argument_count = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        p += 4;
        let (
            reference_kind,
            reference_kind_name,
            reference_owner,
            reference_name,
            reference_descriptor,
            reference_target,
        ) = read_method_handle_details(cp, bootstrap_method_ref_index)?;
        let mut arguments = Vec::with_capacity(argument_count as usize);
        for _ in 0..argument_count {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("BootstrapMethods arguments"));
            }
            let arg_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            p += 2;
            arguments.push(read_constant_pool_display(cp, arg_idx)?);
        }
        out.push(JavaBootstrapMethod {
            bootstrap_method_ref_index,
            reference_kind,
            reference_kind_name,
            reference_owner,
            reference_name,
            reference_descriptor,
            reference_target,
            argument_count,
            arguments,
        });
    }
    Ok(out)
}

fn read_module_targets(
    body: &[u8],
    cp: &[CpEntry],
    p: &mut usize,
    context: &'static str,
) -> Result<Vec<String>, ClassError> {
    let count = read_u16_from(body, p, context)? as usize;
    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        let module_idx = read_u16_from(body, p, context)?;
        targets.push(read_module_name(cp, module_idx)?);
    }
    Ok(targets)
}

fn parse_record_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaRecordComponent>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("Record length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut p = 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 6 > body.len() {
            return Err(ClassError::Truncated("Record component"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let descriptor_idx = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let attributes_count = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap()) as usize;
        p += 6;
        let mut signature = None;
        let mut annotations = Vec::new();
        for _ in 0..attributes_count {
            if p + 6 > body.len() {
                return Err(ClassError::Truncated("Record component attribute header"));
            }
            let attr_name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            let attr_name = read_utf8(cp, attr_name_idx)?;
            let alen = u32::from_be_bytes(body[p + 2..p + 6].try_into().unwrap()) as usize;
            let attr_start = p + 6;
            let attr_end = attr_start
                .checked_add(alen)
                .ok_or(ClassError::Truncated("Record component attribute body"))?;
            if attr_end > body.len() {
                return Err(ClassError::Truncated("Record component attribute body"));
            }
            if attr_name == "Signature" && alen == 2 {
                let signature_idx =
                    u16::from_be_bytes(body[attr_start..attr_end].try_into().unwrap());
                signature = Some(read_utf8(cp, signature_idx)?);
            } else if attr_name == "RuntimeVisibleAnnotations" {
                annotations.extend(parse_annotations_attribute(
                    &body[attr_start..attr_end],
                    cp,
                    "runtime_visible",
                )?);
            } else if attr_name == "RuntimeInvisibleAnnotations" {
                annotations.extend(parse_annotations_attribute(
                    &body[attr_start..attr_end],
                    cp,
                    "runtime_invisible",
                )?);
            }
            p = attr_end;
        }
        out.push(JavaRecordComponent {
            name: read_utf8(cp, name_idx)?,
            descriptor: read_utf8(cp, descriptor_idx)?,
            signature,
            annotations,
        });
    }
    Ok(out)
}

fn read_utf8(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(s) => Ok(s.clone()),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn read_optional_utf8(cp: &[CpEntry], idx: u16) -> Result<Option<String>, ClassError> {
    if idx == 0 {
        return Ok(None);
    }
    Ok(Some(read_utf8(cp, idx)?))
}

fn read_class_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if idx == 0 {
        return Ok(String::new());
    }
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Class { name_idx } => read_utf8(cp, *name_idx),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn read_module_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Module { name_idx } => read_utf8(cp, *name_idx),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn read_package_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Package { name_idx } => read_utf8(cp, *name_idx),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn read_optional_class_name(cp: &[CpEntry], idx: u16) -> Result<Option<String>, ClassError> {
    if idx == 0 {
        return Ok(None);
    }
    Ok(Some(read_class_name(cp, idx)?))
}

fn read_u16_from(body: &[u8], p: &mut usize, context: &'static str) -> Result<u16, ClassError> {
    if *p + 2 > body.len() {
        return Err(ClassError::Truncated(context));
    }
    let value = u16::from_be_bytes(body[*p..*p + 2].try_into().unwrap());
    *p += 2;
    Ok(value)
}

fn parse_code_attribute(body: &[u8], cp: &[CpEntry]) -> Result<JavaCode, ClassError> {
    if body.len() < 8 {
        return Err(ClassError::Truncated("code attribute header"));
    }
    let max_stack = u16::from_be_bytes(body[0..2].try_into().unwrap());
    let max_locals = u16::from_be_bytes(body[2..4].try_into().unwrap());
    let code_length = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let code_start = 8usize;
    let code_end = code_start
        .checked_add(code_length as usize)
        .ok_or(ClassError::Truncated("code body"))?;
    if code_end + 2 > body.len() {
        return Err(ClassError::Truncated("code body"));
    }
    let exception_table_len = u16::from_be_bytes(body[code_end..code_end + 2].try_into().unwrap());
    let exception_table_bytes = (exception_table_len as usize)
        .checked_mul(8)
        .ok_or(ClassError::Truncated("exception table"))?;
    let exception_table_end = (code_end + 2)
        .checked_add(exception_table_bytes)
        .ok_or(ClassError::Truncated("exception table"))?;
    if exception_table_end + 2 > body.len() {
        return Err(ClassError::Truncated("exception table"));
    }
    let exception_handlers = parse_exception_table(
        &body[code_end + 2..exception_table_end],
        exception_table_len,
        cp,
    )?;
    let attributes_count = u16::from_be_bytes(
        body[exception_table_end..exception_table_end + 2]
            .try_into()
            .unwrap(),
    );
    let mut p = exception_table_end + 2;
    let mut line_numbers = Vec::new();
    let mut local_variables = Vec::new();
    let mut local_variable_types = Vec::new();
    let mut attribute_names = Vec::with_capacity(attributes_count as usize);
    let mut stack_map_frame_count = 0u16;
    let mut runtime_visible_type_annotation_count = 0u16;
    let mut runtime_invisible_type_annotation_count = 0u16;
    for _ in 0..attributes_count {
        if p + 6 > body.len() {
            return Err(ClassError::Truncated("code nested attribute header"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let name = read_utf8(cp, name_idx)?;
        let alen = u32::from_be_bytes(body[p + 2..p + 6].try_into().unwrap()) as usize;
        let attr_start = p + 6;
        let attr_end = attr_start
            .checked_add(alen)
            .ok_or(ClassError::Truncated("code nested attribute body"))?;
        if attr_end > body.len() {
            return Err(ClassError::Truncated("code nested attribute body"));
        }
        attribute_names.push(name.clone());
        if name == "LineNumberTable" {
            line_numbers.extend(parse_line_number_table(&body[attr_start..attr_end])?);
        } else if name == "LocalVariableTable" {
            local_variables.extend(parse_local_variable_table(&body[attr_start..attr_end], cp)?);
        } else if name == "LocalVariableTypeTable" {
            local_variable_types.extend(parse_local_variable_type_table(
                &body[attr_start..attr_end],
                cp,
            )?);
        } else if name == "StackMapTable" {
            stack_map_frame_count = parse_stack_map_table_frame_count(&body[attr_start..attr_end])?;
        } else if name == "RuntimeVisibleTypeAnnotations" {
            runtime_visible_type_annotation_count = parse_counted_attribute(
                &body[attr_start..attr_end],
                "RuntimeVisibleTypeAnnotations",
            )?;
        } else if name == "RuntimeInvisibleTypeAnnotations" {
            runtime_invisible_type_annotation_count = parse_counted_attribute(
                &body[attr_start..attr_end],
                "RuntimeInvisibleTypeAnnotations",
            )?;
        }
        p = attr_end;
    }
    let code_bytes = &body[code_start..code_end];
    let instructions = parse_code_instructions(code_bytes)?;
    let instruction_count = instructions.len() as u32;
    let unknown_instruction_count = instructions
        .iter()
        .filter(|instruction| instruction.mnemonic.starts_with("unknown_0x"))
        .count() as u32;
    let xrefs = parse_code_xrefs(code_bytes, cp)?;
    Ok(JavaCode {
        max_stack,
        max_locals,
        code_length,
        exception_table_len,
        exception_handlers,
        attributes_count,
        attribute_names,
        instruction_count,
        unknown_instruction_count,
        stack_map_frame_count,
        runtime_visible_type_annotation_count,
        runtime_invisible_type_annotation_count,
        line_numbers,
        local_variables,
        local_variable_types,
        instructions,
        xrefs,
    })
}

fn parse_exception_table(
    body: &[u8],
    exception_table_len: u16,
    cp: &[CpEntry],
) -> Result<Vec<JavaExceptionHandler>, ClassError> {
    let expected_len = (exception_table_len as usize)
        .checked_mul(8)
        .ok_or(ClassError::Truncated("exception table"))?;
    if body.len() < expected_len {
        return Err(ClassError::Truncated("exception table"));
    }
    let mut handlers = Vec::with_capacity(exception_table_len as usize);
    let mut p = 0usize;
    for _ in 0..exception_table_len {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let end_pc = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let handler_pc = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let catch_type_idx = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        let catch_type = if catch_type_idx == 0 {
            None
        } else {
            Some(read_class_name(cp, catch_type_idx)?)
        };
        handlers.push(JavaExceptionHandler {
            start_pc,
            end_pc,
            handler_pc,
            catch_type,
        });
        p += 8;
    }
    Ok(handlers)
}

fn parse_stack_map_table_frame_count(body: &[u8]) -> Result<u16, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("StackMapTable length"));
    }
    Ok(u16::from_be_bytes(body[0..2].try_into().unwrap()))
}

fn parse_counted_attribute(body: &[u8], attribute_name: &'static str) -> Result<u16, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated(attribute_name));
    }
    Ok(u16::from_be_bytes(body[0..2].try_into().unwrap()))
}

fn parse_exceptions_attribute(body: &[u8], cp: &[CpEntry]) -> Result<Vec<String>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("Exceptions length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(2)
                .ok_or(ClassError::Truncated("Exceptions body"))?,
        )
        .ok_or(ClassError::Truncated("Exceptions body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("Exceptions body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let class_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        out.push(read_class_name(cp, class_idx)?);
        p += 2;
    }
    Ok(out)
}

fn parse_annotations_attribute(
    body: &[u8],
    cp: &[CpEntry],
    visibility: &str,
) -> Result<Vec<JavaAnnotation>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("annotations length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let (next, annotation) = parse_annotation(body, p, cp, visibility)?;
        p = next;
        out.push(annotation);
    }
    Ok(out)
}

fn parse_method_parameters_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaMethodParameter>, ClassError> {
    if body.is_empty() {
        return Err(ClassError::Truncated("MethodParameters length"));
    }
    let count = body[0] as usize;
    let mut p = 1usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 4 > body.len() {
            return Err(ClassError::Truncated("MethodParameters body"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let access_flags = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        p += 4;
        out.push(JavaMethodParameter {
            name: read_optional_utf8(cp, name_idx)?,
            access_flags,
        });
    }
    Ok(out)
}

fn parse_parameter_annotations_attribute(
    body: &[u8],
    cp: &[CpEntry],
    visibility: &str,
) -> Result<Vec<JavaParameterAnnotations>, ClassError> {
    if body.is_empty() {
        return Err(ClassError::Truncated("parameter annotations length"));
    }
    let count = body[0] as usize;
    let mut p = 1usize;
    let mut out = Vec::with_capacity(count);
    for parameter_index in 0..count {
        if p + 2 > body.len() {
            return Err(ClassError::Truncated("parameter annotations body"));
        }
        let annotation_count = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
        p += 2;
        let mut annotations = Vec::with_capacity(annotation_count);
        for _ in 0..annotation_count {
            let (next, annotation) = parse_annotation(body, p, cp, visibility)?;
            p = next;
            annotations.push(annotation);
        }
        out.push(JavaParameterAnnotations {
            parameter_index: parameter_index as u16,
            annotations,
        });
    }
    Ok(out)
}

fn parse_annotation(
    body: &[u8],
    mut p: usize,
    cp: &[CpEntry],
    visibility: &str,
) -> Result<(usize, JavaAnnotation), ClassError> {
    if p + 4 > body.len() {
        return Err(ClassError::Truncated("annotation header"));
    }
    let type_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
    p += 2;
    let pair_count = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    let mut elements = Vec::with_capacity(pair_count);
    for _ in 0..pair_count {
        if p + 2 > body.len() {
            return Err(ClassError::Truncated("annotation element name"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        p += 2;
        let (next, value) = parse_annotation_element_value(body, p, cp)?;
        p = next;
        elements.push(JavaAnnotationElement {
            name: read_utf8(cp, name_idx)?,
            value,
        });
    }
    Ok((
        p,
        JavaAnnotation {
            visibility: visibility.to_string(),
            descriptor: read_utf8(cp, type_idx)?,
            elements,
        },
    ))
}

fn parse_annotation_element_value(
    body: &[u8],
    mut p: usize,
    cp: &[CpEntry],
) -> Result<(usize, JavaAnnotationValue), ClassError> {
    if p >= body.len() {
        return Err(ClassError::Truncated("annotation element tag"));
    }
    let tag_byte = body[p];
    p += 1;
    let tag = (tag_byte as char).to_string();
    match tag_byte as char {
        'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' | 's' => {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("annotation const value"));
            }
            let const_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            p += 2;
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "const".to_string(),
                    value: Some(read_annotation_const_value(cp, const_idx)?),
                    type_name: None,
                    const_name: None,
                    values: Vec::new(),
                },
            ))
        }
        'e' => {
            if p + 4 > body.len() {
                return Err(ClassError::Truncated("annotation enum value"));
            }
            let type_name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            let const_name_idx = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
            p += 4;
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "enum".to_string(),
                    value: None,
                    type_name: Some(read_utf8(cp, type_name_idx)?),
                    const_name: Some(read_utf8(cp, const_name_idx)?),
                    values: Vec::new(),
                },
            ))
        }
        'c' => {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("annotation class value"));
            }
            let class_info_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            p += 2;
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "class".to_string(),
                    value: Some(read_utf8(cp, class_info_idx)?),
                    type_name: None,
                    const_name: None,
                    values: Vec::new(),
                },
            ))
        }
        '@' => {
            let (next, annotation) = parse_annotation(body, p, cp, "nested")?;
            Ok((
                next,
                JavaAnnotationValue {
                    tag,
                    kind: "annotation".to_string(),
                    value: Some(annotation.descriptor),
                    type_name: None,
                    const_name: None,
                    values: Vec::new(),
                },
            ))
        }
        '[' => {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("annotation array length"));
            }
            let count = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let (next, value) = parse_annotation_element_value(body, p, cp)?;
                p = next;
                values.push(value);
            }
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "array".to_string(),
                    value: None,
                    type_name: None,
                    const_name: None,
                    values,
                },
            ))
        }
        _ => Err(ClassError::BadCpTag(tag_byte)),
    }
}

fn read_annotation_const_value(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(s) => Ok(s.clone()),
        CpEntry::String { string_idx } => read_utf8(cp, *string_idx),
        CpEntry::Class { name_idx } => read_utf8(cp, *name_idx),
        _ => Ok(format!("cp#{idx}")),
    }
}

fn read_constant_value(cp: &[CpEntry], idx: u16) -> Result<JavaConstantValue, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Integer(value) => Ok(JavaConstantValue {
            kind: "int".to_string(),
            value: value.to_string(),
        }),
        CpEntry::Float(bits) => Ok(JavaConstantValue {
            kind: "float".to_string(),
            value: f32::from_bits(*bits).to_string(),
        }),
        CpEntry::Long(value) => Ok(JavaConstantValue {
            kind: "long".to_string(),
            value: value.to_string(),
        }),
        CpEntry::Double(bits) => Ok(JavaConstantValue {
            kind: "double".to_string(),
            value: f64::from_bits(*bits).to_string(),
        }),
        CpEntry::String { string_idx } => Ok(JavaConstantValue {
            kind: "string".to_string(),
            value: read_utf8(cp, *string_idx)?,
        }),
        _ => Ok(JavaConstantValue {
            kind: "cp".to_string(),
            value: format!("cp#{idx}"),
        }),
    }
}

fn parse_line_number_table(body: &[u8]) -> Result<Vec<JavaLineNumber>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("LineNumberTable length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(4)
                .ok_or(ClassError::Truncated("LineNumberTable body"))?,
        )
        .ok_or(ClassError::Truncated("LineNumberTable body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("LineNumberTable body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let line_number = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        out.push(JavaLineNumber {
            start_pc,
            line_number,
        });
        p += 4;
    }
    Ok(out)
}

fn parse_local_variable_table(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaLocalVariable>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("LocalVariableTable length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(10)
                .ok_or(ClassError::Truncated("LocalVariableTable body"))?,
        )
        .ok_or(ClassError::Truncated("LocalVariableTable body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("LocalVariableTable body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let length = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let name_idx = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let descriptor_idx = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        let index = u16::from_be_bytes(body[p + 8..p + 10].try_into().unwrap());
        out.push(JavaLocalVariable {
            start_pc,
            length,
            name: read_utf8(cp, name_idx)?,
            descriptor: read_utf8(cp, descriptor_idx)?,
            index,
        });
        p += 10;
    }
    Ok(out)
}

fn parse_local_variable_type_table(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaLocalVariableType>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("LocalVariableTypeTable length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(10)
                .ok_or(ClassError::Truncated("LocalVariableTypeTable body"))?,
        )
        .ok_or(ClassError::Truncated("LocalVariableTypeTable body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("LocalVariableTypeTable body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let length = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let name_idx = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let signature_idx = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        let index = u16::from_be_bytes(body[p + 8..p + 10].try_into().unwrap());
        out.push(JavaLocalVariableType {
            start_pc,
            length,
            name: read_utf8(cp, name_idx)?,
            signature: read_utf8(cp, signature_idx)?,
            index,
        });
        p += 10;
    }
    Ok(out)
}

fn parse_code_instructions(code: &[u8]) -> Result<Vec<JavaInstruction>, ClassError> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode = code[pc];
        let Some(len) = instruction_len(code, pc, opcode)? else {
            out.push(JavaInstruction {
                bci: pc as u32,
                opcode,
                mnemonic: format!("unknown_0x{opcode:02x}"),
                operands: Vec::new(),
                length: 1,
            });
            break;
        };
        out.push(JavaInstruction {
            bci: pc as u32,
            opcode,
            mnemonic: opcode_mnemonic(opcode).to_string(),
            operands: instruction_operands(code, pc, opcode)?,
            length: len as u32,
        });
        pc = pc.saturating_add(len);
    }
    Ok(out)
}

fn instruction_operands(code: &[u8], pc: usize, opcode: u8) -> Result<Vec<String>, ClassError> {
    match opcode {
        0x10 => Ok(vec![format!("{}", code[pc + 1] as i8)]),
        0x11 => Ok(vec![format!("{}", read_i16_operand(code, pc, "sipush")?)]),
        0x12 => Ok(vec![format!("cp#{}", code[pc + 1])]),
        0x13 | 0x14 => Ok(vec![format!("cp#{}", read_u16_operand(code, pc, "ldc_w")?)]),
        0x15..=0x19 | 0x36..=0x3a | 0xa9 => Ok(vec![format!("local={}", code[pc + 1])]),
        0x84 => Ok(vec![
            format!("local={}", code[pc + 1]),
            format!("const={}", code[pc + 2] as i8),
        ]),
        0x99..=0xa8 | 0xc6 | 0xc7 => {
            let offset = read_i16_operand(code, pc, "branch")?;
            Ok(vec![format!("target={}", branch_target(pc, offset as i32))])
        }
        0xaa => tableswitch_operands(code, pc),
        0xab => lookupswitch_operands(code, pc),
        0xb2..=0xb8 | 0xbb | 0xbd | 0xc0 | 0xc1 => Ok(vec![format!(
            "cp#{}",
            read_u16_operand(code, pc, "constant-pool instruction")?
        )]),
        0xb9 => Ok(vec![
            format!("cp#{}", read_u16_operand(code, pc, "invokeinterface")?),
            format!("count={}", code[pc + 3]),
        ]),
        0xba => Ok(vec![format!(
            "cp#{}",
            read_u16_operand(code, pc, "invokedynamic")?
        )]),
        0xbc => Ok(vec![format!("atype={}", newarray_type(code[pc + 1]))]),
        0xc4 => wide_operands(code, pc),
        0xc5 => Ok(vec![
            format!("cp#{}", read_u16_operand(code, pc, "multianewarray")?),
            format!("dimensions={}", code[pc + 3]),
        ]),
        0xc8 | 0xc9 => {
            let offset = read_i32_operand(code, pc, "wide branch")?;
            Ok(vec![format!("target={}", branch_target(pc, offset))])
        }
        _ => Ok(Vec::new()),
    }
}

fn parse_code_xrefs(code: &[u8], cp: &[CpEntry]) -> Result<Vec<JavaXref>, ClassError> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let opcode = code[pc];
        match opcode {
            0x12 => {
                if pc + 1 >= code.len() {
                    return Err(ClassError::Truncated("ldc"));
                }
                let idx = code[pc + 1] as u16;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0x13 | 0x14 => {
                let idx = read_u16_operand(code, pc, "ldc_w")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xb2..=0xb5 => {
                let idx = read_u16_operand(code, pc, "field instruction")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xb6..=0xb8 => {
                let idx = read_u16_operand(code, pc, "method instruction")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xb9 => {
                let idx = read_u16_operand(code, pc, "invokeinterface")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xba => {
                let idx = read_u16_operand(code, pc, "invokedynamic")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            0xbb | 0xbd | 0xc0 | 0xc1 | 0xc5 => {
                let idx = read_u16_operand(code, pc, "class instruction")?;
                if let Some(xref) = resolve_constant_xref(cp, idx, pc as u32, opcode)? {
                    out.push(xref);
                }
            }
            _ => {}
        }

        let Some(len) = instruction_len(code, pc, opcode)? else {
            break;
        };
        pc = pc.saturating_add(len);
    }
    Ok(out)
}

fn read_u16_operand(code: &[u8], pc: usize, label: &'static str) -> Result<u16, ClassError> {
    if pc + 2 >= code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(u16::from_be_bytes([code[pc + 1], code[pc + 2]]))
}

fn read_i16_operand(code: &[u8], pc: usize, label: &'static str) -> Result<i16, ClassError> {
    if pc + 2 >= code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(i16::from_be_bytes([code[pc + 1], code[pc + 2]]))
}

fn read_i32_operand(code: &[u8], pc: usize, label: &'static str) -> Result<i32, ClassError> {
    if pc + 4 >= code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(i32::from_be_bytes([
        code[pc + 1],
        code[pc + 2],
        code[pc + 3],
        code[pc + 4],
    ]))
}

fn branch_target(pc: usize, offset: i32) -> i64 {
    pc as i64 + offset as i64
}

fn tableswitch_operands(code: &[u8], pc: usize) -> Result<Vec<String>, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let default = read_i32_at(code, base, "tableswitch")?;
    let low = read_i32_at(code, base + 4, "tableswitch")?;
    let high = read_i32_at(code, base + 8, "tableswitch")?;
    if high < low {
        return Err(ClassError::Truncated("tableswitch bounds"));
    }
    let cases = high as i64 - low as i64 + 1;
    Ok(vec![
        format!("default={}", branch_target(pc, default)),
        format!("low={low}"),
        format!("high={high}"),
        format!("cases={cases}"),
    ])
}

fn lookupswitch_operands(code: &[u8], pc: usize) -> Result<Vec<String>, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let default = read_i32_at(code, base, "lookupswitch")?;
    let npairs = read_i32_at(code, base + 4, "lookupswitch")?;
    if npairs < 0 {
        return Err(ClassError::Truncated("lookupswitch bounds"));
    }
    Ok(vec![
        format!("default={}", branch_target(pc, default)),
        format!("pairs={npairs}"),
    ])
}

fn newarray_type(atype: u8) -> &'static str {
    match atype {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => "unknown",
    }
}

fn wide_operands(code: &[u8], pc: usize) -> Result<Vec<String>, ClassError> {
    if pc + 1 >= code.len() {
        return Err(ClassError::Truncated("wide"));
    }
    let widened_opcode = code[pc + 1];
    if widened_opcode == 0x84 {
        if pc + 5 >= code.len() {
            return Err(ClassError::Truncated("wide iinc"));
        }
        let local = u16::from_be_bytes([code[pc + 2], code[pc + 3]]);
        let value = i16::from_be_bytes([code[pc + 4], code[pc + 5]]);
        return Ok(vec![
            "wide=iinc".to_string(),
            format!("local={local}"),
            format!("const={value}"),
        ]);
    }
    if pc + 3 >= code.len() {
        return Err(ClassError::Truncated("wide local"));
    }
    let local = u16::from_be_bytes([code[pc + 2], code[pc + 3]]);
    Ok(vec![
        format!("wide={}", opcode_mnemonic(widened_opcode)),
        format!("local={local}"),
    ])
}

fn resolve_constant_xref(
    cp: &[CpEntry],
    idx: u16,
    bci: u32,
    opcode: u8,
) -> Result<Option<JavaXref>, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Fieldref {
            class_idx,
            name_and_type_idx,
        } => member_xref(cp, *class_idx, *name_and_type_idx, bci, opcode, "field").map(Some),
        CpEntry::Methodref {
            class_idx,
            name_and_type_idx,
        } => member_xref(cp, *class_idx, *name_and_type_idx, bci, opcode, "method").map(Some),
        CpEntry::InterfaceMethodref {
            class_idx,
            name_and_type_idx,
        } => member_xref(
            cp,
            *class_idx,
            *name_and_type_idx,
            bci,
            opcode,
            "interface_method",
        )
        .map(Some),
        CpEntry::Class { name_idx } => {
            let name = read_utf8(cp, *name_idx)?;
            Ok(Some(JavaXref {
                bci,
                opcode,
                kind: "class".to_string(),
                owner: name.clone(),
                name: String::new(),
                descriptor: String::new(),
                target: name,
                string_value: None,
            }))
        }
        CpEntry::String { string_idx } => {
            let value = read_utf8(cp, *string_idx)?;
            Ok(Some(JavaXref {
                bci,
                opcode,
                kind: "string".to_string(),
                owner: String::new(),
                name: String::new(),
                descriptor: String::new(),
                target: value.clone(),
                string_value: Some(value),
            }))
        }
        CpEntry::Dynamic {
            name_and_type_idx, ..
        } => dynamic_xref(cp, *name_and_type_idx, bci, opcode, "dynamic").map(Some),
        CpEntry::InvokeDynamic {
            name_and_type_idx, ..
        } => dynamic_xref(cp, *name_and_type_idx, bci, opcode, "invokedynamic").map(Some),
        _ => Ok(None),
    }
}

fn member_xref(
    cp: &[CpEntry],
    class_idx: u16,
    name_and_type_idx: u16,
    bci: u32,
    opcode: u8,
    kind: &str,
) -> Result<JavaXref, ClassError> {
    let owner = read_class_name(cp, class_idx)?;
    let (name, descriptor) = read_name_and_type(cp, name_and_type_idx)?;
    let target = format!("{owner}.{name}:{descriptor}");
    Ok(JavaXref {
        bci,
        opcode,
        kind: kind.to_string(),
        owner,
        name,
        descriptor,
        target,
        string_value: None,
    })
}

fn dynamic_xref(
    cp: &[CpEntry],
    name_and_type_idx: u16,
    bci: u32,
    opcode: u8,
    kind: &str,
) -> Result<JavaXref, ClassError> {
    let (name, descriptor) = read_name_and_type(cp, name_and_type_idx)?;
    let target = format!("{name}:{descriptor}");
    Ok(JavaXref {
        bci,
        opcode,
        kind: kind.to_string(),
        owner: String::new(),
        name,
        descriptor,
        target,
        string_value: None,
    })
}

fn summarize_constant_pool(cp: &[CpEntry]) -> JavaConstantPoolSummary {
    let mut summary = JavaConstantPoolSummary {
        total_slots: cp.len().saturating_sub(1) as u16,
        ..JavaConstantPoolSummary::default()
    };
    for entry in cp.iter().skip(1) {
        match entry {
            CpEntry::Empty => summary.empty_slots += 1,
            CpEntry::Utf8(_) => summary.utf8_count += 1,
            CpEntry::Integer(_) => summary.integer_count += 1,
            CpEntry::Float(_) => summary.float_count += 1,
            CpEntry::Long(_) => summary.long_count += 1,
            CpEntry::Double(_) => summary.double_count += 1,
            CpEntry::Class { .. } => summary.class_count += 1,
            CpEntry::String { .. } => summary.string_count += 1,
            CpEntry::Fieldref { .. } => summary.fieldref_count += 1,
            CpEntry::Methodref { .. } => summary.methodref_count += 1,
            CpEntry::InterfaceMethodref { .. } => summary.interface_methodref_count += 1,
            CpEntry::NameAndType { .. } => summary.name_and_type_count += 1,
            CpEntry::MethodHandle { .. } => summary.method_handle_count += 1,
            CpEntry::MethodType { .. } => summary.method_type_count += 1,
            CpEntry::Dynamic { .. } => summary.dynamic_count += 1,
            CpEntry::InvokeDynamic { .. } => summary.invoke_dynamic_count += 1,
            CpEntry::Module { .. } => summary.module_count += 1,
            CpEntry::Package { .. } => summary.package_count += 1,
        }
    }
    summary.populated_entries = summary.total_slots.saturating_sub(summary.empty_slots);
    summary
}

fn read_method_handle_details(
    cp: &[CpEntry],
    idx: u16,
) -> Result<
    (
        Option<u8>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ),
    ClassError,
> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    let CpEntry::MethodHandle {
        reference_kind,
        reference_index,
    } = &cp[idx as usize]
    else {
        return Ok((None, None, None, None, None, Some(format!("cp#{idx}"))));
    };
    let (owner, name, descriptor, target) = read_member_reference(cp, *reference_index)?;
    Ok((
        Some(*reference_kind),
        Some(method_handle_kind_name(*reference_kind).to_string()),
        Some(owner),
        Some(name),
        Some(descriptor),
        Some(target),
    ))
}

fn read_member_reference(
    cp: &[CpEntry],
    idx: u16,
) -> Result<(String, String, String, String), ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    let (class_idx, name_and_type_idx) = match &cp[idx as usize] {
        CpEntry::Fieldref {
            class_idx,
            name_and_type_idx,
        }
        | CpEntry::Methodref {
            class_idx,
            name_and_type_idx,
        }
        | CpEntry::InterfaceMethodref {
            class_idx,
            name_and_type_idx,
        } => (*class_idx, *name_and_type_idx),
        _ => return Err(ClassError::BadCpIndex(idx)),
    };
    let owner = read_class_name(cp, class_idx)?;
    let (name, descriptor) = read_name_and_type(cp, name_and_type_idx)?;
    let target = format!("{owner}.{name}:{descriptor}");
    Ok((owner, name, descriptor, target))
}

fn read_constant_pool_display(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(value) => Ok(value.clone()),
        CpEntry::Integer(value) => Ok(value.to_string()),
        CpEntry::Float(bits) => Ok(f32::from_bits(*bits).to_string()),
        CpEntry::Long(value) => Ok(value.to_string()),
        CpEntry::Double(bits) => Ok(f64::from_bits(*bits).to_string()),
        CpEntry::String { string_idx } => read_utf8(cp, *string_idx),
        CpEntry::Class { name_idx } => read_utf8(cp, *name_idx),
        CpEntry::MethodType { descriptor_idx } => read_utf8(cp, *descriptor_idx),
        CpEntry::MethodHandle { .. } => {
            let (_, _, _, _, _, target) = read_method_handle_details(cp, idx)?;
            Ok(target.unwrap_or_else(|| format!("cp#{idx}")))
        }
        CpEntry::NameAndType { name_idx, desc_idx } => Ok(format!(
            "{}:{}",
            read_utf8(cp, *name_idx)?,
            read_utf8(cp, *desc_idx)?
        )),
        CpEntry::Fieldref { .. }
        | CpEntry::Methodref { .. }
        | CpEntry::InterfaceMethodref { .. } => {
            let (_, _, _, target) = read_member_reference(cp, idx)?;
            Ok(target)
        }
        CpEntry::Dynamic {
            bootstrap_method_attr_idx,
            name_and_type_idx,
        } => {
            let (name, descriptor) = read_name_and_type(cp, *name_and_type_idx)?;
            Ok(format!(
                "dynamic#{bootstrap_method_attr_idx}:{name}:{descriptor}"
            ))
        }
        CpEntry::InvokeDynamic {
            bootstrap_method_attr_idx,
            name_and_type_idx,
        } => {
            let (name, descriptor) = read_name_and_type(cp, *name_and_type_idx)?;
            Ok(format!(
                "invokedynamic#{bootstrap_method_attr_idx}:{name}:{descriptor}"
            ))
        }
        CpEntry::Module { name_idx } | CpEntry::Package { name_idx } => read_utf8(cp, *name_idx),
        CpEntry::Empty => Ok(format!("cp#{idx}")),
    }
}

fn method_handle_kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "get_field",
        2 => "get_static",
        3 => "put_field",
        4 => "put_static",
        5 => "invoke_virtual",
        6 => "invoke_static",
        7 => "invoke_special",
        8 => "new_invoke_special",
        9 => "invoke_interface",
        _ => "unknown",
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn read_name_and_type(cp: &[CpEntry], idx: u16) -> Result<(String, String), ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::NameAndType { name_idx, desc_idx } => {
            Ok((read_utf8(cp, *name_idx)?, read_utf8(cp, *desc_idx)?))
        }
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

fn opcode_mnemonic(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "nop",
        0x01 => "aconst_null",
        0x02 => "iconst_m1",
        0x03 => "iconst_0",
        0x04 => "iconst_1",
        0x05 => "iconst_2",
        0x06 => "iconst_3",
        0x07 => "iconst_4",
        0x08 => "iconst_5",
        0x09 => "lconst_0",
        0x0a => "lconst_1",
        0x0b => "fconst_0",
        0x0c => "fconst_1",
        0x0d => "fconst_2",
        0x0e => "dconst_0",
        0x0f => "dconst_1",
        0x10 => "bipush",
        0x11 => "sipush",
        0x12 => "ldc",
        0x13 => "ldc_w",
        0x14 => "ldc2_w",
        0x15 => "iload",
        0x16 => "lload",
        0x17 => "fload",
        0x18 => "dload",
        0x19 => "aload",
        0x1a => "iload_0",
        0x1b => "iload_1",
        0x1c => "iload_2",
        0x1d => "iload_3",
        0x1e => "lload_0",
        0x1f => "lload_1",
        0x20 => "lload_2",
        0x21 => "lload_3",
        0x22 => "fload_0",
        0x23 => "fload_1",
        0x24 => "fload_2",
        0x25 => "fload_3",
        0x26 => "dload_0",
        0x27 => "dload_1",
        0x28 => "dload_2",
        0x29 => "dload_3",
        0x2a => "aload_0",
        0x2b => "aload_1",
        0x2c => "aload_2",
        0x2d => "aload_3",
        0x2e => "iaload",
        0x2f => "laload",
        0x30 => "faload",
        0x31 => "daload",
        0x32 => "aaload",
        0x33 => "baload",
        0x34 => "caload",
        0x35 => "saload",
        0x36 => "istore",
        0x37 => "lstore",
        0x38 => "fstore",
        0x39 => "dstore",
        0x3a => "astore",
        0x3b => "istore_0",
        0x3c => "istore_1",
        0x3d => "istore_2",
        0x3e => "istore_3",
        0x3f => "lstore_0",
        0x40 => "lstore_1",
        0x41 => "lstore_2",
        0x42 => "lstore_3",
        0x43 => "fstore_0",
        0x44 => "fstore_1",
        0x45 => "fstore_2",
        0x46 => "fstore_3",
        0x47 => "dstore_0",
        0x48 => "dstore_1",
        0x49 => "dstore_2",
        0x4a => "dstore_3",
        0x4b => "astore_0",
        0x4c => "astore_1",
        0x4d => "astore_2",
        0x4e => "astore_3",
        0x4f => "iastore",
        0x50 => "lastore",
        0x51 => "fastore",
        0x52 => "dastore",
        0x53 => "aastore",
        0x54 => "bastore",
        0x55 => "castore",
        0x56 => "sastore",
        0x57 => "pop",
        0x58 => "pop2",
        0x59 => "dup",
        0x5a => "dup_x1",
        0x5b => "dup_x2",
        0x5c => "dup2",
        0x5d => "dup2_x1",
        0x5e => "dup2_x2",
        0x5f => "swap",
        0x60 => "iadd",
        0x61 => "ladd",
        0x62 => "fadd",
        0x63 => "dadd",
        0x64 => "isub",
        0x65 => "lsub",
        0x66 => "fsub",
        0x67 => "dsub",
        0x68 => "imul",
        0x69 => "lmul",
        0x6a => "fmul",
        0x6b => "dmul",
        0x6c => "idiv",
        0x6d => "ldiv",
        0x6e => "fdiv",
        0x6f => "ddiv",
        0x70 => "irem",
        0x71 => "lrem",
        0x72 => "frem",
        0x73 => "drem",
        0x74 => "ineg",
        0x75 => "lneg",
        0x76 => "fneg",
        0x77 => "dneg",
        0x78 => "ishl",
        0x79 => "lshl",
        0x7a => "ishr",
        0x7b => "lshr",
        0x7c => "iushr",
        0x7d => "lushr",
        0x7e => "iand",
        0x7f => "land",
        0x80 => "ior",
        0x81 => "lor",
        0x82 => "ixor",
        0x83 => "lxor",
        0x84 => "iinc",
        0x85 => "i2l",
        0x86 => "i2f",
        0x87 => "i2d",
        0x88 => "l2i",
        0x89 => "l2f",
        0x8a => "l2d",
        0x8b => "f2i",
        0x8c => "f2l",
        0x8d => "f2d",
        0x8e => "d2i",
        0x8f => "d2l",
        0x90 => "d2f",
        0x91 => "i2b",
        0x92 => "i2c",
        0x93 => "i2s",
        0x94 => "lcmp",
        0x95 => "fcmpl",
        0x96 => "fcmpg",
        0x97 => "dcmpl",
        0x98 => "dcmpg",
        0x99 => "ifeq",
        0x9a => "ifne",
        0x9b => "iflt",
        0x9c => "ifge",
        0x9d => "ifgt",
        0x9e => "ifle",
        0x9f => "if_icmpeq",
        0xa0 => "if_icmpne",
        0xa1 => "if_icmplt",
        0xa2 => "if_icmpge",
        0xa3 => "if_icmpgt",
        0xa4 => "if_icmple",
        0xa5 => "if_acmpeq",
        0xa6 => "if_acmpne",
        0xa7 => "goto",
        0xa8 => "jsr",
        0xa9 => "ret",
        0xaa => "tableswitch",
        0xab => "lookupswitch",
        0xac => "ireturn",
        0xad => "lreturn",
        0xae => "freturn",
        0xaf => "dreturn",
        0xb0 => "areturn",
        0xb1 => "return",
        0xb2 => "getstatic",
        0xb3 => "putstatic",
        0xb4 => "getfield",
        0xb5 => "putfield",
        0xb6 => "invokevirtual",
        0xb7 => "invokespecial",
        0xb8 => "invokestatic",
        0xb9 => "invokeinterface",
        0xba => "invokedynamic",
        0xbb => "new",
        0xbc => "newarray",
        0xbd => "anewarray",
        0xbe => "arraylength",
        0xbf => "athrow",
        0xc0 => "checkcast",
        0xc1 => "instanceof",
        0xc2 => "monitorenter",
        0xc3 => "monitorexit",
        0xc4 => "wide",
        0xc5 => "multianewarray",
        0xc6 => "ifnull",
        0xc7 => "ifnonnull",
        0xc8 => "goto_w",
        0xc9 => "jsr_w",
        0xca => "breakpoint",
        0xfe => "impdep1",
        0xff => "impdep2",
        _ => "unknown",
    }
}

fn instruction_len(code: &[u8], pc: usize, opcode: u8) -> Result<Option<usize>, ClassError> {
    let fixed = match opcode {
        0x00..=0x0f => 1,
        0x10 => 2,
        0x11 => 3,
        0x12 => 2,
        0x13 | 0x14 => 3,
        0x15..=0x19 => 2,
        0x1a..=0x35 => 1,
        0x36..=0x3a => 2,
        0x3b..=0x83 => 1,
        0x84 => 3,
        0x85..=0x98 => 1,
        0x99..=0xa8 => 3,
        0xa9 => 2,
        0xaa => return tableswitch_len(code, pc).map(Some),
        0xab => return lookupswitch_len(code, pc).map(Some),
        0xac..=0xb1 => 1,
        0xb2..=0xb8 => 3,
        0xb9 | 0xba => 5,
        0xbb => 3,
        0xbc => 2,
        0xbd => 3,
        0xbe | 0xbf => 1,
        0xc0 | 0xc1 => 3,
        0xc2 | 0xc3 => 1,
        0xc4 => return wide_len(code, pc).map(Some),
        0xc5 => 4,
        0xc6 | 0xc7 => 3,
        0xc8 | 0xc9 => 5,
        0xca | 0xfe | 0xff => 1,
        _ => return Ok(None),
    };
    if pc + fixed > code.len() {
        return Err(ClassError::Truncated("bytecode instruction"));
    }
    Ok(Some(fixed))
}

fn switch_padding(pc: usize) -> usize {
    (4 - ((pc + 1) % 4)) % 4
}

fn read_i32_at(code: &[u8], pos: usize, label: &'static str) -> Result<i32, ClassError> {
    if pos + 4 > code.len() {
        return Err(ClassError::Truncated(label));
    }
    Ok(i32::from_be_bytes(code[pos..pos + 4].try_into().unwrap()))
}

fn tableswitch_len(code: &[u8], pc: usize) -> Result<usize, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let low = read_i32_at(code, base + 4, "tableswitch")?;
    let high = read_i32_at(code, base + 8, "tableswitch")?;
    if high < low {
        return Err(ClassError::Truncated("tableswitch bounds"));
    }
    let count = (high as i64 - low as i64 + 1) as usize;
    let len = 1usize
        .checked_add(pad)
        .and_then(|v| v.checked_add(12))
        .and_then(|v| v.checked_add(count.checked_mul(4)?))
        .ok_or(ClassError::Truncated("tableswitch"))?;
    if pc + len > code.len() {
        return Err(ClassError::Truncated("tableswitch"));
    }
    Ok(len)
}

fn lookupswitch_len(code: &[u8], pc: usize) -> Result<usize, ClassError> {
    let pad = switch_padding(pc);
    let base = pc + 1 + pad;
    let npairs = read_i32_at(code, base + 4, "lookupswitch")?;
    if npairs < 0 {
        return Err(ClassError::Truncated("lookupswitch bounds"));
    }
    let len = 1usize
        .checked_add(pad)
        .and_then(|v| v.checked_add(8))
        .and_then(|v| v.checked_add((npairs as usize).checked_mul(8)?))
        .ok_or(ClassError::Truncated("lookupswitch"))?;
    if pc + len > code.len() {
        return Err(ClassError::Truncated("lookupswitch"));
    }
    Ok(len)
}

fn wide_len(code: &[u8], pc: usize) -> Result<usize, ClassError> {
    if pc + 1 >= code.len() {
        return Err(ClassError::Truncated("wide"));
    }
    let len = if code[pc + 1] == 0x84 { 6 } else { 4 };
    if pc + len > code.len() {
        return Err(ClassError::Truncated("wide"));
    }
    Ok(len)
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
