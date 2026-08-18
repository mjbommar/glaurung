//! Class-level attributes (JVM Specification 4.7).
//!
//! [`parse_class_attributes`] walks the `attributes` table that follows the
//! method table and decodes the ones that carry class-wide meaning:
//! `InnerClasses`, `EnclosingMethod`, `NestHost`/`NestMembers`,
//! `PermittedSubclasses`, `Module`/`ModulePackages`/`ModuleMainClass`,
//! `BootstrapMethods`, `Record`, and the source/debug strings.

use sha2::{Digest, Sha256};

use super::annotations::parse_annotations_attribute;
use super::code::parse_counted_attribute;
use super::constant_pool::{
    read_class_name, read_constant_pool_display, read_method_handle_details, read_module_name,
    read_name_and_type, read_optional_class_name, read_optional_utf8, read_package_name,
    read_u16_from, read_utf8,
};
use super::types::{
    ClassError, JavaBootstrapMethod, JavaEnclosingMethod, JavaInnerClass, JavaModuleExport,
    JavaModuleInfo, JavaModuleOpen, JavaModuleProvide, JavaModuleRequire, JavaRecordComponent,
};
use super::{CpEntry, JavaClassAttributes};

pub(super) fn parse_class_attributes(
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

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
