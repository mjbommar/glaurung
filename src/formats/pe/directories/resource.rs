//! Windows resource directory parsing.

use std::collections::HashSet;

use crate::formats::pe::sections::SectionTable;
use crate::formats::pe::types::*;
use crate::formats::pe::utils::{calculate_entropy, ReadExt};
use sha2::{Digest, Sha256};

const RESOURCE_DIRECTORY_HEADER_SIZE: usize = 16;
const RESOURCE_DIRECTORY_ENTRY_SIZE: usize = 8;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const RESOURCE_NAME_FLAG: u32 = 0x8000_0000;
const RESOURCE_OFFSET_MASK: u32 = 0x7fff_ffff;

/// Parse the PE resource directory into bounded, leaf-oriented metadata.
pub fn parse_resources<'a>(
    data: &'a [u8],
    sections: &SectionTable,
    resource_dir: &DataDirectory,
    options: &ParseOptions,
) -> Result<ResourceDirectory<'a>> {
    let mut directory = ResourceDirectory::empty();

    if !options.parse_resources || resource_dir.virtual_address == 0 || resource_dir.size == 0 {
        return Ok(directory);
    }

    if options.max_resources == 0 {
        push_once(&mut directory.stop_reasons, "max_resources");
        return Ok(directory);
    }

    let base_offset =
        sections
            .rva_to_offset(resource_dir.virtual_address)
            .ok_or(PeError::InvalidRva {
                rva: resource_dir.virtual_address,
            })?;

    if base_offset >= data.len() {
        return Err(PeError::InvalidOffset {
            offset: base_offset,
        });
    }

    let mut state = ResourceParseState {
        data,
        sections,
        base_offset,
        resource_section_name: sections
            .section_containing_rva(resource_dir.virtual_address)
            .map(|section| section.header.name()),
        options,
        directory: &mut directory,
        visited_directories: HashSet::new(),
        seen_triplets: HashSet::new(),
        resource_ranges: Vec::new(),
    };

    let mut path = Vec::new();
    state.parse_directory(0, 0, &mut path);

    Ok(directory)
}

struct ResourceParseState<'a, 'out> {
    data: &'a [u8],
    sections: &'out SectionTable,
    base_offset: usize,
    resource_section_name: Option<String>,
    options: &'out ParseOptions,
    directory: &'out mut ResourceDirectory<'a>,
    visited_directories: HashSet<usize>,
    seen_triplets: HashSet<(ResourceIdentifier, ResourceIdentifier, ResourceIdentifier)>,
    resource_ranges: Vec<(usize, usize)>,
}

impl<'a> ResourceParseState<'a, '_> {
    fn parse_directory(
        &mut self,
        relative_offset: usize,
        depth: usize,
        path: &mut Vec<ResourceIdentifier>,
    ) {
        if self.directory.resources.len() >= self.options.max_resources {
            push_once(&mut self.directory.stop_reasons, "max_resources");
            return;
        }

        if depth > self.options.max_resource_depth {
            push_once(&mut self.directory.stop_reasons, "max_resource_depth");
            push_once(&mut self.directory.warnings, "resource_depth_exceeded");
            return;
        }

        if !self.visited_directories.insert(relative_offset) {
            push_once(&mut self.directory.warnings, "resource_directory_cycle");
            return;
        }

        let Some(directory_offset) = self.base_offset.checked_add(relative_offset) else {
            push_once(
                &mut self.directory.warnings,
                "resource_directory_offset_overflow",
            );
            return;
        };

        if directory_offset + RESOURCE_DIRECTORY_HEADER_SIZE > self.data.len() {
            push_once(&mut self.directory.warnings, "truncated_resource_directory");
            return;
        }

        self.directory.total_directories += 1;
        self.directory.max_depth = self.directory.max_depth.max(depth);

        let named_entries = self.data.read_u16_le_at(directory_offset + 12).unwrap_or(0);
        let id_entries = self.data.read_u16_le_at(directory_offset + 14).unwrap_or(0);
        let entry_count = named_entries as usize + id_entries as usize;
        self.directory.total_named_entries += named_entries as usize;
        self.directory.total_id_entries += id_entries as usize;
        self.directory.total_entries += entry_count;
        let entries_offset = directory_offset + RESOURCE_DIRECTORY_HEADER_SIZE;

        for index in 0..entry_count {
            if self.directory.resources.len() >= self.options.max_resources {
                push_once(&mut self.directory.stop_reasons, "max_resources");
                return;
            }

            let entry_offset = entries_offset + (index * RESOURCE_DIRECTORY_ENTRY_SIZE);
            if entry_offset + RESOURCE_DIRECTORY_ENTRY_SIZE > self.data.len() {
                push_once(&mut self.directory.warnings, "truncated_resource_entry");
                return;
            }

            let Some(name_or_id) = self.data.read_u32_le_at(entry_offset) else {
                push_once(&mut self.directory.warnings, "truncated_resource_entry");
                return;
            };
            let Some(offset_to_data) = self.data.read_u32_le_at(entry_offset + 4) else {
                push_once(&mut self.directory.warnings, "truncated_resource_entry");
                return;
            };

            let identifier = self.parse_identifier(name_or_id);
            let child_relative_offset = (offset_to_data & RESOURCE_OFFSET_MASK) as usize;
            path.push(identifier);

            if (offset_to_data & RESOURCE_NAME_FLAG) != 0 {
                self.parse_directory(child_relative_offset, depth + 1, path);
            } else {
                self.parse_data_entry(child_relative_offset, path);
            }

            path.pop();
        }
    }

    fn parse_identifier(&mut self, name_or_id: u32) -> ResourceIdentifier {
        if (name_or_id & RESOURCE_NAME_FLAG) == 0 {
            return ResourceIdentifier::Id(name_or_id);
        }

        let relative_offset = (name_or_id & RESOURCE_OFFSET_MASK) as usize;
        let Some(name_offset) = self.base_offset.checked_add(relative_offset) else {
            push_once(
                &mut self.directory.warnings,
                "resource_name_offset_overflow",
            );
            return ResourceIdentifier::Name(String::new());
        };

        if name_offset + 2 > self.data.len() {
            push_once(&mut self.directory.warnings, "truncated_resource_name");
            return ResourceIdentifier::Name(String::new());
        }

        let length = self.data.read_u16_le_at(name_offset).unwrap_or(0) as usize;
        let chars_offset = name_offset + 2;
        let byte_len = length.saturating_mul(2);
        if chars_offset + byte_len > self.data.len() {
            push_once(&mut self.directory.warnings, "truncated_resource_name");
            return ResourceIdentifier::Name(String::new());
        }

        let mut words = Vec::with_capacity(length);
        for chunk in self.data[chars_offset..chars_offset + byte_len].chunks_exact(2) {
            words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }

        let name = String::from_utf16(&words).unwrap_or_else(|_| String::from_utf16_lossy(&words));
        ResourceIdentifier::Name(name)
    }

    fn parse_data_entry(&mut self, relative_offset: usize, path: &[ResourceIdentifier]) {
        let Some(entry_offset) = self.base_offset.checked_add(relative_offset) else {
            push_once(
                &mut self.directory.warnings,
                "resource_data_entry_offset_overflow",
            );
            return;
        };

        if entry_offset + RESOURCE_DATA_ENTRY_SIZE > self.data.len() {
            push_once(
                &mut self.directory.warnings,
                "truncated_resource_data_entry",
            );
            return;
        }

        let Some(data_rva) = self.data.read_u32_le_at(entry_offset) else {
            push_once(
                &mut self.directory.warnings,
                "truncated_resource_data_entry",
            );
            return;
        };
        let Some(size) = self.data.read_u32_le_at(entry_offset + 4) else {
            push_once(
                &mut self.directory.warnings,
                "truncated_resource_data_entry",
            );
            return;
        };
        let code_page = self.data.read_u32_le_at(entry_offset + 8).unwrap_or(0);

        if size as usize > self.options.max_resource_data_bytes {
            push_once(&mut self.directory.stop_reasons, "max_resource_data_bytes");
            push_once(
                &mut self.directory.warnings,
                "resource_data_budget_exceeded",
            );
            return;
        }

        let Some(data_offset) = self.sections.rva_to_offset(data_rva) else {
            push_once(&mut self.directory.warnings, "invalid_resource_data_rva");
            return;
        };

        let Some(data_end) = data_offset.checked_add(size as usize) else {
            push_once(
                &mut self.directory.warnings,
                "resource_data_offset_overflow",
            );
            return;
        };

        if data_offset > self.data.len() {
            push_once(&mut self.directory.warnings, "invalid_resource_data_offset");
            return;
        }

        let mut warnings = Vec::new();
        let resource_data = if data_end <= self.data.len() {
            &self.data[data_offset..data_end]
        } else {
            warnings.push("truncated_resource_data".to_string());
            &self.data[data_offset..]
        };

        let type_id = path.first().cloned().unwrap_or(ResourceIdentifier::Id(0));
        let name = path.get(1).cloned().unwrap_or(ResourceIdentifier::Id(0));
        let language = path.get(2).cloned().unwrap_or(ResourceIdentifier::Id(0));
        let language_id = language.as_id();
        let type_name = type_id
            .as_id()
            .and_then(resource_type_name)
            .map(str::to_string);
        let section_name = self
            .sections
            .section_containing_rva(data_rva)
            .map(|section| section.header.name());

        if !self
            .seen_triplets
            .insert((type_id.clone(), name.clone(), language.clone()))
        {
            push_once(&mut warnings, "duplicate_resource_triplet");
            push_once(&mut self.directory.warnings, "duplicate_resource_triplet");
        }

        if self
            .resource_ranges
            .iter()
            .any(|&(start, end)| ranges_overlap(data_offset, data_end, start, end))
        {
            push_once(&mut warnings, "overlapping_resource_data");
            push_once(&mut self.directory.warnings, "overlapping_resource_data");
        }
        self.resource_ranges.push((data_offset, data_end));

        if let (Some(resource_section), Some(data_section)) =
            (&self.resource_section_name, &section_name)
        {
            if resource_section != data_section {
                push_once(&mut warnings, "resource_data_outside_resource_section");
                push_once(
                    &mut self.directory.warnings,
                    "resource_data_outside_resource_section",
                );
            }
        }

        self.directory.resources.push(ResourceDataEntry {
            type_id,
            type_name,
            name,
            language,
            language_id,
            code_page,
            data_rva,
            data_offset,
            size,
            section_name,
            entropy: calculate_entropy(resource_data),
            sha256: sha256_digest(resource_data),
            magic: classify_resource_data(resource_data).to_string(),
            data: resource_data,
            warnings,
        });
    }
}

fn resource_type_name(id: u32) -> Option<&'static str> {
    match id {
        1 => Some("CURSOR"),
        2 => Some("BITMAP"),
        3 => Some("ICON"),
        4 => Some("MENU"),
        5 => Some("DIALOG"),
        6 => Some("STRINGTABLE"),
        7 => Some("FONTDIR"),
        8 => Some("FONT"),
        9 => Some("ACCELERATOR"),
        10 => Some("RCDATA"),
        11 => Some("MESSAGETABLE"),
        12 => Some("GROUP_CURSOR"),
        14 => Some("GROUP_ICON"),
        16 => Some("VERSIONINFO"),
        17 => Some("DLGINCLUDE"),
        19 => Some("PLUGPLAY"),
        20 => Some("VXD"),
        21 => Some("ANICURSOR"),
        22 => Some("ANIICON"),
        23 => Some("HTML"),
        24 => Some("MANIFEST"),
        _ => None,
    }
}

fn classify_resource_data(data: &[u8]) -> &'static str {
    if data.is_empty() {
        return "empty";
    }

    if data.starts_with(b"MZ") {
        return "pe";
    }
    if data.starts_with(b"\x7fELF") {
        return "elf";
    }
    if data.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        return "java_class";
    }
    if data.starts_with(b"PK\x03\x04") {
        return "zip";
    }
    if data.starts_with(b"\x1f\x8b") {
        return "gzip";
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "png";
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return "gif";
    }
    if data.starts_with(b"BM") {
        return "bitmap";
    }

    let trimmed = data
        .iter()
        .copied()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<assembly") {
        return "xml";
    }

    if data.iter().all(|byte| {
        byte.is_ascii_graphic()
            || *byte == b' '
            || *byte == b'\t'
            || *byte == b'\r'
            || *byte == b'\n'
    }) {
        return "ascii_text";
    }

    "binary"
}

fn push_once(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < left_end
        && right_start < right_end
        && left_start < right_end
        && right_start < left_end
}

fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
