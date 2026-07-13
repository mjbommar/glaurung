//! Dalvik Executable (DEX) parser.
//!
//! DEX is the bytecode container produced by `d8`/`dx` and bundled inside every
//! APK/AAB as `classes*.dex`. This parser exposes the cross-reference tables
//! (strings, types, prototypes, fields, methods, class defs) that make the app
//! and framework layer enumerable: class names, method signatures, and the
//! string pool that anchors most static analysis of an Android app.
//!
//! It is a read-only, bounds-checked, zero-copy parser over the DEX id sections;
//! it deliberately does not (yet) decode `code_item` instruction streams.
//!
//! Layout reference: <https://source.android.com/docs/core/runtime/dex-format>.

pub mod strings;
pub mod types;

use strings::{decode_mutf8, read_uleb128};
pub use types::*;

/// Read a little-endian `u16` at `off` with bounds checking.
fn u16le(data: &[u8], off: usize) -> Result<u16> {
    let b = data.get(off..off + 2).ok_or(DexError::Truncated {
        offset: off,
        needed: 2,
    })?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Read a little-endian `u32` at `off` with bounds checking.
fn u32le(data: &[u8], off: usize) -> Result<u32> {
    let b = data.get(off..off + 4).ok_or(DexError::Truncated {
        offset: off,
        needed: 4,
    })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A parsed DEX file.
pub struct DexParser<'a> {
    data: &'a [u8],
    header: DexHeader,
}

impl<'a> DexParser<'a> {
    /// True if `data` begins with a recognisable DEX magic.
    pub fn is_dex(data: &[u8]) -> bool {
        data.len() >= 8
            && &data[0..4] == DEX_MAGIC_PREFIX
            && data[7] == 0
            && data[4..7].iter().all(|b| b.is_ascii_digit())
    }

    /// Parse a DEX file header. Does not eagerly walk the id tables.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(DexError::Truncated {
                offset: 0,
                needed: HEADER_SIZE,
            });
        }
        if &data[0..4] != DEX_MAGIC_PREFIX || data[7] != 0 {
            return Err(DexError::InvalidMagic);
        }
        let version = [data[4], data[5], data[6]];
        if !version.iter().all(|b| b.is_ascii_digit()) {
            return Err(DexError::InvalidMagic);
        }

        let endian_tag = u32le(data, 40)?;
        if endian_tag != ENDIAN_CONSTANT {
            if endian_tag == REVERSE_ENDIAN_CONSTANT {
                return Err(DexError::MalformedHeader(
                    "big-endian DEX is not supported".into(),
                ));
            }
            return Err(DexError::MalformedHeader(format!(
                "unexpected endian_tag {endian_tag:#x}"
            )));
        }

        let header = DexHeader {
            version,
            checksum: u32le(data, 8)?,
            signature: data[12..32].try_into().unwrap(),
            file_size: u32le(data, 32)?,
            header_size: u32le(data, 36)?,
            endian_tag,
            link_size: u32le(data, 44)?,
            link_off: u32le(data, 48)?,
            map_off: u32le(data, 52)?,
            string_ids_size: u32le(data, 56)?,
            string_ids_off: u32le(data, 60)?,
            type_ids_size: u32le(data, 64)?,
            type_ids_off: u32le(data, 68)?,
            proto_ids_size: u32le(data, 72)?,
            proto_ids_off: u32le(data, 76)?,
            field_ids_size: u32le(data, 80)?,
            field_ids_off: u32le(data, 84)?,
            method_ids_size: u32le(data, 88)?,
            method_ids_off: u32le(data, 92)?,
            class_defs_size: u32le(data, 96)?,
            class_defs_off: u32le(data, 100)?,
            data_size: u32le(data, 104)?,
            data_off: u32le(data, 108)?,
        };

        Ok(Self { data, header })
    }

    /// Parsed header.
    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    /// Number of strings in the string pool.
    pub fn string_count(&self) -> u32 {
        self.header.string_ids_size
    }

    /// Resolve string `idx` from the string pool.
    pub fn string(&self, idx: u32) -> Result<String> {
        if idx >= self.header.string_ids_size {
            return Err(DexError::IndexOutOfRange {
                table: "string_ids",
                index: idx,
            });
        }
        let id_off = self.header.string_ids_off as usize + idx as usize * 4;
        let data_off = u32le(self.data, id_off)? as usize;
        let (utf16_len, consumed) = read_uleb128(self.data, data_off)?;
        decode_mutf8(self.data, data_off + consumed, utf16_len as usize)
    }

    /// Iterate over every string in the pool (index, value). Invalid strings are
    /// skipped so a single bad entry does not abort enumeration.
    pub fn strings(&self) -> impl Iterator<Item = (u32, String)> + '_ {
        (0..self.header.string_ids_size).filter_map(move |i| self.string(i).ok().map(|s| (i, s)))
    }

    /// Resolve a type descriptor (e.g. `"Lcom/example/Foo;"`) by type index.
    pub fn type_descriptor(&self, type_idx: u32) -> Result<String> {
        if type_idx >= self.header.type_ids_size {
            return Err(DexError::IndexOutOfRange {
                table: "type_ids",
                index: type_idx,
            });
        }
        let off = self.header.type_ids_off as usize + type_idx as usize * 4;
        let string_idx = u32le(self.data, off)?;
        self.string(string_idx)
    }

    /// Number of class definitions.
    pub fn class_def_count(&self) -> u32 {
        self.header.class_defs_size
    }

    /// Read the `n`-th `class_def_item`.
    pub fn class_def(&self, n: u32) -> Result<ClassDef> {
        if n >= self.header.class_defs_size {
            return Err(DexError::IndexOutOfRange {
                table: "class_defs",
                index: n,
            });
        }
        let off = self.header.class_defs_off as usize + n as usize * 32;
        Ok(ClassDef {
            class_idx: u32le(self.data, off)?,
            access_flags: u32le(self.data, off + 4)?,
            superclass_idx: u32le(self.data, off + 8)?,
            interfaces_off: u32le(self.data, off + 12)?,
            source_file_idx: u32le(self.data, off + 16)?,
            annotations_off: u32le(self.data, off + 20)?,
            class_data_off: u32le(self.data, off + 24)?,
            static_values_off: u32le(self.data, off + 28)?,
        })
    }

    /// Iterate over all class definitions.
    pub fn class_defs(&self) -> impl Iterator<Item = ClassDef> + '_ {
        (0..self.header.class_defs_size).filter_map(move |i| self.class_def(i).ok())
    }

    /// Fully-qualified descriptor of a class definition, e.g. `Lcom/example/Foo;`.
    pub fn class_name(&self, def: &ClassDef) -> Result<String> {
        self.type_descriptor(def.class_idx)
    }

    /// Read the `n`-th `method_id_item`.
    pub fn method_id(&self, n: u32) -> Result<MethodId> {
        if n >= self.header.method_ids_size {
            return Err(DexError::IndexOutOfRange {
                table: "method_ids",
                index: n,
            });
        }
        let off = self.header.method_ids_off as usize + n as usize * 8;
        Ok(MethodId {
            class_idx: u16le(self.data, off)?,
            proto_idx: u16le(self.data, off + 2)?,
            name_idx: u32le(self.data, off + 4)?,
        })
    }

    /// Number of method references.
    pub fn method_count(&self) -> u32 {
        self.header.method_ids_size
    }

    /// Read the `n`-th `field_id_item`.
    pub fn field_id(&self, n: u32) -> Result<FieldId> {
        if n >= self.header.field_ids_size {
            return Err(DexError::IndexOutOfRange {
                table: "field_ids",
                index: n,
            });
        }
        let off = self.header.field_ids_off as usize + n as usize * 8;
        Ok(FieldId {
            class_idx: u16le(self.data, off)?,
            type_idx: u16le(self.data, off + 2)?,
            name_idx: u32le(self.data, off + 4)?,
        })
    }

    /// Read the `n`-th `proto_id_item`.
    pub fn proto_id(&self, n: u32) -> Result<ProtoId> {
        if n >= self.header.proto_ids_size {
            return Err(DexError::IndexOutOfRange {
                table: "proto_ids",
                index: n,
            });
        }
        let off = self.header.proto_ids_off as usize + n as usize * 12;
        Ok(ProtoId {
            shorty_idx: u32le(self.data, off)?,
            return_type_idx: u32le(self.data, off + 4)?,
            parameters_off: u32le(self.data, off + 8)?,
        })
    }

    /// Human-readable method reference `Lclass;->name(params)ret`.
    ///
    /// Parameter and return types come from the referenced prototype. Returns a
    /// best-effort rendering; malformed indices produce `?` placeholders rather
    /// than an error, so this is safe to call while enumerating.
    pub fn method_signature(&self, n: u32) -> Result<String> {
        let m = self.method_id(n)?;
        let class = self
            .type_descriptor(m.class_idx as u32)
            .unwrap_or_else(|_| "?".into());
        let name = self.string(m.name_idx).unwrap_or_else(|_| "?".into());
        let proto = self.proto_id(m.proto_idx as u32)?;
        let ret = self
            .type_descriptor(proto.return_type_idx)
            .unwrap_or_else(|_| "?".into());
        let params = self.proto_parameters(&proto).unwrap_or_default();
        Ok(format!("{class}->{name}({}){ret}", params.join("")))
    }

    /// Resolve the parameter type descriptors of a prototype via its `type_list`.
    fn proto_parameters(&self, proto: &ProtoId) -> Result<Vec<String>> {
        if proto.parameters_off == 0 {
            return Ok(Vec::new());
        }
        let off = proto.parameters_off as usize;
        let size = u32le(self.data, off)? as usize;
        let mut out = Vec::with_capacity(size);
        for i in 0..size {
            // type_item entries are u16 after the u32 size.
            let type_idx = u16le(self.data, off + 4 + i * 2)? as u32;
            out.push(
                self.type_descriptor(type_idx)
                    .unwrap_or_else(|_| "?".into()),
            );
        }
        Ok(out)
    }

    /// Convenience: descriptors of every defined class.
    pub fn class_names(&self) -> Vec<String> {
        self.class_defs()
            .filter_map(|d| self.class_name(&d).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests;
