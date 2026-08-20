//! Recovering the program from an image a packer replaced it with.
//!
//! A packed binary contains no analysable program: the code an analyst wants is
//! a compressed blob, and what disassembles is a decompressor stub. Function
//! discovery run over such a file does not fail — it succeeds, on the stub, and
//! returns a handful of real functions that are not the program's. Measured on
//! `tests/realistic_corpus/`, the UPX-packed variant of a binary we built
//! ourselves returned eight functions, none of which was one of the eighty-three
//! we linked in.
//!
//! So this module exists to answer two questions in order:
//!
//! 1. **Is this image packed, and by what?** Always answerable, and reported
//!    even when nothing else can be. `crate::triage::packers` recognises a
//!    packer by signature; [`describe`] goes further for UPX and reads the
//!    container's own record of the original size, method and filter.
//! 2. **Can the original be recovered statically?** For UPX/ELF with NRV
//!    compression and no filter, yes, byte for byte — see [`upx`].
//!
//! What must never happen is the third option: returning an image that is
//! *nearly* the original. Every path here either verifies its output against
//! the checksum the packer recorded, or refuses and says which part it could
//! not handle.

pub mod nrv;
pub mod upx;

/// What we know about a packed image, whether or not it can be unpacked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedImage {
    /// The packer's name, for a report or a log line.
    pub packer: &'static str,
    /// Size of the original file, from the packer's own header.
    pub original_size: u64,
    /// Compression method code, in the packer's numbering.
    pub method: u8,
    /// Filter code; non-zero means branch displacements were rewritten.
    pub filter: u8,
}

/// Identify a packed image from its container, without decompressing it.
///
/// Returns `None` for anything not recognised — which includes images that are
/// merely high-entropy. A guess belongs in `crate::triage::packers`, not here.
pub fn describe(data: &[u8]) -> Option<PackedImage> {
    let header = upx::parse_header(data).ok()?;
    Some(PackedImage {
        packer: "UPX",
        original_size: u64::from(header.original_size),
        method: header.method,
        filter: header.filter,
    })
}

/// The original bytes of a packed image, plus its real entry point.
#[derive(Debug, Clone)]
pub struct Recovered {
    /// The packer we unpacked.
    pub packer: &'static str,
    /// The original file.
    pub bytes: Vec<u8>,
    /// Entry point of the original program, not of the stub.
    pub original_entry: u64,
    /// How many compressed blocks the image was reconstructed from.
    pub blocks: usize,
}

/// A packed image we recognised but could not open.
///
/// This is the case that most needs saying out loud. The bytes are a packer's
/// stub, they disassemble perfectly well, and anything that treats the result as
/// the program is wrong in a way nothing downstream can detect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unrecoverable {
    /// The packer we identified from its own container.
    pub packer: &'static str,
    /// What specifically stopped the unpacking.
    pub reason: String,
}

/// Statically unpack an image if it is packed with something we can undo.
///
/// Args:
///     data: the whole packed file.
///
/// Returns:
///     `Ok(Some(..))` when the original was recovered and verified against the
///     packer's own checksum, `Ok(None)` when the image is not packed with a
///     container we recognise, and `Err(..)` when it *is* recognised but could
///     not be unpacked.
pub fn recover(data: &[u8]) -> Result<Option<Recovered>, Unrecoverable> {
    match upx::unpack(data) {
        Ok(u) => Ok(Some(Recovered {
            packer: "UPX",
            original_entry: u.original_entry,
            blocks: u.blocks.len(),
            bytes: u.bytes,
        })),
        Err(upx::UpxError::NotUpx) => Ok(None),
        Err(e) => Err(Unrecoverable {
            packer: "UPX",
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unpacked_binary_is_not_described_as_packed() {
        let plain = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00 ordinary bytes";
        assert_eq!(describe(plain), None);
        assert!(matches!(recover(plain), Ok(None)));
    }
}
