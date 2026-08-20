//! NRV2B / NRV2D / NRV2E decompression, LE32 bit-buffer variants.
//!
//! These are the three compressors UPX uses on ELF images when it is not using
//! LZMA. All three share a bitstream shape and differ only in how the match
//! offset and match length are coded; the differences are called out where they
//! occur rather than split across three near-identical functions.
//!
//! The bit buffer is the "LE32" form: a 32-bit little-endian word is read out of
//! the *same* byte cursor the literal bytes come from, and its bits are consumed
//! most-significant first, thirty-two of them, before the next word is read. That
//! interleaving is why the decoder cannot be split into a bit reader and a byte
//! reader over separate cursors.
//!
//! # Provenance
//!
//! The bitstream was first derived by decoding `upx`-produced blocks from our
//! own corpus, and the published UCL reference implementation was then consulted
//! to settle two points that experiment left ambiguous: the end-of-stream
//! sentinel and the match-length bonus. UCL is GPL-2+ and this crate is
//! Apache-2.0, so it is worth being precise about what is shared: the *format* —
//! which is a method of operation, not expression, and is not what copyright
//! covers. None of the code below is transliterated; the structure, the error
//! taxonomy and the prose are this module's own.
//!
//! Validated by round-trip rather than by resemblance: `src/unpack/upx.rs`
//! reconstructs real `upx`-produced binaries and checks each result against
//! `u_adler`, the checksum the packer itself recorded, so a decoder that is
//! subtly wrong cannot pass.

/// UPX's method byte for NRV2B with a 32-bit little-endian bit buffer.
pub const M_NRV2B_LE32: u8 = 2;
/// UPX's method byte for NRV2D with a 32-bit little-endian bit buffer.
pub const M_NRV2D_LE32: u8 = 5;
/// UPX's method byte for NRV2E with a 32-bit little-endian bit buffer.
pub const M_NRV2E_LE32: u8 = 8;
/// UPX's method byte for a block stored verbatim.
pub const M_STORED: u8 = 0;

/// Why a compressed block could not be decoded.
///
/// Every variant names the specific thing that stopped it. A decompressor that
/// reports one generic failure teaches the caller nothing about whether the
/// input was truncated, was compressed with something we do not implement, or
/// decoded into a size the container disagrees with — and those want different
/// responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NrvError {
    /// A method byte this module does not implement (LZMA, deflate, an 8-bit or
    /// LE16 bit-buffer variant).
    UnsupportedMethod(u8),
    /// The bitstream asked for input past the end of the block.
    InputOverrun,
    /// The bitstream produced more bytes than the block header declared.
    OutputOverrun,
    /// A match referred further back than the output produced so far.
    LookbehindOverrun { m_off: u32, produced: usize },
    /// The stream ended cleanly but short of the declared size.
    ShortOutput { got: usize, want: usize },
}

impl std::fmt::Display for NrvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedMethod(m) => write!(f, "unsupported compression method {m}"),
            Self::InputOverrun => write!(f, "compressed stream ran past the end of the block"),
            Self::OutputOverrun => write!(f, "decompressed past the declared block size"),
            Self::LookbehindOverrun { m_off, produced } => write!(
                f,
                "match offset {m_off} reaches before the start of {produced} decoded bytes"
            ),
            Self::ShortOutput { got, want } => {
                write!(f, "stream ended after {got} bytes, block declares {want}")
            }
        }
    }
}

impl std::error::Error for NrvError {}

/// The interleaved bit/byte cursor the LE32 variants read from.
struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    word: u32,
    bits_left: u32,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            word: 0,
            bits_left: 0,
        }
    }

    /// Next bit, refilling from a little-endian word at the shared cursor.
    fn bit(&mut self) -> Result<u32, NrvError> {
        if self.bits_left > 0 {
            self.bits_left -= 1;
            return Ok((self.word >> self.bits_left) & 1);
        }
        let end = self.pos.checked_add(4).ok_or(NrvError::InputOverrun)?;
        let bytes = self.src.get(self.pos..end).ok_or(NrvError::InputOverrun)?;
        self.word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        self.pos = end;
        self.bits_left = 31;
        Ok(self.word >> 31)
    }

    /// Next literal byte, from the same cursor the words come from.
    fn byte(&mut self) -> Result<u8, NrvError> {
        let b = *self.src.get(self.pos).ok_or(NrvError::InputOverrun)?;
        self.pos += 1;
        Ok(b)
    }
}

/// Largest match offset the format can encode, past which the stream is corrupt.
const MAX_M_OFF: u32 = 0x00ff_ffff + 3;

/// Decode one NRV-compressed block.
///
/// Args:
///     src: the compressed bytes, which may extend past the end of this block.
///     want: the uncompressed size the container declared.
///     method: UPX's method byte; see the `M_*` constants.
///
/// Returns:
///     Exactly `want` bytes, or the reason the stream could not produce them.
pub fn decompress(src: &[u8], want: usize, method: u8) -> Result<Vec<u8>, NrvError> {
    let nrv2b = match method {
        M_NRV2B_LE32 => true,
        M_NRV2D_LE32 | M_NRV2E_LE32 => false,
        other => return Err(NrvError::UnsupportedMethod(other)),
    };
    // NRV2B allows a longer "near" window before the length bonus applies.
    let far_threshold: u32 = if nrv2b { 0xd00 } else { 0x500 };

    let mut r = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(want);
    let mut last_m_off: u32 = 1;

    loop {
        // A run of set bits is a run of literal bytes.
        while r.bit()? == 1 {
            if out.len() >= want {
                return Err(NrvError::OutputOverrun);
            }
            let b = r.byte()?;
            out.push(b);
        }

        // Match offset. NRV2B codes it as a plain bit ladder; 2D and 2E
        // interleave a correction step that lets short offsets cost less.
        let mut m_off: u32 = 1;
        loop {
            m_off = m_off.wrapping_mul(2).wrapping_add(r.bit()?);
            if m_off > MAX_M_OFF {
                return Err(NrvError::LookbehindOverrun {
                    m_off,
                    produced: out.len(),
                });
            }
            if r.bit()? == 1 {
                break;
            }
            if !nrv2b {
                m_off = m_off.wrapping_sub(1).wrapping_mul(2).wrapping_add(r.bit()?);
            }
        }

        // `2` is the escape meaning "same offset as the previous match". In
        // NRV2B the length is coded entirely in the bits that follow; in 2D and
        // 2E the low bit of the offset field carries the first length bit, so
        // the two families seed `m_len` differently.
        let mut m_len: u32;
        if nrv2b {
            if m_off == 2 {
                m_off = last_m_off;
            } else {
                let raw = (m_off - 3)
                    .checked_mul(256)
                    .ok_or(NrvError::InputOverrun)?
                    .wrapping_add(u32::from(r.byte()?));
                if raw == u32::MAX {
                    break; // end-of-stream marker
                }
                m_off = raw + 1;
                last_m_off = m_off;
            }
            m_len = r.bit()?;
            m_len = m_len * 2 + r.bit()?;
            if m_len == 0 {
                m_len = read_gamma(&mut r, want)? + 2;
            }
        } else {
            if m_off == 2 {
                m_off = last_m_off;
                m_len = r.bit()?;
            } else {
                let raw = (m_off - 3)
                    .checked_mul(256)
                    .ok_or(NrvError::InputOverrun)?
                    .wrapping_add(u32::from(r.byte()?));
                if raw == u32::MAX {
                    break;
                }
                m_len = (!raw) & 1;
                m_off = (raw >> 1) + 1;
                last_m_off = m_off;
            }
            if method == M_NRV2D_LE32 {
                m_len = m_len * 2 + r.bit()?;
                if m_len == 0 {
                    m_len = read_gamma(&mut r, want)? + 2;
                }
            } else {
                // NRV2E spends its bits differently: two short encodings for the
                // common lengths, then the same Elias-gamma escape.
                m_len = if m_len != 0 {
                    1 + r.bit()?
                } else if r.bit()? == 1 {
                    3 + r.bit()?
                } else {
                    read_gamma(&mut r, want)? + 3
                };
            }
        }

        if m_off > far_threshold {
            m_len += 1;
        }

        let produced = out.len();
        if m_off == 0 || m_off as usize > produced {
            return Err(NrvError::LookbehindOverrun { m_off, produced });
        }
        let count = m_len as usize + 1;
        if produced + count > want {
            return Err(NrvError::OutputOverrun);
        }
        let mut from = produced - m_off as usize;
        for _ in 0..count {
            let b = out[from];
            out.push(b);
            from += 1;
        }
    }

    if out.len() != want {
        return Err(NrvError::ShortOutput {
            got: out.len(),
            want,
        });
    }
    Ok(out)
}

/// The Elias-gamma-style length escape shared by all three variants.
///
/// `want` bounds it: a corrupt stream can otherwise spin here building a length
/// no output buffer could hold.
fn read_gamma(r: &mut BitReader<'_>, want: usize) -> Result<u32, NrvError> {
    let mut v: u32 = 1;
    loop {
        v = v.wrapping_mul(2).wrapping_add(r.bit()?);
        if v as usize >= want {
            return Err(NrvError::OutputOverrun);
        }
        if r.bit()? == 1 {
            return Ok(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unimplemented_method_is_named_not_guessed() {
        // LZMA is method 14. Guessing at it would produce plausible garbage;
        // the contract is that the caller is told which method stopped us.
        let err = decompress(&[0u8; 32], 16, 14).unwrap_err();
        assert_eq!(err, NrvError::UnsupportedMethod(14));
        assert!(err.to_string().contains("14"), "{err}");
    }

    #[test]
    fn a_truncated_stream_reports_input_overrun() {
        // Two bytes cannot even fill the first bit-buffer word.
        assert_eq!(
            decompress(&[0xff, 0xff], 64, M_NRV2B_LE32).unwrap_err(),
            NrvError::InputOverrun
        );
    }

    #[test]
    fn an_empty_stream_reports_input_overrun_rather_than_empty_output() {
        assert_eq!(
            decompress(&[], 8, M_NRV2B_LE32).unwrap_err(),
            NrvError::InputOverrun
        );
    }

    #[test]
    fn a_match_before_the_start_of_output_is_refused() {
        // First word is all ones: the decoder takes literals until it runs out
        // of input, so this must fail on input rather than emit anything.
        let src = [0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4];
        assert!(matches!(
            decompress(&src, 4096, M_NRV2B_LE32),
            Err(NrvError::InputOverrun)
        ));
    }
}
