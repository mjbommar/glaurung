//! Chunk compression for [`super`].
//!
//! Reading is always pure Rust (`ruzstd`), because a wheel that can read a
//! signature library must not need a C toolchain to do it. Writing has three
//! settings, and only the *default* one is load-bearing for determinism.

use super::{Compression, GsigError};

/// How the writer compresses a chunk.
///
/// Every setting emits standard Zstandard frames (or none at all), so the
/// shipped pure-Rust reader decodes all of them identically. The choice is
/// purely a ratio-versus-dependency trade on the *producing* side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoder {
    /// No compression: chunks are stored verbatim. Useful for measuring the
    /// packed encoding on its own, and for a fixture whose bytes should not
    /// move when a compressor is upgraded.
    Store,
    /// `ruzstd`, pure Rust. **The default**, and the codec the golden fixture
    /// is built with, so enabling `gsig-zstd` never moves a committed hash.
    /// ruzstd 0.9 implements only its `Fastest` level (roughly zstd -1);
    /// `Default`/`Better`/`Best` are declared and unimplemented upstream.
    #[default]
    Zstd,
    /// The reference C zstd at level 19. **Builder only** — needs the
    /// `gsig-zstd` feature, which pulls in `zstd-sys` and therefore a C
    /// compiler. This is what a corpus publisher uses; see the container
    /// section of `docs/reference/function-signature-libraries.md` for the
    /// ratio it buys over [`Encoder::Zstd`].
    #[cfg(feature = "gsig-zstd")]
    ZstdMax,
}

impl Encoder {
    /// The name a CLI and `flirt_library_info_path` use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Zstd => "zstd",
            #[cfg(feature = "gsig-zstd")]
            Self::ZstdMax => "zstd-max",
        }
    }

    /// Parse a codec name, or `None` when this build does not have it.
    ///
    /// `"zstd-max"` is deliberately `None` rather than a silent downgrade to
    /// [`Encoder::Zstd`] without the feature: a publisher who asked for the
    /// dense codec and got the fast one would ship 2x the bytes and never
    /// know.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "store" | "none" => Some(Self::Store),
            "zstd" => Some(Self::Zstd),
            #[cfg(feature = "gsig-zstd")]
            "zstd-max" => Some(Self::ZstdMax),
            _ => None,
        }
    }

    /// The [`Compression`] byte a chunk written by this encoder carries.
    pub fn compression(self) -> Compression {
        match self {
            Self::Store => Compression::None,
            _ => Compression::Zstd,
        }
    }

    /// Compress one chunk payload.
    ///
    /// Returns the stored bytes, which the caller records alongside the
    /// *uncompressed* length. A frame that came out no smaller than its input
    /// is **not** stored verbatim: keeping the codec byte a pure function of
    /// the encoder is what makes two writes of one input byte-identical
    /// regardless of how the data happened to compress.
    pub fn compress(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Store => data.to_vec(),
            Self::Zstd => {
                ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
            }
            #[cfg(feature = "gsig-zstd")]
            Self::ZstdMax => {
                // Level 19 is the research report's measurement point. The
                // C library is deterministic at a fixed level and version;
                // `zstd-sys` vendors the version, so the bytes do not move
                // under us when a system package is upgraded.
                zstd::bulk::compress(data, 19).unwrap_or_else(|_| {
                    ruzstd::encoding::compress_to_vec(
                        data,
                        ruzstd::encoding::CompressionLevel::Fastest,
                    )
                })
            }
        }
    }
}

/// Inflate one chunk payload into `out`, which must already be sized to the
/// chunk's recorded `uncompressed_size`.
///
/// Pre-sizing is WARP's rule and the reason `uncompressed_size` is in the
/// chunk table at all: the arena is allocated once, up front, and every chunk
/// decompresses straight into its own slice of it.
pub fn decompress_into(
    compression: Compression,
    data: &[u8],
    out: &mut [u8],
) -> Result<(), GsigError> {
    match compression {
        Compression::None => {
            if data.len() != out.len() {
                return Err(GsigError::Decompress(format!(
                    "stored chunk is {} bytes, table says {}",
                    data.len(),
                    out.len()
                )));
            }
            out.copy_from_slice(data);
            Ok(())
        }
        Compression::Zstd => {
            let mut decoder = ruzstd::decoding::FrameDecoder::new();
            let written = decoder
                .decode_all(data, out)
                .map_err(|e| GsigError::Decompress(e.to_string()))?;
            if written != out.len() {
                return Err(GsigError::Decompress(format!(
                    "chunk inflated to {written} bytes, table says {}",
                    out.len()
                )));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signature data, not lorem ipsum: repeated prologues with a varying
    /// tail, which is what the Patterns section actually looks like.
    fn sample() -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..2000u32 {
            out.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20]);
            out.extend_from_slice(&i.to_le_bytes());
        }
        out
    }

    #[test]
    fn every_encoder_round_trips_through_the_shipped_reader() {
        let data = sample();
        #[allow(unused_mut)]
        let mut encoders = vec![Encoder::Store, Encoder::Zstd];
        #[cfg(feature = "gsig-zstd")]
        encoders.push(Encoder::ZstdMax);
        for encoder in encoders {
            let packed = encoder.compress(&data);
            let mut out = vec![0u8; data.len()];
            decompress_into(encoder.compression(), &packed, &mut out).unwrap();
            assert_eq!(out, data, "{}", encoder.as_str());
        }
    }

    #[test]
    fn compression_is_deterministic() {
        let data = sample();
        assert_eq!(Encoder::Zstd.compress(&data), Encoder::Zstd.compress(&data));
        #[cfg(feature = "gsig-zstd")]
        assert_eq!(
            Encoder::ZstdMax.compress(&data),
            Encoder::ZstdMax.compress(&data)
        );
    }

    #[test]
    fn a_zstd_chunk_is_smaller_than_stored() {
        let data = sample();
        assert!(Encoder::Zstd.compress(&data).len() < data.len());
    }

    #[test]
    fn a_short_inflate_is_an_error_not_a_partial_buffer() {
        let data = sample();
        let packed = Encoder::Zstd.compress(&data);
        let mut out = vec![0u8; data.len() + 16];
        assert!(matches!(
            decompress_into(Compression::Zstd, &packed, &mut out),
            Err(GsigError::Decompress(_))
        ));
    }

    #[test]
    fn codec_names_round_trip() {
        assert_eq!(Encoder::from_name("store"), Some(Encoder::Store));
        assert_eq!(Encoder::from_name("zstd"), Some(Encoder::Zstd));
        assert_eq!(Encoder::from_name("brotli"), None);
        assert_eq!(Encoder::default(), Encoder::Zstd);
        #[cfg(not(feature = "gsig-zstd"))]
        assert_eq!(Encoder::from_name("zstd-max"), None);
        #[cfg(feature = "gsig-zstd")]
        assert_eq!(Encoder::from_name("zstd-max"), Some(Encoder::ZstdMax));
    }
}
