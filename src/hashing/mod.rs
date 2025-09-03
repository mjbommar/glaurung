//! Centralized module for cryptographic hashing algorithms.

use sha2::{Digest, Sha256, Sha512};

/// Computes the SHA-256 digest of the given data and returns it as a hex string.
pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Computes the SHA-512 digest of the given data and returns it as a hex string.
pub fn sha512_digest(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Computes the BLAKE3 digest of the given data and returns it as a hex string.
/// BLAKE3 is a high-performance cryptographic hash function.
pub fn blake3_digest(data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &[u8] = b"glaurung-test-string";

    #[test]
    fn test_sha256_digest() {
        let expected = "5b7b224b0214d2d635d4e9b3c74e3a9733c2af63a537b2c2a5b8e3a851d849f8";
        assert_eq!(sha256_digest(TEST_DATA), expected);
    }

    #[test]
    fn test_sha512_digest() {
        let expected = "1a838813c2931e635c23c335ac1f2a330167a215d9e53e3f2619a3144959a50115505a6b15a6327a522de3e5e6d188015a22a2f313572f6b2f7e7f5b8df1354a";
        assert_eq!(sha512_digest(TEST_DATA), expected);
    }

    #[test]
    fn test_blake3_digest() {
        let expected = "11b48e56d363114f7f5f7f45b3c01a735fb21db39b23a123f2b15b5915566a48";
        assert_eq!(blake3_digest(TEST_DATA), expected);
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(
            sha256_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            blake3_digest(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
}
