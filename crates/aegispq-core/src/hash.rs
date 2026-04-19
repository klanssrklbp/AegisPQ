//! Cryptographic hashing using BLAKE3.
//!
//! BLAKE3 is used for content hashing, key derivation inputs, and
//! transcript hashing. It provides 256-bit output, is not vulnerable
//! to length-extension attacks, and supports keyed hashing.

/// Length of a BLAKE3 hash output in bytes.
pub const HASH_LEN: usize = 32;

/// A BLAKE3 hash output.
pub type Hash = [u8; HASH_LEN];

/// Compute the BLAKE3 hash of the input data.
pub fn blake3_hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Compute a keyed BLAKE3 hash.
///
/// Used for domain-separated hashing where the key provides
/// context separation. The key must be exactly 32 bytes.
pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Compute a BLAKE3 hash over multiple inputs (transcript hashing).
///
/// Each input is hashed in order. This is used for session transcript
/// hashes where multiple protocol messages must be bound together.
pub fn blake3_transcript(parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        // Length-prefix each part to prevent ambiguous concatenation.
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Incremental BLAKE3 hasher for streaming use.
///
/// Wraps the underlying `blake3::Hasher` to allow feeding data in
/// chunks and finalizing once all data has been consumed.
pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Blake3Hasher {
    /// Create a new incremental hasher.
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Feed more data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 32-byte hash.
    pub fn finalize(&self) -> Hash {
        *self.inner.finalize().as_bytes()
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_different_inputs() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn keyed_hash_differs_from_plain() {
        let key = [0x42u8; 32];
        let plain = blake3_hash(b"data");
        let keyed = blake3_keyed(&key, b"data");
        assert_ne!(plain, keyed);
    }

    #[test]
    fn transcript_order_matters() {
        let a = blake3_transcript(&[b"hello", b"world"]);
        let b = blake3_transcript(&[b"world", b"hello"]);
        assert_ne!(a, b);
    }

    #[test]
    fn transcript_length_prefixing_prevents_ambiguity() {
        // "AB" + "C" must differ from "A" + "BC"
        let a = blake3_transcript(&[b"AB", b"C"]);
        let b = blake3_transcript(&[b"A", b"BC"]);
        assert_ne!(a, b);
    }
}
