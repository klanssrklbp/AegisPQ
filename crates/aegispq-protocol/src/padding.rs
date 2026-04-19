//! Padding schemes for metadata minimization.
//!
//! Padding hides the exact plaintext size from observers. Without padding,
//! ciphertext length reveals plaintext length (AEAD adds only a fixed overhead).

/// Padding scheme selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PaddingScheme {
    /// Pad to the next power of 2 (minimum 256 bytes).
    /// Good general-purpose choice for hiding file sizes.
    PowerOfTwo = 0x01,
    /// Pad to a fixed block size.
    FixedBlock = 0x02,
    /// No padding. Not recommended — leaks exact plaintext size.
    None = 0x00,
}

impl PaddingScheme {
    /// Parse from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::None),
            0x01 => Some(Self::PowerOfTwo),
            0x02 => Some(Self::FixedBlock),
            _ => None,
        }
    }
}

/// Default fixed block size: 4 KiB.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Minimum padded size for PowerOfTwo scheme.
const MIN_POWER_OF_TWO: usize = 256;

/// Apply padding to plaintext.
///
/// Returns the padded data with a 4-byte big-endian length prefix
/// so the original length can be recovered on decryption.
///
/// Format: `[original_length: u32 BE][plaintext][zero_padding]`
pub fn pad(plaintext: &[u8], scheme: PaddingScheme, block_size: usize) -> Vec<u8> {
    let content_len = 4 + plaintext.len(); // 4-byte length prefix + data
    let padded_len = padded_size(content_len, scheme, block_size);

    let mut output = Vec::with_capacity(padded_len);
    output.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    output.extend_from_slice(plaintext);
    output.resize(padded_len, 0); // Zero-fill padding
    output
}

/// Remove padding and recover the original plaintext.
///
/// Returns `None` if the data is malformed (length prefix exceeds buffer).
pub fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 {
        return None;
    }

    let original_len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

    if 4 + original_len > padded.len() {
        return None;
    }

    Some(padded[4..4 + original_len].to_vec())
}

/// Calculate the padded size for a given content length (including the 4-byte length prefix).
pub fn padded_size(content_len: usize, scheme: PaddingScheme, block_size: usize) -> usize {
    match scheme {
        PaddingScheme::None => content_len,
        PaddingScheme::PowerOfTwo => {
            let min = content_len.max(MIN_POWER_OF_TWO);
            min.next_power_of_two()
        }
        PaddingScheme::FixedBlock => {
            let bs = if block_size == 0 {
                DEFAULT_BLOCK_SIZE
            } else {
                block_size
            };
            ((content_len + bs - 1) / bs) * bs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let data = b"Hello, world!";
        let padded = pad(data, PaddingScheme::PowerOfTwo, 0);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(&recovered, data);
    }

    #[test]
    fn power_of_two_padding_sizes() {
        // 4 (prefix) + 10 (data) = 14 → next pow2 = 256 (minimum)
        let padded = pad(&[0u8; 10], PaddingScheme::PowerOfTwo, 0);
        assert_eq!(padded.len(), 256);

        // 4 + 300 = 304 → next pow2 = 512
        let padded = pad(&[0u8; 300], PaddingScheme::PowerOfTwo, 0);
        assert_eq!(padded.len(), 512);

        // 4 + 1000 = 1004 → next pow2 = 1024
        let padded = pad(&[0u8; 1000], PaddingScheme::PowerOfTwo, 0);
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn fixed_block_padding() {
        let padded = pad(&[0u8; 100], PaddingScheme::FixedBlock, 4096);
        assert_eq!(padded.len(), 4096);

        let padded = pad(&[0u8; 5000], PaddingScheme::FixedBlock, 4096);
        assert_eq!(padded.len(), 8192);
    }

    #[test]
    fn no_padding() {
        let data = b"exact size";
        let padded = pad(data, PaddingScheme::None, 0);
        assert_eq!(padded.len(), 4 + data.len());
        let recovered = unpad(&padded).unwrap();
        assert_eq!(&recovered, data);
    }

    #[test]
    fn unpad_rejects_truncated() {
        assert!(unpad(&[0, 0, 0]).is_none()); // Too short for length prefix
        assert!(unpad(&[0, 0, 0, 10]).is_none()); // Claims 10 bytes but has 0
    }

    #[test]
    fn empty_plaintext() {
        let padded = pad(b"", PaddingScheme::PowerOfTwo, 0);
        let recovered = unpad(&padded).unwrap();
        assert!(recovered.is_empty());
    }
}
