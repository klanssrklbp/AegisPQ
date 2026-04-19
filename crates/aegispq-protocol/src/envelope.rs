//! Envelope header parsing and construction.
//!
//! Every AegisPQ data object begins with a 12-byte fixed header:
//!
//! ```text
//! Offset  Size  Field
//! 0       4     Magic: 0x41 0x50 0x51 0x01
//! 4       1     Format type
//! 5       2     Protocol version (big-endian u16)
//! 7       1     Suite identifier
//! 8       4     Payload length (big-endian u32)
//! 12      ...   Payload
//! ```

use crate::error::ProtocolError;
use crate::{version, FormatType, Suite, MAGIC};

/// Size of the envelope header in bytes.
pub const HEADER_SIZE: usize = 12;

/// Maximum payload size: 4 GiB.
pub const MAX_PAYLOAD_SIZE: u32 = u32::MAX;

/// A parsed envelope header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// The format type of this envelope.
    pub format_type: FormatType,
    /// The protocol version.
    pub version: u16,
    /// The algorithm suite.
    pub suite: Suite,
    /// The payload length in bytes.
    pub payload_length: u32,
}

impl Header {
    /// Serialize the header to 12 bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = self.format_type as u8;
        buf[5..7].copy_from_slice(&self.version.to_be_bytes());
        buf[7] = self.suite as u8;
        buf[8..12].copy_from_slice(&self.payload_length.to_be_bytes());
        buf
    }

    /// Parse a header from bytes.
    ///
    /// Returns an error for unknown versions, suites, or format types.
    /// **No silent fallback.** Unknown values are hard rejections.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ProtocolError::Truncated {
                expected: HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        // Verify magic bytes.
        if bytes[0..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        // Parse and validate format type.
        let format_type = FormatType::from_byte(bytes[4]).ok_or(ProtocolError::UnknownFormat {
            found: bytes[4],
        })?;

        // Parse and validate version.
        let ver = u16::from_be_bytes([bytes[5], bytes[6]]);
        if ver < version::MIN_SUPPORTED || ver > version::CURRENT {
            return Err(ProtocolError::UnsupportedVersion {
                found: ver,
                max_supported: version::CURRENT,
            });
        }

        // Parse and validate suite.
        let suite = Suite::from_byte(bytes[7]).ok_or(ProtocolError::UnsupportedSuite {
            found: bytes[7],
        })?;

        // Parse payload length.
        let payload_length = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        Ok(Header {
            format_type,
            version: ver,
            suite,
            payload_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1,
            payload_length: 1024,
        };

        let bytes = header.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.format_type, header.format_type);
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.suite, header.suite);
        assert_eq!(parsed.payload_length, header.payload_length);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut bytes = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1,
            payload_length: 0,
        }
        .to_bytes();
        bytes[0] = 0xFF;

        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(ProtocolError::InvalidMagic)
        ));
    }

    #[test]
    fn header_rejects_unknown_format() {
        let mut bytes = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1,
            payload_length: 0,
        }
        .to_bytes();
        bytes[4] = 0xFF;

        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(ProtocolError::UnknownFormat { found: 0xFF })
        ));
    }

    #[test]
    fn header_rejects_future_version() {
        let mut bytes = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1,
            payload_length: 0,
        }
        .to_bytes();
        // Set version to 999.
        bytes[5..7].copy_from_slice(&999u16.to_be_bytes());

        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn header_rejects_unknown_suite() {
        let mut bytes = Header {
            format_type: FormatType::EncryptedFile,
            version: 1,
            suite: Suite::HybridV1,
            payload_length: 0,
        }
        .to_bytes();
        bytes[7] = 0xFF;

        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(ProtocolError::UnsupportedSuite { found: 0xFF })
        ));
    }

    #[test]
    fn header_rejects_truncated() {
        assert!(matches!(
            Header::from_bytes(&[0x41, 0x50]),
            Err(ProtocolError::Truncated { .. })
        ));
    }
}
