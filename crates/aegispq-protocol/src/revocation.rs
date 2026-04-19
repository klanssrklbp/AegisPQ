//! Revocation certificate construction and parsing.
//!
//! A revocation certificate is a self-signed assertion that an identity
//! should no longer be used for new encryption or signing operations.
//! Revoked keys can still decrypt old ciphertexts.

use crate::envelope::{Header, HEADER_SIZE};
use crate::error::ProtocolError;
use crate::identity::IDENTITY_ID_LEN;
use crate::{FormatType, Suite};

/// Domain separator for revocation certificate signatures.
pub const REVOKE_DOMAIN: &[u8] = b"AegisPQ-v1-revoke";

/// Reason for revoking an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    /// Key material is believed to be compromised.
    Compromised = 0x01,
    /// Replaced by a newer identity via rotation.
    Superseded = 0x02,
    /// No longer in use (voluntary retirement).
    Retired = 0x03,
}

impl RevocationReason {
    /// Parse from a byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Compromised),
            0x02 => Some(Self::Superseded),
            0x03 => Some(Self::Retired),
            _ => None,
        }
    }

    /// Display name for this reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compromised => "compromised",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
        }
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed revocation certificate.
pub struct RevocationCertificate {
    /// The identity being revoked.
    pub identity_id: [u8; IDENTITY_ID_LEN],
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Unix timestamp when revocation takes effect.
    pub effective_at: u64,
    /// Hybrid signature over the certificate data.
    pub signature: Vec<u8>,
}

impl RevocationCertificate {
    /// Construct the bytes that are signed.
    ///
    /// Format: `identity_id || reason || effective_at`
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(IDENTITY_ID_LEN + 1 + 8);
        buf.extend_from_slice(&self.identity_id);
        buf.push(self.reason as u8);
        buf.extend_from_slice(&self.effective_at.to_be_bytes());
        buf
    }

    /// Serialize the revocation certificate to bytes with envelope header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let signable = self.signable_bytes();

        // Payload = signable + signature_len(u16) + signature
        let payload_len = signable.len() + 2 + self.signature.len();

        let header = Header {
            format_type: FormatType::RevocationCertificate,
            version: crate::version::CURRENT,
            suite: Suite::HybridV1,
            payload_length: payload_len as u32,
        };

        let mut out = Vec::with_capacity(HEADER_SIZE + payload_len);
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&signable);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a revocation certificate from bytes (including envelope header).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let header = Header::from_bytes(bytes)?;

        if header.format_type != FormatType::RevocationCertificate {
            return Err(ProtocolError::UnknownFormat {
                found: header.format_type as u8,
            });
        }

        let expected_end = HEADER_SIZE
            .checked_add(header.payload_length as usize)
            .ok_or(ProtocolError::Truncated {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if bytes.len() < expected_end {
            return Err(ProtocolError::Truncated {
                expected: expected_end,
                actual: bytes.len(),
            });
        }
        if bytes.len() > expected_end {
            return Err(ProtocolError::TrailingData {
                expected: expected_end,
                actual: bytes.len(),
            });
        }

        let payload = &bytes[HEADER_SIZE..expected_end];

        // Minimum: identity_id(16) + reason(1) + effective_at(8) + sig_len(2) = 27
        let min_size = IDENTITY_ID_LEN + 1 + 8 + 2;
        if payload.len() < min_size {
            return Err(ProtocolError::Truncated {
                expected: HEADER_SIZE + min_size,
                actual: bytes.len(),
            });
        }

        let mut pos = 0;

        // Identity ID.
        let mut identity_id = [0u8; IDENTITY_ID_LEN];
        identity_id.copy_from_slice(&payload[pos..pos + IDENTITY_ID_LEN]);
        pos += IDENTITY_ID_LEN;

        // Reason.
        let reason = RevocationReason::from_byte(payload[pos]).ok_or(ProtocolError::Truncated {
            expected: pos + 1,
            actual: payload.len(),
        })?;
        pos += 1;

        // Effective timestamp.
        if pos + 8 > payload.len() {
            return Err(ProtocolError::Truncated {
                expected: pos + 8,
                actual: payload.len(),
            });
        }
        let effective_at = u64::from_be_bytes(payload[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Signature (u16 length prefix).
        if pos + 2 > payload.len() {
            return Err(ProtocolError::Truncated {
                expected: pos + 2,
                actual: payload.len(),
            });
        }
        let sig_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;

        if pos + sig_len > payload.len() {
            return Err(ProtocolError::Truncated {
                expected: pos + sig_len,
                actual: payload.len(),
            });
        }
        let signature = payload[pos..pos + sig_len].to_vec();
        pos += sig_len;

        // Reject trailing bytes.
        if pos != payload.len() {
            return Err(ProtocolError::TrailingData {
                expected: pos,
                actual: payload.len(),
            });
        }

        Ok(RevocationCertificate {
            identity_id,
            reason,
            effective_at,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_certificate_roundtrip() {
        let cert = RevocationCertificate {
            identity_id: [0x42; IDENTITY_ID_LEN],
            reason: RevocationReason::Compromised,
            effective_at: 1711800000,
            signature: vec![0xAA; 64],
        };

        let bytes = cert.to_bytes();
        let parsed = RevocationCertificate::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.identity_id, cert.identity_id);
        assert_eq!(parsed.reason, cert.reason);
        assert_eq!(parsed.effective_at, cert.effective_at);
        assert_eq!(parsed.signature, cert.signature);
    }

    #[test]
    fn revocation_reason_display() {
        assert_eq!(RevocationReason::Compromised.as_str(), "compromised");
        assert_eq!(RevocationReason::Superseded.as_str(), "superseded");
        assert_eq!(RevocationReason::Retired.as_str(), "retired");
    }

    #[test]
    fn revocation_reason_roundtrip() {
        for reason in [
            RevocationReason::Compromised,
            RevocationReason::Superseded,
            RevocationReason::Retired,
        ] {
            assert_eq!(RevocationReason::from_byte(reason as u8), Some(reason));
        }
        assert_eq!(RevocationReason::from_byte(0xFF), None);
    }

    #[test]
    fn rejects_wrong_format_type() {
        let cert = RevocationCertificate {
            identity_id: [0x42; IDENTITY_ID_LEN],
            reason: RevocationReason::Retired,
            effective_at: 1711800000,
            signature: vec![0xAA; 64],
        };
        let mut bytes = cert.to_bytes();
        // Overwrite format type to EncryptedFile (0x01).
        bytes[4] = 0x01;
        assert!(matches!(
            RevocationCertificate::from_bytes(&bytes),
            Err(ProtocolError::UnknownFormat { .. })
        ));
    }

    #[test]
    fn rejects_truncated() {
        let cert = RevocationCertificate {
            identity_id: [0x42; IDENTITY_ID_LEN],
            reason: RevocationReason::Retired,
            effective_at: 1711800000,
            signature: vec![0xAA; 64],
        };
        let bytes = cert.to_bytes();
        // Truncate the payload.
        assert!(matches!(
            RevocationCertificate::from_bytes(&bytes[..HEADER_SIZE + 5]),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_trailing_data() {
        let cert = RevocationCertificate {
            identity_id: [0x42; IDENTITY_ID_LEN],
            reason: RevocationReason::Retired,
            effective_at: 1711800000,
            signature: vec![0xAA; 64],
        };
        let mut bytes = cert.to_bytes();
        bytes.push(0xFF);
        assert!(matches!(
            RevocationCertificate::from_bytes(&bytes),
            Err(ProtocolError::TrailingData { .. })
        ));
    }

    #[test]
    fn signable_bytes_deterministic() {
        let cert = RevocationCertificate {
            identity_id: [0x42; IDENTITY_ID_LEN],
            reason: RevocationReason::Compromised,
            effective_at: 1711800000,
            signature: vec![],
        };
        assert_eq!(cert.signable_bytes(), cert.signable_bytes());
        assert_eq!(cert.signable_bytes().len(), IDENTITY_ID_LEN + 1 + 8);
    }
}
