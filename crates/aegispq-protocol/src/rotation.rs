//! Rotation certificate construction and parsing.
//!
//! A rotation certificate is a dual-signed assertion that an old identity
//! has been superseded by a new one. Both the old and new keys sign the
//! certificate, creating a verifiable chain of custody.

use crate::envelope::{Header, HEADER_SIZE};
use crate::error::ProtocolError;
use crate::identity::IDENTITY_ID_LEN;
use crate::{FormatType, Suite};

/// Domain separator for rotation certificate signatures.
pub const ROTATE_DOMAIN: &[u8] = b"AegisPQ-v1-rotate";

/// A parsed rotation certificate.
///
/// Contains the old identity ID, the new identity's full public key set,
/// and two signatures:
/// - `old_signature`: old key signs new public keys (vouching for the successor)
/// - `new_signature`: new key signs old public keys (vouching for the predecessor)
pub struct RotationCertificate {
    /// The identity being rotated away from.
    pub old_identity_id: [u8; IDENTITY_ID_LEN],
    /// The new identity ID.
    pub new_identity_id: [u8; IDENTITY_ID_LEN],
    /// Unix timestamp when rotation takes effect.
    pub effective_at: u64,
    /// New Ed25519 public key.
    pub new_ed25519_pk: Vec<u8>,
    /// New ML-DSA-65 public key.
    pub new_ml_dsa_pk: Vec<u8>,
    /// New X25519 public key.
    pub new_x25519_pk: Vec<u8>,
    /// New ML-KEM-768 public key.
    pub new_ml_kem_pk: Vec<u8>,
    /// Display name for the new identity.
    pub new_display_name: String,
    /// Signature by the OLD key over the new public keys.
    pub old_signature: Vec<u8>,
    /// Signature by the NEW key over the old public keys.
    pub new_signature: Vec<u8>,
}

impl RotationCertificate {
    /// Construct the bytes that the OLD key signs (the new public keys).
    ///
    /// Format: `old_identity_id || new_identity_id || effective_at || new_ed25519_pk || new_ml_dsa_pk || new_x25519_pk || new_ml_kem_pk`
    pub fn old_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.old_identity_id);
        buf.extend_from_slice(&self.new_identity_id);
        buf.extend_from_slice(&self.effective_at.to_be_bytes());
        write_blob(&mut buf, &self.new_ed25519_pk);
        write_blob(&mut buf, &self.new_ml_dsa_pk);
        write_blob(&mut buf, &self.new_x25519_pk);
        write_blob(&mut buf, &self.new_ml_kem_pk);
        buf
    }

    /// Construct the bytes that the NEW key signs (the old identity reference).
    ///
    /// The new key signs the old identity ID + new identity ID + timestamp
    /// to prove the new key holder authorized this rotation.
    /// We include old_identity_id so the new key is explicitly linked to the predecessor.
    ///
    /// Format: `new_identity_id || old_identity_id || effective_at`
    pub fn new_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(IDENTITY_ID_LEN * 2 + 8);
        buf.extend_from_slice(&self.new_identity_id);
        buf.extend_from_slice(&self.old_identity_id);
        buf.extend_from_slice(&self.effective_at.to_be_bytes());
        buf
    }

    /// Serialize the rotation certificate to bytes with envelope header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Identity IDs and timestamp.
        payload.extend_from_slice(&self.old_identity_id);
        payload.extend_from_slice(&self.new_identity_id);
        payload.extend_from_slice(&self.effective_at.to_be_bytes());

        // New public keys (length-prefixed).
        write_blob(&mut payload, &self.new_ed25519_pk);
        write_blob(&mut payload, &self.new_ml_dsa_pk);
        write_blob(&mut payload, &self.new_x25519_pk);
        write_blob(&mut payload, &self.new_ml_kem_pk);

        // Display name (length-prefixed).
        let name_bytes = self.new_display_name.as_bytes();
        payload.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(name_bytes);

        // Signatures (length-prefixed).
        write_blob(&mut payload, &self.old_signature);
        write_blob(&mut payload, &self.new_signature);

        let header = Header {
            format_type: FormatType::RotationCertificate,
            version: crate::version::CURRENT,
            suite: Suite::HybridV1,
            payload_length: payload.len() as u32,
        };

        let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Parse a rotation certificate from bytes (including envelope header).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let header = Header::from_bytes(bytes)?;

        if header.format_type != FormatType::RotationCertificate {
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
        let mut pos = 0;

        // Old and new identity IDs.
        let old_identity_id = read_fixed::<IDENTITY_ID_LEN>(payload, &mut pos)?;
        let new_identity_id = read_fixed::<IDENTITY_ID_LEN>(payload, &mut pos)?;

        // Timestamp.
        let effective_at = read_u64(payload, &mut pos)?;

        // New public keys.
        let new_ed25519_pk = read_blob(payload, &mut pos)?;
        let new_ml_dsa_pk = read_blob(payload, &mut pos)?;
        let new_x25519_pk = read_blob(payload, &mut pos)?;
        let new_ml_kem_pk = read_blob(payload, &mut pos)?;

        // Display name.
        let new_display_name = read_string(payload, &mut pos)?;

        // Signatures.
        let old_signature = read_blob(payload, &mut pos)?;
        let new_signature = read_blob(payload, &mut pos)?;

        // Reject trailing bytes.
        if pos != payload.len() {
            return Err(ProtocolError::TrailingData {
                expected: pos,
                actual: payload.len(),
            });
        }

        Ok(RotationCertificate {
            old_identity_id,
            new_identity_id,
            effective_at,
            new_ed25519_pk,
            new_ml_dsa_pk,
            new_x25519_pk,
            new_ml_kem_pk,
            new_display_name,
            old_signature,
            new_signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn write_blob(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N], ProtocolError> {
    if *pos + N > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + N,
            actual: data.len(),
        });
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    Ok(arr)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, ProtocolError> {
    if *pos + 2 > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + 2,
            actual: data.len(),
        });
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, ProtocolError> {
    if *pos + 8 > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + 8,
            actual: data.len(),
        });
    }
    let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn read_blob(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, ProtocolError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + len,
            actual: data.len(),
        });
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

fn read_string(data: &[u8], pos: &mut usize) -> Result<String, ProtocolError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(ProtocolError::Truncated {
            expected: *pos + len,
            actual: data.len(),
        });
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len]).map_err(|_| ProtocolError::Truncated {
        expected: *pos + len,
        actual: data.len(),
    })?;
    *pos += len;
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> RotationCertificate {
        RotationCertificate {
            old_identity_id: [0x01; IDENTITY_ID_LEN],
            new_identity_id: [0x02; IDENTITY_ID_LEN],
            effective_at: 1711800000,
            new_ed25519_pk: vec![1; 32],
            new_ml_dsa_pk: vec![2; 1952],
            new_x25519_pk: vec![3; 32],
            new_ml_kem_pk: vec![4; 1184],
            new_display_name: "Alice (rotated)".to_string(),
            old_signature: vec![0xAA; 64],
            new_signature: vec![0xBB; 64],
        }
    }

    #[test]
    fn rotation_certificate_roundtrip() {
        let cert = sample_cert();
        let bytes = cert.to_bytes();
        let parsed = RotationCertificate::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.old_identity_id, cert.old_identity_id);
        assert_eq!(parsed.new_identity_id, cert.new_identity_id);
        assert_eq!(parsed.effective_at, cert.effective_at);
        assert_eq!(parsed.new_ed25519_pk, cert.new_ed25519_pk);
        assert_eq!(parsed.new_ml_dsa_pk, cert.new_ml_dsa_pk);
        assert_eq!(parsed.new_x25519_pk, cert.new_x25519_pk);
        assert_eq!(parsed.new_ml_kem_pk, cert.new_ml_kem_pk);
        assert_eq!(parsed.new_display_name, cert.new_display_name);
        assert_eq!(parsed.old_signature, cert.old_signature);
        assert_eq!(parsed.new_signature, cert.new_signature);
    }

    #[test]
    fn signable_bytes_deterministic() {
        let cert = sample_cert();
        assert_eq!(cert.old_signable_bytes(), cert.old_signable_bytes());
        assert_eq!(cert.new_signable_bytes(), cert.new_signable_bytes());
    }

    #[test]
    fn old_and_new_signable_differ() {
        let cert = sample_cert();
        assert_ne!(cert.old_signable_bytes(), cert.new_signable_bytes());
    }

    #[test]
    fn rejects_wrong_format_type() {
        let cert = sample_cert();
        let mut bytes = cert.to_bytes();
        bytes[4] = 0x01; // EncryptedFile
        assert!(matches!(
            RotationCertificate::from_bytes(&bytes),
            Err(ProtocolError::UnknownFormat { .. })
        ));
    }

    #[test]
    fn rejects_truncated() {
        let cert = sample_cert();
        let bytes = cert.to_bytes();
        assert!(matches!(
            RotationCertificate::from_bytes(&bytes[..HEADER_SIZE + 10]),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_trailing_data() {
        let cert = sample_cert();
        let mut bytes = cert.to_bytes();
        bytes.push(0xFF);
        assert!(matches!(
            RotationCertificate::from_bytes(&bytes),
            Err(ProtocolError::TrailingData { .. })
        ));
    }
}
