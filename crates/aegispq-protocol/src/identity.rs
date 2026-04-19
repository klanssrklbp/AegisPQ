//! Identity types and operations.
//!
//! An AegisPQ identity consists of:
//! - A 16-byte identity ID (random UUID)
//! - Hybrid signing keys (Ed25519 + ML-DSA-65)
//! - Hybrid KEM keys (X25519 + ML-KEM-768)
//! - A 32-byte fingerprint (BLAKE3 hash of public keys)

use aegispq_core::hash;
use aegispq_core::nonce;

/// Identity ID length in bytes.
pub const IDENTITY_ID_LEN: usize = 16;

/// Fingerprint length in bytes.
pub const FINGERPRINT_LEN: usize = 32;

/// A 16-byte identity identifier.
pub type IdentityId = [u8; IDENTITY_ID_LEN];

/// A 32-byte identity fingerprint for out-of-band verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; FINGERPRINT_LEN]);

impl Fingerprint {
    /// Display as hex string.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Display as grouped hex (8 groups of 8 hex chars).
    pub fn to_hex_grouped(&self) -> String {
        let hex = self.to_hex();
        hex.as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Parse from hex string.
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.replace(' ', "");
        if hex.len() != FINGERPRINT_LEN * 2 {
            return None;
        }
        let mut bytes = [0u8; FINGERPRINT_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_grouped())
    }
}

/// Compute a fingerprint from public key material.
///
/// The fingerprint is a BLAKE3 hash of the concatenated public keys,
/// with length prefixes to prevent ambiguity.
pub fn compute_fingerprint(
    ed25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    x25519_pk: &[u8],
    ml_kem_pk: &[u8],
) -> Fingerprint {
    let hash = hash::blake3_transcript(&[ed25519_pk, ml_dsa_pk, x25519_pk, ml_kem_pk]);
    Fingerprint(hash)
}

/// Generate a random identity ID.
pub fn generate_identity_id() -> IdentityId {
    // This should never fail on a system with a working CSPRNG.
    nonce::random_bytes::<IDENTITY_ID_LEN>().expect("CSPRNG failure")
}

/// Serialized key package — the public portion of an identity.
///
/// This is what gets shared with other parties for encryption and verification.
#[derive(Clone)]
pub struct KeyPackage {
    /// Random identity identifier.
    pub identity_id: IdentityId,
    /// Human-readable display name (UTF-8, max 256 bytes).
    pub display_name: String,
    /// Ed25519 public key (32 bytes).
    pub ed25519_pk: Vec<u8>,
    /// ML-DSA-65 public key (1,952 bytes).
    pub ml_dsa_pk: Vec<u8>,
    /// X25519 public key (32 bytes).
    pub x25519_pk: Vec<u8>,
    /// ML-KEM-768 public key (1,184 bytes).
    pub ml_kem_pk: Vec<u8>,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Hybrid signature over the serialized key data.
    pub signature: Vec<u8>,
}

impl KeyPackage {
    /// Compute the fingerprint of this key package.
    pub fn fingerprint(&self) -> Fingerprint {
        compute_fingerprint(
            &self.ed25519_pk,
            &self.ml_dsa_pk,
            &self.x25519_pk,
            &self.ml_kem_pk,
        )
    }

    /// Serialize the key package to bytes (without signature, for signing).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.identity_id);
        // Length-prefixed display name.
        let name_bytes = self.display_name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);
        // Public keys (fixed size, but length-prefixed for safety).
        for pk in [
            &self.ed25519_pk,
            &self.ml_dsa_pk,
            &self.x25519_pk,
            &self.ml_kem_pk,
        ] {
            buf.extend_from_slice(&(pk.len() as u16).to_be_bytes());
            buf.extend_from_slice(pk);
        }
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf
    }

    /// Serialize the full key package including the envelope header and signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let signable = self.signable_bytes();
        let sig_bytes = &self.signature;

        // Payload = signable + signature_len(u16) + signature
        let payload_len = signable.len() + 2 + sig_bytes.len();

        let header = crate::envelope::Header {
            format_type: crate::FormatType::KeyPackage,
            version: crate::version::CURRENT,
            suite: crate::Suite::HybridV1,
            payload_length: payload_len as u32,
        };

        let mut out = Vec::with_capacity(crate::envelope::HEADER_SIZE + payload_len);
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&signable);
        out.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(sig_bytes);
        out
    }

    /// Parse a key package from bytes (including envelope header).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        let header = crate::envelope::Header::from_bytes(bytes)?;

        if header.format_type != crate::FormatType::KeyPackage {
            return Err(crate::error::ProtocolError::UnknownFormat {
                found: header.format_type as u8,
            });
        }

        let expected_end = crate::envelope::HEADER_SIZE
            .checked_add(header.payload_length as usize)
            .ok_or(crate::error::ProtocolError::Truncated {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if bytes.len() < expected_end {
            return Err(crate::error::ProtocolError::Truncated {
                expected: expected_end,
                actual: bytes.len(),
            });
        }
        if bytes.len() > expected_end {
            return Err(crate::error::ProtocolError::TrailingData {
                expected: expected_end,
                actual: bytes.len(),
            });
        }
        let payload = &bytes[crate::envelope::HEADER_SIZE..expected_end];
        let min_size = IDENTITY_ID_LEN + 2; // id + name_len
        if payload.len() < min_size {
            return Err(crate::error::ProtocolError::Truncated {
                expected: crate::envelope::HEADER_SIZE + min_size,
                actual: bytes.len(),
            });
        }

        let mut pos = 0;

        // Identity ID.
        let mut identity_id = [0u8; IDENTITY_ID_LEN];
        identity_id.copy_from_slice(&payload[pos..pos + IDENTITY_ID_LEN]);
        pos += IDENTITY_ID_LEN;

        // Display name.
        let name_len = read_u16(payload, &mut pos)? as usize;
        if pos + name_len > payload.len() {
            return Err(crate::error::ProtocolError::Truncated {
                expected: pos + name_len,
                actual: payload.len(),
            });
        }
        let display_name = std::str::from_utf8(&payload[pos..pos + name_len])
            .map_err(|_| crate::error::ProtocolError::Truncated {
                expected: pos + name_len,
                actual: payload.len(),
            })?
            .to_string();
        pos += name_len;

        // Public keys.
        let ed25519_pk = read_length_prefixed(payload, &mut pos)?;
        let ml_dsa_pk = read_length_prefixed(payload, &mut pos)?;
        let x25519_pk = read_length_prefixed(payload, &mut pos)?;
        let ml_kem_pk = read_length_prefixed(payload, &mut pos)?;

        // Timestamp.
        if pos + 8 > payload.len() {
            return Err(crate::error::ProtocolError::Truncated {
                expected: pos + 8,
                actual: payload.len(),
            });
        }
        let created_at = u64::from_be_bytes(payload[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Signature.
        let signature = read_length_prefixed(payload, &mut pos)?;

        // Reject trailing bytes.
        if pos != payload.len() {
            return Err(crate::error::ProtocolError::TrailingData {
                expected: pos,
                actual: payload.len(),
            });
        }

        Ok(KeyPackage {
            identity_id,
            display_name,
            ed25519_pk,
            ml_dsa_pk,
            x25519_pk,
            ml_kem_pk,
            created_at,
            signature,
        })
    }
}

// Helper: read a u16 big-endian value.
fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, crate::error::ProtocolError> {
    if *pos + 2 > data.len() {
        return Err(crate::error::ProtocolError::Truncated {
            expected: *pos + 2,
            actual: data.len(),
        });
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

// Helper: read a length-prefixed byte array (u16 length prefix).
fn read_length_prefixed(
    data: &[u8],
    pos: &mut usize,
) -> Result<Vec<u8>, crate::error::ProtocolError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(crate::error::ProtocolError::Truncated {
            expected: *pos + len,
            actual: data.len(),
        });
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hex_roundtrip() {
        let fp = Fingerprint([0xAB; FINGERPRINT_LEN]);
        let hex = fp.to_hex();
        let parsed = Fingerprint::from_hex(&hex).unwrap();
        assert_eq!(fp, parsed);
    }

    #[test]
    fn fingerprint_display_grouped() {
        let fp = Fingerprint([0x00; FINGERPRINT_LEN]);
        let display = format!("{fp}");
        assert!(display.contains(' '));
        assert_eq!(display.replace(' ', "").len(), 64);
    }

    #[test]
    fn fingerprint_deterministic() {
        let fp1 = compute_fingerprint(b"ed", b"ml", b"x", b"kem");
        let fp2 = compute_fingerprint(b"ed", b"ml", b"x", b"kem");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_changes_with_keys() {
        let fp1 = compute_fingerprint(b"ed1", b"ml", b"x", b"kem");
        let fp2 = compute_fingerprint(b"ed2", b"ml", b"x", b"kem");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn key_package_serialization_roundtrip() {
        let kp = KeyPackage {
            identity_id: [0x42; IDENTITY_ID_LEN],
            display_name: "Alice".to_string(),
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            created_at: 1711800000,
            signature: vec![5; 64],
        };

        let bytes = kp.to_bytes();
        let parsed = KeyPackage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.identity_id, kp.identity_id);
        assert_eq!(parsed.display_name, kp.display_name);
        assert_eq!(parsed.ed25519_pk, kp.ed25519_pk);
        assert_eq!(parsed.ml_dsa_pk, kp.ml_dsa_pk);
        assert_eq!(parsed.x25519_pk, kp.x25519_pk);
        assert_eq!(parsed.ml_kem_pk, kp.ml_kem_pk);
        assert_eq!(parsed.created_at, kp.created_at);
        assert_eq!(parsed.signature, kp.signature);
    }

    #[test]
    fn identity_id_is_random() {
        let id1 = generate_identity_id();
        let id2 = generate_identity_id();
        assert_ne!(id1, id2);
    }
}
