//! Identity and contact record types with binary serialization.
//!
//! Records are the on-disk representation of identities and contacts.
//! They carry public keys in cleartext and private keys as an opaque
//! encrypted blob (produced by [`crate::keystore`]).

use crate::error::StoreError;

/// Magic bytes for identity records: `APQI`.
const IDENTITY_MAGIC: [u8; 4] = [0x41, 0x50, 0x51, 0x49];

/// Magic bytes for contact records: `APQC`.
const CONTACT_MAGIC: [u8; 4] = [0x41, 0x50, 0x51, 0x43];

/// Record format version for identity records.
const IDENTITY_RECORD_VERSION: u16 = 1;

/// Record format version for contact records.
/// Version 2 adds a status field.
const CONTACT_RECORD_VERSION: u16 = 2;

/// Identity status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentityStatus {
    /// Active and usable.
    Active = 0x01,
    /// Rotated — superseded by a newer identity.
    Rotated = 0x02,
    /// Revoked — must not be used.
    Revoked = 0x03,
}

impl IdentityStatus {
    /// Parse from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Active),
            0x02 => Some(Self::Rotated),
            0x03 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A local identity record stored on disk.
///
/// Contains public keys (cleartext) and encrypted private keys.
pub struct IdentityRecord {
    /// 16-byte random identity identifier.
    pub identity_id: [u8; 16],
    /// Human-readable display name.
    pub display_name: String,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Current status of this identity.
    pub status: IdentityStatus,
    /// Ed25519 public key (32 bytes).
    pub ed25519_pk: Vec<u8>,
    /// ML-DSA-65 public key (1,952 bytes).
    pub ml_dsa_pk: Vec<u8>,
    /// X25519 public key (32 bytes).
    pub x25519_pk: Vec<u8>,
    /// ML-KEM-768 public key (1,184 bytes).
    pub ml_kem_pk: Vec<u8>,
    /// Encrypted private key bundle (nonce || ciphertext || tag).
    pub encrypted_private_keys: Vec<u8>,
    /// Argon2id salt (16 bytes).
    pub argon2_salt: [u8; 16],
    /// Argon2id memory cost in KiB.
    pub argon2_memory_kib: u32,
    /// Argon2id iteration count.
    pub argon2_iterations: u32,
    /// Argon2id parallelism.
    pub argon2_parallelism: u32,
}

impl IdentityRecord {
    /// Serialize the identity record to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header.
        buf.extend_from_slice(&IDENTITY_MAGIC);
        buf.extend_from_slice(&IDENTITY_RECORD_VERSION.to_be_bytes());

        // Identity metadata.
        buf.extend_from_slice(&self.identity_id);
        write_string(&mut buf, &self.display_name);
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf.push(self.status as u8);

        // Public keys (length-prefixed).
        write_blob(&mut buf, &self.ed25519_pk);
        write_blob(&mut buf, &self.ml_dsa_pk);
        write_blob(&mut buf, &self.x25519_pk);
        write_blob(&mut buf, &self.ml_kem_pk);

        // Argon2 parameters.
        buf.extend_from_slice(&self.argon2_salt);
        buf.extend_from_slice(&self.argon2_memory_kib.to_be_bytes());
        buf.extend_from_slice(&self.argon2_iterations.to_be_bytes());
        buf.extend_from_slice(&self.argon2_parallelism.to_be_bytes());

        // Encrypted private key bundle (u32 length prefix for large blobs).
        buf.extend_from_slice(&(self.encrypted_private_keys.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.encrypted_private_keys);

        buf
    }

    /// Deserialize an identity record from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, StoreError> {
        let mut pos = 0;

        // Magic.
        let magic = read_fixed::<4>(data, &mut pos)?;
        if magic != IDENTITY_MAGIC {
            return Err(StoreError::CorruptRecord {
                reason: "invalid identity record magic",
            });
        }

        // Version.
        let version = read_u16(data, &mut pos)?;
        if version != IDENTITY_RECORD_VERSION {
            return Err(StoreError::CorruptRecord {
                reason: "unsupported identity record version",
            });
        }

        // Identity metadata.
        let identity_id = read_fixed::<16>(data, &mut pos)?;
        let display_name = read_string(data, &mut pos)?;
        let created_at = read_u64(data, &mut pos)?;
        let status_byte = read_byte(data, &mut pos)?;
        let status = IdentityStatus::from_byte(status_byte).ok_or(StoreError::CorruptRecord {
            reason: "unknown identity status",
        })?;

        // Public keys.
        let ed25519_pk = read_blob(data, &mut pos)?;
        let ml_dsa_pk = read_blob(data, &mut pos)?;
        let x25519_pk = read_blob(data, &mut pos)?;
        let ml_kem_pk = read_blob(data, &mut pos)?;

        // Argon2 parameters.
        let argon2_salt = read_fixed::<16>(data, &mut pos)?;
        let argon2_memory_kib = read_u32(data, &mut pos)?;
        let argon2_iterations = read_u32(data, &mut pos)?;
        let argon2_parallelism = read_u32(data, &mut pos)?;

        // Encrypted private keys.
        let encrypted_private_keys = read_large_blob(data, &mut pos)?;

        Ok(IdentityRecord {
            identity_id,
            display_name,
            created_at,
            status,
            ed25519_pk,
            ml_dsa_pk,
            x25519_pk,
            ml_kem_pk,
            encrypted_private_keys,
            argon2_salt,
            argon2_memory_kib,
            argon2_iterations,
            argon2_parallelism,
        })
    }
}

/// A remote party's public identity, stored locally.
pub struct ContactRecord {
    /// 16-byte identity identifier.
    pub identity_id: [u8; 16],
    /// Human-readable display name.
    pub display_name: String,
    /// Ed25519 public key.
    pub ed25519_pk: Vec<u8>,
    /// ML-DSA-65 public key.
    pub ml_dsa_pk: Vec<u8>,
    /// X25519 public key.
    pub x25519_pk: Vec<u8>,
    /// ML-KEM-768 public key.
    pub ml_kem_pk: Vec<u8>,
    /// Unix timestamp of when the contact was imported.
    pub imported_at: u64,
    /// Current status of this contact (added in record version 2).
    pub status: IdentityStatus,
}

impl ContactRecord {
    /// Serialize the contact record to bytes (version 2).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&CONTACT_MAGIC);
        buf.extend_from_slice(&CONTACT_RECORD_VERSION.to_be_bytes());

        buf.extend_from_slice(&self.identity_id);
        write_string(&mut buf, &self.display_name);

        write_blob(&mut buf, &self.ed25519_pk);
        write_blob(&mut buf, &self.ml_dsa_pk);
        write_blob(&mut buf, &self.x25519_pk);
        write_blob(&mut buf, &self.ml_kem_pk);

        buf.extend_from_slice(&self.imported_at.to_be_bytes());
        buf.push(self.status as u8);

        buf
    }

    /// Deserialize a contact record from bytes.
    ///
    /// Supports version 1 (no status, defaults to Active) and version 2 (with status).
    pub fn from_bytes(data: &[u8]) -> Result<Self, StoreError> {
        let mut pos = 0;

        let magic = read_fixed::<4>(data, &mut pos)?;
        if magic != CONTACT_MAGIC {
            return Err(StoreError::CorruptRecord {
                reason: "invalid contact record magic",
            });
        }

        let version = read_u16(data, &mut pos)?;
        if version != 1 && version != CONTACT_RECORD_VERSION {
            return Err(StoreError::CorruptRecord {
                reason: "unsupported contact record version",
            });
        }

        let identity_id = read_fixed::<16>(data, &mut pos)?;
        let display_name = read_string(data, &mut pos)?;

        let ed25519_pk = read_blob(data, &mut pos)?;
        let ml_dsa_pk = read_blob(data, &mut pos)?;
        let x25519_pk = read_blob(data, &mut pos)?;
        let ml_kem_pk = read_blob(data, &mut pos)?;

        let imported_at = read_u64(data, &mut pos)?;

        // Version 2 adds a status byte; version 1 defaults to Active.
        let status = if version >= 2 {
            let status_byte = read_byte(data, &mut pos)?;
            IdentityStatus::from_byte(status_byte).ok_or(StoreError::CorruptRecord {
                reason: "unknown contact status",
            })?
        } else {
            IdentityStatus::Active
        };

        Ok(ContactRecord {
            identity_id,
            display_name,
            ed25519_pk,
            ml_dsa_pk,
            x25519_pk,
            ml_kem_pk,
            imported_at,
            status,
        })
    }
}

// ---------------------------------------------------------------------------
// Binary serialization helpers
// ---------------------------------------------------------------------------

fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn write_blob(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_byte(data: &[u8], pos: &mut usize) -> Result<u8, StoreError> {
    if *pos >= data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "unexpected end of record",
        });
    }
    let val = data[*pos];
    *pos += 1;
    Ok(val)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, StoreError> {
    if *pos + 2 > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "unexpected end of record",
        });
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, StoreError> {
    if *pos + 4 > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "unexpected end of record",
        });
    }
    let val = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, StoreError> {
    if *pos + 8 > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "unexpected end of record",
        });
    }
    let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N], StoreError> {
    if *pos + N > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "unexpected end of record",
        });
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    Ok(arr)
}

fn read_string(data: &[u8], pos: &mut usize) -> Result<String, StoreError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "string extends past end of record",
        });
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len]).map_err(|_| StoreError::CorruptRecord {
        reason: "invalid UTF-8 in record string",
    })?;
    *pos += len;
    Ok(s.to_string())
}

fn read_blob(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, StoreError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "blob extends past end of record",
        });
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

/// Read a blob with a u32 length prefix (for potentially large data like encrypted keys).
fn read_large_blob(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, StoreError> {
    let len = read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(StoreError::CorruptRecord {
            reason: "large blob extends past end of record",
        });
    }
    let val = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(val)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_record_roundtrip() {
        let record = IdentityRecord {
            identity_id: [0x42; 16],
            display_name: "Alice".to_string(),
            created_at: 1711800000,
            status: IdentityStatus::Active,
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            encrypted_private_keys: vec![5; 200],
            argon2_salt: [0xAA; 16],
            argon2_memory_kib: 262_144,
            argon2_iterations: 3,
            argon2_parallelism: 4,
        };

        let bytes = record.to_bytes();
        let parsed = IdentityRecord::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.identity_id, record.identity_id);
        assert_eq!(parsed.display_name, record.display_name);
        assert_eq!(parsed.created_at, record.created_at);
        assert_eq!(parsed.status, record.status);
        assert_eq!(parsed.ed25519_pk, record.ed25519_pk);
        assert_eq!(parsed.ml_dsa_pk, record.ml_dsa_pk);
        assert_eq!(parsed.x25519_pk, record.x25519_pk);
        assert_eq!(parsed.ml_kem_pk, record.ml_kem_pk);
        assert_eq!(parsed.encrypted_private_keys, record.encrypted_private_keys);
        assert_eq!(parsed.argon2_salt, record.argon2_salt);
        assert_eq!(parsed.argon2_memory_kib, record.argon2_memory_kib);
        assert_eq!(parsed.argon2_iterations, record.argon2_iterations);
        assert_eq!(parsed.argon2_parallelism, record.argon2_parallelism);
    }

    #[test]
    fn contact_record_roundtrip() {
        let record = ContactRecord {
            identity_id: [0x42; 16],
            display_name: "Bob".to_string(),
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            imported_at: 1711800000,
            status: IdentityStatus::Active,
        };

        let bytes = record.to_bytes();
        let parsed = ContactRecord::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.identity_id, record.identity_id);
        assert_eq!(parsed.display_name, record.display_name);
        assert_eq!(parsed.ed25519_pk, record.ed25519_pk);
        assert_eq!(parsed.ml_dsa_pk, record.ml_dsa_pk);
        assert_eq!(parsed.x25519_pk, record.x25519_pk);
        assert_eq!(parsed.ml_kem_pk, record.ml_kem_pk);
        assert_eq!(parsed.imported_at, record.imported_at);
        assert_eq!(parsed.status, record.status);
    }

    #[test]
    fn contact_record_revoked_roundtrip() {
        let record = ContactRecord {
            identity_id: [0x42; 16],
            display_name: "Bob".to_string(),
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            imported_at: 1711800000,
            status: IdentityStatus::Revoked,
        };

        let bytes = record.to_bytes();
        let parsed = ContactRecord::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.status, IdentityStatus::Revoked);
    }

    #[test]
    fn identity_rejects_bad_magic() {
        let mut bytes = IdentityRecord {
            identity_id: [0; 16],
            display_name: String::new(),
            created_at: 0,
            status: IdentityStatus::Active,
            ed25519_pk: vec![],
            ml_dsa_pk: vec![],
            x25519_pk: vec![],
            ml_kem_pk: vec![],
            encrypted_private_keys: vec![],
            argon2_salt: [0; 16],
            argon2_memory_kib: 65536,
            argon2_iterations: 2,
            argon2_parallelism: 1,
        }
        .to_bytes();
        bytes[0] = 0xFF;

        assert!(matches!(
            IdentityRecord::from_bytes(&bytes),
            Err(StoreError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn contact_rejects_bad_magic() {
        let mut bytes = ContactRecord {
            identity_id: [0; 16],
            display_name: String::new(),
            ed25519_pk: vec![],
            ml_dsa_pk: vec![],
            x25519_pk: vec![],
            ml_kem_pk: vec![],
            imported_at: 0,
            status: IdentityStatus::Active,
        }
        .to_bytes();
        bytes[0] = 0xFF;

        assert!(matches!(
            ContactRecord::from_bytes(&bytes),
            Err(StoreError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn rejects_truncated_record() {
        assert!(matches!(
            IdentityRecord::from_bytes(&[0x41, 0x50]),
            Err(StoreError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn identity_status_roundtrip() {
        for status in [
            IdentityStatus::Active,
            IdentityStatus::Rotated,
            IdentityStatus::Revoked,
        ] {
            let byte = status as u8;
            assert_eq!(IdentityStatus::from_byte(byte), Some(status));
        }
        assert_eq!(IdentityStatus::from_byte(0xFF), None);
    }
}
