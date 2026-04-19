//! Filesystem-based storage backend.
//!
//! Stores identity and contact records as individual files in a directory tree:
//!
//! ```text
//! <base_dir>/
//!   identities/
//!     <hex_identity_id>.identity
//!   contacts/
//!     <hex_identity_id>.contact
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::StoreError;
use crate::record::{ContactRecord, IdentityRecord};

/// A filesystem-backed store for identity and contact records.
pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    /// Create or open a store at the given base directory.
    ///
    /// Creates the directory structure if it does not exist.
    pub fn open(base_dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let base_dir = base_dir.into();
        fs::create_dir_all(base_dir.join("identities"))?;
        fs::create_dir_all(base_dir.join("contacts"))?;
        Ok(Self { base_dir })
    }

    /// Return the base directory of this store.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    // --- Identity operations ---

    /// Save an identity record to disk.
    ///
    /// Uses atomic write-temp-fsync-rename to prevent corruption on crash.
    /// On Unix, files are created with mode 0600 (owner-only access).
    pub fn save_identity(&self, record: &IdentityRecord) -> Result<(), StoreError> {
        let path = self.identity_path(&record.identity_id);
        atomic_write(&path, &record.to_bytes())?;
        Ok(())
    }

    /// Load an identity record from disk.
    pub fn load_identity(&self, identity_id: &[u8; 16]) -> Result<IdentityRecord, StoreError> {
        let path = self.identity_path(identity_id);
        let data = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::IdentityNotFound {
                    identity_id: hex_id(identity_id),
                }
            } else {
                StoreError::Io(e)
            }
        })?;
        IdentityRecord::from_bytes(&data)
    }

    /// List all identity IDs in the store.
    pub fn list_identities(&self) -> Result<Vec<[u8; 16]>, StoreError> {
        list_ids(&self.base_dir.join("identities"), "identity")
    }

    /// Delete an identity record from disk.
    pub fn delete_identity(&self, identity_id: &[u8; 16]) -> Result<(), StoreError> {
        let path = self.identity_path(identity_id);
        fs::remove_file(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::IdentityNotFound {
                    identity_id: hex_id(identity_id),
                }
            } else {
                StoreError::Io(e)
            }
        })
    }

    // --- Contact operations ---

    /// Save a contact record to disk.
    ///
    /// Uses atomic write-temp-fsync-rename to prevent corruption on crash.
    /// On Unix, files are created with mode 0600 (owner-only access).
    pub fn save_contact(&self, record: &ContactRecord) -> Result<(), StoreError> {
        let path = self.contact_path(&record.identity_id);
        atomic_write(&path, &record.to_bytes())?;
        Ok(())
    }

    /// Load a contact record from disk.
    pub fn load_contact(&self, identity_id: &[u8; 16]) -> Result<ContactRecord, StoreError> {
        let path = self.contact_path(identity_id);
        let data = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::ContactNotFound {
                    identity_id: hex_id(identity_id),
                }
            } else {
                StoreError::Io(e)
            }
        })?;
        ContactRecord::from_bytes(&data)
    }

    /// List all contact IDs in the store.
    pub fn list_contacts(&self) -> Result<Vec<[u8; 16]>, StoreError> {
        list_ids(&self.base_dir.join("contacts"), "contact")
    }

    /// Delete a contact record from disk.
    pub fn delete_contact(&self, identity_id: &[u8; 16]) -> Result<(), StoreError> {
        let path = self.contact_path(identity_id);
        fs::remove_file(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::ContactNotFound {
                    identity_id: hex_id(identity_id),
                }
            } else {
                StoreError::Io(e)
            }
        })
    }

    // --- Path helpers ---

    fn identity_path(&self, identity_id: &[u8; 16]) -> PathBuf {
        self.base_dir
            .join("identities")
            .join(format!("{}.identity", hex_id(identity_id)))
    }

    fn contact_path(&self, identity_id: &[u8; 16]) -> PathBuf {
        self.base_dir
            .join("contacts")
            .join(format!("{}.contact", hex_id(identity_id)))
    }
}

/// Atomically write `data` to `path` via a temporary file.
///
/// 1. Write to a `.tmp` sibling file with restrictive permissions.
/// 2. `fsync` the file to ensure durability.
/// 3. Rename over the target path (atomic on POSIX).
/// 4. `fsync` the parent directory to make the rename durable.
///
/// On failure after temp-file creation, the temp file is cleaned up
/// on a best-effort basis.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let tmp_path = path.with_extension("tmp");

    // Open with restrictive permissions on Unix (0600 = owner read/write only).
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let result = (|| -> Result<(), StoreError> {
        let mut file = opts.open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, path)?;

        // Fsync the parent directory so the rename is durable.
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

/// Format a 16-byte identity ID as a hex string.
fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a hex filename stem back into a 16-byte ID.
fn parse_hex_id(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

/// List all 16-byte IDs from files in a directory with a given extension.
fn list_ids(dir: &Path, extension: &str) -> Result<Vec<[u8; 16]>, StoreError> {
    let mut ids = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
        Err(e) => return Err(StoreError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Some(id) = parse_hex_id(stem) {
                    ids.push(id);
                }
            }
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ContactRecord, IdentityStatus};

    fn temp_store() -> (tempfile::TempDir, FileStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn sample_identity(id_byte: u8) -> IdentityRecord {
        IdentityRecord {
            identity_id: [id_byte; 16],
            display_name: "Test User".to_string(),
            created_at: 1711800000,
            status: IdentityStatus::Active,
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            encrypted_private_keys: vec![5; 100],
            argon2_salt: [0xAA; 16],
            argon2_memory_kib: 65_536,
            argon2_iterations: 2,
            argon2_parallelism: 1,
        }
    }

    fn sample_contact(id_byte: u8) -> ContactRecord {
        ContactRecord {
            identity_id: [id_byte; 16],
            display_name: "Contact".to_string(),
            ed25519_pk: vec![1; 32],
            ml_dsa_pk: vec![2; 1952],
            x25519_pk: vec![3; 32],
            ml_kem_pk: vec![4; 1184],
            imported_at: 1711800000,
            status: IdentityStatus::Active,
        }
    }

    #[test]
    fn save_load_identity() {
        let (_dir, store) = temp_store();
        let record = sample_identity(0x42);

        store.save_identity(&record).unwrap();
        let loaded = store.load_identity(&record.identity_id).unwrap();

        assert_eq!(loaded.identity_id, record.identity_id);
        assert_eq!(loaded.display_name, record.display_name);
        assert_eq!(loaded.ed25519_pk, record.ed25519_pk);
    }

    #[test]
    fn save_load_contact() {
        let (_dir, store) = temp_store();
        let record = sample_contact(0x42);

        store.save_contact(&record).unwrap();
        let loaded = store.load_contact(&record.identity_id).unwrap();

        assert_eq!(loaded.identity_id, record.identity_id);
        assert_eq!(loaded.display_name, record.display_name);
    }

    #[test]
    fn identity_not_found() {
        let (_dir, store) = temp_store();
        let result = store.load_identity(&[0xFF; 16]);
        assert!(matches!(result, Err(StoreError::IdentityNotFound { .. })));
    }

    #[test]
    fn contact_not_found() {
        let (_dir, store) = temp_store();
        let result = store.load_contact(&[0xFF; 16]);
        assert!(matches!(result, Err(StoreError::ContactNotFound { .. })));
    }

    #[test]
    fn list_identities() {
        let (_dir, store) = temp_store();

        store.save_identity(&sample_identity(0x01)).unwrap();
        store.save_identity(&sample_identity(0x02)).unwrap();

        let mut ids = store.list_identities().unwrap();
        ids.sort();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], [0x01; 16]);
        assert_eq!(ids[1], [0x02; 16]);
    }

    #[test]
    fn list_contacts() {
        let (_dir, store) = temp_store();

        store.save_contact(&sample_contact(0x01)).unwrap();
        store.save_contact(&sample_contact(0x02)).unwrap();

        let mut ids = store.list_contacts().unwrap();
        ids.sort();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn delete_identity() {
        let (_dir, store) = temp_store();
        let record = sample_identity(0x42);

        store.save_identity(&record).unwrap();
        assert!(store.load_identity(&record.identity_id).is_ok());

        store.delete_identity(&record.identity_id).unwrap();
        assert!(matches!(
            store.load_identity(&record.identity_id),
            Err(StoreError::IdentityNotFound { .. })
        ));
    }

    #[test]
    fn delete_contact() {
        let (_dir, store) = temp_store();
        let record = sample_contact(0x42);

        store.save_contact(&record).unwrap();
        store.delete_contact(&record.identity_id).unwrap();
        assert!(matches!(
            store.load_contact(&record.identity_id),
            Err(StoreError::ContactNotFound { .. })
        ));
    }

    #[test]
    fn delete_nonexistent_identity_fails() {
        let (_dir, store) = temp_store();
        assert!(matches!(
            store.delete_identity(&[0xFF; 16]),
            Err(StoreError::IdentityNotFound { .. })
        ));
    }

    #[test]
    fn overwrite_identity() {
        let (_dir, store) = temp_store();
        let mut record = sample_identity(0x42);

        store.save_identity(&record).unwrap();
        record.display_name = "Updated Name".to_string();
        store.save_identity(&record).unwrap();

        let loaded = store.load_identity(&record.identity_id).unwrap();
        assert_eq!(loaded.display_name, "Updated Name");
    }

    #[test]
    fn hex_id_roundtrip() {
        let id = [0xAB; 16];
        let hex = hex_id(&id);
        let parsed = parse_hex_id(&hex).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn empty_store_lists_empty() {
        let (_dir, store) = temp_store();
        assert!(store.list_identities().unwrap().is_empty());
        assert!(store.list_contacts().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, store) = temp_store();
        let record = sample_identity(0x42);
        store.save_identity(&record).unwrap();

        let path = store.identity_path(&record.identity_id);
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn contact_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, store) = temp_store();
        let record = sample_contact(0x42);
        store.save_contact(&record).unwrap();

        let path = store.contact_path(&record.identity_id);
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn no_temp_file_left_after_save() {
        let (_dir, store) = temp_store();
        let record = sample_identity(0x42);
        store.save_identity(&record).unwrap();

        let tmp_path = store
            .identity_path(&record.identity_id)
            .with_extension("tmp");
        assert!(!tmp_path.exists());
    }
}
