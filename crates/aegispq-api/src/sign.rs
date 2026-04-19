//! Standalone hybrid signing and verification.
//!
//! Wraps the core hybrid signature primitives (Ed25519 + ML-DSA-65) with a
//! fixed domain separator for general-purpose signing of arbitrary data.
//!
//! For file-level signatures (which are automatic and use their own domain
//! separator), see [`crate::encrypt`].

use aegispq_core::sig;
use aegispq_store::record::IdentityStatus;

use crate::error::Error;
use crate::types::{Identity, PublicIdentity};

/// Domain separator for standalone document signing.
///
/// This is distinct from file encryption signing (`AegisPQ-v1-file-sign`)
/// to prevent cross-protocol signature reuse.
const SIGN_DOMAIN: &[u8] = b"AegisPQ-v1-sign";

/// Sign arbitrary data with the identity's hybrid signing key.
///
/// Returns the serialized hybrid signature (Ed25519 + ML-DSA-65).
/// The signature includes a fixed domain separator to prevent
/// cross-protocol reuse.
pub fn sign(identity: &Identity, data: &[u8]) -> Result<Vec<u8>, Error> {
    // Enforce lifecycle: only Active identities may sign new data.
    if identity.status != IdentityStatus::Active {
        return Err(crate::identity::revoked_error(&identity.identity_id));
    }

    let signature = sig::sign(&identity.signing_key, SIGN_DOMAIN, data)?;
    Ok(signature.to_bytes())
}

/// Verify a hybrid signature against a public identity.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if verification
/// fails. Returns `Err` only for structural errors (e.g., malformed signature
/// bytes that cannot be parsed).
pub fn verify(
    public_identity: &PublicIdentity,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let sig = sig::HybridSignature::from_bytes(signature)?;
    match sig::verify(&public_identity.verifying_key, SIGN_DOMAIN, data, &sig) {
        Ok(()) => Ok(true),
        Err(aegispq_core::CoreError::SignatureVerificationFailed) => Ok(false),
        Err(e) => Err(e.into()),
    }
}
