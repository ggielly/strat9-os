//! Cryptographic verification for CMOD modules.
//!
//! Provides Ed25519 signature verification to ensure module integrity.
//! The kernel maintains a key store of trusted public keys; modules must
//! be signed by one of these keys to be loaded.
//!
//! # Security Design
//!
//! The signed payload is **code + data only** (everything after the header).
//! The header (containing key_id and signature) is NOT part of the signed
//! payload. This prevents an attacker from using a known key_id to trick
//! the kernel into looking up a legitimate key while verifying a malicious
//! signature.
//!
//! Verification flow:
//! 1. Extract key_id (8 bytes) and signature (64 bytes) from header
//! 2. Look up the public key by key_id
//! 3. Verify signature over: module_data[HEADER_SIZE..]
//!    (code + data, excluding the header)

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use spin::Mutex;

/// Size of an Ed25519 public key in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// Size of a key ID.
pub const KEY_ID_SIZE: usize = 8;

/// Result of a signature verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid (tampered module or wrong key).
    InvalidSignature,
    /// No key found matching the key_id in the module header.
    KeyNotFound,
    /// The signature field is all zeros (unsigned module).
    Unsigned,
}

impl core::fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyResult::Valid => write!(f, "valid"),
            VerifyResult::InvalidSignature => write!(f, "invalid signature"),
            VerifyResult::KeyNotFound => write!(f, "key not found"),
            VerifyResult::Unsigned => write!(f, "unsigned module"),
        }
    }
}

// ============================================================================
// Trusted Key Store
// ============================================================================

/// Global trusted key store protected by a spinlock.
static TRUSTED_KEYS: Mutex<alloc::vec::Vec<TrustedKey>> = Mutex::new(alloc::vec::Vec::new());

/// A trusted signing key with its identifier.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// 8-byte key identifier (matches `key_id` in CMOD header).
    pub id: [u8; KEY_ID_SIZE],
    /// Ed25519 public key (32 bytes).
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    /// Human-readable label for this key.
    pub label: &'static str,
}

/// Register a trusted signing key.
///
/// Called during boot to populate the key store. In production, these
/// keys would be provisioned via a secure channel or hardware root of trust.
pub fn register_trusted_key(
    id: [u8; KEY_ID_SIZE],
    public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    label: &'static str,
) {
    let mut keys = TRUSTED_KEYS.lock();
    if keys.iter().any(|k| k.id == id) {
        log::warn!("[crypto] duplicate key id {:02x?}, skipping", id);
        return;
    }
    keys.push(TrustedKey {
        id,
        public_key,
        label,
    });
    log::info!(
        "[crypto] registered trusted key: {} (id={:02x?})",
        label,
        id
    );
}

/// Remove a trusted signing key by ID.
pub fn remove_trusted_key(id: [u8; KEY_ID_SIZE]) -> bool {
    let mut keys = TRUSTED_KEYS.lock();
    let len_before = keys.len();
    keys.retain(|k| k.id != id);
    keys.len() < len_before
}

/// Number of registered trusted keys.
pub fn trusted_key_count() -> usize {
    TRUSTED_KEYS.lock().len()
}

/// Check if a key ID is registered as trusted.
pub fn is_key_trusted(id: &[u8; KEY_ID_SIZE]) -> bool {
    TRUSTED_KEYS.lock().iter().any(|k| k.id == *id)
}

/// Snapshot of a trusted key for display purposes.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub id: [u8; KEY_ID_SIZE],
    pub label: &'static str,
}

/// Return a snapshot of all registered trusted keys.
pub fn list_trusted_keys() -> alloc::vec::Vec<KeyInfo> {
    TRUSTED_KEYS
        .lock()
        .iter()
        .map(|k| KeyInfo {
            id: k.id,
            label: k.label,
        })
        .collect()
}

/// Lookup a trusted key by its ID.
fn find_trusted_key(id: &[u8; KEY_ID_SIZE]) -> Option<TrustedKey> {
    TRUSTED_KEYS.lock().iter().find(|k| k.id == *id).cloned()
}

// ============================================================================
// Ed25519 Verification
// ============================================================================

/// Verify an Ed25519 signature over data.
///
/// # Arguments
/// * `key_id` - 8-byte identifier for the signing key
/// * `signature` - 64-byte Ed25519 signature
/// * `data` - The data that was signed (code + data sections)
///
/// # Returns
/// * `VerifyResult::Valid` if signature is valid
/// * `VerifyResult::KeyNotFound` if no trusted key matches `key_id`
/// * `VerifyResult::InvalidSignature` if verification fails
/// * `VerifyResult::Unsigned` if signature is all zeros
pub fn verify_signature(
    key_id: &[u8; KEY_ID_SIZE],
    signature: &[u8; ED25519_SIGNATURE_SIZE],
    data: &[u8],
) -> VerifyResult {
    if signature.iter().all(|&b| b == 0) {
        return VerifyResult::Unsigned;
    }

    let key = match find_trusted_key(key_id) {
        Some(k) => k,
        None => return VerifyResult::KeyNotFound,
    };

    let verifying_key = match VerifyingKey::from_bytes(&key.public_key) {
        Ok(vk) => vk,
        Err(_) => {
            log::error!("[crypto] corrupt public key for id {:02x?}", key_id);
            return VerifyResult::InvalidSignature;
        }
    };

    let sig = Signature::from_bytes(signature);

    // Verify and log AFTER the constant-time operation to avoid timing leaks.
    let ok = verifying_key.verify(data, &sig).is_ok();
    if ok {
        log::debug!(
            "[crypto] signature OK for key {} (id={:02x?})",
            key.label,
            key_id
        );
        VerifyResult::Valid
    } else {
        // Log a generic message : no error detail that could leak info.
        log::warn!("[crypto] signature FAILED for key id {:02x?}", key_id);
        VerifyResult::InvalidSignature
    }
}

/// Verify a CMOD module's signature.
///
/// Extracts key_id and signature from the raw header, then verifies
/// the signature over `payload` (which must be code+data, NOT the header).
///
/// # Arguments
/// * `header_bytes` - The raw CMOD header
/// * `key_id_offset` - Byte offset of key_id in header
/// * `sig_offset` - Byte offset of signature in header
/// * `payload` - The data that was signed (code + data sections)
pub fn verify_cmod_signature(
    header_bytes: &[u8],
    key_id_offset: usize,
    sig_offset: usize,
    payload: &[u8],
) -> VerifyResult {
    // Bounds: key_id must fit before signature, signature must fit in header.
    if key_id_offset + KEY_ID_SIZE > sig_offset {
        return VerifyResult::InvalidSignature;
    }
    if sig_offset + ED25519_SIGNATURE_SIZE > header_bytes.len() {
        return VerifyResult::InvalidSignature;
    }

    let mut key_id = [0u8; KEY_ID_SIZE];
    key_id.copy_from_slice(&header_bytes[key_id_offset..key_id_offset + KEY_ID_SIZE]);

    let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
    signature.copy_from_slice(&header_bytes[sig_offset..sig_offset + ED25519_SIGNATURE_SIZE]);

    verify_signature(&key_id, &signature, payload)
}

// ============================================================================
// Key Provisioning (Boot-time initialization)
// ============================================================================

/// Initialize the crypto subsystem.
///
/// Called during kernel boot. In production, keys are provisioned via
/// secure boot chain or hardware root of trust. No default keys are
/// embedded : unsigned or unverifiable modules are rejected.
pub fn init() {
    log::info!("[init] Crypto subsystem...");
    let count = trusted_key_count();
    if count == 0 {
        log::warn!("[init] No trusted keys : module signing verification disabled");
    } else {
        log::info!("[init] Crypto subsystem ready ({} trusted key(s))", count);
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_module_detection() {
        let sig = [0u8; ED25519_SIGNATURE_SIZE];
        let key_id = [0u8; KEY_ID_SIZE];
        assert_eq!(verify_signature(&key_id, &sig, &[]), VerifyResult::Unsigned);
    }

    #[test]
    fn test_key_not_found() {
        let sig = [1u8; ED25519_SIGNATURE_SIZE];
        let key_id = [0xff; KEY_ID_SIZE];
        assert_eq!(
            verify_signature(&key_id, &sig, &[]),
            VerifyResult::KeyNotFound
        );
    }
}
