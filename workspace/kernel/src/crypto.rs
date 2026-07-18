//! Cryptographic verification for CMOD modules.
//!
//! Provides Ed25519 signature verification to ensure module integrity.
//! The kernel maintains a key store of trusted public keys; modules must
//! be signed by one of these keys to be loaded.

use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use spin::Mutex;

/// Size of an Ed25519 public key in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Size of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// Maximum size of a key ID.
pub const KEY_ID_SIZE: usize = 8;

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
static TRUSTED_KEYS: Mutex<Vec<TrustedKey>> = Mutex::new(Vec::new());

/// Register a trusted signing key.
///
/// Called during boot to populate the key store. In production, these
/// keys would be provisioned via a secure channel or hardware root of trust.
pub fn register_trusted_key(id: [u8; KEY_ID_SIZE], public_key: [u8; ED25519_PUBLIC_KEY_SIZE], label: &'static str) {
    let mut keys = TRUSTED_KEYS.lock();
    // Reject duplicate key IDs
    if keys.iter().any(|k| k.id == id) {
        log::warn!("[crypto] duplicate key id {:02x?}, skipping", id);
        return;
    }
    keys.push(TrustedKey { id, public_key, label });
    log::info!("[crypto] registered trusted key: {} (id={:02x?})", label, id);
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

/// Lookup a trusted key by its ID.
fn find_trusted_key(id: &[u8; KEY_ID_SIZE]) -> Option<TrustedKey> {
    TRUSTED_KEYS.lock().iter().find(|k| k.id == *id).cloned()
}

// ============================================================================
// Ed25519 Verification
// ============================================================================

/// Verify an Ed25519 signature over module data.
///
/// # Arguments
/// * `key_id` - 8-byte identifier for the signing key
/// * `signature` - 64-byte Ed25519 signature
/// * `data` - The data that was signed (typically the module payload)
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
    // Check if signature is all zeros (unsigned module)
    if signature.iter().all(|&b| b == 0) {
        return VerifyResult::Unsigned;
    }

    // Look up the trusted key
    let key = match find_trusted_key(key_id) {
        Some(k) => k,
        None => return VerifyResult::KeyNotFound,
    };

    // Parse the public key
    let verifying_key = match VerifyingKey::from_bytes(&key.public_key) {
        Ok(vk) => vk,
        Err(_) => {
            log::error!("[crypto] invalid public key for id {:02x?}", key_id);
            return VerifyResult::InvalidSignature;
        }
    };

    // Parse the signature
    let sig = Signature::from_bytes(signature);

    // Verify
    match verifying_key.verify(data, &sig) {
        Ok(()) => {
            log::debug!("[crypto] signature verified for key {} (id={:02x?})", key.label, key_id);
            VerifyResult::Valid
        }
        Err(e) => {
            log::warn!("[crypto] signature verification failed for key id {:02x?}: {}", key_id, e);
            VerifyResult::InvalidSignature
        }
    }
}

/// Verify a CMOD module's signature.
///
/// This is the main entry point for module signature verification.
/// It extracts the signature and key_id from the raw header bytes
/// and verifies against the module payload.
///
/// # Arguments
/// * `header_bytes` - The raw CMOD header (at least `header_size` bytes)
/// * `header_size` - Size of the header structure
/// * `code_offset` - Offset to code section in the module
/// * `code_size` - Size of the code section
/// * `data_offset` - Offset to data section in the module
/// * `data_size` - Size of the data section
/// * `key_id_offset` - Offset to key_id field in header
/// * `sig_offset` - Offset to signature field in header
pub fn verify_cmod_signature(
    header_bytes: &[u8],
    key_id_offset: usize,
    sig_offset: usize,
    payload: &[u8],
) -> VerifyResult {
    // Extract key_id (8 bytes)
    if key_id_offset + KEY_ID_SIZE > header_bytes.len() {
        return VerifyResult::InvalidSignature;
    }
    let mut key_id = [0u8; KEY_ID_SIZE];
    key_id.copy_from_slice(&header_bytes[key_id_offset..key_id_offset + KEY_ID_SIZE]);

    // Extract signature (64 bytes)
    if sig_offset + ED25519_SIGNATURE_SIZE > header_bytes.len() {
        return VerifyResult::InvalidSignature;
    }
    let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
    signature.copy_from_slice(&header_bytes[sig_offset..sig_offset + ED25519_SIGNATURE_SIZE]);

    verify_signature(&key_id, &signature, payload)
}

// ============================================================================
// Key Provisioning (Boot-time initialization)
// ============================================================================

/// Provision the kernel signing key.
///
/// In a real deployment, this key would be burned into a hardware root of trust
/// or provisioned via a secure boot chain. For development, we embed a
/// well-known key pair.
///
/// The private key (for signing modules) is kept offline. Only the public
/// key is embedded in the kernel.
pub fn provision_dev_keys() {
    // Development key pair (DO NOT use in production!)
    // Public key: generated with `ed25519-keygen` or `openssl`
    //
    // To generate a new key pair:
    //   1. ed25519-keygen -x > dev_key.pub
    //   2. ed25519-keygen > dev_key.priv
    //   3. Sign a module: openssl pkeyutl -sign -inkey dev_key.priv -in module.cmod -out sig.bin
    //
    // For now, we use a placeholder key that must be replaced before production.
    // The actual public key should be set during the build process.

    // Dev key ID: "STRAT9D1" (STRAT9 Dev Key 1)
    let dev_key_id: [u8; KEY_ID_SIZE] = *b"STRAT9D1";

    // Dev public key (32 bytes) - placeholder, must be replaced
    // This is a well-known test key. In production, generate your own.
    let dev_public_key: [u8; ED25519_PUBLIC_KEY_SIZE] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0c, 0x73,
        0x66, 0x20, 0x4f, 0x50, 0x7e, 0xe2, 0x83, 0x84,
        0x6f, 0xc7, 0x43, 0x50, 0x99, 0x63, 0x07, 0x21,
        0x0e, 0x5e, 0xb9, 0x4c, 0x1e, 0x0e, 0x91, 0x1b,
    ];

    register_trusted_key(dev_key_id, dev_public_key, "strat9-dev");
    log::info!("[crypto] dev key provisioned (STRAT9D1)");
}

/// Initialize the crypto subsystem.
///
/// Called during kernel boot to provision trusted keys.
pub fn init() {
    log::info!("[init] Crypto subsystem...");
    provision_dev_keys();
    let count = trusted_key_count();
    log::info!("[init] Crypto subsystem ready ({} trusted key(s))", count);
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
        let sig = [1u8; ED25519_SIGNATURE_SIZE]; // non-zero
        let key_id = [0xff; KEY_ID_SIZE];
        assert_eq!(verify_signature(&key_id, &sig, &[]), VerifyResult::KeyNotFound);
    }
}
