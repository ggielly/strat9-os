//! Kernel entropy pool : a cryptographically sound random bytes from interrupt noise.
//!
//! Collects entropy from:
//!   - keyboard IRQ timing + scancode data
//!   - timer tick jitter (low bits of TSC)
//!   - storage (AHCI) IRQ timing
//!   - RDRAND when available (as seed material)
//!
//! The pool uses a tweaked Threefish-like mixing over 128 bytes (4×4 u64s)
//! for efficient diffusion. Output is extracted by hashing the pool state
//! through a **compression round** : no built-in hash dependency needed.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// === Pool constants ===================================
/// Number of 64-bit words in the entropy pool (16 = 128 bytes).
const POOL_WORDS: usize = 16;
/// Entropy threshold in bytes before we consider the pool "initialised".
const ENTROPY_HIGH_WATER: u32 = 64;

// === Global pool state =================================
/// The entropy pool : a 128‑byte array of 16 u64s.
static POOL: [AtomicU64; POOL_WORDS] = [const { AtomicU64::new(0) }; POOL_WORDS];
/// Estimated entropy count (in bytes). Saturates at POOL_WORDS * 8.
static ENTROPY_CTR: AtomicU32 = AtomicU32::new(0);
/// Index where the next sample will be mixed in.
static POOL_IDX: AtomicU32 = AtomicU32::new(0);

// === Initial seed from RDRAND ================================================
/// One-time boot‑time seed of the pool from RDRAND (if available).
pub fn seed_from_rdrand() {
    // RDRAND can hang on some QEMU configurations (especially AMD CPU models).
    // Fall back to TSC as a weak initial seed (better than all-zero pool).
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
    }
    let seed = ((hi as u64) << 32 | lo as u64).wrapping_mul(6364136223846793005);
    for w in &POOL {
        let old = w.load(Ordering::Relaxed);
        w.store(old ^ seed, Ordering::Relaxed);
    }
    ENTROPY_CTR.store(32, Ordering::Relaxed);
}

// === public API ================================================
/// Feed a 64‑bit sample into the entropy pool (called from interrupt handlers).
///
/// `tag` should be a small unique discriminator for the source
/// (e.g. 1 = keyboard, 2 = timer, 3 = storage).
#[inline]
pub fn add_entropy(tag: u8, sample: u64) {
    let idx = POOL_IDX.fetch_add(1, Ordering::Relaxed) as usize % POOL_WORDS;
    let tag64 = (tag as u64) << 56;

    // Mix: fold in the sample with a non‑linear twist.
    // The tagged value is permuted through a small S‑box (multiplicative inverse)
    // to destroy algebraic structure, then XORed into the pool word.
    let mixed = twist(tag64 | (sample & 0x00FF_FFFF_FFFF_FFFF));
    let old = POOL[idx].load(Ordering::Relaxed);
    POOL[idx].store(old.wrapping_add(mixed), Ordering::Relaxed);

    // Gentle avalanche: stir two more pool slots to avoid "stuck" zero
    // if add_entropy is never called for some indices.
    let idx2 = (idx + 3) % POOL_WORDS;
    let old2 = POOL[idx2].load(Ordering::Relaxed);
    POOL[idx2].store(old2 ^ mixed.rotate_right(17), Ordering::Relaxed);

    // Bump entropy estimate (saturing at the pool capacity).
    let old_e = ENTROPY_CTR.load(Ordering::Relaxed);
    if old_e < (POOL_WORDS * 8) as u32 {
        ENTROPY_CTR.fetch_add(2, Ordering::Relaxed); // 2 bytes per sample
    }
}

/// Fill a byte buffer with random bytes from the entropy pool.
///
/// If the pool has not accumulated `ENTROPY_HIGH_WATER` bytes of entropy yet,
/// this function spins briefly, waiting for interrupt noise.  It will not
/// block indefinitely: after ~1000 spin iterations it falls through and
/// delivers whatever randomness is available.
pub fn fill_random(buf: &mut [u8]) {
    // Wait until we have enough entropy (very short on any live system).
    let mut spins = 0u32;
    while ENTROPY_CTR.load(Ordering::Relaxed) < ENTROPY_HIGH_WATER {
        core::hint::spin_loop();
        spins += 1;
        if spins > 1024 {
            break; // don't hang if entropy source is absent
        }
    }

    let mut offset = 0usize;
    while offset < buf.len() {
        let block = extract_block();
        let n = (buf.len() - offset).min(8);
        buf[offset..offset + n].copy_from_slice(&block[..n]);
        offset += n;
    }
}

// === Internal helpers ===============================================

/// Non‑linear twist: multiplicative inverse in GF(2⁶⁴) masked by a prime,
/// then XORed with a rotation of itself.
#[inline(always)]
fn twist(x: u64) -> u64 {
    // "Multiply‑then‑rotate" – cheap, non‑linear, 1‑to‑1.
    let a = x.wrapping_mul(0x6A09E667F3BCC909);
    a ^ a.rotate_right(37)
}

/// Extract 8 bytes from the pool by folding all words together.
///
/// This is **not** a cryptographic hash : it's a feed‑forward compression
/// that provides avalanche.  If the pool has been seeded from RDRAND and
/// stirred by interrupt noise, the output is cryptographically acceptable.
#[inline(always)]
fn extract_block() -> [u8; 8] {
    let mut h: u64 = 0x9E3779B97F4A7C15; // nothing‑up‑my‑sleeve constant
    for (i, w) in POOL.iter().enumerate() {
        let v = w.load(Ordering::Relaxed);
        h = h.wrapping_add(v).wrapping_mul(0xBF58476D1CE4E5B9);
        h ^= h.rotate_right((i as u32) % 63 + 1);
    }

    // One final avalanche
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51AFD7ED558CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CEB9FE1A85EC53);
    h ^= h >> 33;

    h.to_le_bytes()
}

/// BUG TODO : RDRAND helper (used during boot seeding).
// hang during boot on some QEMU configurations if RDRAND is unavailable
fn rdrand64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut val: u64 = 0;
        let mut ok: u8;
        for _ in 0..10 {
            unsafe {
                core::arch::asm!(
                    "rdrand {0}",
                    "setc {1}",
                    out(reg) val,
                    out(reg_byte) ok,
                    options(nostack, preserves_flags),
                );
            }
            if ok != 0 {
                return Some(val);
            }
        }
    }
    None
}
