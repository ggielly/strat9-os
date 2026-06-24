//! PC Speaker driver : beep codes + music playback.
//!
//! Hardware: PIT channel 2 (port 0x42) generates a square wave,
//! port 0x61 bits 0-1 gate the speaker on/off.
//!
//! Two modes:
//! 1. **Blocking** (boot): `beep()` busy-waits : used before scheduler.
//! 2. **Music** (runtime): note queue drained by PIT timer interrupt.

use super::io::{inb, outb};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

const PIT_FREQ: u32 = 1_193_182;
const PIT_CHANNEL2_CMD: u8 = 0xB2; // channel 2, lobyte/hibyte, mode 3 (square wave), binary
const SPEAKER_GATE_BIT: u8 = 1 << 0;
const SPEAKER_DATA_BIT: u8 = 1 << 1;

static SPEAKER_ACTIVE: AtomicBool = AtomicBool::new(false);
static MUSIC_PLAYING: AtomicBool = AtomicBool::new(false);

/// Current note frequency (Hz). Updated by the music player on timer tick.
static NOTE_FREQ: AtomicU32 = AtomicU32::new(0);

/// Remaining ticks for the current note.
static NOTE_TICKS_LEFT: AtomicU32 = AtomicU32::new(0);

/// Index into the current note sequence.
static NOTE_INDEX: AtomicU32 = AtomicU32::new(0);

/// Total number of notes in the current sequence.
static NOTE_TOTAL: AtomicU32 = AtomicU32::new(0);

/// Pointer to the note sequence array (freq in Hz).
static mut NOTE_SEQ_PTR: *const u32 = core::ptr::null();

/// Pointer to the duration array (in milliseconds).
static mut NOTE_DUR_PTR: *const u32 = core::ptr::null();

/// Tempo multiplier (100 = normal, 200 = double speed, 50 = half speed).
static TEMPO: AtomicU16 = AtomicU16::new(100);

// =========================================================================
// Low-level speaker control
// =========================================================================

/// Set the PIT channel 2 frequency. `hz` = 0 disables the tone.
#[inline]
unsafe fn pit_set_freq(hz: u32) {
    if hz == 0 || hz > 100_000 {
        outb(0x43, PIT_CHANNEL2_CMD);
        outb(0x42, 0);
        outb(0x42, 0);
        return;
    }
    let count = PIT_FREQ / hz;
    outb(0x43, PIT_CHANNEL2_CMD);
    outb(0x42, (count & 0xFF) as u8);
    outb(0x42, ((count >> 8) & 0xFF) as u8);
}

/// Enable or disable the speaker output.
#[inline]
unsafe fn speaker_enable(on: bool) {
    let val = inb(0x61);
    if on {
        outb(0x61, val | SPEAKER_GATE_BIT | SPEAKER_DATA_BIT);
    } else {
        outb(0x61, val & !(SPEAKER_GATE_BIT | SPEAKER_DATA_BIT));
    }
}

// =========================================================================
// Blocking API (pre-scheduler, boot-time diagnostics)
// =========================================================================

/// Play a tone at `freq` Hz for `ms` milliseconds. Blocks via PIT busy-wait.
pub fn beep(freq: u32, ms: u32) {
    if freq == 0 || ms == 0 {
        return;
    }
    unsafe {
        pit_set_freq(freq);
        speaker_enable(true);
    }
    pit_busy_wait(ms);
    unsafe {
        speaker_enable(false);
    }
}

/// Silence the speaker immediately.
pub fn beep_off() {
    unsafe {
        speaker_enable(false);
    }
    SPEAKER_ACTIVE.store(false, Ordering::Relaxed);
}

/// Busy-wait for `ms` milliseconds using PIT channel 2 (mode 0, one-shot).
/// Works before the APIC timer / scheduler are running.
fn pit_busy_wait(ms: u32) {
    if ms == 0 {
        return;
    }
    // PIT one-shot: count = microseconds * PIT_FREQ / 1_000_000
    // For large waits, split into chunks of ~50ms (PIT 16-bit max count ~54ms)
    let chunk_ms = core::cmp::min(ms, 50);
    let chunks = (ms + chunk_ms - 1) / chunk_ms;

    for _ in 0..chunks {
        let wait_ms = core::cmp::min(chunk_ms, ms);
        let count = (PIT_FREQ * wait_ms) / 1000;
        let count = count.min(0xFFFF) as u16;

        unsafe {
            // Gate LOW → disable counting
            let val = inb(0x61);
            outb(0x61, val & !SPEAKER_GATE_BIT);

            // Program PIT channel 2: mode 0 (one-shot)
            outb(0x43, 0xB0);
            outb(0x42, (count & 0xFF) as u8);
            outb(0x42, ((count >> 8) & 0xFF) as u8);

            // Gate HIGH → start counting
            outb(0x61, val | SPEAKER_GATE_BIT);

            // Poll bit 5 of port 0x61 (T2 output) until it goes HIGH
            loop {
                if inb(0x61) & (1 << 5) != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
        }
    }
}

// =========================================================================
// Boot diagnostic beep codes
// =========================================================================

/// Short beep : milestone reached.
pub fn beep_ok() {
    beep(880, 80); // A5, 80ms
}

/// Long beep : critical failure.
pub fn beep_fail() {
    beep(220, 300); // A3, 300ms
}

/// Double beep : warning.
pub fn beep_warn() {
    beep(660, 60); // E5, 60ms
    pit_busy_wait(60);
    beep(660, 60);
}

// =========================================================================
// Boot crescendo : each phase plays a higher pitch
// =========================================================================

/// Play a crescendo beep for boot phase N.
/// Each successive phase uses a higher frequency so you can identify
/// the last completed phase by pitch alone.
pub fn beep_phase(phase: u8) {
    const PHASE_FREQS: [u32; 24] = [
        // Boot fundamentals (1-6)
        262, // 1: Kernel entry (C4)
        294, // 2: Memory manager (D4)
        330, // 3: Paging (E4)
        349, // 4: APIC + SMP (F4)
        392, // 5: Scheduler (G4)
        440, // 6: Hardware drivers (A4)
        // hardware::init() sub-drivers (7-14)
        494, // 7: EC (B4)
        523, // 8: Thermal (C5)
        587, // 9: NIC (D5)
        659, // 10: Storage (E5)
        698, // 11: Timer (F5)
        784, // 12: USB (G5)
        880, // 13: VirtIO GPU (A5)
        988, // 14: Framebuffer (B5)
        // Individual drivers (15+)
        1047, // 15: Hardware milestone (C6)
        1175, // 16: Timers detailed (D6)
        1319, // 17: USB detailed (E6)
        1480, // 18: VirtIO block (F6)
        1661, // 19: AHCI (G6)
        1865, // 20: ATA (A6)
        2093, // 21: NVMe (C7)
        2349, // 22: VirtIO net (D7)
        2637, // 23: VirtIO RNG (E7)
        2794, // 24: VirtIO Console (F7)
    ];
    let idx = (phase as usize).min(PHASE_FREQS.len() - 1);
    beep(PHASE_FREQS[idx], 60);
}

/// Panic melody : descending notes.
pub fn beep_panic() {
    let notes: [(u32, u32); 6] = [
        (880, 150),
        (740, 150),
        (622, 150),
        (523, 150),
        (440, 150),
        (330, 400),
    ];
    for (freq, dur) in notes {
        beep(freq, dur);
        pit_busy_wait(20);
    }
}

/// Startup jingle : ascending notes (happy boot).
pub fn beep_startup() {
    let notes: [(u32, u32); 5] = [
        (523, 80),   // C5
        (659, 80),   // E5
        (784, 80),   // G5
        (1047, 80),  // C6
        (1319, 150), // E6
    ];
    for (freq, dur) in notes {
        beep(freq, dur);
        pit_busy_wait(30);
    }
}

// =========================================================================
// Non-blocking music player (runtime, uses PIT tick)
// =========================================================================

/// A musical note: frequency in Hz and duration code.
/// Duration codes map to note lengths at a given tempo.
///
/// | Code | Note value | Example at 120 BPM |
/// |------|-----------|-------------------|
/// | 1    | Whole     | 2000ms            |
/// | 2    | Half      | 1000ms            |
/// | 4    | Quarter   | 500ms             |
/// | 8    | Eighth    | 250ms             |
/// | 16   | Sixteenth | 125ms             |
pub struct Note {
    pub freq: u32,
    pub dur: u32, // duration code (1, 2, 4, 8, 16)
}

/// Special frequency values.
pub const REST: u32 = 0; // silence
pub const END: u32 = 0xFFFF; // end of sequence

/// Start playing a note sequence. Non-blocking : drained by `speaker_tick()`.
///
/// # Safety
/// `notes` and `durs` must remain valid until playback completes.
pub unsafe fn music_start(notes: &[u32], durs: &[u32], tempo_bpm: u32) {
    if notes.is_empty() || durs.is_empty() {
        return;
    }
    // Tempo: quarter note duration in ms = 60000 / bpm
    // Multiply by 100 for precision: 6_000_000 / bpm
    let quarter_ms = 6_000_000u32 / tempo_bpm;
    TEMPO.store((quarter_ms / 100) as u16, Ordering::Relaxed);

    NOTE_SEQ_PTR = notes.as_ptr();
    NOTE_DUR_PTR = durs.as_ptr();
    NOTE_TOTAL.store(notes.len() as u32, Ordering::Relaxed);
    NOTE_INDEX.store(0, Ordering::Relaxed);
    MUSIC_PLAYING.store(true, Ordering::SeqCst);

    // Start first note immediately
    speaker_tick();
}

/// Stop music playback.
pub fn music_stop() {
    MUSIC_PLAYING.store(false, Ordering::SeqCst);
    beep_off();
}

/// Returns whether music is currently playing.
pub fn music_playing() -> bool {
    MUSIC_PLAYING.load(Ordering::SeqCst)
}

/// Call this from the PIT timer interrupt (~10ms tick) to advance music playback.
///
/// The caller (timer ISR) must hold no locks that `speaker_tick` could contend.
pub fn speaker_tick() {
    if !MUSIC_PLAYING.load(Ordering::SeqCst) {
        return;
    }

    let ticks_left = NOTE_TICKS_LEFT.load(Ordering::Relaxed);
    if ticks_left > 1 {
        NOTE_TICKS_LEFT.store(ticks_left - 1, Ordering::Relaxed);
        return;
    }

    // Advance to next note
    let idx = NOTE_INDEX.load(Ordering::Relaxed);
    let total = NOTE_TOTAL.load(Ordering::Relaxed);

    if idx >= total || unsafe { *NOTE_SEQ_PTR.add(idx as usize) } == END {
        music_stop();
        return;
    }

    let freq = unsafe { *NOTE_SEQ_PTR.add(idx as usize) };
    let dur_code = unsafe { *NOTE_DUR_PTR.add(idx as usize) };

    NOTE_INDEX.store(idx + 1, Ordering::Relaxed);

    // Calculate duration in ticks (10ms per tick)
    // base_ms = (quarter_ms * 4) / dur_code
    let tempo = TEMPO.load(Ordering::Relaxed) as u32;
    let quarter_ms = tempo * 100;
    let base_ms = (quarter_ms * 4) / dur_code.max(1);
    let ticks = (base_ms / 10).max(1);

    NOTE_TICKS_LEFT.store(ticks, Ordering::Relaxed);
    NOTE_FREQ.store(freq, Ordering::Relaxed);

    unsafe {
        if freq == REST || freq == 0 {
            speaker_enable(false);
        } else {
            pit_set_freq(freq);
            speaker_enable(true);
        }
    }
}

// =========================================================================
// Built-in melodies
// =========================================================================

/// The Imperial March (Star Wars) : for panic screens.
/// Notes: (freq Hz, duration code)
pub const IMPERIAL_MARCH_NOTES: [u32; 16] = [
    392, 392, 392, 311, 466, 392, 311, 466, 392, 0, 587, 587, 587, 622, 466, 0,
];
pub const IMPERIAL_MARCH_DURS: [u32; 16] = [4, 4, 4, 8, 2, 4, 8, 2, 4, 4, 4, 4, 4, 4, 2, 4];

/// Startup jingle (ascending arpeggio).
pub const STARTUP_NOTES: [u32; 7] = [523, 0, 659, 0, 784, 0, 1047];
pub const STARTUP_DURS: [u32; 7] = [8, 16, 8, 16, 8, 16, 4];

/// Error / failure tone.
pub const ERROR_NOTES: [u32; 4] = [440, 415, 370, 330];
pub const ERROR_DURS: [u32; 4] = [4, 4, 4, 2];
