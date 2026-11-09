//! L2 : modèle d'APIC local invité (code noyau réel, non exécuté).

#[path = "../../kernel/src/s9vm/apic.rs"]
mod apic;

use apic::{delivery, reg, shorthand, x2apic, LocalApic, SVR_ENABLE, VERSION_VALUE};

#[test]
fn reset_state_is_architectural() {
    let apic = LocalApic::new(3);
    assert_eq!(apic.apic_id(), 3);
    assert_eq!(apic.tpr(), 0);
    assert_eq!(apic.ppr(), 0);
    assert!(apic.enabled());
    assert!(!apic.has_pending());
    assert!(!apic.in_service());
    assert_eq!(apic.mmio_read(reg::VERSION), VERSION_VALUE);
}

#[test]
fn inject_service_eoi_cycle() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x21);
    assert!(apic.has_pending());
    assert_eq!(apic.pending_vector(), Some(0x21));
    assert_eq!(apic.service(), Some(0x21));
    assert!(!apic.has_pending());
    assert!(apic.in_service());
    assert_eq!(apic.ppr(), 0x20);
    apic.eoi();
    assert!(!apic.in_service());
    assert_eq!(apic.ppr(), 0);
}

#[test]
fn tpr_blocks_lower_priority_classes() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::TPR, 0x30);
    apic.inject(0x21); // classe 2 <= 3 : bloqué
    assert_eq!(apic.pending_vector(), None);
    apic.inject(0x41); // classe 4 > 3 : délivrable
    assert_eq!(apic.pending_vector(), Some(0x41));
}

#[test]
fn isr_raises_ppr_and_blocks_same_class() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x30);
    apic.inject(0x31);
    assert_eq!(apic.service(), Some(0x30));
    // Même classe que le vecteur en service : bloqué.
    assert_eq!(apic.pending_vector(), None);
    apic.inject(0x40);
    assert_eq!(apic.pending_vector(), Some(0x40));
}

#[test]
fn disabled_spurious_register_blocks_delivery() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::SVR, 0);
    apic.inject(0x80);
    assert!(!apic.enabled());
    assert_eq!(apic.pending_vector(), None);
    apic.mmio_write(reg::SVR, SVR_ENABLE | 0xFF);
    assert!(apic.enabled());
    assert_eq!(apic.pending_vector(), Some(0x80));
}

#[test]
fn reserved_vectors_are_ignored() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x0F);
    assert!(apic.has_pending());
    assert_eq!(apic.pending_vector(), None);
}

#[test]
fn eoi_clears_highest_in_service_first() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x30);
    apic.inject(0x40);
    assert_eq!(apic.service(), Some(0x30));
    assert_eq!(apic.service(), Some(0x40));
    assert_eq!(apic.ppr(), 0x40);
    apic.eoi();
    assert_eq!(apic.ppr(), 0x30);
    apic.eoi();
    assert!(!apic.in_service());
}

#[test]
fn self_ipi_injects_vector() {
    let mut apic = LocalApic::new(0);
    let icr = (shorthand::SELF << 18) | (delivery::FIXED << 8) | 0x55;
    apic.mmio_write(reg::ICR_LOW, icr);
    assert_eq!(apic.pending_vector(), Some(0x55));
}

#[test]
fn mmio_registers_round_trip() {
    let mut apic = LocalApic::new(0);
    apic.mmio_write(reg::TPR, 0xFFFF_FFFF);
    assert_eq!(apic.tpr(), 0xFF);
    apic.mmio_write(reg::LVT_TIMER, 0x0001_00AB);
    assert_eq!(apic.mmio_read(reg::LVT_TIMER), 0x0001_00AB);
    apic.mmio_write(reg::INITIAL_COUNT, 1234);
    assert_eq!(apic.mmio_read(reg::CURRENT_COUNT), 1234);
    apic.mmio_write(reg::ESR, 0x40);
    assert_eq!(apic.mmio_read(reg::ESR), 0x40);
}

#[test]
fn isr_and_irr_words_use_16_byte_stride() {
    let mut apic = LocalApic::new(0);
    apic.inject(0x40); // mot 2
    assert_eq!(apic.mmio_read(reg::IRR + 2 * 16), 0x1);
    assert_eq!(apic.mmio_read(reg::IRR), 0);
    apic.service();
    assert_eq!(apic.mmio_read(reg::ISR + 2 * 16), 0x1);
}

#[test]
fn x2apic_round_trip_and_reserved() {
    let mut apic = LocalApic::new(5);
    assert_eq!(apic.x2apic_read(x2apic::ID), Some(5 << 24));
    assert_eq!(apic.x2apic_read(0x999), None);

    assert!(apic.x2apic_write(x2apic::TPR, 0x40));
    assert_eq!(apic.tpr(), 0x40);
    // IPI vers soi-même via ICR x2APIC.
    let icr = ((shorthand::SELF as u64) << 18) | ((delivery::FIXED as u64) << 8) | 0x60;
    assert!(apic.x2apic_write(x2apic::ICR, icr));
    assert_eq!(apic.pending_vector(), Some(0x60));
    // SELF-IPI x2APIC.
    assert!(apic.x2apic_write(x2apic::SELF_IPI, 0x70));
    assert_eq!(apic.pending_vector(), Some(0x60));
}

#[test]
fn priority_classes_follow_the_high_nibble() {
    assert_eq!(apic::priority_class(0x00), 0);
    assert_eq!(apic::priority_class(0x1F), 1);
    assert_eq!(apic::priority_class(0xF0), 0xF);
    assert_eq!(apic::priority_class(0xFF), 0xF);
}
