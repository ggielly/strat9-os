//! L2 : encodage du bloc de contrôle s9vm (code noyau réel, non exécuté).

#[path = "../../kernel/src/s9vm/control.rs"]
mod control;

use control::{
    field, make_eptp, region_size_from_basic, revision_from_basic, FieldWidth,
};

#[test]
fn field_widths_match_architecture_encoding() {
    // Bits 14:13 de l'encodage : 00 = 16, 01 = 64, 10 = 32, 11 = naturel.
    assert_eq!(FieldWidth::of(field::GUEST_CS_SELECTOR), FieldWidth::Bits16);
    assert_eq!(FieldWidth::of(field::HOST_RIP), FieldWidth::Natural);
    assert_eq!(FieldWidth::of(field::GUEST_EFER), FieldWidth::Bits64);
    assert_eq!(FieldWidth::of(field::EPT_POINTER), FieldWidth::Bits64);
    assert_eq!(
        FieldWidth::of(field::PRIMARY_PROC_BASED_CONTROLS),
        FieldWidth::Bits32
    );
    assert_eq!(FieldWidth::of(field::EXIT_REASON), FieldWidth::Bits32);
    assert_eq!(FieldWidth::of(field::GUEST_RIP), FieldWidth::Natural);
    assert_eq!(FieldWidth::of(field::HOST_RSP), FieldWidth::Natural);
}

#[test]
fn critical_field_encodings_are_stable() {
    // Ces valeurs sont des invariants matériels ; une régression ici casserait
    // silencieusement toute entrée invitée.
    assert_eq!(field::GUEST_CR0, 0x6800);
    assert_eq!(field::GUEST_CR3, 0x6802);
    assert_eq!(field::GUEST_CR4, 0x6804);
    assert_eq!(field::GUEST_RSP, 0x681C);
    assert_eq!(field::GUEST_RIP, 0x681E);
    assert_eq!(field::GUEST_RFLAGS, 0x6820);
    assert_eq!(field::GUEST_PENDING_DEBUG_EXCEPTIONS, 0x6822);
    assert_eq!(field::HOST_RSP, 0x6C14);
    assert_eq!(field::HOST_RIP, 0x6C16);
    assert_eq!(field::EXIT_REASON, 0x4402);
    assert_eq!(field::EXIT_INTERRUPT_INFO, 0x4404);
    assert_eq!(field::IDT_VECTORING_INFO, 0x4408);
    assert_eq!(field::SECONDARY_PROC_BASED_CONTROLS, 0x401E);
    assert_eq!(field::TPR_THRESHOLD, 0x401C);
    assert_eq!(field::PLE_GAP, 0x4020);
    assert_eq!(field::PLE_WINDOW, 0x4022);
    assert_eq!(field::EPT_POINTER, 0x201A);
}

#[test]
fn revision_and_size_from_basic_msr() {
    // Révision 0x1A sur 31 bits, taille 4096 octets (bits 44:32).
    let basic = 0x1Au64 | (4096u64 << 32);
    assert_eq!(revision_from_basic(basic), 0x1A);
    assert_eq!(region_size_from_basic(basic), 4096);
}

#[test]
fn eptp_encoding_follows_sdm_layout() {
    let root = 0x1234_5000u64;
    let eptp = make_eptp(root, 6, true, true);
    // Bits 2:0 = WB (6), bits 5:3 = 3 (4 niveaux), bit 6 = A/D.
    assert_eq!(eptp & 0x7, 6);
    assert_eq!((eptp >> 3) & 0x7, 3);
    assert_eq!((eptp >> 6) & 1, 1);
    assert_eq!(eptp & 0x000F_FFFF_FFFF_F000, root);

    let without_ad = make_eptp(root, 6, true, false);
    assert_eq!((without_ad >> 6) & 1, 0);
}

#[test]
fn eptp_masks_low_address_bits() {
    // Les bits 11:0 de l'adresse racine sont réservés : ils doivent être nuls.
    let eptp = make_eptp(0x1000_0FFF, 6, true, false);
    assert_eq!(eptp & 0xFFF, 0x1E); // type WB (6) + longueur (3 << 3)
    assert_eq!(eptp & 0x000F_FFFF_FFFF_F000, 0x1000_0000);
}

#[test]
fn decodes_64bit_tss_descriptor_base() {
    use control::ControlBlock;

    // Descripteur de TSS 64 bits synthétique (16 octets) dont la base est
    // éclatée comme l'exige le mode long : base[15:0] octets 2-3,
    // base[23:16] octet 4, base[31:24] octet 7, base[63:32] octets 8-11.
    // Un décodage erroné (décalage ou morceau oublié) produisait une adresse
    // non canonique refusée à l'entrée invitée (`VMfail(8)`).
    let base: u64 = 0xFFFF_FFFF_808B_1640;
    let limit: u16 = 0x0067;
    let access: u8 = 0x89; // TSS 64 bits disponible, DPL 0
    let flags: u8 = 0x00;

    let low = (limit as u64)
        | (((base >> 0) & 0xFFFF) << 16)
        | (((base >> 16) & 0xFF) << 32)
        | ((access as u64) << 40)
        | (((base >> 24) & 0xFF) << 56)
        ;
    // Octet 6 (limite 19:16 + flags) inséré entre l'accès et la base haute.
    let low = low | ((flags as u64) << 48);
    let upper = (base >> 32) as u32;

    assert_eq!(ControlBlock::decode_tss_base(low, upper), base);

    // L'adresse décodée doit rester canonique (bits 63:48 = 0xFFFF).
    let decoded = ControlBlock::decode_tss_base(low, upper);
    assert_eq!(decoded >> 48, 0xFFFF);
    assert_eq!((decoded >> 47) & 1, 1);
}

#[test]
fn tss_base_decoder_handles_low_addresses() {
    use control::ControlBlock;

    let base: u64 = 0x0000_0000_0040_0000;
    let low = 0x67u64 | ((base & 0xFFFF) << 16) | (((base >> 16) & 0xFF) << 32);
    let upper = (base >> 32) as u32;
    assert_eq!(ControlBlock::decode_tss_base(low, upper), base);
}
