/*
 * This file is part of strat9-os.
 *
 * strat9-os is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * strat9-os is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with strat9-os. If not, see <https://www.gnu.org/licenses/>.
 *
 * Website: https://www.strat9-os.org
 * Repository: https://github.com/strat9-os/strat9-os
 *
 * Copyright (C) 2023-26 Guillaume Gielly
 */

//! L2: decoding and classification of s9vm exits (real kernel code).

#[path = "../../kernel/src/s9vm/exit.rs"]
mod exit;

use exit::{
    default_action, external_interrupt_info, reason_name, ExitAction, ExitClass, ExitReason, VectorEvent, CPUID,
    EPT_MISCONFIGURATION, EPT_VIOLATION, EXCEPTION_OR_NMI, EXTERNAL_INTERRUPT, HLT, IO_INSTRUCTION,
    PAUSE, PREEMPTION_TIMER, TRIPLE_FAULT,
};

#[test]
fn decodes_entry_failure_bit() {
    let normal = ExitReason::decode(EPT_VIOLATION as u32);
    assert_eq!(normal.reason, EPT_VIOLATION);
    assert!(!normal.entry_failed);
    assert_eq!(normal.raw(), EPT_VIOLATION as u32);

    let failed = ExitReason::decode(0x8000_0000 | 33);
    assert!(failed.entry_failed);
    assert_eq!(failed.reason, 33);
    assert_eq!(failed.class(), ExitClass::EntryFailure);
    assert_eq!(failed.raw(), 0x8000_0000 | 33);
}

#[test]
fn classifies_common_exits() {
    let cases = [
        (EXCEPTION_OR_NMI, ExitClass::ExceptionOrNmi),
        (EXTERNAL_INTERRUPT, ExitClass::ExternalInterrupt),
        (TRIPLE_FAULT, ExitClass::TripleFault),
        (CPUID, ExitClass::Cpuid),
        (HLT, ExitClass::Halt),
        (PAUSE, ExitClass::Pause),
        (IO_INSTRUCTION, ExitClass::IoPort),
        (EPT_VIOLATION, ExitClass::EptViolation),
        (EPT_MISCONFIGURATION, ExitClass::EptMisconfiguration),
        (PREEMPTION_TIMER, ExitClass::PreemptionTimer),
    ];
    for (reason, expected) in cases {
        assert_eq!(
            ExitReason::decode(reason as u32).class(),
            expected,
            "reason {}",
            reason
        );
    }
}

#[test]
fn default_routing_is_conservative() {
    // What the kernel handles on its own.
    assert_eq!(
        default_action(ExitClass::ExternalInterrupt),
        ExitAction::Resume
    );
    assert_eq!(default_action(ExitClass::Halt), ExitAction::Resume);
    assert_eq!(default_action(ExitClass::Apic), ExitAction::Resume);
    assert_eq!(
        default_action(ExitClass::PreemptionTimer),
        ExitAction::Resume
    );
    // What requires policy (slow path).
    assert_eq!(default_action(ExitClass::IoPort), ExitAction::Forward);
    assert_eq!(default_action(ExitClass::Msr), ExitAction::Forward);
    assert_eq!(default_action(ExitClass::Cpuid), ExitAction::Forward);
    assert_eq!(
        default_action(ExitClass::EptViolation),
        ExitAction::Forward
    );
    // Fatal.
    assert_eq!(default_action(ExitClass::TripleFault), ExitAction::Stop);
    assert_eq!(default_action(ExitClass::EntryFailure), ExitAction::Stop);
}

#[test]
fn decodes_vectoring_information() {
    // Vector 14 (#PF), type 3 (hardware exception), error code, valid.
    let info = 14 | (3 << 8) | (1 << 11) | (1 << 31);
    let event = VectorEvent::decode(info);
    assert_eq!(event.vector, 14);
    assert_eq!(event.kind, 3);
    assert!(event.error_code_valid);
    assert!(event.valid);
    assert!(event.is_exception());
    assert!(!event.is_nmi());

    // NMI (type 2), without error code.
    let nmi = VectorEvent::decode(2 | (2 << 8) | (1 << 31));
    assert!(nmi.is_nmi());
    assert!(!nmi.error_code_valid);
}

#[test]
fn reason_names_are_distinct_and_known() {
    assert_eq!(reason_name(EPT_VIOLATION), "second-level-violation");
    assert_eq!(reason_name(PREEMPTION_TIMER), "preemption-timer");
    assert_eq!(reason_name(CPUID), "cpuid");
    assert_eq!(reason_name(0xFFFF), "unknown");
}
#[test]
fn encodes_external_interrupt_injection_field() {
    // VM-entry interruption information field: bit 31 valid, external type
    // (bits 10:8 = 0), 8-bit vector.
    let info = external_interrupt_info(0x40);
    assert_eq!(info & (1 << 31), 1 << 31);
    assert_eq!((info >> 8) & 0x7, 0);
    assert_eq!(info & 0xFF, 0x40);
    assert_eq!(external_interrupt_info(0), 1 << 31);
    assert_eq!(external_interrupt_info(0xFF) & 0xFF, 0xFF);
}

