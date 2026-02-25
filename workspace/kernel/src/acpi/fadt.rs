//! Definitions for FADT, the Fixed ACPI Description Table.
//! Inspired by Theseus OS.

use super::sdt::{GenericAddressStructure, Sdt};
use zerocopy::{FromBytes, FromZeroes};

pub const FADT_SIGNATURE: &[u8; 4] = b"FACP";

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, FromZeroes)]
pub struct Fadt {
    pub header: Sdt,
    pub firmware_ctrl: u32,
    /// 32-bit physical address of the DSDT.
    pub dsdt: u32,
    _reserved: u8,
    pub preferred_power_managament: u8,
    pub sci_interrupt: u16,
    pub smi_command_port: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4_bios_req: u8,
    pub pstate_control: u8,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm2_control_block: u32,
    pub pm_timer_block: u32,
    pub gpe0_block: u32,
    pub gpe1_block: u32,
    pub pm1_event_length: u8,
    pub pm1_control_length: u8,
    pub pm2_control_length: u8,
    pub pm_timer_length: u8,
    pub gpe0_length: u8,
    pub gpe1_length: u8,
    pub gpe1_base: u8,
    pub c_state_control: u8,
    pub worst_c2_latency: u16,
    pub worst_c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,
    pub iapc_boot_architecture_flags: u16,
    _reserved2: u8,
    pub flags: u32,
    pub reset_reg: GenericAddressStructure,
    pub reset_value: u8,
    _reserved3: [u8; 3],
    /// 64-bit physical address of the FACS.
    pub x_firmware_control: u64,
    /// 64-bit physical address of the DSDT.
    pub x_dsdt: u64,
    pub x_pm1a_event_block: GenericAddressStructure,
    pub x_pm1b_event_block: GenericAddressStructure,
    pub x_pm1a_control_block: GenericAddressStructure,
    pub x_pm1b_control_block: GenericAddressStructure,
    pub x_pm2_control_block: GenericAddressStructure,
    pub x_pm_timer_block: GenericAddressStructure,
    pub x_gpe0_block: GenericAddressStructure,
    pub x_gpe1_block: GenericAddressStructure,
}

impl Fadt {
    /// Finds the FADT in the given `AcpiTables` and returns a reference to it.
    pub fn get() -> Option<&'static Fadt> {
        unsafe { super::find_table(FADT_SIGNATURE).map(|ptr| &*(ptr as *const Fadt)) }
    }
}
