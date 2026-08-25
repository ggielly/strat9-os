//! Regression tests for `brcmstb_gisb` master-name resolution.
//!
//! Issue #56: `add_master_name()` was never called anywhere, so captured
//! masters could never be identified in error reports. These tests pin the
//! resolution contract of `master_name()` and the `format_error()` report.

use strat9_bus_drivers::brcmstb_gisb::{BCM7445_OFFSETS, BrcmstbGisb, GisbErrorInfo};

#[test]
fn master_names_can_be_bulk_loaded() {
    let mut gisb = BrcmstbGisb::new(BCM7445_OFFSETS);
    gisb.set_master_names(["cpu0".into(), "cpu1".into(), "nand".into()]);

    assert_eq!(gisb.master_name(Some(0)), "cpu0");
    assert_eq!(gisb.master_name(Some(1)), "cpu1");
    assert_eq!(gisb.master_name(Some(2)), "nand");
}

#[test]
fn add_master_name_appends_in_order() {
    let mut gisb = BrcmstbGisb::new(BCM7445_OFFSETS);
    gisb.add_master_name("first".into());
    gisb.add_master_name("second".into());

    // Slot 0 = first registered name, slot 1 = second.
    assert_eq!(gisb.master_name(Some(0)), "first");
    assert_eq!(gisb.master_name(Some(1)), "second");

    // Bulk-load replaces (does not concatenate with) previous entries.
    gisb.set_master_names(["only".into()]);
    assert_eq!(gisb.master_name(Some(0)), "only");
    assert_eq!(gisb.master_name(Some(1)), "master1");
}

#[test]
fn unknown_master_ids_fall_back_to_masterN() {
    let mut gisb = BrcmstbGisb::new(BCM7445_OFFSETS);
    gisb.set_master_names(["cpu0".into()]);

    assert_eq!(gisb.master_name(Some(42)), "master42");
}

#[test]
fn generations_without_master_register_report_none() {
    let gisb = BrcmstbGisb::new(BCM7445_OFFSETS);
    assert_eq!(gisb.master_name(None), "none");
}

#[test]
fn format_error_renders_a_complete_report_line() {
    let mut gisb = BrcmstbGisb::new(BCM7445_OFFSETS);
    gisb.set_master_names(["ethsw".into(), "sata".into()]);

    let info = GisbErrorInfo {
        address: 0x0000_0000_dead_beef,
        master: Some(1),
        is_write: true,
        is_timeout: true,
        is_tea: false,
    };
    assert_eq!(
        gisb.format_error(&info),
        "gisb timeout write addr=0x00000000deadbeef master=sata"
    );

    let read_err = GisbErrorInfo {
        address: 0x100,
        master: Some(9),
        is_write: false,
        is_timeout: false,
        is_tea: true,
    };
    assert_eq!(
        gisb.format_error(&read_err),
        "gisb tea read addr=0x0000000000000100 master=master9"
    );
}
