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

//! L2: executes the real-mode BIOS stubs, not just their encoding.
//!
//! The byte contract of [`biosrom::shared_tail_bytes`] is easy to get wrong:
//! the stub pushes `AX`/`DX`, the kernel rewrites the guest registers at the
//! `OUT` exit, and the tail must return the caller's `DS`, `BP` and the
//! kernel-written `AX` before its `IRET`. A wrong pop order still encodes to
//! "a push and a pop for every register" yet hands a DOS boot sector a garbage
//! `DS`, which is exactly the failure this interpreter reproduces cheaply.
//!
//! The interpreter below supports only the instructions [`biosrom`] emits, so
//! it stays a few dozen lines while still executing the real bytes.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../kernel/src/s9vm/biosrom.rs"]
mod biosrom;

use alloc::{vec, vec::Vec};
use biosrom::{
    FAULT_PORT_BASE, ROM_SEGMENT, RomMemory, SCRATCH_GPA, VECTORS, bios_port, fault_port, install,
    stub_offset,
};

/// Guest memory size: covers the IVT, the low 640 KiB and the BIOS ROM.
const MEMORY_LEN: usize = 0x10_0000;

/// Linear guest address of a real-mode `segment:offset` pair (1 MiB wrap).
fn linear(segment: u16, offset: u16) -> u32 {
    ((u32::from(segment) << 4) + u32::from(offset)) & 0xF_FFFF
}

/// Flat guest memory handed to the firmware installer.
struct FlatRom<'a> {
    data: &'a mut Vec<u8>,
}

impl RomMemory for FlatRom<'_> {
    fn write(&mut self, address: u32, bytes: &[u8]) -> bool {
        let start = address as usize;
        let Some(end) = start.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.data.len() {
            return false;
        }
        self.data[start..end].copy_from_slice(bytes);
        true
    }

    fn read(&mut self, address: u32, out: &mut [u8]) -> bool {
        let start = address as usize;
        let Some(end) = start.checked_add(out.len()) else {
            return false;
        };
        if end > self.data.len() {
            return false;
        }
        out.copy_from_slice(&self.data[start..end]);
        true
    }
}

/// Result of executing one instruction.
enum Step {
    /// The instruction completed and execution continues.
    Continue,
    /// An `OUT` reached the host: the kernel services it before the guest runs.
    Out { port: u16, value: u8 },
    /// The stub returned to its caller; the CPU state is final.
    Iret,
}

/// Minimal 16-bit real-mode CPU state plus the instructions the stubs use.
struct Cpu {
    mem: Vec<u8>,
    ax: u16,
    bx: u16,
    cx: u16,
    dx: u16,
    si: u16,
    di: u16,
    bp: u16,
    sp: u16,
    ds: u16,
    es: u16,
    ss: u16,
    cs: u16,
    ip: u16,
    flags: u16,
}

impl Cpu {
    fn read_u8(&self, segment: u16, offset: u16) -> u8 {
        self.mem[linear(segment, offset) as usize]
    }

    fn write_u8(&mut self, segment: u16, offset: u16, value: u8) {
        self.mem[linear(segment, offset) as usize] = value;
    }

    fn read_u16(&self, segment: u16, offset: u16) -> u16 {
        let lo = self.read_u8(segment, offset);
        let hi = self.read_u8(segment, offset.wrapping_add(1));
        u16::from_le_bytes([lo, hi])
    }

    fn write_u16(&mut self, segment: u16, offset: u16, value: u16) {
        let bytes = value.to_le_bytes();
        self.write_u8(segment, offset, bytes[0]);
        self.write_u8(segment, offset.wrapping_add(1), bytes[1]);
    }

    fn push(&mut self, value: u16) {
        self.sp = self.sp.wrapping_sub(2);
        self.write_u16(self.ss, self.sp, value);
    }

    fn pop(&mut self) -> u16 {
        let value = self.read_u16(self.ss, self.sp);
        self.sp = self.sp.wrapping_add(2);
        value
    }

    fn fetch_u8(&mut self) -> u8 {
        let value = self.read_u8(self.cs, self.ip);
        self.ip = self.ip.wrapping_add(1);
        value
    }

    fn fetch_u16(&mut self) -> u16 {
        let lo = self.fetch_u8();
        let hi = self.fetch_u8();
        u16::from_le_bytes([lo, hi])
    }

    fn zf(&self) -> bool {
        self.flags & 0x0040 != 0
    }

    /// `test al, imm`: `ZF` follows the result, `CF` and `OF` are cleared.
    fn test_al(&mut self, imm: u8) {
        let al = (self.ax & 0xFF) as u8;
        self.flags = (self.flags & !0x0001) | if al & imm == 0 { 0x0040 } else { 0 };
    }

    /// Encodes and executes one instruction of the emitted instruction set.
    fn step(&mut self) -> Step {
        let opcode = self.fetch_u8();
        match opcode {
            0x50 => {
                let value = self.ax;
                self.push(value);
            }
            0x52 => {
                let value = self.dx;
                self.push(value);
            }
            0x55 => {
                let value = self.bp;
                self.push(value);
            }
            0x58 => {
                self.ax = self.pop();
            }
            0x5A => {
                self.dx = self.pop();
            }
            0x5D => {
                self.bp = self.pop();
            }
            0x1E => {
                let value = self.ds;
                self.push(value);
            }
            0x1F => {
                self.ds = self.pop();
            }
            0x6A => {
                let imm = self.fetch_u8() as i8 as i16 as u16;
                self.push(imm);
            }
            0x88 => {
                // mov al, ah
                assert_eq!(self.fetch_u8(), 0xE0, "unsupported 0x88 form");
                self.ax = (self.ax & 0xFF00) | ((self.ax >> 8) & 0x00FF);
            }
            0x89 => {
                // mov bp, sp
                assert_eq!(self.fetch_u8(), 0xE5, "unsupported 0x89 form");
                self.bp = self.sp;
            }
            0x83 => {
                let modrm = self.fetch_u8();
                // `83 /n ib` sign-extends its immediate to 16 bits: the stub
                // relies on it (`and word [..], 0xFFBF` is the byte 0xBF).
                let fetch_imm = |cpu: &mut Self| cpu.fetch_u8() as i8 as i16 as u16;
                match modrm {
                    // add sp, imm8
                    0xC4 => {
                        let imm = fetch_imm(self);
                        self.sp = self.sp.wrapping_add(imm);
                    }
                    // or word [bp + disp8], imm8
                    0x4E => {
                        let displacement = self.fetch_u8() as i8 as i16 as u16;
                        let imm = fetch_imm(self);
                        let address = self.bp.wrapping_add(displacement);
                        let value = self.read_u16(self.ss, address) | imm;
                        self.write_u16(self.ss, address, value);
                    }
                    // and word [bp + disp8], imm8
                    0x66 => {
                        let displacement = self.fetch_u8() as i8 as i16 as u16;
                        let imm = fetch_imm(self);
                        let address = self.bp.wrapping_add(displacement);
                        let value = self.read_u16(self.ss, address) & imm;
                        self.write_u16(self.ss, address, value);
                    }
                    other => panic!("unsupported 0x83 /{other:#04x}"),
                }
            }
            0xA0 => {
                // mov al, [imm16] (assembler-style absolute address, DS base)
                let offset = self.fetch_u16();
                let value = self.read_u8(self.ds, offset);
                self.ax = (self.ax & 0xFF00) | u16::from(value);
            }
            0xA8 => {
                let imm = self.fetch_u8();
                self.test_al(imm);
            }
            0xBA => {
                self.dx = self.fetch_u16();
            }
            0xE9 => {
                let displacement = self.fetch_u16() as i16 as u16;
                self.ip = self.ip.wrapping_add(displacement);
            }
            0xEB => {
                let displacement = self.fetch_u8() as i8 as i16 as u16;
                self.ip = self.ip.wrapping_add(displacement);
            }
            0x74 => {
                let displacement = self.fetch_u8() as i8 as i16 as u16;
                if self.zf() {
                    self.ip = self.ip.wrapping_add(displacement);
                }
            }
            0xEE => {
                return Step::Out {
                    port: self.dx,
                    value: (self.ax & 0xFF) as u8,
                };
            }
            0xCF => {
                self.ip = self.pop();
                self.cs = self.pop();
                self.flags = self.pop();
                return Step::Iret;
            }
            other => panic!(
                "unsupported opcode {other:#04x} at {:#06x}:{:#06x}",
                self.cs, self.ip
            ),
        }
        Step::Continue
    }
}

/// Fresh CPU with the firmware installed at its documented place.
fn cpu_with_firmware() -> Cpu {
    let mut mem = vec![0u8; MEMORY_LEN];
    let mut rom = FlatRom { data: &mut mem };
    install(&mut rom, &VECTORS).expect("firmware install");
    Cpu {
        mem,
        ax: 0,
        bx: 0,
        cx: 0,
        dx: 0,
        si: 0,
        di: 0,
        bp: 0,
        sp: 0,
        ds: 0,
        es: 0,
        ss: 0,
        cs: 0,
        ip: 0,
        flags: 0x0002,
    }
}

/// Simulates the `INT vector` instruction at the current `CS:IP`.
fn invoke_interrupt(cpu: &mut Cpu, vector: u8) {
    let (flags, cs, ip) = (cpu.flags, cpu.cs, cpu.ip);
    cpu.push(flags);
    cpu.push(cs);
    cpu.push(ip);
    cpu.cs = ROM_SEGMENT;
    cpu.ip = stub_offset(vector);
}

/// Runs until the guest reaches an `OUT`, returning the reported port and byte.
fn run_to_out(cpu: &mut Cpu) -> (u16, u8) {
    for _ in 0..10_000 {
        match cpu.step() {
            Step::Out { port, value } => return (port, value),
            Step::Continue => {}
            Step::Iret => panic!("iret before any out"),
        }
    }
    panic!("stub did not reach an out");
}

/// Runs until the stub returns through `IRET`.
fn run_to_iret(cpu: &mut Cpu) {
    for _ in 0..10_000 {
        match cpu.step() {
            Step::Iret => return,
            Step::Continue => {}
            Step::Out { port, .. } => panic!("unexpected out on port {port:#06x}"),
        }
    }
    panic!("stub did not return through iret");
}

/// Recovers the caller `AX`/`DX` the way the kernel does at the `OUT` exit.
fn caller_registers(cpu: &Cpu) -> (u16, u16) {
    let dx = cpu.read_u16(cpu.ss, cpu.sp);
    let ax = cpu.read_u16(cpu.ss, cpu.sp.wrapping_add(2));
    (ax, dx)
}

/// Snapshot of the registers a BIOS call must not change.
fn preserved(cpu: &Cpu) -> (u16, u16, u16, u16, u16, u16, u16, u16, u16, u16) {
    (
        cpu.ax, cpu.bx, cpu.cx, cpu.dx, cpu.si, cpu.di, cpu.bp, cpu.ds, cpu.es, cpu.sp,
    )
}

fn preset_caller(cpu: &mut Cpu) {
    cpu.ax = 0x0E2E;
    cpu.bx = 0x1234;
    cpu.cx = 0x0005;
    cpu.dx = 0x0000;
    cpu.si = 0x7D70;
    cpu.di = 0x00AA;
    cpu.bp = 0x7C00;
    cpu.sp = 0x7C00;
    cpu.ds = 0x1FE0;
    cpu.es = 0x0040;
    cpu.ss = 0x0000;
    cpu.cs = 0x1FE0;
    cpu.ip = 0x7D43;
    cpu.flags = 0x0202;
}

#[test]
fn int10_returns_with_the_caller_ds_bp_and_the_kernel_ax() {
    let mut cpu = cpu_with_firmware();
    preset_caller(&mut cpu);
    invoke_interrupt(&mut cpu, 0x10);

    let (port, value) = run_to_out(&mut cpu);
    assert_eq!(
        port,
        bios_port(0x10),
        "the stub reports the vector on its port"
    );
    assert_eq!(value, 0x0E, "the reported byte is AH, the BIOS command");
    // The kernel recovers the real caller values from the saved stack words.
    assert_eq!(caller_registers(&cpu), (0x0E2E, 0x0000));

    // Kernel model: echo AX, keep DX, report success (CF=0, ZF=0).
    cpu.ax = 0x0E2E;
    cpu.dx = 0x0000;
    cpu.mem[SCRATCH_GPA as usize] = 0;
    run_to_iret(&mut cpu);

    // The whole register file is back where the caller left it, and the
    // kernel-written AX reached the guest. A wrong pop order returns
    // DS=0x0E2E, BP=0x1FE0 and AX=0x7C00 here, which is what broke the
    // FreeDOS boot sector.
    assert_eq!(
        preserved(&cpu),
        (
            0x0E2E, 0x1234, 0x0005, 0x0000, 0x7D70, 0x00AA, 0x7C00, 0x1FE0, 0x0040, 0x7C00
        )
    );
    assert_eq!((cpu.cs, cpu.ip), (0x1FE0, 0x7D43));
    assert_eq!(cpu.flags, 0x0202);
}

#[test]
fn int10_reports_cf_and_zf_from_the_kernel_scratch_byte() {
    let mut cpu = cpu_with_firmware();
    preset_caller(&mut cpu);
    invoke_interrupt(&mut cpu, 0x10);
    let _ = run_to_out(&mut cpu);
    cpu.ax = 0x0E2E;
    cpu.dx = 0x0000;
    // Scratch bit 0 = CF, bit 1 = ZF.
    cpu.mem[SCRATCH_GPA as usize] = 0b11;
    run_to_iret(&mut cpu);
    assert_eq!(cpu.flags, 0x0202 | 0x0001 | 0x0040);
}

#[test]
fn int13_keeps_the_kernel_written_dx_result() {
    let mut cpu = cpu_with_firmware();
    preset_caller(&mut cpu);
    // INT 13h AH=08h returns the drive count in DX; the stub had put its port
    // there, so the tail must not restore that saved value.
    cpu.ax = 0x0800;
    cpu.dx = 0x0000;
    invoke_interrupt(&mut cpu, 0x13);
    let (port, value) = run_to_out(&mut cpu);
    assert_eq!(port, bios_port(0x13));
    assert_eq!(value, 0x08);
    assert_eq!(caller_registers(&cpu), (0x0800, 0x0000));
    cpu.ax = 0x0202;
    cpu.dx = 0x0001;
    cpu.mem[SCRATCH_GPA as usize] = 0;
    run_to_iret(&mut cpu);
    assert_eq!(cpu.ax, 0x0202);
    assert_eq!(cpu.dx, 0x0001, "the kernel DX result must survive the tail");
    assert_eq!(preserved(&cpu).1, 0x1234);
    assert_eq!(preserved(&cpu).5, 0x00AA);
    assert_eq!(preserved(&cpu).6, 0x7C00);
    assert_eq!(preserved(&cpu).7, 0x1FE0);
}

#[test]
fn every_serviced_vector_preserves_the_caller_register_file() {
    for &vector in &VECTORS {
        let mut cpu = cpu_with_firmware();
        preset_caller(&mut cpu);
        invoke_interrupt(&mut cpu, vector);
        let (port, _value) = run_to_out(&mut cpu);
        assert_eq!(port, bios_port(vector), "vector {vector:#04x}");
        let (ax, dx) = caller_registers(&cpu);
        assert_eq!(ax, 0x0E2E, "vector {vector:#04x}");
        assert_eq!(dx, 0x0000, "vector {vector:#04x}");
        // The kernel returns the same values for every vector here.
        cpu.ax = 0x0E2E;
        cpu.dx = 0x0000;
        cpu.mem[SCRATCH_GPA as usize] = 0;
        run_to_iret(&mut cpu);
        assert_eq!(
            preserved(&cpu),
            (
                0x0E2E, 0x1234, 0x0005, 0x0000, 0x7D70, 0x00AA, 0x7C00, 0x1FE0, 0x0040, 0x7C00
            ),
            "vector {vector:#04x}"
        );
        assert_eq!((cpu.cs, cpu.ip), (0x1FE0, 0x7D43));
    }
}

#[test]
fn catch_all_stub_reports_the_vector_and_returns_unchanged() {
    let mut cpu = cpu_with_firmware();
    preset_caller(&mut cpu);
    cpu.ax = 0xBEEF;
    cpu.bx = 0x1234;
    cpu.cx = 0x5678;
    cpu.dx = 0x9ABC;
    cpu.flags = 0x0246;
    invoke_interrupt(&mut cpu, 0x20);

    let (port, _value) = run_to_out(&mut cpu);
    assert_eq!(port, fault_port(0x20));
    assert_eq!(port, FAULT_PORT_BASE + 0x20);
    // The catch-all stub pushes DX first, then the hardware frame follows.
    let stacked_ip = cpu.read_u16(cpu.ss, cpu.sp.wrapping_add(2));
    let stacked_cs = cpu.read_u16(cpu.ss, cpu.sp.wrapping_add(4));
    let stacked_flags = cpu.read_u16(cpu.ss, cpu.sp.wrapping_add(6));
    assert_eq!((stacked_cs, stacked_ip), (0x1FE0, 0x7D43));
    assert_eq!(stacked_flags, 0x0246);

    run_to_iret(&mut cpu);
    // A vector with no firmware service must not change the guest at all.
    assert_eq!(
        preserved(&cpu),
        (
            0xBEEF, 0x1234, 0x5678, 0x9ABC, 0x7D70, 0x00AA, 0x7C00, 0x1FE0, 0x0040, 0x7C00
        )
    );
    assert_eq!((cpu.cs, cpu.ip), (0x1FE0, 0x7D43));
    assert_eq!(cpu.flags, 0x0246);
}

#[test]
fn catch_all_stub_uses_one_distinct_port_per_vector() {
    // Only vectors without a firmware service use the catch-all stub.
    for vector in [0x00u8, 0x01, 0x07, 0x1B, 0x1F, 0x21, 0xFF] {
        let mut cpu = cpu_with_firmware();
        preset_caller(&mut cpu);
        invoke_interrupt(&mut cpu, vector);
        let (port, _value) = run_to_out(&mut cpu);
        assert_eq!(port, fault_port(vector), "vector {vector:#04x}");
    }
}
