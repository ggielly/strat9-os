//! Procfs - process filesystem (similar to Linux & BSD /proc)
//!
//! Provides information about running processes and system state.
//!
//! # Structure
//!
//! ```text
//! /proc/
//!   self/       -> symlink to current process
//!   <pid>/      -> process directory
//!     status    -> process status
//!     cmdline   -> command line
//!     fd/       -> file descriptors
//!   cpuinfo     -> CPU information
//!   meminfo     -> memory information
//!   version     -> kernel version
//! ```

use crate::{
    process::{current_pid, get_all_tasks, get_parent_pid},
    syscall::error::SyscallError,
    vfs::scheme::{DirEntry, DynScheme, DT_DIR, DT_REG, FileFlags, FileStat, OpenFlags, OpenResult, Scheme},
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::fmt::Write;

/// Procfs scheme
pub struct ProcScheme {
    // Empty for now - stateless
}

impl ProcScheme {
    pub fn new() -> Self {
        ProcScheme {}
    }

    /// Get procfs entry content
    fn get_entry(&self, path: &str) -> Result<ProcEntry, SyscallError> {
        // Handle /proc/self
        if path == "self" || path == "self/" {
            if let Some(pid) = current_pid() {
                return Ok(ProcEntry::File(format!("{}\n", pid)));
            }
            return Err(SyscallError::NotFound);
        }

        // Handle /proc/self/status
        if path.starts_with("self/") {
            let subpath = &path[5..];
            if let Some(pid) = current_pid() {
                return self.get_process_entry(pid as u64, subpath);
            }
            return Err(SyscallError::NotFound);
        }

        // Handle /proc/<pid>/...
        if let Some(pid_end) = path.find('/') {
            let pid_str = &path[..pid_end];
            let subpath = &path[pid_end + 1..];
            if let Ok(pid) = pid_str.parse::<u64>() {
                return self.get_process_entry(pid, subpath);
            }
        }

        // Handle /proc/<pid> (directory listing)
        if let Ok(pid) = path.parse::<u64>() {
            return Ok(ProcEntry::Directory);
        }

        // Handle root entries
        match path {
            "" | "/" => Ok(ProcEntry::Directory),
            "cpuinfo" => Ok(ProcEntry::File(self.get_cpuinfo())),
            "meminfo" => Ok(ProcEntry::File(self.get_meminfo())),
            "version" => Ok(ProcEntry::File(self.get_version())),
            _ => Err(SyscallError::NotFound),
        }
    }

    /// Get process-specific entry
    fn get_process_entry(&self, pid: u64, subpath: &str) -> Result<ProcEntry, SyscallError> {
        let tasks = get_all_tasks().ok_or(SyscallError::NotFound)?;
        let task = tasks
            .iter()
            .find(|t| t.pid as u64 == pid)
            .ok_or(SyscallError::NotFound)?;

        match subpath {
            "" | "/" => Ok(ProcEntry::Directory),
            "status" => Ok(ProcEntry::File(self.get_process_status(task))),
            "cmdline" => Ok(ProcEntry::File(format!("{}\n", task.name))),
            _ => Err(SyscallError::NotFound),
        }
    }

    /// Generate /proc/cpuinfo content
    fn get_cpuinfo(&self) -> String {
        let mut output = String::new();
        let cpu_count = crate::arch::x86_64::percpu::get_cpu_count();

        for i in 0..cpu_count {
            let _ = writeln!(output, "processor\t: {}", i);
            let _ = writeln!(output, "vendor_id\t: GenuineIntel");
            let _ = writeln!(output, "cpu family\t: 6");
            let _ = writeln!(output, "model\t\t: 85");
            let _ = writeln!(output, "model name\t: QEMU Virtual CPU");
            let _ = writeln!(output, "stepping\t: 0");
            let _ = writeln!(output, "cpu MHz\t\t: 2400.000");
            let _ = writeln!(output, "cache size\t: 4096 KB");
            let _ = writeln!(output, "physical id\t: {}", i);
            let _ = writeln!(output, "siblings\t: 1");
            let _ = writeln!(output, "core id\t\t: {}", i);
            let _ = writeln!(output, "cpu cores\t: 1");
            let _ = writeln!(output, "apicid\t\t: {}", i);
            let _ = writeln!(output, "fpu\t\t: yes");
            let _ = writeln!(output, "fpu_exception\t: yes");
            let _ = writeln!(output, "cpuid level\t: 13");
            let _ = writeln!(output, "wp\t\t: yes");
            let _ = writeln!(output, "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx rdtscp lm constant_tsc rep_good nopl xtopology");
            let _ = writeln!(output, "bugs\t\t: spectre_v1 spectre_v2 spec_store_bypass");
            let _ = writeln!(output, "bogomips\t: 4800.00");
            let _ = writeln!(output, "clflush size\t: 64");
            let _ = writeln!(output, "cache_alignment\t: 64");
            let _ = writeln!(output, "address sizes\t: 40 bits physical, 48 bits virtual");
            let _ = writeln!(output, "power management:\n");
            let _ = writeln!(output, "");
        }

        output
    }

    /// Generate /proc/meminfo content
    fn get_meminfo(&self) -> String {
        // Simplified meminfo for now
        let mut output = String::new();
        let _ = writeln!(output, "MemTotal:       {:>10} kB", 262144); // 256 MB default
        let _ = writeln!(output, "MemFree:        {:>10} kB", 131072);
        let _ = writeln!(output, "MemUsed:        {:>10} kB", 131072);
        let _ = writeln!(output, "Buffers:               0 kB");
        let _ = writeln!(output, "Cached:                0 kB");
        let _ = writeln!(output, "SwapTotal:             0 kB");
        let _ = writeln!(output, "SwapFree:              0 kB");
        output
    }

    /// Generate /proc/version content
    fn get_version(&self) -> String {
        format!("Strat9-OS version 0.1.0 (Bedrock) #1 SMP x86_64 Strat9\n")
    }

    /// Generate process status
    fn get_process_status(&self, task: &Arc<crate::process::task::Task>) -> String {
        let mut output = String::new();

        let _ = writeln!(output, "Name:\t{}", task.name);
        let _ = writeln!(output, "State:\tR (running)");
        let _ = writeln!(output, "Tgid:\t{}", task.tgid);
        let _ = writeln!(output, "Pid:\t{}", task.pid);
        let _ = writeln!(
            output,
            "PPid:\t{}",
            get_parent_pid(task.id).map(|p| p as u64).unwrap_or(0)
        );
        let _ = writeln!(
            output,
            "Pgid:\t{}",
            task.pgid.load(core::sync::atomic::Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "Sid:\t{}",
            task.sid.load(core::sync::atomic::Ordering::Relaxed)
        );
        let uid = task.uid.load(core::sync::atomic::Ordering::Relaxed);
        let euid = task.euid.load(core::sync::atomic::Ordering::Relaxed);
        let gid = task.gid.load(core::sync::atomic::Ordering::Relaxed);
        let egid = task.egid.load(core::sync::atomic::Ordering::Relaxed);
        let _ = writeln!(output, "Uid:\t{}\t{}\t{}\t{}", uid, euid, euid, euid);
        let _ = writeln!(output, "Gid:\t{}\t{}\t{}\t{}", gid, egid, egid, egid);
        let _ = writeln!(output, "Threads:\t1");

        output
    }
}

/// Procfs entry type
enum ProcEntry {
    File(String),
    Directory,
}

/// Kind constants for procfs file-id encoding.
/// Fixed IDs (0, 1, 10, 11, 12) use kind = 0 and are stored as-is.
const KIND_PROC_DIR: u64 = 1; // /proc/<pid>  directory
const KIND_PROC_STATUS: u64 = 2; // /proc/<pid>/status
const KIND_PROC_CMDLINE: u64 = 3; // /proc/<pid>/cmdline

impl ProcScheme {
    /// Encode a (kind, pid) pair into a file_id.
    ///
    /// The high 32 bits hold the kind; the low 32 bits hold the pid.
    /// This guarantees no collision between entries regardless of PID value.
    fn encode_id(kind: u64, pid: u64) -> u64 {
        (kind << 32) | (pid & 0xFFFF_FFFF)
    }

    /// Decode a file_id back into (kind, pid).
    fn decode_id(id: u64) -> (u64, u64) {
        (id >> 32, id & 0xFFFF_FFFF)
    }
}

impl Scheme for ProcScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let entry = self.get_entry(path)?;

        let (flags, file_id) = match entry {
            ProcEntry::File(_) => {
                let id = match path {
                    "cpuinfo" => 10,
                    "meminfo" => 11,
                    "version" => 12,
                    "self/status" => {
                        Self::encode_id(KIND_PROC_STATUS, current_pid().map(|p| p as u64).unwrap_or(0))
                    }
                    "self/cmdline" => {
                        Self::encode_id(KIND_PROC_CMDLINE, current_pid().map(|p| p as u64).unwrap_or(0))
                    }
                    _ if path.starts_with("self") => 1,
                    _ => {
                        if let Some(slash_idx) = path.find('/') {
                            let pid_str = &path[..slash_idx];
                            let sub = &path[slash_idx + 1..];
                            if let Ok(pid) = pid_str.parse::<u64>() {
                                match sub {
                                    "status" => Self::encode_id(KIND_PROC_STATUS, pid),
                                    "cmdline" => Self::encode_id(KIND_PROC_CMDLINE, pid),
                                    _ => 0xFFFF,
                                }
                            } else {
                                0xFFFF
                            }
                        } else {
                            0xFFFF
                        }
                    }
                };
                (FileFlags::empty(), id)
            }
            ProcEntry::Directory => {
                let id = if path.is_empty() || path == "/" {
                    0
                } else if path == "self" || path == "self/" {
                    1
                } else if let Ok(pid) = path.parse::<u64>() {
                    Self::encode_id(KIND_PROC_DIR, pid)
                } else {
                    2
                };
                (FileFlags::DIRECTORY, id)
            }
        };

        if file_id == 0xFFFF {
            return Err(SyscallError::NotFound);
        }

        Ok(OpenResult {
            file_id,
            size: None,
            flags,
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        let (kind, pid) = Self::decode_id(file_id);
        let content = if file_id == 0 {
            // Root directory listing
            let mut list = String::from("self\ncpuinfo\nmeminfo\nversion\n");
            if let Some(tasks) = get_all_tasks() {
                for task in tasks {
                    let _ = writeln!(list, "{}", task.pid);
                }
            }
            list
        } else if file_id == 1 || kind == KIND_PROC_DIR {
            // Process directory listing (self dir or /proc/<pid>)
            String::from("status\ncmdline\n")
        } else {
            // File content — distinguish by kind (high 32 bits) for process files,
            // or by the literal file_id for well-known fixed files.
            match (kind, file_id) {
                (0, 10) => self.get_cpuinfo(),
                (0, 11) => self.get_meminfo(),
                (0, 12) => self.get_version(),
                (KIND_PROC_STATUS, _) => {
                    let tasks = get_all_tasks().ok_or(SyscallError::NotFound)?;
                    let task = tasks
                        .iter()
                        .find(|t| t.pid as u64 == pid)
                        .ok_or(SyscallError::NotFound)?;
                    self.get_process_status(task)
                }
                (KIND_PROC_CMDLINE, _) => {
                    let tasks = get_all_tasks().ok_or(SyscallError::NotFound)?;
                    let task = tasks
                        .iter()
                        .find(|t| t.pid as u64 == pid)
                        .ok_or(SyscallError::NotFound)?;
                    format!("{}\n", task.name)
                }
                _ => return Err(SyscallError::IoError),
            }
        };

        if offset >= content.len() as u64 {
            return Ok(0);
        }

        let start = offset as usize;
        let end = core::cmp::min(start + buf.len(), content.len());
        let to_copy = end - start;

        buf[..to_copy].copy_from_slice(&content.as_bytes()[start..end]);
        Ok(to_copy)
    }

    fn write(&self, _file_id: u64, _offset: u64, _buf: &[u8]) -> Result<usize, SyscallError> {
        Err(SyscallError::PermissionDenied)
    }

    fn close(&self, _file_id: u64) -> Result<(), SyscallError> {
        Ok(())
    }

    fn stat(&self, file_id: u64) -> Result<FileStat, SyscallError> {
        let (kind, _pid) = Self::decode_id(file_id);
        let is_dir = file_id == 0 || file_id == 1 || kind == KIND_PROC_DIR;
        if is_dir {
            Ok(FileStat {
                st_ino: file_id,
                st_mode: 0o040555,
                st_nlink: 2,
                st_size: 0,
                st_blksize: 512,
                st_blocks: 0,
            })
        } else {
            Ok(FileStat {
                st_ino: file_id,
                st_mode: 0o100444,
                st_nlink: 1,
                st_size: 0,
                st_blksize: 512,
                st_blocks: 0,
            })
        }
    }

    fn readdir(&self, file_id: u64) -> Result<Vec<DirEntry>, SyscallError> {
        let (kind, pid) = Self::decode_id(file_id);
        if file_id == 0 {
            let mut entries = Vec::new();
            entries.push(DirEntry { ino: 1, file_type: DT_DIR, name: String::from("self") });
            entries.push(DirEntry { ino: 10, file_type: DT_REG, name: String::from("cpuinfo") });
            entries.push(DirEntry { ino: 11, file_type: DT_REG, name: String::from("meminfo") });
            entries.push(DirEntry { ino: 12, file_type: DT_REG, name: String::from("version") });
            if let Some(tasks) = get_all_tasks() {
                for task in tasks {
                    entries.push(DirEntry {
                        ino: Self::encode_id(KIND_PROC_DIR, task.pid as u64),
                        file_type: DT_DIR,
                        name: format!("{}", task.pid),
                    });
                }
            }
            Ok(entries)
        } else if file_id == 1 || kind == KIND_PROC_DIR {
            // self dir or /proc/<pid>: list status + cmdline with correct inos
            Ok(alloc::vec![
                DirEntry {
                    ino: Self::encode_id(KIND_PROC_STATUS, pid),
                    file_type: DT_REG,
                    name: String::from("status"),
                },
                DirEntry {
                    ino: Self::encode_id(KIND_PROC_CMDLINE, pid),
                    file_type: DT_REG,
                    name: String::from("cmdline"),
                },
            ])
        } else {
            Err(SyscallError::InvalidArgument)
        }
    }
}
