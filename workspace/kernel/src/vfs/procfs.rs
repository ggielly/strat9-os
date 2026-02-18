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
    process::{current_task_id, get_all_tasks},
    syscall::error::SyscallError,
    vfs::scheme::{DynScheme, FileFlags, OpenFlags, OpenResult, Scheme},
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
            if let Some(task_id) = current_task_id() {
                return Ok(ProcEntry::File(format!("{}\n", task_id.as_u64())));
            }
            return Err(SyscallError::NotFound);
        }

        // Handle /proc/self/status
        if path.starts_with("self/") {
            let subpath = &path[5..];
            if let Some(task_id) = current_task_id() {
                return self.get_process_entry(task_id.as_u64(), subpath);
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
            .find(|t| t.id.as_u64() == pid)
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
        let _ = writeln!(output, "Tgid:\t{}", task.id.as_u64());
        let _ = writeln!(output, "Pid:\t{}", task.id.as_u64());
        let _ = writeln!(output, "PPid:\t1");
        let _ = writeln!(output, "Uid:\t0\t0\t0\t0");
        let _ = writeln!(output, "Gid:\t0\t0\t0\t0");
        let _ = writeln!(output, "Threads:\t1");

        output
    }
}

/// Procfs entry type
enum ProcEntry {
    File(String),
    Directory,
}

impl Scheme for ProcScheme {
    fn open(&self, path: &str, _flags: OpenFlags) -> Result<OpenResult, SyscallError> {
        let entry = self.get_entry(path)?;

        let flags = match entry {
            ProcEntry::File(_) => FileFlags::empty(),
            ProcEntry::Directory => FileFlags::DIRECTORY,
        };

        // Use path hash as file ID (simple but works for procfs)
        let file_id = path.len() as u64 ^ (path.as_ptr() as u64);

        Ok(OpenResult {
            file_id,
            size: None, // Dynamic size
            flags,
        })
    }

    fn read(&self, file_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize, SyscallError> {
        // For simplicity, we regenerate content on each read
        // A real implementation would cache the content
        let content = match file_id {
            // These would be properly tracked in a real implementation
            _ => self.get_cpuinfo(), // Fallback
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
}
