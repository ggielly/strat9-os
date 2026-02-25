//! `execve()` syscall implementation.
//! Replaces the current process image with a new one.

use crate::{
    memory::{AddressSpace, UserSliceRead, VmaFlags, VmaPageSize, VmaType},
    process::{
        current_task_clone,
        elf::{load_elf_image, LoadedElfInfo, USER_STACK_BASE, USER_STACK_PAGES, USER_STACK_TOP},
    },
    syscall::{error::SyscallError, SyscallFrame},
    vfs,
};
use alloc::vec::Vec;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

/// SYS_PROC_EXECVE (301): Replace current process image.
pub fn sys_execve(
    frame: &mut SyscallFrame,
    path_ptr: u64,
    argv_ptr: u64,
    envp_ptr: u64,
) -> Result<u64, SyscallError> {
    let current = current_task_clone().ok_or(SyscallError::PermissionDenied)?;

    let mut path_buf = [0u8; 4096];
    let path_slice = UserSliceRead::new(path_ptr, 4096).map_err(|_| SyscallError::Fault)?;

    let mut len = 0;

    loop {
        if len >= 4096 {
            return Err(SyscallError::ArgumentListTooLong);
        } // Reused error code
        let b = path_slice.read_u8(len).map_err(|_| SyscallError::Fault)?;
        if b == 0 {
            break;
        }
        path_buf[len] = b;
        len += 1;
    }
    let path_str =
        core::str::from_utf8(&path_buf[..len]).map_err(|_| SyscallError::InvalidArgument)?;

    let fd = vfs::open(path_str, vfs::OpenFlags::READ)?;

    // Read into memory
    const MAX_EXEC_SIZE: usize = 64 * 1024 * 1024;
    let mut elf_data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match vfs::read(fd, &mut buf) {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                if elf_data.len() + n > MAX_EXEC_SIZE {
                    let _ = vfs::close(fd);
                    return Err(SyscallError::OutOfMemory);
                }
                elf_data.extend_from_slice(&buf[..n]);
            }
            Err(e) => {
                let _ = vfs::close(fd);
                return Err(e);
            }
        }
    }
    let _ = vfs::close(fd);

    if elf_data.len() < 4 {
        return Err(SyscallError::ExecFormatError);
    }

    let new_as = AddressSpace::new_user().map_err(|_| SyscallError::OutOfMemory)?;
    let new_as_arc = alloc::sync::Arc::new(new_as);

    let load_info =
        load_elf_image(&elf_data, &new_as_arc).map_err(|_| SyscallError::ExecFormatError)?;

    let stack_flags = VmaFlags {
        readable: true,
        writable: true,
        executable: false,
        user_accessible: true,
    };
    new_as_arc
        .map_region(
            USER_STACK_BASE,
            USER_STACK_PAGES,
            stack_flags,
            VmaType::Stack,
            VmaPageSize::Small,
        )
        .map_err(|_| SyscallError::OutOfMemory)?;

    let sp = setup_user_stack(
        &new_as_arc,
        argv_ptr,
        envp_ptr,
        &load_info,
        path_str.as_bytes(),
    )?;

    // === EXECVE CLEANUP (POSIX semantics) ===
    // Now that ELF is valid and loaded, perform cleanup before switching address space.

    // 1. Close all file descriptors with CLOEXEC flag
    unsafe {
        let fd_table = &mut *current.process.fd_table.get();
        fd_table.close_cloexec();
    }

    // 2. Reset all signal handlers to SIG_DFL
    current.reset_signals();

    // 3. Clear thread-local storage address and TID pointer — POSIX exec semantics.
    current
        .clear_child_tid
        .store(0, core::sync::atomic::Ordering::Relaxed);
    current
        .user_fs_base
        .store(0, core::sync::atomic::Ordering::Relaxed);
    // Reset FS.base MSR to 0 so the new image starts with a clean TLS pointer.
    unsafe {
        core::arch::asm!(
            "xor eax, eax",
            "xor edx, edx",
            "mov ecx, 0xC0000100", // MSR_FS_BASE
            "wrmsr",
            options(nostack, preserves_flags),
        );
    }

    let old_as =
        unsafe { core::mem::replace(&mut *current.process.address_space.get(), new_as_arc.clone()) };

    unsafe {
        (&*current.process.address_space.get()).switch_to();
    }

    frame.iret_rip = load_info.runtime_entry;
    frame.iret_rsp = sp;

    frame.rdi = 0;
    frame.rsi = 0;
    frame.rdx = 0;
    frame.rcx = 0;
    frame.r8 = 0;
    frame.r9 = 0;
    frame.r10 = 0;
    frame.r11 = 0;
    frame.rbx = 0;
    frame.rbp = 0;
    frame.r12 = 0;
    frame.r13 = 0;
    frame.r14 = 0;
    frame.r15 = 0;
    frame.rax = 0;

    // Safely drop the old address space now that the new CR3 is loaded
    drop(old_as);

    Ok(0)
}

fn setup_user_stack(
    new_as: &AddressSpace,
    argv_ptr: u64,
    envp_ptr: u64,
    elf_info: &LoadedElfInfo,
    exec_path: &[u8],
) -> Result<u64, SyscallError> {
    let args = read_string_array(argv_ptr)?;
    let envs = read_string_array(envp_ptr)?;

    let mut sp = USER_STACK_TOP;
    let mut str_ptrs: Vec<u64> = Vec::with_capacity(args.len()); // stores pointers to arguments
    let mut env_ptrs: Vec<u64> = Vec::with_capacity(envs.len()); // stores pointers to env vars

    // Push strings to stack (highest addresses)
    // We push them in reverse order so they appear in memory roughly sequentially for cache locality?
    // Actually standard is to put them at very top. Order doesn't strictly matter as long as pointers are correct.
    // We'll push ENV strings first (highest), then ARG strings.

    // Push ENV strings
    for env in envs.iter().rev() {
        let len = (env.len() + 1) as u64;
        sp -= len;
        write_bytes_to_as(new_as, sp, env)?;
        write_bytes_to_as(new_as, sp + env.len() as u64, &[0])?;
        env_ptrs.push(sp);
    }
    // env_ptrs: [ptr_to_highest_env, ptr_to_second_highest...] which corresponds to [env[last], env[last-1]...]
    // Userspace expects envp[0] to point to first env string.
    // So we need to reverse env_ptrs to match original order.
    env_ptrs.reverse();

    // Push ARG strings
    for arg in args.iter().rev() {
        let len = (arg.len() + 1) as u64;
        sp -= len;
        write_bytes_to_as(new_as, sp, arg)?;
        write_bytes_to_as(new_as, sp + arg.len() as u64, &[0])?;
        str_ptrs.push(sp);
    }
    str_ptrs.reverse();

    // Push exec path (for AT_EXECFN).
    let mut execfn_ptr = 0u64;
    if !exec_path.is_empty() {
        let len = (exec_path.len() + 1) as u64;
        sp -= len;
        write_bytes_to_as(new_as, sp, exec_path)?;
        write_bytes_to_as(new_as, sp + exec_path.len() as u64, &[0])?;
        execfn_ptr = sp;
    }

    // Push 16 bytes of random seed for AT_RANDOM (deterministic fallback source).
    sp -= 16;
    let rand_ptr = sp;
    let seed = generate_aux_random_seed();
    write_bytes_to_as(new_as, rand_ptr, &seed)?;

    // Align SP to 16 bytes for System V ABI
    sp &= !0xF;

    // Phase 2: Push auxv, pointer arrays, then argc.
    let size_ptr = 8u64;

    // auxv entries end with AT_NULL.
    let mut auxv: Vec<(u64, u64)> = Vec::with_capacity(10);
    auxv.push((AT_PHDR, elf_info.phdr_vaddr));
    auxv.push((AT_PHENT, elf_info.phent as u64));
    auxv.push((AT_PHNUM, elf_info.phnum as u64));
    auxv.push((AT_PAGESZ, 4096));
    if let Some(base) = elf_info.interp_base {
        auxv.push((AT_BASE, base));
    }
    auxv.push((AT_ENTRY, elf_info.program_entry));
    auxv.push((AT_RANDOM, rand_ptr));
    if execfn_ptr != 0 {
        auxv.push((AT_EXECFN, execfn_ptr));
    }

    // AT_NULL terminator.
    sp -= size_ptr;
    write_u64_to_as(new_as, sp, 0)?;
    sp -= size_ptr;
    write_u64_to_as(new_as, sp, AT_NULL)?;
    for &(key, val) in auxv.iter().rev() {
        sp -= size_ptr;
        write_u64_to_as(new_as, sp, val)?;
        sp -= size_ptr;
        write_u64_to_as(new_as, sp, key)?;
    }

    // Push ENVP array
    // [NULL]
    // [envp[n]]
    // ...
    // [envp[0]]
    sp -= size_ptr;
    write_u64_to_as(new_as, sp, 0)?; // NULL terminator

    for &ptr in env_ptrs.iter().rev() {
        sp -= size_ptr;
        write_u64_to_as(new_as, sp, ptr)?;
    }
    // Note: sp now points to envp[0]

    // Push ARGV array
    // [NULL]
    // [argv[n]]
    // ...
    // [argv[0]]
    sp -= size_ptr;
    write_u64_to_as(new_as, sp, 0)?; // NULL terminator

    for &ptr in str_ptrs.iter().rev() {
        sp -= size_ptr;
        write_u64_to_as(new_as, sp, ptr)?;
    }
    // Note: sp now points to argv[0]

    // Push ARGC
    sp -= size_ptr;
    write_u64_to_as(new_as, sp, args.len() as u64)?;

    Ok(sp)
}

fn read_string_array(ptr: u64) -> Result<Vec<Vec<u8>>, SyscallError> {
    let mut res = Vec::new();
    if ptr == 0 {
        return Ok(res);
    }

    let mut arr_off = 0;
    loop {
        // Read string pointer from user memory (current AS)
        let str_ptr = match UserSliceRead::new(ptr + arr_off, 8) {
            Ok(slice) => match slice.read_u64(0) {
                Ok(p) => p,
                Err(_) => return Err(SyscallError::Fault),
            },
            Err(_) => return Err(SyscallError::Fault),
        };

        if str_ptr == 0 {
            break;
        }
        if res.len() > 1024 {
            return Err(SyscallError::ArgumentListTooLong);
        }

        let mut s = Vec::new();
        let mut i = 0;
        loop {
            if i > 4096 {
                return Err(SyscallError::ArgumentListTooLong);
            }
            let b = match UserSliceRead::new(str_ptr + i, 1) {
                Ok(slice) => match slice.read_u8(0) {
                    Ok(byte) => byte,
                    Err(_) => return Err(SyscallError::Fault),
                },
                Err(_) => return Err(SyscallError::Fault),
            };
            if b == 0 {
                break;
            }
            s.push(b);
            i += 1;
        }
        res.push(s);
        arr_off += 8;
    }
    Ok(res)
}

fn write_bytes_to_as(as_ref: &AddressSpace, vaddr: u64, data: &[u8]) -> Result<(), SyscallError> {
    use x86_64::VirtAddr;
    let mut written = 0;
    // We assume data is small enough or we loop? Using unsafe pointer arithmetic.
    // The `AddressSpace` methods like `translate` are needed.

    // Since `load_elf_image` in `elf.rs` used `translate`, we should verify visibility.
    // `AddressSpace` is usually public. `translate` is on `Mapper` trait?
    // `AddressSpace` in `strat9` likely implements `Mapper` or has it.
    // `elf.rs` used `user_as.translate(...)`.
    // I need to import Translate? `AddressSpace` usually has `translate`.

    while written < data.len() {
        let curr_vaddr = vaddr + written as u64;
        let page_offset = (curr_vaddr & 0xFFF) as usize;
        let chunk_size = core::cmp::min(data.len() - written, 4096 - page_offset);

        // translate might fail if page not mapped.
        // `USER_STACK_BASE`..`USER_STACK_TOP` is mapped.
        let phys = as_ref
            .translate(VirtAddr::new(curr_vaddr))
            .ok_or(SyscallError::Fault)?;
        let virt = crate::memory::phys_to_virt(phys.as_u64()) as *mut u8;

        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr().add(written), virt, chunk_size);
        }
        written += chunk_size;
    }
    Ok(())
}

fn write_u64_to_as(as_ref: &AddressSpace, vaddr: u64, val: u64) -> Result<(), SyscallError> {
    let bytes = val.to_ne_bytes();
    write_bytes_to_as(as_ref, vaddr, &bytes)
}

fn generate_aux_random_seed() -> [u8; 16] {
    use x86_64::registers::control::Cr3;
    let mut s = [0u8; 16];
    let t = crate::process::scheduler::ticks();
    let (cr3, _) = Cr3::read();
    let x = t
        ^ (cr3
            .start_address()
            .as_u64()
            .wrapping_mul(0x9e37_79b9_7f4a_7c15));
    s[..8].copy_from_slice(&x.to_le_bytes());
    s[8..].copy_from_slice(&(x.rotate_left(17) ^ 0xa076_1d64_78bd_642f).to_le_bytes());
    s
}
