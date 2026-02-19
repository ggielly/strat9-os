//! Fork syscall implementation with Copy-on-Write
//!
//! Implements POSIX fork() semantics with COW optimization:
//! - Parent and child share all memory pages marked read-only + COW
//! - First write to a shared page triggers allocation of a private copy
//! - DLL/code pages remain shared (never COW)
//!
//! # Returns
//! - In parent: PID of child process
//! - In child: 0
//!
//! # References
//! - Plan 9 rfork: https://9p.io/magic/man2html/2/fork
//! - POSIX fork: https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html

use crate::process::{Task, TaskId, TaskPriority};
use crate::syscall::error::SyscallError;
use crate::memory::cow;
use crate::memory::paging::PageTableFlags;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

/// Fork result returned to the parent
pub struct ForkResult {
    /// PID of the child process
    pub child_pid: TaskId,
    /// Reference to child task (for scheduler)
    pub child_task: Arc<Task>,
}

/// SYS_FORK: Create a child process with COW memory sharing
///
/// # Implementation
/// 1. Clone parent's address space structure (page tables)
/// 2. Mark all writable user pages as COW (read-only + COW flag)
/// 3. Increment refcount on all shared frames
/// 4. Copy parent's CPU context to child
/// 5. Set return values (0 in child, child_pid in parent)
/// 6. Add child to scheduler
///
/// # Safety
/// - Must be called with interrupts disabled
/// - Scheduler lock must be held
pub fn sys_fork() -> Result<ForkResult, SyscallError> {
    // 1. Get current (parent) task
    let parent_task = crate::process::current_task_clone()
        .ok_or(SyscallError::PermissionDenied)?;
    
    let parent_proc = parent_task.process();
    let parent_as = &parent_proc.address_space;
    
    // 2. Allocate child PID and create process structure
    let child_pid = TaskId::new();
    let child_proc = crate::process::Process::new(child_pid)?;
    
    // 3. Clone address space with COW sharing
    clone_address_space_cow(parent_as, &child_proc.address_space)?;
    
    // 4. Copy process resources (FDs, namespace, etc.)
    copy_process_resources(&parent_proc, &child_proc)?;
    
    // 5. Create child task with copied context
    let parent_ctx = parent_task.context();
    let child_task = Task::new_kernel_task_with_context(
        task_entry_wrapper,
        "forked",
        TaskPriority::Normal,
        parent_ctx.clone(), // Copy CPU registers
    )?;
    
    // Link child task to child process
    child_task.set_process(child_proc.clone());
    
    // 6. Set return values
    // Parent will return child_pid, child will return 0
    // This is handled by modifying the saved RAX in the context
    let child_ctx = child_task.context();
    child_ctx.rax = 0; // Child returns 0
    
    // 7. Add child to scheduler
    crate::process::add_task(child_task.clone());
    
    // 8. Parent returns child PID
    Ok(ForkResult {
        child_pid,
        child_task,
    })
}

/// Clone address space with COW strategy
///
/// This function:
/// 1. Duplicates the page table structure (not the actual data)
/// 2. Marks all writable user pages as COW in both parent and child
/// 3. Increments refcount on all shared frames
fn clone_address_space_cow(
    parent_as: &crate::memory::AddressSpace,
    child_as: &crate::memory::AddressSpace,
) -> Result<(), SyscallError> {
    // Clone the page table structure (frames are shared at this point)
    parent_as.clone_structure_for_fork(child_as)?;
    
    // Walk through all user pages and mark writable ones as COW
    parent_as.for_each_user_page(|virt, entry| {
        let flags = entry.flags();
        
        // Skip if:
        // - Not present (shouldn't happen)
        // - Not writable (already RO)
        // - Kernel page (not user)
        // - DLL page (never COW)
        if !entry.is_present() 
            || !flags.contains(PageTableFlags::WRITABLE)
            || !flags.contains(PageTableFlags::USER)
            || flags.contains(PageTableFlags::NO_EXECUTE) // Heuristic for code pages
        {
            return Ok(());
        }
        
        // Get the physical frame
        if let Some(frame) = entry.frame() {
            // Increment refcount (now shared between parent and child)
            cow::frame_inc_ref(frame);
            
            // Mark as COW in both parent and child
            cow::frame_set_cow(frame);
            
            // Create new PTE with COW flags (remove WRITABLE, add COW)
            let mut cow_flags = flags;
            cow_flags.remove(PageTableFlags::WRITABLE);
            // Note: COW flag is software-defined, we track it in FrameMeta
            
            let mut cow_entry = entry;
            cow_entry.set_flags(cow_flags);
            
            // Update both parent and child page tables
            parent_as.update_entry(virt, cow_entry)?;
            child_as.update_entry(virt, cow_entry)?;
        }
        
        Ok(())
    })?;
    
    Ok(())
}

/// Copy process resources from parent to child
fn copy_process_resources(
    parent: &Process,
    child: &Process,
) -> Result<(), SyscallError> {
    // Copy file descriptor table (duplicate handles)
    *child.fd_table.lock() = parent.fd_table.lock().clone();
    
    // Copy namespace (Plan 9 style - shared namespace for now)
    *child.namespace.lock() = parent.namespace.lock().clone();
    
    // Copy signal mask
    child.signal_mask.store(
        parent.signal_mask.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    
    // Copy current working directory
    *child.cwd.lock() = parent.cwd.lock().clone();
    
    // Copy capabilities (with new ownership)
    // TODO: Implement proper capability inheritance
    
    Ok(())
}

/// Entry point wrapper for forked tasks
///
/// This is a dummy entry point - the actual execution continues
/// from where the parent was when fork() was called, because
/// we copied the entire CPU context including RIP.
extern "C" fn task_entry_wrapper() -> ! {
    // Should never reach here - context switch restores parent's RIP
    loop {
        crate::arch::x86_64::hlt();
    }
}

/// Handle COW page fault
///
/// Called from the page fault handler when a write to a COW page occurs.
///
/// # Arguments
/// * `virt_addr` - Virtual address that caused the fault
/// * `address_space` - Address space of the faulting process
///
/// # Returns
/// - Ok(()) if fault was handled (page copied and remapped)
/// - Err() if fault is fatal (true protection violation)
pub fn handle_cow_fault(
    virt_addr: u64,
    address_space: &crate::memory::AddressSpace,
) -> Result<(), &'static str> {
    // Get the PTE for the faulting address
    let entry = address_space.get_entry(virt_addr)
        .ok_or("Failed to get PTE for COW fault")?;
    
    if !entry.is_present() {
        return Err("COW fault on non-present page");
    }
    
    let flags = entry.flags();
    
    // Check if this is actually a COW page
    // We check the FrameMeta COW flag
    if let Some(frame) = entry.frame() {
        if !cow::frame_is_cow(frame) {
            // Not a COW page - this is a real protection violation
            return Err("Write to non-COW read-only page");
        }
        
        // Check refcount to decide if we need to copy
        let refcount = cow::frame_get_refcount(frame);
        
        if refcount == 1 {
            // Optimization: frame is no longer shared
            // Just mark it as writable (no copy needed)
            let mut new_flags = flags;
            new_flags.insert(PageTableFlags::WRITABLE);
            
            let mut new_entry = entry;
            new_entry.set_flags(new_flags);
            
            cow::frame_clear_cow(frame);
            address_space.update_entry(virt_addr, new_entry)?;
        } else {
            // Frame is truly shared: allocate new frame and copy
            resolve_cow_fault(virt_addr, entry, frame, address_space)?;
        }
    } else {
        return Err("COW page has no valid frame");
    }
    
    Ok(())
}

/// Resolve a COW fault by allocating a new frame and copying content
fn resolve_cow_fault(
    virt_addr: u64,
    old_entry: crate::memory::paging::PageTableEntry,
    old_frame: crate::memory::frame::PhysFrame,
    address_space: &crate::memory::AddressSpace,
) -> Result<(), &'static str> {
    use crate::memory::frame::FrameAllocator;
    
    // 1. Allocate a new physical frame
    let mut allocator = crate::memory::get_allocator().lock();
    let allocator = allocator.as_mut().ok_or("Allocator not available")?;
    let new_frame = allocator.alloc(0).ok_or("Failed to allocate frame for COW")?;
    drop(allocator);
    
    // 2. Map both frames into kernel space for copying
    let old_virt = crate::memory::phys_to_virt(old_frame.start_address().as_u64());
    let new_virt = crate::memory::phys_to_virt(new_frame.start_address().as_u64());
    
    // 3. Copy the page content (4096 bytes)
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_virt as *const u8,
            new_virt as *mut u8,
            4096,
        );
    }
    
    // 4. Decrement refcount on old frame
    cow::frame_dec_ref(old_frame);
    
    // 5. Create new PTE pointing to the new frame (writable, not COW)
    let mut new_entry = old_entry;
    new_entry.set_frame(new_frame, PageTableFlags::USER | PageTableFlags::WRITABLE | PageTableFlags::PRESENT);
    
    // 6. Update page table
    address_space.update_entry(virt_addr, new_entry)?;
    
    // 7. Invalidate TLB for this page
    // (update_entry should already do this via invlpg)
    
    log::trace!("COW fault resolved at {:#x}: copied frame {:#x} -> {:#x}",
                virt_addr, old_frame.start_address().as_u64(), new_frame.start_address().as_u64());
    
    Ok(())
}
