// NVMe queue management
// Reference: NVM Express Base Specification 2.0, Section 6

use super::command::{Command, CompletionEntry};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicU16, Ordering};

const fn calculate_doorbell_offset(
    queue_id: u16,
    multiplier: usize,
    dstrd: usize,
) -> usize {
    0x1000 + ((((queue_id as usize) * 2) + multiplier) * (4 << dstrd))
}

pub struct Completion;
pub struct Submission;

pub trait QueueType {
    type EntryType;
    const DOORBELL_OFFSET: usize;
}

impl QueueType for Completion {
    type EntryType = CompletionEntry;
    const DOORBELL_OFFSET: usize = 1;
}

impl QueueType for Submission {
    type EntryType = Command;
    const DOORBELL_OFFSET: usize = 0;
}

#[repr(transparent)]
struct DoorbellRegister {
    value: u32,
}

impl DoorbellRegister {
    fn read(&self) -> u32 {
        unsafe { core::ptr::read_volatile(&self.value) }
    }

    fn write(&self, val: u32) {
        unsafe { core::ptr::write_volatile(&mut self.value, val) }
    }
}

unsafe impl Send for DoorbellRegister {}
unsafe impl Sync for DoorbellRegister {}

pub struct Queue<T: QueueType> {
    doorbell: *const DoorbellRegister,
    index: usize,
    entries: *mut UnsafeCell<T::EntryType>,
    size: usize,
    phase: bool,
    phys_addr: u64,
}

unsafe impl<T: QueueType> Send for Queue<T> {}
unsafe impl<T: QueueType> Sync for Queue<T> {}

impl<T: QueueType> Queue<T> {
    pub fn new(registers_base: usize, size: usize, queue_id: u16, dstrd: usize) -> Self {
        let doorbell_offset = calculate_doorbell_offset(queue_id, T::DOORBELL_OFFSET, dstrd);
        let doorbell = unsafe {
            &*((registers_base + doorbell_offset) as *const DoorbellRegister)
        };

        let frame = crate::memory::allocate_dma_frame()
            .expect("NVMe: failed to allocate queue frame");

        let phys_addr = frame.start_address();
        let virt_addr = crate::memory::phys_to_virt(phys_addr);

        unsafe {
            core::ptr::write_bytes(
                virt_addr as *mut u8,
                0,
                size * core::mem::size_of::<T::EntryType>(),
            );
        }

        Self {
            doorbell,
            entries: virt_addr as *mut UnsafeCell<T::EntryType>,
            size,
            index: 0,
            phase: true,
            phys_addr,
        }
    }

    pub fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn get_entry(&self, idx: usize) -> &mut T::EntryType {
        unsafe { &mut (*self.entries.add(idx)).get() }
    }
}

impl Queue<Completion> {
    pub fn poll_completion(&mut self) -> Option<CompletionEntry> {
        let entry = self.get_entry(self.index);
        let status = unsafe { core::ptr::read_volatile(&entry.status) };

        if ((status & 0x1) != 0) == self.phase {
            let completion = unsafe { core::ptr::read(entry as *const CompletionEntry) };

            let status_type = (completion.status >> 9) & 0x7;
            let status_code = (completion.status >> 1) & 0xFF;

            if status_type != 0 || status_code != 0 {
                log::error!(
                    "NVMe: completion error type={} code={:#x}",
                    status_type,
                    status_code
                );
                return None;
            }

            self.index = (self.index + 1) % self.size;
            if self.index == 0 {
                self.phase = !self.phase;
            }

            self.doorbell.write(self.index as u32);
            Some(completion)
        } else {
            None
        }
    }
}

impl Queue<Submission> {
    pub fn submit_command(&mut self, command: Command, idx: usize) {
        let entry = self.get_entry(idx);
        unsafe {
            core::ptr::write(entry as *mut Command, command);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        let next_index = (idx + 1) % self.size;
        self.doorbell.write(next_index as u32);
    }
}

static NEXT_QUEUE_ID: AtomicU16 = AtomicU16::new(0);

pub struct QueuePair {
    id: u16,
    size: usize,
    command_id: u16,
    submission: Queue<Submission>,
    completion: Queue<Completion>,
}

impl QueuePair {
    pub fn new(registers_base: usize, size: usize, dstrd: usize) -> Self {
        let id = NEXT_QUEUE_ID.fetch_add(1, Ordering::SeqCst);

        Self {
            id,
            size,
            command_id: 0,
            submission: Queue::new(registers_base, size, id, dstrd),
            completion: Queue::new(registers_base, size, id, dstrd),
        }
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn submission_phys(&self) -> u64 {
        self.submission.phys_addr()
    }

    pub fn completion_phys(&self) -> u64 {
        self.completion.phys_addr()
    }

    pub fn submit_command(&mut self, command: Command) -> Option<CompletionEntry> {
        let slot = self.command_id as usize % self.size;

        let mut cmd = command;
        unsafe {
            let cmd_ptr = cmd.as_mut_ptr();
            core::ptr::write(cmd_ptr.add(1) as *mut u16, self.command_id);
        }
        self.command_id = self.command_id.wrapping_add(1);

        self.submission.submit_command(cmd, slot);

        loop {
            if let Some(completion) = self.completion.poll_completion() {
                return Some(completion);
            }
            core::hint::spin_loop();
        }
    }
}
