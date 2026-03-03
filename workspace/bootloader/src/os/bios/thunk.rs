use core::ptr;

use super::THUNK_STACK_ADDR;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ThunkData {
    pub es: u16,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
}

impl ThunkData {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            es: 0,
            edi: 0,
            esi: 0,
            ebp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
        }
    }

    /// Performs the save operation.
    pub unsafe fn save(&self) {
        unsafe {
            ptr::write((THUNK_STACK_ADDR - 64) as *mut ThunkData, *self);
        }
    }

    /// Performs the load operation.
    pub unsafe fn load(&mut self) {
        unsafe {
            *self = ptr::read((THUNK_STACK_ADDR - 64) as *const ThunkData);
        }
    }

    /// Performs the with operation.
    pub unsafe fn with(&mut self, f: extern "C" fn()) {
        unsafe {
            self.save();
            f();
            self.load();
        }
    }
}
