#![no_std]

pub trait RxDescriptor: Copy {
    fn set_buffer_addr(&mut self, phys: u64);
    fn is_done(&self) -> bool;
    fn packet_length(&self) -> u16;
    fn clear_status(&mut self);
}

pub trait TxDescriptor: Copy {
    fn set_buffer(&mut self, phys: u64, len: u16);
    fn set_eop_ifcs_rs(&mut self);
    fn is_done(&self) -> bool;
    fn clear(&mut self);
}

pub struct RxRing<D: RxDescriptor> {
    descs: *mut D,
    count: usize,
    tail: usize,
}

unsafe impl<D: RxDescriptor> Send for RxRing<D> {}

impl<D: RxDescriptor> RxRing<D> {
    /// # Safety
    /// `descs` must point to `count` valid, zero-initialised descriptors.
    pub unsafe fn new(descs: *mut D, count: usize) -> Self {
        Self {
            descs,
            count,
            tail: count - 1,
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn tail(&self) -> usize {
        self.tail
    }

    pub fn desc_mut(&mut self, idx: usize) -> &mut D {
        unsafe { &mut *self.descs.add(idx % self.count) }
    }

    /// Check the next descriptor; returns `(index, packet_length)` if ready.
    pub fn poll(&self) -> Option<(usize, u16)> {
        let next = (self.tail + 1) % self.count;
        let desc = unsafe { &*self.descs.add(next) };
        if desc.is_done() {
            Some((next, desc.packet_length()))
        } else {
            None
        }
    }

    /// Advance tail after consuming a packet. Returns new tail.
    pub fn advance(&mut self) -> usize {
        self.tail = (self.tail + 1) % self.count;
        self.tail
    }

    /// Set up one RX descriptor with a pre-allocated buffer.
    pub fn setup_desc(&mut self, idx: usize, buf_phys: u64) {
        let d = self.desc_mut(idx);
        d.clear_status();
        d.set_buffer_addr(buf_phys);
    }
}

pub struct TxRing<D: TxDescriptor> {
    descs: *mut D,
    count: usize,
    tail: usize,
}

unsafe impl<D: TxDescriptor> Send for TxRing<D> {}

impl<D: TxDescriptor> TxRing<D> {
    pub unsafe fn new(descs: *mut D, count: usize) -> Self {
        Self {
            descs,
            count,
            tail: 0,
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn tail(&self) -> usize {
        self.tail
    }

    pub fn desc(&self, idx: usize) -> &D {
        unsafe { &*self.descs.add(idx % self.count) }
    }

    pub fn desc_mut(&mut self, idx: usize) -> &mut D {
        unsafe { &mut *self.descs.add(idx % self.count) }
    }

    /// Prepare and submit a packet at the current tail slot.
    /// Returns the descriptor index used.
    pub fn submit(&mut self, phys: u64, len: u16) -> usize {
        let idx = self.tail;
        let d = self.desc_mut(idx);
        d.clear();
        d.set_buffer(phys, len);
        d.set_eop_ifcs_rs();
        self.tail = (idx + 1) % self.count;
        idx
    }

    pub fn is_done(&self, idx: usize) -> bool {
        self.desc(idx).is_done()
    }
}
