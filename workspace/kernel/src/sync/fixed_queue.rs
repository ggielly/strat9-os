use core::mem::MaybeUninit;

/// Fixed-capacity FIFO queue with no heap allocation.
pub struct FixedQueue<T, const N: usize> {
    entries: [MaybeUninit<T>; N],
    head: usize,
    len: usize,
}

impl<T, const N: usize> FixedQueue<T, N> {
    /// Creates a new empty queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { MaybeUninit::uninit() }; N],
            head: 0,
            len: 0,
        }
    }

    /// Returns the number of elements currently stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether the queue is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Appends an element to the tail of the queue.
    pub fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }

        let tail = (self.head + self.len) % N;
        self.entries[tail].write(value);
        self.len += 1;
        Ok(())
    }

    /// Removes and returns the element at the head of the queue.
    pub fn pop_front(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        let head = self.head;
        self.head = (self.head + 1) % N;
        self.len -= 1;

        // SAFETY: `head` points to an initialized element while `len > 0`.
        Some(unsafe { self.entries[head].assume_init_read() })
    }

    /// Removes the first element matching `predicate`.
    pub fn remove_first_where<F>(&mut self, mut predicate: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        for offset in 0..self.len {
            let idx = (self.head + offset) % N;
            // SAFETY: `idx` is within the initialized window `[head, head+len)`.
            let entry = unsafe { self.entries[idx].assume_init_ref() };
            if predicate(entry) {
                return Some(self.remove_at(offset));
            }
        }
        None
    }

    fn remove_at(&mut self, offset: usize) -> T {
        debug_assert!(offset < self.len);

        let idx = (self.head + offset) % N;
        // SAFETY: `idx` points to an initialized element by construction.
        let removed = unsafe { self.entries[idx].assume_init_read() };

        for shift in offset..(self.len - 1) {
            let src = (self.head + shift + 1) % N;
            let dst = (self.head + shift) % N;
            // SAFETY: `src` points to an initialized element and `dst` stays
            // within the queue storage.
            let moved = unsafe { self.entries[src].assume_init_read() };
            self.entries[dst].write(moved);
        }

        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }

        removed
    }
}

impl<T, const N: usize> Drop for FixedQueue<T, N> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}