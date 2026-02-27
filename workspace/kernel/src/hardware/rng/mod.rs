// Hardware RNG driver wrapper

pub mod virtio_rng {
    pub use virtio_rng::{init, read_entropy, is_available};
}

// VirtIO Console driver wrapper

pub mod virtio_console {
    pub use virtio_console::{init, write, read, is_available};
}
