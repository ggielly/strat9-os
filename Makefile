.PHONY: all clean kernel bootloader run

# Build configuration
CARGO := cargo
QEMU := qemu-system-x86_64
TARGET := x86_64-unknown-none

# Paths
KERNEL_DIR := kernel
KERNEL_ELF := $(KERNEL_DIR)/target/$(TARGET)/release/libstrat9_kernel.a
BUILD_DIR := build

all: kernel

# Build kernel
kernel:
	@echo "Building Bedrock kernel..."
	cd $(KERNEL_DIR) && $(CARGO) build --release \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(TARGET)
	@echo "Kernel built successfully"

# Build bootloader (TODO: implement)
bootloader:
	@echo "Building bootloader..."
	@echo "TODO: Implement bootloader build"

# Clean build artifacts
clean:
	$(CARGO) clean
	rm -rf $(BUILD_DIR)

# Run in QEMU (requires bootloader to be implemented)
run: kernel
	@echo "Launching QEMU..."
	$(QEMU) \
		-machine q35 \
		-cpu qemu64 \
		-m 256M \
		-serial stdio \
		-display none \
		-no-reboot \
		-no-shutdown \
		-d int,cpu_reset \
		-D qemu.log \
		-drive file=qemu-stuff/disk.img,if=none,id=drv0,format=raw \
		-device virtio-blk-pci,drive=drv0

# Development helpers
check:
	cd $(KERNEL_DIR) && $(CARGO) check \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(TARGET)

clippy:
	cd $(KERNEL_DIR) && $(CARGO) clippy \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(TARGET)

fmt:
	$(CARGO) fmt --all

# Documentation
doc:
	cd $(KERNEL_DIR) && $(CARGO) doc --target $(TARGET) --no-deps --open
