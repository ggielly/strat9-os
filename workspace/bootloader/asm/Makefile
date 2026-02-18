# Makefile for CascadeOS Bootloader Assembly
# Assembles Stage 1 and Stage 2 bootloader

# Tools
NASM = nasm
NASMFLAGS = -f bin

# Directories
ASM_DIR = x86_64
BUILD_DIR = build

# Targets
STAGE1 = $(BUILD_DIR)/stage1.bin
STAGE2 = $(BUILD_DIR)/stage2.bin
BOOTLOADER = $(BUILD_DIR)/bootloader.bin

# Sources
STAGE1_SRC = $(ASM_DIR)/stage1.asm
STAGE2_SRC = $(ASM_DIR)/stage2.asm

.PHONY: all clean

all: $(BUILD_DIR) $(BOOTLOADER)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Assemble Stage 1 (MBR)
$(STAGE1): $(STAGE1_SRC)
	@echo "Assembling Stage 1..."
	$(NASM) $(NASMFLAGS) -o $@ $<
	@echo "Stage 1 size: $$(stat -c%s $@) bytes (must be exactly 512)"
	@if [ $$(stat -c%s $@) -ne 512 ]; then \
		echo "ERROR: Stage 1 must be exactly 512 bytes!"; \
		exit 1; \
	fi

# Assemble Stage 2
$(STAGE2): $(STAGE2_SRC) $(ASM_DIR)/*.asm
	@echo "Assembling Stage 2..."
	$(NASM) $(NASMFLAGS) -I$(ASM_DIR)/ -o $@ $<
	@echo "Stage 2 size: $$(stat -c%s $@) bytes (max 4096)"
	@if [ $$(stat -c%s $@) -gt 4096 ]; then \
		echo "ERROR: Stage 2 exceeds 4KB limit!"; \
		exit 1; \
	fi

# Combine Stage 1 and Stage 2 into bootloader binary
$(BOOTLOADER): $(STAGE1) $(STAGE2)
	@echo "Creating bootloader image..."
	cat $(STAGE1) $(STAGE2) > $@
	@echo "Bootloader created: $@"
	@echo "Total size: $$(stat -c%s $@) bytes"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

test: $(BOOTLOADER)
	@echo "Testing bootloader in QEMU..."
	qemu-system-x86_64 -drive format=raw,file=$(BOOTLOADER) -serial stdio

.PRECIOUS: $(STAGE1) $(STAGE2)
