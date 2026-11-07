KSRC := $(CURDIR)/linux
KOUT := $(CURDIR)/build
KDIR := $(KOUT)
SCRIPTS := $(KSRC)/scripts

MODULES := $(notdir $(patsubst %/Makefile,%,$(wildcard drivers/*/Makefile)))

.PHONY: all kernel modules clean run $(MODULES)

all: kernel modules

config:
	$(MAKE) -C $(KSRC) O=$(KOUT) defconfig

	$(SCRIPTS)/config --file $(KOUT)/.config --enable DEBUG_INFO
	$(SCRIPTS)/config --file $(KOUT)/.config --enable DEBUG_INFO_DWARF5
	$(SCRIPTS)/config --file $(KOUT)/.config --enable GDB_SCRIPTS
	$(SCRIPTS)/config --file $(KOUT)/.config --enable KASAN
	$(SCRIPTS)/config --file $(KOUT)/.config --enable KASAN_INLINE
	$(SCRIPTS)/config --file $(KOUT)/.config --enable KFENCE
	$(SCRIPTS)/config --file $(KOUT)/.config --enable UBSAN
	$(SCRIPTS)/config --file $(KOUT)/.config --enable PROVE_LOCKING
	$(SCRIPTS)/config --file $(KOUT)/.config --enable DEBUG_MUTEXES

	$(MAKE) -C $(KSRC) O=$(KOUT) olddefconfig
# Build the kernel into the 'build/' directory
kernel:
	$(MAKE) -C $(KSRC) O=$(KOUT) -j$$(nproc) bzImage modules

# Build your custom modules against the 'build/' output
modules: $(MODULES)

$(MODULES):
	$(MAKE) -C $(KDIR) M=$(CURDIR)/drivers/$@ modules

# Boot the VM
# 1. The base builder (used by both specific runs)
define build-initramfs
	@echo "--- Building minimal initramfs ---"
	@rm -rf /tmp/irfs
	@mkdir -p /tmp/irfs/bin /tmp/irfs/dev /tmp/irfs/proc /tmp/irfs/sys /tmp/irfs/mnt
	@cp /usr/bin/busybox /tmp/irfs/bin/busybox
	@cd /tmp/irfs/bin && for cmd in sh mount insmod rmmod lsmod dmesg cat ls mkdir sleep echo poweroff setsid cttyhack; do ln -sf busybox $$cmd; done
	@printf '#!/bin/sh\n' > /tmp/irfs/init
	@printf 'mount -t proc none /proc\n' >> /tmp/irfs/init
	@printf 'mount -t sysfs none /sys\n' >> /tmp/irfs/init
	@printf 'mount -t devtmpfs none /dev\n' >> /tmp/irfs/init
	@printf 'mount -t 9p -o trans=virtio,version=9p2000.L drivers /mnt\n' >> /tmp/irfs/init
	@printf 'echo "----------------------------------------"\n' >> /tmp/irfs/init
	@printf 'echo " Mounted! Try: insmod /mnt/$(1)/$(1).ko"\n' >> /tmp/irfs/init
	@printf 'echo "----------------------------------------"\n' >> /tmp/irfs/init
	$(if $(1),@printf 'insmod /mnt/$(1)/$(1).ko\n' >> /tmp/irfs/init)
	@printf 'exec setsid cttyhack /bin/sh\n' >> /tmp/irfs/init
	@chmod +x /tmp/irfs/init
	@cd /tmp/irfs && find . | cpio -o -H newc 2>/dev/null | gzip > /tmp/initramfs.gz
endef

# 2. The generic interactive shell (no auto-load)
run: modules
	$(call build-initramfs,)
	@echo "--- Booting QEMU (Interactive) ---"
	qemu-system-x86_64 -kernel build/arch/x86/boot/bzImage -initrd /tmp/initramfs.gz \
		-append "console=ttyS0 oops=panic panic=0 nowatchdog" \
		-virtfs local,path=$(CURDIR)/drivers,security_model=none,mount_tag=drivers \
		-nographic -no-reboot -enable-kvm -cpu host -m 4G -smp 4 -serial mon:stdio

# 3. The dynamic target (e.g., make run-oops)
run-%: modules
	$(call build-initramfs,$*)
	@echo "--- Booting QEMU (Auto-loading $*) ---"
	qemu-system-x86_64 -kernel build/arch/x86/boot/bzImage -initrd /tmp/initramfs.gz \
		-append "console=ttyS0 oops=panic panic=0 nowatchdog" \
		-virtfs local,path=$(CURDIR)/drivers,security_model=none,mount_tag=drivers \
		-nographic -no-reboot -enable-kvm -cpu host -m 4G -smp 4 -serial mon:stdio

clean:
	@for m in $(MODULES); do \
		$(MAKE) -C $(KDIR) M=$(CURDIR)/drivers/$$m clean; \
	done
