.PHONY: qemu
DEFAULT_LINUX_VERSION:=linux-4.19.324
CONFIG_FILE := $(wildcard config)

ifeq ($(CONFIG_FILE), config)
    include $(CONFIG_FILE)
else
	LINUX_VERSION:=$(DEFAULT_LINUX_VERSION)
endif

all:config build move qemu
config:
	mkdir -p qemu
	cp ../config/initrd.img ./qemu
	cp ../config/qemu_Makefile ./qemu/Makefile
	$(MAKE) -C qemu uninitrd
	cp ../config/ko_Makefile ./src/Makefile
	echo "LINUX_VERSION=$(DEFAULT_LINUX_VERSION)" > ./config
build:
	$(MAKE) -C src all LINUX_VERSION=$(LINUX_VERSION)
move:
	cp ./src/*.ko ./qemu/initrd/
	cp ./src/exp ./qemu/initrd/
qemu:
	$(MAKE) -C qemu LINUX_VERSION=$(LINUX_VERSION)
gdb:
	gdb -q -x ./gdb.gdb --args ../$(LINUX_VERSION)/vmlinux
clean:
	rm -rf qemu
	rm -rf config
	rm -rf src/Makfile
