.PHONY : qemu initrd clean
qemu:initrd
	qemu-system-x86_64 \
		-m 128M \
		-smp cores=2,threads=1 \
		-kernel ../../$(LINUX_VERSION)/arch/x86/boot/bzImage \
		-initrd initrd.img \
		-append "root=/dev/ram rw console=ttyS0 init=/init nosmep nokaslr nosmap nopti" \
		-enable-kvm \
		-cpu kvm64 \
		-monitor /dev/null \
		-nographic \
		-s

initrd:
	cd initrd && find . | cpio -o --format=newc > ../initrd.img
uninitrd:clean
	mkdir -p initrd 
	cd initrd && cpio -idmv < ../initrd.img 
	cd initrd && mkdir -p  proc sys dev etc/init.d
clean:
	rm -rf initrd 

