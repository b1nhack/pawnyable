all: uaf

%: %.c
	x86_64-linux-musl-gcc -static $< -o $@
	mv $@ /media/psf/Linux/pwn/LK01-3/qemu/root
	cd /media/psf/Linux/pwn/LK01-3/qemu/root && find . -print0 | cpio -o -0 -H newc -R root:root > ../test.cpio
