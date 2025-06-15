all: heap heap_modprobe heap_cred heap_core

heap_modprobe: shell

heap_core: core shell

%: %.c
	x86_64-linux-musl-gcc -static $< -o $@
	mv $@ /media/psf/Linux/pwn/LK01-2/qemu/root
	cd /media/psf/Linux/pwn/LK01-2/qemu/root && find . -print0 | cpio -o -0 -H newc -R root:root > ../test.cpio
