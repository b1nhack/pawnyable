all: ret2usr krop kpti kaslr ret2usr_smap ret2usr_kalsr

%: %.c
	x86_64-linux-musl-gcc -static $^ -o $@
	mv $@ /media/psf/Linux/pwn/LK01/qemu/root
	cd /media/psf/Linux/pwn/LK01/qemu/root && find . -print0 | cpio -o -0 -H newc -R root:root > ../test.cpio
