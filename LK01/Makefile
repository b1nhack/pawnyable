all: exp.c
	x86_64-linux-musl-gcc -static exp.c -o exp
	mv exp /media/psf/Linux/pwn/LK01/qemu/root
	cd /media/psf/Linux/pwn/LK01/qemu/root && find . -print0 | cpio -o -0 -H newc -R root:root > ../test.cpio
