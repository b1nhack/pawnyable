all: uffd

%: %.c
	-$(MAKE) iwyu_$*
	x86_64-linux-gnu-gcc -Wall -Wextra -static $< -lpthread -o $@
	x86_64-linux-gnu-strip -s $@
	mv $@ /media/psf/Linux/pwn/LK04/qemu/root
	cd /media/psf/Linux/pwn/LK04/qemu/root && find . -print0 | cpio -o -0 -H newc -R root:root > ../test.cpio

iwyu_%: %.c
	include-what-you-use -Xiwyu --mapping_file=gcc.libc.imp -Xiwyu --update_comments -Xiwyu --quoted_includes_first -target x86_64-pc-linux-gnu $< 2> iwyu.out
	fix_includes.py --update_comments --nosafe_headers --reorder < iwyu.out
	rm iwyu.out
