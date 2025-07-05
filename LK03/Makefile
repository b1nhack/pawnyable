all: double_fetch

%: %.c
	$(MAKE) iwyu_$*
	x86_64-linux-musl-gcc -Wall -Wextra -Werror -static $< -lpthread -o $@
	x86_64-linux-musl-strip -s $@
	mv $@ /media/psf/Linux/pwn/LK03/qemu/root
	cd /media/psf/Linux/pwn/LK03/qemu/root && find . -print0 | cpio -o -0 -H newc -R root:root > ../test.cpio

iwyu_%: %.c
	include-what-you-use -Xiwyu --transitive_includes_only -Xiwyu --quoted_includes_first -Xiwyu --update_comments -Xiwyu --mapping_file=gcc.libc.imp -target x86_64-pc-linux-gnu $< 2> iwyu.out
	fix_includes.py --update_comments --nosafe_headers < iwyu.out
	rm iwyu.out
