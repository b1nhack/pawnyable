TARGET := ret2usr krop kpti kaslr ret2usr_smap ret2usr_kaslr

TOOLCHAIN := x86_64-linux-musl
CC := $(TOOLCHAIN)-gcc
CFLAGS := -Wall -Wextra
LDFLAGS := -static
STRIP := $(TOOLCHAIN)-strip

all: $(TARGET)

iwyu:
	include-what-you-use -Xiwyu --mapping_file=gcc.libc.imp -Xiwyu --update_comments -Xiwyu --quoted_includes_first -target x86_64-pc-linux-gnu $(ARGS) 2> iwyu.out
	fix_includes.py --noblank_lines --update_comments --nosafe_headers --reorder --quoted_includes_first < iwyu.out
	rm iwyu.out

%: %.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
	$(STRIP) -s $@
	-$(MAKE) iwyu ARGS="$(CFLAGS) $<"

clean:
	rm -f $(TARGET)
