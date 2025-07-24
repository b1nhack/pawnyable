TARGET := uffd fuse

CC := x86_64-linux-gnu-gcc
CFLAGS := -Wall -Wextra
LDFLAGS := -static
STRIP := x86_64-linux-gnu-strip

uffd: LDFLAGS += -pthread

fuse: CFLAGS += $(shell pkg-config --cflags fuse)
fuse: LDFLAGS += $(shell pkg-config --libs fuse)

all: $(TARGET)

iwyu:
	include-what-you-use -Xiwyu --mapping_file=gcc.libc.imp -Xiwyu --update_comments -Xiwyu --quoted_includes_first -target x86_64-pc-linux-gnu $(ARGS) 2> iwyu.out
	fix_includes.py --noblank_lines --update_comments --nosafe_headers --reorder --quoted_includes_first < iwyu.out
	rm iwyu.out

%: %.c
	-$(MAKE) iwyu ARGS="$(CFLAGS) $<"
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
	$(STRIP) -s $@

clean:
	rm $(TARGET)
