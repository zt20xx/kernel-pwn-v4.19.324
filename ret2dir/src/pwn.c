#include<linux/proc_fs.h>
#include<linux/module.h>
#include<linux/fs.h>
struct proc_dir_entry *pwn_proc;
size_t jmp_addr=0;
void help_asm(void)
{
	__asm__(
			"swapgs;popfq;ret;"
			"iretq;ret;"
			"pop rdi;ret;"
			"mov cr4,rdi;ret;"
			"pop rax;ret;"
			"mov [rdi], rax; ret;"
			"add rsp,0x320;ret;"
	       );

}
static long pwn_ioctl(struct file *fd,unsigned int a1,unsigned long a2){
	jmp_addr=a2;
	asm volatile(
			"mov rax,[jmp_addr];"
			"mov rsp,rax;"
			"mov rbx,rax;"
			"jmp [rax];ret;"
			);
	return 0;
}
static const struct file_operations fops={
	.owner=THIS_MODULE,
	.unlocked_ioctl=pwn_ioctl,
};
int pwn_init(void)
{
	printk("/proc/pwn create\n");
	pwn_proc=proc_create("pwn",0666,0,&fops);
	return 0;

}
void pwn_exit(void)
{
}

module_init(pwn_init);
module_exit(pwn_exit);
MODULE_LICENSE("GPL");

