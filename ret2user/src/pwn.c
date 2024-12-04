#include<linux/proc_fs.h>
#include<linux/module.h>
#include<linux/fs.h>
struct proc_dir_entry *pwn_proc;
void help_asm(void)
{
	__asm__(
			"swapgs;popfq;ret;"
			"iretq;ret;"
			"pop rdi;ret;"
			"mov cr4,rdi;ret;"
			"pop rax;ret;"
			"mov [rdi], rax; ret;"
	       );

}
static ssize_t pwn_write(struct file *fd,const char *buf,size_t count,loff_t *ops)
{
	char data[64];
	memset(data,'a',64);
	memcpy(data,buf,count);
	return 0;

}
static const struct file_operations fops={
	.owner=THIS_MODULE,
	.write=pwn_write,
};
int pwn_init(void)
{
	printk("core create\n");
	pwn_proc=proc_create("pwn",0666,0,&fops);
	return 0;

}
void pwn_exit(void)
{
}

module_init(pwn_init);
module_exit(pwn_exit);
MODULE_LICENSE("GPL");

