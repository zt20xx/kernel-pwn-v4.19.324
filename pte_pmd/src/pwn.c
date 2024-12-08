#include<linux/proc_fs.h>
#include<linux/module.h>
#include<linux/fs.h>
#include<linux/slab.h>
#include<linux/uaccess.h>
#include<linux/mm.h>
struct proc_dir_entry *pwn_proc;
struct page *g_page=NULL;
static ssize_t pwn_write(struct file *fd,const char *buf,size_t count,loff_t *ops)
{
	return 0;

}
static ssize_t pwn_read(struct file *fd, char *buf,size_t count,loff_t *ops)
{
	return 0;

}
static long pwn_ioctl(struct file *fd,unsigned int a1,unsigned long a2){

	__free_page(g_page);
	return 0;
}
static int pwn_open(struct inode *inode,struct file *file)
{
	g_page=alloc_page(GFP_KERNEL);
	
	if(!g_page){
		return -ENOMEM;
	}
	printk("va: 0x%px -> 0x%016llx \n",page_address(g_page),page_to_phys(g_page));
	return 0;
}
static const struct file_operations fops={
	.owner=THIS_MODULE,
	.write=pwn_write,
	.read=pwn_read,
	.open=pwn_open,
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

