#include<linux/proc_fs.h>
#include<linux/module.h>
#include<linux/fs.h>
#include<linux/slab.h>
#include<linux/uaccess.h>
struct proc_dir_entry *core_proc;
char *g_buf=NULL;
static ssize_t core_write(struct file *fd,const char *buf,size_t count,loff_t *ops)
{
	if(copy_from_user(g_buf,buf,count)){
		return -EINVAL;
	}
	return 0;

}
static ssize_t core_read(struct file *fd, char *buf,size_t count,loff_t *ops)
{
	if(copy_to_user(buf,g_buf,count)){
		return -EINVAL;
	}
	return 0;


}
static int core_open(struct inode *inode,struct file *file)
{
	g_buf=kmalloc(0x400,GFP_KERNEL);
	printk("g_buf: 0x%px\n",g_buf);
	if(!g_buf){
		return -ENOMEM;
	}
	return 0;
}
static const struct file_operations fops={
	.owner=THIS_MODULE,
	.write=core_write,
	.read=core_read,
	.open=core_open,
};
int core_init(void)
{
	printk("core create\n");
	core_proc=proc_create("core",0666,0,&fops);
	return 0;

}
void core_exit(void)
{
}

module_init(core_init);
module_exit(core_exit);
MODULE_LICENSE("GPL");

