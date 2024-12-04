#include <linux/fs.h>
#include<linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
struct proc_dir_entry *pwn_proc;

struct attr {
	struct tmp_flag *flag_addr;
	size_t len;
};

#define BUFFER_SIZE 16
char *pwn_flag;

static long pwn_ioctl(struct file *fd, unsigned int cmd, unsigned long addr) {
	int i=0;
	struct attr *arg ;
	switch (cmd) {
		case 0x6666:
			printk("1.I will tell you the addr:%px\n", pwn_flag);
			break;
		case 0x7777:
			arg = (struct attr *)addr;
			printk("2.I will check the struct addr");
			if ((unsigned long)(arg->flag_addr) >=0x7fffffffde30) {
				printk("too big too bad addr %px\n", arg->flag_addr);
				return -EINVAL;
			}
			printk("before loop %px.%px",arg->flag_addr,pwn_flag);
			while(i<5000){i++;};
			printk("checking %px.%px",arg->flag_addr,pwn_flag);
			if (arg->flag_addr!=pwn_flag){ 
				return -EINVAL;
			}
			printk("3.I will tell you flag:%s\n", pwn_flag);
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pwn_ioctl,
};

static int pwn_init(void) {
	pwn_flag = kmalloc(16, GFP_KERNEL);
	if (!pwn_flag) {
		return -ENOMEM;
	}
	snprintf(pwn_flag, BUFFER_SIZE, "flag{hello}");
	pwn_proc=proc_create("pwn",0666,0,&fops);
	return 0;
}

static void pwn_exit(void) {
	kfree(pwn_flag);
	printk("bye\n");
}

module_init(pwn_init);
module_exit(pwn_exit);

MODULE_LICENSE("GPL");


