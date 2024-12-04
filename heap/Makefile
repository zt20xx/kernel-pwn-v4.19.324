.PHONY : exp
KDIR:=/home/tingzhang/kernel/linux-4.19.320
PWD:=$(shell pwd)
EXTRA_CFLAGS=-O0 -g -fno-stack-protector
obj-m+=pwn.o
all:ko exp
ko:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
exp:
	gcc -g -static -masm=intel exp.c -o exp


