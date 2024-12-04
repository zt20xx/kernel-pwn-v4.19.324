.PHONY: exp 
KDIR:=../../$(LINUX_VERSION)
PWD:=$(shell pwd)
obj-m += pwn.o
EXTRA_CFLAGS += -O0 -g -masm=intel -fno-stack-protector -Werror=return-type
all:ko exp
ko:
	make -C $(KDIR) M=$(PWD) modules

exp:
	gcc -static -masm=intel exp.c -lrt -o exp 
clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -rf exp
