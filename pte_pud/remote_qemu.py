import socket
import readline
def completer(text,state):
    options=["xp/8gx ","va2pa "]
    matches=[option for option in options if option.startswith(text)]
    if state<len(matches):
        return matches[state]
    else:
        return None
readline.set_completer(completer)
readline.parse_and_bind("tab:complete")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 4444))
def get_res_bytes():
    all_data=b''
    count=0
    while True:
        data=sock.recv(1024)
        count+=1
        all_data+=data
        if b'(qemu)' in data and count>1:
            break
    return all_data
def show_res():
    data=get_res_bytes()
    data=data.decode('utf-8')[:-len("(qemu) ")]
    print(data,end='')
def send_cmd(cmd:str):
    cmd=cmd+' \r\n'
    cmd=cmd.encode("utf-8")
    sock.sendall(cmd)
def get_pa_value(pa):
    cmd=f'xp/gx {hex(pa)}'
    send_cmd(cmd)
    data=get_res_bytes()
    head=data.find(b': ')+2
    tail=head+data[head:].find(b'\r\n')
    value = int(data[head:tail],16)
    return value
def va2pa(va):
    addr_offset=va&0xfff
    pte_index=(va>>12)&0x1ff
    pmd_index=(va>>21)&0x1ff
    pud_index=(va>>30)&0x1ff
    pgd_index=(va>>39)&0x1ff
    print(f'PGD[{pgd_index}]->PUD[{pud_index}]->PMD[{pmd_index}]->PTE[{pte_index}]')
    send_cmd("info registers")
    data=get_res_bytes()
    cr3_index=data.find(b'CR3')
    cr3_tail_index=cr3_index+data[cr3_index:].find(b' ')
    cr3_info=data[cr3_index:cr3_tail_index]
    cr3_value=int(cr3_info.split(b'=')[1],16)
    print("cr3:",hex(cr3_value))
    pgd=get_pa_value(cr3_value+0x8*pgd_index)
    pgd=pgd&(2**63-1-0xff)
    print(f"PGD[{pgd_index}]:",hex(pgd))
    if not pgd:
        return
    pud = get_pa_value(pgd + 0x8 * pud_index)
    pud = pud & (2 ** 63 - 1 - 0xff)
    print(f"PUD[{pud_index}]:", hex(pud))
    if not pud:
        return
    pmd = get_pa_value(pud + 0x8 * pmd_index)
    pmd = pmd & (2 ** 63 - 1 - 0xff)
    print(f"PMD[{pmd_index}]:", hex(pmd))
    if not pmd:
        return
    pte = get_pa_value(pmd + 0x8 * pte_index)
    pte = pte & (2 ** 63 - 1 - 0xff)
    print(f"PTE[{pte_index}]:", hex(pte))
    if not pte:
        return
    value=get_pa_value(pte+addr_offset)
    print(f"{hex(va)}:{hex(value)}")
def interactive():
    while True:
        cmd=input("(qemu) ")
        if cmd=="q" or cmd=="exit":
            return
        elif cmd.startswith("va2pa"):
            cmds=cmd.split(' ')
            if len(cmds)==1:
                continue
            va2pa(int(cmds[1],16))
        else:
            send_cmd(cmd)
            show_res()
if __name__=="__main__":
    interactive()

