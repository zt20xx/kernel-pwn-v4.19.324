add-symbol-file ./src/pwn.ko 0xffffffffc0000000
add-symbol-file ./src/exp
target remote:1234
b pwn_read
b get_shell