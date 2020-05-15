#!/sbin/env python
import subprocess
import time
start = list("ILAG23456912365453475897834567")
x = len(start)
i=1
char = 0x27
old = 1 
while i < x:
    start[i] = chr(char)
    print("".join(start))
    p = subprocess.Popen(['./rock'], stdin = subprocess.PIPE, stdout = subprocess.PIPE)
    pp = p.communicate(("".join(start)).encode('utf-8'))[0].decode('utf-8')
    print(pp)
    k = pp.split('You did not pass')
    if int(k[1]) != old:
        print("Found!")
        old = int(k[1])
        i+=1
        char = 0x26
    char+=1 



print("".join(start))
