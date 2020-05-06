#!/usr/bin/env python
import subprocess
import string

command = "/sbin/perf stat -x : -e instructions:u ./movfuscated1"

flag = ""
mm = 0
char = ""
while True:
    for i in string.printable:
        out = subprocess.Popen(command.split(' '), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pp = out.communicate((flag+i).encode('utf-8'))
        perf = pp[1].decode('utf-8')
        count = int(perf.split(':')[0])
        if count > mm:
            mm = count
            char = i
    flag+=char
    print(flag)
