#!/usr/bin/env python

import subprocess
import string

target = ['A', ')', '\\331', 'e', '\\241', '\\361', '\\341', '\\311', '\\031', '\\t', '\\223', '\\023', '\\241', '\\t', '\\271', 'I', '\\271', '\\211', '\\335', 'a', '1', 'i', '\\241', '\\361', 'q', '!', '\\235', '\\325', '=', '\\025', '\\325']

flag = {}

def call_ltrace(line):
    out = subprocess.Popen(['ltrace', '-e', 'strcmp', './rev_rev_rev'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) 
    _, s_err = out.communicate(line)
    s_err = s_err.decode('utf-8')
    s_err = s_err.split('strcmp')[1].split(',')[0][2:-1]
    return s_err
test = string.printable

for x in test:
    v = call_ltrace(x.encode('utf-8')+b'\n')
    if v in target:
        print(x + '-->' + v)
        flag[v] = x

ff = ""

for x in target[::-1]:
    ff+=flag[x]

print(ff)
