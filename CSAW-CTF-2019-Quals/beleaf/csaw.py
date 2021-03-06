#!/usr/bin/python -i
#
# Emulation script for "beleaf" from 0x555555554950 to 0x55555555497d
#
# Powered by gef, unicorn-engine, and capstone-engine
#
# @_hugsy_
#
from __future__ import print_function
import collections
import struct
import capstone, unicorn

registers = collections.OrderedDict(sorted({'$rax': unicorn.x86_const.UC_X86_REG_RAX,'$rbx': unicorn.x86_const.UC_X86_REG_RBX,'$rcx': unicorn.x86_const.UC_X86_REG_RCX,'$rdx': unicorn.x86_const.UC_X86_REG_RDX,'$rsp': unicorn.x86_const.UC_X86_REG_RSP,'$rbp': unicorn.x86_const.UC_X86_REG_RBP,'$rsi': unicorn.x86_const.UC_X86_REG_RSI,'$rdi': unicorn.x86_const.UC_X86_REG_RDI,'$rip': unicorn.x86_const.UC_X86_REG_RIP,'$r8': unicorn.x86_const.UC_X86_REG_R8,'$r9': unicorn.x86_const.UC_X86_REG_R9,'$r10': unicorn.x86_const.UC_X86_REG_R10,'$r11': unicorn.x86_const.UC_X86_REG_R11,'$r12': unicorn.x86_const.UC_X86_REG_R12,'$r13': unicorn.x86_const.UC_X86_REG_R13,'$r14': unicorn.x86_const.UC_X86_REG_R14,'$r15': unicorn.x86_const.UC_X86_REG_R15,'$eflags': unicorn.x86_const.UC_X86_REG_EFLAGS,'$cs': unicorn.x86_const.UC_X86_REG_CS,'$ss': unicorn.x86_const.UC_X86_REG_SS,'$ds': unicorn.x86_const.UC_X86_REG_DS,'$es': unicorn.x86_const.UC_X86_REG_ES,'$fs': unicorn.x86_const.UC_X86_REG_FS,'$gs': unicorn.x86_const.UC_X86_REG_GS}.items(), key=lambda t: t[0]))
uc = None
verbose = False
syscall_register = "$rax"

def disassemble(code, addr):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
    for i in cs.disasm(code, addr):
        return i

def hook_code(emu, address, size, user_data):
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> {:#x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
    return

def code_hook(emu, address, size, user_data):
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> {:#x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
    return

def intr_hook(emu, intno, data):
    print(" \-> interrupt={:d}".format(intno))
    return

def syscall_hook(emu, user_data):
    sysno = emu.reg_read(registers[syscall_register])
    print(" \-> syscall={:d}".format(sysno))
    return

def print_regs(emu, regs):
    for i, r in enumerate(regs):
        print("{:7s} = {:#08x}  ".format(r, emu.reg_read(regs[r])), end="")
        if (i % 4 == 3) or (i == len(regs)-1): print("")
    return


# from https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_64_msr.py
SCRATCH_ADDR = 0xf000
SEGMENT_FS_ADDR = 0x5000
SEGMENT_GS_ADDR = 0x6000
FSMSR = 0xC0000100
GSMSR = 0xC0000101

def set_msr(uc, msr, value, scratch=SCRATCH_ADDR):
    buf = b"\x0f\x30"  # x86: wrmsr
    uc.mem_map(scratch, 0x1000)
    uc.mem_write(scratch, buf)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, value & 0xFFFFFFFF)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)
    uc.mem_unmap(scratch, 0x1000)
    return

def set_gs(uc, addr):    return set_msr(uc, GSMSR, addr)
def set_fs(uc, addr):    return set_msr(uc, FSMSR, addr)



def reset(char, counter):
    emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN)


    emu.mem_map(SEGMENT_FS_ADDR-0x1000, 0x3000)
    set_fs(emu, SEGMENT_FS_ADDR)
    set_gs(emu, SEGMENT_GS_ADDR)

    emu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, 0x61)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RBX, 0x5555555549e0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, 0x7fffffffe080)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, 0x7fffffffe050)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RBP, 0x7fffffffe110)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RSI, 0xa)
    #emu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, 0x61)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, char)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_RIP, 0x555555554950)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R8, 0xffffffffffffff80)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R9, 0x40)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R10, 0x21)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R11, 0x246)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R12, 0x5555555546f0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R13, 0x7fffffffe200)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R14, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_R15, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EFLAGS, 0x202)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_CS, 0x33)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_SS, 0x2b)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_DS, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_ES, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_FS, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_GS, 0x0)
    # Mapping /home/andrea/Documents/CTF/CSAW-CTF-2019-Quals/rev/beleaf/beleaf: 0x555555554000-0x555555555000
    emu.mem_map(0x555555554000, 0x1000, 0o5)
    emu.mem_write(0x555555554000, open('./gef-beleaf-0x555555554000.raw', 'rb').read())

    # Mapping /home/andrea/Documents/CTF/CSAW-CTF-2019-Quals/rev/beleaf/beleaf: 0x555555754000-0x555555755000
    emu.mem_map(0x555555754000, 0x1000, 0o1)
    emu.mem_write(0x555555754000, open('./gef-beleaf-0x555555754000.raw', 'rb').read())

    # Mapping /home/andrea/Documents/CTF/CSAW-CTF-2019-Quals/rev/beleaf/beleaf: 0x555555755000-0x555555756000
    emu.mem_map(0x555555755000, 0x1000, 0o3)
    emu.mem_write(0x555555755000, open('./gef-beleaf-0x555555755000.raw', 'rb').read())

    # Mapping [heap]: 0x555555756000-0x555555777000
    emu.mem_map(0x555555756000, 0x21000, 0o3)
    emu.mem_write(0x555555756000, open('./gef-beleaf-0x555555756000.raw', 'rb').read())

    # Mapping /usr/lib/libc-2.31.so: 0x7ffff7dcf000-0x7ffff7df4000
    emu.mem_map(0x7ffff7dcf000, 0x25000, 0o1)
    emu.mem_write(0x7ffff7dcf000, open('./gef-beleaf-0x7ffff7dcf000.raw', 'rb').read())

    # Mapping /usr/lib/libc-2.31.so: 0x7ffff7df4000-0x7ffff7f40000
    emu.mem_map(0x7ffff7df4000, 0x14c000, 0o5)
    emu.mem_write(0x7ffff7df4000, open('./gef-beleaf-0x7ffff7df4000.raw', 'rb').read())

    # Mapping /usr/lib/libc-2.31.so: 0x7ffff7f40000-0x7ffff7f8b000
    emu.mem_map(0x7ffff7f40000, 0x4b000, 0o1)
    emu.mem_write(0x7ffff7f40000, open('./gef-beleaf-0x7ffff7f40000.raw', 'rb').read())

    # Mapping /usr/lib/libc-2.31.so: 0x7ffff7f8b000-0x7ffff7f8e000
    emu.mem_map(0x7ffff7f8b000, 0x3000, 0o1)
    emu.mem_write(0x7ffff7f8b000, open('./gef-beleaf-0x7ffff7f8b000.raw', 'rb').read())

    # Mapping /usr/lib/libc-2.31.so: 0x7ffff7f8e000-0x7ffff7f91000
    emu.mem_map(0x7ffff7f8e000, 0x3000, 0o3)
    emu.mem_write(0x7ffff7f8e000, open('./gef-beleaf-0x7ffff7f8e000.raw', 'rb').read())

    # Mapping : 0x7ffff7f91000-0x7ffff7f97000
    emu.mem_map(0x7ffff7f91000, 0x6000, 0o3)
    emu.mem_write(0x7ffff7f91000, open('./gef-beleaf-0x7ffff7f91000.raw', 'rb').read())

    # Mapping [vdso]: 0x7ffff7fcf000-0x7ffff7fd1000
    emu.mem_map(0x7ffff7fcf000, 0x2000, 0o5)
    emu.mem_write(0x7ffff7fcf000, open('./gef-beleaf-0x7ffff7fcf000.raw', 'rb').read())

    # Mapping /usr/lib/ld-2.31.so: 0x7ffff7fd1000-0x7ffff7fd3000
    emu.mem_map(0x7ffff7fd1000, 0x2000, 0o1)
    emu.mem_write(0x7ffff7fd1000, open('./gef-beleaf-0x7ffff7fd1000.raw', 'rb').read())

    # Mapping /usr/lib/ld-2.31.so: 0x7ffff7fd3000-0x7ffff7ff3000
    emu.mem_map(0x7ffff7fd3000, 0x20000, 0o5)
    emu.mem_write(0x7ffff7fd3000, open('./gef-beleaf-0x7ffff7fd3000.raw', 'rb').read())

    # Mapping /usr/lib/ld-2.31.so: 0x7ffff7ff3000-0x7ffff7ffb000
    emu.mem_map(0x7ffff7ff3000, 0x8000, 0o1)
    emu.mem_write(0x7ffff7ff3000, open('./gef-beleaf-0x7ffff7ff3000.raw', 'rb').read())

    # Mapping /usr/lib/ld-2.31.so: 0x7ffff7ffc000-0x7ffff7ffd000
    emu.mem_map(0x7ffff7ffc000, 0x1000, 0o1)
    emu.mem_write(0x7ffff7ffc000, open('./gef-beleaf-0x7ffff7ffc000.raw', 'rb').read())

    # Mapping /usr/lib/ld-2.31.so: 0x7ffff7ffd000-0x7ffff7ffe000
    emu.mem_map(0x7ffff7ffd000, 0x1000, 0o3)
    emu.mem_write(0x7ffff7ffd000, open('./gef-beleaf-0x7ffff7ffd000.raw', 'rb').read())

    # Mapping : 0x7ffff7ffe000-0x7ffff7fff000
    emu.mem_map(0x7ffff7ffe000, 0x1000, 0o3)
    emu.mem_write(0x7ffff7ffe000, open('./gef-beleaf-0x7ffff7ffe000.raw', 'rb').read())

    # Mapping [stack]: 0x7ffffffde000-0x7ffffffff000
    emu.mem_map(0x7ffffffde000, 0x21000, 0o3)
    emu.mem_write(0x7ffffffde000, open('./gef-beleaf-0x7ffffffde000.raw', 'rb').read())

    # Mapping [vsyscall]: 0xffffffffff600000-0xffffffffff601000
    emu.mem_map(0xffffffffff600000, 0x1000, 0o4)
    #emu.hook_add(unicorn.UC_HOOK_CODE, code_hook)
    #emu.hook_add(unicorn.UC_HOOK_INTR, intr_hook)
    #emu.hook_add(unicorn.UC_HOOK_INSN, syscall_hook, None, 1, 0, unicorn.x86_const.UC_X86_INS_SYSCALL)
    emu.mem_write(0x7fffffffe110-0xa8, counter)
    return emu

def emulate(emu, start_addr, end_addr):
    #print("========================= Initial registers =========================")
    #print_regs(emu, registers)

    try:
        #print("========================= Starting emulation =========================")
        emu.emu_start(start_addr, end_addr)
    except Exception as e:
        emu.emu_stop()
        #print("========================= Emulation failed =========================")
        #print("[!] Error: {}".format(e))
        return False
    #print("========================= Final registers =========================")
    #print_regs(emu, registers)
    address = emu.reg_read(registers['$rbp']) - 0x98;
    to_find = emu.reg_read(registers["$rax"])
    computed = struct.unpack('<q',emu.mem_read(address, 8))[0]
    #print(hex(computed) + ' == '+hex(to_find)+' ?')
    if computed == to_find:
        return True
    return False

char = 0x30;
pos = 0;
flag = ""
indx = 0
st = ["|" , "/" , "-" , "\\" , "|" , "/" , "-" ,"\\"] 
while char < 0x7f:
    print("["+st[indx]+"]:"+flag+chr(char), end="", flush=True)
    uc = reset(char, struct.pack('<I',pos))
    if(emulate(uc, 0x555555554950, 0x55555555497d)):
        flag +=chr(char)
        char = 0x29
        pos = pos +1    
    indx+=1
    indx = indx+1 if indx < 7 else 0
    print("\r",end="",flush=True)
    char+=1;
    if pos > 32:
        break
print("\n")
print("Win!! This is the flag: "+flag)
# unicorn-engine script generated by gef
