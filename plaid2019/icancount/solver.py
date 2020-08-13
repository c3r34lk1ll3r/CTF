import angr
import claripy


target = angr.Project('icancount', auto_load_libs=False)

flag_buf = target.loader.find_symbol('flag_buf').rebased_addr

check_flag = target.loader.find_symbol('check_flag').rebased_addr

d_addr = target.loader.main_object.min_addr + 0xf9a
a_addr = target.loader.main_object.min_addr + 0xfae

entry_state = target.factory.blank_state(addr = check_flag)

inp = claripy.BVS('inp', 0x13*8)

for i in inp.chop(8):
    entry_state.solver.add(entry_state.solver.And(i>='0', i<='9'))

entry_state.memory.store(flag_buf, inp)

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Setup the simulation with the addresses to specify a success / failure
simulation.use_technique(angr.exploration_techniques.Explorer(find = d_addr, avoid = a_addr))

# Run the simulation
simulation.run()

# Parse out the solution, and print it
flag_int = simulation.found[0].solver.eval(inp)

flag = ""
for i in range(0,19):
    flag = chr(flag_int & 0xff) + flag
    flag_int = flag_int >> 8

print("flag: PCTF{" + flag + "}")
