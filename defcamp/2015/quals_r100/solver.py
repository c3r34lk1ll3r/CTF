import angr


target = angr.Project('r100')

d_adr = 0x4007a1

w_adr = 0x400790

e_state = target.factory.entry_state()

simulation = target.factory.simulation_manager(e_state)

simulation.explore(find=d_adr, avoid=w_adr)

solution=simulation.found[0].posix.dumps(0)
print(solution)
