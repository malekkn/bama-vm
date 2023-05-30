
from sre_constants import SUCCESS
import time
from tkinter.tix import Tree
import angr
import claripy
from ang_mbf.lift_mbf import LifterMBF
from ang_mbf.arch_mbf import ArchMBF


import signal
import os


def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print('ctrl+c [SIGINT]: Stopping Execution for Debug. If you want to kill the programm issue: killmyself():')
    import IPython; IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

if __name__ == '__main__':
    start = time.time()

    file_name = 'morpheus.mbf'
    with open(file_name, 'rb') as f:
        data = f.read()
    my_find = 4767  # find step 1
    my_find = 13779 # find step 2
    my_find = 41750 # find step 3

    my_avoid = list(range(my_find+1, len(data)))

    seen = {}
    for i in range(my_find):
        seen[i] = 0


    p = angr.Project(file_name)

    state = p.factory.blank_state()
    while True:
        if state.addr >= my_find  and state.addr < len(data) and state.addr not in my_avoid:
            found = state
            print('==================================')
            print(found.posix.dumps(1).decode('ascii'))
            print("found at:", state.addr)
            break


        succ = state.step()
        if len(succ.successors) > 1:
            succ_1, succ_2 = succ.successors

            if succ_2.addr not in my_avoid:
                state = succ_2
            else:
                state = succ_1
            seen[state.addr] += 1
        else:
            succ_1 = succ.successors[0]
            if state.addr < my_find:
                ip = succ_1.solver.eval(state.regs.ip)
                seen[ip] += 1
                # forward the program if we are getting stuck in a loop
                if seen[ip] > 2:
                    if b']' in succ_1.block().bytes:
                        succ_1.memory.store(state.regs.ptr, 0x0)
                    elif b')' in succ_1.block().bytes:
                        succ_1.regs.ip += 1
            state = succ_1
    end = time.time()
    print(f'{end-start} seconds')
