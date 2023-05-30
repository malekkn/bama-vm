#!/usr/bin/env python3
import pwnlib.gdb as gdb
from time import sleep


password = b'ESCACRVJZBZFJHIGAXYW'
elf_fixes = [
    [0x5, 0x1],
    [0x12, 0x3e],
    [0x28, 0x0], [0x29, 0x0], [0x2a, 0x0],[0x2b, 0x0],
    [0x3a, 0x0],
    [0x3c, 0x0],
    [0x3e,0x0],
    [0x1a1, 0x7c]]

# 0x1003E0

gdb_cmds = '''
    break *0x0102077
    continue
    continue
    continue
    continue
    dump binary memory bin_dump ($rdi-0x6ca0) ($rdi+$rcx)
'''

# Create a new process, and stop it at 'main'
try:
    io = gdb.debug(['./binary_alpha_launcher.antianalysis'], env={'ALPHA_TOKEN': 'WMJMNJIYFZFLRUHNMCDY'}, gdbscript=gdb_cmds)
except (e):
    pass

# sleep for 3 seconds
sleep(3)
io.sendline(b'exit')
io.close()

# open file as bytesarray
with open('bin_dump', 'rb') as f:
    bin_dump = bytearray(f.read())


for idx, val in elf_fixes:
    bin_dump[idx] = val

# write bytes to a new file
with open('binary_alpha_launcher.unpacked', 'wb') as f:
    f.write(bin_dump)

