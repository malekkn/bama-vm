#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *
import struct


NOP = 0x90
CALL = b"\xe8"
rabbit_path = "./rabbit"
bingo = "0x405f1c"
IMAGE_BASE = 0x400000
IND_CALL_BASE = b"\xba\xa5\xc9\xb9\xbf"  # MOV   EDX,0xbfb9c9a5
CALL_CALC_SIZE = 22
text_start = 0


def addrToIdx(addr):
    return addr - text_start


def idxToAddr(idx):
    return text_start + idx


def patch_ind_call(rabbit, addr, target):
    # print("patching ind call", hex(addr), "with", hex(target))
    patch_size = 0
    # use the instruction before the call to insert larger call ins
    new_add = addr - 7
    patch_size = 7 + 2
    offset = target - addr + 2
    idx = new_add - IMAGE_BASE
    new_ins = b"".join([CALL, struct.pack("<i", offset)])
    for i in range(patch_size):
        if i < len(new_ins):
            rabbit[idx + i] = new_ins[i]
        else:
            # NOP what is left after the patch
            rabbit[idx + i] = NOP
    return


def read_file(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())


def write_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)


# open file and return the elf object
def get_file_elf(filename):
    f = open(filename, "rb")
    elf = ELFFile(f)
    return elf


def nop_range(rabbit, addr, size):
    """nop out a range of bytes index"""
    idx = addr - IMAGE_BASE
    try:
        for i in range(size):
            rabbit[idx + i] = NOP
    except:
        print(idx + i)


def find_pattern(bytestring, pattern):
    """return a list of all indices of the pattern in the bytestring"""
    idx = []
    for i in range(len(bytestring) - len(pattern)):
        if bytestring[i : i + len(pattern)] == pattern:
            idx.append(i)
    return idx


# borrowed from ghidra de-compiler
def calc_call_operand(offset):
    op1 = 0xBFB9C9A5
    op2 = 0x2B495D78

    while op1 != op2:
        tmp = op1
        op1 = (op2 - tmp) & 0xFFFFFFFF
        op2 = tmp
    return tmp + offset


def is_return_addr_read(ins):
    """check for the return address being read: MOV %REG, [%RBP + 8]"""
    return (
        ins.id == X86_INS_MOV
        and ins.operands[0].type == X86_OP_REG
        and ins.operands[0].value.reg == X86_REG_RAX
        and ins.operands[1].type == X86_OP_MEM
        and ins.operands[1].value.mem.base == X86_REG_RBP
        and ins.operands[1].value.mem.disp == 0x8
    )


rabbit = read_file(rabbit_path)  # used to apply patches

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
elf = get_file_elf(rabbit_path)

text_sec = elf.get_section_by_name(".text")
text_start = text_sec.header.sh_addr
text = text_sec.data()  # used for read only and disassemble the text section


def is_valid_call(text, call_sus_idx):
    """Checks whether an instruction is a call by checjing if the target is in text section
    and whether the code at that address is a ENDBR64 instruction"""
    ws = md.disasm(text[call_sus_idx:], idxToAddr(call_sus_idx), 1)
    for ins in ws:
        if X86_GRP_CALL in ins.groups and op.type == X86_OP_IMM:
            callee_sus = ins.operands[0].value.imm
            callee_sus_idx = addrToIdx(callee_sus)
            if 0 < callee_sus_idx and callee_sus_idx < len(text):
                ws2 = md.disasm(text[callee_sus_idx:], idxToAddr(callee_sus_idx), 1)
                for ins2 in ws2:
                    if ins2.id == X86_INS_ENDBR64:
                        # print(hex(ins.address), ins.mnemonic, ins.op_str, ' -> ',hex(ins2.address), ins2.mnemonic, ins2.op_str)
                        return {
                            "caller": idxToAddr(call_sus_idx),
                            "callee": callee_sus,
                            "return_addr": idxToAddr(call_sus_idx + ins.size),
                        }


def find_ret_disp(text, target_addr):
    """find the displacement of the return address from the target address (callee)"""
    disp = 0
    to_patch = 0
    get_disp = False
    # disassemble the text until we find the return address
    ws = md.disasm(text[addrToIdx(target_addr) :], target_addr, len(text))
    for ins in ws:
        if is_return_addr_read(ins):
            get_disp = True
            to_patch = ins.address
        # get the value from ADD %REG, imm
        elif get_disp:
            get_disp = False
            disp = ins.operands[1].value.imm
        elif X86_INS_RET == ins.id:
            return (disp, to_patch)
    return (disp, to_patch)


############################
# Indirect call stuff here #
############################
# find the pattern before indirect calls statically and patch the calls near them
working_set = find_pattern(text, IND_CALL_BASE)

prev_ins = 0
for idx in working_set:
    # nop the calculation because it is useless after the patch
    nop_range(rabbit, idx - 5 + text_start, CALL_CALC_SIZE)
    for ins in md.disasm(text[idx:], idxToAddr(idx), 16):
        for op in ins.operands:
            if X86_GRP_CALL in ins.groups and op.type == X86_OP_REG:
                patch_ind_call(
                    rabbit,
                    ins.address,
                    calc_call_operand(prev_ins.operands[1].value.imm),
                )

        prev_ins = ins

###########################
# Return patch stuff here #
###########################
# find a possible call instruction indices
sus_calls_idx = find_pattern(text, CALL)

# get them one by one and check if valid function call...
funcs = {}
for sus_call in sus_calls_idx:
    # disassemble and check if valid call instruction
    res = is_valid_call(text, sus_call)
    if res is not None and res["callee"] in funcs.keys():
        funcs[res["callee"]][res["caller"]] = res["return_addr"]
    elif res is not None:
        funcs[res["callee"]] = {res["caller"]: res["return_addr"]}

for target in funcs.keys():
    for caller in funcs[target]:
        disp, patch_addr = find_ret_disp(text, target)
        if disp > 0:
            # print(
            #     "patching return patch ins:: target func:",
            #     hex(target),
            #     "caller",
            #     hex(caller),
            #     "retrun address:",
            #     hex(funcs[target][caller]),
            #     "return addr patch ins",
            #     hex(patch_addr),
            #     "disp of return",
            #     hex(disp),
            # )

            # patch the calculation of the return address
            nop_range(rabbit, patch_addr, 12)
            # patch the filler instructions after the caller
            nop_range(rabbit, funcs[target][caller], disp)
            # print("\t\t", hex(disp), "patch:", hex(patch_addr))


write_file("./rabbit_static_patch", rabbit)
