#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *
import struct

bingo = "0x405f1c"
f = "./rabbit"
NOP = 0x90
CALL = b"\xe8"
IMAGE_BASE = 0x400000
BASE_INS = b"\xba\xa5\xc9\xb9\xbf"
text_start = 0


def addrToIdx(addr):
    return addr - text_start


def idxToAddr(idx):
    return text_start + idx


def patch_call(rabbit, addr, target):
    patch_size = 0
    # if (addr == special):
    #     return
    # use the instruction before the call to insert larger call ins
    new_add = addr - 7
    patch_size = 7 + 2
    offset = target - addr + 2
    idx = new_add - IMAGE_BASE
    new_ins = b"".join([CALL, struct.pack("<i", offset)])
    # print('patching ' + ('special: ' if addr == special else ': ') + hex(addr) + ' -> ' + hex(target) + ' at ' + hex(new_add) + (' [pos]' if (target - addr) > 0 else ' [neg]'))

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


# open file and return the stream
def get_file_elf(filename):
    f = open(filename, "rb")
    elf = ELFFile(f)
    return elf


def nop_range(rabbit, idx, size):
    try:
        for i in range(size):
            rabbit[idx + i] = NOP
    except:
        print(idx + i)


# return a list of all indices of the pattern in the bytestring
def find_pattern(bytestring, pattern):
    idx = []
    for i in range(len(bytestring) - len(pattern)):
        if bytestring[i : i + len(pattern)] == pattern:
            idx.append(i)
    return idx


# stolen from ghidra de-compiler
def calc_call_operand(offset):
    uVar4 = 0xBFB9C9A5
    uVar5 = 0x2B495D78

    while uVar4 != uVar5:
        uVar3 = uVar4
        uVar4 = (uVar5 - uVar3) & 0xFFFFFFFF
        uVar5 = uVar3
    return uVar3 + offset


def is_return_addr_read(ins):
    return (
        ins.id == X86_INS_MOV
        and ins.operands[0].type == X86_OP_REG
        and ins.operands[0].value.reg == X86_REG_RAX
        and ins.operands[1].type == X86_OP_MEM
        and ins.operands[1].value.mem.base == X86_REG_RBP
    )


rabbit = read_file(f)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

elf = get_file_elf(f)

text_sec = elf.get_section_by_name(".text")
text_start = text_sec.header.sh_addr
text = text_sec.data()

# find the pattern statically and patch the calls near them
working_set = find_pattern(text, BASE_INS)

prev_ins = 0
for idx in working_set:
    for ins in md.disasm(text[idx:], text_start + idx, 16):
        for op in ins.operands:
            if X86_GRP_CALL in ins.groups and op.type == X86_OP_REG:
                patch_call(
                    rabbit,
                    ins.address,
                    calc_call_operand(prev_ins.operands[1].value.imm),
                )
        prev_ins = ins


# find main function
# starting from the entry point, find the first mov RDI instruction
main_idx = 0
for ins in md.disasm(text, text_start, 16):
    if (
        ins.id == X86_INS_MOV
        and ins.operands[0].type == X86_OP_REG
        and ins.operands[0].value.reg == X86_REG_RDI
    ):
        main_idx = ins.operands[1].value.imm


def check_return_manipulation(addr, stack):
    ret_disp = 0
    read_next_imm = False
    idx = addrToIdx(addr)
    instructions = md.disasm(text[idx:], text_start + idx, 24)
    for ins in instructions:
        if ins.id == X86_INS_CALL and ins.operands[0].type == X86_OP_IMM:
            # push the caller's return address and info to the stack and recurse
            target = addrToIdx(ins.operands[0].value.imm)
            if 0 < target and target < len(text):
                print(hex(ins.address), ins.mnemonic, ins.op_str)
                stack.append(
                    {
                        "addr": ins.address,
                        "next": ins.address + ins.size,
                        "next_idx": addrToIdx(ins.address + ins.size),
                        "target": target,
                    }
                )
                check_return_manipulation(ins.operands[0].value.imm, stack)
        elif ins.id == X86_INS_CALL:
            print(">>>>", hex(ins.address), ins.mnemonic, ins.op_str)
        elif ins.id == X86_INS_RET:
            print(hex(ins.address), ins.mnemonic, ins.op_str)
            # pop the caller
            caller = stack.pop()
            # no ret disp, so we do not do anything
            # if (ret_disp != 0):
            #     nop_range(rabbit, caller['next_idx'], ret_disp)
            return
        elif is_return_addr_read(ins):
            read_next_imm = True
            # patch these instructions with NOPs
            # nop_range(rabbit, addrToIdx(ins.address), 12)
            print(
                "found rbp read at"
                + hex(ins.address)
                + " "
                + ins.mnemonic
                + " "
                + ins.op_str
            )
        elif read_next_imm:
            read_next_imm = False
            ret_disp = ins.operands[1].value.imm
            print(
                "found mov RAX at "
                + hex(ins.address)
                + " "
                + ins.mnemonic
                + " "
                + ins.op_str
            )

    return False


check_return_manipulation(main_idx, list({"addr": 0, "next_idx": 0}))

write_file("./rabbit_static_patch", rabbit)
