import archinfo
import pyvex
from pyvex.lifting.util import *
from pyvex.lifting import register
from .arch_mbf import ArchMBF
import bitstring
import sys
import os
import claripy
from angr import SimValueError
import logging

log = logging.getLogger("LifterMBF")

# This is actually a BrainFuck lifter for pyVEX.  I'm not joking.
# Created by edg on 1/14/2017
# Rewrote by edg for gymrat on 9/4/2017
# The goal of this, and any other lifter, is to convert one basic block of raw bytes into
# a set of VEX instructions representing what the code does.
# A basic block, in this case is defined a set of instructions terminated by:
# !) a conditional branch
# 2) A function call
# 3) A system call
# 4) the end of the program
#
# We need to build an IRSB, a grouping of VEX code, and associated metadata representing one block.
# This is then used by angr itself to perform static analysis and symbolic execution.

##
# These helper functions are how we resolve jumps in BF.
# Because they require scanning the actual code to resolve, they require a global view of the program's memory.
# Lifters in pyvex only get block-at-a-time access to memory, so we solve this by using a "CCall", which tells VEX
# /angr to execute a side-effect-less function and put the result in a variable.
# We therefore let angr resolve all jumps at "run"-time.
# TODO: FIXME: We need to refactor CCall to be more friendly to adding CCalls.  I will document the process
# here as best I can.


# For the sake of my sanity, the ptr is 64 bits wide.
# By the spec, cells are 8 bits, and do all the usual wrapping stuff.
PTR_TYPE = Type.int_64
CELL_TYPE = Type.int_8
PTR_REG = 'ptr'
INOUT_REG = 'inout'
CF_REG = 'cf'
SP_REG = 'sp'
SP_START = 0xf0000000

class Instruction_NOP(Instruction):
    # Convert everything that's not an instruction into a No-op to meet the BF spec
    bin_format = 'xxxxxxxx' # We don't care, match it all
    name = 'nop'

    def parse(self, bitstrm):
        self.last_instruction = False
        data = Instruction.parse(self, bitstrm)
        try:
            bitstrm.peek(8)
        except bitstring.ReadError:
            # We ran off the end!
            self.last_instruction = True
        return data

    def compute_result(self):
        if self.last_instruction:
            self.jump(None, self.constant(self.addr, PTR_TYPE), jumpkind=JumpKind.Exit)


# These are the standard BrainFuck instructions.


class Instruction_INCPTR(Instruction):
    bin_format = bin(ord(">"))[2:].zfill(8)
    name = 'incptr'

    def compute_result(self, *args):
        """
        '>': move the ptr register to the right one cell, or
        ptr += 1
        :param irsb_c:
        :type irsb_c: vex_helpers.IRSBCustomizer
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr += 1
        self.put(ptr, PTR_REG)


class Instruction_DECPTR(Instruction):
    bin_format = bin(ord("<"))[2:].zfill(8)
    name = 'decptr'

    def compute_result(self, *args):
        """
        '<': Move the ptr register to the left one cell, or
        ptr -= 1
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr -= 1
        self.put(ptr, PTR_REG)

class Instruction_INC(Instruction):
    bin_format = bin(ord("+"))[2:].zfill(8)
    name = 'inc'

    def compute_result(self, *args):
        """
        '+': Increment the value of the data memory pointed at by the ptr register, or:
        ptr* += 1

        :type irsb_c: vex_helper.IRSBCustomizer
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        val += 1
        self.store(val, ptr)


class Instruction_DEC(Instruction):
    bin_format = bin(ord("-"))[2:].zfill(8)
    name = 'dec'

    def compute_result(self, *args):
        """
        '-': Increment the data memory value pointed at by the ptr register, or:
        ptr* -= 1
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        val -= 1
        self.store(val, ptr)


class BracketInstruction(Instruction):
    jump_table = {}

    def calculate_jump(self, relevant_instructions):
        bracket_stack = [self]
        if self.addr in self.jump_table:
            return self.jump_table[self.addr]
        for instr in relevant_instructions:
            if isinstance(instr, self.__class__):
                bracket_stack.append(instr)
            elif isinstance(instr, self.closing):
                bracket_stack.pop()
                if len(bracket_stack) == 0:
                    self.jump_table[self.addr] = instr.addr + 1
                    self.jump_table[instr.addr] = self.addr + 1
                    return instr.addr + 1
        if len(bracket_stack) > 0:
            return None

    # find the matching closing tag
    def _build_jump_table(self, state, addr):
        jump_stack = []
        while True:
            try:
                inst = chr(state.mem_concrete(addr, 1))
            except SimValueError:
                break
            except KeyError:
                break
            if inst == '[':
                jump_stack.append(addr)
            elif inst == ']':
                try:
                    src = jump_stack.pop()
                    dest = addr
                    self.jump_table.update({src: dest + 1})
                    self.jump_table.update({dest: src + 1})
                except IndexError:
                    raise ValueError("Extra ] at offset %d" % addr)
            addr += 1
        if jump_stack:
            raise ValueError("Unmatched [s at: " + ",".join(jump_stack))
        return True

    def resolve_jump(self, state, bv_addr):
        addr = bv_addr.args[0]
        if not hasattr(state.scratch, 'jump_table_is_built'):
            state.scratch.jump_table_is_built = self._build_jump_table(state, addr)
        try:
            return self.jump_table[addr]
        except KeyError:
            raise ValueError("There is no entry in the jump table at address %d" % addr)

class Instruction_SKZ(BracketInstruction):
    bin_format = bin(ord("["))[2:].zfill(8)
    name = 'skz'

    def lift(self, irsb_c, past_instructions, future_instructions):
        self.jump_addr = self.calculate_jump(future_instructions)
        BracketInstruction.lift(self, irsb_c, past_instructions, future_instructions)

    def compute_result(self, *args):
        """
        '[': Skip to the matching ], IF the value pointed at by the ptr register is zero.
        The matching ] is defined by pairs of matched braces, not necessarily the next ].

        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        # NOTE: VEX doesn't support non-constant values for conditional exits.
        # What we do to avoid this is to make the default exit of this block the conditional one,
        # and make the other take us to the next instruction.  Therefore, we invert the comparison.
        # Go to the next instruction if *ptr != 0
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(val == 0, next_instr)
        # And go to the next ] if *ptr == 0
        if self.jump_addr:
            self.jump(None, self.jump_addr)
        else:
            jump_addr = self.ccall(PTR_TYPE,
                    self.resolve_jump, [self.constant(self.addr, PTR_TYPE)])
            self.jump(None, jump_addr)


class Instruction_SKNZ(BracketInstruction):
    bin_format = bin(ord("]"))[2:].zfill(8)
    name = 'sknz'

    def lift(self, irsb_c, past_instructions, future_instructions): # TODO make sure matching brackets has same jump target
        self.jump_addr = self.calculate_jump(past_instructions)
        BracketInstruction.lift(self, irsb_c, past_instructions, future_instructions)

    def compute_result(self, *args):
        """
        ']': Skip to the matching [ backward if the value pointed at by the ptr register is not zero.
        Similar to the above, see that for important notes.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(val != 0, next_instr)
        if self.jump_addr:
            self.jump(None, self.jump_addr) # TODO will this break when stuff is split across blocks?
        else:
            raise Exception('Missing matching %s for %s at address %d' % (self.closing.name, self.name, self.addr))

Instruction_SKZ.closing = Instruction_SKNZ
Instruction_SKNZ.closing = Instruction_SKZ


class Instruction_IN(Instruction):
    bin_format = bin(ord(","))[2:].zfill(8)
    name = 'in'

    def compute_result(self, *args):
        """
        ',': Get one byte from standard input.
        We use a "syscall" here, see simos_bf.py for the SimProcedures that get called.
        :return:
        """
        # incrementing the ptr here is a bit of a hack,
        # but it works because the syscall uses ptr-1 as the address to read to
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr += 1
        self.put(ptr, PTR_REG)
        # Having a 0 in the "inout" register tells VEX to kick off simos_bf.WriteByteToPtr()
        self.put(self.constant(0, PTR_TYPE), INOUT_REG)
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)

class Instruction_OUT(Instruction):
    bin_format = bin(ord("."))[2:].zfill(8)
    name = 'out'

    def compute_result(self, *args):
        """
        '.': Get the current value pointed at by the ptr register and print it to stdout
        As above, we use a Syscall / simprocedure to do this
        """
        # incrementing the ptr here is a bit of a hack,
        # but it works because the syscall uses ptr-1 as the address to read from
        ptr = self.get(PTR_REG, PTR_TYPE)
        ptr += 1
        self.put(ptr, PTR_REG)
        # Putting a 1 in "inout", executes simos_bf.ReadValueAtPtr()
        self.put(self.constant(1, PTR_TYPE), INOUT_REG)
        # Go to the next instruction after, but set the Syscall jumpkind
        dst = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, dst, jumpkind=JumpKind.Syscall)


class Instruction_SETCF(Instruction):
    bin_format = bin(ord("&"))[2:].zfill(8)
    name = 'setcf'

    def compute_result(self, *args):
        """
        '&': Set the carry flag
        """
        val = 1
        self.put(self.constant(val, PTR_TYPE), CF_REG)


class Instruction_CLRCF(Instruction):
    bin_format = bin(ord("@"))[2:].zfill(8)
    name = 'clrcf'

    def compute_result(self, *args):
        """
        '@': Clear the carry flag
        """
        val = 0
        self.put(self.constant(val, PTR_TYPE), CF_REG)

class ParanthesesInstruction(Instruction):
    jump_table = {}

    def calculate_jump(self, relevant_instructions):
        bracket_stack = [self]
        if self.addr in self.jump_table:
            return self.jump_table[self.addr]
        for instr in relevant_instructions:
            if isinstance(instr, self.__class__):
                bracket_stack.append(instr)
            elif isinstance(instr, self.closing):
                bracket_stack.pop()
                if len(bracket_stack) == 0:
                    self.jump_table[self.addr] = instr.addr + 1
                    self.jump_table[instr.addr] = self.addr + 1
                    return instr.addr + 1
        if len(bracket_stack) > 0:
            return None

    # find the matching closing tag
    def _build_jump_table(self, state, addr):
        jump_stack = []
        while True:
            try:
                inst = chr(state.mem_concrete(addr, 1))
            except SimValueError:
                break
            except KeyError:
                break
            if inst == '(':
                jump_stack.append(addr)
            elif inst == ')':
                try:
                    src = jump_stack.pop()
                    dest = addr
                    self.jump_table.update({src: dest + 1})
                    self.jump_table.update({dest: src + 1})
                except IndexError:
                    raise ValueError("Extra ) at offset %d" % addr)
            addr += 1
        if jump_stack:
            raise ValueError("Unmatched (s at: " + ",".join(jump_stack))
        return True

    def resolve_jump(self, state, bv_addr):
        addr = bv_addr.args[0]
        if not hasattr(state.scratch, 'jump_table_is_built'):
            state.scratch.jump_table_is_built = self._build_jump_table(state, addr)
        try:
            return self.jump_table[addr]
        except KeyError:
            raise ValueError("There is no entry in the jump table at address %d" % addr)

class Instruction_PSKZ(ParanthesesInstruction):
    bin_format = bin(ord("("))[2:].zfill(8)
    name = 'pskz'

    def lift(self, irsb_c, past_instructions, future_instructions):
        self.jump_addr = self.calculate_jump(future_instructions)
        ParanthesesInstruction.lift(self, irsb_c, past_instructions, future_instructions)

    def compute_result(self, *args):
        """
        '(': Skip to the matching ), IF the value pointed at by the ptr register is zero.
        The matching ) is defined by pairs of matched braces, not necessarily the next ).

        """
        # get the CF flag
        cf_val = self.get(CF_REG, PTR_TYPE)
        # clear the CF flag
        self.put(self.constant(0, PTR_TYPE), CF_REG)

        # NOTE: VEX doesn't support non-constant values for conditional exits.
        # What we do to avoid this is to make the default exit of this block the conditional one,
        # and make the other take us to the next instruction.  Therefore, we invert the comparison.
        # Go to the next instruction if cf != 0
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(cf_val == 1, next_instr)
        # And go to the next ) if cf == 0
        if self.jump_addr:
            self.jump(None, self.jump_addr)
        else:
            jump_addr = self.ccall(PTR_TYPE,
                    self.resolve_jump, [self.constant(self.addr, PTR_TYPE)])
            self.jump(None, jump_addr)


class Instruction_PSKNZ(ParanthesesInstruction):
    bin_format = bin(ord(")"))[2:].zfill(8)
    name = 'psknz'

    def lift(self, irsb_c, past_instructions, future_instructions): # TODO make sure matching brackets has same jump target
        self.jump_addr = self.calculate_jump(past_instructions)
        ParanthesesInstruction.lift(self, irsb_c, past_instructions, future_instructions)

    def compute_result(self, *args):
        """
        ')': Skip to the matching ( backward if the value pointed at by the ptr register is not zero.
        Similar to the above, see that for important notes.
        """
        next_instr = self.constant(self.addr + 1, PTR_TYPE)
        self.jump(None, next_instr)
        if self.jump_addr:
            self.jump(None, self.jump_addr) # TODO will this break when stuff is split across blocks?
        else:
            raise Exception('Missing matching %s for %s at address %d' % (self.closing.name, self.name, self.addr))

Instruction_PSKZ.closing = Instruction_PSKNZ
Instruction_PSKNZ.closing = Instruction_PSKZ

class Instruction_PUSH(Instruction):
    bin_format = bin(ord("v"))[2:].zfill(8)
    name = 'push'

    def compute_result(self, *args):
        """
        'v': Push the value pointed at by the ptr register onto the stack.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        val = self.load(ptr, CELL_TYPE)
        sp = self.get(SP_REG, PTR_TYPE)

        self.store(val, sp)
        sp +=1
        self.put(sp, SP_REG)

class Instruction_POP(Instruction):
    bin_format = bin(ord('^'))[2:].zfill(8)
    name = 'pop'

    def compute_result(self, *args):
        """
        '^': Pop the top of the stack into the cell at the ptr register.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        sp = self.get(SP_REG, PTR_TYPE)
        z = self.constant(SP_START, PTR_TYPE)
        # NOTE: VEX doesn't support non-constant values for conditional exits.
        # What we do to avoid this is to make the default exit of this block the conditional one,
        # and make the other take us to the next instruction.  Therefore, we invert the comparison.
        # Go to the next instruction if cf != 0
        sp -= 1
        val = self.load(sp, CELL_TYPE)
        self.store(val, ptr)
        self.put_conditional(sp == z, z+1, sp, SP_REG)

class Instruction_POP_ADD(Instruction):
    bin_format = bin(ord('#'))[2:].zfill(8)
    name = 'pop_add'

    def compute_result(self, *args):
        """
        '#': Pop the top of the stack and adds it to cell at the ptr register.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        sp = self.get(SP_REG, PTR_TYPE)
        z = self.constant(SP_START, PTR_TYPE)

        sp -= 1
        stack_val = self.load(sp, CELL_TYPE)
        cell_val = self.load(ptr, CELL_TYPE)
        self.store(cell_val + stack_val, ptr)
        self.put(sp, SP_REG)
        self.put_conditional(sp == z, z+1, sp, SP_REG)

class Instruction_POP_SUB(Instruction):
    bin_format = bin(ord('|'))[2:].zfill(8)
    name = 'pop_sub'

    def compute_result(self, *args):
        """
        '|': Pop the top of the stack and substracts it from cell at the ptr register.
        """
        ptr = self.get(PTR_REG, PTR_TYPE)
        sp = self.get(SP_REG, PTR_TYPE)
        z = self.constant(SP_START, PTR_TYPE)

        sp -= 1
        stack_val = self.load(sp, CELL_TYPE)
        cell_val = self.load(ptr, CELL_TYPE)
        self.store(cell_val - stack_val, ptr)
        self.put(sp, SP_REG)
        self.put_conditional(sp == z, z+1, sp, SP_REG)

# The instrs are in this order so we try NOP last.
all_instrs = [
    Instruction_INCPTR,
    Instruction_DECPTR,
    Instruction_INC,
    Instruction_DEC,
    Instruction_SKZ,
    Instruction_SKNZ,
    Instruction_IN,
    Instruction_OUT,
    Instruction_SETCF,
    Instruction_CLRCF,
    Instruction_PSKZ,
    Instruction_PSKNZ,
    Instruction_PUSH,
    Instruction_POP,
    Instruction_POP_ADD,
    Instruction_POP_SUB,
    Instruction_NOP
]


class LifterMBF(GymratLifter):
    instrs = all_instrs

# Tell PyVEX that this lifter exists.
register(LifterMBF, 'MBF')

if __name__ == '__main__':
    log.setLevel('DEBUG')
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import logging
    logging.getLogger('pyvex').setLevel(logging.DEBUG)
    logging.basicConfig()

    test1 = b'v^|#'
    test2 = b'++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>v>---v+++++++vv+++v>>v<-v<v+++v------v--------v>>+v>++v^.^.^.^.^.^.^.^.^.^.++'
    lifter = LifterMBF(archinfo.arch_from_id('mbf'), 0)
    lifter._lift(data=test1, bytes_offset=1)
    lifter.irsb.pp()
    import IPython; IPython.embed()
    lifter = LifterMBF(arch=ArchMBF(), addr=0)
    lifter._lift(data=test2)
    lifter.irsb.pp()
