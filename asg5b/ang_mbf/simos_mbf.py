from angr.simos import SimUserland, register_simos
from angr.procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from angr.procedures.definitions import SimSyscallLibrary
from angr import SimProcedure
from angr.calling_conventions import SimCC, register_syscall_cc, register_default_cc, SimCCUnknown, SimRegArg
from .arch_mbf import ArchMBF


class WriteByteAtPtr(SimProcedure):
    """
    Defines what to do for the "." instruction.
    """
    NUM_ARGS = 0
    num_args = 0
    # pylint:disable=arguments-differ

    def run(self, state):
        # pylint:disable=unused-argument
        self.state.posix.fd[1].write(self.state.regs.ptr-1, 1)
        # self.state.regs.ptr += 1
        return None


class ReadByteToPtr(SimProcedure):
    """
    Defines what to do for the "," instruction
    """
    num_args = 0
    NUM_ARGS = 0
    # pylint:disable=arguments-differ

    def run(self):
        self.state.posix.fd[0].read(self.state.regs.ptr-1, 1)
        # NOTE: The behavior of EOF (this is zero) is undefined!!!
        # self.state.regs.ptr += 1
        return None


P['mbf'] = {}
P['mbf']['write_byte_at_ptr'] = WriteByteAtPtr
P['mbf']['read_byte_to_ptr'] = ReadByteToPtr

syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names('brainfuck')
syscall_lib.add_all_from_dict(P['mbf'])
syscall_lib.add_number_mapping_from_dict('MBF', {0 : 'read_byte_to_ptr',
                                                1 : 'write_byte_at_ptr'})

class SimMBF(SimUserland):
    """
    Defines the "OS" of a BrainFuck program.

    This means:
    -  The memory layout (separate code and data)
    -  The "syscalls" (read stdin and write stdout)

    """

    def __init__(self, project, **kwargs):
        super(SimMBF, self).__init__(project, syscall_library=L['brainfuck'], name="MBF", **kwargs)

    def state_blank(self, data_region_size=0x8000, **kwargs):
        # pylint:disable=arguments-differ
        state = super(SimMBF, self).state_blank(**kwargs)  # pylint:disable=invalid-name
        # PTR starts halfway through memory
        state.regs.ptr = 0x80000000
        state.regs.sp = 0xf0000000
        state.memory.map_region(state.regs.ptr, data_region_size, 3, init_zero=True)
        state.memory.map_region(state.regs.sp, data_region_size, 3, init_zero=True)
        # reserve a place for a zero at the bottom of the stack
        state.regs.sp += 1
        return state

    def state_entry(self, **kwargs):
        state = super(SimMBF, self).state_entry(**kwargs)
        return state


class SimBFSyscall(SimCC):
    """
    This defines our syscall format.
    Obviously this is pretty dumb, for BrainFuck
    This is really just here to make the two simprocedures work.
    """

    # No need to pull the regs out, we always just want ptr straight up.
    # THis is usually a list of string register names.
    ARG_REGS = [ 'ptr' ]
    # We never return anything to registers, but if we did, we'd use a RegArg object here.
    #RETURN_VAL = ""
    ARCH = ArchMBF
    RETURN_ADDR = SimRegArg('ip_at_syscall', 8)

    @staticmethod
    def _match(arch, args, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.inout


register_simos('mbf', SimMBF)
register_syscall_cc('MBF','default',SimBFSyscall)
register_default_cc('MBF',SimCCUnknown)
