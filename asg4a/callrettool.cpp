#include "pin.H"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

/* Undefine these to get some feedback about what your pintool is doing. */
//#define PRINT_BASIC_BLOCKS /* show basic block addresses when instrumenting them */
//#define PRINT_ALL_INSTS /* print each instruction before instrumenting it*/
//#define PRINT_UNHANDLED_INSTS /* print instructions which are not instrumented */

KNOB<std::string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool", "i", "input.txt", "specify input file to be tainted");

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define ROUND_DOWN(N, S) ((N / S) * S)


typedef uint16_t tag_t;

/* Given an address, return the corresponding shadow memory (where we'll store the taint tags). */
inline tag_t *addrToShadow(const void *addr) {
    return (tag_t *)((((uint64_t)(addr)+0x200000000000ull) << 1) & 0x7fffffffffffull);
}

bool is_ins_in_text(unsigned int code_ptr) {
    unsigned int text_start = 0x4022f0;
    unsigned int text_end = 0x040fdcf;
    return (code_ptr >= text_start && code_ptr <= text_end);
}

static void handle_call_reg(unsigned N, uint64_t target, uint64_t ins_ptr, uint32_t ins_len) {
    fprintf(stderr, "call ind reg,0x%lx, to, 0x%lx, next ins, 0x%lx\n", ins_ptr, target, ins_ptr + ins_len);
}

static void handle_call_mem(unsigned N, uint64_t target, uint64_t ins_ptr, uint32_t ins_len) {
    if (is_ins_in_text(target))
        fprintf(stderr, "call ind mem,0x%lx, to, 0x%lx, next ins, 0x%lx\n", ins_ptr, target, ins_ptr + ins_len);
}

static void handle_call_imm(uint64_t target, uint64_t ins_ptr, uint32_t ins_len) {
    fprintf(stderr, "call dir, 0x%lx, to, 0x%lx,next ins, 0x%lx\n", ins_ptr, target, ins_ptr + ins_len);
}

static void handle_ret(const CONTEXT *ctxt, uint64_t ins_ptr) {
    ADDRINT takenIP = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    if (is_ins_in_text(takenIP))
        fprintf(stderr, "ret xxx, 0x%lx, taken, 0x%lx\n", ins_ptr, takenIP);
}

/* PIN calls this while translating an instruction */
void Instrument(INS ins, void *) {
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);

#ifdef PRINT_ALL_INSTS
    printf("instrumenting@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
#endif

    switch (ins_opcode) {
    case XED_ICLASS_CALL_NEAR:
        if (INS_OperandIsReg(ins, 0))
            INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_call_reg,
                IARG_UINT32, INS_OperandWidth(ins, 0) / 8,
                IARG_REG_VALUE, INS_OperandReg(ins, 0),
                IARG_INST_PTR,
                IARG_UINT32, INS_Size(ins),
                IARG_END);
        else if (INS_OperandIsMemory(ins, 0))
            INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)handle_call_mem,
                IARG_UINT32, INS_OperandWidth(ins, 0) / 8,
                IARG_MEMORYREAD_EA,
                IARG_INST_PTR,
                IARG_UINT32, INS_Size(ins),
                IARG_END);
        else {
            // operand is an immediate
            // check if the immediate is a pointer in .text segment
            unsigned int code_ptr = strtoul(&INS_Disassemble(ins).c_str()[5], NULL, 16);
            if (is_ins_in_text(code_ptr))
                INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)handle_call_imm,
                    IARG_UINT32, code_ptr,
                    IARG_INST_PTR,
                    IARG_UINT32, INS_Size(ins),
                    IARG_END);
        }
        break;
    case XED_ICLASS_RET_FAR:
    case XED_ICLASS_RET_NEAR:
        if (is_ins_in_text(INS_Address(ins)))
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                (AFUNPTR)handle_ret,
                IARG_CONTEXT,
                IARG_INST_PTR,
                IARG_END);
        break;
    case XED_ICLASS_MOV:
        // log the mov instructions that overwrites the return address (rbp+8) reachable in this trace
        if (INS_OperandIsMemory(ins, 0) && INS_OperandMemoryBaseReg(ins, 0) == REG_RBP && INS_OperandMemoryDisplacement(ins, 0) == 8)
            fprintf(stderr, "movq rbp, 0x%lx,ins_size, %ld, used, %s \n", INS_Address(ins), INS_Size(ins), INS_Disassemble(ins).c_str());
        break;
        // mov reg, reg
    default:
#ifdef PRINT_UNHANDLED_INSTS
        printf("unhandled @%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
#endif
        break;
    }
}

std::map<int, std::string> g_open_fds;

/* post-event callback for open/openat() system calls (called by syscall_exit) */
void open_hook(const char *filename, int fd) {
    if (fd == -1)
        return;

    /* Keep track of file descriptors, for use in read_hook, below. */
    g_open_fds[fd] = std::string(filename);
}

/* post-event callback for read() system call (called by syscall_exit) */
void read_hook(int fd, char *buf, size_t count) {
    if (count == (size_t)-1)
        return;

    /* Only taint the file we're interested in. */
    if (g_open_fds[fd] != KnobInputFile.Value())
        return;

    size_t pos = lseek(fd, 0, SEEK_CUR) - count; /* [current pos] - [bytes read] = start pos */
    for (uint n = 0; n < count; ++n) {
        /*
         * This is where we taint the input. Specifically, for file offset n,
         * we set the shadow memory for the buffer to tag (color) n+1.
         */
        *(addrToShadow(buf + n)) = pos + n + 1;
    }
}

/*
 * Some context which we store in syscall_entry, because we need it in syscall_exit.
 * (!) To support threads, you'd have to store this in thread local storage (see PIN's TLS helper functions).
 */
static uint64_t g_last_syscall;
static uint64_t g_last_context[4];

/* PIN calls this just before a system call */
void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    g_last_syscall = PIN_GetSyscallNumber(ctx, std);
    for (unsigned n = 0; n < 4; ++n)
        g_last_context[n] = PIN_GetSyscallArgument(ctx, std, n);
}

/* PIN calls this just after a system call */
void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    uint64_t ret = PIN_GetSyscallReturn(ctx, std);
    switch (g_last_syscall) {
    case SYS_open:
        open_hook((char *)g_last_context[0], ret);
        break;
    case SYS_openat:
        open_hook((char *)g_last_context[1], ret);
        break;
    case SYS_read:
        read_hook(g_last_context[0], (char *)g_last_context[1], ret);
        break;
    default:
        break;
    }
}

void Trace(TRACE trace, void *) {
    /* Iterate through the basic blocks which PIN wants to instrument right now. */
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        /*
         * The system libraries use many more instructions than the BAMA binary does.
         * We suggest that you exclude libraries from instrumentation (with the code below).
         * and implement tainting by instrumenting the individual library calls instead.
         */
        IMG img = IMG_FindByAddress(BBL_Address(bbl));
        if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
            continue;

#ifdef PRINT_BASIC_BLOCKS
        printf("Instrumenting basic block at %p\n", BBL_Address(bbl));
#endif

        /* Instrument every instruction in this basic block. */
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            Instrument(ins, 0);
        }
    }
}

int main(int argc, char *argv[]) {
    /* This makes PIN handle IFuncs; RTN_FindByName gives us implementations in modern PIN, so we can pretend they don't exist. */
    PIN_InitSymbolsAlt(IFUNC_SYMBOLS);
    if (PIN_Init(argc, argv))
        return 1;

    /* We want to instrument instructions. */
    TRACE_AddInstrumentFunction(Trace, 0);
    /* Let's go! */
    PIN_StartProgram();
}
