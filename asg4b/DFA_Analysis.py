
import ghidra.program.model.block.SimpleBlockModel as sbm


OTHER = 0
WASHER = 1
START = 0x0416520
ADDR_OFFSET = 0x8
FIRST_OFFSET = 0x20


def getFunc(address):
    # fm = currentProgram.getFunctionManager()
    f = getFunctionAt(toAddr(address))
    if f is None:
        f = createFunction(toAddr(address), 'FUN_' + hex(address)[2:-1])
    return f

arith = ['ADD', 'SUB', 'XOR', 'OR', 'SHL', 'SHR']
def classifyFunc(analysedFunc):
    '''classify function based on a static form of tain analysis'''

    regs_t = {}
    stack = []
    entry = analysedFunc[0]
    maxAddress = analysedFunc[1]

    ins = getInstructionAt(entry) # TEST RDI, RDI

    op_0 = ins.getDefaultOperandRepresentation(0)

    regs_t[op_0] = True
    regs_t[u'RAX'] = False

    while ins.getAddress() < maxAddress:
        ins = ins.getNext()
        op_0 = ins.getDefaultOperandRepresentation(0)
        op_1 = ins.getDefaultOperandRepresentation(1)

        if ins.getMnemonicString() == 'MOV' or ins.getMnemonicString() in arith:
            if op_1 in regs_t.keys():
                regs_t[op_0] = regs_t[op_1]
            elif ins.getMnemonicString() == 'MOV' and op_1.isdigit(): # only clear tag if MOV %REG, imm
                regs_t[op_0] = False
        elif ins.getMnemonicString() == 'PUSH':
            if op_0 in regs_t.keys():
                stack.append(regs_t[op_0])
            else:
                regs_t[op_0] = False
                stack.append(False)
        elif ins.getMnemonicString() == 'POP':
            regs_t[op_0] = stack.pop()

    return 'WASHER' if not regs_t[u'RAX'] else 'OTHER'


def getFuncsRanges(current_addr, addr_arr_end):
    funcs = []

    while current_addr < addr_arr_end:
        address = memory.getLong(toAddr(current_addr))
        f = getFunc(address)

        body = f.getBody()
        funcs.append([body.getMinAddress(), body.getMaxAddress()])

        current_addr = current_addr + ADDR_OFFSET
    return funcs

def getClassesStr(funcs):
    output = ''
    for f in funcs:
        entry = f[0].getAddressableWordOffset()
        cls = classifyFunc(f)
        output = output + str(entry) + '\n' + cls + '\n'
    return output





# First get the functions addresses
bbm = sbm(currentProgram)
memory = currentProgram.getMemory()

addr_arr_end = memory.getLong(toAddr(START + ADDR_OFFSET))
current_addr = START + FIRST_OFFSET

# Then get the functions ranges
funcs = getFuncsRanges(current_addr, addr_arr_end)

# Then Classify the functions
output = getClassesStr(funcs)


# Finally write output to file
print('\n>> Printing Data Flow classification results to file')
with open('./text/classes.txt', 'w') as f:
    f.write(output)
print('done <<\n')

