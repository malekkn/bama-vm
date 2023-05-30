import ghidra.program.model.block.SimpleBlockModel as sbm


OTHER = 0
WASHER = 1
START = 0x0416520
ADDR_OFFSET = 0x8
FIRST_OFFSET = 0x20


def getFunc(address):
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionAt(toAddr(address))
    if f is None:
        # print("No function at address: " + hex(address) + " creating one now")
        f = createFunction(toAddr(address), "FUN_" + hex(address)[2:-1])

    return f

def getFuncsBasicBlocks(current_addr, addr_arr_end):
    funcs = []

    while current_addr < addr_arr_end:
        address = memory.getLong(toAddr(current_addr))
        f = getFunc(address)

        cbs = bbm.getCodeBlocksContaining(f.getBody(), monitor)

        blocks_list = []
        while cbs.hasNext():
            blocks_list.append(cbs.next())
        funcs.append(blocks_list)
        current_addr = current_addr + ADDR_OFFSET
    return funcs

def analyzeFunc(f):
    '''analyze the function and return a dictionary with the following keys:
    entry: the entry code block
    blocks: a list of all code blocks in the function
    graph: a dictionary of code blocks with their successors'''

    f_dict = {}
    edges = 0
    for cb in f:
        edges = edges + cb.getNumSources(monitor)
        edges = edges + cb.getNumDestinations(monitor)

        # get destinations of block
        l = []
        ds = cb.getDestinations(monitor)
        while ds.hasNext():
            l.append(ds.next().getDestinationAddress())

        f_dict[cb.getFirstStartAddress()] = l
    edges = edges / 2

    return {
        "name": f[0].getName(),
        "entry": f[0].getFirstStartAddress(),
        "blocks": len(f),
        "edges": edges,
        "graph": f_dict,
    }

def classifyNodeCount(analysedFunc):
    '''classification of functions based on the number of nodes in the graph'''
    if analysedFunc["blocks"] == 10:
        return "WASHER"
    else:
        return "OTHER"

def classifyEdgesPattern(analysedFunc):
    '''classification of a function based on a pattern in the graph edges'''
    # count code blocks with self-loops
    g = analysedFunc["graph"]
    cb_with_loop = []
    for cb in g.keys():
        for edge in g[cb]:
            if cb == edge:
                cb_with_loop.append(cb)

    if len(cb_with_loop) == 1:
        cb = cb_with_loop.pop()
         # remove self-loop
        tmp = g[cb]
        tmp.remove(cb)
        dst = tmp.pop()
        # need to see if the self-loop is one hop from the exit code block with only single edges between them
        # self-loop --> hop --> ret
        if len(g[dst]) == 1 and len(g[g[dst][0]]) == 0:
                return "WASHER"
    return "OTHER"

# you can choose which helper functions you want to use here
def classifyFunc(analysedFunc):
    # return classifyNodeCount(analysedFunc)
    return classifyEdgesPattern(analysedFunc)

def getClassesStr(funcs):
    output = ""
    for f in funcs:
        res = analyzeFunc(f)
        entry = res["entry"].getAddressableWordOffset()
        cls = classifyFunc(res)
        output = output + str(entry) + "\n" + cls + "\n"
    return output




# First get the functions addresses
bbm = sbm(currentProgram)
memory = currentProgram.getMemory()

addr_arr_end = memory.getLong(toAddr(START + ADDR_OFFSET))
current_addr = START + FIRST_OFFSET

# Then get the functions basic blocks for analysis
funcs = getFuncsBasicBlocks(current_addr, addr_arr_end)

# Then analyze the functions and classify them
output = getClassesStr(funcs)



# write output to file
print("\n>> Printing Control Flow Graph classification results to file")
with open("./text/classes.txt", "w") as f:
    f.write(output)
print("done <<\n")
