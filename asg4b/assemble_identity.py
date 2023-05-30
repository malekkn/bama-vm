#!/usr/bin/env python3

TYPE = 0
VAL = 1
LOC = 3
IN_VAL = 5
INS = 7
FILLER = 0x23 # hash symbol

def backtrack_arith(a_list, val):
    # loop backwards over the arith list
    # reverse the list
    a_list.reverse()
    for i in range(len(a_list)):
        operand = a_list[i]['val']

        # undo the instructions
        ins = a_list[i]['ins']
        if ins == 'xor':
            val = val ^  operand
        elif ins == 'add':
            val = val -  operand
        elif ins == 'sub':
            val = val +  operand
        elif ins == 'or':
            val = val |  operand
        elif ins == 'shl':
            val = val >>  operand
        elif ins == 'shr':
            val = val <<  operand

    # discard upper bits
    val = val & 0xFF
    return val

#main function
def main():
    logfile = './text/log.txt'

    tmpdata = bytearray(2000)

    # open log file lines
    with open(logfile, 'r') as f:
        logdata = f.readlines()

    arith = dict()
    for i, l in enumerate(logdata):
        l = l.split(',')

        loc = l[LOC]
        modified = loc in arith.keys()
        byte_loc = int(loc) - 1
        value = int(l[VAL])
        type = l[TYPE]
        in_value = int(l[IN_VAL])
        ins = l[INS]

        if 'arith' in type:
            arith_log = {'val': value, 'in_value': in_value,'ins': ins, 'full': l}
            if modified:
                arith[loc].append(arith_log)
            # only start tracking the arithmetic operations when we see our tainted filler value getting modified
            # this will only look at relevant instructions
            elif in_value == FILLER:
                    arith[loc] = [arith_log]
        else:
            if modified and in_value != FILLER:
                value = backtrack_arith(arith[loc], value)
            tmpdata[byte_loc] = value


    # remove nullbytes from the end of the file
    while tmpdata[-1] == 0:
        tmpdata.pop()

    with open("./text/secret.txt", 'wb') as f:
        f.write(tmpdata)

#entry point function
if __name__ == "__main__":
    main()
