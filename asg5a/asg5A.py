
WORD_SIZE = 0x10
WORD_IR_SIZE = 0x50
MEANING_IR_SIZE = 0x38
LEGAL_CHARS = "@A1C2E4H5K6M7P8R9UVWXYZ*~^&/:,;-"
DECODE_CHARS = "0123456789abcdef"

input_test = '@W,&@^WUPX@MW696'
meaning_IR_test = b'\x01\x01\x01\x01\x00\x01\x00\x01\x01\x00\x01\x00\x00\x01\x00\x00\x00\x01\x01\x01\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x01\x00\x00\x01\x00\x00\x00'

def word_encoder(input):
    input_ptr = input[0]
    TMP_IR_PTR = bytearray(WORD_IR_SIZE)
    off = 0
    if len(input) > 0x10:
        return -1
    for i, letter in enumerate (input):
        idx = LEGAL_CHARS.find(letter)
        if idx == -1:
            return -1
        # input_ptr = input_ptr + 1
        TMP_IR_PTR[off + 4] = idx
        TMP_IR_PTR[off + 3] = (idx >> 1)
        TMP_IR_PTR[off + 0] = (idx >> 4)
        TMP_IR_PTR[off + 3] = TMP_IR_PTR[off + 3] & 1
        TMP_IR_PTR[off + 1] = (idx >> 3)
        TMP_IR_PTR[off + 1] = TMP_IR_PTR[off + 1] & 1
        TMP_IR_PTR[off + 2] = (idx >> 2)
        TMP_IR_PTR[off + 4] = TMP_IR_PTR[off + 4] & 1
        TMP_IR_PTR[off + 2] = TMP_IR_PTR[off + 2] & 1
        off = off + 5

    return TMP_IR_PTR

def word_decoder(input):
    word = bytearray(WORD_SIZE)
    i = 0
    j = 0
    tmp = 0
    try:
    # map each 5 byte in the input to one byte in the word
        while (i < len(input)):
            if (input[i + 0] != 0x00):
                tmp = tmp | 0x10
            if (input[i + 1] != 0x00):
                tmp = tmp | 8
            if (input[i + 2] != 0x00):
                tmp = tmp | 4
            if (input[i + 3] != 0x00):
                tmp = tmp | 2
            if (input[i + 4] != 0x00):
                tmp = tmp | 1
            word[j] = ord(LEGAL_CHARS[tmp])
            i = i + 5
            j = j + 1
            # add the char from the legal chars to the word
            tmp = 0
    except:
        print("Error", tmp)
        print(input[i], input[i+1], input[i+2], input[i+3], input[i+4])
        exit()
    return word.decode('ascii')

def meaning_decoder(input):
    i = 0
    j = 0
    output = ['A'] * 14 # bytearray(0x38)
    while (True):
        tmp = ~-(input[i] == 0x00) & 0xffffff80
        if (input[i + 1] != 0x00):
            tmp = tmp | 0x40
        if (input[i + 2] != 0x00):
            tmp = tmp | 0x20
        if (input[i + 3] != 0x00):
            tmp = tmp | 0x10
        if (input[i + 4] != 0x00):
            tmp = tmp | 8
        if (input[i + 5] != 0x00):
            tmp = tmp | 4
        if (input[i + 6] != 0x00):
            tmp = tmp | 2
        if (input[i + 7] != 0x00):
            tmp = tmp | 1

        i = i + 8
        output[j]   = DECODE_CHARS[tmp >> 4 & 0xf]
        output[j+1] = DECODE_CHARS[tmp & 0xf]
        j = j + 2
        if (i == MEANING_IR_SIZE):
            break
    return ''.join(output)

def check_meaning_word(m, w):
    import subprocess
    proc = subprocess.Popen(['./oracle', w], stdout=subprocess.PIPE)
    out, err = proc.communicate()
    out = out.decode('utf-8')
    if m in out:
        return True
    return False

import angr
import claripy

CHECK_WORD_FIND = 0x04013fe
CHECK_WORD_AVOID = 0x4013b6

CHECK_WORD_ADDR = 0x04013f0
GET_MEANING_ADDR = 0x401407
WORD_IR_ADDR = 0x42424200
MEANING_IR_ADDR = 0x42425000

MEANING_FIND = 0x40140c
MEANING_AVOID = 0x40140f

def get_word_check_state():
    p = angr.Project('./oracle')

    state_check = p.factory.call_state(CHECK_WORD_ADDR)

    # capture the SMT of the checking function
    word_BVS = claripy.BVS('word_ir', WORD_IR_SIZE * 8)
    state_check.memory.store(WORD_IR_ADDR, word_BVS)

    state_check.regs.rdi = WORD_IR_ADDR
    state_check.regs.rsi = 0x5f

    # bytes are either 0x00 or 0x01
    for b in word_BVS.chop(8):
        state_check.solver.add(b < b'\x02')
        state_check.solver.add(b >= b'\x00')

    sm = p.factory.simulation_manager(state_check)
    sm.use_technique(angr.exploration_techniques.veritesting.Veritesting())
    sm.explore(find=CHECK_WORD_FIND, avoid=CHECK_WORD_AVOID)

    return sm.found[0]

def get_meanings(found_check):
    p = angr.Project('./oracle')
    # using the ir obtained from the check function
    word_SMT = found_check.memory.load(WORD_IR_ADDR, WORD_IR_SIZE)
    meaning_BVS = claripy.BVS('meaning_ir', MEANING_IR_SIZE * 8)

    # get the get meaning function
    state = p.factory.call_state(GET_MEANING_ADDR)

    # adding constraint to the new call state
    for m in found_check.solver.constraints:
        state.solver.add(m)

    state.memory.store(addr=WORD_IR_ADDR, data=word_SMT)
    state.memory.store(addr=MEANING_IR_ADDR, data=meaning_BVS)

    state.regs.rdi = MEANING_IR_ADDR # meaning ir address
    state.regs.rsi = WORD_IR_ADDR # word ir address

    # capture the SMT of the meaning mapping function
    sm = p.factory.simulation_manager(state)
    sm.use_technique(angr.exploration_techniques.veritesting.Veritesting())
    sm.explore(find=MEANING_FIND, avoid=MEANING_AVOID)

    meaning_state = sm.found[0]

    meaning_SMT = meaning_state.memory.load(MEANING_IR_ADDR, MEANING_IR_SIZE)
    meanings_ir = meaning_state.solver.eval_upto(meaning_SMT, n=1000,cast_to=bytes)
    print(f'Found {len(meanings_ir)} meanings!')
    print('Getting a word for each meaning...')
    res = []
    for meaning in meanings_ir:
        try:
            # copy state else we get unsatisfiable stuff
            tmp_found = meaning_state.copy()
            # add the constraint so we can get the word of a meaning
            tmp_found.solver.add(meaning_SMT == meaning)
            wb = tmp_found.solver.eval(tmp_found.memory.load(WORD_IR_ADDR, WORD_IR_SIZE), cast_to=bytes)

            m = meaning_decoder(meaning)
            w = word_decoder(wb)
            res.append((m, w))
        except Exception as ex:
            print(f'Exception occurred {type(ex).__name__}')

    # import IPython; IPython.embed()
    return res


def main():

    print('capturing algorithm determining if a word has meaning...')
    check_state = get_word_check_state()
    print('capturing algorithm determining meanings of a word...')
    res = get_meanings(check_state)
    print('Writing results to meanings.out...')
    # write the results to a file meanings.out
    # if the file is there rename it
    import os
    if os.path.isfile('meanings.out'):
        os.rename('meanings.out', 'meanings.out.old')
    with open('meanings.out', 'w') as f:
        for m, w in res:
            f.write(f'{m} {w}\n')


    print('Done!')
if __name__ == '__main__':
    main()
