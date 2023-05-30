#!/usr/bin/env python3

#  read a file as bytearray
import struct

NOP = 0x90
CALL = b"\xe8"
IMAGE_BASE = 0x400000
special = 0x0405C12


def read_file_bytes(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())


def patch_call(rabbit, addr, target):
    patch_size = 0
    if addr == special:
        return
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


def nop_range(rabbit, idx, size):
    for i in range(size):
        rabbit[idx + i] = NOP


# main function
def main():
    logfile = "./text/log.txt"
    rabbit = read_file_bytes("rabbit")

    # open log file lines
    with open(logfile, "r") as f:
        logdata = f.readlines()

    calls_to_patch = dict()
    calls_stack = []
    irrelevant = []
    for l in logdata:
        l = l.strip().split(",")
        if len(l) < 3:
            continue
        ins = l[0]
        ins_addr = int(l[1], 16)
        target = int(l[3], 16)
        #  path to process calls
        if "call" in ins:
            next_ins = int(l[5].strip(), 16)
            # add to the callers stack for matching with returns
            calls_stack.append(
                {
                    "ins": ins,
                    "ins_addr": ins_addr,
                    "target": target,
                    "next_ins": next_ins,
                }
            )

            # if indirect add to calls patching dictionary
            if "ind" in ins:
                if (ins_addr in calls_to_patch.keys()) and (
                    "targets" in calls_to_patch[ins_addr].keys()
                ):
                    calls_to_patch[ins_addr]["targets"].add(target)
                else:
                    calls_to_patch[ins_addr] = {
                        "targets": set([target]),
                        "next_ins": next_ins,
                    }
        elif "ret" in ins:
            # pop a call and check if the return does not have same target as the call's next ins
            caller = calls_stack.pop()
            if target != caller["next_ins"]:
                # calculate index in the binary to do the patch
                start_sled = caller["next_ins"]
                end_sled = target
                idx = start_sled - IMAGE_BASE
                # if the target of the return is not the same as the call next ins,
                # then the code in between is irrelevant
                nop_range(rabbit, idx, end_sled - start_sled)
        elif "movq" in ins:
            # remove the instructions that read ret address, add some const to it and write it back
            PATTERN_START_OFFSET = 8
            idx = ins_addr - IMAGE_BASE - PATTERN_START_OFFSET
            ins_size = int(l[3])
            nop_range(rabbit, idx, ins_size + PATTERN_START_OFFSET)

    # patch the calls with one unique target
    for ins in calls_to_patch.keys():
        if len(calls_to_patch[ins]["targets"]) == 1:
            patch_call(rabbit, ins, list(calls_to_patch[ins]["targets"]).pop())

    # write to file
    with open("rabbit_dynamic_patch", "wb") as f:
        f.write(rabbit)


# entry point function
if __name__ == "__main__":
    main()
