# __Binary and Malware Analysis__
# Challenge 4A

* __Malek Kanaan__
* vunet id : __mkn668__
* Hacker Handle: __Krypt0__

# Task 1: Dynamic Deobfuscation
## Call Instructions:
To figure out where the indirect calls are leading, I wrote a PIN tool that logs any `call %REG` instruction with the value in the register. Initially, many irrelevant calls were logged. For example, calls to external library functions can not be patched to be static. Further, some of these calls also target the `plt` section to resolve external calls, etc. So to log only relevant calls, the tool only logs indirect calls that target code in the text section. This method produced fewer `call` log-line in the log than `ret` lines. Turns out the binary has many indirect call instructions from the form `call [memory]`. The tool logs direct call instructions as well. By logging relevant calls as done before we match the number of calls and returns in the log.
Finally, for all of these `call` log-lines, the normal return address (next instruction after the call) is also logged to be used to patch misleading code involved with changing and misleading the used return address.


## Return Addresses:
### 1. Return target
To determine if the return address was not patched by the callee, the PIN tool instruments the `ret` instructions on `IPOINT_TAKEN_BRANCH` so that we can see where the callee is returning to at runtime. The actual value is retrieved from the context object by reading the instruction pointer register for that `ret`.

### 2. Mov instruction that manipulate the return address
To find out where the return address is manipulated, we instrument the instructions from the form `MOV [%RBP + 8], %REG`. Which overwrites the original return address value. This instruction is proceeded by 2 instructions, one loads the return address to a register and the second adds a constant to it. This helps us `NOP` this instruction code as it is misleading/unnecessary.

## Processing of the log and patching
The log is the output of the PIN tool when running the `rabbit` with the secret obtained with the dynamic taint analysis done in the previous assignment.
A provided python script processes the log and patches the binary with the deduced information.
### Patching Indirect Calls
From the log, we can read the indirect calls performed by `rabbit`. I noticed that the indirect call instruction is 2 bytes long. While a direct call instruction is 5 bytes. However, by inspecting the binary, I saw that these calls are usually proceeded with an `add` instruction that adds a constant to the same register used by the call. Hence, the patch script uses this to fit a new call and `NOP`s what is left to ensure correctness. Further, only calls that always use the same functions are patched. Further, these were the calls with a removable `ADD` instruction before them anyway.

### Removing Irrelevant Code
The python script also takes care of removing irrelevant code. This happens in 2 parts.
* First: log-lines that includes a return address overwrite (`MOV [%RBP + 8], %REG`) are used to `NOP` out code that modifies the return address including the read and add instructions. Hence, the return address is left untouched. However, the code in the return address must also by `NOP`ped or we crash. So:
* Second: When a return log-line is encountered, the script matches it with its caller (a simple pop from a callers stack) and checks whether the return address logged by the return equals the address of the next instruction after the call. If there is a mismatch, the bytes between last byte of the call instruction and the logged return address are `NOP`ped.

These 2 parts ensure that useless calculation of are not performed, the return address is not-modified and that a `NOP` sled follows every call to ensure correctness. Hence, unused and misleading code is removed.

# Task 2: Static Patching
## Indirect Call Patching
Patching the indirect calls is straight forward. Determine the call target from previous calculations and patch. Looking in ghidra, I identified a certain pattern before every indirect call. 2 constants are put in 2 registers. Then a calculation is performed on them using a loop. For example see`0x40253a`. later and right before the call, a (negative) constant is added to the result of previous calculation, see `0x402565`. So we construct a working set of the addresses of the start of the pattern such as `0x40253a`. We loop until we find the `ADD` and the `CALL %reg` instruction after it. We get the constant from the add instruction and calculate the jump using the loop that is de-compiled in ghidra. For example the loop at `0x402546`:
```
uVar4 = 0xbfb9c9a5;
uVar5 = 0x2b495d78;
do {
    uVar3 = uVar4;
    uVar4 = uVar5 - uVar3;
    uVar5 = uVar3;
} while (uVar4 != 0);
```
A new call instruction with the calculated jump is inserted over the `ADD` instruction like in the dynamic patch. Further, the jmp calculation logic is also replaced with `NOP`s because it is useless.

## Return Path Patch
If we follow a similar approach we can find where the return address gets modified using the pattern `MOV [%RBP + 8], %REG`. However, even if we identified a place where the return address is modified, determining the (original) return address of a function is hard. Because we need to know who the caller was to decide the correct return address. Hence, the program will not work when the return address calculation is removed.

### Two approaches were taken:
We start from the `entry` function to decide the address of `main`. Then we iterate recursively on direct calls and check for the patching instruction. The approach is implemented in `static_patch_recs.py`. Which first performs the static indirect call patching then tries to recursively walk the program. This approach although seems promising, did not get that deep in the program and only one return patch is found.

The second approach is more involving however also straightforward. The script in `static_patch.py` first scans the text for any suspected direct `CALL` instruction. This is simply by matching any byte with `0xe8`. Then all suspected calls are checked for validity by disassembling them and checking whether the target is in the text of the binary. If so, then the first instruction of the target is disassembled and checked whether it is a `ENDBR64` instruction which is in the beginning of every function in `rabbit`.
For every valid call, the script disassemble the target function and looks for any return address modification. From here we have all the info we need to patch. The caller next instruction is trivial, the return displacement, and the areas to be `NOP`ed. Namely, return address modifications and misleading bytes after a call.

# Notes and Observations
The dynamic analysis approach involved only code on one path. Specifically the path with correct flag and secret, while other indirect calls and return stuff are not reached. Hence, the static analysis finds more indirect calls and return address modifications.

# Files Included
* `rabbit` : the binary analyzed (as provided in the assignment).
* `makefile`, `makefile.rules`: required to compile the tool (as provided with the assignment)
* `callrettool.cpp`: the source code for the tool to perform the analysis and produce the log.
* `dynamic_patch.py`: processes the log in `./text/log.txt`, patches the binary and produce the patched rabbit in `rabbit_dynamic_patch`.
* `static_patch.py`: performs the patches statically on `rabbit` and produces the patched version in `rabbit_static_patch`.
* `static_patch_recs.py`: an implementation of a recursive return fix approach(for demonstration purposes).
* `secret.txt`: this is the secret found in assignment 3.
* `run_me.sh`: compiles the tool, run the analysis with PIN, run the python script to do the dynamic patch using the log and then runs the static patching script.

# Running the Analysis
Simply run the `run_me.sh` and the patched binaries should appear in the same directory. Make sure that the executables have the correct permissions.

# Libraries used
* Capstone
* pyelftools

>  `pip3 install capstone pyelftools`
