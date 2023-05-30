# __Binary and Malware Analysis__
# Challenge 3

* __Malek Kanaan__
* vunet id : __mkn668__
* Hacker Handle: __Krypt0__


# CMP comparisons
The `CMP` instructions are the main target for this analysis. The first step is to find the direct comparisons with tainted values. This can be done by instrumenting the `CMP` instructions with handlers for the different types of operands namely:
```
CMP <mem>   $const
CMP <mem>   %reg
CMP %reg    <mem>
CMP %reg    %reg
CMP %reg    $const
```

If the comparison involves a tainted value, the tool logs the comparison. If no obfuscation is there (by washing taint on arithmetic operations) the value is then found. When processed, this recovers a paragraph with some random letters dotted around.

# Library Functions Comparisons
Looking at the `ltrace` output of the `rabbit`, we can see multiple `libc` functions being called. Using ghidra, we can further see the list of library functions from `libc` and other libraries. The relevant functions are hooked with calls to propagate taints when modifying memory addresses, and to log the comparisons with tainted values.
Here is a list of the instrumenting performed on these functions:

* `memset`: Instrumented to propagate taint from the constant argument in `RSI`; if taint is present to the memory locations touched by the function. And washes it if `RSI` is not tainted.
* `memcpy`: Instrumented to propagate the taint from the source to the destination bytes.
* `strncpy`: Similar to `memcpy` instrumentation behavior to propagate taint to destination string bytes.
* `memcmp`, `strncmp` and `strcmp` : Instrumented to log the comparisons with tainted values.
When running with this instrumentation, more text is retrieved from the secret.

# Arithmetic && Obfuscated Operations
Up to this stage the arithmetic operations were clearing taint. However, this will leave a good part of the secret hidden. At the 3rd stage, we remove the taint clearing code. This will show some more characters but a non readable (non ascii) paragraph shows up after the run. This clearly the artifact of the obfuscation that is happening before some of the comparisons.


Therefore, this work instruments arithmetic operations such that taint is not cleared and tainted values and their operands are logged. The tool logs `ADD`, `SUB`, `SBB`, `SHL`, `SHR`, `ROR`, `XOR`, `AND` and `OR` operations, tainted values and operands. The idea is to back-track starting from the `CMP` operation to undo the obfuscation and compute the correct input value of that byte. Callback handlers are added for all operand types to these operations:
```
arith_op %reg   %reg
arith_op %reg   <mem>
arith_op %reg   $const
arith_op <mem>  %reg
arith_op <mem>  $const
```
This instrumentation showed the text behind the obfuscated paragraph. However, some missing/wrong characters and non-ascii values are still present. So I was not yet done.

# Debugging and Command Line Flags
After all of previous work was implemented, some parts of the secret were still unrecoverable. Something did not make sense. A lot of debugging was done to ensure that the log entries were correct I looked at: operands order, what is the tainted value and what is the other (constant) value, which operand is the destination and to which location does it belong to in the input.
I found some taint propagation bugs, and some entry log had values in wrong positions etc. Further text was recovered but not all. This leaves one thing, A command-line flag that was hinted in the introduction to this task.
Looking at the `ltrace` output we see one interesting call:'
```
getopt_long(3, 0x7ffd430b7058, "hi:fwopx:t:", 0x44d400, 0)
```
This call parses the command line arguments. Its third argument is the options string `"hi:fwopx:t:"`. After looking in ghidra and trying multiple flags, it turns out that the `-f --fortune` flag shows the rest of the secret text and provides the full coverage. Other flags either work by chance(`-p --prob`), requires an unknown arguments(`-x -t`) or does not work. One last issue was that the taint color is referring to the `location + 1 ` of a byte from the input. This was accounted for in the python script that processes the log.

# Processing of the log
The processing of the log to produce the secret uses a python script. The script reads the log lines and compute the values of the secret. Relevant arithmetic operations' information are added to a dictionary grouped by the location of the byte. The key to this list is the the tainted byte location (`color`) logged by the tool. When a comparison line is encountered, the script queries the dictionary and backtracks any arithmetic operations done on that byte before the comparison. This computes an adequate input character to pass the comparison. Else, when no arithmetic operations are found, the comparison value is considered adequate. The computed values are placed in the correct location in the input file. Finally, the bytes of the input file are written to a file named `input.txt` in the `text` directory where we can read the secret (or any part recovered at a stage).

# Files Included
* `rabbit` : the binary analyzed (as provided in the assignment).
* `makefile`, `makefile.rules`: required to compile the tool (as provided with the assignment)
* `tainttool.cpp`: the source code for the tool to perform the analysis.
* `assemble_identity.py`: processes the log in `./text/log.txt` and produce the secret in `./text/input.txt`.
* `secret.txt`: this is the recovered secret named as mandated by the course staff.
* `run_me.sh`: compiles the tool, run the analysis with PIN, run the python script to process the log and then runs the rabbit with the secret.txt.

# Running the Analysis
Simply run the `run_me.sh` and the secret should be produced in the file `./text/input.txt`. Make sure that the executables have the correct permissions.
