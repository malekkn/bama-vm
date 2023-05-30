# __Binary and Malware Analysis__
# Assignment 1

* __Malek Kanaan__
* vunet id : __mkn668__
* Hacker Handle: __Krypt0__

# Anti-debugging:
Running the binary with `strace` shows that its calls to `ptrace` fail and then the program exists. Hence, It detects debugging and `strace` presence this way.
To patch this, first we take a look at the function at address `0x00100f5c`. Here we see two calls at addresses `0x00100f84` and `0x00100f9d` to a code block that loads `0x65` into `EAX` which corresponds to `ptrace`, then the flow jumps to a `syscall` instruction. The return values of these two calls are used to set a boolean value in `EBX`. That value is used in calculating arguments to the functions at the end. This function (and others that perform other checks) uses this boolean (or int) value when calculating their arguments. Although the internals vary slightly per check function, these functions always perform return address or control flow modifications. Hence, here, the calculated value influences the return address patching procedure (see ` 0x00100fc8  AND EBX, 0x1` and further).
> This pattern of return values that are later used at the end of a function by other calls to patch the return address repeats across the binary in functions that perform checks.

Ghidra shows the calculation like `uVar5 = ~(-iVar1 - iVar2) & 1`. When running in gdb, the value left in `EBX` is 1. I tried to solve this by introducing a `MOV` instruction, but it is longer than the replaced one which is problematic. Hence, we reuse the same instruction but with a negated operand such as `0x00100fc8 AND EBX, 0x0`. After this patch, the program passes this check and continues to the next check.


# Anti-VM / Platform Detection:
When running with the previous patch, the program still exists prematurely. However, the strace shows now that the program tries to read values from multiple system files namely:
```
open("/sys/class/dmi/id/sys_vendor", O_RDONLY) = 3
:
open("/sys/class/dmi/id/board_vendor", O_RDONLY) = 3
:
open("/sys/class/dmi/id/bios_vendor", O_RDONLY) = 3
:
open("/sys/class/dmi/id/chassis_vendor", O_RDONLY) = 3
```
Which looks like a type of a VM or a platform detection attempt. In the function at `0x00100d19` we can see all of this. The program reads those values and compares each of them to a set of predefined values.
While analyzing the program, a certain function (defined at `0x00100310`) was used frequently. It takes a buffer and `xor`'s its bytes with `0x4d` for a certain number.
Another similar one at `0x00100265` does the same but for strings, aka, it stops at a `0x0`.
By following the data labels and using the decryption functions described, many static messages can be deciphered. This revealed a lot regarding the behavior in many places. Further, most of these strings ends with a `0x4d 0x0`, The `0x4d` is the `null` byte of the encrypted message and the `0x0` is the `null` byte of the cipher.
>A simple search query using these 2 bytes shows a bunch of these strings. Decrypting the strings and renaming their labels is very helpful for the analysis in general.

Here (in `0x00100d19`), for example, it checks whether the string returned is equal to VMW, VMWare,  QEMU, Xen, innotek, GS201 HOOLI (google tensor SoC), and APL1W07 (Apple 15 SoC).
Those comparisons are done in two for-loops. Each of which set a flags in a register based on the comparison result. The next snippet shows the mentioned instructions.
```
0x00100dfb 85 c0       TEST   EAX,EAX
0x00100dfd 0f 95 c0    SETNZ  AL
:
0x00100e39 85 c0       TEST   EAX,EAX
0x00100e3b 0f 94 c3    SETZ   BL
```

The two values in `AL` and `BL` are involved in steering the execution down the line. After debugging the program with gdb, it turns out that those two registers must be zero to have progress and not an exit. Therefore, the four instructions shown above are patched to cicomvent this. However trying to negate both instructions between `SETZ` and `SETNZ` fails to work. It even crashes when running with `strace`. Therefor, and after some tries. Turns out a value of zero in EAX in both cases will make the program progress a patch looks like:


```
00100dfb b8 00 00        MOV        EAX,0x0
         00 00

:
00100e39 B8 00 00    MOV        EAX,0x0
         00 00
```

Which then makes the program pass this check and print the following message:

```
Loading...    ****
BINARY BOOTLOAD v4h
ROM OK
SYSTEM CHECKS OK
STAGE 2 INACCESSIBLE: PERMISSION DENIED
```

# Authorization system
This section describes two ways of authorization. One of them uses one static key and the other can have many more keys that satisfy a constraint. The following sections assumes that that the static key is the `Master Alpha Token`, while the variable key is the `Alpha Token` that can be generated for users.

## Master Alpha Token (static)
Looking at the few functions that were left with symbols, we see one called `getenv(char *)` this function returns the value of an environment variable. It is used in two other functions namely at `0x00101019` and `0x00100ade`. The first looks like it only check whether the variable is present. It uses the function at `0x00100310` to decrypt the variable name then it calls `getenv` with it.
The interesting part is that, the expected environnement variable value can be read directly from the check performed. The check is a simple in-line addition of the bool values.

```
iVar5 = (uint)(*pcVar4 != 'W')      + (uint)(pcVar4[1] != 'M')      + (uint)(pcVar4[2] != 'J') +
        (uint)(pcVar4[3] != 'M')    + (uint)(pcVar4[4] != 'N')      + (uint)(pcVar4[5] != 'J') +
        (uint)(pcVar4[6] != 'I')    + (uint)(pcVar4[7] != 'Y')      + (uint)(pcVar4[8] != 'F') +
        (uint)(pcVar4[9] != 'Z')    + (uint)(pcVar4[10] != 'F')     + (uint)(pcVar4[0xb] != 'L') +
        (uint)(pcVar4[0xc] != 'R')  + (uint)(pcVar4[0xd] != 'U')    + (uint)(pcVar4[0xe] != 'H') +
        (uint)(pcVar4[0xf] != 'N')  + (uint)(pcVar4[0x10] != 'M')   + (uint)(pcVar4[0x11] != 'C') +
        (uint)(pcVar4[0x12] != 'D') + (uint)(pcVar4[0x13] != 'Y');
bVar7 = iVar5 == 0;
```

If any of these characters do not match the expected one, the value will be larger than zero and the test at `0x00100c75` will fail. By using the decrypt function or gdb we see that the environment variable is named `ALPHA_TOKEN` and its value is `WMJMNJIYFZFLRUHNMCDY`.When the value of the token matches in the calculation and the sum is zero, a flag `bVar7` is set to 1. This flag is passed to later routines that patch the return address of this function that otherwise will steer it to print the error message and exit.
By running the (patched) binary with the token value in the environment we successfully get to the connector software with what looks like a debug message regarding the number of free intercal bytes:
```
$ env ALPHA_TOKEN=WMJMNJIYFZFLRUHNMCDY ./binary_alpha_launcher.antianalysis
Loading...    *****
BINARY BOOTLOAD v4h
ROM OK
SYSTEM CHECKS OK
STAGE 2 LOADING...
BINARY LAUNCHER -  CLOSED ALPHA
COPYRIGHT © 1999-2022 DEUS EX MACHINA.

1336 INTERCAL BYTES FREE

BINARY LAUNCHER -=# WARNING: CLOSED ALPHA; DO NOT SHARE; PLAYING REQUIRES PASSWORD!
$
```
## The Connector Software
The previous master key also starts the connector software which asks for a password. The master key is a fast way to launch this binary.

## Authorization Alpha Token (Variable)

The same function that checks for the correctness of the token has another interesting snippet of code right after the calculation for the static Alpha Token.

```
iVar3 = 0;
for (; *pcVar4 != '\0'; pcVar4 = pcVar4 + 1) {
    iVar3 = iVar3 + ((int)*pcVar4 ^ 0x1ffU);
}
```

This snippet has a for-loop that accumulates the value of each character in the key `xor`ed with `0x1ff`.  This value is later checked whether is equal to `0x1518` in the functions' arguments at the end. Again, this looks like the return patching pattern. The goal now is to craft a key that produces this value under these constrains. One such key is `BDCA6E894F57`; any permutation of this key also works and many more can be crafted.

When providing a valid token in the `ALPHA_TOKEN` variable, the program reports a warning message regarding the hardware as follows:

```
$ env ALPHA_TOKEN=BDCA6E894F57 ./binary_alpha_launcher.antianalysis
Loading...    ******
BINARY BOOTLOAD v4h
ROM OK
WARNING: BINARY launcher may only run on attested DEUS EX MACHINA™ hardware!
```

When investigating with gdb, the program seems to request a bunch of CPU and hardware info using `CPUID` instruction. This instruction appears in 2 functions, `0x0010131f` and `0x0010095a`. The first does not appear to have any interesting function calls to patch the return address like other functions. However, the latter does exhibit that pattern. The return values are loaded and used in conditions for 2 comparisons after the calls to some functions that do some calculations.

We identify these instructions:
```
0x001009fe 8B 4C 24 18  MOV     ECX,dword ptr [RSP + local_140]
0x00100a02 8D 51 B5     LEA     EDX,[RCX + -0x4b]
0x00100a05 81 FA D4     CMP     EDX,0x2d4
           02 00 00
```
Using gdb we see that those values are responsible for correctly patching the return address. Hence, we patch them in a way that they do not interfere with the overall calculation in the arguments at the end. For the first one, we need a value in `ECX` smaller than `0x4b` for its comparison to pass. Hence, we use xor on ECX to have a `0x0` in there. Further, we omit the CMP instruction as a whole so that its flags are not set. The patch looks like this:
```
        001009fe 31 c9           XOR        ECX,ECX
        00100a00 90              NOP
        00100a01 90              NOP
        00100a02 90              NOP
        00100a03 90              NOP
        00100a04 90              NOP
        00100a05 90              NOP
        00100a06 90              NOP
        00100a07 90              NOP
        00100a08 90              NOP
        00100a09 90              NOP
        00100a0a 90              NOP

```
When we run the patched binary with a generated key we see the following output and then exits:

```
$ env ALPHA_TOKEN=BDCA6E894F57 ./binary_alpha_launcher.antianalysis
Loading...    *******
BINARY BOOTLOAD v4h
ROM OK
WARNING: The master alpha token has been disabled
This invalid boot attempt has been logged, mkn668
```
This behavior hints that the binary does not like to run outside a certain environment unlike when using the master token. We investigate this in the next section.

# Debug code
In `strace` output, a call to `uname` is done amongst the system calls made. From the way the system calls were issued, the search for `0x3f` constant byte that corresponds to `uname` system call `RAX` value. We found some non disassembled bytes at address `00100245` which when disassembled reveal a `uname` syscall pattern.
Using gdb, we break at this point and do `backtrace`. This shows another non disassembled section in Ghidra. When disassembled,  this code block shows some sort of a function starting at `0010179e`. The code starts with a call to a `time` function. The value must be between `0x370013ff = 922751999` and `0x3702b700 = 922924800`.
Another check is done on the hostname. This is the `uname` invocation that we observed originally. A function call at `001017da` is made right after the time-bound check with a data pointer and the buffer used by `uname` as arguments. This function compares the hostname obtained from `uname` character by character with a decrypted char from the required hostname. After decrypting the memory (by xor’ing with 0x4d) we find `ZionHQ` as the required hostname. Now to enable the dev message we set those values in our machine and run the program using the master key:

```
$ sudo hostname ZionHQ
$ sudo date -s '@922920000'
$ env ALPHA_TOKEN=WMJMNJIYFZFLRUHNMCDY ./binary_alpha_launcher.antianalysis

Loading...    *****
BINARY BOOTLOAD v4h
ROM OK
SYSTEM CHECKS OK
STAGE 2 LOADING...
BINARY BOOTLOAD v4h
ROM OK
CONNECTION SYSTEM OK
STAGE 2 LOADING...

*** DEV NOTE: disable the master alpha token

BINARY LAUNCHER -  CLOSED ALPHA
COPYRIGHT © 1999-2022 DEUS EX MACHINA.

1336 INTERCAL BYTES FREE

BINARY LAUNCHER -=# WARNING: CLOSED ALPHA; DO NOT SHARE; PLAYING REQUIRES PASSWORD!
$
```
Here the program does not show the warning and does not exit like in the previous section. Instead, it shows up a dev note to disable the master token and then proceeds to show the console for the connector software.

