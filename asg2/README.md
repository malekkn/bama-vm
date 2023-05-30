# __Binary and Malware Analysis__
# Challenge 2

* __Malek Kanaan__
* vunet id : __mkn668__
* Hacker Handle: __Krypt0__

# Dumping & assembling the ELF file
## Determine the right time to dump max. 1 point
The right time to dump the ELF file should be after that the packer has decrypted/de-obfuscated the packed binary. When analyzing the `strace` output of the launcher, we notice some repeated calls to `mmap` and `mprotect` with different flags. One flag was `PROT_EXEC`. Looking around in ghidra, specifically at `0x102072`, these calls are surrounding another function call that looks suspiciously similar to the decrypt function from the last challenge. This one, however, has an extra parameter. Looking at XREFs for this function, we see it being called at `0x10214c` with two constants `0x0` and `0x40`, then the first 4 bytes of the result are compared to `0x7f ELF`. Clearly a sanity check is made on the binary elf header starting from 0 and for size 64 bytes. However this is still early stage to dump as the data in memory doesn't have code yet. So the this must happen after this check function has returned and close to the `mmap` calls. Hence, putting things together we can say that a good time for dumping the binary is right after the last chuck is decoded and mapped around `0x102072`. Either one chunk every iteration, or once after the last decrypt call.

## Determine the right memory location(s) to dump
Since we know at what point we can dump the binary. We can simply use gdb to inspect the location to which the binary is being decrypted to. In each iteration, the call to the decrypt function has the destination value in `%rdi`. So every iteration the  destination address shifts forward with a certain offset. We can dump those regions by using the destination from iteration `i` with the destination from `i-1` or calculating the offsets and use them etc.
In the last iteration we add up the value of the size (in `%rcx`) to the destination pointer to determine where the binary ends. For example:
```
dump binary memory part_1 0x400000 0x401000
continue
dump binary memory part_2 0x401000 0x404000
continue
dump binary memory part_3 0x404000 0x406ca0
continue
dump binary memory part_4 0x406ca0 0x507080
```
Another approach is to break after the last iteration and dump using:

```
dump binary memory bin_dump ($rdi-0x6ca0) ($rdi+$rcx)
```
`0x6ca0` is the offset between the first and last iteration destinations. `%rcx` here has the size of the last chunk.

## Dump the memory and assemble the ELF file  max. 1 point
If we dump in multiple chunks we can use `cat part_1 ... part_n > full` to assemble the binary. If we dump in one hit, then the binary is ready for further work.

# Ensure that the ELF file runs & tool output is sane
The ELF output had many weird values with some errors. To fix the weird values we need to change the following:
```
e_ident`   at offset 0x5     to 0x1    (little endian)
e_machine at offset 0x12    to 0x3e   (AMD x86-64)
```
This leaves us with errors about the `.dynamic` section in dynamic segment. Using `strigns` on the binary doesn't return any of the usual section headers. looking around with ghidra, I am also unable to find any section header data. Hence, the section header related values in the elf header are not relevant and can be replaced with zeros. Namely:
```
e_shoff	        0x28    (4 bytes) section header table offset is wrong
e_shentsize     0x3a	Contains the size of a section header table entry.
e_shnum         0x3c    Contains the number of entries in the section header table.
e_shstrndx 	    0x3e    Contains index of the sec hdr table entry for the section names
```
This will fix the `readelf -h` error but the binary will get a segmentation fault if we run it. In ghidra, we noticed that in the program header array entry `PT_DYNAMIC`, the  `_DYNAMIC` lable was pointing to null bytes! Hence, it is pointing to the wrong location.

> *Commence a lot of looking around the binary and reading resources online about program and section headers*.

The binary has a list of strings of function and library names and some other stuff. This turns out to be the dynamic strings table `DT_STRTAB`. The dynamic section must have a reference to this table in it. Searching using ghidra memory search tool I found what looks like a Dynamic table entry!. Crawling back a bit and I found the address at offset `0x7cb0` while the old reference was pointing to offset `0x6cb0`. This finally fixed the binary and I can now run it standalone.

# Find the password and start the game!
Using ghidra I followed an XREF to one of the strings that say `login` and found the code that validates the password character by character. Which can be read from the assembley or the decompiler code. The password is `ESCACRVJZBZFJHIGAXYW`

# Anti-unpacking measures
After using the password and issuing a `login` command, the binary gets stuck at that point. Inspecting the binary in ghidra shows that in `main()`. The binary makes several calls to `getauxval()`. It requests
The interesting one which causes the infinite loop is `getauxval(0x18)`.
The binary requires some values to be in the auxiliary vector to operate. Those values are:
1. `AT_PAGESZ` = 0x6   System page size.
2. `AT_BASE_PLATFORM` = 0x18  pointer to a string identifying real platforms.
3. `AT_RANDOM` = 0x19  Address of 16 random bytes.

The second one is used in many places as a anti-unpacking measure:
1. __Infinite loop after login, if value is zero__ This is the normal case. Because the value is not set in the aux. vector, the call returns zero.
2. __The code pointer to the game logic incorrectly calculated__ The value returned from `getauxval(0x18)` is used to determine the the argument to the call instruction. Hence, if the value is incorrect. The game won't start. Simply gets a segmentation fault.

Using GDB to debug the packed binary with in the launcher, we obtain the expected value for `AT_BASE_PLATFORM` which is `0x88413a4dc9009b49`. This value is then added to the auxiliary vector by hijacking the `__libc_start_main` call using the `LD_PRELOAD` trick. Then we call the original main normally. Check the file `my_start_main`.

With all of the mentioned tricks the binary finaly shows a packman game with some epic gameplay.

# Files included:
* `run_me.sh`: runs all other scripts and programs to get the unpacked binary. It also logs in and starts the game.
* `my_start_main.c`: Hijacking `__libc_start_main` to insert the auxiliary value into the vector.
* `dump_patch.py`: a python script to dump the binary and patch it.

# Resources that helped me through this

* ELF-64 Object File Format book: https://uclibc.org/docs/elf-64-gen.pdf


* elf.h source code: https://code.woboq.org/userspace/glibc/elf/elf.h.html

* oracle documentations: https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/6n33n7fcb/index.html

