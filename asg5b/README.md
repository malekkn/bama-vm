
# __Binary and Malware Analysis__
# Challenge 4B
* __Malek Kanaan__
* vunet id : __mkn668__
* Hacker Handle: __Krypt0__

# Introduction

The bf lifter works with `*.bf` files and only supports the vanilla brain fuck language. To support `*.mbf` files, The package is renamed to `angr_mbf` and all classes, architecture name, loader backend etc. were changed to reflect and support the morpheus brain fuck extension.
> angr version used: `9.0.7491`

# I/O operators are self-incrementing

In the `Morpheus dialect` of Brain Fuck, the input and the output instructions has a side effect. This effect moves the cell pointer to the right (By incrementing the cell pointer by one). In normal setting this can be achieved by incrementing the pointer right after the I\O call. Howver, in `pyvex`, it is not trivial to add instructions after a terminating instruction, in this case the `syscall`. Therefore, another solution can be to increment the pointer at runtime in the `simos_mbf.py` for the simulation.

## SemBex input/output

In the `state.posix.dump(0)` we find the input for this stage `see_how_deE`.


In the output `state.posix.dumps(1).decode('ascii')` we find a part with some readable letters
```bash
: ., ,   . , -. : . -:..                   T  t
 .  .  .,., ,.: .. : . -:..                a   h                    p
. . .,., ,.:. .,., ,.: ,     .             k    e       ./*..  ..    i
  . .  .,., ,.: ,  .., .:..:. -. : ,,      e            */. .  ./     l
```

# Condition flag extension

To implement this
This extension includes 4 new instructions. Namely:
1. `&`: Sets the CF flag to 1. A new Instruction class is added to provide the lif logic to `vex`. The class named `Instruction_SETCF` stores 1 in `CF` as a set value.
2. `@`: Clears the CF flag value. The class `Instruction_CLRCF` does the opposite, storing a zero in the `CF` register.
3. `(`: loads the value of the `CF` and then clears it by storing zero in there. The instruction jumps past the matiching
4. `)`: jumps back to the matching `(`.
## SemBex input/output
In the `state.posix.dump(0)` we find the input for this stage`see_how_deEp_T_rabbit_hole_g`.
`
In the output `state.posix.dumps(1).decode('ascii')` we find more characters and the words `take the blue pill`:
```
: ., ,   . , -. : . -:..                   T  t
 .  .  .,., ,.: .. : . -:..                a   h                    p
. . .,., ,.:. .,., ,.: ,     .             k    e       ./*..  ..    i
  . .  .,., ,.: ,  .., .:..:. -. : ,,      e            */. .  ./     l
, ,.:. .  ., ,.:. .  . .,  . := ..:-                b   **..*. ./      l ,/#/*.. .,
.,., ,.:...  , */  . . .., ..  ..  ., ,,.           l   *((///,*/. .(#(#(((((,  .,.
.  . ...,,*,. .. .*,.  ,*//(*. . . := ..:-          u   ,((///.*(* *//(/*/(((,.
., ,. -. : ,,.,.         .****/(/*  .  . .          e   ,(((/(,/(/   ..,.
 ,.:  -. :..*   .            .,,***/(*. . .             *(((*(,/#/
  .-:: ...*(,,.,                 ,,**,**//,.            ,#(*/((/**
     ..:.,/*,,*                      ,.**/**/#/,         /(*//,*.    .,//*,,.
      :..,(/**        .,*,..           ,/*,((///((#/.               /***/((((((((((/((/*,

```



# Stack Extension

The bottomless stack extension requires several elements to maintain and use the stack. First, a memory area is reserved in the `simos_mbf.py` module using `state.memory.map_region()`. Second, a 64 bit register is needed to maintain the (head of) stack pointer. This is defined in the `arch_mbf.py` module. Finally: the instruction must be also implemented as classes in `lift_mbf.py`.
1. `v`: pushes the current cell on the stack. Implemented in class `Instruction_PUSH`
2. `^`: pops the top of the stack to the current cell. Implemented in class `Instruction_POP`
3. `#`: pops the stack and adds it to current cell. Implemented in class `Instruction_POP_ADD`
4. `|`: pops the stack and subtracts it from current cell. Implemented in class `Instruction_POP_SUB`

The stack pointer always points to the next empty address. When push is issued, the value is first loaded at the stack pointer address and then the stack pointer is incremented. On the other hand, Pop instruction first decrements the stack pointer and then loads the value to memory at the `PTR` address. The stack achieves the bottomless behavior by reserving the first element to be zero. when a pop is issued, the instruction checks whether the stack pointer is equal to the bottom address. If that is the case the stack pointer is incremented by one.

## SemBex input/output

In the `state.posix.dump(0)` we find the input for this stage see says `see_how_deEp_T_rabbit_hole_gOes`.

In the output `state.posix.dumps(1).decode('ascii')` we find more characters and the words `take the blue pill`:
```
: ., ,   . , -. : . -:..                   T  t
 .  .  .,., ,.: .. : . -:..                a   h                    p
. . .,., ,.:. .,., ,.: ,     .             k    e       ./*..  ..    i
  . .  .,., ,.: ,  .., .:..:. -. : ,,      e            */. .  ./     l
, ,.:. .  ., ,.:. .  . .,  . := ..:-                b   **..*. ./      l ,/#/*.. .,
.,., ,.:...  , */  . . .., ..  ..  ., ,,.           l   *((///,*/. .(#(#(((((,  .,.
.  . ...,,*,. .. .*,.  ,*//(*. . . := ..:-          u   ,((///.*(* *//(/*/(((,.
., ,. -. : ,,.,.         .****/(/*  .  . .          e   ,(((/(,/(/   ..,.
 ,.:  -. :..*   .            .,,***/(*. . .             *(((*(,/#/
  .-:: ...*(,,.,                 ,,**,**//,.            ,#(*/((/**
     ..:.,/*,,*                      ,.**/**/#/,         /(*//,*.    .,//*,,.
      :..,(/**        .,*,..           ,/*,((///((#/.               /***/((((((((((/((/*,
       ...,//*,,.        ,,**,**,.  ./. ./*****(//*(((#/.           ,.////(((/////(..   .,/.
         ..,#(//.**,       ..*,/,*,/(*,,.   ./,***(((/((((##,        ,.*/((///,,...       ..
             */(/*/,*,,        ,,/((*/((*,*/,   ,,*/*(*/*(/*(##(,           ..,***/(///*,.
                *(//*/,*.*..    *#(/,/*//(//((**,   ,*****(#((#(((#(.
                   .*((//****,,*((/(*(****///(//(,(*.   .****////((*/(/
                       ./(((*(//#(((///(//***,*/(//(///*,. ,****,**,  .,/.
                           ./((((((/(//(///((///*,**(/(/(//*,/(((//***,  *,
                               ./((((((/(*((/(//((**/****//**.*//((/(///, ,
                                    *(#(/(((/(/(/(//((//***,,/(*(/*,*/** .*
                                        *((((/(/(/(/#/(/(/*.***(/*/*/*  .,*
                                           ./#/(((/(///((**./**,,*(***(/(*
                                               ,(##*((*(((/(///,,,,*,/(/*
                                                   ,##/((/(//*(*//*///*
                                                       .(##((((((#(.
```
> Path two message is also provided in the Appendix. Tbh I choose that path too now that I see it B-)

# Files Included
* `solve.py`: Runs the symbolic execution and prints the message in the output
* `morpheus.mbf`: Is the program provided by the assignment.
* `ang_mbf/**`: package that implements the Brain f*uck Morpheus extension logic for the lifter.

# Appendix

## Path 2 Message
```bash
beliEve_what_ you_wnt_To_believE
==================================
: .. .   . .   .*#(##. . .**.  .  ,(#%%*.,. .
 .  .,., ,.:.  .##/#%%(  .**.  ##(#(##,*.,(*                                ,(%%%%%%(,
. . :  ..   . .  *%/(###*   .  **((#%(.                             ,,..*#((((/*//****//#(
 . . ./    ,/.  ,  */ ,,,# .,., ,.:                           .:.: -:,%#((/*,*,..   ,**.  ./
.  . (,      /(.  ;  *, ./      ,/(/,............       -. : . -:..##(///,*,,.         ,.   ,
 ,, .%*, .*   ./( .  .,., ,.: ,(*//#%#######(##(#*    -. : . -::(%(//*/,,                   .*
.  . .#(,  */,/*/%%.          ,,((((####(#(#*,. , */  . .    *%(#((,,*.        *,,           (
..  .  *#/*#(##*.*(##.         .*/#%###(///.  , .. . . .  ,%%(((,*,,      .**/**             *.
 . .  . .(####/(#*,/(##  .  .  . .  .     ...,,*,. ..   *%%(%%%(**.    ,*//***           ,**/(
., ,.:.,.. ####(/#(,*((#/   .,., ,.:  .,., ,.: :.:.,.,#%#((##((##(%#./*///**,          /*//%,
  ., ,.: :\ .%##(#/(*(#/.,    .,., ,.:..:. -. : ,,,(%%##(#/##/%**#,*/%%/**,         ***//(
    ,.:  -.\../###//((*/,.      .,., ,.:  -. :..*%##((/#(#(#%#(**//*/%/((.       ,(,*/*#
      ,., ,.:  -(%#(/(#/ .  .  . .  .-:: ... *&###%#(###(/((*//#((#((/*,  /    */*/*#,
        .,., ,.:. .  ..,., ,.:    -:: ... ,%#((%(#*##///#(/**/((((/*,   *,/(/,*/(*#
         .,., ,.:. .  . .,., ,.:= ..:. .%##((#//(%/(###(***###///*.  .//,/(//*/((
  T  ke      \.,., ,.:        = ..:../%#*#(((#(#/((%*,*//*##%(*,   ,**,*###%%#,
   a            ., .,., ,.: = ..:. %%##%#(####(###****#((((/(.  .*/*/#(/#((#.
        th    e ,.:= ..:., ,.: . *%####((/(*(##(/,**((//(/.  ,**/((##((#%#
                 ,.:= ..:-:: ...,%((#%(#((/.**,(**,*(%(*  .*#//#%(##((%,
  r   EEEE        :.. .:.: -:::-/#/((**(.**.///*,/,/*. .**//*/(*((#%(
            d        :.. .:.: -: %%(,/,*./(#*/##*(%((///*(((%(#(#%,
    1                 :.. .:.: -::((*/(*(//#(/*,(#(#( /(/*(#(#%/
   P l                  . .:.: -:. (###(/*( ,(///#/*/*,(##%##.
     l.                   ,., ,.:..,.(((/   (/**//. . *((%,
                             . := ..:-: */.,.*,,  .*/*/
                               .:. .  . .,., ,...
```
