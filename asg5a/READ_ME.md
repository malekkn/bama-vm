# __Binary and Malware Analysis__
# Challenge 5A

* __Malek Kanaan__
* vunet id : __mkn668__
* Hacker Handle: __Krypt0__

# Syntactical Validity of a Word

Running the `oracle` binary with input `HELLO` gives the output:
```bash
$ ./oracle 'HELLO'
Requested word invalid: HELLO
```

Examining the `oracle` binary using ghidra reveals the different messages that the program outputs namely
* Requested word invalid
* Requested word has no meaning: %s (%d != 0)
* Meaning of %s: "%s"

The string printed depends on the output of the function at `0x1012e0` (IMAGE_BASE 0x100000).
That function checks the validity of the input while transforming it to the intermediate representation (from now on referred to as IR). First, the word must be 16 characters long and each character is one of the following: `A1C2E4H5K6M7P8R9UVWXYZ*~^&/:,;-`

Supplying a word of length 16 with a valid character to the oracle we get:
```bash
$ ./oracle 'AAAAAAAAAAAAAAAA'
Requested word has no meaning: AAAAAAAAAAAAAAAA (90 != 0)
```

By generating random words that satisfy these constraints and feeding them to the oracle we found some valid words that have a meaning. For example:
```bash
$ ./oracle '~EP2E1@8&55EK~WA'
Meaning of ~EP2E1@8&55EK~WA: "00000000000000".
```

# Encoder and Decoders

Using ghidra we can extract the code that encodes an input word into IR. The encoder picks a char from the input. Then it gets the index of it in the legal characters string. The index is a value between 0 and 31 which can be represented by 5 bits. Hence, the encoder logic maps this index into 5 bytes. So the resulting IR is `5 * 16 = 80 bytes`.

Another logic also takes care of transforming the IR of a meaning class back to a ascii. However, the meaning class IR is 56 bytes, and each character in the result must be one of these characters `"0123456789abcdef`

These encoder/decoder are imported to the python script from the de-compiled code in ghidra.
Another decoder for the word IR is also written to inverse an IR representation back to ascii when needed. It looks very similar to the meaning decoder but uses the characters and constraints corresponding to the word encoder.

# Capturing the Word has Meaning Algorithm

It is not trivial to get the algorithm that does this using static analysis or random brute force. Thus, Using angr to do this is a better idea (lol).
First we initialize a `call_state`. This state is supplied with the constraint that a byte in the IR should be either be a `0x1` or a `0x00` which hopefully guide the engine to be more accurate. Then a symbolic bit vector is loaded in the memory (and address in `%RDI`) to be used to capture the algorithm performed on it.
The script targets the function which has the word IR buffer as the first argument (and has 0x5f constant as the second). The found argument to the explorer is right before the call to the meaning mapping class (so it passes the check that it's returned zero), while the avoid is the address of the block that the program goes to when there is no class (the function did not return a zero). The resulted `found` state after calling `explore` holds the state and constraints that capture this algorithm.
The default search technique used by angr takes a lot of time and results in a state explosion. This can be due to the loop in the word validation algorithm. I supplied `DFS` (depth first search) as a technique. This makes the execution significantly faster.

# Capturing the Meaning Assignment Algorithm

After that the word check function returns with zero, another function (at `0x1047a0`)gets called with two arguments. The first argument hold the meaning IR and the second is the word IR. To capture this algorithm, again, we use angr. Starting by initializing a new `call_state`. This function takes two arguments. The first is the buffer of the resulted meaning IR and the second is the word IR. We load a new symbolic bit vector in memory and its address in `%RDI`. The Other argument reuses the symbolic bit vector from the previous algorithm (loaded from that sate's memory to this state) which is loaded into memory and its address to `%RSI`. The constraints from the older state are added to this new state because they are related in the flow of the program. Then we run the explorer to capture the algorithm.

# Obtaining all Possible Meanings

To obtain a given word from a class, first we call `eval_upto` with the `meaning_SMT` (which holds the meaning mapping algorithm) and a `n=1000`. This returns a set of meanings IR's of size 307.
To find a corresponding word to a given class, we add the meaning IR as a constraint to the symbolic state found after exploring. Then we call `eval` on the word_SMT that should give an IR of a word corresponding to that meaning class. However, the solver only evaluated one or two classes and the rest were unsatisfiable.
Clearly there was an issue in the word_SMT that captures the algorithm of valid words. With further inspection, turns out that this algorithm can only generate a limited number of valid word IR's (around 500) when evaluated using `eval_upto` with `n = 2000`
After a lot of debugging, turns out that the word SMT did not capture the full algorithm. Looking through the angr api, I stumbled by the [Veritesting technique](https://api.angr.io/angr#angr.exploration_techniques.veritesting.Veritesting). The description says:

> Enable veritesting. This technique, described in a a paper from CMU, attempts to address the problem of state explosions in loops by performing smart merging.

Clearly this could be a proper solution to out initial problem of state explosion. Subsequently, the resulted word SMT was able to generate very large number of words with ease.
This also fixed the issue of unsatisfiable meaning class to word mapping evaluation in the later step.

# Results
In the end, the script is able to capture 307 meanings and a word that corresponds to each one of them. The meaning and words are generated using the hacked encoders and decoders due to lack of time to do the last step of capturing these algorithms.

# Files Included
* `oracle`: the binary translating words to their meanings. (Provided by the assignment)
* `meanings.out`: the file containing the words and their meanings.
* `asg5A.py`: The script to generate the `meanings.out` file (if the file exists it will be renamed to `meanings.out.old`).

# Running the Solution

Simply run the python script with python3 like
```bash
$ python3 asg5A.py
````
