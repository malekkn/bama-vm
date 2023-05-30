#!/bin/bash
# install dependencies
python3 -m pip install --upgrade pwntools

# dump the binary and patch it
python3 ./dump_patch.py

# make it executable
chmod +x ./binary_alpha_launcher.unpacked
rm bin_dump

# compile the hijack of libc_start_main
rm my_start_main.so
gcc -o my_start_main.so -shared -fPIC my_start_main.c

# run the game with the hijack
echo -e 'password\nESCACRVJZBZFJHIGAXYW\nlogin\nstart' | LD_PRELOAD=./my_start_main.so ./binary_alpha_launcher.unpacked
