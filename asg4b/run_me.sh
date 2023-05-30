#!/bin/bash

TEXT=./text
OBJ=./obj-intel64
GHIDRA_PROG=./ghidra_prog
LOG=$TEXT/log.txt
INPUT=$TEXT/input.txt
TOOL=$OBJ/tainttool.so
TOOL_OBJ=$OBJ/tainttool.o
SECRET=$TEXT/secret.txt
CLASSES=$TEXT/classes.txt
CFG_PY=./CFG_Analysis.py
DFA_PY=./DFA_Analysis.py


#  check if text directory exists
for DIR in $GHIDRA_PROG $TEXT $OBJ
do
    if [[ -d $DIR ]]; then
        rm -rf $DIR
    fi
    mkdir $DIR
done

if [ -z "$1" ]; then
    echo "Usage: ./run_me.sh <analysis type>"
    echo "Analysis type: cfg, dfa"
    exit 1
fi

if [ $1 == "cfg" ]; then
    echo "Running CFG analysis"
    # run the ghidra script for the cfg analysis
    $GHIDRA_ROOT/support/analyzeHeadless $GHIDRA_PROG rabbit_prog -import ./rabbit -postScript $CFG_PY
elif [ $1 == "dfa" ]; then
    echo "Running DFA analysis"
    # run the ghidra script for the dfa analysis
    $GHIDRA_ROOT/support/analyzeHeadless $GHIDRA_PROG rabbit_prog -import ./rabbit -postScript $DFA_PY
else
    echo "Invalid Analysis type: cfg, dfa""
    exit 1
fi


if [ ! -f $CLASSES ]; then
    echo "No classification file found check the ghidra script is run ...!"
    exit 1
fi

python3 -c 'print("#" * 2000)' > $INPUT

make PIN_ROOT=$PIN_ROOT $TOOL -j

if [ -f "$TOOL" ]; then
    $PIN_ROOT/pin -t $TOOL -i $INPUT -- ./rabbit -i $INPUT -f -x follow_the_rabbit_dear_consultant> $LOG
    /bin/python3 ./assemble_identity.py
    echo -e `python3 -c 'print("#" * 48)'`
    echo -e `python3 -c 'print("# secret")'`
    echo -e `python3 -c 'print("#" * 48)'`


    cat $TEXT/secret.txt
    rm $INPUT
else
    echo "Error: $TOOL not found..."
fi

