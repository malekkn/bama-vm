#!/bin/bash
INPUT=./text/input.txt
LOG=./text/log.txt
TOOL=./obj-intel64/tainttool.so
TOOL_OBJ=./obj-intel64/tainttool.o
#  check if text directory exists
if [ ! -d ./text ]; then
    mkdir ./text
fi


for FILE in $INPUT $LOG $TOOL $TOOL_OBJ
do
    if [[ -f "$FILE" ]]; then
        rm $FILE
    fi
done

python3 -c 'print("#" * 2000)' > $INPUT

make PIN_ROOT=$PIN_ROOT $TOOL -j

$PIN_ROOT/pin -t $TOOL -i $INPUT -- ./rabbit -i $INPUT -f -x follow_the_rabbit_dear_consultant > $LOG

python3 assemble_identity.py

./rabbit -i ./text/input.txt -f

echo "========================<Secret>========================"

cat $INPUT
