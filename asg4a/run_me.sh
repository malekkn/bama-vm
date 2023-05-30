#!/bin/bash
INPUT=./secret.txt
LOG=./text/log.txt
TOOL=./obj-intel64/callrettool.so
TOOL_OBJ=./obj-intel64/callrettool.o
DYN_PATCH=./dynamic_patch.py
STATIC_PATCH=./static_patch.py

#  check if tmp directories exist
if [ ! -d ./text ]; then
    mkdir ./text
fi

if [ ! -d ./obj-intel64 ]; then
    mkdir ./obj-intel64
fi


for FILE in $LOG $TOOL $TOOL_OBJ
do
    if [[ -f "$FILE" ]]; then
        rm $FILE
    fi
done

####################
# dynamic patching #
####################
# run the tool to log ind calls
make PIN_ROOT=$PIN_ROOT $TOOL -j

$PIN_ROOT/pin -t $TOOL -i $INPUT -- ./rabbit -i $INPUT -f  2> $LOG

python3 $DYN_PATCH
echo "###########################"
echo "Dynamic patching done!"


####################
# static patching #
####################

echo "performing static patching"
python3 $STATIC_PATCH
echo "Static patching done!"

