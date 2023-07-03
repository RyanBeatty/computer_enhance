#!/bin/bash
set -Eeuo pipefail

FILENAME=$(find ../perfaware/part1/ -not -name "*.asm" -not -name "*.txt" -not -name "*.cpp" -name "*$1*")

if [ ${2-default} == "default" ]
then
    echo "dissasembly"
    # Test dissasembly.
    ./build/main $FILENAME > ./build/test.asm;
    nasm ./build/test.asm -o ./build/test
    diff ./build/test $FILENAME
elif [ "$2" == "simstate" ]
then
    echo "simstate"
    # Test simulate.
    ./build/main --simstate $FILENAME > ./build/test.txt;
    # Remove the header line from Casey's output.
    sed 1d "$FILENAME.txt" > ./build/no_header.txt
    # Remove carriage return.
    sed 's/\r$//' ./build/no_header.txt > ./build/actual.txt
    diff ./build/test.txt ./build/actual.txt
else
    echo "debug"
    # Run with gdb.
    gdb -ex run --args ./build/main $FILENAME
fi

