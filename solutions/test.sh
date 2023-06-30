#!/bin/bash
set -Eeuo pipefail

FILENAME=$(find ../perfaware/part1/ -not -name "*.asm" -not -name "*.txt" -not -name "*.cpp" -name "*$1*")

if [ ${2-default} == "default" ]
then
    # Test dissasembly.
    ./build/main $FILENAME > ./build/test.asm;
    nasm ./build/test.asm -o ./build/test
    diff ./build/test $FILENAME
else
    # Run with gdb.
    gdb -ex run --args ./build/main $FILENAME
fi

