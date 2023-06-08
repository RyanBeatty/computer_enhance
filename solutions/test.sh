FILENAME=$(find ../perfaware/part1/ -not -name "*.asm" -not -name "*.txt" -not -name "*.cpp" -name "*$1*")
./build/main $FILENAME > ./build/test.asm;
nasm ./build/test.asm -o ./build/test
diff ./build/test $FILENAME