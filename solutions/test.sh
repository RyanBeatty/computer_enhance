./build/main $1 > ./build/test.asm;
nasm ./build/test.asm -o ./build/test
diff ./build/test $1