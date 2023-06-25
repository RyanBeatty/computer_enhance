#include "sim86_shared.h"
// hello world

#include <stdint.h>
#include <stdio.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#define Assert(expr)      \
    {                     \
        if (!(expr)) {    \
            breakpoint(); \
            assert(0);    \
        }                 \
    }

void __attribute__((noinline)) breakpoint() {}

uint8_t* ReadFile(char* input_filename, size_t* buffer_length) {
    FILE* fd = fopen(input_filename, "r");
    fseek(fd, 0, SEEK_END);
    long num_bytes = ftell(fd);
    Assert(num_bytes != -1);
    uint8_t* buffer = (uint8_t*)calloc(num_bytes, sizeof(uint8_t));
    rewind(fd);
    fread(buffer, num_bytes, sizeof(uint8_t), fd);
    fclose(fd);
    *buffer_length = num_bytes;
    return buffer;
}

int main(int argc, char* argv[]) {
    char* input_filename = NULL;
    switch (argc) {
        case 2: {
            input_filename = argv[1];
            break;
        }
        default: {
            fprintf(stderr, "USAGE: ./main <input_filename>\n");
            exit(EXIT_FAILURE);
        }
    }

    size_t buffer_length = 0;
    uint8_t* disassembly = ReadFile(input_filename, &buffer_length);

    uint32_t Version = Sim86_GetVersion();
    printf("Sim86 Version: %u (expected %u)\n", Version, SIM86_VERSION);
    if (Version != SIM86_VERSION) {
        printf("ERROR: Header file version doesn't match DLL.\n");
        return -1;
    }

    instruction_table Table;
    Sim86_Get8086InstructionTable(&Table);
    printf("8086 Instruction Instruction Encoding Count: %u\n", Table.EncodingCount);

    uint32_t Offset = 0;
    while (Offset < sizeof(disassembly)) {
        instruction Decoded;
        Sim86_Decode8086Instruction(sizeof(disassembly) - Offset, disassembly + Offset, &Decoded);
        if (Decoded.Op) {
            Offset += Decoded.Size;
            printf("Size:%u Op:%s Flags:0x%x\n", Decoded.Size, Sim86_MnemonicFromOperationType(Decoded.Op),
                   Decoded.Flags);
        } else {
            printf("Unrecognized instruction\n");
            break;
        }
    }

    return 0;
}
