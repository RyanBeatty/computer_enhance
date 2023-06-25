#include "sim86_shared.h"
// hello world

#include <stdint.h>
#include <stdio.h>

int main() {
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
    while (Offset < sizeof(ExampleDisassembly)) {
        instruction Decoded;
        Sim86_Decode8086Instruction(sizeof(ExampleDisassembly) - Offset, ExampleDisassembly + Offset, &Decoded);
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
