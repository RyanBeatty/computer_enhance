#include "sim86_shared.h"
// hello world

#include <inttypes.h>
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

void PrintRegisterAccess(register_access reg, FILE* stream) {
    // TODO: I think both of these are for the internals of the decoder. Seemed to mostly be used when convertint to the
    // reg name. Assert(!reg.Count); Assert(!reg.Offset);
    const char* reg_name = Sim86_RegisterNameFromOperand(&reg);
    fprintf(stream, "%s", reg_name);
}

void PrintMemoryAccess(effective_address_expression address, FILE* stream) {
    fprintf(stream, "[");
    PrintRegisterAccess(address.Terms[0].Register, stream);
    if (address.Terms[1].Register.Index) {
        fprintf(stream, " + ");
        PrintRegisterAccess(address.Terms[1].Register, stream);
    }
    if (address.Displacement) {
        const char sign = address.Displacement >= 0 ? '+' : '-';
        fprintf(stream, " %c ", sign);
        fprintf(stream, "%" PRId32 "", address.Displacement);
    }
    fprintf(stream, "]");
}

void PrintOperand(instruction_operand operand, FILE* stream) {
    switch (operand.Type) {
        case Operand_None: {
            break;
        }
        case Operand_Register: {
            PrintRegisterAccess(operand.Register, stream);
            break;
        }
        case Operand_Memory: {
            PrintMemoryAccess(operand.Address, stream);
            break;
        }
        case Operand_Immediate: {
            immediate imm = operand.Immediate;
            Assert(imm.Flags == 0);
            fprintf(stream, "%" PRId32 "", imm.Value);
            break;
        }
        default: {
            fprintf(stderr, "Unknown or None operand type: %d\n", operand.Type);
            exit(EXIT_FAILURE);
        }
    }
}

void PrintInstruction(instruction instruction, FILE* stream) {
    const char* op = Sim86_MnemonicFromOperationType(instruction.Op);
    fprintf(stream, "%s ", op);
    PrintOperand(instruction.Operands[0], stream);
    if (instruction.Operands[1].Type) {
        fprintf(stream, ", ");
    }
    PrintOperand(instruction.Operands[1], stream);
    fprintf(stream, "\n");
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
    printf("; Sim86 Version: %u (expected %u)\n", Version, SIM86_VERSION);
    if (Version != SIM86_VERSION) {
        printf("ERROR: Header file version doesn't match DLL.\n");
        return -1;
    }

    instruction_table Table;
    Sim86_Get8086InstructionTable(&Table);
    printf("; 8086 Instruction Instruction Encoding Count: %u\n", Table.EncodingCount);

    uint32_t Offset = 0;
    while (Offset < buffer_length) {
        instruction Decoded;
        Sim86_Decode8086Instruction(buffer_length - Offset, disassembly + Offset, &Decoded);
        if (Decoded.Op) {
            Offset += Decoded.Size;
            PrintInstruction(Decoded, stdout);
        } else {
            printf("Unrecognized instruction\n");
            break;
        }
    }

    return 0;
}
