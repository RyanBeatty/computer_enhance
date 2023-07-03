#include "sim86_shared.h"
// hello world

#include <inttypes.h>
#include <stdbool.h>
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
}

typedef struct Sim86RegState {
    // Shared sim appears to start indexing at 1;
    uint16_t registers[9];
} Sim86RegState;

void Sim86RegState_Init(Sim86RegState* state) { memset(state, 0, sizeof(Sim86RegState)); }

typedef struct Sim86State {
    Sim86RegState register_state;
} Sim86State;

void Sim86State_Init(Sim86State* state) { memset(state, 0, sizeof(Sim86State)); }

void Sim86State_SimulateMov(Sim86State* state, instruction instr) {
    Assert(instr.Op == Op_mov);

    instruction_operand source = instr.Operands[1];
    uint8_t vals[2];
    switch (source.Type) {
        case Operand_Immediate: {
            immediate imm = source.Immediate;
            vals[0] = imm.Value;
            vals[1] = imm.Value >> 8;
            break;
        }
        default: {
            fprintf(stderr, "Uknown source operand type: %d!\n", source.Type);
            exit(EXIT_FAILURE);
        }
    }

    instruction_operand dest = instr.Operands[0];
    switch (dest.Type) {
        case Operand_Register: {
            register_access reg = dest.Register;
            Sim86RegState* register_state = &state->register_state;
            // Find the base address of the register we are storing into.
            uint8_t* reg_ptr = (uint8_t*)&register_state->registers[reg.Index];
            // Offset our base address if we are only addressing the high portion of the register.
            reg_ptr += reg.Offset;
            for (size_t i = 0; i < reg.Count; ++i, ++reg_ptr) {
                *reg_ptr = vals[i];
            }
            break;
        }
        default: {
            fprintf(stderr, "Unkown dest operand type: %d\n", dest.Type);
            exit(EXIT_FAILURE);
        }
    }
}

void Sim86State_SimulateInstruction(Sim86State* state, instruction instruction) {
    switch (instruction.Op) {
        case Op_mov: {
            Sim86State_SimulateMov(state, instruction);
            break;
        }
        default: {
            const char* op_name = Sim86_MnemonicFromOperationType(instruction.Op);
            fprintf(stderr, "Unknown instruction type: %s\n", op_name);
            exit(EXIT_FAILURE);
        }
    }
}

void PrintSim86RegStateDiff(Sim86RegState old, Sim86RegState new, FILE* stream) {
    size_t len = sizeof(new.registers) / sizeof(new.registers[0]);
    for (size_t i = 0; i < len; ++i) {
        uint16_t old_value = old.registers[i];
        uint16_t new_value = new.registers[i];
        // Each instruction can only modify one full register, so stop once we've printed this out.
        if (old_value != new_value) {
            register_access access = {.Index = i, .Offset = 0, .Count = 2};
            const char* reg_name = Sim86_RegisterNameFromOperand(&access);
            fprintf(stream, " ; %s:0x%x->0x%x", reg_name, old_value, new_value);
            break;
        }
    }
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

    Sim86State state;
    Sim86State_Init(&state);
    Sim86RegState register_state_old = state.register_state;

    uint32_t Offset = 0;
    while (Offset < buffer_length) {
        instruction Decoded;
        Sim86_Decode8086Instruction(buffer_length - Offset, disassembly + Offset, &Decoded);
        if (Decoded.Op) {
            Offset += Decoded.Size;
            Sim86State_SimulateInstruction(&state, Decoded);
            PrintInstruction(Decoded, stdout);
            if (true) {
                PrintSim86RegStateDiff(register_state_old, state.register_state, stdout);
            }
            printf("\n");
        } else {
            printf("Unrecognized instruction\n");
            break;
        }
        register_state_old = state.register_state;
    }

    return 0;
}
