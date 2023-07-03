#include "sim86_shared.h"
// hello world

#include <getopt.h>
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
            fprintf(stream, " ; %s:0x%x->0x%x ", reg_name, old_value, new_value);
            break;
        }
    }
}

void PrintSim86RegStateFinal(Sim86RegState reg_state, FILE* stream) {
    fprintf(stream, "Final registers:\n");
    size_t len = sizeof(reg_state.registers) / sizeof(reg_state.registers[0]);
    for (size_t i = 1; i < len; ++i) {
        register_access access = {.Count = 2, .Index = i, .Offset = 0};
        const char* reg_name = Sim86_RegisterNameFromOperand(&access);
        uint16_t value = reg_state.registers[i];
        fprintf(stream, "%8s: 0x%04x (%u)\n", reg_name, value, value);
    }
    fprintf(stream, "\n");
}

typedef enum Sim86Flags { Sim86Flags_Sim_State = 0x01 } Sim86Flags;

uint32_t ParseCommandLineArgs(int argc, char* argv[], char** input_filename) {
    uint32_t flags = 0;
    int c;

    while (1) {
        static struct option long_options[] = {/* These options set a flag. */
                                               /* These options don’t set a flag.
                                                  We distinguish them by their indices. */
                                               {"simstate", no_argument, 0, 's'},
                                               {0, 0, 0, 0}};
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "s", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1) break;

        switch (c) {
            case 0:
                Assert(false);
                // /* If this option set a flag, do nothing else now. */
                // if (long_options[option_index].flag != 0) break;
                // printf("option %s", long_options[option_index].name);
                // if (optarg) printf(" with arg %s", optarg);
                // printf("\n");
                break;

            case 's':
                flags |= Sim86Flags_Sim_State;
                break;

            case '?':
                /* getopt_long already printed an error message. */
                fprintf(stderr, "Unknown option\n");
                exit(EXIT_FAILURE);
                break;

            default:
                abort();
        }
    }

    /* Print any remaining command line arguments (not options). */
    if (optind + 1 == argc) {
        *input_filename = argv[optind];
    } else {
        fprintf(stderr, "USAGE: ./main [OPTIONS...] <input_filename>\n");
        exit(EXIT_FAILURE);
    }

    return flags;
}

int main(int argc, char* argv[]) {
    char* input_filename = NULL;
    uint32_t flags = ParseCommandLineArgs(argc, argv, &input_filename);

    size_t buffer_length = 0;
    uint8_t* disassembly = ReadFile(input_filename, &buffer_length);

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
            breakpoint();
            if (flags & Sim86Flags_Sim_State) {
                PrintSim86RegStateDiff(register_state_old, state.register_state, stdout);
            }
            printf("\n");
        } else {
            printf("Unrecognized instruction\n");
            break;
        }
        register_state_old = state.register_state;
    }
    printf("\n");

    if (flags & Sim86Flags_Sim_State) {
        PrintSim86RegStateFinal(state.register_state, stdout);
    }

    return 0;
}
