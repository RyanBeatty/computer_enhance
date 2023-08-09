#include "sim86_shared.h"
// hello world

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#define Assert(expr)        \
    {                       \
        if (!(expr)) {      \
            breakpoint();   \
            assert((expr)); \
        }                   \
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Execution.

typedef enum FlagsRegisterBit {
    FLAG_CF = (1 << 0),   // Carry
    FLAG_PF = (1 << 2),   // Parity
    FLAG_AF = (1 << 4),   // Aux carry
    FLAG_ZF = (1 << 6),   // Zero
    FLAG_SF = (1 << 7),   // Sign
    FLAG_TF = (1 << 8),   // Trap
    FLAG_IF = (1 << 9),   // Interrupt
    FLAG_DF = (1 << 10),  // Direction
    FLAG_OF = (1 << 11),  // Overflow
} FlagsRegisterBit;

typedef union Sim86RegState {
    struct {
        uint16_t Zero;

        uint16_t ax;
        uint16_t bx;
        uint16_t cx;
        uint16_t dx;
        uint16_t sp;
        uint16_t bp;
        uint16_t si;
        uint16_t di;
        uint16_t es;
        uint16_t cs;
        uint16_t ss;
        uint16_t ds;
        uint16_t ip;
        uint16_t flags;
    };

    uint8_t u8[15][2];
    uint16_t registers[15];

} Sim86RegState;

#define FLAGS_REGISTER_INDEX 14

void Sim86RegState_Init(Sim86RegState* state) { memset(state, 0, sizeof(Sim86RegState)); }
void Sim86RegState_SetFlags(Sim86RegState* register_state, uint16_t value, uint16_t af_flag) {
    uint16_t flag_state = 0;
    flag_state |= value == 0 ? FLAG_ZF : 0;
    flag_state |= (value & 0b1000000000000000) != 0 ? FLAG_CF : 0;

    uint8_t bit_set_count = 0;
    for (size_t mask = 1; mask < 256; mask <<= 1) {
        bit_set_count += (value & mask) != 0;
    }
    flag_state |= (bit_set_count % 2 == 0) ? FLAG_PF : 0;

    breakpoint();
    flag_state |= af_flag ? FLAG_AF : 0;

    register_state->flags = flag_state;
}

typedef struct Sim86State {
    Sim86RegState register_state;
} Sim86State;

void Sim86State_Init(Sim86State* state) { memset(state, 0, sizeof(Sim86State)); }

uint16_t Sim86State_Load(Sim86State* state, instruction_operand source) {
    uint8_t vals[2];
    switch (source.Type) {
        case Operand_Immediate: {
            immediate imm = source.Immediate;
            vals[0] = imm.Value;
            vals[1] = imm.Value >> 8;
            break;
        }
        case Operand_Register: {
            // TODO: Coalesce with storing values into registers.
            register_access reg = source.Register;
            Sim86RegState* register_state = &state->register_state;
            // Find the base address of the register we are storing into.
            Assert(reg.Index < (sizeof(register_state->registers) / sizeof(register_state->registers[0])));
            uint8_t* reg_ptr = (uint8_t*)&register_state->registers[reg.Index];
            // Offset our base address if we are only addressing the high portion of the register.
            reg_ptr += reg.Offset;
            for (size_t i = 0; i < reg.Count; ++i) {
                vals[i] = reg_ptr[i];
            }
            break;
        }
        default: {
            fprintf(stderr, "Unknown source operand type: %d!\n", source.Type);
            exit(EXIT_FAILURE);
        }
    }

    uint16_t value = 0;
    value |= vals[0];
    value |= vals[1] << 8;
    return value;
}

void Sim86State_Store(Sim86State* state, instruction_operand dest, uint16_t value) {
    uint8_t vals[2];
    vals[0] = value;
    vals[1] = value >> 8;
    switch (dest.Type) {
        case Operand_Register: {
            // TODO: Coalesce with loading values from registers.
            register_access reg = dest.Register;
            Sim86RegState* register_state = &state->register_state;
            // Find the base address of the register we are storing into.
            Assert(reg.Index < (sizeof(register_state->registers) / sizeof(register_state->registers[0])));
            uint8_t* reg_ptr = (uint8_t*)&register_state->registers[reg.Index];
            // Offset our base address if we are only addressing the high portion of the register.
            reg_ptr += reg.Offset;
            for (size_t i = 0; i < reg.Count; ++i) {
                reg_ptr[i] = vals[i];
            }
            break;
        }
        default: {
            fprintf(stderr, "Unkown dest operand type: %d\n", dest.Type);
            exit(EXIT_FAILURE);
        }
    }
}

void Sim86State_SimulateBinaryOp(Sim86State* state, instruction instr) {
    instruction_operand source = instr.Operands[1];
    instruction_operand dest = instr.Operands[0];
    uint16_t source_value = Sim86State_Load(state, source);
    uint16_t dest_value = Sim86State_Load(state, dest);
    uint16_t result = 0;
    bool should_store_result = true;
    bool should_set_flags = false;
    uint16_t af_flag = 0;
    switch (instr.Op) {
        case Op_mov: {
            result = source_value;
            break;
        }
        case Op_sub: {
            result = dest_value - source_value;
            af_flag = ((dest_value & 0xF) - (source_value & 0xF)) & 0x10;
            should_set_flags = true;
            break;
        }
        case Op_add: {
            result = dest_value + source_value;
            af_flag = ((dest_value & 0xF) + (source_value & 0xF)) & 0x10;
            should_set_flags = true;
            break;
        }
        case Op_cmp: {
            result = dest_value - source_value;
            should_store_result = false;
            should_set_flags = true;
            break;
        }
        default: {
            const char* op_name = Sim86_MnemonicFromOperationType(instr.Op);
            fprintf(stderr, "Unknown instruction type: %s\n", op_name);
            exit(EXIT_FAILURE);
        }
    }
    if (should_set_flags) {
        Sim86RegState_SetFlags(&state->register_state, result, af_flag);
    }
    if (should_store_result) {
        Sim86State_Store(state, dest, result);
    }
}

void Sim86State_SimulateInstruction(Sim86State* state, instruction instruction) {
    switch (instruction.Op) {
        case Op_mov:
        case Op_add:
        case Op_sub:
        case Op_cmp: {
            Sim86State_SimulateBinaryOp(state, instruction);
            break;
        }
        default: {
            const char* op_name = Sim86_MnemonicFromOperationType(instruction.Op);
            fprintf(stderr, "Unknown instruction type: %s\n", op_name);
            exit(EXIT_FAILURE);
        }
    }
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Output Printing.

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

void PrintSim86RegStateFlags(uint16_t flags, FILE* stream) {
    for (size_t i = FLAG_CF; i <= FLAG_OF; i <<= 1) {
        if (flags & i) {
            char c = '\0';
            switch (i) {
                case FLAG_CF: {
                    c = 'S';
                    break;
                }
                case FLAG_ZF: {
                    c = 'Z';
                    break;
                }
                case FLAG_PF: {
                    c = 'P';
                    break;
                }
                case FLAG_AF: {
                    c = 'A';
                    break;
                }
                default: {
                    fprintf(stderr, "Unknown Flag bit while printing %ld\n", i);
                    exit(EXIT_FAILURE);
                }
            }

            fprintf(stream, "%c", c);
        }
    }
}

void PrintSim86RegStateDiff(Sim86RegState old, Sim86RegState new, FILE* stream) {
    fprintf(stream, " ;");

    size_t len = sizeof(new.registers) / sizeof(new.registers[0]);
    for (size_t i = 0; i < len; ++i) {
        uint16_t old_value = old.registers[i];
        uint16_t new_value = new.registers[i];
        // Each instruction can only modify one full register, so stop once we've printed this out.
        if (old_value != new_value) {
            if (i == FLAGS_REGISTER_INDEX) {
                fprintf(stream, " flags:");
                PrintSim86RegStateFlags(old.flags, stream);
                fprintf(stream, "->");
                PrintSim86RegStateFlags(new.flags, stream);
            } else {
                register_access access = {.Index = i, .Offset = 0, .Count = 2};
                const char* reg_name = Sim86_RegisterNameFromOperand(&access);
                fprintf(stream, " %s:0x%x->0x%x", reg_name, old_value, new_value);
            }
        }
    }

    fprintf(stream, " ");
}

void PrintSim86RegStateFinal(Sim86RegState reg_state, FILE* stream) {
    fprintf(stream, "Final registers:\n");
    size_t len = sizeof(reg_state.registers) / sizeof(reg_state.registers[0]);
    for (size_t i = 1; i < len; ++i) {
        register_access access = {.Count = 2, .Index = i, .Offset = 0};
        const char* reg_name = Sim86_RegisterNameFromOperand(&access);
        uint16_t value = reg_state.registers[i];
        if (value) {
            fprintf(stream, "%8s: ", reg_name);
            if (i == FLAGS_REGISTER_INDEX) {
                PrintSim86RegStateFlags(value, stream);
                fprintf(stream, "\n");
            } else {
                fprintf(stream, "0x%04x (%u)\n", value, value);
            }
        }
    }
    fprintf(stream, "\n");
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
