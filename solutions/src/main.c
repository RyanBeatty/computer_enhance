#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#define Assert(expr)      \
    {                     \
        if (!(expr)) {    \
            breakpoint(); \
        }                 \
    }

void __attribute__((noinline)) breakpoint() {}

#define W_MASK(byte) ((byte)&0b00000001)
#define D_MASK(byte) (((byte)&0b00000010) >> 1)
#define REG_MASK(byte) (((byte)&0b00111000) >> 3)
#define R_M_MASK(byte) ((byte)&0b00000111)
#define MOD_MASK(byte) (((byte)&0b11000000))

#define MOD_MEMORY_MODE_NO_DISP ((uint8_t)0b00000000)
#define MOD_MEMORY_MODE_8BIT_DISP ((uint8_t)0b01000000)
#define MOD_MEMORY_MODE_16BIT_DISP ((uint8_t)0b10000000)
#define MOD_REGISTER_MODE ((uint8_t)0b11000000)

typedef struct ByteCursor {
    uint8_t* stream;
    size_t stream_len;
    size_t i;
} ByteCursor;

void ByteCursorInit(ByteCursor* cursor, uint8_t* stream, size_t stream_len) {
    cursor->stream = stream;
    cursor->stream_len = stream_len;
    cursor->i = 0;
}

uint8_t ByteCursorPop(ByteCursor* cursor) {
    Assert(cursor->i < cursor->stream_len);
    uint8_t next_byte = cursor->stream[cursor->i];
    ++cursor->i;
    return next_byte;
}

bool ByteCursorNotEmpty(ByteCursor* cursor) { return cursor->i < cursor->stream_len; }

typedef struct AsmWriter {
    char* output;
} AsmWriter;

void AsmWriterEmitInstructionEnd(AsmWriter* writer) { arrpush(writer->output, '\n'); }

void AsmWriterEmit(AsmWriter* writer, const char* instruction) {
    for (const char* i = instruction; *i != '\0'; ++i) {
        arrpush(writer->output, *i);
    }
}

void AsmWriterEmitInstructionStreamEnd(AsmWriter* writer) { arrpush(writer->output, '\0'); }

void AsmWriterInit(AsmWriter* writer) { writer->output = NULL; }

void AsmWriterEmitHeader(AsmWriter* writer, char* filename) {
    const char* token = strtok(filename, "/");
    const char* prev_token = token;
    while (token != NULL) {
        prev_token = token;
        token = strtok(NULL, "/");
    }
    AsmWriterEmit(writer, "; ");
    AsmWriterEmit(writer, prev_token);
    AsmWriterEmit(writer, " disassembly:");
    AsmWriterEmitInstructionEnd(writer);

    AsmWriterEmit(writer, "bits 16");
    AsmWriterEmitInstructionEnd(writer);
    AsmWriterEmitInstructionEnd(writer);
}

void AsmWriterEmitBits8(AsmWriter* writer, uint8_t bits) {
    char str[9];
    sprintf(str, "%hhu", bits);
    AsmWriterEmit(writer, str);
}

void AsmWriterEmitBits16(AsmWriter* writer, uint16_t bits) {
    char str[17];
    sprintf(str, "%hu", bits);
    AsmWriterEmit(writer, str);
}

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

const char* ResolveRegister(uint8_t op_code, uint8_t reg) {
    // Do some masking so we can make this a simple switch lookup.
    uint8_t w = W_MASK(op_code);
    w = w << 3;
    reg |= w;
    switch (reg) {
        case 0b00000000: {
            return "al";
        }
        case 0b00001000: {
            return "ax";
        }
        case 0b00000001: {
            return "cl";
        }
        case 0b00001001: {
            return "cx";
        }
        case 0b00000010: {
            return "dl";
        }
        case 0b00001010: {
            return "dx";
        }
        case 0b00000011: {
            return "bl";
        }
        case 0b00001011: {
            return "bx";
        }
        case 0b00000100: {
            return "ah";
        }
        case 0b00001100: {
            return "sp";
        }
        case 0b00000101: {
            return "ch";
        }
        case 0b00001101: {
            return "bp";
        }
        case 0b00000110: {
            return "dh";
        }
        case 0b00001110: {
            return "si";
        }
        case 0b00000111: {
            return "bh";
        }
        case 0b00001111: {
            return "di";
        }
        default: {
            fprintf(stderr, "Unknown register: %x\n", reg);
            exit(EXIT_FAILURE);
        }
    }
}

const char* ResolveRM(ByteCursor* cursor, uint8_t op_code, uint8_t byte) {
    const char* res = NULL;
    switch (MOD_MASK(byte)) {
        case MOD_REGISTER_MODE: {
            res = ResolveRegister(op_code, R_M_MASK(byte));
            break;
        }
        default: {
            fprintf(stderr, "Uknown mode: %x\n", MOD_MASK(byte));
            exit(EXIT_FAILURE);
        }
    }
    return res;
}

void ParseIm8ToReg(ByteCursor* cursor, AsmWriter* writer, const char* reg) {
    uint8_t byte = ByteCursorPop(cursor);
    AsmWriterEmit(writer, "mov ");
    AsmWriterEmit(writer, reg);
    AsmWriterEmit(writer, ", ");
    AsmWriterEmitBits8(writer, byte);
}

void ParseIm16ToReg(ByteCursor* cursor, AsmWriter* writer, const char* reg) {
    uint8_t low = ByteCursorPop(cursor);
    uint8_t high = ByteCursorPop(cursor);
    uint16_t data = (high << 8) | low;
    AsmWriterEmit(writer, "mov ");
    AsmWriterEmit(writer, reg);
    AsmWriterEmit(writer, ", ");
    AsmWriterEmitBits16(writer, data);
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
    uint8_t* buffer = ReadFile(input_filename, &buffer_length);
    ByteCursor cursor;
    ByteCursorInit(&cursor, buffer, buffer_length);

    bool no_error = 1;
    AsmWriter writer;
    AsmWriterInit(&writer);
    AsmWriterEmitHeader(&writer, input_filename);
    while (no_error && ByteCursorNotEmpty(&cursor)) {
        uint8_t op_code = ByteCursorPop(&cursor);
        switch (op_code) {
            case 0x88:
            case 0x89:
            case 0x8A:
            case 0x8B: {
                uint8_t next_byte = ByteCursorPop(&cursor);
                const char* src_reg = ResolveRegister(op_code, REG_MASK(next_byte));
                const char* dest_reg = ResolveRM(&cursor, op_code, next_byte);

                bool d = D_MASK(op_code);
                if (d) {
                    const char* temp = src_reg;
                    src_reg = dest_reg;
                    dest_reg = temp;
                }

                AsmWriterEmit(&writer, "mov");
                AsmWriterEmit(&writer, " ");
                AsmWriterEmit(&writer, dest_reg);
                AsmWriterEmit(&writer, ", ");
                AsmWriterEmit(&writer, src_reg);
                break;
            }
            case 0xB0: {
                ParseIm8ToReg(&cursor, &writer, "al");
                break;
            }
            case 0xB1: {
                ParseIm8ToReg(&cursor, &writer, "cl");
                break;
            }
            case 0xB2: {
                ParseIm8ToReg(&cursor, &writer, "dl");
                break;
            }
            case 0xB3: {
                ParseIm8ToReg(&cursor, &writer, "bl");
                break;
            }
            case 0xB4: {
                ParseIm8ToReg(&cursor, &writer, "ah");
                break;
            }
            case 0xB5: {
                ParseIm8ToReg(&cursor, &writer, "ch");
                break;
            }
            case 0xB6: {
                ParseIm8ToReg(&cursor, &writer, "dh");
                break;
            }
            case 0xB7: {
                ParseIm8ToReg(&cursor, &writer, "bh");
                break;
            }
            case 0xB8: {
                ParseIm16ToReg(&cursor, &writer, "ax");
                break;
            }
            case 0xB9: {
                ParseIm16ToReg(&cursor, &writer, "cx");
                break;
            }
            case 0xBA: {
                ParseIm16ToReg(&cursor, &writer, "dx");
                break;
            }
            case 0xBB: {
                ParseIm16ToReg(&cursor, &writer, "bx");
                break;
            }
            case 0xBC: {
                ParseIm16ToReg(&cursor, &writer, "sp");
                break;
            }
            case 0xBD: {
                ParseIm16ToReg(&cursor, &writer, "bp");
                break;
            }
            case 0xBE: {
                ParseIm16ToReg(&cursor, &writer, "si");
                break;
            }
            case 0xBF: {
                ParseIm16ToReg(&cursor, &writer, "di");
                break;
            }
            default: {
                fprintf(stderr, "Unknown opcode: %x\n", op_code);
                no_error = 0;
            }
        }
        AsmWriterEmitInstructionEnd(&writer);
    }

    AsmWriterEmitInstructionStreamEnd(&writer);
    printf("%s", writer.output);
}
