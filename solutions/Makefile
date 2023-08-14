# Thanks to Job Vranish (https://spin.atomicobject.com/2016/08/26/makefile-c-projects/)
TARGET_EXEC := main

BUILD_DIR := ./build
SRC_DIRS := ./src
LIB_DIR := ./libs
SIM86_DIR := ../perfaware/sim86

LIBS := ""
LDFLAGS := $(shell pkg-config --cflags --libs $(LIBS))
LDFLAGS := $(LDFLAGS) -lm -lsim86 -L/usr/local/lib/sim86/

# Find all the C and C++ files we want to compile
# Note the single quotes around the * expressions. Make will incorrectly expand these otherwise.
# SRCS := $(shell find $(SRC_DIRS) -name '*.cpp' -or -name '*.c' -or -name '*.s')
SRCS := $(SRC_DIRS)/main.c

# String substitution for every C/C++ file.
# As an example, hello.cpp turns into ./build/hello.cpp.o
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

# String substitution (suffix version without %).
# As an example, ./build/hello.cpp.o turns into ./build/hello.cpp.d
DEPS := $(OBJS:.o=.d)

# Every folder in ./src will need to be passed to GCC so that it can find header files
INC_DIRS := $(shell find $(SRC_DIRS) -type d)
# Add a prefix to INC_DIRS. So moduleA would become -ImoduleA. GCC understands this -I flag
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

# The -MMD and -MP flags together generate Makefiles for us!
# These files will have .d instead of .o as the output.
CPPFLAGS := $(INC_FLAGS) -MMD -MP -g -Wall

BTFLAGS := -D BT_INTERNAL=1 -DBT_SLOW=1

# The final build step.
$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Build step for C source
$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(BTFLAGS) -c $< -o $@ $(LDFLAGS)


.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

scratch: $(BUILD_DIR)/$(TARGET_EXEC)
	nasm ../perfaware/part1/bt_scratch.asm -o $(BUILD_DIR)/scratch
	gdb -ex run --args $(BUILD_DIR)/$(TARGET_EXEC) $(BUILD_DIR)/scratch

test_parse: $(BUILD_DIR)/$(TARGET_EXEC)
	./test.sh 37
	./test.sh 38
	./test.sh 39
	./test.sh 40
	./test.sh 41

test: $(BUILD_DIR)/$(TARGET_EXEC)
	./test.sh 43 simstate
	./test.sh 44 simstate
	./test.sh 45 simstate
	./test.sh 46 simstate
	./test.sh 47 simstate
	./test.sh 48 printip
	./test.sh 49 printip

# Instructions for building were taken from comments on using decoder as shared lib post.
# Had to modify sim86_shared.h slightly to get it to compile with C.
sim86:
	mkdir -p $(LIB_DIR)/sim86; \
	cd $(SIM86_DIR); \
	pwd; \
	clang++ -c -fPIC -o sim86_shared.o sim86_lib.cpp; \
	clang++ -shared sim86_shared.o -o libsim86.so;
	
	#cp $(SIM86_DIR)/libsim86.so $(LIB_DIR)/sim86/;
	# Also need to add /usr/local/lib to /etc/ld.so.conf and run ldconfig again
	sudo cp $(SIM86_DIR)/libsim86.so /usr/local/lib/libsim86.so
	# cp $(SIM86_DIR)/shared/sim86_shared.h $(LIB_DIR)/sim86/;

# Include the .d makefiles. The - at the front suppresses the errors of missing
# Makefiles. Initially, all the .d files will be missing, and we don't want those
# errors to show up.
-include $(DEPS)