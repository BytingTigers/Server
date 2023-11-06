# Compiler and Linker
CC := gcc
LD := gcc

# Directories
SRC_DIR := src
BUILD_DIR := build

# Flags
CFLAGS := -Wall -Wextra -I$(SRC_DIR)
LDFLAGS := -pthread
LIBS := -lhiredis -ljwt

# Files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Targets
all: start

start: $(OBJS)
	$(LD) $^ -o $@ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: all clean

clean:
	rm -rf $(BUILD_DIR)/* start
