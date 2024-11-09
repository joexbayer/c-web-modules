# Compiler
CC = gcc

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

CFLAGS = -Wall -Wextra -I$(SRC_DIR)
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/my_program

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

run: $(TARGET)
	$(TARGET)

.PHONY: all clean