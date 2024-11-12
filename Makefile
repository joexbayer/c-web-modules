# Compiler
CC = gcc

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

CFLAGS = -Wall -Wextra -I$(SRC_DIR) -I./include -pthread -fsanitize=thread,undefined -g
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/cweb

# Library
LIB_DIR = libs
LIB_SRCS = src/map.c
LIB_OBJS = $(patsubst $(LIB_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRCS))
LIB_TARGET = $(LIB_DIR)/libmap.so

all: $(TARGET) $(LIB_TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB_TARGET): $(LIB_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) -I./include -fPIC -shared -o $@ $^

$(BUILD_DIR)/%.o: $(LIB_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

run: $(TARGET)
	$(TARGET)


.PHONY: all clean run