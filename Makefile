# Compiler
ifeq ($(OS), Windows_NT)
	$(error Windows is not supported)
endif

CC = gcc

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

LDFLAGS = -lssl -lcrypto -lsqlite3 -ljansson
CFLAGS = -O2 -Wall -Werror -Wextra -I$(SRC_DIR) -I./include -pthread -g 
ifeq ($(shell uname), Darwin)
HOMEBREW_PREFIX := $(shell brew --prefix openssl@3)
	ifeq ($(HOMEBREW_PREFIX),)
		$(error openssl@3 is not installed, make sure its installed with `brew install openssl@3`)
	endif
	CFLAGS += -I/opt/homebrew/opt/openssl@3/include -fsanitize=thread,undefined
	LDFLAGS += -L/opt/homebrew/opt/openssl@3/lib
endif

# Export dynamic symbols on Linux
ifeq ($(shell uname), Linux)
	CFLAGS += -Wl,--export-dynamic -fsanitize=thread,undefined,bounds
endif

SRCS = $(wildcard $(SRC_DIR)/*.c) 
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/cweb

# Library
LIB_DIR = libs
LIB_SRCS = libs/module.c src/map.c
LIB_OBJS = $(patsubst $(LIB_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRCS))
LIB_TARGET = $(LIB_DIR)/libmodule.so

all: $(LIB_TARGET) $(TARGET)

$(TARGET): $(OBJS) ${LIB_DIR}/libevent.so
	@mkdir -p $(BIN_DIR)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB_TARGET): $(LIB_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -I./include -fPIC -shared -o $@ $^

$(BUILD_DIR)/%.o: $(LIB_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

${LIB_DIR}/libevent.so: ${LIB_DIR}/libevent.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $^

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f $(LIB_TARGET) libs/libevent.so

run: all
	$(TARGET)


.PHONY: all clean run