# Compiler
ifeq ($(OS), Windows_NT)
	$(error Windows is not supported)
endif

CC = gcc

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
TEST_DIR = tests
TEST_BUILD_DIR = build/tests

LDFLAGS = -lssl -lcrypto -lsqlite3 -ljansson
CFLAGS = -O2 -Wall -Werror -Wextra -I$(SRC_DIR) -I./include -pthread -g  
TEST_CFLAGS = $(CFLAGS) -I./tests
ifeq ($(shell uname), Darwin)
HOMEBREW_PREFIX := $(shell brew --prefix openssl@3)
JANSSON_PREFIX := $(shell brew --prefix jansson)
	ifeq ($(HOMEBREW_PREFIX),)
		$(error openssl@3 is not installed, make sure its installed with `brew install openssl@3`)
	endif
	ifeq ($(JANSSON_PREFIX),)
		$(error jansson is not installed, make sure its installed with `brew install jansson`)
	endif

	CFLAGS += -I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/jansson/include -fsanitize=thread,undefined
	LDFLAGS += -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/jansson/lib
endif
# Export dynamic symbols on Linux
ifeq ($(shell uname), Linux)
ifndef NO_SANITIZE
	CFLAGS += -Wl,--export-dynamic -fsanitize=thread,undefined,bounds
else
	CFLAGS += -Wl,--export-dynamic
endif
endif
ifdef PRODUCTION
CFLAGS += -DPRODUCTION
endif

SRCS = $(wildcard $(SRC_DIR)/*.c) 
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/cweb

TEST_SRCS = $(TEST_DIR)/test_main.c \
	$(TEST_DIR)/test_jobs.c \
	$(TEST_DIR)/test_db.c \
	$(TEST_DIR)/test_scheduler.c \
	$(TEST_DIR)/test_helpers.c \
	$(TEST_DIR)/test_stubs.c \
	$(LIB_DIR)/http.c \
	$(SRC_DIR)/jobs.c \
	$(SRC_DIR)/db.c \
	$(SRC_DIR)/scheduler.c \
	$(SRC_DIR)/map.c \
	$(SRC_DIR)/list.c \
	$(SRC_DIR)/uuid.c

TEST_OBJS = $(patsubst %.c, $(TEST_BUILD_DIR)/%.o, $(TEST_SRCS))
TEST_TARGET = $(BIN_DIR)/cweb_tests

# Library
LIB_DIR = libs
LIB_SRCS = libs/module.c src/map.c src/uuid.c
LIB_OBJS = $(patsubst $(LIB_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRCS))
LIB_TARGET = $(LIB_DIR)/libmodule.so
HTTP_LIB_SRCS = libs/http.c
HTTP_LIB_OBJS = $(patsubst $(LIB_DIR)/%.c, $(BUILD_DIR)/%.o, $(HTTP_LIB_SRCS))
HTTP_LIB_TARGET = $(LIB_DIR)/libhttp.so

all: $(LIB_TARGET) $(HTTP_LIB_TARGET) $(TARGET)

$(TARGET): $(OBJS) ${LIB_DIR}/libevent.so $(HTTP_LIB_TARGET)
	@mkdir -p $(BIN_DIR)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

$(LIB_TARGET): $(LIB_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -I./include -fPIC -shared -o $@ $^

$(BUILD_DIR)/%.o: $(LIB_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

$(HTTP_LIB_TARGET): $(HTTP_LIB_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -I./include -fPIC -shared -o $@ $^

${LIB_DIR}/libevent.so: ${LIB_DIR}/libevent.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $^

tests: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f $(LIB_TARGET) libs/libevent.so $(HTTP_LIB_TARGET)

purge:
	rm -rf ./modules/*.so
	rm -rf ./modules/routes.dat

run: all
	$(TARGET)


.PHONY: all clean run tests
