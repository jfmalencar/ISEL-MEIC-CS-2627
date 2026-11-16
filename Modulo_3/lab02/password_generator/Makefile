
# Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
# Project      : Cybersecurity (Module 3 - Hardware Security): Lab 2
# Author       : Tiago M. Dias (tiago.dias@isel.pt)
# File         : Makefile
# Created      : 2026-11-09
# Last modified: 2026-11-09
# Description  : Build and execution rules for the password generator.
#

# Application files and directories
APP_NAME := password_generator
APP_DIR  := application
APP_SRC  := $(APP_DIR)/src/app.c
APP_BIN  := $(APP_DIR)/bin/$(APP_NAME)
APP_OBJ  := $(APP_DIR)/obj/app.o

# Compiler and build options
CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS := -I$(APP_DIR)/inc
LDFLAGS  :=

# Default arguments used by the run target
RUN_ARGS ?= -g -l 16

# Build the application
.PHONY: all run clean
all: $(APP_BIN)

# Compile the C source file into an object file
$(APP_OBJ): $(APP_SRC) $(APP_DIR)/inc/app.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Link the object file to produce the executable
$(APP_BIN): $(APP_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ -o $@

# Compile and execute the application
run: all
	@./$(APP_BIN) $(RUN_ARGS)

# Remove generated files
clean:
	@rm -f $(APP_OBJ) $(APP_BIN)

