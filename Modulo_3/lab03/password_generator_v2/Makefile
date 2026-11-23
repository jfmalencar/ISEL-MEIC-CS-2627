# Institution  : Instituto Superior de Engenharia de Lisboa (ISEL)
# Project      : Cybersecurity (Module 3 - Hardware Security): Lab 3
# Author       : Tiago M. Dias (tiago.dias@isel.pt)
# File         : Makefile
# Created      : 2026-11-16
# Last modified: 2026-11-16
# Description  : Build and execution rules for the password generator.
#

# Application files and directories
APP_NAME := password_generator
APP_DIR  := application
APP_SRC  := $(APP_DIR)/src/app.c $(APP_DIR)/src/file_io.c
APP_OBJ  := $(APP_DIR)/obj/app.o $(APP_DIR)/obj/file_io.o
APP_BIN  := $(APP_DIR)/bin/$(APP_NAME)

# Compiler and build options
CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS := -I$(APP_DIR)/inc
LDFLAGS  :=

# Default arguments used by the run target
RUN_ARGS ?= -g -l 16

.PHONY: all run clean

# Build the application
all: $(APP_BIN)

# Compile the application and file-handling source files
$(APP_DIR)/obj/app.o: $(APP_DIR)/src/app.c $(APP_DIR)/inc/app.h $(APP_DIR)/inc/file_io.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(APP_DIR)/obj/file_io.o: $(APP_DIR)/src/file_io.c $(APP_DIR)/inc/file_io.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Link the application executable
$(APP_BIN): $(APP_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ -o $@

# Compile and run from the application's binary directory
run: all
	@cd $(APP_DIR)/bin && ./$(APP_NAME) $(RUN_ARGS)

# Remove generated files
clean:
	@rm -f $(APP_OBJ) $(APP_BIN)
