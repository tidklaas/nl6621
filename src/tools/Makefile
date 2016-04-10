################################################
# Toplevel makefile for all tools              #
################################################

ifeq ($(V),)
    Q := @
    # Do not print "Entering directory ...".
    MAKEFLAGS += --no-print-directory
endif

# Source directory
src_dir=$(CURDIR)
CC      = gcc  
CFLAGS  += -W -Wall -Wextra -Wpedantic   

SRC     := $(wildcard *.c)  
OBJ     := $(SRC:.c=.o)  
DEP     := $(SRC:.c=.d)  
BINS    := genfw

-include $(DEP)

.PHONY: clean

all: genfw  

genfw: genfw.o

clean:  
	$(Q)rm -f $(OBJ) $(DEP) genfw
