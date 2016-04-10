################################################
# Toplevel makefile for all Cortex-M targets   #
################################################

ifeq ($(V),)
    Q := @
    # Do not print "Entering directory ...".
    MAKEFLAGS += --no-print-directory
endif

# Use the size optimised nano version of newlib.
# This usually is the version of newlib you want to use, although it has some
# limitations, like printf not having support for floating point vars.
# This relies on your newlib installation to provide a working nano.specs
# file. On Debian you will need at least version 2.1.0+git20141201.db59ff3-2
# of package libnewlib-arm-none-eabi
USE_NANO    := true

# Debian's libnewlib-arm-none-eabi package version 2.2.0+git20150830.5a3d536-1
# ships with a buggy nano.specs file that does not set up a proper include
# path for finding the nano version of newlib.h.
# Also, the nano version has been built with the -fshort-wchar option, making
# it incompatible with object files using the standard ABI. By enabling this
# option atomthreads and libopencm3 will also be compiled with -fshort-wchar.
#FIX_DEBIAN  := true

# Build directory
ifdef O
    build_dir=$(shell readlink -f $(O))
else
    build_dir=$(CURDIR)/build
endif

# Source directory
src_dir=$(CURDIR)

# Clean object list before including board makefile
objs := 
aobjs :=

# set default board if none is given
ifeq ($(BOARD),)
    BOARD = nl6621-y1
endif

# set default target if none is given
ifeq ($(TARGET),)
    TARGET = nl6621
endif

# set basename of locm3 target library to use
LIBNAME := libopencm3_$(TARGET)

# Configure toolchain
CROSS_COMPILE   ?=  arm-none-eabi-

CC      := $(CROSS_COMPILE)gcc
CXX     := $(CROSS_COMPILE)g++
LD      := $(CROSS_COMPILE)gcc
AR      := $(CROSS_COMPILE)ar
AS      := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump
GDB     := $(CROSS_COMPILE)gdb
STFLASH  = $(shell which st-flash)



# Check if user wants to use external opencm3 lib or if we have to build
# it ourselves
ifeq ($(OPENCM3_DIR),)
    OPENCM3_DIR = $(src_dir)/libopencm3
    build_lib = true
endif

ifneq ($(V),)
    $(info Using $(OPENCM3_DIR) as path to opencm3 library)
endif


# Set up search paths for libopencm3
INCLUDE_DIR = $(OPENCM3_DIR)/include
LIB_DIR     = $(OPENCM3_DIR)/lib
SCRIPT_DIR  = $(OPENCM3_DIR)/scripts

# GCC flags
CFLAGS       =  -Os -g
CFLAGS      += -Wall -Werror
CFLAGS      += -Wredundant-decls -Wstrict-prototypes
CFLAGS      += -fno-common -ffunction-sections -fdata-sections

# Enable stack-checking (disable if not required)
ifeq ($(STACK_CHECK),true)
    CFLAGS  += -DATOM_STACK_CHECKING -DTESTS_LOG_STACK_USAGE
endif

# C & C++ preprocessor common flags
CPPFLAGS    += -MD
CPPFLAGS    += -Wall -Wundef -Werror
CPPFLAGS    += -I$(INCLUDE_DIR) $(DEFS)
CPPFLAGS    += -I$(board_dir) -I$(common_dir) -I$(src_dir) -I$(kernel_dir) -I$(tests_dir)

# Assembler flags
ASFLAGS     += -D__ASSEMBLY__ 
ASFLAGS     += -D__NEWLIB__

# Linker flags
LDFLAGS     += --static -nostartfiles
LDFLAGS     += -L$(LIB_DIR)
LDFLAGS     += -T$(LDSCRIPT)
LDFLAGS     += -Wl,-Map=$(build_dir)/$(*).map
LDFLAGS     += -Wl,--gc-sections
LDFLAGS     += -Wl,--fatal-warnings
ifeq ($(V),99)
LDFLAGS     += -Wl,--print-gc-sections
endif

## Used libraries
# Target specific version libopencm3
LDLIBS		+= -l$(LIBNAME)

## Gather newlib libraries and set up specfiles.
NEWLIBS	    += -lc -lgcc

ifeq ($(USE_NANO),true)
SPECS       := -specs=nano.specs

ifeq ($(FIX_DEBIAN),true)
SPECS       += -I/usr/include/newlib/nano
LOCM3_FLAGS += -fshort-wchar
CFLAGS      += -fshort-wchar
endif
endif

# add all required newlib libraries as a group
LDLIBS      += -Wl,--start-group $(NEWLIBS) -Wl,--end-group

.PHONY: all
all: build_all

.PHONY: build_all
build_all: atomthreads tools

# Add build dependency for local libopencm3 if no external libopencm3 is used 
ifeq ($(build_lib),true)
$(LIB_DIR)/$(LIBNAME).a: 
	$(Q)if [ ! -f libopencm3/Makefile ] ; then \
		printf "######## ERROR ########\n"; \
		printf "\tlibopencm3 is not initialized.\n"; \
		printf "\tPlease run:\n"; \
		printf "\t$$ git submodule init\n"; \
		printf "\t$$ git submodule update\n"; \
		printf "\tbefore running make.\n"; \
		printf "######## ERROR ########\n"; \
		exit 1; \
	fi
	$(Q)$(MAKE) -C libopencm3 V=$(V) CROSS_COMPILE=$(CROSS_COMPILE) \
		CFLAGS=$(LOCM3_FLAGS)
endif

$(build_dir):
	$(Q)mkdir -p $@

.PHONY: tools
tools:
	$(Q)$(MAKE) V=$(V) -C tools all

.PHONY: tools_clean
tools_clean:
	$(Q)$(MAKE) V=$(V) -C tools clean

atomthreads: $(build_dir)/atomkernel.o

$(build_dir)/atomkernel.o: atomthreads_build

.PHONY: atomthreads_build
atomthreads_build: $(LIB_DIR)/$(LIBNAME).a atomthreads_init $(build_dir)
	$(Q)$(MAKE) -C atomthreads/ports/cortex-m V=$(V) O=$(build_dir) \
		BOARD=$(BOARD) CROSS_COMPILE=$(CROSS_COMPILE)               \
		OPENCM3_DIR=$(OPENCM3_DIR) USE_NANO=$(USE_NANO)             \
		FIX_DEBIAN=$(FIX_DEBIAN) all 

.PHONY: atomthreads_clean
atomthreads_clean:
	$(Q)$(MAKE) -C atomthreads/ports/cortex-m V=$(V) O=$(build_dir) \
		BOARD=$(BOARD) CROSS_COMPILE=$(CROSS_COMPILE)               \
		OPENCM3_DIR=$(OPENCM3_DIR) USE_NANO=$(USE_NANO)             \
		FIX_DEBIAN=$(FIX_DEBIAN) clean

atomthreads_init: 
	$(Q)if [ ! -f atomthreads/README ] ; then \
		printf "######## ERROR ########\n"; \
		printf "\tatomthreads is not initialized.\n"; \
		printf "\tPlease run:\n"; \
		printf "\t$$ git submodule init\n"; \
		printf "\t$$ git submodule update\n"; \
		printf "\tbefore running make.\n"; \
		printf "######## ERROR ########\n"; \
		exit 1; \
	fi

# Clean. Remove only tools and atomthread's object files and images
.PHONY: clean
clean: atomthreads_clean tools_clean
	$(Q)rm -rf $(build_dir)

# Real clean. Also clean libopencm3 if it was built in tree
.PHONY: realclean
realclean: clean
ifeq ($(build_lib),true)
	$(Q)$(MAKE) -C libopencm3 V=$(V) clean
endif

# Docs
.PHONY: doxygen
doxygen:
ifeq ($(build_lib),true)
	$(Q)$(MAKE) -C libopencm3 V=$(V) doc
endif


