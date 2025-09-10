# ARM64 macOS/Darwin specific Makefile for probe-busybox
# This file handles macOS-specific compilation issues on ARM64

# Remove unsupported compiler flags for clang on macOS
CFLAGS := $(filter-out -finline-limit=0,$(CFLAGS))
CFLAGS := $(filter-out -falign-jumps=1,$(CFLAGS))
CFLAGS := $(filter-out -falign-labels=1,$(CFLAGS))
CFLAGS := $(filter-out -falign-loops=1,$(CFLAGS))
CFLAGS := $(filter-out -static-libgcc,$(CFLAGS))

# Add macOS-specific flags
CFLAGS += -D_DARWIN_C_SOURCE=1

# Ensure we're using the right compiler
CC ?= clang
HOSTCC ?= clang

# Disable problematic optimizations that don't work well on macOS
CFLAGS += -fno-strict-aliasing

# Add macOS-specific include paths if needed
CFLAGS += -I/usr/local/include

# Ensure proper linking on macOS
LDFLAGS += -L/usr/local/lib

# ARM64 specific optimizations that work with clang
CFLAGS += -march=armv8-a
