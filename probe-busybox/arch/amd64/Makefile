# AMD64 specific Makefile for probe-busybox
# This file handles AMD64-specific compilation issues with clang on FreeBSD

# Remove unsupported compiler flags for clang on FreeBSD
CFLAGS := $(filter-out -finline-limit=0,$(CFLAGS))
CFLAGS := $(filter-out -falign-jumps=1,$(CFLAGS))
CFLAGS := $(filter-out -falign-labels=1,$(CFLAGS))
CFLAGS := $(filter-out -falign-loops=1,$(CFLAGS))
CFLAGS := $(filter-out -static-libgcc,$(CFLAGS))

# Add FreeBSD-specific flags
CFLAGS += -D_FREEBSD_C_SOURCE=1

# Ensure we're using the right compiler (allow override from environment)
CC ?= cc
HOSTCC ?= cc

# Disable problematic optimizations that don't work well with clang
CFLAGS += -fno-strict-aliasing

# Add FreeBSD-specific include paths if needed
CFLAGS += -I/usr/local/include

# Ensure proper linking on FreeBSD
LDFLAGS += -L/usr/local/lib

# AMD64 specific optimizations that work with clang
CFLAGS += -march=native

