#
#	Makefile for core static library
#
#	Copyright (c) 2013-2015 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=..
# @note SRC is not defined here as simply expanded, because OSDEP is defined by common.mk
SRC=\
	memset_s.c \
	corelib.c \
	$(OSDEP)/osdep.c

include $(MATRIXSSL_ROOT)/common.mk

# Generated files
STATIC:=libcore_s.a

all: compile

compile: $(OBJS) $(STATIC)

# Special rule to build memset_s function without optimization
# Also generate the assembly file for info
memset_s.o: memset_s.c
	$(CC) -O0 -Wall -ffunction-sections -fdata-sections -o memset_s.o -c memset_s.c
	$(CC) -O0 -g -fverbose-asm -S memset_s.c

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile *.h

# Build the static library
# Redirect stderr to null so we don't see the 'empty file' warnings
$(STATIC): $(OBJS)
	$(AR) -rcuv $@ $^ 2>/dev/null

clean:
	rm -f $(STATIC) $(OBJS) memset_s.s

