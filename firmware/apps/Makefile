#
#   Makefile for MatrixSSL example apps
#
#	Copyright (c) 2013-2015 INSIDE Secure Corporation. All Rights Reserved.
#

include ../common.mk

STATICS		= ../matrixssl/libssl_s$(A) ../crypto/libcrypt_s$(A) ../core/libcore_s$(A)

SERVER_EXE 	= server$(E) 
CLIENT_EXE 	= client$(E) 
OBJS = http$(O)
SERVER_OBJS = server$(O) $(OBJS)
CLIENT_OBJS = client$(O) $(OBJS)

#
#	Compile options
#
CFLAGS += -I.. -I../crypto

all: compile

compile: $(SERVER_EXE) $(CLIENT_EXE)

$(SERVER_EXE):$(SERVER_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(STATICS) $(LDFLAGS)

$(CLIENT_EXE):$(CLIENT_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(STATICS) $(LDFLAGS)

#
#	Clean up all generated files
#
clean:
	rm -f $(SERVER_EXE) $(SERVER_OBJS) $(CLIENT_EXE) $(CLIENT_OBJS)
