#
#	Makefile for MatrixSSL testing
#
#	Copyright (c) 2013-2015 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..
TEST_SRC:=sslTest.c
CERT_SRC:=certValidate.c
SRC:=$(TEST_SRC) $(CERT_SRC)

include $(MATRIXSSL_ROOT)/common.mk

# Generated files
CERT_EXE:=certValidate$(E)
TEST_EXE:=sslTest$(E)

# Linked files
STATIC:=../libssl_s.a $(MATRIXSSL_ROOT)/crypto/libcrypt_s.a $(MATRIXSSL_ROOT)/core/libcore_s.a



all: compile

compile: $(OBJS) $(CERT_EXE) $(TEST_EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(TEST_EXE): $(TEST_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

$(CERT_EXE):$(CERT_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TEST_EXE) $(CERT_EXE) $(OBJS)

