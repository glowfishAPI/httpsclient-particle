#
#	Makefile for crypto static library

#	Copyright (c) 2013-2015 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=..
SRC:=\
	prng/prng.c \
	prng/yarrow.c \
	symmetric/aes.c \
	symmetric/aesGCM.c \
	symmetric/des3.c \
	symmetric/seed.c \
	symmetric/arc4.c \
	symmetric/rc2.c \
	symmetric/idea.c \
	digest/sha1.c \
	digest/sha256.c \
	digest/sha224.c \
	digest/sha384.c \
	digest/sha512.c \
	digest/md5.c \
	digest/md4.c \
	digest/md2.c \
	digest/hmac.c \
	hardware/aesni.c \
	math/pstm.c \
	math/pstm_montgomery_reduce.c \
	math/pstm_sqr_comba.c \
	math/pstm_mul_comba.c \
	pubkey/pubkey.c \
	pubkey/rsa.c \
	pubkey/ecc.c \
	pubkey/dh.c \
	pubkey/pkcs.c \
	keyformat/asn1.c \
	keyformat/base64.c \
	keyformat/x509.c






include ../common.mk

# Generated files
STATIC:=libcrypt_s.a

all: compile

compile: $(OBJS) $(STATIC)
	@echo $(STROPTS)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile *.h */*.h

# Build the static library
# Direct stderr to null so we don't see the 'empty file' warnings
$(STATIC): $(OBJS)
	$(AR) -rcuv $@ $^ 2>/dev/null

clean:
	rm -f $(STATIC) $(OBJS)

