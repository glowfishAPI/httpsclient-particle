#
#

include ../../../common.mk

STATICS = ../../libcrypt_s$(A) ../../../core/libcore_s$(A)

MATRIX_DIR=../../..

REF_EXE 	= eccperf$(E)
REF_OBJS 	= eccperf$(O)

#
#	Compile options
#
CFLAGS  += -I$(MATRIX_DIR) -I../..

all: compile

compile: $(REF_OBJS) $(REF_EXE)

$(REF_EXE):$(REF_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(STATICS)
	$(STRIP) $(REF_EXE)

#
#	Clean up all generated files
#
clean:
	rm -f $(REF_EXE) $(REF_OBJS)
