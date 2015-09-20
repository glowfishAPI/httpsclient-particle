#
#	makefile for crypto testing
#
#

include ../../common.mk

STATICS     = ../libcrypt_s$(A) ../../core/libcore_s$(A)

BASE_DIR=../..

VECTOR_EXE 	= algorithmTest$(E)
VECTOR_OBJS	= algorithmTest$(O)
SPEED_EXE 	= throughputTest$(E)
SPEED_OBJS 	= throughputTest$(O)
RSAPERF_EXE 	= ./rsaperf/rsaperf$(E)
RSAPERF_OBJS	= ./rsaperf/rsaperf$(O)
DHPERF_EXE 	= ./dhperf/dhperf$(E)
DHPERF_OBJS	= ./dhperf/dhperf$(O)
ECCPERF_EXE 	= ./eccperf/eccperf$(E)
ECCPERF_OBJS	= ./eccperf/eccperf$(O)

#
#	Compile options
#
CFLAGS  += -I$(BASE_DIR) -I..

all: compile

compile: $(SPEED_EXE) $(VECTOR_EXE) $(RSAPERF_EXE) $(DHPERF_EXE) $(ECCPERF_EXE)

$(SPEED_EXE):$(SPEED_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS) $(STATICS)

$(VECTOR_EXE):$(VECTOR_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS) $(STATICS)

$(RSAPERF_EXE):$(RSAPERF_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS) $(STATICS)

$(DHPERF_EXE):$(DHPERF_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS) $(STATICS)

$(ECCPERF_EXE):$(ECCPERF_OBJS) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS) $(STATICS)

#
#	Clean up all generated files
#
clean:
	rm -f $(SPEED_EXE) $(SPEED_OBJS) $(VECTOR_EXE) $(VECTOR_OBJS) $(RSAPERF_EXE) $(RSAPERF_OBJS) $(DHPERF_EXE) $(DHPERF_OBJS) $(ECCPERF_EXE) $(ECCPERF_OBJS)
