##
#	Common Makefile definitions.
#	Copyright (c) INSIDE Secure, 2012-2015. All Rights Reserved.
#

#-------------------------------------------------------------------------------
## Makefile variables that must be defined in this file
# @param[out] $(BUILD) Set here for release or debug
BUILD:=release  ##< Release build strips binary and optimizes
#BUILD:=debug 	##< Debug build keeps debug symbols and disables compiler optimizations. Assembly language optimizations remain enabled
# @param[out] $(PKCS11_LIB) Optional path and names of PKCS11 libraries

#-------------------------------------------------------------------------------
## Makefile variables that are read by this file.
# @param[in] $(MATRIXSSL_ROOT) Must be set to root MatrixSSL directory
# @param[in] $(CC) Used to determine the target platform, which will differ from host if cross compiling.
# @param[in] $(CPU) If set, should be the target cpu for the compiler, suitable for the '-mcpu=' flag. See 'gcc --help=target' for valid values.

#-------------------------------------------------------------------------------
## Makefile variables that are modified by this file
# @param[in,out] $(CFLAGS) Appended with many options as determined by this file, to be passed to compiler
# @param[in,out] $(LDFLAGS) Appended with many options as determined by this file, to be passed to linker

#-------------------------------------------------------------------------------
## Makefile variables that are created by this file
# @param[out] $(OSDEP) Set to platform code directory (./core/$OSDEP/osdep.c), based on $(CC)
# @param[out] $(CCARCH) Set to compiler's target architecture, based on $(CC)
# @param[out] $(STRIP) Set to the executable to use to strip debug symbols from executables
# @param[out] $(STROPS) Human readable description of relevant MatrixSSL compile options.
# @param[out] $(O) Set to the target platform specific object file extension
# @param[out] $(A) Set to the target phatform specific static library (archive) file extension
# @param[out] $(E) Set to the target platform specific executable file extension

#-------------------------------------------------------------------------------

## Set the directory path that contains the core, crypto and matrixssl directories.
# @note MAKEFILE_LIST is set by make to list of parsed Makefiles so far.
#  We get the last one in the list (this file), remove the filename,
#  and remove the trailing '/'
#MATRIXSSL_ROOT:=$(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

## Based on the value of CC, determine the target, eg.
#  x86_64-redhat-linux
#  i686-linux-gnu
#  x86_64-apple-darwin14.0.0
#  arm-linux-gnueabi
#  arm-linux-gnueabihf
#  arm-none-eabi
#  mips-linux-gnu
#  powerpc-linux-gnu
CCARCH:=$(shell $(CC) -v 2>&1 | sed -n '/Target: / s/// p')
STROPTS:="Built for $(CCARCH)"

## uname of the Host environment, eg.
#  Linux
#  Darwin
# @note Unused
#UNAME:=$(shell uname)

## Standard file extensions for Linux/OS X.
O:=.o
A:=.a
E=

# Check if this version of make supports undefine
ifneq (,$(findstring undefine,$(.FEATURES)))
 HAVE_UNDEFINE:=1
endif

ifdef MATRIX_DEBUG
 CFLAGS+=-O0 -g -DDEBUG -Wall
 STRIP:=test # no-op
else
 ifneq (,$(findstring -none,$(CCARCH)))
  CFLAGS+=-Os -Wall	# Compile bare-metal for size
 else
  CFLAGS+=-O3 -Wall	# Compile all others for speed
 endif
 STRIP:=strip
endif

ifneq (,$(findstring -linux,$(CCARCH)))
 JOBS:=-j$(shell grep -c processor /proc/cpuinfo)
else ifneq (,$(findstring apple,$(CCARCH)))
 JOBS:=-j$(shell sysctl -n machdep.cpu.thread_count)
endif

default: $(BUILD)

debug:
	@$(MAKE) compile "MATRIX_DEBUG=1"

release:
	@$(MAKE) $(JOBS) compile



# 64 Bit Intel Target
ifneq (,$(findstring x86_64-,$(CCARCH)))
 CFLAGS+=-m64
 STROPTS+=", 64-bit Intel RSA/ECC ASM"
 # Enable AES-NI if the host supports it (assumes Host is Target)
 ifneq (,$(findstring -linux,$(CCARCH)))
  ifeq ($(shell grep -o -m1 aes /proc/cpuinfo),aes)
   CFLAGS+=-maes -mpclmul -msse4.1
   STROPTS+=", AES-NI ASM"
  endif
 else ifneq (,$(findstring apple,$(CCARCH)))
  ifeq ($(shell sysctl -n hw.optional.aes),1)
   CFLAGS+=-maes -mpclmul -msse4.1
   STROPTS+=", AES-NI ASM"
  endif
 endif

# 32 Bit Intel Target
else ifneq (,$(findstring i686-,$(CCARCH)))
 CFLAGS+=-m32
 STROPTS+=", 32-bit Intel RSA/ECC ASM"

# ARM Target
else ifneq (,$(findstring arm-,$(CCARCH)))
 STROPTS+=", 32-bit ARM RSA/ECC ASM"
 ifneq (,$(findstring arm-linux,$(CCARCH)))
  HARDWARE:=$(shell sed -n '/Hardware[ \t]*: / s/// p' /proc/cpuinfo)
  # Raspberry Pi Host and Target
  ifneq (,$(findstring BCM2708,$(HARDWARE)))
   CFLAGS+=-mfpu=vfp -mfloat-abi=hard -ffast-math -march=armv6zk -mtune=arm1176jzf-s
   STROPTS+=", Raspberry Pi"
  endif
  # Beagleboard/bone Host and Target
  ifneq (,$(findstring AM33XX,$(HARDWARE)))
   CFLAGS+=-mfpu=neon -mfloat-abi=hard -ffast-math -march=armv7-a -mtune=cortex-a8
   STROPTS+=", Beagleboard"
  endif
  ifdef HAVE_UNDEFINE
   undefine HARDWARE
  endif
 endif

endif

CFLAGS+=-ffunction-sections -fdata-sections -fomit-frame-pointer

# If we're using clang (it may be invoked via 'cc' or 'gcc'),
#  handle minor differences in compiler behavior vs. gcc
ifeq ($(shell $(CC) --version | grep -o clang),clang)
 CFLAGS+=-Wno-error=unused-variable -Wno-error=\#warnings -Wno-error=\#pragma-messages
endif

# Handle differences between the OS X ld and GNU ld
ifneq (,$(findstring -apple,$(CCARCH)))
 LDFLAGS+=-Wl,-dead_strip
else
 LDFLAGS+=-Wl,--gc-sections
endif

CFLAGS+=-I$(MATRIXSSL_ROOT)

# Linux Target
ifneq (,$(findstring -linux,$(CCARCH)))
 OSDEP:=POSIX
 CFLAGS+=-I/usr/include

# OS X Target
else ifneq (,$(findstring -apple,$(CCARCH)))
 OSDEP:=POSIX
 CFLAGS+=-isystem -I/usr/include

# Bare Metal / RTOS Target
else ifneq (,$(findstring -none,$(CCARCH)))
 OSDEP:=METAL
 CFLAGS+=-fno-exceptions -fno-unwind-tables -fno-non-call-exceptions -fno-asynchronous-unwind-tables -ffreestanding -fno-builtin -nostartfiles
 ifneq (,$(findstring cortex-,$(CPU)))
  CFLAGS+=-mthumb -mcpu=$(CPU) -mslow-flash-data
  ifeq (cortex-m4,$(CPU))
   CFLAGS+=-mcpu=cortex-m4 -mtune=cortex-m4
  else ifeq (cortex-m3,$(CPU))
   CFLAGS+=-mcpu=cortex-m3 -mtune=cortex-m3 -mfpu=vpf
  else ifeq (cortex-m0,$(CPU))
   CFLAGS+=-mcpu=cortex-m0 -mtune=cortex-m0 -mfpu=vpf
  endif
 endif
endif

# This must be defined after OSDEP, because core/Makefile uses OSDEP in SRC
OBJS:=$(SRC:.c=.o) $(SRC:.S:*.o)


# Remove extra spaces in CFLAGS
#CFLAGS:=$(strip $(CFLAGS))

# Display the precompiler defines for the current build settings
defines:
	:| $(CC) $(CFLAGS) -dM -E -x c -

