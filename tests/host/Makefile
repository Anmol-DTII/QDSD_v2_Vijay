# Host build of the token subsystem + software hardware model, for the Python tests.
#   make MBEDTLS=/path/to/mbedtls-3.6.x   (built with CFLAGS=-fPIC)
#   make test
#
# Builds the same sources the firmware builds (src/token, src/protocol,
# src/state_machine, src/security, src/port/port_crypto.c, src/usb/ccid.c,
# src/usb/msc.c)
# against port_host.c, the software model of the SE050, SE052F and flash.

MBEDTLS ?= ../../../deps/mbedtls-3.6.2
ROOT    := ../..
SRC     := $(ROOT)/src

CFLAGS  += -std=c11 -O2 -g -fPIC -Wall -Wextra -Werror -Wshadow -Wconversion \
           -Wno-sign-conversion -Wmissing-prototypes -I$(ROOT)/include -I$(MBEDTLS)/include \
           -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -shared -fsanitize=address,undefined
LIBS    := $(MBEDTLS)/library/libmbedcrypto.a

SRCS := $(wildcard $(SRC)/token/*.c) \
        $(SRC)/protocol/stmt.c $(SRC)/protocol/tlv.c $(SRC)/protocol/der.c \
        $(SRC)/state_machine/state_record.c $(SRC)/security/self_test.c \
        $(SRC)/port/port_crypto.c $(SRC)/usb/ccid.c $(SRC)/usb/msc.c \
        port_host.c

HDRS := $(wildcard $(ROOT)/include/*/*.h)

all: libqdsd_host.so

libqdsd_host.so: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(SRCS) $(LDFLAGS) $(LIBS) -o $@

test: libqdsd_host.so
	LD_PRELOAD=$$($(CC) -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0 \
	PYTHONPATH=$(ROOT)/tools python3 -m unittest -v test_flows test_v32 test_ccid test_session test_drive

clean:
	rm -f libqdsd_host.so

.PHONY: all test clean
