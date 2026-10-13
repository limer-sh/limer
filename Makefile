# Limer - HTTP load balancer with payload-based distribution
CC      ?= cc
CFLAGS  ?= -O2 -g
override CFLAGS += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS ?=
LDLIBS  += -lm -lcrypt

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

# TLS support is enabled automatically when OpenSSL is available.
# Force it with `make TLS=1` or disable it with `make TLS=0`.
TLS ?= $(shell pkg-config --exists openssl 2>/dev/null && echo 1 || echo 0)
ifeq ($(TLS),1)
override CFLAGS += -DLIMER_TLS $(shell pkg-config --cflags openssl 2>/dev/null)
LDLIBS += $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)
endif

# Response compression needs zlib, libzstd and libbrotli (auto-detected).
ENCODE ?= $(shell pkg-config --exists zlib libzstd libbrotlienc 2>/dev/null && echo 1 || echo 0)
ifeq ($(ENCODE),1)
override CFLAGS += -DLIMER_ENCODE $(shell pkg-config --cflags zlib libzstd libbrotlienc 2>/dev/null)
LDLIBS += $(shell pkg-config --libs zlib libzstd libbrotlienc 2>/dev/null)
endif

# `make SAN=1` builds everything with AddressSanitizer + UBSan.
ifeq ($(SAN),1)
override CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer -O1
override LDFLAGS += -fsanitize=address,undefined
endif

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
LIBOBJ := $(filter-out build/main.o,$(OBJ))
BIN := limer

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c src/limer.h | build
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

build:
	mkdir -p build

-include $(OBJ:.o=.d)

# ---------------------------------------------------------------- tests

build/unit: tests/unit.c $(LIBOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/unit.c $(LIBOBJ) $(LDLIBS)

build/fuzz: tests/fuzz.c $(LIBOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/fuzz.c $(LIBOBJ) $(LDLIBS)

unit: build/unit
	./build/unit

FUZZ_ITERS ?= 50000
fuzz: build/fuzz
	./build/fuzz $(FUZZ_ITERS)

integration: $(BIN)
	./tests/run_tests.sh

security: $(BIN)
	python3 tests/security_tests.py

features: $(BIN)
	./tests/run_features.sh

# Everything: unit tests, parser fuzzing, integration, feature and security suites.
check: unit fuzz integration features security

# The same suites with sanitizers enabled (slower; rebuilds everything).
check-asan:
	$(MAKE) clean
	$(MAKE) SAN=1 check
	$(MAKE) clean

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -rf build $(BIN) tests/tmp

.PHONY: all unit fuzz integration features security check check-asan install clean
