# Limer - HTTP load balancer with payload-based distribution
CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS ?=
LDLIBS  += -lm

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

# TLS support is enabled automatically when OpenSSL is available.
# Force it with `make TLS=1` or disable it with `make TLS=0`.
TLS ?= $(shell pkg-config --exists openssl 2>/dev/null && echo 1 || echo 0)
ifeq ($(TLS),1)
CFLAGS += -DLIMER_TLS $(shell pkg-config --cflags openssl 2>/dev/null)
LDLIBS += $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)
endif

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
BIN := limer

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c src/limer.h | build
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

build:
	mkdir -p build

-include $(OBJ:.o=.d)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

check: $(BIN)
	./tests/run_tests.sh

clean:
	rm -rf build $(BIN)

.PHONY: all install check clean
