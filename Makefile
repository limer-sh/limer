# Limer - HTTP load balancer with payload-based distribution
CC      ?= cc
CFLAGS  ?= -O2 -g
override CFLAGS += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -pthread
LDFLAGS ?=
override LDFLAGS += -pthread
LDLIBS  += -lm -lresolv

UNAME_S := $(shell uname -s)
PKG_CONFIG ?= pkg-config
ifeq ($(UNAME_S),Darwin)
# macOS: Homebrew keeps OpenSSL and libxcrypt off the default search path
# ("keg-only"), so point pkg-config at them. bcrypt for basic_auth comes from
# libxcrypt (`brew install libxcrypt`); the system crypt() has no bcrypt.
BREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
PKG_CONFIG := PKG_CONFIG_PATH="$(PKG_CONFIG_PATH):$(BREW_PREFIX)/opt/openssl@3/lib/pkgconfig:$(BREW_PREFIX)/opt/libxcrypt/lib/pkgconfig:$(BREW_PREFIX)/lib/pkgconfig" pkg-config
override CFLAGS += -D__APPLE_USE_RFC_3542 $(shell $(PKG_CONFIG) --cflags libxcrypt 2>/dev/null)
ifeq ($(shell $(PKG_CONFIG) --exists libxcrypt 2>/dev/null && echo 1),1)
LDLIBS += $(shell $(PKG_CONFIG) --libs libxcrypt)
else
$(error libxcrypt is needed for bcrypt on macOS: brew install libxcrypt)
endif
else
LDLIBS += -lcrypt
endif

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

# TLS support is enabled automatically when OpenSSL is available.
# Force it with `make TLS=1` or disable it with `make TLS=0`.
TLS ?= $(shell $(PKG_CONFIG) --exists openssl 2>/dev/null && echo 1 || echo 0)
ifeq ($(TLS),1)
override CFLAGS += -DLIMER_TLS $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo -lssl -lcrypto)
endif

# Response compression needs zlib, libzstd and libbrotli (auto-detected).
ENCODE ?= $(shell $(PKG_CONFIG) --exists zlib libzstd libbrotlienc 2>/dev/null && echo 1 || echo 0)
ifeq ($(ENCODE),1)
override CFLAGS += -DLIMER_ENCODE $(shell $(PKG_CONFIG) --cflags zlib libzstd libbrotlienc 2>/dev/null)
LDLIBS += $(shell $(PKG_CONFIG) --libs zlib libzstd libbrotlienc 2>/dev/null)
endif

# HTTP/2 needs libnghttp2 (auto-detected; requires TLS for ALPN).
H2 ?= $(shell $(PKG_CONFIG) --exists libnghttp2 2>/dev/null && echo 1 || echo 0)
ifeq ($(H2),1)
ifeq ($(TLS),1)
override CFLAGS += -DLIMER_H2 $(shell $(PKG_CONFIG) --cflags libnghttp2 2>/dev/null)
LDLIBS += $(shell $(PKG_CONFIG) --libs libnghttp2 2>/dev/null)
endif
endif

# HTTP/3 needs ngtcp2 and nghttp3 with the GnuTLS crypto backend (auto-detected;
# requires TLS). Disable with `make H3=0`.
H3_PKGS := libngtcp2 libngtcp2_crypto_gnutls libnghttp3 gnutls
H3 ?= $(shell $(PKG_CONFIG) --exists $(H3_PKGS) 2>/dev/null && echo 1 || echo 0)
ifeq ($(H3),1)
ifeq ($(TLS),1)
override CFLAGS += -DLIMER_H3 $(shell $(PKG_CONFIG) --cflags $(H3_PKGS) 2>/dev/null)
LDLIBS += $(shell $(PKG_CONFIG) --libs $(H3_PKGS) 2>/dev/null)
endif
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

ddos: $(BIN)
	python3 tests/ddos_test.py

scale: $(BIN)
	python3 tests/scale_test.py

drain: $(BIN)
	python3 tests/drain_test.py

rollback: $(BIN)
	python3 tests/rollback_test.py

# Builds a deliberately broken variant of limer, so it takes a little longer.
binrollback: $(BIN)
	python3 tests/binrollback_test.py

# Needs the aioquic Python package (skips without it).
h3: $(BIN)
	python3 tests/h3_test.py

status: $(BIN)
	python3 tests/status_test.py

reload: $(BIN)
	python3 tests/reload_test.py

admin: $(BIN)
	python3 tests/admin_test.py

discover: $(BIN)
	python3 tests/discover_test.py
	python3 tests/broadcast_test.py

# Needs `pebble` (PEBBLE=/path), optionally `pebble-challtestsrv` (CHALLTESTSRV=/path) for dns-01,
# and `127.0.0.1 limer.test www.limer.test alpn.limer.test dns.limer.test` in /etc/hosts; skips otherwise.
acme: $(BIN)
	./tests/run_acme.sh

# Everything: unit tests, parser fuzzing, integration, feature, ACME, security and DoS-guard suites.
check: unit fuzz integration features acme security ddos scale drain rollback binrollback h3 status reload admin discover broadcast

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

.PHONY: all unit fuzz integration features acme security ddos scale drain rollback binrollback h3 status reload admin discover broadcast check check-asan install clean
