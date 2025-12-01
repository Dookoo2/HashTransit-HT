# Part of the HashTransit (HT) project.
#
# SPDX-FileCopyrightText: 2025 HashTransit contributors
# SPDX-License-Identifier: Apache-2.0
#
# This file is part of HashTransit (HT). See LICENSE for details.
# Coded by DooKoo2: https://github.com/Dookoo2

# ======= Toolchain =======
CXX      ?= g++
AR       ?= ar
ARFLAGS  ?= rcs

CXX_PATH := $(shell command -v $(CXX) 2>/dev/null)
ifeq ($(CXX_PATH),)
  $(warning CXX '$(CXX)' not found; falling back to g++)
  CXX := g++
endif

# ======= Paths =======
PREFIX   ?= /usr/local
OBJDIR   ?= build

# ======= OpenSSL =======
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo -lssl -lcrypto)

# ======= Flags =======
CPPFLAGS ?= -Iinclude $(OPENSSL_CFLAGS) -D_FORTIFY_SOURCE=2
CXXFLAGS ?= -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -fPIC -pthread
LDFLAGS  ?=
LDLIBS   ?= $(OPENSSL_LIBS) -lpthread

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
CPPFLAGS += -DMSG_NOSIGNAL=0
endif

# ======= Sources / Objects =======
SRCS_COMMON := \
  src/common/utils.cpp \
  src/common/http_parser.cpp \
  src/common/hmac.cpp \
  src/common/aead.cpp \
  src/common/time.cpp \
  src/common/log.cpp

SRCS_CLIENT := \
  src/client/http_low.cpp \
  src/client/http_tls_client.cpp \
  src/client/client.cpp

SRCS := $(SRCS_COMMON) $(SRCS_CLIENT)
OBJS := $(patsubst src/%.cpp,$(OBJDIR)/%.o,$(SRCS))

# ======= Default =======
.PHONY: all
all: libht_client.a

libht_client.a: $(OBJS)
	@echo "  AR      $@"
	@$(AR) $(ARFLAGS) $@ $^

$(OBJDIR)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	@echo "  CXX     $<"
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@echo "  CLEAN"
	@rm -rf $(OBJDIR) libht_client.a

.PHONY: debug
debug: CXXFLAGS := -std=c++17 -O0 -g -DDEBUG -Wall -Wextra -Wpedantic -fPIC -pthread
debug: clean all

print-%:
	@echo '$* = $($*)'

.PHONY: install
install: libht_client.a
	@echo "  INSTALL headers -> $(DESTDIR)$(PREFIX)/include"
	@mkdir -p $(DESTDIR)$(PREFIX)/include
	@cp -R include/ht $(DESTDIR)$(PREFIX)/include/
	@echo "  INSTALL lib     -> $(DESTDIR)$(PREFIX)/lib"
	@mkdir -p $(DESTDIR)$(PREFIX)/lib
	@install -m 0644 libht_client.a $(DESTDIR)$(PREFIX)/lib/

.PHONY: uninstall
uninstall:
	@echo "  UNINSTALL from $(DESTDIR)$(PREFIX)"
	@rm -f $(DESTDIR)$(PREFIX)/lib/libht_client.a
	@rm -rf $(DESTDIR)$(PREFIX)/include/ht

