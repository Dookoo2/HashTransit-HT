# Part of the HashTransit (HT) project.
#
# SPDX-FileCopyrightText: 2025 HashTransit contributors
# SPDX-License-Identifier: Apache-2.0
#
# This file is part of HashTransit (HT). See LICENSE for details.
# Coded by DooKoo2: https://github.com/Dookoo2

# ---- Compiler selection ----
CXX      ?= g++
CXX_PATH := $(shell command -v $(CXX) 2>/dev/null)
ifeq ($(CXX_PATH),)
  $(warning CXX '$(CXX)' not found; falling back to g++)
  CXX := g++
endif

# ---- Flags ----
CPPFLAGS ?= -Iinclude -D_FORTIFY_SOURCE=2
CXXFLAGS ?= -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -pthread
LDFLAGS  ?=
ARFLAGS  ?= rcs

# OpenSSL
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo -lssl -lcrypto)

# hiredis (Redis client)
HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis 2>/dev/null)
HIREDIS_LIBS   := $(shell pkg-config --libs   hiredis 2>/dev/null || echo -lhiredis)

CPPFLAGS += $(OPENSSL_CFLAGS) $(HIREDIS_CFLAGS)

# ---- Paths ----
SRC_COMMON := src/common
SRC_SERVER := src/server
BUILD      := build
TARGET     := libht_server.a

# ---- Sources ----
COMMON_SRCS := \
  $(SRC_COMMON)/aead.cpp \
  $(SRC_COMMON)/auth.cpp \
  $(SRC_COMMON)/hmac.cpp \
  $(SRC_COMMON)/http_parser.cpp \
  $(SRC_COMMON)/log.cpp \
  $(SRC_COMMON)/nonce_cache.cpp \
  $(SRC_COMMON)/ratelimit.cpp \
  $(SRC_COMMON)/time.cpp \
  $(SRC_COMMON)/tls_ctx.cpp \
  $(SRC_COMMON)/utils.cpp

SERVER_SRCS := \
  $(SRC_SERVER)/http_plain.cpp \
  $(SRC_SERVER)/http_tls.cpp \
  $(SRC_SERVER)/server.cpp

SRCS := $(COMMON_SRCS) $(SERVER_SRCS)

# ---- Objects ----
OBJS := $(patsubst %.cpp,$(BUILD)/%.o,$(SRCS))

# ---- Rules ----
.PHONY: all clean print-vars

all: $(TARGET)
	@echo "  OK      $(TARGET)"

$(TARGET): $(OBJS)
	@echo "  AR      $@"
	@ar $(ARFLAGS) $@ $(OBJS)

# compile .cpp → .o into build/...
$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	@echo "  CXX     $<"
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

clean:
	@echo "  CLEAN"
	@rm -rf $(BUILD) $(TARGET)

print-vars:
	@echo "CXX=$(CXX)"
	@echo "CPPFLAGS=$(CPPFLAGS)"
	@echo "CXXFLAGS=$(CXXFLAGS)"
	@echo "OPENSSL_CFLAGS=$(OPENSSL_CFLAGS)"
	@echo "OPENSSL_LIBS=$(OPENSSL_LIBS)"
	@echo "HIREDIS_CFLAGS=$(HIREDIS_CFLAGS)"
	@echo "HIREDIS_LIBS=$(HIREDIS_LIBS)"

# Notes:
# * Static library does not link against OpenSSL/hiredis here; those LIBS are
#   for final executables. Keep this file focused on archiving objects.
# * Ensure libhiredis-dev and libssl-dev are installed on the system.

