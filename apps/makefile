# apps/Makefile
# Build two executables:
#   - ht_server_basic (links against ../ht/libht_server.a + OpenSSL + hiredis)
#   - ht_client_cli   (links against ../ht_cl/libht_client.a + OpenSSL)
#
# Important: for static archives, dependent shared libs must appear AFTER the archive.

# ---- Compiler selection ----
CXX      ?= g++
CXX_PATH := $(shell command -v $(CXX) 2>/dev/null)
ifeq ($(CXX_PATH),)
  $(warning CXX '$(CXX)' not found; falling back to g++)
  CXX := g++
endif

# ---- Flags ----
CPPFLAGS ?= -I../ht/include -I../ht_cl/include -D_FORTIFY_SOURCE=2
CXXFLAGS ?= -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -pthread
LDFLAGS  ?=

# OpenSSL
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || echo -lssl -lcrypto)

# hiredis (server app needs it because libht_server.a uses hiredis)
HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis 2>/dev/null)
HIREDIS_LIBS   := $(shell pkg-config --libs   hiredis 2>/dev/null || echo -lhiredis)

# Common compile flags (add both cflags; harmless if unused)
CPPFLAGS += $(OPENSSL_CFLAGS) $(HIREDIS_CFLAGS)

# ---- Paths to static libraries ----
LIB_SERVER := ../ht/libht_server.a
LIB_CLIENT := ../ht_cl/libht_client.a

# ---- Targets ----
.PHONY: all clean
all: ht_server_basic ht_client_cli

# Server app: object(s) first, then static archive, then its dependencies
ht_server_basic: ht_server_basic.o $(LIB_SERVER)
	@echo "  LINK    $@"
	@$(CXX) $(LDFLAGS) -o $@ ht_server_basic.o \
		-L../ht -lht_server \
		$(OPENSSL_LIBS) $(HIREDIS_LIBS) -lpthread

# Client app: object(s) first, then client archive, then deps (no hiredis needed)
ht_client_cli: ht_client_cli.o $(LIB_CLIENT)
	@echo "  LINK    $@"
	@$(CXX) $(LDFLAGS) -o $@ ht_client_cli.o \
		-L../ht_cl -lht_client \
		$(OPENSSL_LIBS) -lpthread

# Generic compile rule
%.o: %.cpp
	@echo "  CXX     $<"
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

clean:
	@echo "  CLEAN"
	@rm -f *.o ht_server_basic ht_client_cli

