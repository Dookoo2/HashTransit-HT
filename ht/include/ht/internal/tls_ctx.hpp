/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#pragma once
#include <memory>
#include <string>
#include <openssl/ssl.h>
#include "ht/server_config.hpp"

namespace ht::internal {

// Lightweight RAII wrapper over SSL_CTX
class TlsContext {
public:
    explicit TlsContext(const ht::ServerConfig& cfg);
    ~TlsContext();

    SSL_CTX* ctx() const { return _ctx; }

    // non-copyable
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

private:
    SSL_CTX* _ctx = nullptr;

    void log_last_error(const char* where);
};

} // namespace ht::internal

