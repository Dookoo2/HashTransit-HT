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
#include <openssl/ssl.h>
#include <string>
#include "ht/client_config.hpp"

namespace ht::internal {

// Minimal TLS client context. Loads system CA or custom CA, sets SNI,
// and (optionally) mTLS client certificate.
class TlsClientContext {
public:
    explicit TlsClientContext(const ht::ClientConfig& cfg);
    ~TlsClientContext();

    SSL_CTX* ctx() const { return _ctx; }

    // non-copyable
    TlsClientContext(const TlsClientContext&) = delete;
    TlsClientContext& operator=(const TlsClientContext&) = delete;

private:
    SSL_CTX* _ctx = nullptr;
    void log_last_error(const char* where);
};

} // namespace ht::internal

