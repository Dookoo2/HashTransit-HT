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
#include <thread>
#include <atomic>
#include "ht/server_config.hpp"
#include "ht/internal/auth.hpp"
#include "ht/internal/nonce_cache.hpp"
#include "ht/internal/ratelimit.hpp"
#include "ht/internal/tls_ctx.hpp"

namespace ht {

// HMAC-Transport HTTP(S) server
class Server {
public:
    explicit Server(const ServerConfig& cfg);
    ~Server();

    // Blocking run: create socket, listen and accept.
    void run();

    // Optional stop (sets flag, unblocks accept on some platforms)
    void stop();

private:
    ServerConfig _cfg;
    internal::AuthStore _auth;
    internal::NonceCache _nonces;
    internal::TokenBucketMap _ip_rl;
    internal::TokenBucketMap _key_rl;
    std::unique_ptr<internal::TlsContext> _tls; // only for mode C
    std::atomic<bool> _stop{false};
    std::thread _nonce_gc_thread;

    void nonce_gc_loop();
    void serve_plain();
    void serve_tls();

    // helpers
    int create_listen_socket();
};

} // namespace ht

