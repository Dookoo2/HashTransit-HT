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
#include <string>
#include <cstddef>
#include <cstdint>
#include "ht/types.hpp"

namespace ht {

// Public client configuration. Per-instance; thread-safe at call level.
struct ClientConfig {
    // Transport/auth
    ht::Mode   mode = ht::Mode::AuthOnly;
    ht::AeadAlg aead = ht::AeadAlg::Chacha20;

    // Endpoint
    std::string host = "127.0.0.1";
    std::uint16_t port = 8080;
    std::string  base_path = "";   // optional path prefix, e.g. "/api"

    // Auth key (single key-id for this client instance)
    std::string key_id;            // e.g. "device-001"
    std::string secret_hex;        // 64 hex chars -> 32 bytes PSK

    // Timeouts
    int connect_timeout_sec = 5;   // TCP connect timeout
    int io_timeout_sec      = 5;   // recv/send timeout
    int ka_max              = 100; // max requests per connection before re-open

    // TLS (mode C), and optionally for A/B over HTTPS if desired
    bool tls_verify_peer = true;       // verify server certificate
    std::string tls_ca_file;           // optional CA file path
    std::string tls_sni;               // optional SNI servername override
    std::string tls_client_cert_file;  // optional mTLS
    std::string tls_client_key_file;   // optional mTLS

    // Logging
    std::string log_file = "client.log";
};

} // namespace ht

