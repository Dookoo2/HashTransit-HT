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
#include <cstdint>

namespace ht {

enum class Mode { AuthOnly, AuthAead, TlsTube };
enum class AeadAlg { Chacha20, AesGcm };

struct ServerConfig {
    // Core
    Mode     mode = Mode::AuthOnly;
    uint16_t port = 8080;

    // TLS (mode C)
    bool        tls_enabled = false;
    std::string tls_cert_file;
    std::string tls_key_file;
    std::string tls_client_ca;
    bool        require_client_cert = false;

    // AEAD (mode B)
    AeadAlg aead = AeadAlg::Chacha20;
    size_t  max_body = 2*1024*1024;
    int     ts_skew_sec = 120;
    int     nonce_ttl_sec = 600;

    // Auth (file fallback; ignored when auth_use_redis=true)
    std::string auth_file;

    // Error redaction
    bool redact_errors = false;

    // Rate limits
    double rl_ip_rate   = 0.0;
    double rl_ip_burst  = 0.0;
    double rl_key_rate  = 0.0;
    double rl_key_burst = 0.0;

    // Anti-replay capacity guard
    size_t max_pending = 100000;

    // Keep-alive
    int  ka_timeout_sec = 5;
    int  ka_max         = 100;

    // ---- Redis auth backend (NEW) ----
    bool auth_use_redis = false;
    struct {
        std::string host = "127.0.0.1";
        int         port = 6379;
        int         db   = 0;
        std::string password;
        std::string key_prefix = "ht:key:";
        int         pool_size  = 8;
        int         timeout_ms = 200;
        int         cache_ttl_sec = 60;
    } redis;
};

} // namespace ht

