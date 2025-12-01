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
#include <unordered_map>
#include <memory>
#include <mutex>
#include "ht/client_config.hpp"
#include "ht/http_response.hpp"

namespace ht {

// High-level HTTP(S) HMAC-Transport client with keep-alive and TLS support.
class Client {
public:
    explicit Client(const ClientConfig& cfg);
    ~Client();

    // Single-call convenience helpers
    // - POST /echo (payload is plaintext for all modes; will be AEAD-encrypted in B)
    bool post_echo(const std::string& payload, HttpResponse& out);

    // Generic request:
    //  method: "GET" or "POST"
    //  path:   e.g. "/echo" (will be prefixed by base_path if set)
    //  query:  map of query parameters
    //  plaintext_body: plaintext data (will be encrypted in mode B)
    bool request(const std::string& method,
                 const std::string& path,
                 const std::unordered_map<std::string,std::string>& query,
                 const std::string& plaintext_body,
                 HttpResponse& out);

private:
    struct Impl;
    std::unique_ptr<Impl> _p;
};

} // namespace ht

