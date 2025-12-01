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
#include "ht/http_request.hpp"
#include "ht/server_config.hpp"
#include "ht/internal/auth.hpp"
#include "ht/internal/nonce_cache.hpp"

namespace ht::internal {

struct VerifyResult {
    bool ok = false;
    std::string key_id;
    std::string reason;
    std::string canonical; // for AEAD AAD
};

// Parse timestamp from header (unix or ISO8601)
bool parse_timestamp(const std::string& s, std::int64_t& out_epoch);

// Verify HMAC-authenticated request.
// If verify_plain_body_hash == true, compute SHA256(body) and compare.
VerifyResult verify_request_common(const ht::HttpRequest& R,
                                   const ht::ServerConfig& cfg,
                                   AuthStore& auth,
                                   NonceCache& nonces,
                                   bool verify_plain_body_hash);

} // namespace ht::internal

