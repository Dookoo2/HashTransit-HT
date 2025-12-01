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

namespace ht::internal {

// Accept either unix seconds or ISO8601 "YYYY-MM-DDTHH:MM:SSZ"
bool parse_timestamp(const std::string& s, std::int64_t& out_epoch);

// HMAC-SHA256(key, msg) -> 32 bytes (binary) as std::string
bool hmac_sha256_bin(const std::string& key_bin,
                     const std::string& msg,
                     std::string& out_bin);

} // namespace ht::internal

