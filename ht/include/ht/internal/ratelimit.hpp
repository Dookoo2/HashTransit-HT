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
#include <unordered_map>
#include <string>
#include <chrono>
#include <mutex>

namespace ht::internal {

// Simple token-bucket map keyed by string (IP, key-id).
class TokenBucketMap {
public:
    TokenBucketMap() = default;

    // Returns true if request is allowed under (rate, burst).
    bool allow(const std::string& key, double rate, double burst);

private:
    struct Bucket {
        double tokens = 0.0;
        std::chrono::steady_clock::time_point last{};
        bool init = false;
    };

    std::mutex _mtx;
    std::unordered_map<std::string, Bucket> _buckets;
};

} // namespace ht::internal

