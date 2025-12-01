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
#include <cstddef>

namespace ht::internal {

// Anti-replay cache: remembers (key|nonce) for TTL, supports pressure pruning.
class NonceCache {
public:
    NonceCache() = default;

    // Insert new key. Returns false if it was already present or over capacity.
    bool insert_if_absent(const std::string& key, int ttl_sec,
                          std::size_t max_pending);

    // Periodic GC — drop expired.
    void gc(int ttl_sec);

private:
    using clock = std::chrono::steady_clock;
    std::mutex _mtx;
    std::unordered_map<std::string, clock::time_point> _seen;

    void prune_locked(std::size_t target_keep, int ttl_sec);
};

} // namespace ht::internal

