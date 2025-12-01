/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/nonce_cache.hpp"
#include <vector>
#include <algorithm>

namespace ht::internal {

bool NonceCache::insert_if_absent(const std::string& key,
                                  int ttl_sec,
                                  std::size_t max_pending)
{
    using clock = std::chrono::steady_clock;
    const auto now = clock::now();
    std::lock_guard<std::mutex> lk(_mtx);

    // pressure-based pruning
    if (_seen.size() > max_pending) {
        prune_locked(static_cast<std::size_t>(max_pending * 0.8), ttl_sec);
        if (_seen.size() > max_pending) {
            // still over capacity
            return false;
        }
    }

    auto it = _seen.find(key);
    if (it != _seen.end()) {
        return false; // replay
    }
    _seen[key] = now;
    return true;
}

void NonceCache::gc(int ttl_sec) {
    using clock = std::chrono::steady_clock;
    const auto now = clock::now();
    const auto ttl = std::chrono::seconds(ttl_sec);
    std::lock_guard<std::mutex> lk(_mtx);
    for (auto it = _seen.begin(); it != _seen.end();) {
        if (now - it->second > ttl) it = _seen.erase(it);
        else ++it;
    }
}

void NonceCache::prune_locked(std::size_t target_keep, int ttl_sec) {
    using clock = std::chrono::steady_clock;
    const auto now = clock::now();
    const auto ttl = std::chrono::seconds(ttl_sec);

    // 1) drop expired
    for (auto it = _seen.begin(); it != _seen.end();) {
        if (now - it->second > ttl) it = _seen.erase(it);
        else ++it;
    }
    if (_seen.size() <= target_keep) return;

    // 2) drop oldest
    std::vector<std::pair<std::string, clock::time_point>> v;
    v.reserve(_seen.size());
    for (auto& kv : _seen) v.emplace_back(kv.first, kv.second);

    std::size_t to_remove = _seen.size() - target_keep;
    if (to_remove == 0) return;

    std::nth_element(v.begin(), v.begin() + (long)to_remove - 1, v.end(),
                     [](auto& a, auto& b) { return a.second < b.second; });
    auto cut_time = v[to_remove - 1].second;

    for (auto it = _seen.begin(); it != _seen.end();) {
        if (it->second <= cut_time) {
            it = _seen.erase(it);
            if (_seen.size() <= target_keep) break;
        } else {
            ++it;
        }
    }
}

} // namespace ht::internal

