/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/ratelimit.hpp"
#include <algorithm>

namespace ht::internal {

bool TokenBucketMap::allow(const std::string& key, double rate, double burst) {
    if (rate <= 0.0 || burst <= 0.0) return true;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(_mtx);
    auto& b = _buckets[key];
    if (!b.init) {
        b.tokens = burst;
        b.last   = now;
        b.init   = true;
    }
    double elapsed = std::chrono::duration<double>(now - b.last).count();
    b.last   = now;
    b.tokens = std::min(burst, b.tokens + elapsed * rate);
    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    return false;
}

} // namespace ht::internal

