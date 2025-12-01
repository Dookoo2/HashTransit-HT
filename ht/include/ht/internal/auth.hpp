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
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <chrono>

// hiredis types live in the global namespace; include the header here
#include <hiredis/hiredis.h>

namespace ht::internal {

/**
 * Redis-backed key store with optional file fallback.
 * Thread-safe lookups. When Redis is used, secrets are cached in-memory with TTL.
 */
class AuthStore {
public:
    AuthStore();
    ~AuthStore();

    // ---- File backend (kept for backward compatibility) ----
    bool init_file(const std::string& path);

    // ---- Redis backend ----
    struct RedisOptions {
        std::string host = "127.0.0.1";
        int         port = 6379;
        int         db   = 0;                 // SELECT db
        std::string password;                 // optional
        std::string key_prefix = "ht:key:";   // key = key_prefix + key_id
        int         pool_size  = 8;           // number of hiredis connections
        int         timeout_ms = 200;         // connect + command timeout
        int         cache_ttl_sec = 60;       // TTL for in-memory cache entries
    };
    bool init_redis(const RedisOptions& opt);

    // Lookup secret by key_id. Returns true and fills out_secret_bin (32 bytes) if found.
    bool lookup(const std::string& key_id, std::string& out_secret_bin);

private:
    enum class Backend { None, File, Redis };
    Backend _backend = Backend::None;

    // -------- File map --------
    std::mutex _file_mtx;
    std::unordered_map<std::string, std::string> _file_map; // key_id -> secret_bin(32B)

    // -------- Redis pool + cache --------
    struct RedisConn { ::redisContext* ctx = nullptr; bool valid = false; };
    std::vector<RedisConn> _pool;
    std::deque<size_t>     _free;
    std::mutex             _pool_mtx;
    std::condition_variable _pool_cv;

    RedisOptions _opt{};
    int          _timeout_ms = 200;
    std::string  _prefix = "ht:key:";

    struct CacheEntry {
        std::string secret; // 32B binary
        std::chrono::steady_clock::time_point expires;
    };
    std::mutex _cache_mtx;
    std::unordered_map<std::string, CacheEntry> _cache;

    // helpers
    bool hex_to_bytes(const std::string& hex, std::string& out_bin) const;
    static int  hexval(char c);

    bool redis_connect_one(size_t idx);
    void redis_close_one(size_t idx);
    bool redis_auth_and_select(::redisContext* ctx);
    bool redis_get_secret(const std::string& key_id, std::string& out_secret_bin);

    // RAII slot guard for pool index
    class Slot {
    public:
        explicit Slot(AuthStore& s) : store(s) {}
        ~Slot() { release(); }
        bool acquire();
        void release();
        ::redisContext* ctx();     // ensure connected and return pointer
        size_t index() const { return idx; }
    private:
        AuthStore& store;
        size_t idx = (size_t)-1;
        bool   have = false;
    };
};

} // namespace ht::internal

