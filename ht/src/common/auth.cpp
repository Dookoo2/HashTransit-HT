/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/auth.hpp"
#include "ht/log.hpp"

#include <fstream>
#include <sstream>
#include <cstring>
#include <cassert>

namespace ht::internal {

AuthStore::AuthStore() = default;

AuthStore::~AuthStore() {
    // Close Redis connections (if any)
    for (auto& c : _pool) {
        if (c.ctx) {
            redisFree(c.ctx);
            c.ctx = nullptr;
            c.valid = false;
        }
    }
}

/* ---------------- File backend ---------------- */

static int hexval_local(char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return 10+(c-'a');
    if(c>='A'&&c<='F')return 10+(c-'A');
    return -1;
}

int AuthStore::hexval(char c) { return hexval_local(c); }

bool AuthStore::hex_to_bytes(const std::string& hex, std::string& out_bin) const {
    if (hex.size() % 2) return false;
    out_bin.clear(); out_bin.reserve(hex.size()/2);
    for (size_t i=0;i<hex.size(); i+=2){
        int h = hexval_local(hex[i]);
        int l = hexval_local(hex[i+1]);
        if (h<0 || l<0) return false;
        out_bin.push_back(static_cast<char>((h<<4)|l));
    }
    return true;
}

bool AuthStore::init_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.good()) {
        ht::log_line(std::string("[AUTH] failed to open file: ")+path);
        return false;
    }
    std::unordered_map<std::string,std::string> tmp;
    std::string kid, sec_hex;
    size_t line_no = 0;
    for (std::string line; std::getline(in, line); ) {
        ++line_no;
        // trim locally
        auto trim = [](std::string& s){
            size_t a=0; while(a<s.size() && isspace((unsigned char)s[a])) ++a;
            size_t b=s.size(); while(b>a && isspace((unsigned char)s[b-1])) --b;
            if(a>0 || b<s.size()) s.assign(s.begin()+a, s.begin()+b);
        };
        trim(line);
        if (line.empty() || line[0]=='#') continue;
        std::istringstream iss(line);
        if (!(iss >> kid >> sec_hex)) {
            ht::log_line("[AUTH] bad line "+std::to_string(line_no));
            return false;
        }
        std::string sec_bin;
        if (!hex_to_bytes(sec_hex, sec_bin) || sec_bin.size()!=32) {
            ht::log_line("[AUTH] bad secret at line "+std::to_string(line_no));
            return false;
        }
        tmp[kid] = std::move(sec_bin);
    }
    {
        std::lock_guard<std::mutex> lk(_file_mtx);
        _file_map.swap(tmp);
        _backend = Backend::File;
    }
    ht::log_line("[AUTH] file backend initialized: "+std::to_string(_file_map.size())+" entries");
    return true;
}

/* ---------------- Redis backend ---------------- */

bool AuthStore::init_redis(const RedisOptions& opt) {
    _opt = opt;
    _prefix = opt.key_prefix;
    _timeout_ms = opt.timeout_ms;
    if (_opt.pool_size <= 0) _opt.pool_size = 1;

    _pool.resize(_opt.pool_size);

    // Pre-connect all slots (best effort)
    for (size_t i=0; i<_pool.size(); ++i) {
        (void)redis_connect_one(i);
    }
    {
        std::lock_guard<std::mutex> lk(_pool_mtx);
        for (size_t i=0; i<_pool.size(); ++i) _free.push_back(i);
    }
    {
        std::lock_guard<std::mutex> lk(_cache_mtx);
        _cache.clear();
    }
    _backend = Backend::Redis;
    ht::log_line("[AUTH] redis backend initialized: pool="+std::to_string(_pool.size())+
                 " host="+_opt.host+":"+std::to_string(_opt.port)+
                 " db="+std::to_string(_opt.db)+
                 " prefix="+_prefix+
                 " cache_ttl="+std::to_string(_opt.cache_ttl_sec)+"s");
    return true;
}

bool AuthStore::redis_connect_one(size_t idx) {
    assert(idx < _pool.size());

    timeval tv{};
    tv.tv_sec  = _opt.timeout_ms / 1000;
    tv.tv_usec = (_opt.timeout_ms % 1000) * 1000;

    ::redisContext* ctx = redisConnectWithTimeout(_opt.host.c_str(), _opt.port, tv);
    if (!ctx || ctx->err) {
        if (ctx) {
            ht::log_line(std::string("[AUTH][redis] connect error: ")+ctx->errstr);
            redisFree(ctx);
        } else {
            ht::log_line("[AUTH][redis] connect error: NULL context");
        }
        _pool[idx].ctx = nullptr;
        _pool[idx].valid = false;
        return false;
    }

    // AUTH/SELECT if requested
    if (!redis_auth_and_select(ctx)) {
        redisFree(ctx);
        _pool[idx].ctx = nullptr;
        _pool[idx].valid = false;
        return false;
    }

    _pool[idx].ctx = ctx;
    _pool[idx].valid = true;
    return true;
}

bool AuthStore::redis_auth_and_select(::redisContext* ctx) {
    if (!_opt.password.empty()) {
        redisReply* r = (redisReply*)redisCommand(ctx, "AUTH %s", _opt.password.c_str());
        if (!r) {
            ht::log_line("[AUTH][redis] AUTH failed: no reply");
            return false;
        }
        bool ok = (r->type != REDIS_REPLY_ERROR);
        if (!ok) {
            ht::log_line(std::string("[AUTH][redis] AUTH error: ")+ (r->str ? r->str : ""));
        }
        freeReplyObject(r);
        if (!ok) return false;
    }
    if (_opt.db != 0) {
        redisReply* r = (redisReply*)redisCommand(ctx, "SELECT %d", _opt.db);
        if (!r) {
            ht::log_line("[AUTH][redis] SELECT failed: no reply");
            return false;
        }
        bool ok = (r->type != REDIS_REPLY_ERROR);
        if (!ok) {
            ht::log_line(std::string("[AUTH][redis] SELECT error: ")+ (r->str ? r->str : ""));
        }
        freeReplyObject(r);
        if (!ok) return false;
    }
    return true;
}

void AuthStore::redis_close_one(size_t idx) {
    if (idx >= _pool.size()) return;
    if (_pool[idx].ctx) {
        redisFree(_pool[idx].ctx);
        _pool[idx].ctx = nullptr;
    }
    _pool[idx].valid = false;
}

bool AuthStore::Slot::acquire() {
    if (have) return true;
    std::unique_lock<std::mutex> lk(store._pool_mtx);
    store._pool_cv.wait(lk, [&]{ return !store._free.empty(); });
    idx = store._free.front();
    store._free.pop_front();
    have = true;
    return true;
}

void AuthStore::Slot::release() {
    if (!have) return;
    {
        std::lock_guard<std::mutex> lk(store._pool_mtx);
        store._free.push_back(idx);
    }
    store._pool_cv.notify_one();
    idx = (size_t)-1;
    have = false;
}

::redisContext* AuthStore::Slot::ctx() {
    // Ensure connected; the slot is exclusively owned by this thread until release().
    auto& c = store._pool[idx];
    if (!c.valid || !c.ctx || c.ctx->err) {
        store.redis_close_one(idx);
        (void)store.redis_connect_one(idx);
    }
    return store._pool[idx].ctx;
}

bool AuthStore::redis_get_secret(const std::string& key_id, std::string& out_secret_bin) {
    // In-memory TTL cache
    {
        std::lock_guard<std::mutex> lk(_cache_mtx);
        auto it = _cache.find(key_id);
        if (it != _cache.end()) {
            if (std::chrono::steady_clock::now() < it->second.expires) {
                out_secret_bin = it->second.secret;
                return true;
            } else {
                _cache.erase(it);
            }
        }
    }

    // Acquire a connection slot
    Slot slot(*this);
    if (!slot.acquire()) return false;

    // Key: prefix + key_id
    const std::string rkey = _prefix + key_id;

    ::redisContext* c = slot.ctx();
    if (!c) return false;

    // Single GET
    redisReply* r = (redisReply*)redisCommand(c, "GET %s", rkey.c_str());
    if (!r) {
        // Connection likely broken; next acquire will reconnect
        return false;
    }

    bool ok = false;
    if (r->type == REDIS_REPLY_NIL) {
        ok = false; // not found
    } else if (r->type == REDIS_REPLY_STRING && r->str) {
        const std::string hex(r->str, r->len);
        if (hex.size() == 64) {
            std::string bin;
            if (hex_to_bytes(hex, bin) && bin.size()==32) {
                out_secret_bin = std::move(bin);
                ok = true;
            }
        }
    } else if (r->type == REDIS_REPLY_ERROR) {
        ht::log_line(std::string("[AUTH][redis] GET error: ")+(r->str? r->str : ""));
        ok = false;
    }
    freeReplyObject(r);

    if (ok) {
        std::lock_guard<std::mutex> lk(_cache_mtx);
        _cache[key_id] = CacheEntry{
            out_secret_bin,
            std::chrono::steady_clock::now() + std::chrono::seconds(_opt.cache_ttl_sec)
        };
    }
    return ok;
}

/* ---------------- Public lookup (dispatch by backend) ---------------- */

bool AuthStore::lookup(const std::string& key_id, std::string& out_secret_bin) {
    if (_backend == Backend::File) {
        std::lock_guard<std::mutex> lk(_file_mtx);
        auto it = _file_map.find(key_id);
        if (it == _file_map.end()) return false;
        out_secret_bin = it->second;
        return true;
    } else if (_backend == Backend::Redis) {
        return redis_get_secret(key_id, out_secret_bin);
    }
    return false;
}

} // namespace ht::internal

