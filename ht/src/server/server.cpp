/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/server.hpp"
#include "ht/log.hpp"

#include <stdexcept>
#include <string>
#include <cstring>
#include <cerrno>
#include <thread>
#include <utility>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Forward declarations of per-connection handlers provided by http_* modules.
namespace ht::internal {

// Handles a single plain HTTP connection (keep-alive is managed inside).
void handle_connection_plain(int fd,
                             const ht::ServerConfig& cfg,
                             const std::string& peer_ip,
                             ht::internal::AuthStore& auth,
                             ht::internal::NonceCache& nonces,
                             ht::internal::TokenBucketMap& ip_rl,
                             ht::internal::TokenBucketMap& key_rl);

// Handles a single HTTPS connection (keep-alive is managed inside).
void handle_connection_tls(int fd,
                           const ht::ServerConfig& cfg,
                           const std::string& peer_ip,
                           ht::internal::TlsContext& tls,
                           ht::internal::AuthStore& auth,
                           ht::internal::NonceCache& nonces,
                           ht::internal::TokenBucketMap& ip_rl,
                           ht::internal::TokenBucketMap& key_rl);

} // namespace ht::internal

namespace ht {

// ---------- small socket helpers (internal) ----------

static int set_reuseaddr(int s) { int o = 1; return ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o)); }
static int set_reuseport(int s) { int o = 1; return ::setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &o, sizeof(o)); }
static int set_nodelay (int s)  { int o = 1; return ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &o, sizeof(o)); }

static std::string sockaddr_to_ip(const sockaddr_storage& ss) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (ss.ss_family == AF_INET) {
        const sockaddr_in* a = reinterpret_cast<const sockaddr_in*>(&ss);
        inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf));
    } else if (ss.ss_family == AF_INET6) {
        const sockaddr_in6* a = reinterpret_cast<const sockaddr_in6*>(&ss);
        inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf));
    } else {
        std::snprintf(buf, sizeof(buf), "unknown");
    }
    return std::string(buf);
}

// ---------- Server impl ----------

Server::Server(const ServerConfig& cfg)
    : _cfg(cfg)
{
    // --- Initialize auth backend (file or Redis) ---
    if (_cfg.auth_use_redis) {
        internal::AuthStore::RedisOptions ropt;
        ropt.host          = _cfg.redis.host;
        ropt.port          = _cfg.redis.port;
        ropt.db            = _cfg.redis.db;
        ropt.password      = _cfg.redis.password;
        ropt.key_prefix    = _cfg.redis.key_prefix;
        ropt.pool_size     = _cfg.redis.pool_size;
        ropt.timeout_ms    = _cfg.redis.timeout_ms;
        ropt.cache_ttl_sec = _cfg.redis.cache_ttl_sec;

        if (!_auth.init_redis(ropt)) {
            throw std::runtime_error("AuthStore: failed to init Redis backend");
        }
    } else {
        if (_cfg.auth_file.empty()) {
            throw std::runtime_error("AuthStore: auth_file is required when Redis is disabled");
        }
        if (!_auth.init_file(_cfg.auth_file)) {
            throw std::runtime_error("AuthStore: failed to load auth_file");
        }
    }

    // --- Initialize TLS context if needed ---
    if (_cfg.mode == Mode::TlsTube) {
        // The TLS context object holds SSL_CTX and resumption settings.
        // Constructor performs necessary initialization (see tls_ctx.cpp).
        _tls = std::make_unique<internal::TlsContext>(_cfg);
    }

    // --- Start background nonce GC loop (lightweight) ---
    _nonce_gc_thread = std::thread(&Server::nonce_gc_loop, this);
}

Server::~Server() {
    stop();
    if (_nonce_gc_thread.joinable()) {
        _nonce_gc_thread.join();
    }
}

void Server::stop() {
    // Set stop flag; accept loops will observe it and break.
    _stop.store(true, std::memory_order_relaxed);
    // Note: we do not hold a listening FD here to close forcefully.
    //       If you add one, close() it here to unblock accept().
}

int Server::create_listen_socket() {
    int srv = ::socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        ht::log_line(std::string("[FATAL] socket() failed: ") + std::strerror(errno));
        throw std::runtime_error("socket() failed");
    }
    (void)set_reuseaddr(srv);
    (void)set_reuseport(srv);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(_cfg.port);

    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ht::log_line(std::string("[FATAL] bind() failed: ") + std::strerror(errno));
        ::close(srv);
        throw std::runtime_error("bind() failed");
    }
    if (listen(srv, 512) < 0) {
        ht::log_line(std::string("[FATAL] listen() failed: ") + std::strerror(errno));
        ::close(srv);
        throw std::runtime_error("listen() failed");
    }
    return srv;
}

void Server::run() {
    // Basic boot log
    ht::log_line("[INFO] HMAC-Transport server starting...");
    {
        std::string m = (_cfg.mode == Mode::AuthOnly ? "A"
                        : _cfg.mode == Mode::AuthAead ? "B" : "C");
        ht::log_line(std::string("[INFO] Mode: ") + m);
    }
    ht::log_line("[INFO] Port: " + std::to_string(_cfg.port));
    if (_cfg.auth_use_redis) {
        ht::log_line(std::string("[INFO] Auth backend: REDIS host=") + _cfg.redis.host +
                     ":" + std::to_string(_cfg.redis.port) +
                     " db=" + std::to_string(_cfg.redis.db) +
                     " prefix=" + _cfg.redis.key_prefix);
    } else {
        ht::log_line("[INFO] Auth backend: FILE " + _cfg.auth_file);
    }
    if (_cfg.redact_errors) {
        ht::log_line("[INFO] Error redaction: ENABLED");
    }
    if (_cfg.rl_ip_rate > 0.0 && _cfg.rl_ip_burst > 0.0) {
        ht::log_line("[INFO] RL-IP: rate=" + std::to_string(_cfg.rl_ip_rate) +
                     " burst=" + std::to_string(_cfg.rl_ip_burst));
    }
    if (_cfg.rl_key_rate > 0.0 && _cfg.rl_key_burst > 0.0) {
        ht::log_line("[INFO] RL-Key: rate=" + std::to_string(_cfg.rl_key_rate) +
                     " burst=" + std::to_string(_cfg.rl_key_burst));
    }
    ht::log_line("[INFO] Anti-replay: nonce_ttl=" + std::to_string(_cfg.nonce_ttl_sec) +
                 "s, max_pending=" + std::to_string(_cfg.max_pending));
    ht::log_line("[INFO] KA timeout=" + std::to_string(_cfg.ka_timeout_sec) +
                 "s, KA max=" + std::to_string(_cfg.ka_max));

    // Dispatch transport
    if (_cfg.mode == Mode::TlsTube) {
        serve_tls();
    } else {
        serve_plain();
    }
}

void Server::nonce_gc_loop() {
    // Adaptive sleep: min(100ms, max(50ms, 0.1 * nonce_ttl))
    while (!_stop.load(std::memory_order_relaxed)) {
        int ms = 100;
        if (_cfg.nonce_ttl_sec > 0) {
            ms = std::max(50, std::min(1000, _cfg.nonce_ttl_sec * 100));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));

        // Enforce TTL proactively. Without this, the cache only shrinks under
        // pressure-based pruning, which makes memory usage spiky.
        if (_cfg.nonce_ttl_sec > 0) {
            _nonces.gc(_cfg.nonce_ttl_sec);
        }
    }
}

void Server::serve_plain() {
    int srv = create_listen_socket();
    ht::log_line(std::string("[INFO] Listening HTTP on :") + std::to_string(_cfg.port) +
                 " mode=" + (_cfg.mode == Mode::AuthAead ? "B" : "A"));

    while (!_stop.load(std::memory_order_relaxed)) {
        sockaddr_storage cli{};
        socklen_t cl = sizeof(cli);
        int fd = ::accept(srv, reinterpret_cast<sockaddr*>(&cli), &cl);
        if (fd < 0) {
            if (errno == EINTR) continue;
            // transient error; continue
            continue;
        }
        (void)set_nodelay(fd);
        std::string peer = sockaddr_to_ip(cli);

        // Detach a per-connection handler; it will manage the fd lifetime.
        std::thread([this, fd, peer]() {
            internal::handle_connection_plain(fd, this->_cfg, peer,
                                              this->_auth, this->_nonces,
                                              this->_ip_rl, this->_key_rl);
            // handler is responsible for closing the fd
        }).detach();
    }

    ::close(srv);
}

void Server::serve_tls() {
    // TLS mode requires a valid TLS context; constructed in the ctor.
    if (!_tls) {
        throw std::runtime_error("TLS requested but TlsContext is not initialized");
    }

    int srv = create_listen_socket();
    ht::log_line(std::string("[INFO] Listening HTTPS on :") + std::to_string(_cfg.port) +
                 " mode=C");

    while (!_stop.load(std::memory_order_relaxed)) {
        sockaddr_storage cli{};
        socklen_t cl = sizeof(cli);
        int fd = ::accept(srv, reinterpret_cast<sockaddr*>(&cli), &cl);
        if (fd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        (void)set_nodelay(fd);
        std::string peer = sockaddr_to_ip(cli);

        // Detach a per-connection handler; it will manage the fd lifetime.
        std::thread([this, fd, peer]() {
            internal::handle_connection_tls(fd, this->_cfg, peer, *this->_tls,
                                            this->_auth, this->_nonces,
                                            this->_ip_rl, this->_key_rl);
            // handler is responsible for closing the fd and SSL shutdown
        }).detach();
    }

    ::close(srv);
}

} // namespace ht
