/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/server_config.hpp"
#include "ht/http_request.hpp"
#include "ht/internal/http_parser.hpp"
#include "ht/internal/utils.hpp"
#include "ht/internal/hmac.hpp"
#include "ht/internal/aead.hpp"
#include "ht/internal/ratelimit.hpp"
#include "ht/internal/auth.hpp"
#include "ht/internal/nonce_cache.hpp"
#include "ht/internal/time.hpp"
#include "ht/internal/tls_ctx.hpp"
#include "ht/log.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <strings.h>
#include <sstream>
#include <vector>
#include <algorithm>

namespace ht::internal {

// --- HTTP/1.1 keep-alive helpers ---

static bool is_http11(const std::string& ver) {
    return ver == "HTTP/1.1";
}

static bool should_keep_alive(const ht::HttpRequest& R) {
    std::string conn = lower_copy(hdr_ci(R, "Connection"));
    if (is_http11(R.httpver)) {
        return (conn != "close");
    } else {
        return (conn == "keep-alive");
    }
}

// --- TLS I/O helpers ---

static bool ssl_send_all(SSL* ssl, const char* d, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, d + off, static_cast<int>(len - off));
        if (n <= 0) {
            (void)SSL_get_error(ssl, n);
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

static void build_common_headers(std::ostringstream& oss,
                                 const ht::ServerConfig& cfg,
                                 std::size_t content_len,
                                 bool keep_alive)
{
    oss << "Content-Length: " << content_len << "\r\n";
    if (keep_alive) {
        oss << "Connection: keep-alive\r\n";
        oss << "Keep-Alive: timeout=" << cfg.ka_timeout_sec
            << ", max=" << cfg.ka_max << "\r\n";
    } else {
        oss << "Connection: close\r\n";
    }
}

static void send_http_resp_ssl_ex(SSL* ssl,
                                  const ht::ServerConfig& cfg,
                                  int sc,
                                  const char* st,
                                  const std::string& body,
                                  bool keep_alive,
                                  const std::vector<std::pair<std::string,std::string>>& extra_hdrs,
                                  const char* ctype = "application/json")
{
    std::ostringstream oss;
    oss << "HTTP/1.1 " << sc << " " << st << "\r\n";
    oss << "Content-Type: " << ctype << "\r\n";
    for (const auto& kv : extra_hdrs) {
        oss << kv.first << ": " << kv.second << "\r\n";
    }
    build_common_headers(oss, cfg, body.size(), keep_alive);
    oss << "\r\n";
    const std::string h = oss.str();
    (void)ssl_send_all(ssl, h.data(), h.size());
    (void)ssl_send_all(ssl, body.data(), body.size());
}

static void send_http_resp_ssl(SSL* ssl,
                               const ht::ServerConfig& cfg,
                               int sc,
                               const char* st,
                               const std::string& body,
                               bool keep_alive,
                               const char* ctype = "application/json")
{
    send_http_resp_ssl_ex(ssl, cfg, sc, st, body, keep_alive, {}, ctype);
}

static std::string make_error_body(const ht::ServerConfig& cfg,
                                   const std::string& reason)
{
    if (cfg.redact_errors) return R"({"status":"ERROR"})";
    return std::string(R"({"status":"ERROR","reason":")") + reason + R"("})";
}

static bool recv_http_request_ssl(SSL* ssl,
                                  const ht::ServerConfig& cfg,
                                  ht::HttpRequest& R)
{
    std::string req;
    req.reserve(4096);
    char buf[1024];
    while (true) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            (void)SSL_get_error(ssl, n);
            return false;
        }
        req.append(buf, buf + n);
        if (req.find("\r\n\r\n") != std::string::npos) break;
        if (req.size() > (1u << 20)) return false; // header abuse guard
    }

    std::size_t hdr_end = req.find("\r\n\r\n");
    std::string hdrs = req.substr(0, hdr_end);
    std::size_t line_end = hdrs.find("\r\n");
    if (line_end == std::string::npos) return false;
    std::string first = hdrs.substr(0, line_end);
    if (!parse_request_line(first, R)) return false;

    std::size_t pos = line_end + 2;
    R.headers.clear();
    while (pos < hdrs.size()) {
        std::size_t next = hdrs.find("\r\n", pos);
        if (next == std::string::npos) next = hdrs.size();
        std::string line = hdrs.substr(pos, next - pos);
        pos = next + 2;
        std::size_t c = line.find(':');
        if (c != std::string::npos) {
            std::string k = line.substr(0, c), v = line.substr(c + 1);
            trim_inplace(k);
            trim_inplace(v);
            R.headers[k] = v;
        }
    }

    std::size_t content_len = 0;
    auto it = R.headers.find("Content-Length");
    if (it != R.headers.end()) {
        try {
            content_len = static_cast<std::size_t>(std::stoul(it->second));
        } catch (...) {
            return false;
        }
        if (content_len > cfg.max_body) return false;
    }

    R.body.clear();
    if (hdr_end + 4 < req.size()) {
        const char* p = req.data() + hdr_end + 4;
        std::size_t have = req.size() - (hdr_end + 4);
        R.body.assign(p, p + std::min(have, content_len));
    }
    while (R.body.size() < content_len) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            (void)SSL_get_error(ssl, n);
            return false;
        }
        std::size_t need = content_len - R.body.size();
        R.body.append(buf, buf + std::min<std::size_t>(static_cast<std::size_t>(n), need));
    }
    return true;
}

// --- Per-request dispatcher (TLS) ---

static bool dispatch_request_tls(SSL* ssl,
                                 const ht::ServerConfig& cfg,
                                 const std::string& peer_ip,
                                 const ht::HttpRequest& R,
                                 ht::internal::AuthStore& auth,
                                 ht::internal::NonceCache& nonces,
                                 ht::internal::TokenBucketMap& /*ip_rl*/,
                                 ht::internal::TokenBucketMap& key_rl)
{
    bool ka = should_keep_alive(R);

    if (R.method != "GET" && R.method != "POST") {
        send_http_resp_ssl(ssl, cfg, 405, "Method Not Allowed",
                           make_error_body(cfg, "ONLY_GET_OR_POST"), ka);
        return ka;
    }

    if (R.path == "/health") {
        send_http_resp_ssl(ssl, cfg, 200, "OK", R"({"status":"OK"})", ka);
        return ka;
    }
    if (R.path == "/time" && R.method == "GET") {
        std::ostringstream os;
        os << R"({"status":"OK","utc":")" << ht::utc_iso8601_now() << R"("})";
        send_http_resp_ssl(ssl, cfg, 200, "OK", os.str(), ka);
        return ka;
    }

    if (R.path == "/echo" && R.method == "POST") {
        if (cfg.mode == ht::Mode::AuthAead) {
            // Mode B (AEAD)
            auto vr = verify_request_common(R, cfg, auth, nonces, /*verify_plain_body_hash=*/false);
            if (!vr.ok) {
                ht::log_line(std::string("[401] TLS ip=") + peer_ip + " reason=" + vr.reason);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, vr.reason), ka);
                return ka;
            }
            if (!key_rl.allow(vr.key_id, cfg.rl_key_rate, cfg.rl_key_burst)) {
                ht::log_line(std::string("[429] TLS ip=") + peer_ip +
                             " key=" + vr.key_id + " reason=KEY_RATE_LIMIT");
                send_http_resp_ssl(ssl, cfg, 429, "Too Many Requests",
                                   make_error_body(cfg, "RATE_LIMIT"), ka);
                return ka;
            }

            const std::string aead_alg  = hdr_ci(R, "X-HT-AEAD");
            const std::string nonce_hex = hdr_ci(R, "X-HT-AEAD-Nonce");
            if (aead_alg != "chacha20" && aead_alg != "aesgcm") {
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "BAD_AEAD_ALG"), ka);
                return ka;
            }

            std::string psk;
            if (!auth.lookup(vr.key_id, psk)) {
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "UNKNOWN_KEY"), ka);
                return ka;
            }
            const std::string ts_hdr = hdr_ci(R, "X-HT-Timestamp");

            std::string key32;
            if (!derive_aead_key_32(psk, aead_alg, ts_hdr, vr.key_id, "c2s", key32)) {
                secure_wipe(psk);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "AEAD_KEY_DERIVE_FAIL"), ka);
                return ka;
            }
            std::string nonce12;
            if (!hex_to_bytes(nonce_hex, nonce12) || nonce12.size() != 12) {
                secure_wipe(psk);
                secure_wipe(key32);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "BAD_AEAD_NONCE"), ka);
                return ka;
            }

            std::string plaintext;
            if (!aead_decrypt_body(plaintext, R.body, aead_alg, key32, nonce12, vr.canonical)) {
                secure_wipe(psk);
                secure_wipe(key32);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "AEAD_DECRYPT_FAIL"), ka);
                return ka;
            }

            const std::string body_h  = hdr_ci(R, "X-HT-Body-SHA256");
            const std::string body_sha = sha256_hex(plaintext);
            if (!ct_equal_hex(body_sha, body_h)) {
                secure_wipe(psk);
                secure_wipe(key32);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "BAD_BODY_HASH"), ka);
                return ka;
            }

            unsigned char resp_iv[12];
            if (RAND_bytes(resp_iv, sizeof(resp_iv)) != 1) {
                secure_wipe(psk);
                secure_wipe(key32);
                send_http_resp_ssl(ssl, cfg, 500, "Internal Server Error",
                                   make_error_body(cfg, "RAND_FAIL"), ka);
                return ka;
            }
            std::string resp_nonce12(reinterpret_cast<const char*>(resp_iv), sizeof(resp_iv));

            std::string key32_s2c;
            if (!derive_aead_key_32(psk, aead_alg, ts_hdr, vr.key_id, "s2c", key32_s2c)) {
                secure_wipe(psk);
                secure_wipe(key32);
                secure_wipe(key32_s2c);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, "AEAD_KEY_DERIVE_FAIL"), ka);
                return ka;
            }

            std::string ct;
            if (!aead_encrypt_body(ct, plaintext, aead_alg, key32_s2c, resp_nonce12, vr.canonical)) {
                secure_wipe(psk);
                secure_wipe(key32);
                secure_wipe(key32_s2c);
                send_http_resp_ssl(ssl, cfg, 500, "Internal Server Error",
                                   make_error_body(cfg, "AEAD_ENCRYPT_FAIL"), ka);
                return ka;
            }

            std::vector<std::pair<std::string,std::string>> extra{
                {"X-HT-AEAD", aead_alg},
                {"X-HT-AEAD-Nonce", bytes_to_hex(reinterpret_cast<const unsigned char*>(resp_nonce12.data()),
                                                 resp_nonce12.size())}
            };
            send_http_resp_ssl_ex(ssl, cfg, 200, "OK", ct, ka, extra, "application/octet-stream");

            secure_wipe(psk);
            secure_wipe(key32);
            secure_wipe(key32_s2c);
            ht::log_line(std::string("[200] TLS mode=B OK ip=") + peer_ip);
            return ka;
        } else {
            // Modes A / C
            auto vr = verify_request_common(R, cfg, auth, nonces, /*verify_plain_body_hash=*/true);
            if (!vr.ok) {
                ht::log_line(std::string("[401] TLS ip=") + peer_ip + " reason=" + vr.reason);
                send_http_resp_ssl(ssl, cfg, 401, "Unauthorized",
                                   make_error_body(cfg, vr.reason), ka);
                return ka;
            }
            if (!key_rl.allow(vr.key_id, cfg.rl_key_rate, cfg.rl_key_burst)) {
                ht::log_line(std::string("[429] TLS ip=") + peer_ip +
                             " key=" + vr.key_id + " reason=KEY_RATE_LIMIT");
                send_http_resp_ssl(ssl, cfg, 429, "Too Many Requests",
                                   make_error_body(cfg, "RATE_LIMIT"), ka);
                return ka;
            }
            std::ostringstream os;
            os << R"({"status":"OK","echo_size":)" << R.body.size() << "}";
            send_http_resp_ssl(ssl, cfg, 200, "OK", os.str(), ka);
            ht::log_line(std::string("[200] TLS mode=A/C OK ip=") + peer_ip);
            return ka;
        }
    }

    send_http_resp_ssl(ssl, cfg, 404, "Not Found",
                       make_error_body(cfg, "NOT_FOUND"), ka);
    return ka;
}

// --- Exported entry point for server.cpp ---

void handle_connection_tls(int fd,
                           const ht::ServerConfig& cfg,
                           const std::string& peer_ip,
                           ht::internal::TlsContext& tls,
                           ht::internal::AuthStore& auth,
                           ht::internal::NonceCache& nonces,
                           ht::internal::TokenBucketMap& ip_rl,
                           ht::internal::TokenBucketMap& key_rl)
{
    SSL_CTX* server_ctx = tls.ctx(); // obtain underlying SSL_CTX* from wrapper
    SSL* ssl = SSL_new(server_ctx);
    if (!ssl) { ::close(fd); return; }
    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) <= 0) {
        (void)ERR_get_error(); // drain errors
        SSL_free(ssl);
        ::close(fd);
        return;
    }

    // Apply kernel timeouts to the underlying socket
    timeval tv{cfg.ka_timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int served = 0;
    while (served < cfg.ka_max) {
        if (!ip_rl.allow(peer_ip, cfg.rl_ip_rate, cfg.rl_ip_burst)) {
            ht::log_line(std::string("[429] TLS ip=") + peer_ip + " reason=IP_RATE_LIMIT");
            ht::HttpRequest dummy;
            if (!recv_http_request_ssl(ssl, cfg, dummy)) break;
            bool ka = should_keep_alive(dummy);
            send_http_resp_ssl(ssl, cfg, 429, "Too Many Requests",
                               make_error_body(cfg, "RATE_LIMIT"), ka);
            if (!ka) break;
            ++served;
            continue;
        }

        ht::HttpRequest R;
        if (!recv_http_request_ssl(ssl, cfg, R)) break;

        bool ka_next = dispatch_request_tls(ssl, cfg, peer_ip, R,
                                            auth, nonces, ip_rl, key_rl);
        ++served;
        if (!ka_next) break;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(fd);
}

} // namespace ht::internal

