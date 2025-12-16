/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/client.hpp"
#include "ht/log.hpp"
#include "ht/http_response.hpp"

#include "ht/internal/utils.hpp"
#include "ht/internal/http_parser.hpp"
#include "ht/internal/hmac.hpp"
#include "ht/internal/aead.hpp"
#include "ht/internal/time.hpp"
#include "ht/internal/tls_cli_ctx.hpp"
#include "ht/internal/http_low.hpp"  // shared TCP + HTTP response parser

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include <sstream>
#include <algorithm>
#include <mutex>
#include <memory>
#include <vector>

#include <chrono>
#include <limits>
#include <cstring>

#include <poll.h>
#include <cerrno>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

namespace {

// Returns remaining milliseconds until deadline, clamped to [0, INT_MAX].
[[nodiscard]] inline int remaining_ms(std::chrono::steady_clock::time_point deadline) noexcept {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    if (now >= deadline) return 0;
    const auto ms = duration_cast<milliseconds>(deadline - now).count();
    if (ms <= 0) return 0;
    if (ms > static_cast<long long>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(ms);
}

// Drain OpenSSL error stack into logs.
inline void log_openssl_errors(const char* where) {
    unsigned long e = 0;
    while ((e = ::ERR_get_error()) != 0) {
        char buf[256];
        ::ERR_error_string_n(e, buf, sizeof(buf));
        ht::log_line(std::string("[CLIENT] ") + where + ": " + buf);
    }
}

// Robust TLS handshake that handles WANT_READ/WANT_WRITE and bounded deadline.
// Works with both blocking and non-blocking sockets.
[[nodiscard]] bool ssl_connect_with_deadline(SSL* ssl, int fd, int timeout_sec) {
    if (!ssl || fd < 0) return false;

    const int effective_timeout = std::max(1, timeout_sec);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(effective_timeout);

    while (true) {
        ::ERR_clear_error();
        const int rc = ::SSL_connect(ssl);
        if (rc == 1) {
            return true;
        }

        const int ssl_err = ::SSL_get_error(ssl, rc);

        // OpenSSL handshake requires more I/O.
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            const short ev = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            const int ms = remaining_ms(deadline);
            if (ms <= 0) {
                ht::log_line("[CLIENT] SSL_connect timeout");
                return false;
            }
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = ev;
            int pr = 0;
            do {
                pr = ::poll(&pfd, 1, ms);
            } while (pr < 0 && errno == EINTR);

            if (pr <= 0) {
                ht::log_line("[CLIENT] SSL_connect poll() timeout or error");
                return false;
            }
            continue;
        }

        // Underlying socket error.
        if (ssl_err == SSL_ERROR_SYSCALL) {
            const int e = errno;
            if (e == EINTR) {
                continue;
            }
            if (e == EAGAIN || e == EWOULDBLOCK) {
                // Treat as transient. Wait for readability and retry.
                const int ms = remaining_ms(deadline);
                if (ms <= 0) {
                    ht::log_line("[CLIENT] SSL_connect timeout (EAGAIN)");
                    return false;
                }
                pollfd pfd{};
                pfd.fd = fd;
                pfd.events = POLLIN;
                int pr = 0;
                do {
                    pr = ::poll(&pfd, 1, ms);
                } while (pr < 0 && errno == EINTR);
                if (pr <= 0) {
                    ht::log_line("[CLIENT] SSL_connect poll() timeout (EAGAIN)");
                    return false;
                }
                continue;
            }

            ht::log_line(std::string("[CLIENT] SSL_connect syscall error: errno=") + std::to_string(e) +
                         " (" + std::strerror(e) + ")");
            log_openssl_errors("SSL_connect");
            return false;
        }

        // Protocol / certificate / other SSL-layer error.
        ht::log_line(std::string("[CLIENT] SSL_connect failed: ssl_error=") + std::to_string(ssl_err));
        log_openssl_errors("SSL_connect");
        return false;
    }
}

} // namespace

namespace ht {

struct Client::Impl {
    ClientConfig cfg;
    std::string secret_bin;  // 32B PSK

    std::unique_ptr<internal::TlsClientContext> tls; // only for TLS mode

    // Keep-alive state
    std::mutex mtx;
    std::unique_ptr<internal::TcpConn> plain;
    std::unique_ptr<SSL, void(*)(SSL*)> ssl{nullptr, [](SSL* s){ if(s){ SSL_free(s); } }};
    int served_on_conn = 0;

    Impl(const ClientConfig& c): cfg(c) {
        ht::set_log_file(cfg.log_file);
        if (!internal::hex_to_bytes(cfg.secret_hex, secret_bin) || secret_bin.size()!=32) {
            ht::log_line("[CLIENT] invalid secret_hex, must be 64 hex chars");
        }
        if (cfg.mode == Mode::TlsTube) {
            tls = std::make_unique<internal::TlsClientContext>(cfg);
        }
    }

    ~Impl() {
        std::lock_guard<std::mutex> lk(mtx);
        close_conn_locked();
    }

    void close_conn_locked() {
        if (ssl) {
            SSL* s = ssl.get();
            SSL_shutdown(s);
            ssl.reset(nullptr);
        }
        if (plain) {
            plain->close();
            plain.reset();
        }
        served_on_conn = 0;
    }

    bool ensure_conn_locked() {
        if (cfg.mode == Mode::TlsTube) {
            if (ssl) {
                if (served_on_conn < cfg.ka_max) return true;
                close_conn_locked();
            }
            // Open raw TCP
            plain = std::make_unique<internal::TcpConn>();
            if (!plain->open(cfg)) {
                plain.reset();
                return false;
            }

            // Wrap with SSL
            if (!tls || !tls->ctx()) {
                ht::log_line("[CLIENT] TLS ctx not ready");
                return false;
            }
            SSL* s = SSL_new(tls->ctx());
            if (!s) {
                ht::log_line("[CLIENT] SSL_new failed");
                return false;
            }
            SSL_set_fd(s, plain->fd());
            const std::string sni = cfg.tls_sni.empty() ? cfg.host : cfg.tls_sni;
            SSL_set_tlsext_host_name(s, sni.c_str());

            // IMPORTANT: certificate chain validation is not enough.
            // Hostname/IP verification must be explicitly configured.
            // This is only applied when tls_verify_peer=true.
            if (cfg.tls_verify_peer) {
                X509_VERIFY_PARAM* param = SSL_get0_param(s);
                if (!param) {
                    SSL_free(s);
                    plain->close();
                    plain.reset();
                    ht::log_line("[CLIENT] SSL_get0_param failed");
                    return false;
                }

                // If the expected name is an IP literal, verify against IP SAN.
                // Otherwise verify against DNS name (supports wildcards as per OpenSSL rules).
                unsigned char tmp[16];
                const bool is_ipv4 = (::inet_pton(AF_INET, sni.c_str(), tmp) == 1);
                const bool is_ipv6 = (!is_ipv4 && (::inet_pton(AF_INET6, sni.c_str(), tmp) == 1));
                if (is_ipv4 || is_ipv6) {
                    if (X509_VERIFY_PARAM_set1_ip_asc(param, sni.c_str()) != 1) {
                        SSL_free(s);
                        plain->close();
                        plain.reset();
                        ht::log_line("[CLIENT] X509_VERIFY_PARAM_set1_ip_asc failed");
                        return false;
                    }
                } else {
                    if (SSL_set1_host(s, sni.c_str()) != 1) {
                        SSL_free(s);
                        plain->close();
                        plain.reset();
                        ht::log_line("[CLIENT] SSL_set1_host failed");
                        return false;
                    }
                }
            }

            // Perform TLS handshake in non-blocking mode with a bounded deadline.
            // This avoids rare failures caused by treating SSL_ERROR_WANT_* as fatal.
            const int fd = plain->fd();
            const int old_flags = ::fcntl(fd, F_GETFL, 0);
            if (old_flags < 0 || ::fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
                SSL_free(s);
                plain->close();
                plain.reset();
                ht::log_line("[CLIENT] fcntl(O_NONBLOCK) failed");
                return false;
            }

            const int handshake_timeout_sec = std::max(5, cfg.connect_timeout_sec);
            const bool hs_ok = ssl_connect_with_deadline(s, fd, handshake_timeout_sec);

            // Restore original socket flags (typically back to blocking mode).
            (void)::fcntl(fd, F_SETFL, old_flags);

            if (!hs_ok) {
                SSL_free(s);
                plain->close();
                plain.reset();
                return false;
            }

            // Enforce verification result explicitly.
            if (cfg.tls_verify_peer) {
                const long vr = SSL_get_verify_result(s);
                if (vr != X509_V_OK) {
                    SSL_free(s);
                    plain->close();
                    plain.reset();
                    ht::log_line(std::string("[CLIENT] TLS verify failed: ") + X509_verify_cert_error_string(vr));
                    return false;
                }
            }

            ssl.reset(s);
            served_on_conn = 0;
            return true;
        }

        // Plain HTTP
        if (plain && served_on_conn < cfg.ka_max) return true;
        if (plain) { plain->close(); plain.reset(); }
        plain = std::make_unique<internal::TcpConn>();
        if (!plain->open(cfg)) { plain.reset(); return false; }
        served_on_conn = 0;
        return true;
    }

    bool send_all_locked(const std::string& data) {
        if (cfg.mode == Mode::TlsTube) {
            if (!ssl) return false;
            std::size_t off = 0;
            while (off < data.size()) {
                int n = SSL_write(ssl.get(), data.data() + off, (int)(data.size() - off));
                if (n <= 0) { (void)SSL_get_error(ssl.get(), n); return false; }
                off += (std::size_t)n;
            }
            return true;
        }
        return plain->send_all(data.data(), data.size());
    }

    bool recv_response_locked(HttpResponse& out) {
        std::string head;
        const std::string delim = "\r\n\r\n";

        if (cfg.mode == Mode::TlsTube) {
            char buf[1024];
            while (head.find(delim) == std::string::npos) {
                int n = SSL_read(ssl.get(), buf, sizeof(buf));
                if (n <= 0) { (void)SSL_get_error(ssl.get(), n); return false; }
                head.append(buf, buf + n);
                if (head.size() > (1u<<20)) return false;
            }
        } else {
            if (!plain->recv_until(head, delim, (1u<<20))) return false;
        }

        std::size_t hdr_end_off = 0;
        if (!internal::parse_http_response(head, hdr_end_off, out.status_code, out.status_text, out.headers)) return false;

        std::size_t content_len = 0;
        auto it = out.headers.find("Content-Length");
        if (it != out.headers.end()) {
            try { content_len = (std::size_t)std::stoul(it->second); } catch(...) { return false; }
        } else {
            return false;
        }

        out.body.clear();
        if (hdr_end_off < head.size()) {
            const char* p = head.data() + hdr_end_off;
            std::size_t have = head.size() - hdr_end_off;
            out.body.assign(p, p + std::min(have, content_len));
        }

        while (out.body.size() < content_len) {
            char buf[4096];
            const std::size_t need = content_len - out.body.size();
            int n = 0;

            if (cfg.mode == Mode::TlsTube) {
                n = SSL_read(ssl.get(), buf, std::min<std::size_t>(sizeof(buf), need));
                if (n <= 0) { (void)SSL_get_error(ssl.get(), n); return false; }
            } else {
                n = ::recv(plain->fd(), buf, std::min<std::size_t>(sizeof(buf), need), 0);
                if (n <= 0) return false;
            }
            out.body.append(buf, buf + n);
        }

        const std::string conn = internal::lower_copy(internal::hdr_ci(out.headers, "Connection"));
        const bool do_close = (conn == "close");
        served_on_conn++;

        if (do_close || served_on_conn >= cfg.ka_max) {
            close_conn_locked();
        }
        return true;
    }
};

Client::Client(const ClientConfig& cfg)
    : _p(std::make_unique<Client::Impl>(cfg)) {}

Client::~Client() = default;

bool Client::request(const std::string& method,
                     const std::string& path,
                     const std::unordered_map<std::string,std::string>& query,
                     const std::string& plaintext_body,
                     HttpResponse& out)
{
    std::lock_guard<std::mutex> lk(_p->mtx);
    if (!_p->ensure_conn_locked()) return false;

    // Prepare canonical elements (must be consistent for HMAC and AEAD)
    const std::string qcanon = internal::canonical_query_sorted(query);
    const std::string ts     = ht::utc_iso8601_now();
    const std::string nonce  = internal::random_hex(16);
    const std::string body_h = internal::sha256_hex(plaintext_body);
    const std::string method_up = internal::upper_copy(method);

    std::ostringstream oss_can;
    oss_can << "HT1\n" << method_up << "\n" << path << "\n" << qcanon
            << "\n" << body_h << "\n" << ts << "\n" << nonce << "\n" << _p->cfg.key_id;
    const std::string canonical = oss_can.str();

    // Sign canonical
    std::string mac_bin;
    if (!internal::hmac_sha256_bin(_p->secret_bin, canonical, mac_bin)) return false;
    const std::string sig_hex =
        internal::bytes_to_hex((const unsigned char*)mac_bin.data(), mac_bin.size());

    // Build request start-line and headers
    const std::string qstring = qcanon.empty() ? "" : ("?" + qcanon);
    std::string full_path = _p->cfg.base_path;
    if (!full_path.empty() && full_path[0] != '/') full_path = "/" + full_path;
    full_path += path + qstring;

    std::ostringstream req;
    req << method_up << " " << full_path << " HTTP/1.1\r\n";
    req << "Host: " << _p->cfg.host << "\r\n";
    req << "User-Agent: ht-client/1\r\n";
    req << "Accept: */*\r\n";
    req << "X-HT-Version: 1\r\n";
    req << "X-HT-KeyId: " << _p->cfg.key_id << "\r\n";
    req << "X-HT-Timestamp: " << ts << "\r\n";
    req << "X-HT-Nonce: " << nonce << "\r\n";
    req << "X-HT-Body-SHA256: " << body_h << "\r\n";
    req << "X-HT-Signature: " << sig_hex << "\r\n";
    req << "Connection: keep-alive\r\n";

    std::string wire_body;
    if (_p->cfg.mode == Mode::AuthAead) {
        const std::string aead_alg = (_p->cfg.aead == AeadAlg::Chacha20) ? "chacha20" : "aesgcm";
        const std::string req_nonce12_hex = internal::random_hex(12);
        std::string req_nonce12_bin; (void)internal::hex_to_bytes(req_nonce12_hex, req_nonce12_bin);

        std::string key32;
        if (!internal::derive_aead_key_32(_p->secret_bin, aead_alg, ts, _p->cfg.key_id, "c2s", key32)) {
            return false;
        }

        std::string ct;
        if (!internal::aead_encrypt_body(ct, plaintext_body, aead_alg, key32, req_nonce12_bin, canonical)) {
            internal::secure_wipe(key32);
            return false;
        }
        internal::secure_wipe(key32);

        wire_body.swap(ct);
        req << "X-HT-AEAD: " << aead_alg << "\r\n";
        req << "X-HT-AEAD-Nonce: " << req_nonce12_hex << "\r\n";
        req << "Content-Type: application/octet-stream\r\n";
    } else {
        wire_body = plaintext_body;
        req << "Content-Type: application/json\r\n";
    }

    req << "Content-Length: " << wire_body.size() << "\r\n";
    req << "\r\n";

    const std::string head = req.str();
    if (!_p->send_all_locked(head)) return false;
    if (!wire_body.empty()) {
        if (!_p->send_all_locked(wire_body)) return false;
    }

    // Receive and parse response
    if (!_p->recv_response_locked(out)) return false;

    // AEAD response decryption (mode B): derive s2c with same ts/key_id
    if (_p->cfg.mode == Mode::AuthAead) {
        const std::string aead_alg = internal::lower_copy(internal::hdr_ci(out.headers, "X-HT-AEAD"));
        const std::string resp_nonce_hex = internal::hdr_ci(out.headers, "X-HT-AEAD-Nonce");
        if (aead_alg != "chacha20" && aead_alg != "aesgcm") return false;

        std::string resp_nonce12;
        if (!internal::hex_to_bytes(resp_nonce_hex, resp_nonce12) || resp_nonce12.size() != 12) return false;

        std::string key32_s2c;
        if (!internal::derive_aead_key_32(_p->secret_bin, aead_alg, ts, _p->cfg.key_id, "s2c", key32_s2c)) {
            return false;
        }

        std::string pt;
        if (!internal::aead_decrypt_body(pt, out.body, aead_alg, key32_s2c, resp_nonce12, canonical)) {
            internal::secure_wipe(key32_s2c);
            return false;
        }
        internal::secure_wipe(key32_s2c);
        out.body.swap(pt);
    }

    return true;
}

bool Client::post_echo(const std::string& payload, HttpResponse& out) {
    return request("POST", "/echo", /*query*/{}, payload, out);
}

} // namespace ht
