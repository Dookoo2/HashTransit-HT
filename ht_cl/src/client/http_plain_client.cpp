/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/client_config.hpp"
#include "ht/http_response.hpp"
#include "ht/log.hpp"
#include "ht/internal/utils.hpp"
#include "ht/internal/http_parser.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <algorithm>

namespace ht {
namespace {

// Simple RAII for a TCP socket fd
class TcpConn {
public:
    TcpConn() = default;
    ~TcpConn(){ close(); }

    bool open(const ht::ClientConfig& cfg) {
        close();

        struct addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = nullptr;
        int rc = getaddrinfo(cfg.host.c_str(), std::to_string(cfg.port).c_str(), &hints, &res);
        if (rc != 0 || !res) {
            ht::log_line(std::string("[TCP] getaddrinfo failed: ") + gai_strerror(rc));
            return false;
        }
        int s = -1;
        for (auto* p = res; p; p = p->ai_next) {
            s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (s < 0) continue;

            // connect with timeout via blocking + SO_SNDTIMEO/SO_RCVTIMEO (coarse)
            timeval tv{cfg.connect_timeout_sec, 0};
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            if (::connect(s, p->ai_addr, p->ai_addrlen) == 0) {
                int one = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                _fd = s;
                break;
            }
            ::close(s);
            s = -1;
        }
        freeaddrinfo(res);

        if (_fd < 0) {
            ht::log_line("[TCP] connect failed");
            return false;
        }

        // set IO timeout
        timeval tv2{cfg.io_timeout_sec, 0};
        setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));
        setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
        return true;
    }

    void close(){ if (_fd>=0) { ::close(_fd); _fd=-1; } }
    int  fd() const { return _fd; }

    bool send_all(const char* d, std::size_t len) {
        std::size_t off = 0;
        while (off < len) {
            ssize_t n = ::send(_fd, d + off, len - off, MSG_NOSIGNAL);
            if (n <= 0) return false;
            off += (std::size_t)n;
        }
        return true;
    }

    bool recv_exact(char* d, std::size_t len) {
        std::size_t off = 0;
        while (off < len) {
            ssize_t n = ::recv(_fd, d + off, len - off, 0);
            if (n <= 0) return false;
            off += (std::size_t)n;
        }
        return true;
    }

    bool recv_until(std::string& out, const std::string& delim, std::size_t max_total = (1u<<20)) {
        char buf[1024];
        while (out.find(delim) == std::string::npos) {
            ssize_t n = ::recv(_fd, buf, sizeof(buf), 0);
            if (n <= 0) return false;
            out.append(buf, buf + n);
            if (out.size() > max_total) return false;
        }
        return true;
    }

private:
    int _fd = -1;
};

// Parse HTTP/1.1 response with mandatory Content-Length.
// Returns false on parse error / early close / timeout.
bool parse_http_response(const std::string& head_and_maybe_body,
                         std::size_t& hdr_end_off,
                         int& status_code,
                         std::string& status_text,
                         std::unordered_map<std::string,std::string>& headers)
{
    std::size_t hdr_end = head_and_maybe_body.find("\r\n\r\n");
    if (hdr_end == std::string::npos) return false;
    hdr_end_off = hdr_end + 4;

    std::string hdrs = head_and_maybe_body.substr(0, hdr_end);
    std::size_t line_end = hdrs.find("\r\n");
    if (line_end == std::string::npos) return false;
    std::string status = hdrs.substr(0, line_end);
    // "HTTP/1.1 200 OK"
    std::istringstream iss(status);
    std::string httpver;
    if (!(iss >> httpver >> status_code)) return false;
    std::getline(iss, status_text);
    if (!status_text.empty() && status_text[0] == ' ') status_text.erase(0,1);

    headers.clear();
    std::size_t pos = line_end + 2;
    while (pos < hdrs.size()) {
        std::size_t next = hdrs.find("\r\n", pos);
        if (next == std::string::npos) next = hdrs.size();
        std::string line = hdrs.substr(pos, next - pos);
        pos = next + 2;
        std::size_t c = line.find(':');
        if (c != std::string::npos) {
            std::string k = line.substr(0, c), v = line.substr(c + 1);
            ht::internal::trim_inplace(k);
            ht::internal::trim_inplace(v);
            headers[k] = v;
        }
    }
    return true;
}

} // namespace
} // namespace ht

