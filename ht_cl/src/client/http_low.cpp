// SPDX-License-Identifier: Apache-2.0
// Part of the HashTransit (HT) project.
// ht_cl/src/client/http_low.cpp

#include "ht/internal/http_low.hpp"
#include "ht/log.hpp"
#include "ht/internal/utils.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <cerrno>
#include <cstring>
#include <sstream>

// NEW:
#include <fcntl.h>   // fcntl, O_NONBLOCK
#include <poll.h>    // poll

namespace ht::internal {

TcpConn::~TcpConn() { close(); }

bool TcpConn::open(const ht::ClientConfig& cfg) {
    close();

    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(cfg.host.c_str(), std::to_string(cfg.port).c_str(), &hints, &res);
    if (rc != 0 || !res) {
        ht::log_line(std::string("[TCP] getaddrinfo failed: ") + gai_strerror(rc));
        return false;
    }

    const int connect_timeout_ms = std::max(1, cfg.connect_timeout_sec) * 1000;

    int s_ok = -1;
    for (auto* p = res; p; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;

        // Switch to non-blocking for a bounded-time connect
        int flags = fcntl(s, F_GETFL, 0);
        if (flags < 0) { ::close(s); continue; }
        if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) { ::close(s); continue; }

        int ret = ::connect(s, p->ai_addr, p->ai_addrlen);
        if (ret == 0) {
            // Connected immediately
        } else if (ret < 0 && errno == EINPROGRESS) {
            // Wait for connect completion (writable) with timeout
            struct pollfd pfd;
            pfd.fd     = s;
            pfd.events = POLLOUT;
            pfd.revents = 0;

            int pr = ::poll(&pfd, 1, connect_timeout_ms);
            if (pr <= 0 || !(pfd.revents & POLLOUT)) {
                // timeout or not writable -> this addr failed
                ::close(s);
                continue;
            }
            // Check the actual connect() status
            int soerr = 0;
            socklen_t slen = sizeof(soerr);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
                ::close(s);
                continue;
            }
        } else {
            // Immediate error
            ::close(s);
            continue;
        }

        // Back to blocking mode for normal I/O (SO_*TIMEO will work)
        (void)fcntl(s, F_SETFL, flags);

        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        // Apply per-op I/O timeouts
        timeval tv{cfg.io_timeout_sec, 0};
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        s_ok = s;
        break;
    }
    freeaddrinfo(res);

    if (s_ok < 0) {
        ht::log_line("[TCP] connect failed (timed out or refused)");
        return false;
    }

    _fd = s_ok;
    return true;
}

void TcpConn::close(){
    if (_fd>=0) { ::close(_fd); _fd=-1; }
}

bool TcpConn::send_all(const char* d, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(_fd, d + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) return false;
        off += (std::size_t)n;
    }
    return true;
}

bool TcpConn::recv_exact(char* d, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = ::recv(_fd, d + off, len - off, 0);
        if (n <= 0) return false;
        off += (std::size_t)n;
    }
    return true;
}

bool TcpConn::recv_until(std::string& out, const std::string& delim, std::size_t max_total) {
    char buf[1024];
    while (out.find(delim) == std::string::npos) {
        ssize_t n = ::recv(_fd, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        out.append(buf, buf + n);
        if (out.size() > max_total) return false;
    }
    return true;
}

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

} // namespace ht::internal

