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
#include <cstddef>
#include "ht/client_config.hpp"

namespace ht::internal {

// RAII TCP connection with timeouts and basic send/recv helpers.
class TcpConn {
public:
    TcpConn() = default;
    ~TcpConn();

    // Open TCP connection to cfg.host:cfg.port with timeouts.
    bool open(const ht::ClientConfig& cfg);

    void close();
    int  fd() const { return _fd; }

    bool send_all(const char* d, std::size_t len);
    bool recv_exact(char* d, std::size_t len);
    bool recv_until(std::string& out, const std::string& delim, std::size_t max_total = (1u<<20));

private:
    int _fd = -1;
};

// Parse HTTP/1.1 response with mandatory Content-Length.
bool parse_http_response(const std::string& head_and_maybe_body,
                         std::size_t& hdr_end_off,
                         int& status_code,
                         std::string& status_text,
                         std::unordered_map<std::string,std::string>& headers);

} // namespace ht::internal

