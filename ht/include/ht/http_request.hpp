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

namespace ht {

// Plain HTTP request structure as produced by our parser.
struct HttpRequest {
    std::string method;   // "GET", "POST", ...
    std::string path;     // "/echo"
    std::string query;    // "a=1&b=2"
    std::string httpver;  // "HTTP/1.1"
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

} // namespace ht

