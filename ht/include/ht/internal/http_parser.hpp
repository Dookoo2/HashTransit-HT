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
#include "ht/http_request.hpp"

namespace ht::internal {

// Parse "GET /path?x=1 HTTP/1.1"
bool parse_request_line(const std::string& line, ht::HttpRequest& r);

// Parse query string into map
std::unordered_map<std::string, std::string> parse_query(const std::string& q);

// Make sorted canonical query string
std::string canonical_query_sorted(const std::unordered_map<std::string,std::string>& params);

// Case-insensitive header lookup
std::string hdr_ci(const ht::HttpRequest& R, const char* name);

} // namespace ht::internal

