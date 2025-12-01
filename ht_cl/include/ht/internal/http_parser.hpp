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
struct HttpRequest; // fwd if needed elsewhere
}

namespace ht::internal {

// Parse "GET /path?x=1 HTTP/1.1" (not used client-side for requests; kept for symmetry)
bool parse_request_line(const std::string& line, ht::HttpRequest& r);

// Query helpers (used for canonicalization)
std::unordered_map<std::string,std::string> parse_query(const std::string& q);
std::string canonical_query_sorted(const std::unordered_map<std::string,std::string>& params);

// Case-insensitive header lookup in a response-hash (utility)
std::string hdr_ci(const std::unordered_map<std::string,std::string>& H, const char* name);

} // namespace ht::internal

