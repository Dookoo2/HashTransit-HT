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
#include <cstdint>

namespace ht::internal {

// Trim spaces from both sides (in-place).
void trim_inplace(std::string& s);

// Hex helpers
int  hexval(char c);
bool hex_to_bytes(const std::string& hex, std::string& out);
std::string bytes_to_hex(const unsigned char* p, std::size_t n);

// SHA-256 as hex (uses OpenSSL from .cpp)
std::string sha256_hex(const std::string& data);

// Constant-time hex equality
bool ct_equal_hex(const std::string& a, const std::string& b);

// Upper / lower
std::string upper_copy(std::string s);
std::string lower_copy(std::string s);

// Securely wipe string contents
void secure_wipe(std::string& s);

} // namespace ht::internal

