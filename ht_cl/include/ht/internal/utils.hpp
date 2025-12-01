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
#include <cstddef>
#include <cstdint>

namespace ht::internal {

void trim_inplace(std::string& s);
int  hexval(char c);
bool hex_to_bytes(const std::string& hex, std::string& out);
std::string bytes_to_hex(const unsigned char* p, std::size_t n);
std::string sha256_hex(const std::string& data);
bool ct_equal_hex(const std::string& a, const std::string& b);
std::string upper_copy(std::string s);
std::string lower_copy(std::string s);
void secure_wipe(std::string& s);

// Random hex nonce of n bytes -> 2n hex chars (using OpenSSL RAND_bytes).
std::string random_hex(std::size_t n);

} // namespace ht::internal

