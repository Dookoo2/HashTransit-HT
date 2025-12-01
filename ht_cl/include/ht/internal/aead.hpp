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

namespace ht::internal {

bool derive_aead_key_32(const std::string& psk,
                        const std::string& alg,
                        const std::string& ts,
                        const std::string& key_id,
                        const char* dir_tag,
                        std::string& key_out);

bool aead_decrypt_body(std::string& plaintext,
                       const std::string& ciphertext,
                       const std::string& aead_alg,
                       const std::string& key32,
                       const std::string& nonce12,
                       const std::string& aad);

bool aead_encrypt_body(std::string& ciphertext,
                       const std::string& plaintext,
                       const std::string& aead_alg,
                       const std::string& key32,
                       const std::string& nonce12,
                       const std::string& aad);

} // namespace ht::internal

