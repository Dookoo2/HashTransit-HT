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
#include <cstddef>
#include <cstdint>
#include <string>

namespace ht {

// Transport mode: A = auth only, B = auth + AEAD, C = TLS tube
enum class Mode {
    AuthOnly,
    AuthAead,
    TlsTube
};

enum class AeadAlg {
    Chacha20,
    AesGcm
};

} // namespace ht

