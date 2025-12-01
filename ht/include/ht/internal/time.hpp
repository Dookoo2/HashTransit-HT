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

namespace ht {
// Return current UTC timestamp in strict ISO8601 "YYYY-MM-DDTHH:MM:SSZ".
std::string utc_iso8601_now();
} // namespace ht

