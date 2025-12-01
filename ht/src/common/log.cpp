/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/log.hpp"
#include <mutex>
#include <fstream>
#include <iostream>

namespace {
std::mutex g_log_mtx;
std::ofstream g_log_ofs;
std::string g_log_path = "log.txt";

void open_if_needed_unlocked() {
    if (!g_log_ofs.is_open()) {
        g_log_ofs.open(g_log_path, std::ios::out | std::ios::app);
    }
}
} // namespace

namespace ht {

void set_log_file(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    g_log_path = path;
    if (g_log_ofs.is_open()) {
        g_log_ofs.close();
    }
    open_if_needed_unlocked();
}

void log_line(const std::string& line) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    open_if_needed_unlocked();
    if (g_log_ofs) {
        g_log_ofs << line << '\n';
        g_log_ofs.flush();
    }
    std::cout << line << '\n';
}

} // namespace ht

