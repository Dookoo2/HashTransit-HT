/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/hmac.hpp"
#include <openssl/hmac.h>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <sstream>

namespace ht::internal {

bool parse_timestamp(const std::string& s, std::int64_t& out_epoch) {
    if(!s.empty() && std::all_of(s.begin(), s.end(), ::isdigit)){
        try { out_epoch = std::stoll(s); return true; } catch(...) { return false; }
    }
    if(s.size()==20 && s[4]=='-' && s[7]=='-' && s[10]=='T' && s[13]==':' && s[16]==':' && s[19]=='Z'){
        int y=std::stoi(s.substr(0,4));
        int m=std::stoi(s.substr(5,2));
        int d=std::stoi(s.substr(8,2));
        int H=std::stoi(s.substr(11,2));
        int M=std::stoi(s.substr(14,2));
        int S=std::stoi(s.substr(17,2));
        std::tm tm{};
        tm.tm_year=y-1900; tm.tm_mon=m-1; tm.tm_mday=d;
        tm.tm_hour=H; tm.tm_min=M; tm.tm_sec=S;
        out_epoch = timegm(&tm); // GNU extension
        return (out_epoch != -1);
    }
    return false;
}

bool hmac_sha256_bin(const std::string& key_bin,
                     const std::string& msg,
                     std::string& out_bin)
{
    unsigned int mac_len=0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char* p = HMAC(EVP_sha256(),
                            key_bin.data(), (int)key_bin.size(),
                            (const unsigned char*)msg.data(), msg.size(),
                            mac, &mac_len);
    if(!p || mac_len!=32) return false;
    out_bin.assign((const char*)mac, 32);
    return true;
}

} // namespace ht::internal

