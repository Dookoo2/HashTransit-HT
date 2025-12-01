/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/utils.hpp"
#include <algorithm>
#include <cctype>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace ht::internal {

void trim_inplace(std::string& s) {
    std::size_t a = 0;
    while (a < s.size() && std::isspace((unsigned char)s[a])) ++a;
    std::size_t b = s.size();
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    if (a > 0 || b < s.size()) s.assign(s.begin()+a, s.begin()+b);
}

int hexval(char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return 10+(c-'a');
    if(c>='A'&&c<='F')return 10+(c-'A');
    return -1;
}

bool hex_to_bytes(const std::string& hex, std::string& out){
    if(hex.size() % 2) return false;
    out.clear(); out.reserve(hex.size()/2);
    for(std::size_t i=0;i<hex.size(); i+=2){
        int h=hexval(hex[i]); int l=hexval(hex[i+1]);
        if(h<0 || l<0) return false;
        out.push_back((char)((h<<4)|l));
    }
    return true;
}

std::string bytes_to_hex(const unsigned char* p, std::size_t n){
    static const char* H="0123456789abcdef";
    std::string s; s.resize(n*2);
    for(std::size_t i=0;i<n;++i){ s[2*i]=H[p[i]>>4]; s[2*i+1]=H[p[i]&0xF]; }
    return s;
}

std::string sha256_hex(const std::string& data) {
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.data(), data.size(), d);
    return bytes_to_hex(d, SHA256_DIGEST_LENGTH);
}

bool ct_equal_hex(const std::string& a, const std::string& b){
    if(a.size()!=b.size()) return false;
    unsigned char acc=0;
    for(std::size_t i=0;i<a.size();++i) acc |= (unsigned char)(a[i]^b[i]);
    return acc==0;
}

std::string upper_copy(std::string s){
    for(char& c: s) c = (char)std::toupper((unsigned char)c);
    return s;
}
std::string lower_copy(std::string s){
    for(char& c: s) c = (char)std::tolower((unsigned char)c);
    return s;
}

void secure_wipe(std::string& s){
    if(!s.empty()){
        OPENSSL_cleanse(s.data(), s.size());
        s.clear();
        s.shrink_to_fit();
    }
}

std::string random_hex(std::size_t n_bytes){
    std::string b; b.resize(n_bytes);
    if (RAND_bytes((unsigned char*)b.data(), (int)b.size()) != 1) return {};
    return bytes_to_hex((const unsigned char*)b.data(), b.size());
}

} // namespace ht::internal

