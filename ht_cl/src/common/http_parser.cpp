/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/http_parser.hpp"
#include <sstream>
#include <vector>
#include <algorithm>
#include <strings.h> // strcasecmp
#include "ht/internal/utils.hpp"

namespace ht { struct HttpRequest {}; } // stub to satisfy header if compiled alone

namespace ht::internal {

bool parse_request_line(const std::string&, ht::HttpRequest&) {
    // Client side does not use this; keep stub for symmetry.
    return false;
}

std::unordered_map<std::string,std::string> parse_query(const std::string& q){
    auto url_decode = [](const std::string& s){
        std::string o; o.reserve(s.size());
        for(std::size_t i=0;i<s.size();++i){
            if(s[i]=='%' && i+2<s.size()){
                int hi=hexval(s[i+1]), lo=hexval(s[i+2]);
                if(hi>=0 && lo>=0){ o.push_back((char)((hi<<4)|lo)); i+=2; continue; }
            }
            if(s[i]=='+'){ o.push_back(' '); continue; }
            o.push_back(s[i]);
        }
        return o;
    };
    std::unordered_map<std::string,std::string> m; std::size_t p=0;
    while(p<q.size()){
        std::size_t eq=q.find('=',p), amp=q.find('&',p);
        if(eq==std::string::npos) break;
        std::string k=url_decode(q.substr(p,eq-p));
        std::string v=url_decode(q.substr(eq+1,(amp==std::string::npos?q.size():amp)-(eq+1)));
        m[k]=v; if(amp==std::string::npos) break; p=amp+1;
    }
    return m;
}

std::string canonical_query_sorted(const std::unordered_map<std::string,std::string>& params){
    auto enc = [](const std::string& s){
        static const char unreserved[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        auto is_unreserved = [&](unsigned char c){
            for(const char* p=unreserved; *p; ++p) if(*p==c) return true;
            return false;
        };
        std::string out; out.reserve(s.size()*3);
        for(unsigned char c: s){
            if(is_unreserved(c)) out.push_back((char)c);
            else {
                char buf[4]; static const char* H="0123456789ABCDEF";
                buf[0]='%'; buf[1]=H[c>>4]; buf[2]=H[c&0xF]; buf[3]=0;
                out+=buf;
            }
        }
        return out;
    };

    std::vector<std::pair<std::string,std::string>> v(params.begin(), params.end());
    std::sort(v.begin(), v.end(), [](const auto& a, const auto& b){
        if(a.first<b.first) return true;
        if(a.first>b.first) return false;
        return a.second<b.second;
    });
    std::ostringstream oss;
    bool first=true;
    for(const auto& kv: v){
        if(!first) oss << '&';
        first=false;
        oss << enc(kv.first) << '=' << enc(kv.second);
    }
    return oss.str();
}

std::string hdr_ci(const std::unordered_map<std::string,std::string>& H, const char* name){
    auto it = H.find(name);
    if (it != H.end()) return it->second;
    for (const auto& kv : H){
        if (strcasecmp(kv.first.c_str(), name)==0) return kv.second;
    }
    return {};
}

} // namespace ht::internal

