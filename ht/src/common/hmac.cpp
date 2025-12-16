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
#include "ht/internal/http_parser.hpp"
#include "ht/internal/utils.hpp"
#include "ht/log.hpp"
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <chrono>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <algorithm> // std::all_of

namespace ht::internal {

bool parse_timestamp(const std::string& s, std::int64_t& out_epoch) {
    // numeric unix seconds
    if (!s.empty() && std::all_of(s.begin(), s.end(), ::isdigit)) {
        try {
            out_epoch = std::stoll(s);
            return true;
        } catch (...) {
            return false;
        }
    }
    // ISO8601 "YYYY-MM-DDTHH:MM:SSZ"
    if (s.size() == 20 && s[4] == '-' && s[7] == '-' &&
        s[10] == 'T' && s[13] == ':' && s[16] == ':' && s[19] == 'Z')
    {
        int y = std::stoi(s.substr(0, 4));
        int m = std::stoi(s.substr(5, 2));
        int d = std::stoi(s.substr(8, 2));
        int H = std::stoi(s.substr(11, 2));
        int M = std::stoi(s.substr(14, 2));
        int S = std::stoi(s.substr(17, 2));
        std::tm tm{};
        tm.tm_year = y - 1900;
        tm.tm_mon  = m - 1;
        tm.tm_mday = d;
        tm.tm_hour = H;
        tm.tm_min  = M;
        tm.tm_sec  = S;
        // timegm is GNU extension (Linux)
        out_epoch = timegm(&tm);
        return (out_epoch != -1);
    }
    return false;
}

static bool hmac_sha256_bin(const std::string& key_bin,
                            const std::string& msg,
                            std::string& out_bin)
{
    unsigned int mac_len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char* p = HMAC(EVP_sha256(),
                            key_bin.data(), (int)key_bin.size(),
                            reinterpret_cast<const unsigned char*>(msg.data()),
                            msg.size(),
                            mac, &mac_len);
    if (!p || mac_len != 32) return false;
    out_bin.assign(reinterpret_cast<const char*>(mac), 32);
    return true;
}

VerifyResult verify_request_common(const ht::HttpRequest& R,
                                   const ht::ServerConfig& cfg,
                                   AuthStore& auth,
                                   NonceCache& nonces,
                                   bool verify_plain_body_hash)
{
    VerifyResult vr;

    const std::string version = hdr_ci(R, "X-HT-Version");
    const std::string key_id  = hdr_ci(R, "X-HT-KeyId");
    const std::string ts_s    = hdr_ci(R, "X-HT-Timestamp");
    const std::string nonce   = hdr_ci(R, "X-HT-Nonce");
    const std::string body_h  = hdr_ci(R, "X-HT-Body-SHA256");
    const std::string sig_hex = hdr_ci(R, "X-HT-Signature");

    // NOTE: Put a strict upper bound on nonce length to prevent header abuse
    // and unbounded growth of the anti-replay cache key material.
    constexpr std::size_t kMaxNonceLen = 128;

    if (version != "1" || key_id.empty() || ts_s.empty() ||
        nonce.size() < 8 || nonce.size() > kMaxNonceLen ||
        body_h.size() != 64 || sig_hex.size() != 64)
    {
        vr.reason = "BAD_AUTH_FIELDS";
        return vr;
    }

    // timestamp skew
    std::int64_t ts_epoch = 0;
    if (!parse_timestamp(ts_s, ts_epoch)) {
        vr.reason = "BAD_TS";
        return vr;
    }
    const std::int64_t now_s =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    if (std::llabs(now_s - ts_epoch) > cfg.ts_skew_sec) {
        vr.reason = "TS_SKEW";
        return vr;
    }

    // key lookup
    std::string key_bin;
    if (!auth.lookup(key_id, key_bin)) {
        vr.reason = "UNKNOWN_KEY";
        return vr;
    }

    // canonical query
    const auto qmap = parse_query(R.query);
    const std::string qcanon = canonical_query_sorted(qmap);

    // canonical string
    const std::string method_up = upper_copy(R.method);
    std::ostringstream oss;
    oss << "HT1\n"
        << method_up  << "\n"
        << R.path     << "\n"
        << qcanon     << "\n"
        << body_h     << "\n"
        << ts_s       << "\n"
        << nonce      << "\n"
        << key_id;
    const std::string canonical = oss.str();

    // HMAC verify
    std::string expected_mac;
    if (!hmac_sha256_bin(key_bin, canonical, expected_mac)) {
        secure_wipe(key_bin);
        vr.reason = "HMAC_FAIL";
        return vr;
    }
    std::string sig_bin;
    if (!hex_to_bytes(sig_hex, sig_bin) || sig_bin.size() != 32) {
        secure_wipe(key_bin);
        vr.reason = "BAD_SIG_FORMAT";
        return vr;
    }
    if (CRYPTO_memcmp(expected_mac.data(), sig_bin.data(), 32) != 0) {
        secure_wipe(key_bin);
        vr.reason = "BAD_SIG";
        return vr;
    }

    // anti-replay (insert only after successful authentication)
    // This prevents trivial DoS where an attacker fills the nonce cache with
    // random (key_id|nonce) pairs without knowing a valid key.
    {
        const std::string k = key_id + "|" + nonce;
        if (!nonces.insert_if_absent(k, cfg.nonce_ttl_sec, cfg.max_pending)) {
            secure_wipe(key_bin);
            vr.reason = "REPLAY_OR_OVER_CAPACITY";
            return vr;
        }
    }

    if (verify_plain_body_hash) {
        const std::string body_sha = sha256_hex(R.body);
        if (!ct_equal_hex(body_sha, body_h)) {
            secure_wipe(key_bin);
            vr.reason = "BAD_BODY_HASH";
            return vr;
        }
    }

    secure_wipe(key_bin);
    vr.ok        = true;
    vr.key_id    = key_id;
    vr.canonical = canonical;
    return vr;
}

} // namespace ht::internal
