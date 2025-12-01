/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/tls_ctx.hpp"
#include "ht/log.hpp"
#include <openssl/err.h>

namespace ht::internal {

TlsContext::TlsContext(const ht::ServerConfig& cfg) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_method();
    _ctx = SSL_CTX_new(method);
    if (!_ctx) {
        log_last_error("SSL_CTX_new");
        return;
    }

    // TLS1.2+
    if (!SSL_CTX_set_min_proto_version(_ctx, TLS1_2_VERSION)) {
        log_last_error("set_min_proto");
    }

    // certificates
    if (SSL_CTX_use_certificate_file(_ctx, cfg.tls_cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        log_last_error("use_certificate_file");
    }
    if (SSL_CTX_use_PrivateKey_file(_ctx, cfg.tls_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        log_last_error("use_privatekey_file");
    }
    if (SSL_CTX_check_private_key(_ctx) != 1) {
        log_last_error("check_private_key");
    }

    if (!cfg.tls_client_ca.empty()) {
        if (SSL_CTX_load_verify_locations(_ctx, cfg.tls_client_ca.c_str(), nullptr) != 1) {
            log_last_error("load_verify_locations");
        }
        int vmode = SSL_VERIFY_PEER;
        if (cfg.require_client_cert) vmode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(_ctx, vmode, nullptr);
    }

    // session cache
    SSL_CTX_set_session_cache_mode(_ctx, SSL_SESS_CACHE_SERVER);
    const unsigned char sid_ctx[] = "ht_server_sid_ctx_v1";
    SSL_CTX_set_session_id_context(_ctx, sid_ctx, (unsigned int)sizeof(sid_ctx));
}

TlsContext::~TlsContext() {
    if (_ctx) {
        SSL_CTX_free(_ctx);
        _ctx = nullptr;
    }
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}

void TlsContext::log_last_error(const char* where) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        ht::log_line(std::string("[TLS] error at ") + where + ": " + buf);
    }
}

} // namespace ht::internal

