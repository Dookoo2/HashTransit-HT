/*
 * Part of the HashTransit (HT) project.
 *
 * SPDX-FileCopyrightText: 2025 HashTransit contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of HashTransit (HT). See LICENSE for details.
 * Coded by DooKoo2: https://github.com/Dookoo2
 */

#include "ht/internal/tls_cli_ctx.hpp"
#include "ht/log.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace ht::internal {

TlsClientContext::TlsClientContext(const ht::ClientConfig& cfg) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_client_method();
    _ctx = SSL_CTX_new(method);
    if (!_ctx) {
        log_last_error("SSL_CTX_new");
        return;
    }

    if (!SSL_CTX_set_min_proto_version(_ctx, TLS1_2_VERSION)) {
        log_last_error("set_min_proto");
    }

    // Trust store
    if (!cfg.tls_ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(_ctx, cfg.tls_ca_file.c_str(), nullptr) != 1) {
            log_last_error("load_verify_locations(CA)");
        }
    } else {
        if (SSL_CTX_set_default_verify_paths(_ctx) != 1) {
            log_last_error("set_default_verify_paths");
        }
    }

    // Optional mTLS
    if (!cfg.tls_client_cert_file.empty() && !cfg.tls_client_key_file.empty()) {
        if (SSL_CTX_use_certificate_file(_ctx, cfg.tls_client_cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            log_last_error("use_certificate_file(client)");
        }
        if (SSL_CTX_use_PrivateKey_file(_ctx, cfg.tls_client_key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            log_last_error("use_privatekey_file(client)");
        }
        if (SSL_CTX_check_private_key(_ctx) != 1) {
            log_last_error("check_private_key(client)");
        }
    }

    // Verification
    if (cfg.tls_verify_peer) {
        SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, nullptr);
    } else {
        SSL_CTX_set_verify(_ctx, SSL_VERIFY_NONE, nullptr);
    }

    // Enable client session cache for resumption
    SSL_CTX_set_session_cache_mode(_ctx, SSL_SESS_CACHE_CLIENT);
}

TlsClientContext::~TlsClientContext() {
    if (_ctx) {
        SSL_CTX_free(_ctx);
        _ctx = nullptr;
    }
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}

void TlsClientContext::log_last_error(const char* where) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        ht::log_line(std::string("[TLS-CLI] error at ") + where + ": " + buf);
    }
}

} // namespace ht::internal

