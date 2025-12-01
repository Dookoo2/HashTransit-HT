// SPDX-License-Identifier: MIT
// Part of HashTransit (HT) project.
// apps/ht_server_basic.cpp

#include "ht/server.hpp"
#include "ht/server_config.hpp"

#include <iostream>
#include <string>
#include <cstdio>     // freopen
#include <unistd.h>   // dup2, STDOUT_FILENO, STDERR_FILENO
#include <fcntl.h>    // open

// Silences all console output by redirecting stdout/stderr to /dev/null.
// This is process-wide and affects all library logs printing to stdio.
static void make_process_quiet() {
    int nullfd = ::open("/dev/null", O_WRONLY);
    if (nullfd >= 0) {
        (void)::dup2(nullfd, STDOUT_FILENO);
        (void)::dup2(nullfd, STDERR_FILENO);
        ::close(nullfd);
    }
}

static void usage(const char* argv0) {
    std::cerr <<
      "Usage:\n  " << argv0
      << " --mode A|B|C --port <n> "
         "[--auth_file <path>]\n"
         "  [--aead chacha20|aesgcm]         (mode B)\n"
         "  [--tls_cert <crt> --tls_key <key>] (mode C)\n"
         "  [--redact_errors 0|1]\n"
         "  [--quiet 0|1]                    (suppress all console logs when 1)\n"
         "  Redis auth backend:\n"
         "    --auth_redis 1 "
         "[--redis_host 127.0.0.1] [--redis_port 6379] [--redis_db 0]\n"
         "    [--redis_password ****] [--redis_prefix ht:key:] [--redis_pool 8]\n"
         "    [--redis_timeout_ms 200] [--auth_cache_ttl 60]\n";
}

int main(int argc, char** argv) {
    ht::ServerConfig cfg;
    std::string modeS, aeadS;
    bool quiet = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--mode" && i+1 < argc) modeS = argv[++i];
        else if (a == "--port" && i+1 < argc) cfg.port = (uint16_t)std::stoi(argv[++i]);
        else if (a == "--auth_file" && i+1 < argc) cfg.auth_file = argv[++i];
        else if (a == "--aead" && i+1 < argc) aeadS = argv[++i];
        else if (a == "--tls_cert" && i+1 < argc) cfg.tls_cert_file = argv[++i];
        else if (a == "--tls_key"  && i+1 < argc) cfg.tls_key_file  = argv[++i];
        else if (a == "--redact_errors" && i+1 < argc) cfg.redact_errors = (std::stoi(argv[++i]) != 0);
        else if (a == "--quiet" && i+1 < argc) quiet = (std::stoi(argv[++i]) != 0);

        // Redis backend flags
        else if (a == "--auth_redis" && i+1 < argc) cfg.auth_use_redis = (std::stoi(argv[++i]) != 0);
        else if (a == "--redis_host" && i+1 < argc) cfg.redis.host = argv[++i];
        else if (a == "--redis_port" && i+1 < argc) cfg.redis.port = std::stoi(argv[++i]);
        else if (a == "--redis_db" && i+1 < argc)   cfg.redis.db = std::stoi(argv[++i]);
        else if (a == "--redis_password" && i+1<argc) cfg.redis.password = argv[++i];
        else if (a == "--redis_prefix" && i+1<argc)   cfg.redis.key_prefix = argv[++i];
        else if (a == "--redis_pool" && i+1<argc)     cfg.redis.pool_size = std::stoi(argv[++i]);
        else if (a == "--redis_timeout_ms" && i+1<argc) cfg.redis.timeout_ms = std::stoi(argv[++i]);
        else if (a == "--auth_cache_ttl" && i+1<argc)   cfg.redis.cache_ttl_sec = std::stoi(argv[++i]);

        else { usage(argv[0]); return 2; }
    }

    // Apply quiet mode before any logging can occur.
    if (quiet) {
        make_process_quiet();
    }

    // Mode selection
    if (modeS == "A") cfg.mode = ht::Mode::AuthOnly;
    else if (modeS == "B") cfg.mode = ht::Mode::AuthAead;
    else if (modeS == "C") cfg.mode = ht::Mode::TlsTube;
    else { usage(argv[0]); return 2; }

    // AEAD selection for mode B
    if (cfg.mode == ht::Mode::AuthAead) {
        if (aeadS == "aesgcm") cfg.aead = ht::AeadAlg::AesGcm;
        else                   cfg.aead = ht::AeadAlg::Chacha20;
    }

    // TLS files for mode C
    if (cfg.mode == ht::Mode::TlsTube) {
        if (cfg.tls_cert_file.empty() || cfg.tls_key_file.empty()) {
            std::cerr << "Mode C requires --tls_cert and --tls_key\n";
            return 2;
        }
    }

    // Auth backend requirement
    if (!cfg.auth_use_redis && cfg.auth_file.empty()) {
        std::cerr << "Either --auth_file (file backend) or --auth_redis 1 (Redis backend) must be provided\n";
        return 2;
    }

    try {
        ht::Server srv(cfg);
        srv.run();  // blocking
    } catch (const std::exception& e) {
        // Note: if --quiet 1 is used, this message is suppressed as well.
        std::cerr << "[FATAL] exception: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

