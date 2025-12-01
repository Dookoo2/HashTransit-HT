// SPDX-License-Identifier: MIT
// Part of HashTransit (HT) project.
// apps/ht_client_cli.cpp

#include "ht/client.hpp"
#include "ht/http_response.hpp"

#include <iostream>
#include <unordered_map>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>

static void usage(const char* argv0){
    std::cerr <<
      "Usage:\n"
      "  " << argv0 << " --mode A|B|C --host 127.0.0.1 --port 8080 "
      "--keyid device-001 --key 64HEX [--aead chacha20|aesgcm] "
      "[--tls_ca server.crt] [--insecure 0|1] [--path /echo] [--data STRING]\n"
      "\n"
      "Timeouts:\n"
      "  --connect_timeout <sec>   TCP connect timeout in seconds (default 2)\n"
      "  --io_timeout <sec>        per-op I/O timeout in seconds (default 2)\n"
      "\n"
      "Benchmark mode (continuous requests for a fixed duration):\n"
      "  " << argv0 << " ... --bench 1 --duration 3 --concurrency 1\n"
      "    --bench         0|1   enable benchmark mode (default 0)\n"
      "    --duration      int   duration in seconds (default 3)\n"
      "    --concurrency   int   number of worker threads (default 1)\n";
}

struct BenchStats {
    std::atomic<uint64_t> sent{0};
    std::atomic<uint64_t> success{0};
    std::atomic<uint64_t> failed{0};
    std::mutex mtx;
    std::vector<double> lat_ms; // per-request latency in milliseconds

    void add_latency(double ms) {
        std::lock_guard<std::mutex> lk(mtx);
        lat_ms.push_back(ms);
    }
};

// Compute percentile from a sorted vector (0..100).
static double percentile_sorted(const std::vector<double>& v, double p) {
    if (v.empty()) return 0.0;
    if (p <= 0.0) return v.front();
    if (p >= 100.0) return v.back();
    const double idx = (p/100.0) * (static_cast<double>(v.size() - 1));
    const size_t i = static_cast<size_t>(idx);
    const double frac = idx - static_cast<double>(i);
    // Linear interpolation between neighbors
    if (i + 1 < v.size()) return v[i] + (v[i+1] - v[i]) * frac;
    return v[i];
}

int main(int argc, char** argv){
    ht::ClientConfig cfg;
    cfg.mode = ht::Mode::AuthOnly;
    cfg.aead = ht::AeadAlg::Chacha20;
    cfg.host = "127.0.0.1";
    cfg.port = 8080;
    cfg.key_id = "device-001";
    cfg.secret_hex.clear();
    cfg.tls_verify_peer = true;

    // Reasonable defaults to guarantee termination under network stalls:
    cfg.connect_timeout_sec = 2; // seconds
    cfg.io_timeout_sec      = 2; // seconds

    std::string path = "/echo";
    std::string data = "hello";

    // Benchmark options
    bool bench = false;
    int duration_sec = 3;
    int concurrency = 1;

    std::string modeS, aeadS;
    for(int i=1;i<argc;++i){
        std::string a=argv[i];
        if(a=="--mode" && i+1<argc) modeS = argv[++i];
        else if(a=="--host" && i+1<argc) cfg.host = argv[++i];
        else if(a=="--port" && i+1<argc) cfg.port = (uint16_t)std::stoi(argv[++i]);
        else if(a=="--keyid" && i+1<argc) cfg.key_id = argv[++i];
        else if(a=="--key" && i+1<argc) cfg.secret_hex = argv[++i];
        else if(a=="--aead" && i+1<argc) aeadS = argv[++i];
        else if(a=="--tls_ca" && i+1<argc) cfg.tls_ca_file = argv[++i];
        else if(a=="--insecure" && i+1<argc) { cfg.tls_verify_peer = (std::stoi(argv[++i])!=0); }
        else if(a=="--path" && i+1<argc) path = argv[++i];
        else if(a=="--data" && i+1<argc) data = argv[++i];
        else if(a=="--bench" && i+1<argc) bench = (std::stoi(argv[++i])!=0);
        else if(a=="--duration" && i+1<argc) duration_sec = std::max(1, std::stoi(argv[++i]));
        else if(a=="--concurrency" && i+1<argc) concurrency = std::max(1, std::stoi(argv[++i]));
        else if(a=="--connect_timeout" && i+1<argc) cfg.connect_timeout_sec = std::max(1, std::stoi(argv[++i]));
        else if(a=="--io_timeout" && i+1<argc)      cfg.io_timeout_sec      = std::max(1, std::stoi(argv[++i]));
        else { usage(argv[0]); return 2; }
    }

    if(modeS=="A") cfg.mode = ht::Mode::AuthOnly;
    else if(modeS=="B") cfg.mode = ht::Mode::AuthAead;
    else if(modeS=="C") cfg.mode = ht::Mode::TlsTube;
    else { usage(argv[0]); return 2; }

    if(cfg.mode==ht::Mode::AuthAead){
        if(aeadS=="aesgcm") cfg.aead = ht::AeadAlg::AesGcm;
        else cfg.aead = ht::AeadAlg::Chacha20;
    }

    if(cfg.secret_hex.size()!=64){
        std::cerr<<"Bad --key: must be 64 hex chars\n";
        return 2;
    }

    if (!bench) {
        // Single-shot request mode (legacy behavior).
        ht::Client cli(cfg);
        ht::HttpResponse resp;
        if(!cli.request("POST", path, /*query*/{}, data, resp)){
            std::cerr<<"request() failed\n";
            return 1;
        }
        std::cout<<"HTTP "<<resp.status_code<<" "<<resp.status_text<<"\n";
        for (auto& kv: resp.headers){
            std::cout<<kv.first<<": "<<kv.second<<"\n";
        }
        std::cout<<"\n"<<resp.body<<"\n";
        return 0;
    }

    // === Benchmark mode ===
    // Each worker thread holds its own ht::Client instance.
    BenchStats stats;
    std::atomic<bool> stop{false};

    const auto t_start_wall = std::chrono::steady_clock::now();
    const auto t_end_wall   = t_start_wall + std::chrono::seconds(duration_sec);

    auto worker = [&](int /*tid*/){
        ht::Client cli(cfg);
        for (;;) {
            // IMPORTANT: check deadline BEFORE starting another request
            if (stop.load(std::memory_order_relaxed)) break;
            const auto now = std::chrono::steady_clock::now();
            if (now >= t_end_wall) break;

            const auto t0 = now;
            ht::HttpResponse resp;
            const bool ok = cli.request("POST", path, /*query*/{}, data, resp);
            const auto t1 = std::chrono::steady_clock::now();

            stats.sent.fetch_add(1, std::memory_order_relaxed);

            if (ok && resp.status_code == 200) {
                stats.success.fetch_add(1, std::memory_order_relaxed);
                const double ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
                stats.add_latency(ms);
            } else {
                stats.failed.fetch_add(1, std::memory_order_relaxed);
            }
            // Loop continues; next iteration will check deadline again.
        }
    };

    // Launch workers
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(concurrency));
    for (int i = 0; i < concurrency; ++i) {
        threads.emplace_back(worker, i);
    }

    // Sleep until deadline, then signal stop and join
    std::this_thread::sleep_until(t_end_wall);
    stop.store(true, std::memory_order_relaxed);
    for (auto& th : threads) th.join();

    const auto t_stop_wall = std::chrono::steady_clock::now();
    const double wall_sec = std::chrono::duration_cast<std::chrono::microseconds>(t_stop_wall - t_start_wall).count() / 1e6;

    // Prepare stats
    std::vector<double> v;
    {
        std::lock_guard<std::mutex> lk(stats.mtx);
        v = std::move(stats.lat_ms);
    }
    std::sort(v.begin(), v.end());

    const uint64_t sent    = stats.sent.load(std::memory_order_relaxed);
    const uint64_t success = stats.success.load(std::memory_order_relaxed);
    const uint64_t failed  = stats.failed.load(std::memory_order_relaxed);

    const double rps = (wall_sec > 0.0) ? (static_cast<double>(success) / wall_sec) : 0.0;

    double mn = 0.0, mx = 0.0, avg = 0.0;
    if (!v.empty()) {
        mn = v.front();
        mx = v.back();
        const double sum = std::accumulate(v.begin(), v.end(), 0.0);
        avg = sum / static_cast<double>(v.size());
    }

    const double p50 = percentile_sorted(v, 50.0);
    const double p90 = percentile_sorted(v, 90.0);
    const double p95 = percentile_sorted(v, 95.0);
    const double p99 = percentile_sorted(v, 99.0);

    // Print summary
    std::cout << "=== HT benchmark results ===\n";
    std::cout << "duration: " << std::fixed << std::setprecision(3) << wall_sec << " s\n";
    std::cout << "concurrency: " << concurrency << "\n";
    std::cout << "sent:     " << sent    << "\n";
    std::cout << "success:  " << success << "\n";
    std::cout << "errors:   " << failed  << "\n";
    std::cout << "RPS:      " << std::fixed << std::setprecision(2) << rps << " req/s\n";
    std::cout << "latency (ms):\n";
    std::cout << "  min: " << std::fixed << std::setprecision(3) << mn
              << "  avg: " << avg
              << "  p50: " << p50
              << "  p90: " << p90
              << "  p95: " << p95
              << "  p99: " << p99
              << "  max: " << mx << "\n";

    return 0;
}

