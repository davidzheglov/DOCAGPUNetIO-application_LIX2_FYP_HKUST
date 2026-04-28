/*
 * benchmark_harness.cpp — five-tier benchmark coordinator.
 *
 * Orchestrates 75 benchmark runs: 5 tiers × 5 rates × 3 repetitions.
 * For each run:
 *   1. Launch data_source (replay mode) at the target rate.
 *   2. Launch the tier-specific receiver binary.
 *   3. Discard BenchmarkResult packets during the warmup window (5 s).
 *   4. Collect BenchmarkResult packets for the measurement window (30 s).
 *   5. Kill both subprocesses.
 *   6. Compute per-tick latency metrics and write to CSV.
 *
 * Results CSV columns:
 *   run_id, tier, rate_hz, repetition, n_ticks, drop_rate,
 *   e2e_p50, e2e_p95, e2e_p99, e2e_mean,
 *   ingest_p50, ingest_p95, ingest_p99, ingest_mean,
 *   compute_p50, compute_p95, compute_p99, compute_mean,
 *   throughput_per_sec
 *
 * Usage:
 *   benchmark_harness [--csv-dir data/] [--results results/benchmark.csv]
 *                     [--warmup 5] [--duration 30]
 *                     [--tiers 1,2,3,4,5] [--rates 10000,50000,100000,250000,500000]
 *                     [--reps 3]
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "benchmark_result.h"
#include "signal_result.h"

using Clock = std::chrono::steady_clock;
using Sec   = std::chrono::seconds;

/* ── Default config ──────────────────────────────────────────────────────── */
static const int DEFAULT_WARMUP   = 5;
static const int DEFAULT_DURATION = 30;
static const int DEFAULT_REPS     = 3;

/* ── Percentile helper ───────────────────────────────────────────────────── */
static double percentile(std::vector<double> &v, double p)
{
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t idx = (size_t)(p * (double)(v.size() - 1) + 0.5);
    return v[std::min(idx, v.size() - 1)];
}

static double mean_of(const std::vector<double> &v)
{
    if (v.empty()) return 0.0;
    double s = 0;
    for (double x : v) s += x;
    return s / (double)v.size();
}

/* ── Receiver binary names by tier ──────────────────────────────────────── */
static const char *receiver_binary(int tier)
{
    switch (tier) {
    case 1: return "./bin/cpu_receiver";
    case 2: return "./bin/dpdk_receiver";
    case 3: return "./bin/rdma_receiver";
    case 4: return "./bin/gpu_receiver";
    case 5: return "./bin/gpu_receiver";   /* same binary, different deployment */
    default: return nullptr;
    }
}

/* ── Hardware config for tier-specific args ──────────────────────────────── */
static std::string g_dpdk_pci  = "0000:bd:00.0";   /* T2: ConnectX-7 NIC PCIe */
static std::string g_gpu_pcie  = "00000000:AC:00.0"; /* T4: GPU 1 PCIe */
static std::string g_nic_pcie  = "0000:bd:00.0";     /* T4: NIC PCIe for DOCA */
static int         g_gpu_id    = 1;                   /* T4: CUDA device */
static std::string g_mcast_iface;                     /* NIC IP for multicast output */
static std::string g_receiver_iface;                  /* T1 CPU receiver iface name */

/* ── Remote sender config (lxcpu2 host) ──────────────────────────────────── */
/* When g_sender_ssh is non-empty, the harness drives the sender over SSH on
 * the remote host (e.g. lxcpu2), unicasting to g_sender_dest (the DPU relay
 * on tmfifo). The DPU relay is expected to be already running.
 *
 * When g_sender_ssh is empty, the harness falls back to spawning data_source
 * locally (legacy same-host T1 loopback mode). */
static std::string g_sender_ssh;          /* user@host for ssh; empty = local */
static std::string g_sender_bin
    = "~/DOCAGPUNetIO-application_LIX2_FYP_HKUST/bin/data_source";
static std::string g_sender_csv
    = "~/DOCAGPUNetIO-application_LIX2_FYP_HKUST/data/ticks.csv";
static std::string g_sender_dest = "192.168.100.2:6005";  /* DPU relay listen-port */

/* ── Build receiver args ─────────────────────────────────────────────────── */
static std::vector<std::string> receiver_args(int tier)
{
    std::vector<std::string> args;

    if (tier == 2) {
        /* DPDK EAL args come first, then "--" separator, then app args */
        args.push_back("-a");
        args.push_back(g_dpdk_pci);
        args.push_back("-l");
        args.push_back("0-1");
        args.push_back("-n");
        args.push_back("4");
        args.push_back("--");
    }

    args.push_back("--tier");
    args.push_back(std::to_string(tier));

    if (tier == 1 && !g_receiver_iface.empty()) {
        args.push_back("--iface");
        args.push_back(g_receiver_iface);
    }

    if (tier == 4 || tier == 5) {
        args.push_back("--gpu");
        args.push_back(std::to_string(g_gpu_id));
        args.push_back("--gpu-pcie");
        args.push_back(g_gpu_pcie);
        args.push_back("--nic-pcie");
        args.push_back(g_nic_pcie);
    }

    return args;
}

/* ── Launch subprocess ───────────────────────────────────────────────────── */
static pid_t launch(const char *binary,
                     const std::vector<std::string> &extra_args)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        /* child */
        std::vector<const char *> argv;
        argv.push_back(binary);
        for (const auto &a : extra_args) argv.push_back(a.c_str());
        argv.push_back(nullptr);
        execv(binary, const_cast<char *const *>(argv.data()));
        perror("execv");
        _exit(1);
    }
    return pid;
}

/* ── Kill process tree ───────────────────────────────────────────────────── */
static void kill_proc(pid_t pid)
{
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    int status;
    waitpid(pid, &status, 0);
}

/* ── Launch the sender on lxcpu2 over SSH ────────────────────────────────────
 * Runs data_source in replay mode on the remote host, unicasting to the DPU
 * relay (which fans it out as multicast onto the wire). Returns the local
 * ssh-client pid; the actual remote process must also be killed via SSH on
 * teardown (kill_remote_sender). */
static pid_t launch_sender_ssh(long rate_hz)
{
    std::string remote_cmd =
        "pkill -x data_source 2>/dev/null || true; sleep 0.2; "
        + g_sender_bin
        + " --mode replay"
        + " --csv "  + g_sender_csv
        + " --rate " + std::to_string(rate_hz)
        + " --dest " + g_sender_dest;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        execlp("ssh", "ssh",
               "-o", "BatchMode=yes",
               "-o", "ServerAliveInterval=10",
               "-o", "StrictHostKeyChecking=accept-new",
               g_sender_ssh.c_str(),
               remote_cmd.c_str(),
               (char *)nullptr);
        perror("execlp ssh");
        _exit(127);
    }
    return pid;
}

static void kill_remote_sender(void)
{
    if (g_sender_ssh.empty()) return;
    std::string cmd = "ssh -o BatchMode=yes -o ConnectTimeout=3 "
                    + g_sender_ssh
                    + " 'pkill -x data_source 2>/dev/null || true'"
                      " >/dev/null 2>&1";
    (void)system(cmd.c_str());
}

/* ── UDP receiver socket for BenchmarkResult ─────────────────────────────── */
static int make_result_socket(int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    timeval tv{ .tv_sec = 0, .tv_usec = 50000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* ── CSV writer ──────────────────────────────────────────────────────────── */
struct RunResult {
    int    run_id, tier, repetition;
    long   rate_hz;
    size_t n_ticks;
    double drop_rate;
    double e2e_p50, e2e_p95, e2e_p99, e2e_mean;
    double ingest_p50, ingest_p95, ingest_p99, ingest_mean;
    double compute_p50, compute_p95, compute_p99, compute_mean;
    double throughput;
    /* Signal-rate metrics (post-kernel SignalResult emissions on port 5006) */
    double signals_total_per_sec;       /* every processed tick → throughput proxy */
    double signals_actionable_per_sec;  /* only signal != 0 (real buy/sell decisions) */
};

static void write_header(std::ofstream &f)
{
    f << "run_id,tier,rate_hz,repetition,n_ticks,drop_rate,"
      << "e2e_p50_us,e2e_p95_us,e2e_p99_us,e2e_mean_us,"
      << "ingest_p50_us,ingest_p95_us,ingest_p99_us,ingest_mean_us,"
      << "compute_p50_us,compute_p95_us,compute_p99_us,compute_mean_us,"
      << "throughput_per_sec,"
      << "signals_total_per_sec,signals_actionable_per_sec\n";
}

static void write_row(std::ofstream &f, const RunResult &r)
{
    auto ns_to_us = [](double ns) { return ns / 1000.0; };
    f << r.run_id       << ','
      << r.tier         << ','
      << r.rate_hz      << ','
      << r.repetition   << ','
      << r.n_ticks      << ','
      << r.drop_rate    << ','
      << ns_to_us(r.e2e_p50)  << ',' << ns_to_us(r.e2e_p95)  << ','
      << ns_to_us(r.e2e_p99)  << ',' << ns_to_us(r.e2e_mean) << ','
      << ns_to_us(r.ingest_p50)  << ',' << ns_to_us(r.ingest_p95)  << ','
      << ns_to_us(r.ingest_p99)  << ',' << ns_to_us(r.ingest_mean) << ','
      << ns_to_us(r.compute_p50)  << ',' << ns_to_us(r.compute_p95)  << ','
      << ns_to_us(r.compute_p99)  << ',' << ns_to_us(r.compute_mean) << ','
      << r.throughput   << ','
      << r.signals_total_per_sec << ','
      << r.signals_actionable_per_sec << '\n';
    f.flush();
}

/* ── Single benchmark run ────────────────────────────────────────────────── */
static RunResult run_one(int run_id, int tier, long rate_hz, int repetition,
                          const char *csv_path, int result_fd, int signal_fd,
                          int warmup_sec, int duration_sec)
{
    fprintf(stderr,
        "\n[harness] RUN %d | tier=T%d | rate=%ld | rep=%d\n",
        run_id, tier, rate_hz, repetition);

    /* Kill any leftover receivers locally; on remote host the SSH launcher
     * will pkill data_source itself before starting the new one. */
    system("pkill -f bin/cpu_receiver  2>/dev/null; "
           "pkill -f bin/dpdk_receiver 2>/dev/null; "
           "pkill -f bin/rdma_receiver 2>/dev/null; "
           "pkill -f bin/gpu_receiver  2>/dev/null; "
           "true");
    if (g_sender_ssh.empty()) {
        system("pkill -f bin/data_source 2>/dev/null; true");
    } else {
        kill_remote_sender();
    }
    usleep(300000);

    /* Launch data_source — remote (lxcpu2 via SSH) or local (legacy) */
    pid_t ds_pid = -1;
    if (!g_sender_ssh.empty()) {
        fprintf(stderr, "[harness] launching remote sender on %s\n",
                g_sender_ssh.c_str());
        ds_pid = launch_sender_ssh(rate_hz);
    } else {
        std::vector<std::string> ds_args = {
            "--mode", "replay",
            "--csv",  csv_path,
            "--rate", std::to_string(rate_hz)
        };
        if (!g_mcast_iface.empty() && (tier == 2 || tier == 4 || tier == 5)) {
            ds_args.push_back("--iface");
            ds_args.push_back(g_mcast_iface);
        }
        ds_pid = launch("./bin/data_source", ds_args);
    }
    if (ds_pid < 0) { fprintf(stderr, "Failed to launch data_source\n"); }

    /* Brief pause for data_source to start (longer for remote — SSH + pkill) */
    usleep(g_sender_ssh.empty() ? 200000 : 800000);

    /* Launch receiver */
    std::vector<std::string> rx_args = receiver_args(tier);
    pid_t rx_pid = launch(receiver_binary(tier), rx_args);
    if (rx_pid < 0) {
        kill_proc(ds_pid);
        fprintf(stderr, "Failed to launch receiver for tier %d\n", tier);
    }

    /* Drain both sockets during warmup */
    auto t_start = Clock::now();
    {
        BenchmarkResult br{};
        SignalResult    sr{};
        auto warmup_end = t_start + Sec(warmup_sec);
        fprintf(stderr, "[harness] warming up for %d s...\n", warmup_sec);
        while (Clock::now() < warmup_end) {
            recv(result_fd, &br, sizeof(br), 0);  /* discard */
            recv(signal_fd, &sr, sizeof(sr), MSG_DONTWAIT);  /* non-blocking drain */
        }
    }

    /* Collect during measurement window — poll both sockets */
    std::vector<double> e2e_ns, ingest_ns, compute_ns;
    e2e_ns.reserve(rate_hz * duration_sec);
    ingest_ns.reserve(rate_hz * duration_sec);
    compute_ns.reserve(rate_hz * duration_sec);

    uint64_t n_dropped = 0;
    uint64_t n_signals_total = 0;       /* every SignalResult received */
    uint64_t n_signals_actionable = 0;  /* signal != 0 only */
    auto measure_end = Clock::now() + Sec(duration_sec);
    fprintf(stderr, "[harness] measuring for %d s...\n", duration_sec);

    pollfd pfds[2];
    pfds[0].fd = result_fd; pfds[0].events = POLLIN;
    pfds[1].fd = signal_fd; pfds[1].events = POLLIN;

    while (Clock::now() < measure_end) {
        int pr = poll(pfds, 2, 50);  /* 50 ms tick */
        if (pr <= 0) continue;

        if (pfds[0].revents & POLLIN) {
            BenchmarkResult br{};
            ssize_t n = recv(result_fd, &br, sizeof(br), 0);
            if (n == sizeof(BenchmarkResult)) {
                if (br.dropped) { ++n_dropped; }
                else if (br.t4_ns > br.t1_ns &&
                         br.t4_ns - br.t1_ns <= 10000000000ULL) {
                    e2e_ns.push_back((double)(br.t4_ns - br.t1_ns));
                    ingest_ns.push_back((double)(br.t2_ns - br.t1_ns));
                    compute_ns.push_back((double)(br.t3_ns - br.t2_ns));
                }
            }
        }
        if (pfds[1].revents & POLLIN) {
            SignalResult sr{};
            ssize_t n = recv(signal_fd, &sr, sizeof(sr), 0);
            if (n == sizeof(SignalResult)) {
                ++n_signals_total;
                if (sr.signal != 0) ++n_signals_actionable;
            }
        }
    }

    /* Kill subprocesses */
    kill_proc(rx_pid);
    if (!g_sender_ssh.empty()) {
        kill_remote_sender();   /* tells the remote machine to stop sending */
    }
    kill_proc(ds_pid);          /* reaps the local ssh client (or local data_source) */
    usleep(100000);

    size_t n_ticks = e2e_ns.size();
    double drop_rate = (n_ticks + n_dropped) > 0
        ? (double)n_dropped / (double)(n_ticks + n_dropped) : 0.0;

    RunResult r{};
    r.run_id     = run_id;
    r.tier       = tier;
    r.rate_hz    = rate_hz;
    r.repetition = repetition;
    r.n_ticks    = n_ticks;
    r.drop_rate  = drop_rate;
    r.e2e_p50    = percentile(e2e_ns, 0.50);
    r.e2e_p95    = percentile(e2e_ns, 0.95);
    r.e2e_p99    = percentile(e2e_ns, 0.99);
    r.e2e_mean   = mean_of(e2e_ns);
    r.ingest_p50  = percentile(ingest_ns, 0.50);
    r.ingest_p95  = percentile(ingest_ns, 0.95);
    r.ingest_p99  = percentile(ingest_ns, 0.99);
    r.ingest_mean = mean_of(ingest_ns);
    r.compute_p50  = percentile(compute_ns, 0.50);
    r.compute_p95  = percentile(compute_ns, 0.95);
    r.compute_p99  = percentile(compute_ns, 0.99);
    r.compute_mean = mean_of(compute_ns);
    r.throughput   = duration_sec > 0
        ? (double)n_ticks / (double)duration_sec : 0.0;
    r.signals_total_per_sec      = duration_sec > 0
        ? (double)n_signals_total / (double)duration_sec : 0.0;
    r.signals_actionable_per_sec = duration_sec > 0
        ? (double)n_signals_actionable / (double)duration_sec : 0.0;

    fprintf(stderr,
        "[harness] T%d @%ld: n=%zu drop=%.2f%% e2e_p50=%.1fus e2e_p99=%.1fus "
        "tput=%.0f/s sig_total=%.0f/s sig_act=%.0f/s\n",
        tier, rate_hz, n_ticks, drop_rate * 100.0,
        r.e2e_p50 / 1000.0, r.e2e_p99 / 1000.0, r.throughput,
        r.signals_total_per_sec, r.signals_actionable_per_sec);

    return r;
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    const char *csv_dir       = "data";
    const char *results_path  = "results/benchmark.csv";
    int         warmup_sec    = DEFAULT_WARMUP;
    int         duration_sec  = DEFAULT_DURATION;
    int         reps          = DEFAULT_REPS;
    std::string tiers_str     = "1,2,3,4,5";
    std::string rates_str     = "10000,50000,100000,250000,500000";

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--csv-dir")  && i+1<argc) csv_dir      = argv[++i];
        else if (!strcmp(argv[i],"--results")  && i+1<argc) results_path = argv[++i];
        else if (!strcmp(argv[i],"--warmup")   && i+1<argc) warmup_sec   = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--duration") && i+1<argc) duration_sec = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--reps")     && i+1<argc) reps         = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--tiers")    && i+1<argc) tiers_str    = argv[++i];
        else if (!strcmp(argv[i],"--rates")    && i+1<argc) rates_str    = argv[++i];
        else if (!strcmp(argv[i],"--dpdk-pci") && i+1<argc) g_dpdk_pci   = argv[++i];
        else if (!strcmp(argv[i],"--gpu-pcie") && i+1<argc) g_gpu_pcie   = argv[++i];
        else if (!strcmp(argv[i],"--nic-pcie") && i+1<argc) g_nic_pcie   = argv[++i];
        else if (!strcmp(argv[i],"--gpu-id")   && i+1<argc) g_gpu_id     = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--iface")   && i+1<argc) g_mcast_iface = argv[++i];
        else if (!strcmp(argv[i],"--receiver-iface") && i+1<argc) g_receiver_iface = argv[++i];
        else if (!strcmp(argv[i],"--sender-ssh")  && i+1<argc) g_sender_ssh  = argv[++i];
        else if (!strcmp(argv[i],"--sender-bin")  && i+1<argc) g_sender_bin  = argv[++i];
        else if (!strcmp(argv[i],"--sender-csv")  && i+1<argc) g_sender_csv  = argv[++i];
        else if (!strcmp(argv[i],"--sender-dest") && i+1<argc) g_sender_dest = argv[++i];
    }

    /* Parse tier list */
    std::vector<int> tiers;
    {
        std::istringstream ss(tiers_str);
        std::string tok;
        while (std::getline(ss, tok, ','))
            tiers.push_back(atoi(tok.c_str()));
    }

    /* Parse rate list */
    std::vector<long> rates;
    {
        std::istringstream ss(rates_str);
        std::string tok;
        while (std::getline(ss, tok, ','))
            rates.push_back(atol(tok.c_str()));
    }

    std::string csv_path = std::string(csv_dir) + "/ticks.csv";

    fprintf(stderr, "[harness] benchmark: %zu tiers × %zu rates × %d reps = %zu runs\n",
            tiers.size(), rates.size(), reps,
            tiers.size() * rates.size() * (size_t)reps);
    fprintf(stderr, "[harness] warmup=%ds measure=%ds\n", warmup_sec, duration_sec);
    fprintf(stderr, "[harness] results → %s\n", results_path);

    /* Create results directory */
    {
        std::string dir(results_path);
        size_t slash = dir.rfind('/');
        if (slash != std::string::npos) {
            std::string cmd = "mkdir -p " + dir.substr(0, slash);
            system(cmd.c_str());
        }
    }

    /* Open result collection socket */
    int result_fd = make_result_socket(BENCH_RESULT_PORT);
    if (result_fd < 0) return 1;

    /* Also intercept SignalResult on port 5006 — we count signals here so the
     * fill_simulator does not need to be running during benchmarks. */
    int signal_fd = make_result_socket(SIGNAL_PORT);
    if (signal_fd < 0) { close(result_fd); return 1; }

    /* Open CSV */
    std::ofstream csv_out(results_path);
    if (!csv_out) { fprintf(stderr, "Cannot write %s\n", results_path); return 1; }
    write_header(csv_out);

    int run_id = 0;
    for (int tier : tiers) {
        for (long rate : rates) {
            for (int rep = 0; rep < reps; ++rep) {
                ++run_id;
                RunResult r = run_one(run_id, tier, rate, rep + 1,
                                       csv_path.c_str(), result_fd, signal_fd,
                                       warmup_sec, duration_sec);
                write_row(csv_out, r);
            }
        }
    }

    close(result_fd);
    close(signal_fd);

    fprintf(stderr, "\n[harness] all %d runs complete. Results in %s\n",
            run_id, results_path);
    return 0;
}
