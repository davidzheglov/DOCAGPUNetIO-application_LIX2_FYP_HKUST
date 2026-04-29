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
#include <netdb.h>
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

static std::string make_env_assignment(const char *name)
{
    const char *val = getenv(name);
    return std::string(name) + "=" + (val ? val : "");
}

/* ── Hardware config for tier-specific args ──────────────────────────────── */
static std::string g_dpdk_pci  = "0000:bd:00.0";   /* T2: ConnectX-7 NIC PCIe */
static std::string g_rdma_dev  = "mlx5_0";         /* T3: RDMA device */
static std::string g_gpu_pcie  = "0000:ac:00.0";   /* T4: GPU 1 PCIe */
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
static std::string g_sender_control_path; /* optional shared SSH control socket */
static bool        g_light_bench = false; /* skip Monte Carlo in receiver kernels */
static std::string g_clock_cal_script
    = "~/DOCAGPUNetIO-application_LIX2_FYP_HKUST/scripts/clock_cal_server.py";
static std::string g_clock_cal_host;
static int         g_clock_cal_port = 6006;

static std::string sender_stats_path_for_run(int run_id)
{
    return "/tmp/doca_bench_sender_stats_" + std::to_string(run_id) + ".txt";
}

static uint64_t read_counter_from_file(const std::string &path)
{
    std::ifstream f(path);
    uint64_t v = 0;
    if (f) f >> v;
    return v;
}

static uint64_t read_remote_counter_via_ssh(const std::string &remote_path)
{
    std::string cmd = "ssh -o BatchMode=yes -o ConnectTimeout=3 ";
    if (!g_sender_control_path.empty()) {
        cmd += "-o ControlMaster=no -o ControlPath=" + g_sender_control_path + " ";
    }
    cmd += g_sender_ssh + " 'cat " + remote_path + " 2>/dev/null || echo 0'";

    FILE *p = popen(cmd.c_str(), "r");
    if (!p) return 0;
    unsigned long long v = 0;
    fscanf(p, "%llu", &v);
    pclose(p);
    return (uint64_t)v;
}

static uint64_t wall_time_ns()
{
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string sender_ssh_host()
{
    if (!g_clock_cal_host.empty()) return g_clock_cal_host;
    size_t at = g_sender_ssh.find('@');
    return (at == std::string::npos) ? g_sender_ssh : g_sender_ssh.substr(at + 1);
}

static std::string ssh_base_cmd()
{
    std::string cmd = "ssh -o BatchMode=yes -o ConnectTimeout=3 ";
    if (!g_sender_control_path.empty()) {
        cmd += "-o ControlMaster=no -o ControlPath=" + g_sender_control_path + " ";
    }
    return cmd;
}

struct ClockSample {
    bool     valid = false;
    uint64_t remote_ref_ns = 0;
    uint64_t local_ref_ns  = 0;
    uint64_t rtt_ns        = 0;
};

static ClockSample sample_clock_pair()
{
    ClockSample best{};
    if (g_sender_ssh.empty()) {
        best.valid = true;
        best.local_ref_ns = wall_time_ns();
        best.remote_ref_ns = best.local_ref_ns;
        return best;
    }

    std::string host = sender_ssh_host();
    if (host.empty()) return best;

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = nullptr;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", g_clock_cal_port);
    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0 || !res) {
        return best;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return best;
    }

    timeval tv{.tv_sec = 0, .tv_usec = 200000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    for (int i = 0; i < 24; ++i) {
        uint64_t t_a = wall_time_ns();
        ssize_t sent = sendto(fd, &t_a, sizeof(t_a), 0, res->ai_addr, res->ai_addrlen);
        if (sent != (ssize_t)sizeof(t_a)) continue;

        uint64_t rep[3]{};
        ssize_t nr = recv(fd, rep, sizeof(rep), 0);
        uint64_t t_d = wall_time_ns();
        if (nr != (ssize_t)sizeof(rep)) continue;

        uint64_t t_b = rep[1];
        uint64_t t_c = rep[2];
        uint64_t remote_span = (t_c >= t_b) ? (t_c - t_b) : 0;
        uint64_t round_trip = (t_d >= t_a) ? (t_d - t_a) : 0;
        uint64_t rtt = (round_trip >= remote_span) ? (round_trip - remote_span) : round_trip;
        uint64_t local_ref = t_a + (round_trip / 2);
        uint64_t remote_ref = t_b + ((t_c >= t_b) ? ((t_c - t_b) / 2) : 0);

        if (!best.valid || rtt < best.rtt_ns) {
            best.valid = true;
            best.rtt_ns = rtt;
            best.local_ref_ns = local_ref;
            best.remote_ref_ns = remote_ref;
        }
        usleep(5000);
    }

    close(fd);
    freeaddrinfo(res);
    return best;
}

static uint64_t sender_t1_to_local_ns(uint64_t sender_t1_ns,
                                      const ClockSample &start,
                                      const ClockSample &end)
{
    if (!start.valid) return sender_t1_ns;
    if (!end.valid || end.remote_ref_ns <= start.remote_ref_ns) {
        int64_t offset = (int64_t)start.local_ref_ns - (int64_t)start.remote_ref_ns;
        return (uint64_t)((int64_t)sender_t1_ns + offset);
    }

    long double remote_span = (long double)(end.remote_ref_ns - start.remote_ref_ns);
    long double local_span  = (long double)((int64_t)end.local_ref_ns - (int64_t)start.local_ref_ns);
    long double alpha       = ((long double)sender_t1_ns - (long double)start.remote_ref_ns) / remote_span;
    long double mapped      = (long double)start.local_ref_ns + alpha * local_span;
    if (mapped < 0.0L) mapped = 0.0L;
    return (uint64_t)(mapped + 0.5L);
}

static bool start_remote_clock_server()
{
    if (g_sender_ssh.empty()) return true;
    std::string cmd = ssh_base_cmd() + g_sender_ssh
        + " 'pkill -f clock_cal_server.py 2>/dev/null || true; "
          "nohup python3 " + g_clock_cal_script
        + " --ip 0.0.0.0 --port " + std::to_string(g_clock_cal_port)
        + " >/tmp/clock_cal_server.log 2>&1 </dev/null &'";
    if (system(cmd.c_str()) != 0) return false;

    for (int i = 0; i < 20; ++i) {
        ClockSample s = sample_clock_pair();
        if (s.valid) return true;
        usleep(100000);
    }
    return false;
}

static void stop_remote_clock_server()
{
    if (g_sender_ssh.empty()) return;
    std::string cmd = ssh_base_cmd() + g_sender_ssh
        + " 'pkill -f clock_cal_server.py 2>/dev/null || true'"
          " >/dev/null 2>&1";
    system(cmd.c_str());
}

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

    if (tier == 3) {
        args.push_back("--dev");
        args.push_back(g_rdma_dev);
    }

    args.push_back("--tier");
    args.push_back(std::to_string(tier));

    if (g_light_bench)
        args.push_back("--light-bench");

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

static pid_t launch_receiver(int tier, const char *binary,
                             const std::vector<std::string> &extra_args)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        std::vector<std::string> owned_args;
        std::vector<const char *> argv;

        /* T2/T3/T4 need the same privilege model as their manual bring-up
         * commands on lxcpu1. Preserve the caller's environment so CUDA/DOCA/
         * DPDK library paths continue to work under sudo. */
        bool need_sudo = (tier >= 2 && tier <= 5) && (geteuid() != 0);
        if (need_sudo) {
            argv.push_back("sudo");
            argv.push_back("-E");
            argv.push_back("env");
            owned_args.push_back(make_env_assignment("PATH"));
            owned_args.push_back(make_env_assignment("LD_LIBRARY_PATH"));
            argv.push_back(owned_args[0].c_str());
            argv.push_back(owned_args[1].c_str());
        }

        argv.push_back(binary);
        for (const auto &a : extra_args) argv.push_back(a.c_str());
        argv.push_back(nullptr);

        if (need_sudo) {
            execvp("sudo", const_cast<char *const *>(argv.data()));
            perror("execvp sudo");
        } else {
            execv(binary, const_cast<char *const *>(argv.data()));
            perror("execv");
        }
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
static pid_t launch_sender_ssh(long rate_hz, const std::string &stats_path)
{
    std::string remote_cmd =
        "pkill -x data_source 2>/dev/null || true; sleep 0.2; "
        + g_sender_bin
        + " --mode replay"
        + " --csv "  + g_sender_csv
        + " --rate " + std::to_string(rate_hz)
        + " --stats-file " + stats_path
        + " --dest " + g_sender_dest;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        std::vector<std::string> owned_args;
        std::vector<const char *> argv = {
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ServerAliveInterval=10",
            "-o", "StrictHostKeyChecking=accept-new",
        };
        if (!g_sender_control_path.empty()) {
            owned_args.push_back("ControlPath=" + g_sender_control_path);
            argv.push_back("-o");
            argv.push_back("ControlMaster=no");
            argv.push_back("-o");
            argv.push_back(owned_args.back().c_str());
        }
        argv.push_back(g_sender_ssh.c_str());
        argv.push_back(remote_cmd.c_str());
        argv.push_back(nullptr);
        execvp("ssh", const_cast<char *const *>(argv.data()));
        perror("execlp ssh");
        _exit(127);
    }
    return pid;
}

static void kill_remote_sender(void)
{
    if (g_sender_ssh.empty()) return;
    std::string cmd = "ssh -o BatchMode=yes -o ConnectTimeout=3 ";
    if (!g_sender_control_path.empty()) {
        cmd += "-o ControlMaster=no -o ControlPath=" + g_sender_control_path + " ";
    }
    cmd += g_sender_ssh
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
    int rcvbuf = 256 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

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
    size_t sent_ticks;
    size_t processed_ticks;
    size_t n_ticks;
    double drop_rate;
    size_t receiver_reported_drops;
    size_t inferred_missing_ticks;
    size_t rejected_invalid_order;
    size_t rejected_too_old;
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
    f << "run_id,tier,rate_hz,repetition,sent_ticks,processed_ticks,n_ticks,drop_rate,"
      << "receiver_reported_drops,inferred_missing_ticks,"
      << "rejected_invalid_order,rejected_too_old,"
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
      << r.sent_ticks   << ','
      << r.processed_ticks << ','
      << r.n_ticks      << ','
      << r.drop_rate    << ','
      << r.receiver_reported_drops << ','
      << r.inferred_missing_ticks << ','
      << r.rejected_invalid_order << ','
      << r.rejected_too_old << ','
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
    std::string sender_stats_path = sender_stats_path_for_run(run_id);

    /* Kill any leftover receivers locally; on remote host the SSH launcher
     * will pkill data_source itself before starting the new one. */
    system("pkill -f bin/cpu_receiver  2>/dev/null; "
           "pkill -f bin/dpdk_receiver 2>/dev/null; "
           "pkill -f bin/rdma_receiver 2>/dev/null; "
           "pkill -f bin/gpu_receiver  2>/dev/null; "
           "true");
    if (g_sender_ssh.empty()) {
        system("pkill -f bin/data_source 2>/dev/null; true");
        unlink(sender_stats_path.c_str());
    } else {
        kill_remote_sender();
        std::string rm_cmd = "ssh -o BatchMode=yes -o ConnectTimeout=3 ";
        if (!g_sender_control_path.empty()) {
            rm_cmd += "-o ControlMaster=no -o ControlPath=" + g_sender_control_path + " ";
        }
        rm_cmd += g_sender_ssh + " 'rm -f " + sender_stats_path + "'";
        system(rm_cmd.c_str());
    }
    usleep(300000);

    /* Launch data_source — remote (lxcpu2 via SSH) or local (legacy) */
    pid_t ds_pid = -1;
    if (!g_sender_ssh.empty()) {
        fprintf(stderr, "[harness] launching remote sender on %s\n",
                g_sender_ssh.c_str());
        ds_pid = launch_sender_ssh(rate_hz, sender_stats_path);
    } else {
        std::vector<std::string> ds_args = {
            "--mode", "replay",
            "--csv",  csv_path,
            "--rate", std::to_string(rate_hz),
            "--stats-file", sender_stats_path
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
    pid_t rx_pid = launch_receiver(tier, receiver_binary(tier), rx_args);
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
            while (recv(result_fd, &br, sizeof(br), MSG_DONTWAIT) == sizeof(br)) {}
            while (recv(signal_fd, &sr, sizeof(sr), MSG_DONTWAIT) == sizeof(sr)) {}
            usleep(1000);
        }
    }

    /* Collect raw results during measurement. Sender-side t1 is reconciled
     * into the local clock domain after the run using two clock samples. */
    std::vector<BenchmarkResult> raw_results;
    std::vector<double> e2e_ns, ingest_ns, compute_ns;

    uint64_t n_dropped = 0;
    uint64_t n_inferred_missing_ticks = 0;
    uint64_t n_rejected_invalid_order = 0;
    uint64_t n_rejected_too_old = 0;
    uint64_t n_signals_total = 0;       /* every SignalResult received */
    uint64_t n_signals_actionable = 0;  /* signal != 0 only */
    bool have_last_tick_id = false;
    uint32_t last_tick_id = 0;
    ClockSample cal_start = sample_clock_pair();
    uint64_t sent_ticks_start = g_sender_ssh.empty()
        ? read_counter_from_file(sender_stats_path)
        : read_remote_counter_via_ssh(sender_stats_path);
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
            ssize_t n;
            while ((n = recv(result_fd, &br, sizeof(br), MSG_DONTWAIT)) == sizeof(BenchmarkResult)) {
                if (n == sizeof(BenchmarkResult)) {
                    if (!br.dropped) {
                        if (have_last_tick_id && br.tick_id > last_tick_id + 1) {
                            n_inferred_missing_ticks +=
                                (uint64_t)(br.tick_id - last_tick_id - 1);
                        }
                        if (!have_last_tick_id || br.tick_id > last_tick_id) {
                            last_tick_id = br.tick_id;
                            have_last_tick_id = true;
                        }
                        raw_results.push_back(br);
                    }
                    if (br.dropped) { ++n_dropped; }
                }
            }
        }
        if (pfds[1].revents & POLLIN) {
            SignalResult sr{};
            ssize_t n;
            while ((n = recv(signal_fd, &sr, sizeof(sr), MSG_DONTWAIT)) == sizeof(SignalResult)) {
                ++n_signals_total;
                if (sr.signal != 0) ++n_signals_actionable;
            }
        }
    }

    uint64_t sent_ticks_end = g_sender_ssh.empty()
        ? read_counter_from_file(sender_stats_path)
        : read_remote_counter_via_ssh(sender_stats_path);
    ClockSample cal_end = sample_clock_pair();
    uint64_t sent_ticks_window = (sent_ticks_end >= sent_ticks_start)
        ? (sent_ticks_end - sent_ticks_start) : 0;

    e2e_ns.reserve(raw_results.size());
    ingest_ns.reserve(raw_results.size());
    compute_ns.reserve(raw_results.size());
    for (const BenchmarkResult &raw_br : raw_results) {
        BenchmarkResult br = raw_br;
        br.t1_ns = sender_t1_to_local_ns(raw_br.t1_ns, cal_start, cal_end);
        if (!(br.t4_ns > br.t1_ns && br.t3_ns >= br.t2_ns && br.t2_ns >= br.t1_ns)) {
            ++n_rejected_invalid_order;
            continue;
        }
        if (br.t4_ns - br.t1_ns > 10000000000ULL) {
            ++n_rejected_too_old;
            continue;
        }
        e2e_ns.push_back((double)(br.t4_ns - br.t1_ns));
        ingest_ns.push_back((double)(br.t2_ns - br.t1_ns));
        compute_ns.push_back(br.compute_ns != 0
            ? (double)br.compute_ns
            : (double)(br.t3_ns - br.t2_ns));
    }

    /* Kill subprocesses */
    kill_proc(rx_pid);
    if (!g_sender_ssh.empty()) {
        kill_remote_sender();   /* tells the remote machine to stop sending */
    }
    kill_proc(ds_pid);          /* reaps the local ssh client (or local data_source) */
    usleep(100000);

    size_t n_ticks = e2e_ns.size();
    uint64_t processed_ticks = n_signals_total;
    double drop_rate = sent_ticks_window > 0
        ? (double)(sent_ticks_window > processed_ticks
              ? (sent_ticks_window - processed_ticks) : 0ULL) / (double)sent_ticks_window
        : 0.0;

    RunResult r{};
    r.run_id     = run_id;
    r.tier       = tier;
    r.rate_hz    = rate_hz;
    r.repetition = repetition;
    r.sent_ticks = sent_ticks_window;
    r.processed_ticks = processed_ticks;
    r.n_ticks    = n_ticks;
    r.drop_rate  = drop_rate;
    r.receiver_reported_drops = n_dropped;
    r.inferred_missing_ticks = n_inferred_missing_ticks;
    r.rejected_invalid_order = n_rejected_invalid_order;
    r.rejected_too_old = n_rejected_too_old;
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
        "[harness] T%d @%ld: n=%zu drop=%.2f%% "
        "(sent=%llu processed=%llu rx_drop=%llu gap_drop=%llu invalid=%llu too_old=%llu) "
        "e2e_p50=%.1fus e2e_p99=%.1fus "
        "tput=%.0f/s sig_total=%.0f/s sig_act=%.0f/s\n",
        tier, rate_hz, n_ticks, drop_rate * 100.0,
        (unsigned long long)sent_ticks_window,
        (unsigned long long)processed_ticks,
        (unsigned long long)n_dropped,
        (unsigned long long)n_inferred_missing_ticks,
        (unsigned long long)n_rejected_invalid_order,
        (unsigned long long)n_rejected_too_old,
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
        else if (!strcmp(argv[i],"--rdma-dev") && i+1<argc) g_rdma_dev   = argv[++i];
        else if (!strcmp(argv[i],"--gpu-pcie") && i+1<argc) g_gpu_pcie   = argv[++i];
        else if (!strcmp(argv[i],"--nic-pcie") && i+1<argc) g_nic_pcie   = argv[++i];
        else if (!strcmp(argv[i],"--gpu-id")   && i+1<argc) g_gpu_id     = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--iface")   && i+1<argc) g_mcast_iface = argv[++i];
        else if (!strcmp(argv[i],"--receiver-iface") && i+1<argc) g_receiver_iface = argv[++i];
        else if (!strcmp(argv[i],"--sender-ssh")  && i+1<argc) g_sender_ssh  = argv[++i];
        else if (!strcmp(argv[i],"--sender-bin")  && i+1<argc) g_sender_bin  = argv[++i];
        else if (!strcmp(argv[i],"--sender-csv")  && i+1<argc) g_sender_csv  = argv[++i];
        else if (!strcmp(argv[i],"--sender-dest") && i+1<argc) g_sender_dest = argv[++i];
        else if (!strcmp(argv[i],"--sender-control-path") && i+1<argc) g_sender_control_path = argv[++i];
        else if (!strcmp(argv[i],"--clock-cal-host") && i+1<argc) g_clock_cal_host = argv[++i];
        else if (!strcmp(argv[i],"--clock-cal-port") && i+1<argc) g_clock_cal_port = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--light-bench")) g_light_bench = true;
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

    if (!start_remote_clock_server()) {
        fprintf(stderr, "[harness] warning: clock calibration server unavailable; "
                        "falling back to raw sender timestamps\n");
    }

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
    stop_remote_clock_server();

    fprintf(stderr, "\n[harness] all %d runs complete. Results in %s\n",
            run_id, results_path);
    return 0;
}
