/*
 * fill_simulator.cpp — Stage 5: order book engine.
 *
 * Listens on UDP port 5006 for SignalResult packets from any tier receiver.
 * Simulates order fills using mid_price ± half_spread + commission.
 * Tracks per-instrument position, P&L, win rate, and Sharpe ratio.
 * Writes a trade log CSV and a summary JSON on exit (SIGINT).
 *
 * Usage:
 *   fill_simulator [--port 5006] [--commission 0.0005] [--output results/fills.csv]
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "signal_result.h"
#include "tick_message.h"

/* ── Constants ───────────────────────────────────────────────────────────── */
#define DEFAULT_COMMISSION  0.0005   /* 5 bps per side */
#define DEFAULT_OUTPUT      "results/fills.csv"

/* ── Per-instrument state ─────────────────────────────────────────────────── */
struct InstrumentState {
    int8_t   position   = 0;       /* -1 short, 0 flat, +1 long */
    double   entry_px   = 0.0;
    double   realized   = 0.0;
    uint64_t n_trades   = 0;
    uint64_t n_wins     = 0;
};

/* ── Trade record (for CSV log) ─────────────────────────────────────────── */
struct Trade {
    uint64_t tick_id;
    uint16_t instrument_id;
    char     side[5];    /* BUY / SELL */
    double   price;
    double   pnl;        /* realized on close */
    uint64_t t1_ns;      /* not available here — zero */
    uint64_t t4_ns;
};

/* ── Global state ────────────────────────────────────────────────────────── */
static volatile sig_atomic_t g_stop = 0;
static void sig_handler(int) { g_stop = 1; }

static std::array<InstrumentState, MAX_INSTRUMENTS> g_instruments{};
static std::vector<Trade> g_trades;
static double g_commission = DEFAULT_COMMISSION;

/* ── Fill logic ─────────────────────────────────────────────────────────── */
static void process_signal(const SignalResult &sig)
{
    if (sig.signal == 0) return;  /* hold — do nothing */

    int inst = sig.instrument_id % MAX_INSTRUMENTS;
    InstrumentState &state = g_instruments[inst];
    double exec_px = sig.mid_price + (double)sig.signal * sig.spread * 0.5;

    if (state.position == 0) {
        /* Open new position */
        state.position = sig.signal;
        state.entry_px = exec_px * (1.0 + (double)sig.signal * g_commission);

    } else if (state.position != sig.signal) {
        /* Close / reverse position */
        double close_px = exec_px * (1.0 - (double)state.position * g_commission);
        double pnl = (close_px - state.entry_px) * (double)state.position;
        state.realized += pnl;
        ++state.n_trades;
        if (pnl > 0) ++state.n_wins;

        Trade tr{};
        tr.tick_id       = sig.tick_id;
        tr.instrument_id = sig.instrument_id;
        snprintf(tr.side, sizeof(tr.side), "%s",
                 state.position > 0 ? "SELL" : "BUY ");
        tr.price  = close_px;
        tr.pnl    = pnl;
        tr.t4_ns  = sig.t4_ns;
        g_trades.push_back(tr);

        /* Open new position if reversing */
        if (sig.signal != 0) {
            state.position = sig.signal;
            state.entry_px = exec_px * (1.0 + (double)sig.signal * g_commission);
        } else {
            state.position = 0;
            state.entry_px = 0.0;
        }
    }
}

/* ── Write CSV ───────────────────────────────────────────────────────────── */
static void write_csv(const char *path)
{
    /* Create output directory if needed */
    std::string dir(path);
    size_t slash = dir.rfind('/');
    if (slash != std::string::npos) {
        dir = dir.substr(0, slash);
        std::string mkdir_cmd = "mkdir -p " + dir;
        system(mkdir_cmd.c_str());
    }

    std::ofstream f(path);
    if (!f) { fprintf(stderr, "Cannot write %s\n", path); return; }

    f << "tick_id,instrument_id,side,price,pnl,t4_ns\n";
    for (const auto &tr : g_trades) {
        f << tr.tick_id << ','
          << tr.instrument_id << ','
          << tr.side << ','
          << tr.price << ','
          << tr.pnl << ','
          << tr.t4_ns << '\n';
    }
    fprintf(stderr, "[fill_sim] wrote %zu trades to %s\n", g_trades.size(), path);
}

/* ── Write summary ───────────────────────────────────────────────────────── */
static void write_summary()
{
    double total_pnl  = 0.0;
    uint64_t n_trades = 0;
    uint64_t n_wins   = 0;
    std::vector<double> trade_pnls;
    trade_pnls.reserve(g_trades.size());

    for (const auto &tr : g_trades) {
        total_pnl += tr.pnl;
        trade_pnls.push_back(tr.pnl);
    }
    for (const auto &inst : g_instruments) {
        n_trades += inst.n_trades;
        n_wins   += inst.n_wins;
    }

    double win_rate = n_trades > 0 ? (double)n_wins / (double)n_trades : 0.0;

    /* Sharpe (daily equivalent, rough) */
    double mean = 0.0, var = 0.0;
    for (double p : trade_pnls) mean += p;
    if (!trade_pnls.empty()) mean /= (double)trade_pnls.size();
    for (double p : trade_pnls) var += (p - mean) * (p - mean);
    if (trade_pnls.size() > 1) var /= (double)(trade_pnls.size() - 1);
    double sharpe = var > 0.0 ? mean / std::sqrt(var) : 0.0;

    fprintf(stderr,
        "\n[fill_sim] === Summary ===\n"
        "  Total trades : %lu\n"
        "  Win rate     : %.1f%%\n"
        "  Total P&L    : %.6f\n"
        "  Sharpe ratio : %.3f\n",
        n_trades, win_rate * 100.0, total_pnl, sharpe);
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    int         listen_port = SIGNAL_PORT;
    const char *output_path = DEFAULT_OUTPUT;
    g_commission = DEFAULT_COMMISSION;

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i],"--port")       && i+1<argc) listen_port  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--commission")  && i+1<argc) g_commission = atof(argv[++i]);
        else if (!strcmp(argv[i],"--output")      && i+1<argc) output_path  = argv[++i];
    }

    fprintf(stderr, "[fill_simulator] listening on port %d\n", listen_port);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }

    /* Set receive timeout so we can check g_stop periodically */
    timeval tv{ .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint64_t n_rx = 0;
    SignalResult sig{};

    while (!g_stop) {
        ssize_t n = recv(fd, &sig, sizeof(sig), 0);
        if (n == sizeof(SignalResult)) {
            process_signal(sig);
            if (++n_rx % 100000 == 0)
                fprintf(stderr, "[fill_sim] processed %lu signals\n", n_rx);
        }
    }

    fprintf(stderr, "\n[fill_sim] shutting down, processed %lu signals\n", n_rx);

    write_csv(output_path);
    write_summary();

    close(fd);
    return 0;
}
