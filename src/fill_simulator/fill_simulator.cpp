/*
 * fill_simulator.cpp — Stage 5: order book engine.
 *
 * Listens on UDP port 5006 for SignalResult packets from any tier receiver.
 * Uses PnLTracker (FIFO matching, from development-david-local) for P&L.
 * Writes a trade log CSV and summary on exit (SIGINT / SIGTERM).
 *
 * Usage:
 *   fill_simulator [--port 5006] [--commission 5] [--output results/fills.csv]
 *
 * --commission N   commission in bps per side (default: 5)
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "signal_result.h"
#include "tick_message.h"
#include "pnl_tracker.h"

#define DEFAULT_OUTPUT "results/fills.csv"

static volatile sig_atomic_t g_stop = 0;
static void sig_handler(int) { g_stop = 1; }

int main(int argc, char **argv)
{
    int         listen_port    = SIGNAL_PORT;
    double      commission_bps = 5.0;
    const char *output_path    = DEFAULT_OUTPUT;

    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--port")       && i+1 < argc) listen_port    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--commission")  && i+1 < argc) commission_bps = atof(argv[++i]);
        else if (!strcmp(argv[i], "--output")      && i+1 < argc) output_path    = argv[++i];
    }

    fprintf(stderr, "[fill_simulator] port=%d  commission=%.1f bps  output=%s\n",
            listen_port, commission_bps, output_path);

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

    /* 100 ms receive timeout so we can check g_stop regularly */
    timeval tv{ .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    PnLTracker tracker(commission_bps);
    uint64_t   n_rx = 0;
    SignalResult sig{};

    while (!g_stop) {
        ssize_t n = recv(fd, &sig, sizeof(sig), 0);
        if (n != (ssize_t)sizeof(SignalResult)) continue;

        tracker.on_signal(sig);

        if (++n_rx % 10000 == 0) {
            fprintf(stderr,
                "[fill_sim] %lu signals | trades=%d | PnL=$%.4f | "
                "win=%.1f%% | rsi_sig=%+d\n",
                n_rx, tracker.total_trades, tracker.cumulative_pnl,
                tracker.win_rate(), (int)sig.rsi_signal);
        }
    }

    fprintf(stderr, "\n[fill_sim] stopping — processed %lu signals\n", n_rx);
    tracker.print_summary();
    tracker.write_csv(output_path);

    close(fd);
    return 0;
}
