#pragma once

/*
 * pnl_tracker.h — FIFO order-matching P&L tracker.
 *
 * Ported from development-david-local/common/pnl_tracker.h and adapted to
 * consume SignalResult packets (our wire format) rather than Order structs.
 *
 * Design:
 *   - Per-instrument FIFO queue of open buy positions
 *   - On SELL signal: match against oldest open buy, realise P&L
 *   - Tracks: cumulative P&L, peak P&L, drawdown, win rate, Sharpe
 *   - commission: applied as fraction of execution price (default 5 bps/side)
 *
 * Usage:
 *   PnLTracker tracker;
 *   tracker.on_signal(sig);        // call for each non-zero SignalResult
 *   tracker.print_summary();
 *   tracker.write_csv("fills.csv");
 */

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <string>
#include <vector>

#include "tick_message.h"    /* MAX_INSTRUMENTS */
#include "signal_result.h"

#define DEFAULT_COMMISSION_BPS  5     /* bps per side */

/* ── Open position in the FIFO queue ──────────────────────────────────────── */

struct OpenPosition {
    uint64_t  tick_id;
    uint16_t  instrument_id;
    double    entry_px;      /* price paid, after commission */
    float     qty;
};

/* ── Closed trade record ───────────────────────────────────────────────────── */

struct ClosedTrade {
    uint64_t  tick_id;
    uint16_t  instrument_id;
    int8_t    side;          /* +1 = closed long, -1 = closed short */
    double    entry_px;
    double    exit_px;
    double    pnl;
    uint64_t  t4_ns;
};

/* ── Tracker ───────────────────────────────────────────────────────────────── */

struct PnLTracker {
    double commission_rate;   /* fraction, e.g. 0.0005 = 5 bps */

    /* Per-instrument open buy queue (FIFO) */
    std::deque<OpenPosition> open_longs[MAX_INSTRUMENTS];
    std::deque<OpenPosition> open_shorts[MAX_INSTRUMENTS];

    double   cumulative_pnl = 0.0;
    double   peak_pnl       = 0.0;
    int      total_trades   = 0;
    int      winning_trades = 0;

    std::vector<ClosedTrade> closed_trades;
    std::vector<double>      trade_pnls;    /* for Sharpe calculation */

    explicit PnLTracker(double commission_bps = DEFAULT_COMMISSION_BPS)
        : commission_rate(commission_bps / 10000.0) {}

    /*
     * on_signal() — process one SignalResult from the kernel.
     * signal == 0: hold, no action.
     * signal == +1: open/add long at mid + half_spread + commission.
     * signal == -1: close oldest long (if any) and realise P&L.
     */
    void on_signal(const SignalResult &sig)
    {
        if (sig.signal == 0) return;

        int inst = sig.instrument_id % MAX_INSTRUMENTS;

        if (sig.signal == +1) {
            /* Buy: execution at ask = mid + half_spread */
            double exec_px = sig.mid_price + sig.spread * 0.5;
            double cost_px = exec_px * (1.0 + commission_rate);  /* include commission */
            open_longs[inst].push_back({sig.tick_id, sig.instrument_id, cost_px, 1.0f});

        } else {
            /* Sell: execution at bid = mid - half_spread */
            auto &q = open_longs[inst];
            if (q.empty()) return;   /* no open long to close */

            OpenPosition buy = q.front();
            q.pop_front();

            double exec_px = sig.mid_price - sig.spread * 0.5;
            double recv_px = exec_px * (1.0 - commission_rate);  /* after commission */
            double pnl     = (recv_px - buy.entry_px) * buy.qty;

            cumulative_pnl += pnl;
            peak_pnl        = std::max(peak_pnl, cumulative_pnl);
            total_trades++;
            if (pnl > 0.0) winning_trades++;

            closed_trades.push_back({
                sig.tick_id, sig.instrument_id, +1,
                buy.entry_px, recv_px, pnl, sig.t4_ns
            });
            trade_pnls.push_back(pnl);
        }
    }

    double win_rate() const
    {
        return total_trades > 0
            ? 100.0 * winning_trades / total_trades
            : 0.0;
    }

    double max_drawdown() const
    {
        return std::max(0.0, peak_pnl - cumulative_pnl);
    }

    /* Annualised Sharpe (assumes each trade = independent period). */
    double sharpe() const
    {
        int n = (int)trade_pnls.size();
        if (n < 2) return 0.0;
        double mean = 0, var = 0;
        for (double p : trade_pnls) mean += p;
        mean /= n;
        for (double p : trade_pnls) var += (p - mean) * (p - mean);
        double sd = std::sqrt(var / (n - 1));
        return sd > 0.0 ? mean / sd : 0.0;
    }

    int open_positions() const
    {
        int total = 0;
        for (int i = 0; i < MAX_INSTRUMENTS; ++i)
            total += (int)open_longs[i].size();
        return total;
    }

    void print_summary() const
    {
        printf("\n  === Trade Performance ===\n");
        printf("  Total closed trades : %d\n",    total_trades);
        printf("  Winning trades      : %d (%.1f%%)\n", winning_trades, win_rate());
        printf("  Cumulative P&L      : $%.6f\n", cumulative_pnl);
        printf("  Peak P&L            : $%.6f\n", peak_pnl);
        printf("  Max drawdown        : $%.6f\n", max_drawdown());
        printf("  Sharpe ratio        : %.3f\n",  sharpe());
        printf("  Open positions      : %d\n",    open_positions());
    }

    void write_csv(const char *path) const
    {
        FILE *f = fopen(path, "w");
        if (!f) { fprintf(stderr, "[pnl] cannot open %s\n", path); return; }
        fprintf(f, "tick_id,instrument_id,side,entry_px,exit_px,pnl,t4_ns\n");
        for (const auto &t : closed_trades) {
            fprintf(f, "%llu,%u,%d,%.6f,%.6f,%.8f,%llu\n",
                    (unsigned long long)t.tick_id,
                    (unsigned)t.instrument_id,
                    (int)t.side,
                    t.entry_px, t.exit_px, t.pnl,
                    (unsigned long long)t.t4_ns);
        }
        fclose(f);
    }
};
