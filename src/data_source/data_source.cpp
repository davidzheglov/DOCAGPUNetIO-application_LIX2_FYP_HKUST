/*
 * data_source.cpp — unified tick data source for the GPU tick pipeline.
 *
 * Modes:
 *   --mode replay   Read historical CSV, send TickMessage UDP multicast
 *                   at configurable rate using busy-wait timing.
 *   --mode live     Connect to Binance WebSocket, subscribe to bookTicker
 *                   + aggTrade streams, forward as UDP multicast.
 *                   (requires ENABLE_LIVE_FEED / libwebsockets)
 *   --mode both     Replay + live simultaneously on separate threads,
 *                   each at half the requested rate.
 *
 * Usage:
 *   data_source --mode replay --csv data/ticks.csv --rate 500000
 *   data_source --mode live   --symbols BTCUSDT,ETHUSDT
 *   data_source --mode both   --csv data/ticks.csv --rate 500000
 *
 * UDP multicast: 239.0.0.1:5005  (TICK_MCAST_ADDR / TICK_MCAST_PORT)
 * T1 timestamp is stamped at sendto().
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "tick_message.h"

#ifdef ENABLE_LIVE_FEED
#  include <libwebsockets.h>
#endif

/* ── CPU pause hint ─────────────────────────────────────────────────────────── */
#ifdef ARCH_X86_64
#  include <immintrin.h>
#  define CPU_PAUSE() _mm_pause()
#elif defined(ARCH_AARCH64)
#  define CPU_PAUSE() __asm__ volatile("yield" ::: "memory")
#else
#  define CPU_PAUSE() ((void)0)
#endif

using Clock = std::chrono::high_resolution_clock;
using NS    = std::chrono::nanoseconds;

/* ────────────────────────────────────────────────────────────────────────────
 *  Multicast socket helpers
 * ────────────────────────────────────────────────────────────────────────── */

/* Global stop flag — set by SIGINT/SIGTERM, polled by worker loops. */
static std::atomic<bool> g_stop{false};

/* Global: if set via --iface, forces multicast out a specific NIC */
static const char *g_mcast_iface = nullptr;

/*
 * Global: if set via --dest <ip:port>, overrides the default multicast
 * destination (239.0.0.1:5005) with a user-specified unicast address.
 *
 * Use case: --mode live on the HOST needs to hand the tick stream to a
 * relay on the DPU ARM (e.g. 192.168.100.2:6005 over tmfifo_net0) because
 * the bridge split-horizon rule on DPU prevents a direct host→PF1 TX
 * multicast from looping back to host PF1 RX / DOCA Flow.
 */
static const char *g_dest_override = nullptr;
static const char *g_stats_file = nullptr;

static void write_stats_file(uint32_t sent_ticks)
{
    if (!g_stats_file) return;
    FILE *f = fopen(g_stats_file, "w");
    if (!f) return;
    fprintf(f, "%u\n", sent_ticks);
    fclose(f);
}

static int make_send_socket(sockaddr_in &dest)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    /* Parse destination: either --dest <ip:port> or default multicast. */
    const char *dst_ip   = TICK_MCAST_ADDR;
    int         dst_port = TICK_MCAST_PORT;
    char        dst_buf[64] = {};

    if (g_dest_override) {
        strncpy(dst_buf, g_dest_override, sizeof(dst_buf) - 1);
        char *colon = strchr(dst_buf, ':');
        if (colon) {
            *colon = '\0';
            dst_port = atoi(colon + 1);
        }
        dst_ip = dst_buf;
        fprintf(stderr, "[data_source] unicast dest override: %s:%d\n",
                dst_ip, dst_port);
    }

    uint32_t dst_addr = inet_addr(dst_ip);
    bool is_mcast = (ntohl(dst_addr) & 0xF0000000u) == 0xE0000000u;

    if (is_mcast) {
        /* Multicast TTL = 1 (LAN only) */
        int ttl = 1;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

        /* Bind multicast output to a specific NIC (bypasses loopback) */
        if (g_mcast_iface) {
            struct in_addr iface_addr{};
            iface_addr.s_addr = inet_addr(g_mcast_iface);
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                            &iface_addr, sizeof(iface_addr)) < 0) {
                perror("IP_MULTICAST_IF");
            } else {
                fprintf(stderr, "[data_source] multicast bound to interface %s\n",
                        g_mcast_iface);
            }
        }
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons((uint16_t)dst_port);
    dest.sin_addr.s_addr = dst_addr;
    return fd;
}

/* Back-compat wrapper: old signature (ignores its mcast_addr/port args when
 * g_dest_override is set; otherwise uses them as defaults). */
static int make_mcast_send_socket(const char * /*mcast_addr*/, int /*port*/,
                                   sockaddr_in &dest)
{
    return make_send_socket(dest);
}

static void send_tick(int fd, const sockaddr_in &dest, TickMessage &tick)
{
    tick.timestamp_ns = now_ns();   /* T1 stamped at sendto() */
    sendto(fd, &tick, sizeof(tick), 0,
           reinterpret_cast<const sockaddr *>(&dest), sizeof(dest));
}

/* ────────────────────────────────────────────────────────────────────────────
 *  CSV replay
 *
 *  Expected CSV format (header required):
 *    timestamp_ns,instrument_id,bid,ask,last_price,volume
 *    1709000000000000000,0,42000.50,42001.00,42000.75,1.5
 *
 *  The timestamp_ns column is used only to preserve relative ordering;
 *  actual T1 is always stamped fresh at sendto().
 * ────────────────────────────────────────────────────────────────────────── */

struct CsvTick {
    uint16_t instrument_id;
    double   bid, ask, last_price, volume;
};

static bool load_csv(const char *path, std::vector<CsvTick> &out)
{
    std::ifstream f(path);
    if (!f) { fprintf(stderr, "Cannot open CSV: %s\n", path); return false; }

    std::string line;
    std::getline(f, line); /* skip header */

    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        CsvTick t{};
        uint64_t ts_unused;
        if (sscanf(line.c_str(), "%lu,%hu,%lf,%lf,%lf,%lf",
                   &ts_unused, &t.instrument_id,
                   &t.bid, &t.ask, &t.last_price, &t.volume) == 6) {
            out.push_back(t);
        }
    }
    fprintf(stderr, "[replay] loaded %zu ticks from %s\n", out.size(), path);
    return !out.empty();
}

static void run_replay(const char *csv_path, long rate_hz, uint8_t source_flag,
                        std::atomic<bool> &stop)
{
    std::vector<CsvTick> ticks;
    if (!load_csv(csv_path, ticks)) return;

    sockaddr_in dest{};
    int fd = make_mcast_send_socket(TICK_MCAST_ADDR, TICK_MCAST_PORT, dest);
    if (fd < 0) return;

    const long ns_per_tick = 1000000000L / rate_hz;
    uint32_t   tick_id     = 0;

    fprintf(stderr, "[replay] starting at %ld msg/sec (%.1f μs/tick)\n",
            rate_hz, (double)ns_per_tick / 1000.0);

    auto next_send = Clock::now();

    while (!stop.load(std::memory_order_relaxed)) {
        for (size_t i = 0; i < ticks.size() && !stop.load(); ++i, ++tick_id) {
            TickMessage msg{};
            msg.tick_id       = tick_id;
            msg.instrument_id = ticks[i].instrument_id;
            msg.source        = source_flag;
            msg.bid           = ticks[i].bid;
            msg.ask           = ticks[i].ask;
            msg.last_price    = ticks[i].last_price;
            msg.volume        = ticks[i].volume;

            /* Busy-wait until next send slot */
            while (Clock::now() < next_send) CPU_PAUSE();
            send_tick(fd, dest, msg);
            if ((tick_id & 0x3FFu) == 0) write_stats_file(tick_id + 1);
            next_send += NS(ns_per_tick);
        }
        /* loop dataset */
    }

    close(fd);
    write_stats_file(tick_id);
    fprintf(stderr, "[replay] stopped after %u ticks\n", tick_id);
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Binance WebSocket live feed
 *  (compiled only when ENABLE_LIVE_FEED is defined)
 * ────────────────────────────────────────────────────────────────────────── */

#ifdef ENABLE_LIVE_FEED

/* Minimal JSON field extractor — avoids a full JSON library dependency. */
static bool json_get_double(const char *json, const char *key, double &val)
{
    const char *p = strstr(json, key);
    if (!p) return false;
    p += strlen(key);
    /* skip ": or :" */
    while (*p && (*p == '"' || *p == ':' || *p == ' ')) ++p;
    if (*p == '"') ++p;  /* quoted number */
    char *end;
    val = strtod(p, &end);
    return end != p;
}

static bool json_get_string(const char *json, const char *key,
                             char *buf, size_t buf_sz)
{
    const char *p = strstr(json, key);
    if (!p) return false;
    p += strlen(key);
    while (*p && (*p == '"' || *p == ':' || *p == ' ')) ++p;
    if (*p == '"') ++p;
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < buf_sz) buf[n++] = *p++;
    buf[n] = '\0';
    return n > 0;
}

struct LiveContext {
    int            fd;
    sockaddr_in    dest;
    std::atomic<uint32_t> tick_id{0};
    std::atomic<bool>    *stop;
};

/* Accumulated fragment buffer (messages can arrive in fragments) */
#define MAX_MSG_LEN (4096)

static LiveContext *g_live_ctx = nullptr;
static char        g_frag_buf[MAX_MSG_LEN];
static size_t      g_frag_len = 0;

/* Per-instrument book state — replaces the previous single static pair, which
 * collided across symbols (e.g. an ETH bookTicker overwriting BTC's bid/ask). */
static double g_last_bid[MAX_INSTRUMENTS] = {0};
static double g_last_ask[MAX_INSTRUMENTS] = {0};

static bool json_has_event(const char *json, const char *event_value)
{
    /* Matches "e":"<event_value>" — true only for streams that publish "e",
     * i.e. aggTrade. bookTicker has no "e" field. */
    const char *p = strstr(json, "\"e\":\"");
    if (!p) return false;
    p += 5;  /* past `"e":"` */
    return strncmp(p, event_value, strlen(event_value)) == 0;
}

static void process_binance_message(const char *msg, LiveContext *ctx)
{
    /* bookTicker: {"u":...,"s":"BTCUSDT","b":"42000","B":"1","a":"42001","A":"1"} */
    /* aggTrade:   {"e":"aggTrade","s":"BTCUSDT","p":"42000","q":"0.1",...} */
    /* Combined-stream envelope: {"stream":"btcusdt@aggTrade","data":{...}} */

    char symbol[16] = {};
    if (!json_get_string(msg, "\"s\"", symbol, sizeof(symbol))) return;

    TickMessage tick{};
    tick.tick_id       = ctx->tick_id.fetch_add(1, std::memory_order_relaxed);
    tick.instrument_id = symbol_to_id(symbol);
    tick.source        = TICK_SOURCE_LIVE;

    const bool is_trade = json_has_event(msg, "aggTrade");

    if (is_trade) {
        double price = 0, qty = 0;
        if (!json_get_double(msg, "\"p\"", price)) return;
        json_get_double(msg, "\"q\"", qty);
        tick.bid        = g_last_bid[tick.instrument_id];
        tick.ask        = g_last_ask[tick.instrument_id];
        tick.last_price = price;
        tick.volume     = qty;
    } else {
        /* Treat as bookTicker. */
        double bid = 0, ask = 0;
        if (!json_get_double(msg, "\"b\"", bid)) return;
        if (!json_get_double(msg, "\"a\"", ask)) return;
        g_last_bid[tick.instrument_id] = bid;
        g_last_ask[tick.instrument_id] = ask;
        tick.bid        = bid;
        tick.ask        = ask;
        tick.last_price = (bid + ask) * 0.5;
        tick.volume     = 0;
    }
    send_tick(ctx->fd, ctx->dest, tick);
}

static int lws_callback(struct lws *wsi, enum lws_callback_reasons reason,
                         void * /*user*/, void *in, size_t len)
{
    (void)wsi;
    LiveContext *ctx = g_live_ctx;

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        fprintf(stderr, "[live] WebSocket connected\n");
        g_frag_len = 0;
        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        if (g_frag_len + len < MAX_MSG_LEN) {
            memcpy(g_frag_buf + g_frag_len, in, len);
            g_frag_len += len;
        }
        if (lws_is_final_fragment(wsi)) {
            g_frag_buf[g_frag_len] = '\0';
            process_binance_message(g_frag_buf, ctx);
            g_frag_len = 0;
        }
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        fprintf(stderr, "[live] connection error: %s\n",
                in ? (char *)in : "(unknown)");
        return -1;

    case LWS_CALLBACK_CLIENT_CLOSED:
        fprintf(stderr, "[live] connection closed\n");
        return -1;

    default:
        break;
    }
    return 0;
}

static const struct lws_protocols k_protocols[] = {
    { "binance-stream", lws_callback, 0, MAX_MSG_LEN, 0, nullptr, 0 },
    { nullptr, nullptr, 0, 0, 0, nullptr, 0 }
};

static void run_live(const std::vector<std::string> &symbols,
                      std::atomic<bool> &stop)
{
    sockaddr_in dest{};
    int fd = make_mcast_send_socket(TICK_MCAST_ADDR, TICK_MCAST_PORT, dest);
    if (fd < 0) return;

    /* Build stream path: /stream?streams=btcusdt@bookTicker/btcusdt@aggTrade/... */
    std::string path = "/stream?streams=";
    for (size_t i = 0; i < symbols.size(); ++i) {
        std::string sym = symbols[i];
        for (char &c : sym) c = (char)tolower((unsigned char)c);
        if (i) path += '/';
        path += sym + "@bookTicker/" + sym + "@aggTrade";
    }

    LiveContext ctx;
    ctx.fd   = fd;
    ctx.dest = dest;
    ctx.stop = &stop;
    g_live_ctx = &ctx;

    struct lws_context_creation_info info{};
    info.protocols = k_protocols;
    info.options   = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port      = CONTEXT_PORT_NO_LISTEN;

    struct lws_context *lws_ctx = lws_create_context(&info);
    if (!lws_ctx) { fprintf(stderr, "[live] lws_create_context failed\n"); return; }

    while (!stop.load()) {
        /* Connect / reconnect loop */
        struct lws_client_connect_info ccinfo{};
        ccinfo.context       = lws_ctx;
        ccinfo.address       = "stream.binance.com";
        ccinfo.port          = 443;
        ccinfo.path          = path.c_str();
        ccinfo.host          = ccinfo.address;
        ccinfo.origin        = ccinfo.address;
        ccinfo.protocol      = k_protocols[0].name;
        ccinfo.ssl_connection = LCCSCF_USE_SSL;

        struct lws *wsi = lws_client_connect_via_info(&ccinfo);
        if (!wsi) {
            fprintf(stderr, "[live] connect failed, retrying in 3s\n");
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        /* Service loop — exits when lws returns < 0 (disconnect / error) */
        while (!stop.load()) {
            if (lws_service(lws_ctx, 50) < 0) break;
        }

        if (!stop.load()) {
            fprintf(stderr, "[live] disconnected, retrying in 3s\n");
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
    }

    lws_context_destroy(lws_ctx);
    close(fd);
    fprintf(stderr, "[live] stopped\n");
}

#else /* !ENABLE_LIVE_FEED */

static void run_live(const std::vector<std::string> &, std::atomic<bool> &)
{
    fprintf(stderr, "[live] not compiled — rebuild with libwebsockets\n");
}

#endif /* ENABLE_LIVE_FEED */

/* ────────────────────────────────────────────────────────────────────────────
 *  main
 * ────────────────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --mode <replay|live|both> [options]\n"
        "\n"
        "Replay options:\n"
        "  --csv <path>          CSV tick file (default: data/ticks.csv)\n"
        "  --rate <msg/sec>      send rate (default: 500000)\n"
        "\n"
        "Live options:\n"
        "  --symbols <SYM,...>   comma-separated symbols (default: BTCUSDT,ETHUSDT)\n"
        "\n"
        "Both mode runs replay + live simultaneously at --rate/2 each.\n"
        "\n"
        "Network options:\n"
        "  --iface <IP>          bind multicast to NIC with this IP\n"
        "                        (required for T2/T4 — sends via physical NIC)\n"
        "  --dest <IP:PORT>      override destination (default 239.0.0.1:5005).\n"
        "                        Use for live-on-host: send unicast to DPU ARM\n"
        "                        relay, e.g. --dest 192.168.100.2:6005\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *mode_str  = nullptr;
    const char *csv_path  = "data/ticks.csv";
    long        rate_hz   = 500000;
    std::string symbols_str = "BTCUSDT,ETHUSDT";

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--mode")    && i + 1 < argc) mode_str    = argv[++i];
        else if (!strcmp(argv[i], "--csv")     && i + 1 < argc) csv_path    = argv[++i];
        else if (!strcmp(argv[i], "--rate")    && i + 1 < argc) rate_hz     = atol(argv[++i]);
        else if (!strcmp(argv[i], "--symbols") && i + 1 < argc) symbols_str = argv[++i];
        else if (!strcmp(argv[i], "--iface")   && i + 1 < argc) g_mcast_iface   = argv[++i];
        else if (!strcmp(argv[i], "--dest")    && i + 1 < argc) g_dest_override = argv[++i];
        else if (!strcmp(argv[i], "--stats-file") && i + 1 < argc) g_stats_file = argv[++i];
        else if (!strcmp(argv[i], "--help"))  { usage(argv[0]); return 0; }
    }

    if (!mode_str) { usage(argv[0]); return 1; }

    std::string mode(mode_str);

    /* Parse symbol list */
    std::vector<std::string> symbols;
    {
        std::istringstream ss(symbols_str);
        std::string tok;
        while (std::getline(ss, tok, ','))
            if (!tok.empty()) symbols.push_back(tok);
    }

    std::atomic<bool> &stop = g_stop;

    /* Install SIGINT/SIGTERM handler — sets g_stop so worker loops exit promptly */
    signal(SIGINT,  [](int) { g_stop.store(true, std::memory_order_relaxed); });
    signal(SIGTERM, [](int) { g_stop.store(true, std::memory_order_relaxed); });

    if (mode == "replay") {
        fprintf(stderr, "[data_source] mode=replay rate=%ld\n", rate_hz);
        std::thread worker([&]{ run_replay(csv_path, rate_hz, TICK_SOURCE_REPLAY, stop); });
        pause();
        stop = true;
        worker.join();

    } else if (mode == "live") {
        fprintf(stderr, "[data_source] mode=live\n");
        std::thread worker([&]{ run_live(symbols, stop); });
        pause();
        stop = true;
        worker.join();

    } else if (mode == "both") {
        fprintf(stderr, "[data_source] mode=both rate=%ld (half each)\n", rate_hz);
        std::thread replay_t([&]{
            run_replay(csv_path, rate_hz / 2, TICK_SOURCE_REPLAY, stop);
        });
        std::thread live_t([&]{
            run_live(symbols, stop);
        });
        pause();
        stop = true;
        replay_t.join();
        live_t.join();

    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode_str);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
