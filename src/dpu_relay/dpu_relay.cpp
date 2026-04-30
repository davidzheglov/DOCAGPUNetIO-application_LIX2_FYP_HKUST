/*
 * dpu_relay.cpp — Lightweight UDP relay for BlueField-3 DPU ARM.
 *
 * Receives UDP unicast packets on a configurable port and forwards them
 * to a UDP multicast group. Designed to bridge host-sourced live tick
 * streams (Binance WebSocket) to the working multicast path that reaches
 * host receivers (T1–T4).
 *
 * Usage on DPU ARM:
 *   ./dpu_relay --listen-port 6005 --iface 10.10.10.1
 *
 * Host data_source sends unicast to this relay:
 *   ./data_source --mode live --dest 192.168.100.2:6005
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

static volatile bool g_running = true;
static const char *g_stats_file = nullptr;

static void sigint_handler(int) {
    g_running = false;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --listen-port <port>   UDP port to listen on (default: 6005)\n"
        "  --mcast-addr <ip>      Multicast destination address (default: 239.0.0.1)\n"
        "  --mcast-port <port>    Multicast destination port (default: 5005)\n"
        "  --iface <ip>           Interface IP for multicast output (default: 10.10.10.3)\n"
        "  --stats-file <path>    Write cumulative forwarded packet count here\n"
        "  --no-restamp           Forward bytes verbatim (default: re-stamp first 8\n"
        "                         bytes with egress wall-clock ns — TickMessage T1)\n"
        "\n"
        "Forwards UDP packets received on listen-port to multicast group.\n"
        "Run on DPU ARM to bridge host unicast -> working multicast path.\n",
        prog);
}

static void write_stats_file(uint64_t pkt_count) {
    if (!g_stats_file) return;
    FILE *f = fopen(g_stats_file, "w");
    if (!f) return;
    fprintf(f, "%lu\n", pkt_count);
    fclose(f);
}

int main(int argc, char **argv) {
    int listen_port = 6005;
    const char *mcast_addr = "239.0.0.1";
    int mcast_port = 5005;
    /* lxcpu2 DPU ARM p0 address per project topology. Override with --iface. */
    const char *iface_ip = "10.10.10.3";
    bool restamp_t1 = true;  /* Overwrite first 8 bytes (TickMessage.timestamp_ns) at egress */

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--listen-port") && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--mcast-addr") && i + 1 < argc) {
            mcast_addr = argv[++i];
        } else if (!strcmp(argv[i], "--mcast-port") && i + 1 < argc) {
            mcast_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--iface") && i + 1 < argc) {
            iface_ip = argv[++i];
        } else if (!strcmp(argv[i], "--stats-file") && i + 1 < argc) {
            g_stats_file = argv[++i];
        } else if (!strcmp(argv[i], "--no-restamp")) {
            restamp_t1 = false;
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* ── Listening socket (unicast from host) ─────────────────────────────── */
    int listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* Larger RX buffer — Binance bursts during volatile periods can exceed
     * the default ~256KB and silently drop on the kernel side. */
    int rcvbuf = 4 * 1024 * 1024;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("SO_RCVBUF");
    }

    sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(listen_port);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&listen_addr),
             sizeof(listen_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    fprintf(stderr, "[dpu_relay] listening on UDP port %d\n", listen_port);

    /* ── Multicast send socket ────────────────────────────────────────────── */
    int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_fd < 0) {
        perror("socket");
        close(listen_fd);
        return 1;
    }

    int ttl = 1;
    setsockopt(send_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    struct in_addr iface_addr{};
    iface_addr.s_addr = inet_addr(iface_ip);
    if (setsockopt(send_fd, IPPROTO_IP, IP_MULTICAST_IF,
                   &iface_addr, sizeof(iface_addr)) < 0) {
        perror("IP_MULTICAST_IF");
        fprintf(stderr, "[dpu_relay] warning: failed to bind multicast to %s\n",
                iface_ip);
    } else {
        fprintf(stderr, "[dpu_relay] multicast output bound to %s\n", iface_ip);
    }

    sockaddr_in mcast_dest{};
    memset(&mcast_dest, 0, sizeof(mcast_dest));
    mcast_dest.sin_family = AF_INET;
    mcast_dest.sin_port = htons(mcast_port);
    mcast_dest.sin_addr.s_addr = inet_addr(mcast_addr);

    fprintf(stderr, "[dpu_relay] forwarding to %s:%d  (Ctrl+C to stop)\n",
            mcast_addr, mcast_port);

    /* ── Forward loop (batched: recvmmsg + sendmmsg) ─────────────────────────
     * The previous one-syscall-per-packet loop maxed the ARM core at ~600 k
     * syscalls/sec, throttling all four downstream receivers to that ceiling.
     * Batching 64 packets per syscall pushes the effective ceiling above
     * what 1 MHz benchmark rates need, so T4's actual throughput advantage
     * can finally be observed. */
    constexpr int    BATCH        = 64;
    constexpr size_t PKT_BUF_SIZE = 2048;

    /* Per-batch buffers: one mmsghdr/iovec/datagram-buffer triple per slot. */
    static char         buffers[BATCH][PKT_BUF_SIZE];
    static struct iovec iovs_rx[BATCH];
    static struct iovec iovs_tx[BATCH];
    static struct mmsghdr msgs_rx[BATCH];
    static struct mmsghdr msgs_tx[BATCH];

    for (int i = 0; i < BATCH; ++i) {
        iovs_rx[i].iov_base = buffers[i];
        iovs_rx[i].iov_len  = PKT_BUF_SIZE;
        memset(&msgs_rx[i], 0, sizeof(msgs_rx[i]));
        msgs_rx[i].msg_hdr.msg_iov    = &iovs_rx[i];
        msgs_rx[i].msg_hdr.msg_iovlen = 1;
        /* No msg_name on RX — we don't need the source address. */
    }

    /* Bounded-wait recvmmsg: returns up to BATCH packets or after the timeout.
     * Keeps the loop responsive at low rates so partial batches still flush. */
    struct timespec rx_timeout = { 0, 1000000 };  /* 1 ms */

    uint64_t pkt_count   = 0;
    uint64_t byte_count  = 0;
    uint64_t batch_count = 0;
    uint64_t last_stats_pkt_count = 0;
    write_stats_file(0);

    while (g_running) {
        int n_recv = recvmmsg(listen_fd, msgs_rx, BATCH, MSG_WAITFORONE, &rx_timeout);
        if (n_recv < 0) {
            if (errno == EINTR) continue;
            perror("recvmmsg");
            break;
        }
        if (n_recv == 0) continue;   /* timeout */

        /* Re-stamp T1 in every datagram at egress — single timespec read
         * for the whole batch is fine; the within-batch ordering is sub-µs. */
        if (restamp_t1) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL
                            + (uint64_t)ts.tv_nsec;
            for (int i = 0; i < n_recv; ++i) {
                if (msgs_rx[i].msg_len >= sizeof(uint64_t)) {
                    memcpy(buffers[i], &now_ns, sizeof(now_ns));
                }
            }
        }

        /* Build TX descriptors that fan out to the multicast destination.
         * We can't reuse the RX iovecs directly because their iov_len is
         * the buffer capacity, not the received payload size. */
        for (int i = 0; i < n_recv; ++i) {
            iovs_tx[i].iov_base = buffers[i];
            iovs_tx[i].iov_len  = msgs_rx[i].msg_len;
            memset(&msgs_tx[i], 0, sizeof(msgs_tx[i]));
            msgs_tx[i].msg_hdr.msg_name    = &mcast_dest;
            msgs_tx[i].msg_hdr.msg_namelen = sizeof(mcast_dest);
            msgs_tx[i].msg_hdr.msg_iov     = &iovs_tx[i];
            msgs_tx[i].msg_hdr.msg_iovlen  = 1;
        }

        int sent_total = 0;
        while (sent_total < n_recv) {
            int sent = sendmmsg(send_fd, msgs_tx + sent_total,
                                n_recv - sent_total, 0);
            if (sent < 0) {
                if (errno == EINTR) continue;
                perror("sendmmsg");
                break;
            }
            sent_total += sent;
        }

        for (int i = 0; i < sent_total; ++i) byte_count += msgs_rx[i].msg_len;
        pkt_count   += sent_total;
        batch_count += 1;
        if (pkt_count - last_stats_pkt_count >= 4096) {
            write_stats_file(pkt_count);
            last_stats_pkt_count = pkt_count;
        }

        /* Lighter logging — once per ~10000 packets, batched, no \r flicker. */
        if (pkt_count % 100000 == 0) {
            fprintf(stderr,
                    "[dpu_relay] %lu pkts in %lu batches (%lu MB)\n",
                    pkt_count, batch_count, byte_count / (1024 * 1024));
        }
    }

    fprintf(stderr,
            "\n[dpu_relay] stopped — forwarded %lu packets (%lu bytes total)\n",
            pkt_count, byte_count);
    write_stats_file(pkt_count);

    close(listen_fd);
    close(send_fd);
    return 0;
}
