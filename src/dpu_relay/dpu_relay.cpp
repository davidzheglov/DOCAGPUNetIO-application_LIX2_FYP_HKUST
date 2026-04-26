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
#include <cstdio>
#include <cstdlib>
#include <cstring>

static volatile bool g_running = true;

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
        "  --iface <ip>           Interface IP for multicast output (default: 10.10.10.1)\n"
        "\n"
        "Forwards UDP packets received on listen-port to multicast group.\n"
        "Run on DPU ARM to bridge host unicast -> working multicast path.\n",
        prog);
}

int main(int argc, char **argv) {
    int listen_port = 6005;
    const char *mcast_addr = "239.0.0.1";
    int mcast_port = 5005;
    const char *iface_ip = "10.10.10.1";

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--listen-port") && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--mcast-addr") && i + 1 < argc) {
            mcast_addr = argv[++i];
        } else if (!strcmp(argv[i], "--mcast-port") && i + 1 < argc) {
            mcast_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--iface") && i + 1 < argc) {
            iface_ip = argv[++i];
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

    /* ── Forward loop ─────────────────────────────────────────────────────── */
    char buf[2048];
    sockaddr_in src_addr{};
    socklen_t src_len = sizeof(src_addr);
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;

    while (g_running) {
        ssize_t n = recvfrom(listen_fd, buf, sizeof(buf), 0,
                             reinterpret_cast<sockaddr*>(&src_addr), &src_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }

        ssize_t sent = sendto(send_fd, buf, n, 0,
                              reinterpret_cast<sockaddr*>(&mcast_dest),
                              sizeof(mcast_dest));
        if (sent < 0) {
            perror("sendto");
        } else {
            pkt_count++;
            byte_count += n;
            if (pkt_count % 10000 == 0) {
                fprintf(stderr,
                        "[dpu_relay] forwarded %lu pkts (%lu MB)\r",
                        pkt_count, byte_count / (1024 * 1024));
            }
        }
    }

    fprintf(stderr,
            "\n[dpu_relay] stopped — forwarded %lu packets (%lu bytes total)\n",
            pkt_count, byte_count);

    close(listen_fd);
    close(send_fd);
    return 0;
}
