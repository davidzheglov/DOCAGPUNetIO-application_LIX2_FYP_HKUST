/*
 * doca_flow_test.cu — Minimal DOCA Flow + GPUNetIO RX test.
 *
 * Tests whether DOCA Flow can steer packets into a GPU-backed RX queue.
 * Follows the NVIDIA reference pattern:
 *   - Root CONTROL pipe (matches IPv4/UDP, forwards to non-root pipe)
 *   - Non-root BASIC pipe (RSS to GPU RX queue)
 *   - "vnf,hws,isolated" mode
 *
 * Usage:
 *   sudo ./doca_flow_test --nic-pcie 0000:bd:00.1 --gpu-pcie 0000:ac:00.0 --gpu 1
 */

#include <doca_gpunetio.h>
#include <doca_gpunetio_dev_eth_rxq.cuh>
#include <doca_eth_rxq.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_mmap.h>
#include <doca_ctx.h>
#include <doca_flow.h>

#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>

#include <cuda_runtime.h>
#include <arpa/inet.h>

/* ── Config ─────────────────────────────────────────────────────────────── */
#define MAX_PKT_NUM  2048
#define MAX_PKT_SIZE 2048
#define QUEUE_ID     0
#define FLOW_NB_COUNTERS 1024

/* ── Macros ─────────────────────────────────────────────────────────────── */
#define CHECK_DOCA(call, step)                                            \
    do {                                                                  \
        doca_error_t _e = (call);                                         \
        fprintf(stderr, "  [%s] %s -> %s (%d)\n",                        \
                (_e == DOCA_SUCCESS) ? "OK" : "FAIL",                     \
                (step), doca_error_get_descr(_e), (int)_e);              \
        if (_e != DOCA_SUCCESS) { return -1; }                            \
    } while (0)

#define CHECK_CUDA(call)                                                  \
    do {                                                                  \
        cudaError_t _e = (call);                                          \
        if (_e != cudaSuccess) {                                          \
            fprintf(stderr, "  [FAIL] CUDA: %s\n",                       \
                    cudaGetErrorString(_e));                               \
            return -1;                                                    \
        }                                                                 \
    } while (0)

/* ── GPU kernel: poll RX queue and report ───────────────────────────────── */
__global__ void poll_rx_kernel(struct doca_gpu_eth_rxq *rxq_gpu,
                               uint32_t *pkt_count,
                               uint32_t *quit_flag)
{
    uint64_t polls = 0;

    while (*quit_flag == 0) {
        uint64_t first_pkt_idx = 0;
        uint32_t rx_pkt_num = 0;

        /* Use the _thread variant directly for single-thread kernel */
        doca_gpu_dev_eth_rxq_recv_thread(rxq_gpu,
                                         MAX_PKT_NUM,  /* max_rx_pkts */
                                         0,            /* timeout_ns (0 = no wait) */
                                         &first_pkt_idx,
                                         &rx_pkt_num,
                                         nullptr);     /* out_attr */

        polls++;

        if (rx_pkt_num > 0) {
            uint32_t old = atomicAdd(pkt_count, rx_pkt_num);
            if (old == 0) {
                printf("[GPU] *** FIRST PACKETS! rx_pkt_num=%u, first_idx=%llu ***\n",
                       rx_pkt_num, (unsigned long long)first_pkt_idx);
            }
        }

        /* Periodic heartbeat every ~100k polls */
        if (polls % 100000 == 0) {
            printf("[GPU] heartbeat: %llu polls, %u total pkts received\n",
                   (unsigned long long)polls, *pkt_count);
        }
    }

    printf("[GPU] kernel exiting: %llu polls, %u total pkts\n",
           (unsigned long long)polls, *pkt_count);
}

/* ── Helpers ────────────────────────────────────────────────────────────── */
static volatile int g_quit = 0;
static void sig_handler(int) { g_quit = 1; }

static size_t get_page_size(void)
{
    long ret = sysconf(_SC_PAGESIZE);
    return (ret > 0) ? (size_t)ret : 4096;
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    const char *nic_pcie = "";
    const char *gpu_pcie = "";
    int cuda_device = 1;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--nic-pcie") && i+1 < argc) nic_pcie = argv[++i];
        else if (!strcmp(argv[i], "--gpu-pcie") && i+1 < argc) gpu_pcie = argv[++i];
        else if (!strcmp(argv[i], "--gpu") && i+1 < argc) cuda_device = atoi(argv[++i]);
    }

    if (!nic_pcie[0] || !gpu_pcie[0]) {
        fprintf(stderr, "Usage: %s --nic-pcie <addr> --gpu-pcie <addr> [--gpu <id>]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    fprintf(stderr, "=============================================================\n");
    fprintf(stderr, "  DOCA Flow + GPUNetIO RX Test\n");
    fprintf(stderr, "  NIC: %-20s  GPU: %-20s\n", nic_pcie, gpu_pcie);
    fprintf(stderr, "=============================================================\n\n");

    doca_error_t err;

    /* ── Step 0: CUDA init ──────────────────────────────────────────────── */
    fprintf(stderr, "STEP 0: CUDA init (device %d)\n", cuda_device);
    {
        cudaError_t ce = cudaSetDevice(cuda_device);
        fprintf(stderr, "  [%s] cudaSetDevice(%d) -> %s\n",
                ce == cudaSuccess ? "OK" : "FAIL", cuda_device, cudaGetErrorString(ce));
        if (ce != cudaSuccess) return 1;

        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, cuda_device);
        fprintf(stderr, "  GPU name: %s  (SM %d.%d)\n", prop.name, prop.major, prop.minor);
    }

    /* ── Step 1: Open DOCA NIC device ───────────────────────────────────── */
    fprintf(stderr, "\nSTEP 1: Open DOCA device (%s)\n", nic_pcie);
    struct doca_dev *dev = nullptr;
    {
        struct doca_devinfo **dev_list;
        uint32_t nb_devs;
        CHECK_DOCA(doca_devinfo_create_list(&dev_list, &nb_devs), "devinfo_create_list");
        fprintf(stderr, "  Found %u DOCA devices\n", nb_devs);

        bool found = false;
        for (uint32_t i = 0; i < nb_devs; ++i) {
            uint8_t is_equal = 0;
            doca_devinfo_is_equal_pci_addr(dev_list[i], nic_pcie, &is_equal);
            if (is_equal) {
                CHECK_DOCA(doca_dev_open(dev_list[i], &dev), "doca_dev_open");
                found = true;
                break;
            }
        }
        doca_devinfo_destroy_list(dev_list);
        if (!found) { fprintf(stderr, "  [FAIL] NIC device not found\n"); return 1; }
    }

    /* ── Step 2: Create GPU context ─────────────────────────────────────── */
    fprintf(stderr, "\nSTEP 2: Create GPU context (%s)\n", gpu_pcie);
    struct doca_gpu *gpu_dev = nullptr;
    CHECK_DOCA(doca_gpu_create(gpu_pcie, &gpu_dev), "doca_gpu_create");

    /* ── Step 3: DOCA Flow init (skip with SKIP_FLOW=1 to isolate ctx_start) */
    fprintf(stderr, "\nSTEP 3: DOCA Flow init\n");
    struct doca_flow_port *flow_port = nullptr;
    bool skip_flow = (getenv("SKIP_FLOW") != nullptr);
    if (skip_flow) {
        fprintf(stderr, "  SKIP_FLOW=1 — skipping flow init to test ctx_start alone\n");
    } else {
        struct doca_flow_cfg *flow_cfg = nullptr;
        CHECK_DOCA(doca_flow_cfg_create(&flow_cfg), "flow_cfg_create");
        CHECK_DOCA(doca_flow_cfg_set_pipe_queues(flow_cfg, 1), "set_pipe_queues(1)");
        const char *mode = getenv("DOCA_ISOLATED") ? "vnf,hws,isolated" : "vnf,hws";
        fprintf(stderr, "  Using mode: %s\n", mode);
        CHECK_DOCA(doca_flow_cfg_set_mode_args(flow_cfg, mode), "set_mode_args");
        CHECK_DOCA(doca_flow_cfg_set_nr_counters(flow_cfg, FLOW_NB_COUNTERS), "set_nr_counters");
        CHECK_DOCA(doca_flow_init(flow_cfg), "doca_flow_init");
        doca_flow_cfg_destroy(flow_cfg);

        struct doca_flow_port_cfg *port_cfg = nullptr;
        CHECK_DOCA(doca_flow_port_cfg_create(&port_cfg), "port_cfg_create");
        CHECK_DOCA(doca_flow_port_cfg_set_port_id(port_cfg, 0), "set_port_id(0)");
        CHECK_DOCA(doca_flow_port_cfg_set_dev(port_cfg, dev), "set_dev");
        CHECK_DOCA(doca_flow_port_start(port_cfg, &flow_port), "flow_port_start");
        doca_flow_port_cfg_destroy(port_cfg);
    }

    /* ── Step 4: Create ETH RX queue (GPU-backed, CYCLIC) ───────────────── */
    fprintf(stderr, "\nSTEP 4: Create ETH RX queue\n");
    struct doca_eth_rxq *rxq_cpu = nullptr;
    CHECK_DOCA(doca_eth_rxq_create(dev, MAX_PKT_NUM, MAX_PKT_SIZE, &rxq_cpu), "eth_rxq_create");
    CHECK_DOCA(doca_eth_rxq_set_type(rxq_cpu, DOCA_ETH_RXQ_TYPE_CYCLIC), "set_type(CYCLIC)");

    uint32_t buf_size = 0;
    CHECK_DOCA(doca_eth_rxq_estimate_packet_buf_size(
        DOCA_ETH_RXQ_TYPE_CYCLIC, 0, 0, MAX_PKT_SIZE, MAX_PKT_NUM,
        0, 0, 0, &buf_size), "estimate_buf_size");
    fprintf(stderr, "  Estimated buffer size: %u bytes\n", buf_size);

    size_t page_sz = get_page_size();
    buf_size = ((buf_size + page_sz - 1) / page_sz) * page_sz;

    /* ── Step 5: Allocate GPU memory for packet buffer ──────────────────── */
    fprintf(stderr, "\nSTEP 5: Allocate GPU packet buffer (%u bytes)\n", buf_size);
    void *gpu_pkt_buf = nullptr;
    CHECK_DOCA(doca_gpu_mem_alloc(gpu_dev, buf_size, page_sz,
        DOCA_GPU_MEM_TYPE_GPU, &gpu_pkt_buf, NULL), "gpu_mem_alloc");
    fprintf(stderr, "  GPU buffer at: %p\n", gpu_pkt_buf);

    /* ── Step 6: Create MMAP ────────────────────────────────────────────── */
    fprintf(stderr, "\nSTEP 6: Create MMAP\n");
    struct doca_mmap *pkt_mmap = nullptr;
    CHECK_DOCA(doca_mmap_create(&pkt_mmap), "mmap_create");
    CHECK_DOCA(doca_mmap_add_dev(pkt_mmap, dev), "mmap_add_dev");

    int dmabuf_fd = -1;
    doca_error_t dm_ret = doca_gpu_dmabuf_fd(gpu_dev, gpu_pkt_buf, buf_size, &dmabuf_fd);
    if (dm_ret == DOCA_SUCCESS) {
        fprintf(stderr, "  Using dmabuf (fd=%d)\n", dmabuf_fd);
        CHECK_DOCA(doca_mmap_set_dmabuf_memrange(pkt_mmap, dmabuf_fd, gpu_pkt_buf, 0, buf_size),
                   "set_dmabuf_memrange");
    } else {
        fprintf(stderr, "  dmabuf unavailable (%s), using peermem\n", doca_error_get_descr(dm_ret));
        CHECK_DOCA(doca_mmap_set_memrange(pkt_mmap, gpu_pkt_buf, buf_size), "set_memrange");
    }
    CHECK_DOCA(doca_mmap_set_permissions(pkt_mmap,
        DOCA_ACCESS_FLAG_LOCAL_READ_WRITE | DOCA_ACCESS_FLAG_PCI_RELAXED_ORDERING),
        "set_permissions");
    CHECK_DOCA(doca_mmap_start(pkt_mmap), "mmap_start");

    /* ── Step 7: Bind buffer to RX queue ────────────────────────────────── */
    fprintf(stderr, "\nSTEP 7: Bind buffer to RX queue\n");
    CHECK_DOCA(doca_eth_rxq_set_pkt_buf(rxq_cpu, pkt_mmap, 0, buf_size), "set_pkt_buf");

    /* ── Step 8: Set datapath on GPU and start context ──────────────────── */
    fprintf(stderr, "\nSTEP 8: Start RXQ context on GPU\n");
    struct doca_ctx *rxq_ctx = doca_eth_rxq_as_doca_ctx(rxq_cpu);
    fprintf(stderr, "  [%s] as_doca_ctx -> %p\n", rxq_ctx ? "OK" : "FAIL", (void*)rxq_ctx);
    if (!rxq_ctx) return 1;

    CHECK_DOCA(doca_ctx_set_datapath_on_gpu(rxq_ctx, gpu_dev), "set_datapath_on_gpu");
    CHECK_DOCA(doca_ctx_start(rxq_ctx), "ctx_start");

    struct doca_gpu_eth_rxq *rxq_gpu = nullptr;
    CHECK_DOCA(doca_eth_rxq_get_gpu_handle(rxq_cpu, &rxq_gpu), "get_gpu_handle");

    /* ── Step 9: Assign queue ID for flow steering ──────────────────────── */
    fprintf(stderr, "\nSTEP 9: Apply queue ID\n");
    CHECK_DOCA(doca_eth_rxq_apply_queue_id(rxq_cpu, QUEUE_ID), "apply_queue_id(0)");

    /* ── Step 10: Create flow pipes (NVIDIA reference pattern) ──────────── */
    fprintf(stderr, "\nSTEP 10: Create DOCA Flow pipes\n");

    /* 10a: Non-root BASIC pipe (RSS to GPU RX queue) */
    fprintf(stderr, "  10a: Non-root BASIC pipe (UDP RSS -> queue %d)\n", QUEUE_ID);
    struct doca_flow_pipe *udp_pipe = nullptr;
    struct doca_flow_pipe_entry *udp_counter_entry = nullptr;
    {
        struct doca_flow_match match = {};
        match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
        match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;

        struct doca_flow_monitor monitor = {};
        monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        uint16_t rss_queues[1] = { QUEUE_ID };
        struct doca_flow_fwd fwd = {};
        fwd.type = DOCA_FLOW_FWD_RSS;
        fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
        fwd.rss.queues_array = rss_queues;
        fwd.rss.outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP;
        fwd.rss.nr_queues = 1;

        struct doca_flow_fwd miss_fwd = {};
        miss_fwd.type = DOCA_FLOW_FWD_DROP;

        struct doca_flow_pipe_cfg *pipe_cfg = nullptr;
        CHECK_DOCA(doca_flow_pipe_cfg_create(&pipe_cfg, flow_port), "udp_pipe_cfg_create");
        doca_flow_pipe_cfg_set_name(pipe_cfg, "UDP_RSS_PIPE");
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        CHECK_DOCA(doca_flow_pipe_cfg_set_is_root(pipe_cfg, false), "udp_set_is_root(false)");
        CHECK_DOCA(doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL), "udp_set_match");
        CHECK_DOCA(doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor), "udp_set_monitor");

        err = doca_flow_pipe_create(pipe_cfg, &fwd, &miss_fwd, &udp_pipe);
        fprintf(stderr, "  [%s] udp_pipe_create -> %s (%d)\n",
                err == DOCA_SUCCESS ? "OK" : "FAIL", doca_error_get_descr(err), (int)err);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) return 1;

        /* Add entry to the non-root pipe */
        err = doca_flow_pipe_basic_add_entry(0, udp_pipe, &match, 0, NULL, NULL, NULL,
                                              DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, NULL,
                                              &udp_counter_entry);
        fprintf(stderr, "  [%s] udp_pipe_basic_add_entry -> %s (%d)\n",
                err == DOCA_SUCCESS ? "OK" : "FAIL", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return 1;

        CHECK_DOCA(doca_flow_entries_process(flow_port, 0, 10000, 0), "udp_entries_process");
    }

    /* 10b: Root CONTROL pipe (matches IPv4/UDP -> forwards to UDP pipe) */
    fprintf(stderr, "  10b: Root CONTROL pipe\n");
    struct doca_flow_pipe *root_pipe = nullptr;
    struct doca_flow_pipe_entry *root_udp_entry = nullptr;
    struct doca_flow_pipe_entry *root_all_entry = nullptr;
    {
        struct doca_flow_monitor monitor = {};
        monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

        struct doca_flow_pipe_cfg *pipe_cfg = nullptr;
        CHECK_DOCA(doca_flow_pipe_cfg_create(&pipe_cfg, flow_port), "root_pipe_cfg_create");
        doca_flow_pipe_cfg_set_name(pipe_cfg, "ROOT_CONTROL_PIPE");
        CHECK_DOCA(doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL), "root_set_type(CONTROL)");
        CHECK_DOCA(doca_flow_pipe_cfg_set_is_root(pipe_cfg, true), "root_set_is_root(true)");
        CHECK_DOCA(doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor), "root_set_monitor");

        err = doca_flow_pipe_create(pipe_cfg, NULL, NULL, &root_pipe);
        fprintf(stderr, "  [%s] root_pipe_create -> %s (%d)\n",
                err == DOCA_SUCCESS ? "OK" : "FAIL", doca_error_get_descr(err), (int)err);
        doca_flow_pipe_cfg_destroy(pipe_cfg);
        if (err != DOCA_SUCCESS) return 1;

        /* Add UDP match entry: IPv4 + UDP -> forward to udp_pipe */
        struct doca_flow_match udp_match = {};
        udp_match.outer.eth.type = htons(DOCA_FLOW_ETHER_TYPE_IPV4);
        udp_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        udp_match.outer.ip4.next_proto = IPPROTO_UDP;

        struct doca_flow_fwd udp_fwd = {};
        udp_fwd.type = DOCA_FLOW_FWD_PIPE;
        udp_fwd.next_pipe = udp_pipe;

        /* doca_flow_pipe_control_add_entry signature:
         * (pipe_queue, pipe, match, match_mask, condition, actions, actions_mask,
         *  action_descs, monitor, priority, fwd, usr_ctx, entry) */
        err = doca_flow_pipe_control_add_entry(0, root_pipe,
                                                &udp_match,     /* match */
                                                NULL,           /* match_mask */
                                                NULL,           /* condition */
                                                NULL,           /* actions */
                                                NULL,           /* actions_mask */
                                                NULL,           /* action_descs */
                                                NULL,           /* monitor */
                                                1,              /* priority (high) */
                                                &udp_fwd,       /* fwd */
                                                NULL,           /* usr_ctx */
                                                &root_udp_entry);
        fprintf(stderr, "  [%s] root_control_add_entry(UDP, prio=1) -> %s (%d)\n",
                err == DOCA_SUCCESS ? "OK" : "FAIL", doca_error_get_descr(err), (int)err);
        if (err != DOCA_SUCCESS) return 1;

        /* Also add a catch-all entry at lower priority to debug */
        struct doca_flow_match all_match = {};
        struct doca_flow_fwd all_fwd = {};
        all_fwd.type = DOCA_FLOW_FWD_PIPE;
        all_fwd.next_pipe = udp_pipe;

        err = doca_flow_pipe_control_add_entry(0, root_pipe,
                                                &all_match,
                                                NULL, NULL, NULL, NULL, NULL, NULL,
                                                10,             /* priority (low) */
                                                &all_fwd,
                                                NULL,
                                                &root_all_entry);
        fprintf(stderr, "  [%s] root_control_add_entry(CATCH-ALL, prio=10) -> %s (%d)\n",
                err == DOCA_SUCCESS ? "OK" : "FAIL", doca_error_get_descr(err), (int)err);
        /* Non-fatal if this fails */

        CHECK_DOCA(doca_flow_entries_process(flow_port, 0, 10000, 0), "root_entries_process");
    }

    fprintf(stderr, "\n=============================================================\n");
    fprintf(stderr, "  All DOCA init complete! Launching GPU poll kernel...\n");
    fprintf(stderr, "  Send UDP packets to this NIC to test.\n");
    fprintf(stderr, "  Press Ctrl+C to stop.\n");
    fprintf(stderr, "=============================================================\n\n");

    /* ── Launch GPU kernel ──────────────────────────────────────────────── */
    uint32_t *d_pkt_count = nullptr;
    uint32_t *d_quit = nullptr;
    cudaMallocHost(&d_pkt_count, sizeof(uint32_t));
    cudaHostAlloc(&d_quit, sizeof(uint32_t), cudaHostAllocMapped | cudaHostAllocWriteCombined);
    *d_pkt_count = 0;
    *d_quit = 0;

    poll_rx_kernel<<<1, 1>>>(rxq_gpu, d_pkt_count, d_quit);
    cudaError_t launch_err = cudaGetLastError();
    fprintf(stderr, "[%s] GPU kernel launched: %s\n",
            launch_err == cudaSuccess ? "OK" : "FAIL", cudaGetErrorString(launch_err));
    if (launch_err != cudaSuccess) return 1;

    /* ── Main loop: query flow counters and report ──────────────────────── */
    auto start = std::chrono::steady_clock::now();
    uint64_t last_root_pkts = 0, last_udp_pkts = 0;

    while (!g_quit) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        if (g_quit) break;

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();

        /* Query root pipe UDP entry counter */
        struct doca_flow_resource_query root_stats = {};
        doca_error_t rq = doca_flow_resource_query_entry(root_udp_entry, &root_stats);

        /* Query UDP pipe entry counter */
        struct doca_flow_resource_query udp_stats = {};
        doca_error_t uq = doca_flow_resource_query_entry(udp_counter_entry, &udp_stats);

        /* Query catch-all entry counter */
        struct doca_flow_resource_query all_stats = {};
        doca_error_t aq = DOCA_ERROR_UNKNOWN;
        if (root_all_entry)
            aq = doca_flow_resource_query_entry(root_all_entry, &all_stats);

        /* Process pending entries */
        doca_flow_entries_process(flow_port, 0, 0, 0);

        fprintf(stderr, "[%llds] ROOT_UDP: %s pkts=%lu bytes=%lu | "
                        "UDP_PIPE: %s pkts=%lu bytes=%lu | "
                        "CATCH_ALL: %s pkts=%lu | "
                        "GPU: %u pkts\n",
                (long long)elapsed,
                rq == DOCA_SUCCESS ? "ok" : "err",
                (unsigned long)root_stats.counter.total_pkts,
                (unsigned long)root_stats.counter.total_bytes,
                uq == DOCA_SUCCESS ? "ok" : "err",
                (unsigned long)udp_stats.counter.total_pkts,
                (unsigned long)udp_stats.counter.total_bytes,
                aq == DOCA_SUCCESS ? "ok" : "err",
                (unsigned long)all_stats.counter.total_pkts,
                *d_pkt_count);

        /* Highlight if counters changed */
        if (root_stats.counter.total_pkts != last_root_pkts ||
            udp_stats.counter.total_pkts != last_udp_pkts) {
            fprintf(stderr, "  ^^^ COUNTER CHANGE! root_udp +%lu, udp_pipe +%lu\n",
                    (unsigned long)(root_stats.counter.total_pkts - last_root_pkts),
                    (unsigned long)(udp_stats.counter.total_pkts - last_udp_pkts));
            last_root_pkts = root_stats.counter.total_pkts;
            last_udp_pkts = udp_stats.counter.total_pkts;
        }
    }

    /* ── Cleanup ────────────────────────────────────────────────────────── */
    fprintf(stderr, "\n[test] stopping GPU kernel...\n");
    *d_quit = 1;
    cudaDeviceSynchronize();
    fprintf(stderr, "[test] final packet count: %u\n", *d_pkt_count);

    fprintf(stderr, "[test] cleaning up...\n");
    doca_flow_port_stop(flow_port);
    doca_flow_destroy();
    doca_ctx_stop(rxq_ctx);
    doca_eth_rxq_destroy(rxq_cpu);
    doca_mmap_stop(pkt_mmap);
    doca_mmap_destroy(pkt_mmap);
    doca_gpu_mem_free(gpu_dev, gpu_pkt_buf);
    doca_gpu_destroy(gpu_dev);
    doca_dev_close(dev);
    cudaFreeHost(d_pkt_count);
    cudaFreeHost(d_quit);

    fprintf(stderr, "[test] done.\n");
    return 0;
}
