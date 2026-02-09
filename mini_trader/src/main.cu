#include <iostream>
#include <vector>
#include <algorithm>
#include <cuda_runtime.h>

#include "types.h"
#include "cuda_utils.h"
#include "market_sim.h"
#include "kernels.h"

int main(int argc, char** argv) {
  // args: total_events thr qty batch_size
  int total_n   = (argc > 1) ? std::atoi(argv[1]) : 5'000'000;
  float thr     = (argc > 2) ? std::atof(argv[2]) : 0.0008f;
  float qty     = (argc > 3) ? std::atof(argv[3]) : 1.0f;
  int batch_n   = (argc > 4) ? std::atoi(argv[4]) : 1'000'000;

  if (batch_n <= 0) batch_n = total_n;
  std::cout << "total_n=" << total_n << " thr=" << thr
            << " qty=" << qty << " batch_n=" << batch_n << "\n";

  // ---- Parameters for the simulator
  const float start_price = 100.0f;
  const uint64_t dt_ns = 1000;       // 1us
  const float sigma = 0.0005f;

  // ---- Streams (2 for ping-pong)
  cudaStream_t stream[2];
  CUDA_CHECK(cudaStreamCreate(&stream[0]));
  CUDA_CHECK(cudaStreamCreate(&stream[1]));

  // ---- Pinned host buffers (2 batches)
  Event* h_ev[2] = {nullptr, nullptr};
  int*   h_count[2] = {nullptr, nullptr};

  CUDA_CHECK(cudaMallocHost(&h_ev[0], sizeof(Event) * (size_t)batch_n));
  CUDA_CHECK(cudaMallocHost(&h_ev[1], sizeof(Event) * (size_t)batch_n));
  CUDA_CHECK(cudaMallocHost(&h_count[0], sizeof(int)));
  CUDA_CHECK(cudaMallocHost(&h_count[1], sizeof(int)));

  // ---- Device buffers (2 batches)
  Event* d_ev[2] = {nullptr, nullptr};
  Order* d_orders[2] = {nullptr, nullptr};
  int*   d_count[2] = {nullptr, nullptr};

  for (int b = 0; b < 2; ++b) {
    CUDA_CHECK(cudaMalloc(&d_ev[b], sizeof(Event) * (size_t)batch_n));
    CUDA_CHECK(cudaMalloc(&d_orders[b], sizeof(Order) * (size_t)batch_n));
    CUDA_CHECK(cudaMalloc(&d_count[b], sizeof(int)));
  }

  // ---- Timing
  cudaEvent_t t0, t1;
  CUDA_CHECK(cudaEventCreate(&t0));
  CUDA_CHECK(cudaEventCreate(&t1));
  CUDA_CHECK(cudaEventRecord(t0));

  int64_t total_orders = 0;
  int processed = 0;
  int buf = 0;

  while (processed < total_n) {
    int n = std::min(batch_n, total_n - processed);

    // 1) CPU generates into pinned host buffer
    uint64_t batch_start_t = (uint64_t)processed * dt_ns;
    generate_market_data(h_ev[buf], n, start_price, batch_start_t, dt_ns, sigma,
                         /*seed=*/12345u + (uint32_t)processed);

    // 2) async H->D copy + memset count
    CUDA_CHECK(cudaMemsetAsync(d_count[buf], 0, sizeof(int), stream[buf]));
    CUDA_CHECK(cudaMemcpyAsync(d_ev[buf], h_ev[buf],
                               sizeof(Event) * (size_t)n,
                               cudaMemcpyHostToDevice,
                               stream[buf]));

    // 3) kernel launch (same stream => ordered after copy)
    int threads = 256;
    int blocks = (n + threads - 1) / threads;
    decide_orders<<<blocks, threads, 0, stream[buf]>>>(
      d_ev[buf], n, thr, qty, d_orders[buf], d_count[buf]
    );
    CUDA_CHECK(cudaGetLastError());

    // 4) copy back just the count (cheap). (Optional: copy back small order sample)
    CUDA_CHECK(cudaMemcpyAsync(h_count[buf], d_count[buf],
                               sizeof(int),
                               cudaMemcpyDeviceToHost,
                               stream[buf]));

    // 5) If we’ve already launched previous buffer, wait for it and accumulate
    int prev = 1 - buf;
    if (processed != 0) {
      CUDA_CHECK(cudaStreamSynchronize(stream[prev]));
      total_orders += *h_count[prev];
    }

    processed += n;
    buf = 1 - buf;
  }

  // synchronize last in-flight
  CUDA_CHECK(cudaStreamSynchronize(stream[1 - buf]));
  total_orders += *h_count[1 - buf];

  CUDA_CHECK(cudaEventRecord(t1));
  CUDA_CHECK(cudaEventSynchronize(t1));
  float ms = 0.0f;
  CUDA_CHECK(cudaEventElapsedTime(&ms, t0, t1));

  std::cout << "Total orders fired: " << total_orders << "\n";
  std::cout << "Total time: " << ms << " ms\n";
  std::cout << "End-to-end throughput: " << (double)total_n / (ms * 1e6) << " GEvents/s\n";

  // cleanup
  for (int b = 0; b < 2; ++b) {
    CUDA_CHECK(cudaFree(d_ev[b]));
    CUDA_CHECK(cudaFree(d_orders[b]));
    CUDA_CHECK(cudaFree(d_count[b]));
  }
  CUDA_CHECK(cudaFreeHost(h_ev[0]));
  CUDA_CHECK(cudaFreeHost(h_ev[1]));
  CUDA_CHECK(cudaFreeHost(h_count[0]));
  CUDA_CHECK(cudaFreeHost(h_count[1]));
  CUDA_CHECK(cudaStreamDestroy(stream[0]));
  CUDA_CHECK(cudaStreamDestroy(stream[1]));
  CUDA_CHECK(cudaEventDestroy(t0));
  CUDA_CHECK(cudaEventDestroy(t1));

  return 0;
}