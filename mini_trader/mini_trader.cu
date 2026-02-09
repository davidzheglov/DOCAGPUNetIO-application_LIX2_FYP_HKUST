#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <random>
#include <iostream>

#define CUDA_CHECK(call) do {                                         \
  cudaError_t err = (call);                                           \
  if (err != cudaSuccess) {                                           \
    std::fprintf(stderr, "CUDA error %s:%d: %s\n",                    \
                 __FILE__, __LINE__, cudaGetErrorString(err));        \
    std::exit(1);                                                     \
  }                                                                   \
} while (0)

struct __align__(16) Event {
  uint64_t t_ns;
  float price;
  uint32_t _pad; // keep alignment simple
};

enum Side : int8_t { NONE = 0, BUY = 1, SELL = -1 };

struct __align__(16) Order {
  uint64_t t_ns;
  float price;
  float qty;
  int8_t side;
  int8_t _pad[3];
};

// CPU market-data simulator: random walk prices
static std::vector<Event> generate_market_data(int n, float start_price, uint64_t dt_ns,
                                               float sigma_step = 0.0005f) {
  std::vector<Event> v(n);
  std::mt19937 rng(12345);
  std::normal_distribution<float> noise(0.0f, sigma_step);

  float price = start_price;
  uint64_t t = 0;
  for (int i = 0; i < n; ++i) {
    float r = noise(rng);
    price *= (1.0f + r);
    if (price < 0.01f) price = 0.01f;

    v[i].t_ns = t;
    v[i].price = price;
    v[i]._pad = 0;
    t += dt_ns;
  }
  return v;
}

// GPU: compute decision + emit order per event (order or no order)
__global__ void decide_orders(const Event* __restrict__ ev,
                              int n,
                              float thr,      // return threshold
                              float qty,      // fixed quantity for now
                              Order* __restrict__ out_orders,
                              int* __restrict__ out_order_count) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;

  // For i==0 we cannot compute return, so no order
  if (i == 0) {
    out_orders[i] = {ev[i].t_ns, ev[i].price, 0.0f, (int8_t)NONE, {0,0,0}};
    return;
  }

  float p = ev[i].price;
  float pprev = ev[i - 1].price;
  float ret = (pprev != 0.0f) ? (p - pprev) / pprev : 0.0f;

  int8_t side = NONE;
  float oqty = 0.0f;

  if (ret > thr) { side = BUY;  oqty = qty; }
  else if (ret < -thr) { side = SELL; oqty = qty; }

  out_orders[i] = {ev[i].t_ns, p, oqty, side, {0,0,0}};

  // Count how many orders fired (atomic)
  if (side != NONE) atomicAdd(out_order_count, 1);
}

int main(int argc, char** argv) {
  int n = (argc > 1) ? std::atoi(argv[1]) : 5'000'000;
  float thr = (argc > 2) ? std::atof(argv[2]) : 0.0008f; // 8 bps threshold
  float qty = (argc > 3) ? std::atof(argv[3]) : 1.0f;

  std::cout << "n=" << n << " thr=" << thr << " qty=" << qty << "\n";

  // 1) CPU generates market data
  auto h_ev = generate_market_data(n, 100.0f, 1000 /*1us*/);

  // 2) Allocate device memory
  Event* d_ev = nullptr;
  Order* d_orders = nullptr;
  int* d_count = nullptr;

  CUDA_CHECK(cudaMalloc(&d_ev, sizeof(Event) * (size_t)n));
  CUDA_CHECK(cudaMalloc(&d_orders, sizeof(Order) * (size_t)n));
  CUDA_CHECK(cudaMalloc(&d_count, sizeof(int)));
  CUDA_CHECK(cudaMemset(d_count, 0, sizeof(int)));

  // 3) Copy host -> device
  cudaEvent_t h2d0, h2d1, k0, k1, d2h0, d2h1;
  CUDA_CHECK(cudaEventCreate(&h2d0)); CUDA_CHECK(cudaEventCreate(&h2d1));
  CUDA_CHECK(cudaEventCreate(&k0));   CUDA_CHECK(cudaEventCreate(&k1));
  CUDA_CHECK(cudaEventCreate(&d2h0)); CUDA_CHECK(cudaEventCreate(&d2h1));

  CUDA_CHECK(cudaEventRecord(h2d0));
  CUDA_CHECK(cudaMemcpy(d_ev, h_ev.data(), sizeof(Event) * (size_t)n, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaEventRecord(h2d1));
  CUDA_CHECK(cudaEventSynchronize(h2d1));

  float h2d_ms = 0.0f;
  CUDA_CHECK(cudaEventElapsedTime(&h2d_ms, h2d0, h2d1));
  std::cout << "H->D copy: " << h2d_ms << " ms\n";

  // 4) Launch decision kernel
  int threads = 256;
  int blocks = (n + threads - 1) / threads;

  CUDA_CHECK(cudaEventRecord(k0));
  decide_orders<<<blocks, threads>>>(d_ev, n, thr, qty, d_orders, d_count);
  CUDA_CHECK(cudaEventRecord(k1));
  CUDA_CHECK(cudaGetLastError());
  CUDA_CHECK(cudaEventSynchronize(k1));

  float k_ms = 0.0f;
  CUDA_CHECK(cudaEventElapsedTime(&k_ms, k0, k1));
  std::cout << "Kernel: " << k_ms << " ms"
            << " | throughput: " << (double)n / (k_ms * 1e6) << " GEvents/s\n";

  // 5) Copy results back (just orders + count)
  std::vector<Order> h_orders(20); // pull first 20 for demo
  int h_count = 0;

  CUDA_CHECK(cudaEventRecord(d2h0));
  CUDA_CHECK(cudaMemcpy(&h_count, d_count, sizeof(int), cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(h_orders.data(), d_orders, sizeof(Order) * h_orders.size(), cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaEventRecord(d2h1));
  CUDA_CHECK(cudaEventSynchronize(d2h1));

  float d2h_ms = 0.0f;
  CUDA_CHECK(cudaEventElapsedTime(&d2h_ms, d2h0, d2h1));
  std::cout << "D->H copy (count + first 20 orders): " << d2h_ms << " ms\n";

  std::cout << "Orders fired: " << h_count << " out of " << n << "\n";

  // Print first few emitted orders (including NONE, so you see structure)
  for (size_t i = 0; i < h_orders.size(); ++i) {
    const auto& o = h_orders[i];
    const char* s = (o.side == BUY ? "BUY" : (o.side == SELL ? "SELL" : "NONE"));
    std::printf("i=%zu t=%llu price=%.6f side=%s qty=%.2f\n",
                i, (unsigned long long)o.t_ns, o.price, s, o.qty);
  }

  // cleanup
  CUDA_CHECK(cudaFree(d_ev));
  CUDA_CHECK(cudaFree(d_orders));
  CUDA_CHECK(cudaFree(d_count));

  CUDA_CHECK(cudaEventDestroy(h2d0)); CUDA_CHECK(cudaEventDestroy(h2d1));
  CUDA_CHECK(cudaEventDestroy(k0));   CUDA_CHECK(cudaEventDestroy(k1));
  CUDA_CHECK(cudaEventDestroy(d2h0)); CUDA_CHECK(cudaEventDestroy(d2h1));

  return 0;
}