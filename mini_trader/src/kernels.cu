#include "kernels.h"
#include <cuda_runtime.h>

__global__ void decide_orders(const Event* __restrict__ ev,
                              int n,
                              float thr,
                              float qty,
                              Order* __restrict__ out_orders,
                              int* __restrict__ out_order_count) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;

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

  if (side != NONE) atomicAdd(out_order_count, 1);
}