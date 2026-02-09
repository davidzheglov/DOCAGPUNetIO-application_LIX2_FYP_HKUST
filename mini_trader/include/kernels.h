#pragma once
#include "types.h"

__global__ void decide_orders(const Event* __restrict__ ev,
                              int n,
                              float thr,
                              float qty,
                              Order* __restrict__ out_orders,
                              int* __restrict__ out_order_count);