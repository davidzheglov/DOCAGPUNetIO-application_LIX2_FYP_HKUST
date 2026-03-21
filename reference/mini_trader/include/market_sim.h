#pragma once
#include <cstdint>
#include "types.h"

// Fill exactly n events into out[]. Pure CPU.
void generate_market_data(Event* out, int n,
                          float start_price,
                          uint64_t start_t_ns,
                          uint64_t dt_ns,
                          float sigma_step,
                          uint32_t seed);