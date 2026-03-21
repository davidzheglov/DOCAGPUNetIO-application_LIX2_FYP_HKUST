#include "market_sim.h"
#include <random>

void generate_market_data(Event* out, int n,
                          float start_price,
                          uint64_t start_t_ns,
                          uint64_t dt_ns,
                          float sigma_step,
                          uint32_t seed) {
  std::mt19937 rng(seed);
  std::normal_distribution<float> noise(0.0f, sigma_step);

  float price = start_price;
  uint64_t t = start_t_ns;

  for (int i = 0; i < n; ++i) {
    float r = noise(rng);
    price *= (1.0f + r);
    if (price < 0.01f) price = 0.01f;

    out[i].t_ns = t;
    out[i].price = price;
    out[i]._pad = 0;
    t += dt_ns;
  }
}