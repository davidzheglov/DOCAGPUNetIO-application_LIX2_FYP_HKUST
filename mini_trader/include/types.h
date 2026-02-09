#pragma once
#include <cstdint>

struct alignas(16) Event {
  uint64_t t_ns;
  float price;
  uint32_t _pad;
};

enum Side : int8_t { NONE = 0, BUY = 1, SELL = -1 };

struct alignas(16) Order {
  uint64_t t_ns;
  float price;
  float qty;
  int8_t side;
  int8_t _pad[3];
};