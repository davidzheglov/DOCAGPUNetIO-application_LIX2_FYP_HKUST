NVCC=nvcc
CXXFLAGS=-O3 -std=c++17
NVCCFLAGS=-O3 -std=c++17

INCLUDES=-Iinclude

SRCS=src/main.cu src/kernels.cu src/market_sim.cpp
OUT=mini_trader_stream

all: $(OUT)

$(OUT): $(SRCS)
	$(NVCC) $(NVCCFLAGS) $(INCLUDES) $(SRCS) -o $(OUT)

clean:
	rm -f $(OUT)