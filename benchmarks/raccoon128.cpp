#include "raccoon/raccoon128.hpp"
#include "bench_common.hpp"
#include <benchmark/benchmark.h>

template<size_t d>
static void
bench_raccoon128_keygen(benchmark::State& state)
{
  std::array<uint8_t, 16> seed{};
  std::array<uint8_t, raccoon128::raccoon128_skey_t<d>::get_byte_len()> sk_bytes{};

  prng::prng_t prng{};
  prng.read(seed);

  for (auto _ : state) {
    auto skey = raccoon128::raccoon128_skey_t<d>::generate(seed);
    skey.as_bytes(sk_bytes);

    benchmark::DoNotOptimize(seed);
    benchmark::DoNotOptimize(skey);
    benchmark::DoNotOptimize(sk_bytes);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(bench_raccoon128_keygen<1>)->Name("raccoon128/keygen/unmasked")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<2>)->Name("raccoon128/keygen/masked(order 1)")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<4>)->Name("raccoon128/keygen/masked(order 3)")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<8>)->Name("raccoon128/keygen/masked(order 7)")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<16>)
  ->Name("raccoon128/keygen/masked(order 15)")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<32>)
  ->Name("raccoon128/keygen/masked(order 31)")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
