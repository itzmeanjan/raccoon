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

template<size_t d>
static void
bench_raccoon128_sign(benchmark::State& state)
{
  constexpr size_t fixed_msg_byte_len = 32;

  std::array<uint8_t, 16> seed{};
  std::array<uint8_t, raccoon128::SIG_BYTE_LEN> sig_bytes{};
  std::vector<uint8_t> msg(fixed_msg_byte_len, 0);

  prng::prng_t prng{};
  prng.read(seed);
  prng.read(msg);

  auto skey = raccoon128::raccoon128_skey_t<d>::generate(seed);

  for (auto _ : state) {
    skey.sign(msg, sig_bytes);

    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(sig_bytes);
    benchmark::DoNotOptimize(skey);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

static void
bench_raccoon128_verify(benchmark::State& state)
{
  constexpr size_t fixed_msg_byte_len = 32;
  constexpr size_t num_shares = 1;

  std::array<uint8_t, 16> seed{};
  std::array<uint8_t, raccoon128::SIG_BYTE_LEN> sig_bytes{};
  std::vector<uint8_t> msg(fixed_msg_byte_len, 0);

  prng::prng_t prng{};
  prng.read(seed);
  prng.read(msg);

  auto skey = raccoon128::raccoon128_skey_t<num_shares>::generate(seed);
  auto pkey = skey.get_pkey();
  skey.sign(msg, sig_bytes);

  bool is_verified = true;
  for (auto _ : state) {
    is_verified &= pkey.verify(msg, sig_bytes);

    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(sig_bytes);
    benchmark::DoNotOptimize(pkey);
    benchmark::DoNotOptimize(is_verified);
    benchmark::ClobberMemory();
  }

  state.SetItemsProcessed(state.iterations());
}

// clang-format off
BENCHMARK(bench_raccoon128_keygen<1>)->Name("raccoon128/keygen/unmasked")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<2>)->Name("raccoon128/keygen/masked/order 1")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<4>)->Name("raccoon128/keygen/masked/order 3")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<8>)->Name("raccoon128/keygen/masked/order 7")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<16>)->Name("raccoon128/keygen/masked/order 15")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_keygen<32>)->Name("raccoon128/keygen/masked/order 31")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);

BENCHMARK(bench_raccoon128_sign<1>)->Name("raccoon128/sign/unmasked")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_sign<2>)->Name("raccoon128/sign/masked/order 1")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_sign<4>)->Name("raccoon128/sign/masked/order 3")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_sign<8>)->Name("raccoon128/sign/masked/order 7")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_sign<16>)->Name("raccoon128/sign/masked/order 15")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon128_sign<32>)->Name("raccoon128/sign/masked/order 31")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);

BENCHMARK(bench_raccoon128_verify)->Name("raccoon128/verify")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
// clang-format on
