#include "raccoon/raccoon256.hpp"
#include "bench_common.hpp"
#include <benchmark/benchmark.h>

template<size_t d>
static void
bench_raccoon256_keygen(benchmark::State& state)
{
  std::array<uint8_t, raccoon256::SEED_BYTE_LEN> seed{};
  std::array<uint8_t, raccoon256::raccoon256_skey_t<d>::get_byte_len()> sk_bytes{};

  prng::prng_t prng{};
  prng.read(seed);

  for (auto _ : state) {
    auto skey = raccoon256::raccoon256_skey_t<d>::generate(seed);
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
bench_raccoon256_sign(benchmark::State& state)
{
  constexpr size_t fixed_msg_byte_len = 32;

  std::array<uint8_t, raccoon256::SEED_BYTE_LEN> seed{};
  std::array<uint8_t, raccoon256::SIG_BYTE_LEN> sig_bytes{};
  std::vector<uint8_t> msg(fixed_msg_byte_len, 0);

  prng::prng_t prng{};
  prng.read(seed);
  prng.read(msg);

  auto skey = raccoon256::raccoon256_skey_t<d>::generate(seed);

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
bench_raccoon256_verify(benchmark::State& state)
{
  constexpr size_t fixed_msg_byte_len = 32;
  constexpr size_t num_shares = 1;

  std::array<uint8_t, raccoon256::SEED_BYTE_LEN> seed{};
  std::array<uint8_t, raccoon256::SIG_BYTE_LEN> sig_bytes{};
  std::vector<uint8_t> msg(fixed_msg_byte_len, 0);

  prng::prng_t prng{};
  prng.read(seed);
  prng.read(msg);

  auto skey = raccoon256::raccoon256_skey_t<num_shares>::generate(seed);
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
BENCHMARK(bench_raccoon256_keygen<1>)->Name("raccoon256/keygen/unmasked")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_keygen<2>)->Name("raccoon256/keygen/masked/order 1")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_keygen<4>)->Name("raccoon256/keygen/masked/order 3")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_keygen<8>)->Name("raccoon256/keygen/masked/order 7")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_keygen<16>)->Name("raccoon256/keygen/masked/order 15")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_keygen<32>)->Name("raccoon256/keygen/masked/order 31")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);

BENCHMARK(bench_raccoon256_sign<1>)->Name("raccoon256/sign/unmasked")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_sign<2>)->Name("raccoon256/sign/masked/order 1")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_sign<4>)->Name("raccoon256/sign/masked/order 3")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_sign<8>)->Name("raccoon256/sign/masked/order 7")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_sign<16>)->Name("raccoon256/sign/masked/order 15")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon256_sign<32>)->Name("raccoon256/sign/masked/order 31")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);

BENCHMARK(bench_raccoon256_verify)->Name("raccoon256/verify")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
// clang-format on
