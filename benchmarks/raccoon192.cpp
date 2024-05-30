#include "raccoon/raccoon192.hpp"
#include "bench_common.hpp"
#include <benchmark/benchmark.h>

template<size_t d>
static void
bench_raccoon192_keygen(benchmark::State& state)
{
  std::array<uint8_t, raccoon192::SEED_BYTE_LEN> seed{};
  std::array<uint8_t, raccoon192::raccoon192_skey_t<d>::get_byte_len()> sk_bytes{};

  prng::prng_t prng{};
  prng.read(seed);

  for (auto _ : state) {
    auto skey = raccoon192::raccoon192_skey_t<d>::generate(seed);
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
bench_raccoon192_sign(benchmark::State& state)
{
  constexpr size_t fixed_msg_byte_len = 32;

  std::array<uint8_t, raccoon192::SEED_BYTE_LEN> seed{};
  std::array<uint8_t, raccoon192::SIG_BYTE_LEN> sig_bytes{};
  std::vector<uint8_t> msg(fixed_msg_byte_len, 0);

  prng::prng_t prng{};
  prng.read(seed);
  prng.read(msg);

  auto skey = raccoon192::raccoon192_skey_t<d>::generate(seed);

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
bench_raccoon192_verify(benchmark::State& state)
{
  constexpr size_t fixed_msg_byte_len = 32;
  constexpr size_t num_shares = 1;

  std::array<uint8_t, raccoon192::SEED_BYTE_LEN> seed{};
  std::array<uint8_t, raccoon192::SIG_BYTE_LEN> sig_bytes{};
  std::vector<uint8_t> msg(fixed_msg_byte_len, 0);

  prng::prng_t prng{};
  prng.read(seed);
  prng.read(msg);

  auto skey = raccoon192::raccoon192_skey_t<num_shares>::generate(seed);
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

BENCHMARK(bench_raccoon192_keygen<1>)->Name("raccoon192/keygen/1")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_keygen<2>)->Name("raccoon192/keygen/2")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_keygen<4>)->Name("raccoon192/keygen/4")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_keygen<8>)->Name("raccoon192/keygen/8")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_keygen<16>)->Name("raccoon192/keygen/16")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_keygen<32>)->Name("raccoon192/keygen/32")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);

BENCHMARK(bench_raccoon192_sign<1>)->Name("raccoon192/sign/1")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_sign<2>)->Name("raccoon192/sign/2")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_sign<4>)->Name("raccoon192/sign/4")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_sign<8>)->Name("raccoon192/sign/8")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_sign<16>)->Name("raccoon192/sign/16")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(bench_raccoon192_sign<32>)->Name("raccoon192/sign/32")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);

BENCHMARK(bench_raccoon192_verify)->Name("raccoon192/verify")->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
