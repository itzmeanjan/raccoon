CXX ?= clang++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native
LINK_FLAGS = -flto
ASAN_FLAGS = -g -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=address # From https://clang.llvm.org/docs/AddressSanitizer.html
UBSAN_FLAGS = -g -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=undefined # From https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

I_FLAGS = -I ./include
SHA3_INC_DIR = ./sha3/include
ASCON_INC_DIR = ./ascon/include
SUBTLE_INC_DIR = ./subtle/include
DEP_IFLAGS = -I $(SHA3_INC_DIR) -I $(ASCON_INC_DIR) -I $(SUBTLE_INC_DIR)

SRC_DIR = include
RACCOON_SOURCES := $(shell find $(SRC_DIR) -name '*.hpp')
BUILD_DIR = build
ASAN_BUILD_DIR = $(BUILD_DIR)/asan
UBSAN_BUILD_DIR = $(BUILD_DIR)/ubsan

TEST_DIR = tests
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS := $(addprefix $(BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
ASAN_TEST_OBJECTS := $(addprefix $(ASAN_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
UBSAN_TEST_OBJECTS := $(addprefix $(UBSAN_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
TEST_LINK_FLAGS = -lgtest -lgtest_main
TEST_BINARY = $(BUILD_DIR)/test.out
ASAN_TEST_BINARY = $(ASAN_BUILD_DIR)/test.out
UBSAN_TEST_BINARY = $(UBSAN_BUILD_DIR)/test.out
GTEST_PARALLEL = ./gtest-parallel/gtest-parallel

BENCHMARK_DIR = benchmarks
BENCHMARK_SOURCES := $(wildcard $(BENCHMARK_DIR)/*.cpp)
BENCHMARK_HEADERS := $(wildcard $(BENCHMARK_DIR)/*.hpp)
BENCHMARK_OBJECTS := $(addprefix $(BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(BENCHMARK_SOURCES))))
BENCHMARK_LINK_FLAGS = -lbenchmark -lbenchmark_main -lpthread
BENCHMARK_BINARY = $(BUILD_DIR)/bench.out
PERF_LINK_FLAGS = -lbenchmark -lbenchmark_main -lpfm -lpthread
PERF_BINARY = $(BUILD_DIR)/perf.out
BENCHMARK_OUT_FILE = bench_result_on_$(shell uname -s)_$(shell uname -r)_$(shell uname -m)_with_$(CXX)_$(shell $(CXX) -dumpversion).json

all: test

$(ASAN_BUILD_DIR):
	mkdir -p $@

$(UBSAN_BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

$(GTEST_PARALLEL):
	git submodule update --init gtest-parallel

$(SHA3_INC_DIR): $(GTEST_PARALLEL)
	git submodule update --init sha3

$(ASCON_INC_DIR): $(SHA3_INC_DIR)
	git submodule update --init ascon

$(SUBTLE_INC_DIR): $(ASCON_INC_DIR)
	git submodule update --init subtle

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(BUILD_DIR) $(SHA3_INC_DIR) $(ASCON_INC_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(ASAN_BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(ASAN_BUILD_DIR) $(SHA3_INC_DIR) $(ASCON_INC_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(ASAN_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(UBSAN_BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(UBSAN_BUILD_DIR) $(SHA3_INC_DIR) $(ASCON_INC_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(UBSAN_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(TEST_BINARY): $(TEST_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

$(ASAN_TEST_BINARY): $(ASAN_TEST_OBJECTS)
	$(CXX) $(ASAN_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

$(UBSAN_TEST_BINARY): $(UBSAN_TEST_OBJECTS)
	$(CXX) $(UBSAN_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

test: $(TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

asan_test: $(ASAN_TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

ubsan_test: $(UBSAN_TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

$(BUILD_DIR)/%.o: $(BENCHMARK_DIR)/%.cpp $(BUILD_DIR) $(SHA3_INC_DIR) $(ASCON_INC_DIR) $(SUBTLE_INC_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(DEP_IFLAGS) -c $< -o $@

$(BENCHMARK_BINARY): $(BENCHMARK_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(BENCHMARK_LINK_FLAGS) -o $@

benchmark: $(BENCHMARK_BINARY)
	# Must *not* build google-benchmark with libPFM
	./$< --benchmark_time_unit=ms --benchmark_min_warmup_time=.5 --benchmark_enable_random_interleaving=true --benchmark_repetitions=16 --benchmark_min_time=0.1s --benchmark_display_aggregates_only=true --benchmark_report_aggregates_only=true --benchmark_counters_tabular=true --benchmark_out_format=json --benchmark_out=$(BENCHMARK_OUT_FILE)

$(PERF_BINARY): $(BENCHMARK_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(PERF_LINK_FLAGS) -o $@

perf: $(PERF_BINARY)
	# Must build google-benchmark with libPFM, follow https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7
	./$< --benchmark_time_unit=ms --benchmark_min_warmup_time=.5 --benchmark_enable_random_interleaving=true --benchmark_repetitions=16 --benchmark_min_time=0.1s --benchmark_display_aggregates_only=true --benchmark_report_aggregates_only=true --benchmark_counters_tabular=true --benchmark_perf_counters=CYCLES --benchmark_out_format=json --benchmark_out=$(BENCHMARK_OUT_FILE)

.PHONY: format clean

clean:
	rm -rf $(BUILD_DIR)

format: $(RACCOON_SOURCES) $(TEST_SOURCES) $(BENCHMARK_SOURCES) $(BENCHMARK_HEADERS)
	clang-format -i $^
