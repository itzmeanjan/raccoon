CXX ?= clang++
CXX_FLAGS = -std=c++20
WARN_FLAGS = -Wall -Wextra -pedantic
OPT_FLAGS = -O3 -march=native
LINK_FLAGS = -flto

I_FLAGS = -I ./include
SHA3_INC_DIR = ./sha3/include
ASCON_INC_DIR = ./ascon/include
SUBTLE_INC_DIR = ./subtle/include
DEP_IFLAGS = -I $(SHA3_INC_DIR) -I $(ASCON_INC_DIR) -I $(SUBTLE_INC_DIR)

SRC_DIR = include
RACCOON_SOURCES := $(wildcard $(SRC_DIR)/*.hpp)
BUILD_DIR = build

TEST_DIR = tests
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS := $(addprefix $(BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
TEST_LINK_FLAGS = -lgtest -lgtest_main
TEST_BINARY = $(BUILD_DIR)/test.out
GTEST_PARALLEL = ./gtest-parallel/gtest-parallel

all: test

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

$(TEST_BINARY): $(TEST_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(LINK_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

test: $(TEST_BINARY) $(GTEST_PARALLEL)
	$(GTEST_PARALLEL) $< --print_test_times

.PHONY: format clean

clean:
	rm -rf $(BUILD_DIR)

format: $(RACCOON_SOURCES) $(TEST_SOURCES)
	clang-format -i $^
