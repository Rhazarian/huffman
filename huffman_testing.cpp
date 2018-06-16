#include <sstream>
#include <random>
#include <gtest/gtest.h>

#include "lib/huffman.h"

namespace {
std::string compress_decompress(std::string const& str) {
    std::istringstream in(str);
    std::ostringstream compressed_out;
    compress(in, compressed_out);
    std::istringstream compressed_in(compressed_out.str());
    std::ostringstream decompressed_out;
    decompress(compressed_in, decompressed_out);
    return decompressed_out.str();
}
}

TEST(correctness, blank) // NOLINT
{
    std::string str;
    EXPECT_EQ(str, compress_decompress(str));
}

namespace {

std::mt19937 gen(0); // NOLINT
std::uniform_int_distribution<> char_dist(std::numeric_limits<char>::min(), std::numeric_limits<char>::max()); // NOLINT

char random_char()
{
    return static_cast<char>(char_dist(gen));
}

std::string random_string(size_t n)
{
    std::string str;
    str.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        str.push_back(random_char());
    }
    return str;
}

std::uniform_int_distribution<> short_str_dist(0, 500); // NOLINT

size_t random_short_str_length()
{
    return static_cast<size_t>(short_str_dist(gen));
}

std::uniform_int_distribution<> long_str_dist(10000, 100000); // NOLINT

size_t random_long_str_length()
{
    return static_cast<size_t>(long_str_dist(gen));
}

std::uniform_int_distribution<> long_long_str_dist(100000, 1000000); // NOLINT

size_t random_long_long_str_length()
{
    return static_cast<size_t>(long_long_str_dist(gen));
}
}

TEST(correctness, random_short_strings) // NOLINT
{
    constexpr size_t LOOP_COUNT = 100;
    for (size_t i = 0; i < LOOP_COUNT; ++i) {
        std::string str = random_string(random_short_str_length());
        EXPECT_EQ(str, compress_decompress(str));
    }
}

TEST(correctness, random_long_strings) // NOLINT
{
    constexpr size_t LOOP_COUNT = 50;
    for (size_t i = 0; i < LOOP_COUNT; ++i) {
        std::string str = random_string(random_long_str_length());
        EXPECT_EQ(str, compress_decompress(str));
    }
}

TEST(correctness, random_long_long_strings) // NOLINT
{
    constexpr size_t LOOP_COUNT = 25;
    for (size_t i = 0; i < LOOP_COUNT; ++i) {
        std::string str = random_string(random_long_long_str_length());
        EXPECT_EQ(str, compress_decompress(str));
    }
}