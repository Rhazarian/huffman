#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <queue>
#include <functional>
#include <memory>
#include <cassert>
#include <iostream>
#include <stdexcept>

#include "huffman.h"

namespace {

typedef unsigned char byte_t;
constexpr uint8_t bits_in_byte = std::numeric_limits<byte_t>::digits;

struct bit_istream {
    std::array<byte_t, 1u << 16u> buffer{};
    uint8_t bit_pos{};
    size_t pos{};
    size_t size{};
    std::istream& istream;

    explicit bit_istream(std::istream& istream) : istream(istream) {
        check_buffer();
    }

    void check_buffer()
    {
        if (size_t shift = size - pos; shift < 2) {
            for (size_t i = 0; i < shift; ++i) {
                buffer[i] = buffer[pos + i];
            }
            static_assert(sizeof(char) == sizeof(byte_t));
            istream.read(reinterpret_cast<char*>(buffer.data() + shift), buffer.size() - shift);
            size = shift + istream.gcount();
            pos = 0;
        }
    }

    bool read_bit()
    {
        assert(pos < size);
        bool bit = (buffer[pos] & (1 << (bits_in_byte - 1 - bit_pos))) != 0;
        ++bit_pos;
        if (bit_pos == bits_in_byte) {
            bit_pos = 0;
            ++pos;
            check_buffer();
        }
        return bit;
    };

    uint8_t read_8_bits()
    {
        assert(pos < size);
        uint8_t bits = (buffer[pos] << bit_pos) | (buffer[pos + 1] >> (bits_in_byte - bit_pos));
        ++pos;
        check_buffer();
        return bits;
    }

    bool has_more()
    {
        return !istream.fail() || pos < size;
    }

    void rewind()
    {
        istream.clear();
        istream.seekg(std::ios::beg);
        pos = size = bit_pos = 0;
        check_buffer();
    }

};

struct bit_ostream {
    std::array<byte_t, 1u << 16u> buffer{};
    uint8_t bit_pos{};
    size_t size{};
    std::ostream& ostream;

    explicit bit_ostream(std::ostream& ostream) : ostream(ostream) { }

    void flush_buffer()
    {
        static_assert(sizeof(char) == sizeof(byte_t));
        ostream.write(reinterpret_cast<const char*>(buffer.data()), size + (bit_pos != 0));
        size = bit_pos = 0;
        buffer.fill(0);
    }

    void write_bits(uint64_t bits, uint8_t count)
    {
        assert(count <= std::numeric_limits<decltype(bits)>::digits);
        bits <<= std::numeric_limits<decltype(bits)>::digits - count;
        for (uint8_t i = 0; i < count; ++i) {
            decltype(bits) mask = (decltype(bits)(1) << (std::numeric_limits<decltype(bits)>::digits - 1 - i));
            buffer[size] |= (byte_t((bits & mask) != 0)) << (bits_in_byte - 1 - bit_pos);
            ++bit_pos;
            if (bit_pos == bits_in_byte) {
                bit_pos = 0;
                ++size;
                if (size == buffer.size()) {
                    flush_buffer();
                }
            }
        }
    }

    ~bit_ostream()
    {
        flush_buffer();
    }

};

constexpr size_t ALPHABET_SIZE = 1u << std::numeric_limits<byte_t>::digits;

struct symbol {
    byte_t byte;
    size_t count;
    uint64_t code;
    uint8_t bits;

    symbol(byte_t byte, size_t count, uint64_t code, uint8_t bits) : byte(byte), count(count), code(code), bits(bits) { }
};

std::vector<symbol> build_histogram(bit_istream& istream)
{
    std::vector<symbol> histogram;
    histogram.reserve(ALPHABET_SIZE);
    for (size_t i = 0; i < ALPHABET_SIZE; ++i) {
        histogram.emplace_back(i, 0, 0, 0);
    }
    while (istream.has_more()) {
        static_assert(bits_in_byte == 8);
        ++histogram[istream.read_8_bits()].count;
    }
    istream.rewind();
    return histogram;
}

struct encode_node {
    byte_t byte{};
    size_t count{};
    std::shared_ptr<encode_node> left = nullptr;
    std::shared_ptr<encode_node> right = nullptr;

    encode_node() = default;

    encode_node(byte_t byte, size_t count) : byte(byte), count(count) { }

    encode_node(encode_node left, encode_node right) : count(left.count + right.count),
            left(std::make_shared<encode_node>(left)), right(std::make_shared<encode_node>(right)) { }
};

void store_tree(encode_node const& node, uint64_t code, uint8_t bits, std::vector<symbol>& histogram,
        bit_ostream& ostream)
{
    assert(bits <= std::numeric_limits<decltype(code)>::digits);
    if (!node.left && !node.right) {
        ostream.write_bits(1, 1);
        ostream.write_bits(node.byte, bits_in_byte);
        histogram[node.byte].code = code;
        histogram[node.byte].bits = bits;
        return;
    }
    else {
        ostream.write_bits(0, 1);
    }
    ++bits;
    store_tree(*node.left, (code << 1) + 0, bits, histogram, ostream);
    store_tree(*node.right, (code << 1) + 1, bits, histogram, ostream);
}

constexpr size_t MAX_TREE_NODES = 511;

void make_tree(std::vector<symbol>& histogram, bit_ostream& ostream)
{
    std::array<encode_node, MAX_TREE_NODES> nodes{};
    std::function<bool(encode_node, encode_node)> comparator = [](encode_node const& lhs, encode_node const& rhs) {
        return lhs.count > rhs.count;
    };
    std::priority_queue<encode_node, std::vector<encode_node>, decltype(comparator)> queue(comparator);
    for (auto const& symbol : histogram) {
        if (symbol.count > 0) {
            queue.emplace(symbol.byte, symbol.count);
        }
    }
    while (queue.size() != 1) {
        auto lhs = queue.top();
        queue.pop();
        auto rhs = queue.top();
        queue.pop();
        queue.emplace(lhs, rhs);
    }
    auto root = queue.top();
    store_tree(root, 0, !root.left && !root.right, histogram, ostream);
}

struct decode_node {
    byte_t byte;
    std::shared_ptr<decode_node> left;
    std::shared_ptr<decode_node> right;

    explicit decode_node(byte_t byte) : byte(byte), left(nullptr), right(nullptr) { }

    decode_node(decode_node left, decode_node right) : byte(0),
            left(std::make_shared<decode_node>(left)), right(std::make_shared<decode_node>(right)) { }
};

decode_node recover_tree(bit_istream& istream)
{
    if (istream.read_bit()) {
        static_assert(bits_in_byte == 8);
        byte_t byte = istream.read_8_bits();
        return decode_node(byte);
    }
    auto left = recover_tree(istream);
    auto right = recover_tree(istream);
    return decode_node(left, right);
}

}

void compress(std::istream& in, std::ostream& out)
{
    bit_istream istream(in);
    auto histogram = build_histogram(istream);
    union {
        size_t value;
        char bytes[sizeof(size_t)];
    } file_size{};
    for (auto const& symbol : histogram) {
        file_size.value += symbol.count;
    }
    if (file_size.value == 0) {
        return;
    }
    for (char byte : file_size.bytes) {
        out.put(byte);
    }
    bit_ostream ostream(out);
    make_tree(histogram, ostream);
    while (istream.has_more()) {
        static_assert(bits_in_byte == 8);
        byte_t byte = istream.read_8_bits();
        ostream.write_bits(histogram[byte].code, histogram[byte].bits);
    }
}

void decompress(std::istream& in, std::ostream& out)
{
    union {
        size_t value;
        char bytes[sizeof(size_t)];
    } file_size{};
    for (char& byte : file_size.bytes) {
        int tmp = in.get();
        if (tmp == std::char_traits<char>::eof()) {
            return;
        } else {
            byte = static_cast<char>(tmp);
        }
    }
    if (file_size.value == 0) {
        return;
    }
    bit_istream istream(in);
    auto root = recover_tree(istream);
    for (size_t i = 0; i < file_size.value; ++i) {
        if (!istream.has_more()) {
            throw std::runtime_error("Not enough data");
        }
        auto* node = &root;
        while (!(!node->left && !node->right)) {
            if (istream.read_bit()) {
                node = node->right.get();
            } else {
                node = node->left.get();
            }
        }
        out.put(node->byte);
    }
}