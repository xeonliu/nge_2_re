#include "nge2/common.hpp"

#include <istream>
#include <ostream>

namespace nge2 {

uint8_t read_uint8(std::istream& f) {
    uint8_t val = 0;
    f.read(reinterpret_cast<char*>(&val), 1);
    if (!f) throw std::runtime_error("Failed to read uint8");
    return val;
}

uint16_t read_uint16_le(std::istream& f) {
    uint8_t buf[2] = {};
    f.read(reinterpret_cast<char*>(buf), 2);
    if (!f) throw std::runtime_error("Failed to read uint16");
    return static_cast<uint16_t>(buf[0]) |
           (static_cast<uint16_t>(buf[1]) << 8);
}

uint32_t read_uint32_le(std::istream& f) {
    uint8_t buf[4] = {};
    f.read(reinterpret_cast<char*>(buf), 4);
    if (!f) throw std::runtime_error("Failed to read uint32");
    return static_cast<uint32_t>(buf[0]) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

void write_uint8(std::ostream& f, uint8_t value) {
    f.write(reinterpret_cast<const char*>(&value), 1);
}

void write_uint16_le(std::ostream& f, uint16_t value) {
    uint8_t buf[2] = {
        static_cast<uint8_t>(value),
        static_cast<uint8_t>(value >> 8)
    };
    f.write(reinterpret_cast<const char*>(buf), 2);
}

void write_uint32_le(std::ostream& f, uint32_t value) {
    uint8_t buf[4] = {
        static_cast<uint8_t>(value),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 24)
    };
    f.write(reinterpret_cast<const char*>(buf), 4);
}

uint32_t calculate_word_aligned_length(uint32_t unaligned_length) {
    return 4u * ((unaligned_length + 3u) / 4u);
}

uint32_t align_size(uint32_t unaligned_size, uint32_t alignment) {
    return alignment * ((unaligned_size + alignment - 1u) / alignment);
}

std::vector<uint8_t> zero_pad_and_align_string(const std::vector<uint8_t>& content) {
    // Pad string to a size divisible by 4
    // Appends up to 4 NUL bytes.  Mirrors the Python:
    //   padded_length = 4 * int((len(content) + 4) / 4)
    //   return (content + b'\0\0\0\0')[0:padded_length]
    size_t padded_length = 4 * ((content.size() + 4) / 4);
    std::vector<uint8_t> padded = content;
    padded.resize(padded_length, 0);
    return padded;
}

std::streamsize get_stream_size(std::istream& f) {
    auto saved = f.tellg();
    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    f.seekg(saved);
    return size;
}

} // namespace nge2
