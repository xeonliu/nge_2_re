#pragma once

#include <cstdint>
#include <iosfwd>
#include <stdexcept>
#include <string>
#include <vector>

namespace nge2 {

// ---- Binary I/O ----

uint8_t  read_uint8(std::istream& f);
uint16_t read_uint16_le(std::istream& f);
uint32_t read_uint32_le(std::istream& f);

void write_uint8(std::ostream& f, uint8_t value);
void write_uint16_le(std::ostream& f, uint16_t value);
void write_uint32_le(std::ostream& f, uint32_t value);

// ---- Alignment helpers ----

/// Return length rounded up to the next multiple of 4.
uint32_t calculate_word_aligned_length(uint32_t unaligned_length);

/// Return size rounded up to the next multiple of alignment.
uint32_t align_size(uint32_t unaligned_size, uint32_t alignment);

/// Append up to 4 NUL bytes so that total length is a multiple of 4.
std::vector<uint8_t> zero_pad_and_align_string(const std::vector<uint8_t>& content);

// ---- Stream helpers ----

/// Return the total byte count of the stream without changing the current position.
std::streamsize get_stream_size(std::istream& f);

} // namespace nge2
