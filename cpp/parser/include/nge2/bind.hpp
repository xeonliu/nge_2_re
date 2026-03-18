#pragma once

#include "nge2/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace nge2 {

/// A single entry in a BIND archive.
struct BindEntry {
    std::vector<uint8_t> content;
    uint32_t get_size() const { return static_cast<uint32_t>(content.size()); }
};

/// BIND archive container.
///
/// Binary layout:
///   "BIND"          4 bytes
///   size_byte_size  uint16  (1, 2, or 4)
///   num_entries     uint16
///   block_size      uint32
///   header_size     uint32  (= align(16 + n*size_byte_size, block_size))
///   entry_sizes     n × size_byte_size
///   <padding to header_size>
///   entry_data[0]   align(entry_size, block_size)
///   ...
struct BindArchive {
    uint16_t size_byte_size = 4;
    uint32_t block_size     = 2048;
    std::vector<BindEntry> entries;

    void add_entry(const std::vector<uint8_t>& content);

    // ---- I/O ----
    void open(const std::string& path);
    void save(const std::string& path) const;

    /// Extract each entry as <dir>/<N>.bin
    void unpack(const std::string& dir) const;

    /// Pack <dir>/0.bin, 1.bin, … into this archive (clears existing entries).
    void pack(const std::string& dir);
};

} // namespace nge2
