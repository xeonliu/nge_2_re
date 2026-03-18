#pragma once

#include "nge2/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace nge2 {

/// Represents a single file stored inside an HGAR archive.
struct HGArchiveFile {
    std::vector<uint8_t> long_name;   ///< Present in V3 archives; empty otherwise.
    std::vector<uint8_t> short_name;  ///< 8.3 format short filename (raw bytes).
    uint32_t size             = 0;
    uint32_t encoded_identifier = 0;
    uint32_t identifier       = 0;
    uint32_t unknown_first    = 0;    ///< Only present in V3.
    uint32_t unknown_last     = 0;    ///< Only present in V3.
    bool     is_compressed    = false;
    std::vector<uint8_t> content;

    /// Generate the canonical filename used when extracting files to disk.
    /// Format: "long_name#short_name#idNUMBER.ext"  (simplified when possible)
    std::string get_viable_name() const;

    /// Decode encoded_identifier → identifier and is_compressed flag.
    void decode_identifier(uint32_t limit);

    /// Brute-force encode identifier → encoded_identifier.
    /// Only needed when creating new entries from scratch.
    void encode_identifier(uint32_t limit);
};

/// An HGAR archive container.
struct HGArchive {
    int      version          = 0;
    uint32_t identifier_limit = 0;
    std::string filename;
    std::vector<HGArchiveFile> files;

    /// (Re)compute identifier_limit from the current file count.
    void calculate_identifier_limit();

    /// Decode all file identifiers.  Must be called after loading is complete.
    void decode_identifiers();

    // ---- I/O ----
    void open(const std::string& path);
    /// Note: may call encode_identifier() on entries that have no encoded_identifier yet.
    void save(const std::string& path);

    /// Extract all files into output_dir (directory must exist).
    void extract(const std::string& output_dir) const;

    /// Print human-readable info to stdout.
    void info() const;
};

} // namespace nge2
