#pragma once

#include "nge2/common.hpp"

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

namespace nge2 {

/// A single string entry in a TEXT archive.
/// Stores raw bytes (as they appear in the file) plus two unknown uint32 fields.
struct TextString {
    uint32_t             unknown_first  = 0;
    uint32_t             unknown_second = 0;
    std::vector<uint8_t> raw_content;   ///< Raw bytes; may include Shift-JIS.
    bool                 is_null        = false; ///< True for out-of-bounds dummy entries.
};

/// A TEXT archive: a table of (unknown, string_index) pairs plus a string pool.
struct TextArchive {
    /// (unknown_field, string_index)
    std::vector<std::pair<uint32_t, uint32_t>> entries;
    std::vector<TextString>                    strings;
    std::vector<std::string>                   warnings;
    uint32_t header_padding = 0;
    uint32_t entry_padding  = 0;

    // ---- I/O ----
    void open(const std::string& path);
    void open_bytes(const uint8_t* data, size_t length);
    void save(const std::string& path) const;

    /// Serialize to a byte buffer (equivalent to Python's serialize()).
    std::vector<uint8_t> serialize() const;

    /// Export entries + strings as JSON to path + ".TEXT.json".
    void export_text(const std::string& path) const;

    /// Import entries + strings from a ".TEXT.json" file.
    void import_text(const std::string& json_path);

private:
    void _parse(std::istream& f, std::streamsize file_size);
    void _serialize_to_stream(std::ostream& f) const;

    void warn(const std::string& msg);
};

} // namespace nge2
