#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace nge2 {
namespace iso9660 {

static constexpr uint32_t SECTOR_SIZE = 2048u;

/// Minimal ISO 9660 directory-record as we need it.
struct DirRecord {
    uint8_t  record_length   = 0;
    uint32_t extent_lba      = 0;   ///< Location of extent (LE uint32).
    uint32_t data_length     = 0;   ///< Data length in bytes (LE uint32).
    uint8_t  flags           = 0;   ///< Bit 1 = directory.
    std::string name;               ///< Decoded, version suffix stripped.
    bool     is_directory    = false;
    uint64_t abs_record_pos  = 0;   ///< Absolute byte offset of this record in the image.
};

/// Callback signature: (iso_path, file_abs_offset_in_iso, file_size_bytes)
using FileCallback = std::function<void(const std::string& iso_path,
                                        uint32_t extent_lba,
                                        uint32_t data_length,
                                        uint64_t dir_record_abs_pos)>;

/// Read the Primary Volume Descriptor and return (root_lba, root_length).
std::pair<uint32_t, uint32_t> read_pvd_root(std::istream& iso);

/// Recursively iterate every file record in the ISO, calling cb for each file.
void walk_files(std::istream& iso,
                uint32_t dir_lba, uint32_t dir_length,
                const std::string& current_path,
                const FileCallback& cb);

/// Strip ISO9660 version suffix (";1") and trim trailing NUL.
std::string strip_version_suffix(const std::string& name);

} // namespace iso9660
} // namespace nge2
