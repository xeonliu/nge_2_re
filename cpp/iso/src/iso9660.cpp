#include "nge2/iso9660.hpp"

#include <cstring>
#include <istream>
#include <stdexcept>

namespace nge2 {
namespace iso9660 {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static uint32_t read_le32_at(const uint8_t* buf, size_t off) {
    return static_cast<uint32_t>(buf[off]) |
           (static_cast<uint32_t>(buf[off+1]) << 8) |
           (static_cast<uint32_t>(buf[off+2]) << 16) |
           (static_cast<uint32_t>(buf[off+3]) << 24);
}

std::string strip_version_suffix(const std::string& name) {
    // Remove trailing NUL
    std::string s = name;
    while (!s.empty() && s.back() == '\0') s.pop_back();
    // Strip ";1" (or ";NNN")
    auto semi = s.rfind(';');
    if (semi != std::string::npos) s.erase(semi);
    return s;
}

// ---------------------------------------------------------------------------
// PVD
// ---------------------------------------------------------------------------

std::pair<uint32_t, uint32_t> read_pvd_root(std::istream& iso) {
    // PVD is at sector 16 (byte offset 0x8000).
    // Root directory record starts at 0x8000 + 0x9E = 0x809E.
    // Extent LBA  (LE uint32) at PVD+0x9E
    // Data length (LE uint32) at PVD+0xA6

    iso.seekg(0x8000);
    uint8_t pvd[2048] = {};
    iso.read(reinterpret_cast<char*>(pvd), 2048);
    if (!iso)
        throw std::runtime_error("Failed to read Primary Volume Descriptor");

    // Descriptor type must be 1 (Primary Volume Descriptor)
    if (pvd[0] != 0x01)
        throw std::runtime_error("Sector 16 is not a Primary Volume Descriptor");

    uint32_t root_lba    = read_le32_at(pvd, 0x9E);
    uint32_t root_length = read_le32_at(pvd, 0xA6);
    return {root_lba, root_length};
}

// ---------------------------------------------------------------------------
// Directory walking
// ---------------------------------------------------------------------------

static DirRecord parse_record(const uint8_t* data, size_t rec_offset,
                               uint64_t dir_abs_base) {
    DirRecord r;
    r.record_length  = data[rec_offset + 0];
    if (r.record_length == 0) return r;

    r.extent_lba    = read_le32_at(data, rec_offset + 2);
    r.data_length   = read_le32_at(data, rec_offset + 10);
    r.flags         = data[rec_offset + 25];
    r.is_directory  = (r.flags & 0x02) != 0;

    uint8_t file_id_len = data[rec_offset + 32];
    std::string fid(reinterpret_cast<const char*>(data + rec_offset + 33),
                    file_id_len);
    r.name = strip_version_suffix(fid);
    r.abs_record_pos = dir_abs_base + rec_offset;
    return r;
}

void walk_files(std::istream& iso,
                uint32_t dir_lba, uint32_t dir_length,
                const std::string& current_path,
                const FileCallback& cb) {
    // Read the entire directory extent
    uint64_t dir_byte_off = static_cast<uint64_t>(dir_lba) * SECTOR_SIZE;
    iso.seekg(static_cast<std::streamoff>(dir_byte_off));
    std::vector<uint8_t> dir_data(dir_length);
    iso.read(reinterpret_cast<char*>(dir_data.data()), dir_length);
    if (!iso)
        throw std::runtime_error("Failed to read directory sector at LBA " +
                                 std::to_string(dir_lba));

    size_t i = 0;
    while (i < dir_length) {
        uint8_t rec_len = dir_data[i];
        if (rec_len == 0) {
            // Advance to next sector boundary
            size_t next = ((i / SECTOR_SIZE) + 1) * SECTOR_SIZE;
            if (next <= i) break;
            i = next;
            continue;
        }
        if (i + rec_len > dir_length) break;

        DirRecord rec = parse_record(dir_data.data(), i, dir_byte_off);
        i += rec_len;

        // Skip "." and ".." entries (single 0x00 or 0x01 byte identifiers)
        if (rec.name.size() == 1 &&
            (static_cast<uint8_t>(rec.name[0]) == 0x00 ||
             static_cast<uint8_t>(rec.name[0]) == 0x01))
            continue;

        if (rec.name.empty()) continue;

        std::string entry_path = current_path + "/" + rec.name;

        if (rec.is_directory) {
            walk_files(iso, rec.extent_lba, rec.data_length, entry_path, cb);
        } else {
            cb(entry_path, rec.extent_lba, rec.data_length, rec.abs_record_pos);
        }
    }
}

} // namespace iso9660
} // namespace nge2
