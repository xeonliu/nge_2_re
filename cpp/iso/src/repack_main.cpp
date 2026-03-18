/// nge2-repack-iso  –  Repack modified files into a PSP UMD/ISO image
///                     (mirrors scripts/pack/repack.py)

#include "nge2/iso9660.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace nge2::iso9660;

static constexpr uint32_t SEC = SECTOR_SIZE;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static uint32_t read_le32_at_pos(std::fstream& f, uint64_t pos) {
    f.seekg(static_cast<std::streamoff>(pos));
    uint8_t buf[4] = {};
    f.read(reinterpret_cast<char*>(buf), 4);
    return static_cast<uint32_t>(buf[0]) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

static void write_le32_at_pos(std::fstream& f, uint64_t pos, uint32_t value) {
    f.seekp(static_cast<std::streamoff>(pos));
    uint8_t buf[4] = {
        static_cast<uint8_t>(value),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 24)
    };
    f.write(reinterpret_cast<const char*>(buf), 4);
}

static void write_be32_at_pos(std::fstream& f, uint64_t pos, uint32_t value) {
    f.seekp(static_cast<std::streamoff>(pos));
    uint8_t buf[4] = {
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value)
    };
    f.write(reinterpret_cast<const char*>(buf), 4);
}

// ---------------------------------------------------------------------------
// File entry
// ---------------------------------------------------------------------------

struct ISOFileEntry {
    fs::path   realpath;
    std::string isopath;
    uint64_t   dir_record_pos      = 0;
    uint32_t   original_extent_lba = 0;
    uint32_t   original_size       = 0;
    uint32_t   new_extent_lba      = 0;
    uint32_t   new_size            = 0;
};

// ---------------------------------------------------------------------------
// Normalise an ISO path component for comparison
// ---------------------------------------------------------------------------

static std::string normalise(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    auto semi = out.rfind(';');
    if (semi != std::string::npos) out.erase(semi);
    return out;
}

// ---------------------------------------------------------------------------
// Main repack logic
// ---------------------------------------------------------------------------

static void repack_umd(const std::string& input_iso,
                       const std::string& output_iso,
                       const std::string& workfolder,
                       uint32_t sector_padding = 1) {

    // Collect files from workfolder
    std::vector<ISOFileEntry> entries;
    for (const auto& p : fs::recursive_directory_iterator(workfolder)) {
        if (!p.is_regular_file()) continue;
        if (p.path().filename().string().front() == '.') continue;

        std::string rel = "/" +
            fs::relative(p.path(), workfolder).generic_string();
        // replace backslashes (Windows)
        for (char& c : rel) if (c == '\\') c = '/';

        ISOFileEntry e;
        e.realpath = p.path();
        e.isopath  = rel;
        entries.push_back(e);
    }
    std::sort(entries.begin(), entries.end(),
              [](const ISOFileEntry& a, const ISOFileEntry& b) {
                  return a.isopath < b.isopath;
              });

    if (entries.empty()) {
        std::cerr << "No files found in workfolder: " << workfolder << "\n";
        return;
    }

    // Open original ISO read-only to locate directory records
    {
        std::ifstream fin(input_iso, std::ios::binary);
        if (!fin) throw std::runtime_error("Cannot open ISO: " + input_iso);

        auto [root_lba, root_len] = read_pvd_root(fin);

        // Build map: normalised_isopath → (dir_record_pos, extent_lba, size)
        std::map<std::string, std::tuple<uint64_t, uint32_t, uint32_t>> iso_map;

        walk_files(fin, root_lba, root_len, "",
            [&](const std::string& iso_path, uint32_t lba, uint32_t sz,
                uint64_t drpos) {
                iso_map[normalise(iso_path)] = {drpos, lba, sz};
            });

        for (auto& e : entries) {
            auto key = normalise(e.isopath);
            auto it = iso_map.find(key);
            if (it == iso_map.end())
                throw std::runtime_error("File not found in ISO: " + e.isopath);

            auto [drpos, lba, sz] = it->second;
            e.dir_record_pos      = drpos;
            e.original_extent_lba = lba;
            e.original_size       = sz;

            std::cout << "Found " << e.isopath
                      << " lba=" << lba << " size=" << sz << "\n";
        }
    }

    // Sort by original LBA
    std::sort(entries.begin(), entries.end(),
              [](const ISOFileEntry& a, const ISOFileEntry& b) {
                  return a.original_extent_lba < b.original_extent_lba;
              });

    // Copy ISO and patch it
    {
        // Get original ISO size
        std::ifstream src(input_iso, std::ios::binary | std::ios::ate);
        if (!src) throw std::runtime_error("Cannot re-open ISO: " + input_iso);
        uint64_t original_total = static_cast<uint64_t>(src.tellg());
        src.seekg(0);

        // Write to output (copy everything up to first file content)
        std::ofstream dst(output_iso, std::ios::binary);
        if (!dst) throw std::runtime_error("Cannot create output: " + output_iso);

        uint64_t first_content_off =
            static_cast<uint64_t>(entries[0].original_extent_lba) * SEC;

        // Copy header
        std::vector<char> hdr(static_cast<size_t>(first_content_off));
        src.read(hdr.data(), static_cast<std::streamsize>(first_content_off));
        dst.write(hdr.data(), static_cast<std::streamsize>(first_content_off));
        dst.flush();

        // Re-open output as read/write for in-place updates
        dst.close();
        std::fstream fout(output_iso,
                          std::ios::in | std::ios::out | std::ios::binary);
        if (!fout) throw std::runtime_error("Cannot open output r/w: " + output_iso);

        fout.seekp(0, std::ios::end);

        for (auto& e : entries) {
            uint64_t cur_offset = static_cast<uint64_t>(fout.tellp());
            uint64_t orig_off   = static_cast<uint64_t>(e.original_extent_lba) * SEC;

            if (cur_offset < orig_off) {
                // Seek to the original LBA
                fout.seekp(static_cast<std::streamoff>(orig_off));
            }

            uint64_t write_start = static_cast<uint64_t>(fout.tellp());
            std::cout << "Writing " << e.isopath
                      << " at offset 0x" << std::hex << write_start
                      << std::dec << "\n";

            // Write file bytes
            std::ifstream sf(e.realpath, std::ios::binary);
            if (!sf) throw std::runtime_error("Cannot open: " + e.realpath.string());
            const uint32_t CHUNK = 65536;
            std::vector<char> buf(CHUNK);
            while (sf) {
                sf.read(buf.data(), CHUNK);
                auto n = sf.gcount();
                if (n > 0) fout.write(buf.data(), n);
            }

            uint64_t write_end = static_cast<uint64_t>(fout.tellp());
            uint32_t new_size  = static_cast<uint32_t>(write_end - write_start);

            // Pad to sector_padding boundary
            uint64_t pad_unit  = static_cast<uint64_t>(sector_padding) * SEC;
            uint64_t next_bnd  = ((write_end / pad_unit) + 1) * pad_unit;
            if (next_bnd > write_end) {
                fout.seekp(static_cast<std::streamoff>(next_bnd - 1));
                fout.write("\x00", 1);
            }

            e.new_extent_lba = static_cast<uint32_t>(write_start / SEC);
            e.new_size       = new_size;

            // Update directory record: +2 = extent_lba LE, +0x0A = size LE, +0x0E = size BE
            write_le32_at_pos(fout, e.dir_record_pos + 2,    e.new_extent_lba);
            write_le32_at_pos(fout, e.dir_record_pos + 0x0A, e.new_size);
            write_be32_at_pos(fout, e.dir_record_pos + 0x0E, e.new_size);

            std::cout << "  Updated dir record @0x" << std::hex
                      << e.dir_record_pos << " lba=" << e.new_extent_lba
                      << " size=" << e.new_size << std::dec << "\n";
        }

        // Ensure output is at least as large as original
        uint64_t cur_size = static_cast<uint64_t>(fout.seekp(0, std::ios::end).tellp());
        if (cur_size < original_total) {
            fout.seekp(static_cast<std::streamoff>(original_total - 1));
            fout.write("\x00", 1);
        }

        // Update PVD volume space size at 0x8050 (LE) and 0x8054 (BE)
        fout.seekp(0, std::ios::end);
        uint32_t final_sectors = static_cast<uint32_t>(
            static_cast<uint64_t>(fout.tellp()) / SEC);
        write_le32_at_pos(fout, 0x8050, final_sectors);
        write_be32_at_pos(fout, 0x8054, final_sectors);

        std::cout << "Updated PVD volume space = " << final_sectors << " sectors.\n";
    }

    std::cout << "Repack done: " << output_iso << "\n";
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog
        << " <input_iso> <output_iso> <workfolder> [--sector-padding N]\n"
        << "\n"
        << "  input_iso      Original UMD/ISO image.\n"
        << "  output_iso     Destination for patched ISO.\n"
        << "  workfolder     Directory whose files will replace those in the ISO.\n"
        << "  --sector-padding N  Pad files to N-sector boundaries (default: 1).\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) { print_usage(argv[0]); return 1; }

    std::string input_iso  = argv[1];
    std::string output_iso = argv[2];
    std::string workfolder = argv[3];
    uint32_t sector_padding = 1;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--sector-padding" && i + 1 < argc)
            sector_padding = static_cast<uint32_t>(std::stoul(argv[++i]));
    }

    try {
        repack_umd(input_iso, output_iso, workfolder, sector_padding);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
