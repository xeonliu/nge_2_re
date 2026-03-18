/// nge2-unpack-iso  –  Extract files from an ISO9660 image (mirrors scripts/pack/unpack.py)

#include "nge2/iso9660.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace nge2::iso9660;

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <iso_file> -o <output_dir> [--keep-version]\n"
        << "\n"
        << "  iso_file       Path to the ISO9660 image.\n"
        << "  -o <dir>       Directory to extract files into.\n"
        << "  --keep-version Keep the ISO9660 ';1' version suffix on filenames.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) { print_usage(argv[0]); return 1; }

    std::string iso_path;
    std::string out_dir;
    bool keep_version = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            out_dir = argv[++i];
        } else if (arg == "--keep-version") {
            keep_version = true;
        } else {
            iso_path = arg;
        }
    }

    if (iso_path.empty() || out_dir.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    try {
        std::ifstream iso(iso_path, std::ios::binary);
        if (!iso) throw std::runtime_error("Cannot open ISO: " + iso_path);

        auto [root_lba, root_len] = read_pvd_root(iso);

        uint64_t files_extracted = 0;

        walk_files(iso, root_lba, root_len, "",
            [&](const std::string& iso_path_entry,
                uint32_t extent_lba, uint32_t data_length,
                uint64_t /*dir_record_pos*/) {

                // Build local output path
                // Strip leading '/'
                std::string rel = iso_path_entry;
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);

                if (!keep_version)
                    rel = strip_version_suffix(rel);

                fs::path out_file = fs::path(out_dir) / rel;
                fs::create_directories(out_file.parent_path());

                std::cout << "Extracting: " << rel << "\n";

                // Seek to file data and copy
                iso.seekg(static_cast<std::streamoff>(
                    static_cast<uint64_t>(extent_lba) * SECTOR_SIZE));

                std::ofstream out(out_file, std::ios::binary);
                if (!out)
                    throw std::runtime_error("Cannot write: " + out_file.string());

                const uint32_t CHUNK = 65536;
                std::vector<char> buf(CHUNK);
                uint32_t remaining = data_length;
                while (remaining > 0) {
                    uint32_t to_read = std::min(remaining, CHUNK);
                    iso.read(buf.data(), to_read);
                    out.write(buf.data(), iso.gcount());
                    remaining -= static_cast<uint32_t>(iso.gcount());
                    if (iso.gcount() == 0) break;
                }

                ++files_extracted;
            });

        std::cout << "Extraction complete. " << files_extracted << " file(s) extracted.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
