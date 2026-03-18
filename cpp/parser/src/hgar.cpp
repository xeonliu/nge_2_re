#include "nge2/hgar.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifdef NGE2_USE_OPENMP
#  include <omp.h>
#endif

namespace nge2 {

// ---------------------------------------------------------------------------
// HGArchiveFile
// ---------------------------------------------------------------------------

std::string HGArchiveFile::get_viable_name() const {
    auto strip_and_split = [](const std::vector<uint8_t>& raw,
                               std::string& base, std::string& ext) {
        // Trim trailing nulls, spaces, CR, LF, TAB
        auto last = raw.rbegin();
        while (last != raw.rend() &&
               (*last == 0 || *last == ' ' || *last == '\r' ||
                *last == '\n' || *last == '\t'))
            ++last;
        std::string s(raw.begin(), last.base());

        auto dot = s.rfind('.');
        if (dot != std::string::npos) {
            base = s.substr(0, dot);
            ext  = s.substr(dot + 1);
        } else {
            base = s;
            ext  = "";
        }
    };

    std::string long_base, long_ext, short_base, short_ext;

    if (!long_name.empty())
        strip_and_split(long_name, long_base, long_ext);

    if (!short_name.empty())
        strip_and_split(short_name, short_base, short_ext);

    std::string file_name, file_format;

    if (long_base.empty() || long_base == short_base)
        file_name = short_base;
    else
        file_name = long_base + "#" + short_base;

    if (long_ext.empty() || long_ext == short_ext)
        file_format = short_ext;
    else
        file_format = short_ext + "#" + long_ext;

    if (file_format.empty())
        file_format = "NOEXT";

    return file_name + "#id" + std::to_string(identifier) + "." + file_format;
}

void HGArchiveFile::decode_identifier(uint32_t limit) {
    is_compressed = ((encoded_identifier >> 31) == 1u);

    uint32_t xor_mask   = encoded_identifier & 0x7FFFFFFFu;
    uint32_t mult_result = 0;

    for (int rounds = 6; rounds > 0; --rounds) {
        mult_result = static_cast<uint32_t>(
            (static_cast<uint64_t>(mult_result ^ xor_mask) * 0x3D09u) &
            0xFFFFFFFFu);
        xor_mask >>= 5;
    }

    mult_result &= (limit - 1u);
    identifier = mult_result;
}

void HGArchiveFile::encode_identifier(uint32_t limit) {
    const uint32_t compression_mask = is_compressed ? 0x80000000u : 0u;

#ifdef NGE2_USE_OPENMP
    uint32_t found = 0;
    bool     done  = false;

#   pragma omp parallel for schedule(dynamic, 4096) shared(found, done)
    for (int64_t guess = 0x7FFFFFFFll; guess > 0; --guess) {
#       pragma omp flush(done)
        if (done) continue;

        uint32_t xor_mask   = static_cast<uint32_t>(guess) & 0x7FFFFFFFu;
        uint32_t mult_result = 0;

        for (int rounds = 6; rounds > 0; --rounds) {
            mult_result = static_cast<uint32_t>(
                (static_cast<uint64_t>(mult_result ^ xor_mask) * 0x3D09u) &
                0xFFFFFFFFu);
            xor_mask >>= 5;
        }

        mult_result &= (limit - 1u);
        if (mult_result == identifier) {
#           pragma omp critical
            {
                if (!done) {
                    found = static_cast<uint32_t>(guess) | compression_mask;
                    done  = true;
                }
            }
        }
    }

    if (done) {
        encoded_identifier = found;
        return;
    }
#else
    for (uint32_t guess = 0x7FFFFFFFu; guess > 0; --guess) {
        uint32_t xor_mask    = guess & 0x7FFFFFFFu;
        uint32_t mult_result = 0;

        for (int rounds = 6; rounds > 0; --rounds) {
            mult_result = static_cast<uint32_t>(
                (static_cast<uint64_t>(mult_result ^ xor_mask) * 0x3D09u) &
                0xFFFFFFFFu);
            xor_mask >>= 5;
        }

        mult_result &= (limit - 1u);
        if (mult_result == identifier) {
            encoded_identifier = guess | compression_mask;
            return;
        }
    }
#endif

    throw std::runtime_error("encode_identifier: no valid encoding found");
}

// ---------------------------------------------------------------------------
// HGArchive
// ---------------------------------------------------------------------------

void HGArchive::calculate_identifier_limit() {
    uint32_t n = static_cast<uint32_t>(files.size());
    uint32_t limit = 16;
    while (n > limit) {
        limit *= 2;
        if (limit > 32768) { limit = 32768; break; }
    }
    identifier_limit = 2 * limit;
}

void HGArchive::decode_identifiers() {
    for (auto& f : files)
        f.decode_identifier(identifier_limit);
}

void HGArchive::open(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path);

    // Store filename for later use
    filename = std::filesystem::path(path).filename().string();

    // Magic
    char magic[4] = {};
    f.read(magic, 4);
    if (std::strncmp(magic, "HGAR", 4) != 0)
        throw std::runtime_error("Not an HGAR file: " + path);

    version = static_cast<int>(read_uint16_le(f));
    if (version != 1 && version != 3)
        throw std::runtime_error("Unknown HGAR version: " + std::to_string(version));

    uint16_t num_files = read_uint16_le(f);
    files.clear();
    files.resize(num_files);

    std::vector<uint32_t> file_header_offsets(num_files);
    for (uint32_t i = 0; i < num_files; ++i)
        file_header_offsets[i] = read_uint32_le(f);

    std::vector<std::pair<uint32_t, uint32_t>> file_unknowns(num_files, {0, 0});
    std::vector<std::vector<uint8_t>> file_long_names(num_files);

    if (version == 3) {
        for (uint32_t i = 0; i < num_files; ++i) {
            file_unknowns[i].first  = read_uint32_le(f);
            file_unknowns[i].second = read_uint32_le(f);
        }

        for (uint32_t i = 0; i < num_files; ++i) {
            uint32_t file_number = read_uint32_le(f);

            // Read null-terminated name aligned to 4-byte boundaries
            std::vector<uint8_t> long_name;
            while (true) {
                uint8_t chunk[4] = {};
                f.read(reinterpret_cast<char*>(chunk), 4);
                long_name.insert(long_name.end(), chunk, chunk + 4);
                if (long_name.back() == 0) break;
            }
            file_long_names[i] = long_name;

            if (file_number != i) {
                std::cerr << "\tWarning: File stored as #" << file_number
                          << " but expected #" << i << "\n";
            }
        }
    }

    for (uint32_t i = 0; i < num_files; ++i) {
        f.seekg(file_header_offsets[i]);

        // Short name: 12 bytes (8 name + 4 ext area, though last 4 may hold ext)
        uint8_t short_name_raw[0xC] = {};
        f.read(reinterpret_cast<char*>(short_name_raw), 0xC);

        // Mimic Python: short_name[0:-4].rstrip() + short_name[-4:].rstrip()
        // Trim trailing spaces/nulls from first 8 bytes, then from last 4 bytes
        auto rstrip = [](uint8_t* begin, uint8_t* end) -> uint8_t* {
            while (end > begin && (*(end-1) == ' ' || *(end-1) == 0)) --end;
            return end;
        };
        auto* p8_end  = rstrip(short_name_raw,       short_name_raw + 8);
        auto* p4_end  = rstrip(short_name_raw + 8,   short_name_raw + 12);

        std::vector<uint8_t> short_name(short_name_raw, p8_end);
        short_name.insert(short_name.end(), short_name_raw + 8, p4_end);

        uint32_t enc_id   = read_uint32_le(f);
        uint32_t file_size = read_uint32_le(f);

        auto& file = files[i];
        file.short_name         = short_name;
        file.long_name          = file_long_names[i];
        file.size               = file_size;
        file.encoded_identifier = enc_id;
        file.unknown_first      = file_unknowns[i].first;
        file.unknown_last       = file_unknowns[i].second;

        file.content.resize(file_size);
        f.read(reinterpret_cast<char*>(file.content.data()), file_size);
    }

    calculate_identifier_limit();
    decode_identifiers();
}

void HGArchive::save(const std::string& path) {
    std::ofstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file for writing: " + path);

    f.write("HGAR", 4);
    write_uint16_le(f, static_cast<uint16_t>(version));

    uint16_t num_files = static_cast<uint16_t>(files.size());
    write_uint16_le(f, num_files);

    // Calculate header size
    uint32_t header_size = 4 + 2 + 2 + 4 * num_files;
    if (version == 3) {
        header_size += 8 * num_files;  // unknowns
        for (const auto& file : files)
            header_size += 4 + static_cast<uint32_t>(file.long_name.size());
    }

    // Write file start offsets
    uint32_t file_offset = header_size;
    for (const auto& file : files) {
        write_uint32_le(f, file_offset);
        file_offset += 0xC + 4 + 4;  // short_name + encoded_identifier + size
        file_offset += calculate_word_aligned_length(file.size);
    }

    if (version == 3) {
        for (const auto& file : files) {
            write_uint32_le(f, file.unknown_first);
            write_uint32_le(f, file.unknown_last);
        }
        for (uint32_t i = 0; i < num_files; ++i) {
            write_uint32_le(f, i);
            f.write(reinterpret_cast<const char*>(files[i].long_name.data()),
                    static_cast<std::streamsize>(files[i].long_name.size()));
        }
    }

    for (auto& file : files) {
        // Format short name as 8.3 (pad with spaces)
        // Split at '.' in short_name
        std::string sn(file.short_name.begin(), file.short_name.end());
        std::string sn_name, sn_ext;
        {
            auto dot = sn.find('.');
            if (dot != std::string::npos) {
                sn_name = sn.substr(0, dot);
                sn_ext  = sn.substr(dot + 1);
            } else {
                sn_name = sn;
                sn_ext  = "";
            }
        }
        // Pad to 8 + 1 + 3 = 12 bytes
        char formatted[12];
        std::memset(formatted, ' ', sizeof(formatted));
        std::memcpy(formatted,     sn_name.c_str(), std::min<size_t>(sn_name.size(), 8));
        formatted[8] = '.';
        std::memcpy(formatted + 9, sn_ext.c_str(),  std::min<size_t>(sn_ext.size(),  3));
        f.write(formatted, 12);

        // Encoded identifier: encode if needed
        if (file.encoded_identifier == 0 && file.identifier != 0) {
            file.encode_identifier(identifier_limit);
        }
        write_uint32_le(f, file.encoded_identifier);
        write_uint32_le(f, file.size);

        f.write(reinterpret_cast<const char*>(file.content.data()),
                static_cast<std::streamsize>(file.size));

        // Pad to 4-byte alignment
        uint32_t padding = calculate_word_aligned_length(file.size) - file.size;
        if (padding > 0 && padding < 4) {
            static const char zeros[4] = {};
            f.write(zeros, padding);
        }
    }
}

void HGArchive::extract(const std::string& output_dir) const {
    namespace fs = std::filesystem;
    fs::create_directories(output_dir);

    for (const auto& file : files) {
        std::string out_path = output_dir + "/" + file.get_viable_name();
        std::ofstream out(out_path, std::ios::binary);
        if (!out)
            throw std::runtime_error("Cannot write: " + out_path);
        out.write(reinterpret_cast<const char*>(file.content.data()),
                  static_cast<std::streamsize>(file.content.size()));
        std::cout << "Extracted: " << file.get_viable_name() << "\n";
    }
}

void HGArchive::info() const {
    std::cout << "Version:           " << version << "\n";
    std::cout << "Number of files:   " << files.size() << "\n";
    std::cout << "Identifier limit:  0x" << std::hex << identifier_limit
              << std::dec << "\n";
    for (const auto& file : files) {
        std::cout << "  " << file.get_viable_name()
                  << "  size=" << file.size
                  << "  compressed=" << (file.is_compressed ? "yes" : "no")
                  << "\n";
    }
}

} // namespace nge2
