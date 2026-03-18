#include "nge2/bind.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace nge2 {

void BindArchive::add_entry(const std::vector<uint8_t>& content) {
    entries.push_back({content});
}

void BindArchive::open(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + path);

    char magic[4] = {};
    f.read(magic, 4);
    if (std::strncmp(magic, "BIND", 4) != 0)
        throw std::runtime_error("Not a BIND file: " + path);

    size_byte_size = read_uint16_le(f);
    if (size_byte_size != 1 && size_byte_size != 2 && size_byte_size != 4)
        throw std::runtime_error("Illegal BIND size_byte_size: " +
                                 std::to_string(size_byte_size));

    uint16_t num_entries = read_uint16_le(f);
    block_size = read_uint32_le(f);
    uint32_t header_size = read_uint32_le(f);

    // Read each entry's size
    std::vector<std::pair<uint32_t, uint32_t>> processed; // (offset, size)
    uint32_t prev_end = header_size;
    for (uint16_t i = 0; i < num_entries; ++i) {
        uint32_t entry_offset = prev_end;
        uint32_t entry_size   = 0;

        if (size_byte_size == 1)
            entry_size = read_uint8(f);
        else if (size_byte_size == 2)
            entry_size = read_uint16_le(f);
        else
            entry_size = read_uint32_le(f);

        uint32_t padded = align_size(entry_size, block_size);
        prev_end += padded;

        processed.emplace_back(entry_offset, entry_size);
    }

    entries.clear();
    for (const auto& [off, sz] : processed) {
        f.seekg(off);
        std::vector<uint8_t> content(sz);
        f.read(reinterpret_cast<char*>(content.data()), sz);
        entries.push_back({std::move(content)});
    }
}

void BindArchive::save(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open for writing: " + path);

    f.write("BIND", 4);
    write_uint16_le(f, size_byte_size);

    uint16_t n = static_cast<uint16_t>(entries.size());
    write_uint16_le(f, n);
    write_uint32_le(f, block_size);

    // header_size = align(16 + n*size_byte_size, block_size)
    uint32_t raw_header = 16u + n * size_byte_size;
    uint32_t header_size = align_size(raw_header, block_size);
    write_uint32_le(f, header_size);

    for (const auto& entry : entries) {
        if (size_byte_size == 1)
            write_uint8(f, static_cast<uint8_t>(entry.get_size()));
        else if (size_byte_size == 2)
            write_uint16_le(f, static_cast<uint16_t>(entry.get_size()));
        else
            write_uint32_le(f, entry.get_size());
    }

    // Pad header
    uint32_t pad_count = header_size - raw_header;
    std::vector<uint8_t> zeros(pad_count, 0);
    f.write(reinterpret_cast<const char*>(zeros.data()),
            static_cast<std::streamsize>(zeros.size()));

    for (const auto& entry : entries) {
        uint32_t sz        = entry.get_size();
        uint32_t padded_sz = align_size(sz, block_size);

        f.write(reinterpret_cast<const char*>(entry.content.data()),
                static_cast<std::streamsize>(sz));

        uint32_t pad = padded_sz - sz;
        if (pad > 0) {
            std::vector<uint8_t> p(pad, 0);
            f.write(reinterpret_cast<const char*>(p.data()),
                    static_cast<std::streamsize>(p.size()));
        }
    }
}

void BindArchive::unpack(const std::string& dir) const {
    namespace fs = std::filesystem;
    fs::create_directories(dir);

    for (size_t i = 0; i < entries.size(); ++i) {
        std::string out = dir + "/" + std::to_string(i) + ".bin";
        std::cout << "#\tWriting " << out << "\n";
        std::ofstream f(out, std::ios::binary);
        if (!f) throw std::runtime_error("Cannot write: " + out);
        f.write(reinterpret_cast<const char*>(entries[i].content.data()),
                static_cast<std::streamsize>(entries[i].content.size()));
    }
}

void BindArchive::pack(const std::string& dir) {
    entries.clear();
    for (size_t i = 0; ; ++i) {
        std::string in = dir + "/" + std::to_string(i) + ".bin";
        std::cout << "#\tReading " << in << "\n";
        std::ifstream f(in, std::ios::binary);
        if (!f) { std::cout << "#\t\tDoesn't exist, no more files to pack\n"; break; }
        std::vector<uint8_t> content((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
        entries.push_back({std::move(content)});
    }
}

} // namespace nge2
