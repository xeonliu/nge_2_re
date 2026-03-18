/// Unit tests for the nge2_parser library
///
/// Uses a minimal "Catch2-style" hand-rolled test harness so that there are
/// no external dependencies required to run the tests.

#include "nge2/bind.hpp"
#include "nge2/common.hpp"
#include "nge2/hgar.hpp"
#include "nge2/text.hpp"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

// Cross-platform helper: return a unique temp path for a given base name.
static std::string tmpfile(const char* name) {
    return (std::filesystem::temp_directory_path() / name).string();
}

// ---------------------------------------------------------------------------
// Tiny test framework
// ---------------------------------------------------------------------------

static int g_failed = 0;
static int g_passed = 0;

#define SECTION(name) \
    std::cout << "[ TEST ] " << name << "\n"

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "  FAIL  " << __FILE__ << ":" << __LINE__ \
                      << "  " << #expr << "\n"; \
            ++g_failed; \
        } else { \
            ++g_passed; \
        } \
    } while (0)

#define CHECK_THROW(expr) \
    do { \
        bool threw = false; \
        try { expr; } catch (...) { threw = true; } \
        if (!threw) { \
            std::cerr << "  FAIL  " << __FILE__ << ":" << __LINE__ \
                      << "  expected exception from: " << #expr << "\n"; \
            ++g_failed; \
        } else { \
            ++g_passed; \
        } \
    } while (0)

// ---------------------------------------------------------------------------
// common.hpp tests
// ---------------------------------------------------------------------------

static void test_common() {
    SECTION("read/write uint8");
    {
        std::ostringstream out(std::ios::binary);
        nge2::write_uint8(out, 0xAB);
        std::istringstream in(out.str(), std::ios::binary);
        CHECK(nge2::read_uint8(in) == 0xABu);
    }

    SECTION("read/write uint16_le");
    {
        std::ostringstream out(std::ios::binary);
        nge2::write_uint16_le(out, 0x1234);
        std::string s = out.str();
        CHECK(static_cast<uint8_t>(s[0]) == 0x34);
        CHECK(static_cast<uint8_t>(s[1]) == 0x12);
        std::istringstream in(s, std::ios::binary);
        CHECK(nge2::read_uint16_le(in) == 0x1234u);
    }

    SECTION("read/write uint32_le");
    {
        std::ostringstream out(std::ios::binary);
        nge2::write_uint32_le(out, 0xDEADBEEFu);
        std::string s = out.str();
        CHECK(static_cast<uint8_t>(s[0]) == 0xEF);
        CHECK(static_cast<uint8_t>(s[1]) == 0xBE);
        CHECK(static_cast<uint8_t>(s[2]) == 0xAD);
        CHECK(static_cast<uint8_t>(s[3]) == 0xDE);
        std::istringstream in(s, std::ios::binary);
        CHECK(nge2::read_uint32_le(in) == 0xDEADBEEFu);
    }

    SECTION("calculate_word_aligned_length");
    {
        CHECK(nge2::calculate_word_aligned_length(0) == 0);
        CHECK(nge2::calculate_word_aligned_length(1) == 4);
        CHECK(nge2::calculate_word_aligned_length(4) == 4);
        CHECK(nge2::calculate_word_aligned_length(5) == 8);
    }

    SECTION("align_size");
    {
        CHECK(nge2::align_size(0, 2048) == 0);
        CHECK(nge2::align_size(1, 2048) == 2048);
        CHECK(nge2::align_size(2048, 2048) == 2048);
        CHECK(nge2::align_size(2049, 2048) == 4096);
    }

    SECTION("zero_pad_and_align_string");
    {
        // len=3 → padded to 4*(3+4)/4 = 4*(1) = 4? No, Python: 4*int((3+4)/4) = 4*1 = 4
        // Actually Python: 4 * int((len(content) + 4) / 4)
        // len=3: 4 * int(7/4) = 4 * 1 = 4
        // len=4: 4 * int(8/4) = 4 * 2 = 8
        // len=5: 4 * int(9/4) = 4 * 2 = 8
        std::vector<uint8_t> v3 = {1, 2, 3};
        auto p3 = nge2::zero_pad_and_align_string(v3);
        CHECK(p3.size() == 4);
        CHECK(p3[3] == 0);

        std::vector<uint8_t> v4 = {1, 2, 3, 4};
        auto p4 = nge2::zero_pad_and_align_string(v4);
        CHECK(p4.size() == 8);

        std::vector<uint8_t> v5 = {1, 2, 3, 4, 5};
        auto p5 = nge2::zero_pad_and_align_string(v5);
        CHECK(p5.size() == 8);
    }
}

// ---------------------------------------------------------------------------
// BIND round-trip test
// ---------------------------------------------------------------------------

static std::string make_bind_bytes(uint16_t size_byte_size,
                                   uint32_t block_size,
                                   const std::vector<std::vector<uint8_t>>& entries) {
    nge2::BindArchive ba;
    ba.size_byte_size = size_byte_size;
    ba.block_size     = block_size;
    for (const auto& e : entries) ba.add_entry(e);

    std::ostringstream ss(std::ios::binary);
    // We serialize via a temp file using the system temp directory; since we want a string,
    // we save and re-read.
    const std::string tmp = tmpfile("nge2_test_bind.bin");
    ba.save(tmp);

    std::ifstream f(tmp, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

static void test_bind() {
    SECTION("BIND magic header");
    {
        auto bytes = make_bind_bytes(4, 16, {{0x01, 0x02}});
        CHECK(bytes.size() >= 4);
        CHECK(bytes.substr(0, 4) == "BIND");
    }

    SECTION("BIND round-trip (size_byte_size=4, block_size=16)");
    {
        std::vector<uint8_t> e1 = {0xAA, 0xBB, 0xCC};
        std::vector<uint8_t> e2 = {0x11, 0x22};
        auto bytes = make_bind_bytes(4, 16, {e1, e2});

        const std::string tmp = tmpfile("nge2_test_bind2.bin");
        {
            std::ofstream out(tmp, std::ios::binary);
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        }

        nge2::BindArchive loaded;
        loaded.open(tmp);
        CHECK(loaded.entries.size() == 2);
        CHECK(loaded.entries[0].content == e1);
        CHECK(loaded.entries[1].content == e2);
    }

    SECTION("BIND bad magic throws");
    {
        const std::string tmp = tmpfile("nge2_test_bind_bad.bin");
        {
            std::ofstream out(tmp, std::ios::binary);
            out.write("XXXX\x04\x00\x00\x00", 8);
        }
        nge2::BindArchive ba;
        CHECK_THROW(ba.open(tmp));
    }
}

// ---------------------------------------------------------------------------
// TEXT round-trip test
// ---------------------------------------------------------------------------

static void test_text() {
    SECTION("TEXT round-trip");
    {
        // Build a minimal TEXT file manually
        // Header: "TEXT" + num_entries(1) + header_size(16) + content_start(24)
        // Entry: unknown(0) + string_offset(24)
        // String: uf(0) + us(0) + "HELLO\0\0\0" (8 bytes, padded to 4)
        std::vector<uint8_t> raw;
        auto push32le = [&](uint32_t v) {
            raw.push_back(v & 0xFF);
            raw.push_back((v >> 8) & 0xFF);
            raw.push_back((v >> 16) & 0xFF);
            raw.push_back((v >> 24) & 0xFF);
        };
        // magic
        raw.push_back('T'); raw.push_back('E');
        raw.push_back('X'); raw.push_back('T');
        push32le(1);  // num_entries = 1
        push32le(16); // header_size = 16
        push32le(24); // content_start = 24 (16 header + 1*8 entries)

        // Entry table (1 entry, offset 0x0A bytes)
        push32le(0);   // unknown
        push32le(24);  // string_offset = 24 (= content_start)

        // String at offset 24: uf + us + "HI\0\0"
        push32le(0); // unknown_first
        push32le(0); // unknown_second
        raw.push_back('H'); raw.push_back('I');
        raw.push_back(0); raw.push_back(0); // null + pad to 4

        const std::string tmp = tmpfile("nge2_test_text.bin");
        {
            std::ofstream f(tmp, std::ios::binary);
            f.write(reinterpret_cast<const char*>(raw.data()),
                    static_cast<std::streamsize>(raw.size()));
        }

        nge2::TextArchive ta;
        ta.open(tmp);

        CHECK(ta.entries.size() == 1);
        CHECK(ta.strings.size() == 1);
        // The raw_content should be "HI" (trailing nulls stripped)
        CHECK(ta.strings[0].raw_content.size() == 2);
        CHECK(ta.strings[0].raw_content[0] == 'H');
        CHECK(ta.strings[0].raw_content[1] == 'I');

        // Round-trip: save and reload
        const std::string tmp2 = tmpfile("nge2_test_text_rt.bin");
        ta.save(tmp2);

        nge2::TextArchive ta2;
        ta2.open(tmp2);
        CHECK(ta2.entries.size() == 1);
        CHECK(ta2.strings.size() == 1);
        CHECK(ta2.strings[0].raw_content == ta.strings[0].raw_content);
    }

    SECTION("TEXT bad magic throws");
    {
        const std::string tmp = tmpfile("nge2_test_text_bad.bin");
        {
            std::ofstream f(tmp, std::ios::binary);
            f.write("NOPE", 4);
        }
        nge2::TextArchive ta;
        CHECK_THROW(ta.open(tmp));
    }
}

// ---------------------------------------------------------------------------
// HGAR round-trip test  (minimal V1 archive)
// ---------------------------------------------------------------------------

static void test_hgar() {
    SECTION("HGAR V1 round-trip");
    {
        // Build a minimal V1 HGAR archive with one file
        // Header: "HGAR" + version(1,u16) + num_files(1,u16) + offset(u32)
        // File entry at offset: short_name(12B) + enc_id(u32) + size(u32) + data

        nge2::HGArchive hgar;
        hgar.version = 1;
        hgar.files.clear();

        nge2::HGArchiveFile f;
        f.short_name = {'T','E','S','T','.','B','I','N'};
        f.size = 4;
        f.content = {0xDE, 0xAD, 0xBE, 0xEF};
        f.encoded_identifier = 0x1234ABCD;
        f.unknown_first = 0;
        f.unknown_last = 0;
        hgar.files.push_back(f);
        hgar.calculate_identifier_limit();
        hgar.decode_identifiers();

        const std::string tmp = tmpfile("nge2_test_hgar.har");
        hgar.save(tmp);

        nge2::HGArchive loaded;
        loaded.open(tmp);
        CHECK(loaded.version == 1);
        CHECK(loaded.files.size() == 1);
        CHECK(loaded.files[0].size == 4);
        CHECK(loaded.files[0].content == std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    }

    SECTION("HGAR bad magic throws");
    {
        const std::string tmp = tmpfile("nge2_test_hgar_bad.har");
        {
            std::ofstream out(tmp, std::ios::binary);
            out.write("XXXX", 4);
        }
        nge2::HGArchive ha;
        CHECK_THROW(ha.open(tmp));
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    test_common();
    test_bind();
    test_text();
    test_hgar();

    std::cout << "\n";
    if (g_failed == 0)
        std::cout << "All " << g_passed << " checks passed.\n";
    else
        std::cout << g_failed << " FAILED, " << g_passed << " passed.\n";

    return g_failed == 0 ? 0 : 1;
}
