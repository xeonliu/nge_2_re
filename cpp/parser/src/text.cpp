#include "nge2/text.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

namespace nge2 {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void TextArchive::warn(const std::string& msg) {
    warnings.push_back(msg);
    std::cerr << msg << "\n";
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

void TextArchive::_parse(std::istream& f, std::streamsize file_size) {
    char magic[4] = {};
    f.read(magic, 4);
    if (std::strncmp(magic, "TEXT", 4) != 0)
        throw std::runtime_error("Not a TEXT file! Missing TEXT magic.");

    uint32_t num_entries        = read_uint32_le(f);
    uint32_t header_size        = read_uint32_le(f);
    uint32_t content_start_off  = read_uint32_le(f);

    if (header_size != 16)
        warn("Non-standard TEXT header size: " + std::to_string(header_size));

    // Skip to header end (capturing any padding)
    auto pre_header_pos = f.tellg();
    f.seekg(header_size);
    header_padding = static_cast<uint32_t>(
        static_cast<std::streamoff>(f.tellg()) -
        static_cast<std::streamoff>(pre_header_pos));

    // Read entry table: (unknown, string_offset)
    std::vector<uint32_t> entry_unknowns(num_entries);
    std::vector<uint32_t> entry_string_offsets(num_entries);
    for (uint32_t i = 0; i < num_entries; ++i) {
        entry_unknowns[i]        = read_uint32_le(f);
        entry_string_offsets[i] = read_uint32_le(f);
    }

    // Skip to content section (capturing any padding)
    auto pre_entry_pos = f.tellg();
    f.seekg(content_start_off);
    entry_padding = static_cast<uint32_t>(
        static_cast<std::streamoff>(f.tellg()) -
        static_cast<std::streamoff>(pre_entry_pos));

    // Build a sorted, deduplicated list of string offsets
    std::set<uint32_t>  offset_set(entry_string_offsets.begin(),
                                    entry_string_offsets.end());
    std::vector<uint32_t> sorted_offsets(offset_set.begin(), offset_set.end());
    std::sort(sorted_offsets.begin(), sorted_offsets.end());

    // Read each unique string and build offset→index mapping
    std::map<uint32_t, uint32_t> offset_to_index;
    strings.clear();

    for (uint32_t idx = 0; idx < static_cast<uint32_t>(sorted_offsets.size()); ++idx) {
        uint32_t off = sorted_offsets[idx];
        offset_to_index[off] = idx;

        TextString ts;

        if (static_cast<std::streamsize>(off) >= file_size) {
            warn("Out-of-bounds string in TEXT file, using nulls instead");
            ts.is_null = true;
            strings.push_back(std::move(ts));
            continue;
        }

        f.seekg(off);
        ts.unknown_first  = read_uint32_le(f);
        ts.unknown_second = read_uint32_le(f);

        // Read null-terminated bytes aligned to 4-byte chunks
        std::vector<uint8_t> raw;
        while (true) {
            uint8_t chunk[4] = {};
            f.read(reinterpret_cast<char*>(chunk), 4);
            raw.insert(raw.end(), chunk, chunk + 4);
            if (raw.back() == 0) break;
        }
        // Strip trailing NUL bytes
        while (!raw.empty() && raw.back() == 0)
            raw.pop_back();

        ts.raw_content = std::move(raw);
        strings.push_back(std::move(ts));
    }

    // Build entry list using string indices
    entries.clear();
    for (uint32_t i = 0; i < num_entries; ++i)
        entries.emplace_back(entry_unknowns[i],
                             offset_to_index.at(entry_string_offsets[i]));
}

void TextArchive::open(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    auto size = get_stream_size(f);
    _parse(f, size);
}

void TextArchive::open_bytes(const uint8_t* data, size_t length) {
    std::string buf(reinterpret_cast<const char*>(data), length);
    std::istringstream ss(buf, std::ios::binary);
    _parse(ss, static_cast<std::streamsize>(length));
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

void TextArchive::_serialize_to_stream(std::ostream& f) const {
    f.write("TEXT", 4);

    uint32_t num_entries = static_cast<uint32_t>(entries.size());
    write_uint32_le(f, num_entries);
    write_uint32_le(f, 16u);  // fixed header size

    // content_start_offset = 16 (header) + 8 * num_entries
    uint32_t content_start = 16u + 8u * num_entries;
    write_uint32_le(f, content_start);

    // Pre-compute string offsets and serialised content
    struct ConvertedString {
        uint32_t             unknown_first;
        uint32_t             unknown_second;
        std::vector<uint8_t> raw;  // empty iff is_null
        uint32_t             offset;
        bool                 is_null;
    };

    uint32_t current_off = content_start;
    std::vector<ConvertedString> converted;
    converted.reserve(strings.size());

    for (const auto& ts : strings) {
        ConvertedString cs;
        cs.unknown_first  = ts.unknown_first;
        cs.unknown_second = ts.unknown_second;
        cs.is_null        = ts.is_null;
        cs.offset         = current_off;

        if (!ts.is_null) {
            // Add null terminator then pad to 4-byte boundary
            std::vector<uint8_t> raw = ts.raw_content;
            raw.push_back(0);
            cs.raw = zero_pad_and_align_string(raw);
            current_off += 8u + static_cast<uint32_t>(cs.raw.size());
        }

        converted.push_back(std::move(cs));
    }

    // Write entry table
    for (const auto& [unk, str_idx] : entries) {
        write_uint32_le(f, unk);
        write_uint32_le(f, converted.at(str_idx).offset);
    }

    // Write string data
    for (const auto& cs : converted) {
        if (cs.is_null) continue;
        write_uint32_le(f, cs.unknown_first);
        write_uint32_le(f, cs.unknown_second);
        f.write(reinterpret_cast<const char*>(cs.raw.data()),
                static_cast<std::streamsize>(cs.raw.size()));
    }
}

void TextArchive::save(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file for writing: " + path);
    _serialize_to_stream(f);
}

std::vector<uint8_t> TextArchive::serialize() const {
    std::ostringstream buf(std::ios::binary);
    _serialize_to_stream(buf);
    const auto& s = buf.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ---------------------------------------------------------------------------
// JSON export / import  (minimal hand-rolled JSON, no external library)
// ---------------------------------------------------------------------------

static std::string hex_encode(const std::vector<uint8_t>& v) {
    std::ostringstream ss;
    for (uint8_t b : v)
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(b);
    return ss.str();
}

static std::vector<uint8_t> hex_decode(const std::string& s) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        uint8_t b = static_cast<uint8_t>(
            std::stoi(s.substr(i, 2), nullptr, 16));
        out.push_back(b);
    }
    return out;
}

void TextArchive::export_text(const std::string& path) const {
    std::string out_path = path + ".TEXT.json";
    std::ofstream f(out_path);
    if (!f) throw std::runtime_error("Cannot write: " + out_path);

    f << "{\n";
    f << "  \"header_padding\": " << header_padding << ",\n";
    f << "  \"entry_padding\": "  << entry_padding  << ",\n";

    // Warnings
    f << "  \"warnings\": [";
    for (size_t i = 0; i < warnings.size(); ++i) {
        if (i) f << ", ";
        f << "\"" << warnings[i] << "\"";
    }
    f << "],\n";

    // Entries: [[unknown, string_index], ...]
    f << "  \"entries\": [";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i) f << ", ";
        f << "[" << entries[i].first << ", " << entries[i].second << "]";
    }
    f << "],\n";

    // Strings: [[unknown_first, unknown_second, "hex_content", is_null], ...]
    f << "  \"strings\": [\n";
    for (size_t i = 0; i < strings.size(); ++i) {
        const auto& ts = strings[i];
        f << "    [" << ts.unknown_first << ", " << ts.unknown_second
          << ", \"" << hex_encode(ts.raw_content) << "\", "
          << (ts.is_null ? "true" : "false") << "]";
        if (i + 1 < strings.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";

    std::cout << "Exported: " << out_path << "\n";
}

// Very minimal JSON parser for the format we just wrote above.
static std::string extract_json_value(const std::string& json,
                                       const std::string& key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos);
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < json.size() && json[pos] == ' ') ++pos;
    if (pos >= json.size()) return {};
    if (json[pos] == '[' || json[pos] == '{') {
        // Return block
        char open  = json[pos];
        char close = (open == '[') ? ']' : '}';
        int depth  = 0;
        size_t start = pos;
        for (; pos < json.size(); ++pos) {
            if (json[pos] == open)  ++depth;
            if (json[pos] == close) { --depth; if (!depth) break; }
        }
        return json.substr(start, pos - start + 1);
    }
    // Simple scalar (number, string)
    size_t start = pos;
    if (json[pos] == '"') {
        ++start; ++pos;
        while (pos < json.size() && json[pos] != '"') ++pos;
        return json.substr(start, pos - start);
    }
    while (pos < json.size() && json[pos] != ',' && json[pos] != '\n' &&
           json[pos] != '}')
        ++pos;
    return json.substr(start, pos - start);
}

void TextArchive::import_text(const std::string& json_path) {
    std::ifstream f(json_path);
    if (!f) throw std::runtime_error("Cannot open: " + json_path);
    std::string json((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    header_padding = std::stoul(extract_json_value(json, "header_padding"));
    entry_padding  = std::stoul(extract_json_value(json, "entry_padding"));

    entries.clear();
    strings.clear();
    warnings.clear();

    // Parse entries array: [[unk, idx], ...]
    {
        std::string arr = extract_json_value(json, "entries");
        size_t p = 0;
        while ((p = arr.find('[', p)) != std::string::npos) {
            ++p;
            auto end = arr.find(']', p);
            if (end == std::string::npos) break;
            std::string pair = arr.substr(p, end - p);
            auto comma = pair.find(',');
            if (comma == std::string::npos) { p = end; continue; }
            uint32_t unk = std::stoul(pair.substr(0, comma));
            uint32_t idx = std::stoul(pair.substr(comma + 1));
            entries.emplace_back(unk, idx);
            p = end + 1;
        }
    }

    // Parse strings array: [[uf, us, "hex", is_null], ...]
    {
        std::string arr = extract_json_value(json, "strings");
        size_t p = 0;
        while ((p = arr.find('[', p)) != std::string::npos) {
            ++p;
            auto end = arr.find(']', p);
            if (end == std::string::npos) break;
            std::string tup = arr.substr(p, end - p);

            // Split by comma outside of strings
            std::vector<std::string> parts;
            std::string cur;
            bool in_str = false;
            for (char c : tup) {
                if (c == '"')  { in_str = !in_str; continue; }
                if (c == ',' && !in_str) { parts.push_back(cur); cur.clear(); continue; }
                cur += c;
            }
            parts.push_back(cur);

            if (parts.size() >= 4) {
                TextString ts;
                ts.unknown_first  = std::stoul(parts[0]);
                ts.unknown_second = std::stoul(parts[1]);
                ts.raw_content    = hex_decode(parts[2]);
                ts.is_null        = (parts[3].find("true") != std::string::npos);
                strings.push_back(std::move(ts));
            }
            p = end + 1;
        }
    }
}

} // namespace nge2
