/// nge2 – Unified CLI for NGE2 translation tools
///
/// Subcommands
///   hgar  extract <archive.har>  [--output-dir <dir>]
///   hgar  info    <archive.har>
///   text  export  <file.bin>
///   text  import  <file.bin.TEXT.json>
///   bind  unpack  <archive.bin>  [--output-dir <dir>]
///   bind  pack    <dir.BINDPACK> [--output <archive.bin>]

#include "nge2/bind.hpp"
#include "nge2/hgar.hpp"
#include "nge2/text.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static void usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <subcommand> <action> <file> [options]\n"
        << "\n"
        << "Subcommands:\n"
        << "  hgar  extract  <archive.har>  [-o <output_dir>]\n"
        << "  hgar  info     <archive.har>\n"
        << "  text  export   <file.bin>\n"
        << "  text  import   <file.bin.TEXT.json>\n"
        << "  bind  unpack   <archive.bin>  [-o <output_dir>]\n"
        << "  bind  pack     <dir>          [-o <archive.bin>]\n";
}

// ---------------------------------------------------------------------------
// hgar
// ---------------------------------------------------------------------------

static int cmd_hgar(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "hgar: need action and file\n"; return 1;
    }
    const std::string& action = args[0];
    const std::string& path   = args[1];

    std::string output_dir;
    for (size_t i = 2; i + 1 < args.size(); ++i) {
        if (args[i] == "-o" || args[i] == "--output-dir")
            output_dir = args[i + 1];
    }

    nge2::HGArchive hgar;
    hgar.open(path);

    if (action == "info") {
        hgar.info();
        return 0;
    }

    if (action == "extract") {
        if (output_dir.empty())
            output_dir = path + ".HGARPACK";
        hgar.extract(output_dir);
        return 0;
    }

    std::cerr << "hgar: unknown action '" << action << "'\n";
    return 1;
}

// ---------------------------------------------------------------------------
// text
// ---------------------------------------------------------------------------

static int cmd_text(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "text: need action and file\n"; return 1;
    }
    const std::string& action = args[0];
    const std::string& path   = args[1];

    nge2::TextArchive ta;

    if (action == "export") {
        ta.open(path);
        ta.export_text(path);
        return 0;
    }

    if (action == "import") {
        // path is a .TEXT.json file; output goes to the path without that suffix
        const std::string suffix = ".TEXT.json";
        if (path.size() < suffix.size() ||
            path.substr(path.size() - suffix.size()) != suffix) {
            std::cerr << "text import: input must end with " << suffix << "\n";
            return 1;
        }
        std::string out = path.substr(0, path.size() - suffix.size());
        ta.import_text(path);
        ta.save(out);
        std::cout << "Saved: " << out << "\n";
        return 0;
    }

    std::cerr << "text: unknown action '" << action << "'\n";
    return 1;
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

static int cmd_bind(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "bind: need action and file\n"; return 1;
    }
    const std::string& action = args[0];
    const std::string& path   = args[1];

    std::string output;
    for (size_t i = 2; i + 1 < args.size(); ++i) {
        if (args[i] == "-o" || args[i] == "--output")
            output = args[i + 1];
    }

    nge2::BindArchive ba;

    if (action == "unpack") {
        ba.open(path);
        if (output.empty()) output = path + ".BINDPACK";
        ba.unpack(output);
        return 0;
    }

    if (action == "pack") {
        const std::string suffix = ".BINDPACK";
        if (output.empty()) {
            if (path.size() >= suffix.size() &&
                path.substr(path.size() - suffix.size()) == suffix)
                output = path.substr(0, path.size() - suffix.size());
            else
                output = path + ".bin";
        }
        ba.pack(path);
        ba.save(output);
        std::cout << "Saved: " << output << "\n";
        return 0;
    }

    std::cerr << "bind: unknown action '" << action << "'\n";
    return 1;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(argv[0]); return 1; }

    std::string subcmd = argv[1];
    std::vector<std::string> rest(argv + 2, argv + argc);

    try {
        if (subcmd == "hgar") return cmd_hgar(rest);
        if (subcmd == "text") return cmd_text(rest);
        if (subcmd == "bind") return cmd_bind(rest);

        std::cerr << "Unknown subcommand: " << subcmd << "\n";
        usage(argv[0]);
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
