// symbolize_crash — resolve crash-report backtraces to function + file:line.
//
// The native CrashHandler writes raw return addresses into crash_*.json. This
// tool turns them into symbols using the captured module base + binary path:
//   - macOS:  atos -o <module> -l <base> <address>
//   - Linux:  addr2line -e <module> -f -C <address - base>   (PIE offset)
//
// Usage:
//   ./desktop/build_fixcheck/bin/symbolize_crash <crash.json> [--json]
//   ./desktop/build_fixcheck/bin/symbolize_crash <dir/>             (all crash files)
//
// Build the engine module with debug info (-g) for file:line; without it you
// still get function names from the symbol table.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <sys/types.h>
#include <dirent.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

unsigned long long parse_addr(const std::string& s) {
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        return std::strtoull(s.c_str() + 2, nullptr, 16);
    }
    return std::strtoull(s.c_str(), nullptr, 0);
}

// Runs a command and returns the first line of stdout (trimmed).
std::string run(const std::string& cmd) {
    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) return "";
    char buf[512];
    std::string out;
    if (std::fgets(buf, sizeof(buf), p) != nullptr) {
        out = buf;
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    }
    ::pclose(p);
    return out;
}

// Resolve one return address to a human-readable symbol string.
std::string symbolize(const std::string& module_path, unsigned long long module_base,
                      unsigned long long address) {
    if (module_path.empty() || module_base == 0 || address == 0) {
        return "<unknown module/address>";
    }
#if defined(__APPLE__)
    char cmd[2048];
    std::snprintf(cmd, sizeof(cmd), "atos -o '%s' -l 0x%llx 0x%llx 2>/dev/null",
                  module_path.c_str(), module_base, address);
    std::string sym = run(cmd);
    if (sym.empty() || sym.find("0x") == 0 || sym == "atos") {
        return "<unresolved>";
    }
    return sym;
#else
    const unsigned long long offset = address - module_base;
    char cmd[2048];
    std::snprintf(cmd, sizeof(cmd), "addr2line -e '%s' -f -C 0x%llx 2>/dev/null",
                  module_path.c_str(), offset);
    std::string sym = run(cmd);
    if (sym.empty() || sym == "??") {
        return "<unresolved>";
    }
    return sym;
#endif
}

// Emits the enriched representation of one crash file.
int process_crash_file(const std::string& path, bool as_json) {
    json doc;
    try {
        doc = json::parse(std::ifstream(path), nullptr, true, true);
    } catch (...) {
        std::cerr << "skip (unparseable): " << path << std::endl;
        return 1;
    }

    const std::string module_path = doc.value("module_path", "");
    const std::string base_str = doc.value("module_base", "");
    const unsigned long long module_base = parse_addr(base_str);

    json symbols = json::array();
    std::vector<std::string> pretty;
    if (doc.contains("backtrace") && doc["backtrace"].is_array()) {
        for (const auto& a : doc["backtrace"]) {
            const std::string addr = a.get<std::string>();
            const std::string sym = symbolize(module_path, module_base, parse_addr(addr));
            symbols.push_back({{"address", addr}, {"symbol", sym}});
            pretty.push_back("  " + addr + "  " + sym);
        }
    }

    if (as_json) {
        doc["symbols"] = symbols;
        std::cout << doc.dump(2) << std::endl;
    } else {
        std::cout << path << std::endl;
        std::cout << "  signal " << doc.value("signal", 0) << " "
                  << doc.value("signame", "") << "  module=" << module_path
                  << " base=" << base_str << std::endl;
        for (const auto& line : pretty) std::cout << line << std::endl;
    }
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: symbolize_crash <crash.json|dir/> [--json]" << std::endl;
        return 1;
    }
    const std::string target = argv[1];
    const bool as_json = (argc > 2 && std::string(argv[2]) == "--json");

    // Directory mode: process every crash_*.json / anomaly_*.json in it.
    DIR* d = ::opendir(target.c_str());
    if (d) {
        struct dirent* e = nullptr;
        int rc = 0;
        while ((e = ::readdir(d)) != nullptr) {
            const std::string name = e->d_name;
            if (name.rfind("crash_", 0) != 0 && name.rfind("anomaly_", 0) != 0) continue;
            rc |= process_crash_file(target + "/" + name, as_json);
        }
        ::closedir(d);
        return rc;
    }
    return process_crash_file(target, as_json);
}
