#include "dha.hpp"
#include <iostream>
#include <exception>
namespace {
void write_stdout(const std::string &s) {
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (out != INVALID_HANDLE_VALUE && GetConsoleMode(out, &mode)) {
        const int n =
            MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (n > 0) {
            std::wstring w(static_cast<size_t>(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
            DWORD done = 0;
            size_t pos = 0;
            while (pos < w.size()) {
                const DWORD chunk = static_cast<DWORD>((std::min)(w.size() - pos, size_t{16384}));
                if (!WriteConsoleW(out, w.data() + pos, chunk, &done, nullptr) || done == 0)
                    throw dha::Failure{5, "Console output failed"};
                pos += done;
            }
            return;
        }
    }
    std::cout << s;
    std::cout.flush();
    if (!std::cout)
        throw dha::Failure{5, "Output failed"};
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        std::vector<std::wstring> args;
        for (int i = 1; i < argc; ++i)
            args.emplace_back(argv[i]);
        const auto o = dha::parse(args);
        if (o.help) {
            write_stdout(
                "driver-health-auditor 1.0.0\nUsage: driver-health-auditor [--all | --device "
                "<instance-id>] [--json]\n       driver-health-auditor --help | "
                "--version\nDefault: audit present device-associated drivers, prioritize "
                "findings.\n--all: include retained non-present devices and print every "
                "association.\n--device: exact case-insensitive instance ID, including retained "
                "devices.\n--json: complete UTF-8 schema 1.0; no progress text on "
                "stdout.\nRead-only. No network, elevation, remediation or newer-driver "
                "lookup.\nExit: 0 completed (including findings), 2 usage, 3 device not found,\n   "
                "   4 acquisition failure, 5 unexpected internal failure.\n");
            return 0;
        }
        if (o.version_only) {
            write_stdout("driver-health-auditor 1.0.0\n");
            return 0;
        }
        const auto a = dha::acquire(o);
        write_stdout(o.json ? dha::json(a) : dha::human(a, o.all || !o.device.empty()));
        return 0;
    } catch (const dha::Failure &e) {
        std::cerr << "driver-health-auditor: " << e.message << '\n';
        return e.exit_code;
    } catch (const std::exception &e) {
        std::cerr << "driver-health-auditor: internal failure: " << e.what() << '\n';
        return 5;
    } catch (...) {
        std::cerr << "driver-health-auditor: unexpected internal failure\n";
        return 5;
    }
}
