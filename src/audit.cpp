#include "win_raii.hpp"
#include <map>
#include <set>
#include <versionhelpers.h>
namespace dha {
Audit acquire(const Options &o) {
    Audit a;
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        a.native_arch = "x64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        a.native_arch = "x86";
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        a.native_arch = "arm64";
        break;
    default:
        a.native_arch = "unknown";
        break;
    }
#if defined(_M_X64)
    if (a.native_arch != "x64")
        throw Failure{4, "Use a build matching the native OS architecture"};
#elif defined(_M_IX86)
    if (a.native_arch != "x86")
        throw Failure{4, "Use a build matching the native OS architecture"};
#elif defined(_M_ARM64)
    if (a.native_arch != "arm64")
        throw Failure{4, "Use a build matching the native OS architecture"};
#endif
    if (!IsWindows10OrGreater())
        throw Failure{4, "Windows 10 or a corresponding Server generation is required"};
    // Read-only descriptive build metadata; no deprecated version query or private API.
    wchar_t build[128]{};
    DWORD build_bytes = sizeof(build);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"CurrentBuildNumber", RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, build,
                     &build_bytes) == ERROR_SUCCESS)
        a.os_version = "build " + utf8(build);
    Handle token(nullptr);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) {
        TOKEN_ELEVATION e{};
        DWORD size = 0;
        if (GetTokenInformation(token.value, TokenElevation, &e, sizeof(e), &size))
            a.elevated = e.TokenIsElevated != 0;
    }
    a.devices = acquire_devices(o, a.warnings);
    correlate(a);
    std::map<std::wstring, Service> services;
    for (auto &r : a.drivers) {
        acquire_package(r);
        std::set<std::wstring> seen;
        for (const auto &d : a.devices)
            if (d.driver_id == r.id && !d.service.empty() && seen.insert(lower(d.service)).second) {
                const auto key = lower(d.service);
                auto it = services.find(key);
                if (it == services.end())
                    it = services.emplace(key, acquire_service(d.service)).first;
                r.services.push_back(it->second);
            }
    }
    findings(a);
    return a;
}
} // namespace dha
