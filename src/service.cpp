#include "win_raii.hpp"
#include <cwctype>
namespace dha {
namespace {
std::wstring resolve(std::wstring s) {
    if (s.empty())
        return {};
    if (s.front() == L'"') {
        const auto q = s.find(L'"', 1);
        if (q == std::wstring::npos || q + 1 != s.size())
            return {};
        s = s.substr(1, q - 1);
    }
    // Do not expand arbitrary environment variables or accept command-line arguments.
    const auto low = lower(s);
    if (low.rfind(L"\\systemroot\\", 0) == 0)
        s = windows_directory() + s.substr(11);
    else if (low.rfind(L"%systemroot%\\", 0) == 0)
        s = windows_directory() + s.substr(12);
    else if (low.rfind(L"system32\\", 0) == 0)
        s = windows_directory() + L"\\" + s;
    else if (low.rfind(L"\\??\\", 0) == 0)
        s = s.substr(4);
    if (s.find(L'%') != std::wstring::npos)
        return {};
    return s;
}
} // namespace
Service acquire_service(const std::wstring &name) {
    Service s;
    s.name = name;
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.value) {
        s.state = win_error(GetLastError());
        return s;
    }
    ScHandle svc(OpenServiceW(scm.value, name.c_str(), SERVICE_QUERY_CONFIG));
    if (!svc.value) {
        s.state = win_error(GetLastError());
        return s;
    }
    DWORD n = 0;
    if (QueryServiceConfigW(svc.value, nullptr, 0, &n) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        s.state = "configuration_unavailable";
        return s;
    }
    if (!n || n > 8192) {
        s.state = "configuration_unavailable";
        return s;
    }
    std::vector<BYTE> b(n);
    auto *c = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(b.data());
    if (!QueryServiceConfigW(svc.value, c, n, &n)) {
        s.state = win_error(GetLastError());
        return s;
    }
    s.type = c->dwServiceType;
    s.start = c->dwStartType;
    s.image = c->lpBinaryPathName ? c->lpBinaryPathName : L"";
    s.state = "available";
    if ((c->dwServiceType & (static_cast<DWORD>(SERVICE_KERNEL_DRIVER) |
                             static_cast<DWORD>(SERVICE_FILE_SYSTEM_DRIVER))) == 0) {
        s.binary_state = "not_driver_service";
        return s;
    }
    s.binary = resolve(s.image);
    if (!safe_local_path(s.binary)) {
        s.binary_state = "blocked_path";
        return s;
    }
    const DWORD attr = GetFileAttributesW(s.binary.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        const auto e = GetLastError();
        s.binary_state =
            (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? "missing" : "unavailable";
        return s;
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        s.binary_state = "unavailable";
        return s;
    }
    s.binary_state = "available";
    s.architecture = inspect_pe(s.binary);
    s.signature = inspect_signature(s.binary);
    return s;
}
} // namespace dha
