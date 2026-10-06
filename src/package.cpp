#include "win_raii.hpp"
#include <array>
namespace dha {
namespace {
bool leaf(const std::wstring &name) {
    return !name.empty() && name != L"." && name != L".." &&
           name.find_first_of(L"\\/:\r\n") == std::wstring::npos;
}
std::wstring inf_value(HINF inf, const wchar_t *key) {
    INFCONTEXT ctx{};
    if (!SetupFindFirstLineW(inf, L"Version", key, &ctx))
        return {};
    DWORD n = 0;
    SetupGetStringFieldW(&ctx, 1, nullptr, 0, &n);
    if (!n || n > 1024 * 1024)
        return {};
    std::vector<wchar_t> b(n);
    if (!SetupGetStringFieldW(&ctx, 1, b.data(), n, nullptr))
        return {};
    return b.data();
}
} // namespace
void acquire_package(Driver &r) {
    if (!leaf(r.inf)) {
        r.package_state = "no_safe_published_inf";
        return;
    }
    const auto path = windows_directory() + L"\\INF\\" + r.inf;
    if (!safe_local_path(path)) {
        r.package_state = "blocked_path";
        return;
    }
    DWORD n = 0;
    SetupGetInfDriverStoreLocationW(path.c_str(), nullptr, nullptr, nullptr, 0, &n);
    if (n && n <= 32768) {
        std::vector<wchar_t> b(n);
        if (SetupGetInfDriverStoreLocationW(path.c_str(), nullptr, nullptr, b.data(), n, nullptr))
            r.store_inf = b.data();
    }
    InfHandle inf(SetupOpenInfFileW(path.c_str(), nullptr, INF_STYLE_WIN4, nullptr));
    if (inf.value == INVALID_HANDLE_VALUE) {
        r.package_state = win_error(GetLastError());
        return;
    }
    r.package_provider = inf_value(inf.value, L"Provider");
    // DriverVer is two fields; preserve the exact published string for comparison by readers.
    INFCONTEXT ctx{};
    if (SetupFindFirstLineW(inf.value, L"Version", L"DriverVer", &ctx)) {
        wchar_t date[256]{}, ver[256]{};
        if (SetupGetStringFieldW(&ctx, 1, date, 256, nullptr) &&
            SetupGetStringFieldW(&ctx, 2, ver, 256, nullptr))
            r.package_version = std::wstring(date) + L"," + ver;
    }
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const wchar_t *decorated =
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64   ? L"CatalogFile.NTamd64"
        : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? L"CatalogFile.NTarm64"
                                                                    : L"CatalogFile.NTx86";
    auto catalog = inf_value(inf.value, decorated);
    if (catalog.empty())
        catalog = inf_value(inf.value, L"CatalogFile.NT");
    if (catalog.empty())
        catalog = inf_value(inf.value, L"CatalogFile");
    r.package_state = r.store_inf.empty() || r.package_provider.empty() || r.package_version.empty()
                          ? "partial"
                          : "available";
    if (leaf(catalog) && !r.store_inf.empty()) {
        const auto slash = r.store_inf.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            r.catalog = r.store_inf.substr(0, slash + 1) + catalog;
            r.signature = inspect_signature(r.catalog);
        }
    }
}
} // namespace dha
