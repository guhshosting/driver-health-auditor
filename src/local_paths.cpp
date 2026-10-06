#include "win_raii.hpp"
namespace dha {
std::wstring windows_directory() {
    std::vector<wchar_t> b(32768);
    const UINT n = GetWindowsDirectoryW(b.data(), static_cast<UINT>(b.size()));
    if (!n || n >= b.size())
        throw Failure{4, "Windows directory unavailable"};
    return {b.data(), n};
}
bool safe_local_path(const std::wstring &path) {
    // Only drive-absolute DOS paths on local volumes; reject device namespaces, ADS, traversal,
    // network drives and ALL reparse points before following them. No UNC file APIs.
    if (path.size() < 3 ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\' ||
        path.find_first_of(L"/\r\n\"", 3) != std::wstring::npos ||
        path.find(L':', 2) != std::wstring::npos)
        return false;
    const auto root = path.substr(0, 3);
    const auto type = GetDriveTypeW(root.c_str());
    if (type != DRIVE_FIXED && type != DRIVE_RAMDISK && type != DRIVE_REMOVABLE &&
        type != DRIVE_CDROM)
        return false;
    // Reject SUBST mappings too: a drive alias can hide a UNC or reparse parent.
    std::vector<wchar_t> mapping(32768);
    const auto drive = path.substr(0, 2);
    if (!QueryDosDeviceW(drive.c_str(), mapping.data(), 32768) ||
        std::wstring(mapping.data()).rfind(L"\\Device\\", 0) != 0 ||
        std::wstring(mapping.data()).rfind(L"\\Device\\Mup", 0) == 0 ||
        std::wstring(mapping.data()).rfind(L"\\Device\\LanmanRedirector", 0) == 0)
        return false;
    // Validate every component before allowing a missing ancestor to end the filesystem walk.
    size_t syntax_pos = 3;
    while (syntax_pos < path.size()) {
        const auto end = path.find(L'\\', syntax_pos);
        const auto part =
            path.substr(syntax_pos, end == std::wstring::npos ? end : end - syntax_pos);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
            part.back() == L' ')
            return false;
        if (end == std::wstring::npos)
            break;
        syntax_pos = end + 1;
        if (syntax_pos == path.size())
            return false;
    }
    size_t pos = 3;
    while (pos < path.size()) {
        const auto end = path.find(L'\\', pos);
        const auto part = path.substr(pos, end == std::wstring::npos ? end : end - pos);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
            part.back() == L' ')
            return false;
        const auto prefix = path.substr(0, end);
        const auto attr = GetFileAttributesW(prefix.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            const auto e = GetLastError();
            return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
        }
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT)
            return false;
        if (end == std::wstring::npos)
            return true;
        pos = end + 1;
    }
    return false;
}
} // namespace dha
