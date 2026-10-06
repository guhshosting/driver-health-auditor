#include "win_raii.hpp"
namespace dha {
std::string inspect_pe(const std::wstring &path) {
    if (!safe_local_path(path))
        return "unknown";
    Handle h(CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (h.value == INVALID_HANDLE_VALUE)
        return "unknown";
    IMAGE_DOS_HEADER dos{};
    DWORD n = 0;
    if (!ReadFile(h.value, &dos, sizeof(dos), &n, nullptr) || n != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)))
        return "unknown";
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h.value, &size) ||
        static_cast<LONGLONG>(dos.e_lfanew) >
            size.QuadPart - static_cast<LONGLONG>(sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)))
        return "unknown";
    LARGE_INTEGER offset{};
    offset.QuadPart = dos.e_lfanew;
    if (!SetFilePointerEx(h.value, offset, nullptr, FILE_BEGIN))
        return "unknown";
    DWORD sig = 0;
    IMAGE_FILE_HEADER header{};
    if (!ReadFile(h.value, &sig, sizeof(sig), &n, nullptr) || n != sizeof(sig) ||
        sig != IMAGE_NT_SIGNATURE || !ReadFile(h.value, &header, sizeof(header), &n, nullptr) ||
        n != sizeof(header))
        return "unknown";
    if (!(header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ||
        header.SizeOfOptionalHeader < sizeof(WORD) ||
        static_cast<LONGLONG>(dos.e_lfanew) +
                static_cast<LONGLONG>(sizeof(DWORD) + sizeof(header)) +
                header.SizeOfOptionalHeader >
            size.QuadPart)
        return "unknown";
    WORD magic = 0;
    if (!ReadFile(h.value, &magic, sizeof(magic), &n, nullptr) || n != sizeof(magic))
        return "unknown";
    if ((header.Machine == IMAGE_FILE_MACHINE_I386 && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) ||
        ((header.Machine == IMAGE_FILE_MACHINE_AMD64 ||
          header.Machine == IMAGE_FILE_MACHINE_ARM64) &&
         magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
        return "unknown";
    switch (header.Machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_I386:
        return "x86";
    case IMAGE_FILE_MACHINE_ARM64:
        return "arm64";
    default:
        return "unknown";
    }
}
} // namespace dha
