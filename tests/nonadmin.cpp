#include <windows.h>
#include <string>
#include <iostream>
// Validation harness only: run the auditor with a restricted, non-elevated token.
int wmain(int argc, wchar_t **argv) {
    if (argc != 2)
        return 2;
    HANDLE original = nullptr, restricted = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                          &original))
        return 1;
    BYTE sid[SECURITY_MAX_SID_SIZE]{};
    DWORD length = sizeof(sid);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &length)) {
        CloseHandle(original);
        return 1;
    }
    SID_AND_ATTRIBUTES deny{sid, 0};
    if (!CreateRestrictedToken(original, DISABLE_MAX_PRIVILEGE, 1, &deny, 0, nullptr, 0, nullptr,
                               &restricted)) {
        CloseHandle(original);
        return 1;
    }
    CloseHandle(original);
    std::wstring command = L"\"" + std::wstring(argv[1]) + L"\" --json";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL ok =
        CreateProcessAsUserW(restricted, nullptr, command.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(restricted);
    if (!ok) {
        std::cerr << "Restricted process failed: " << GetLastError() << '\n';
        return 1;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 5;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(code);
}
