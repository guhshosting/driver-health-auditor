#ifndef DHA_WIN_RAII_HPP
#define DHA_WIN_RAII_HPP
#include "dha.hpp"
#include <setupapi.h>
#include <winsvc.h>
namespace dha {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() {
        if (value != INVALID_HANDLE_VALUE && value != nullptr)
            CloseHandle(value);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
};
struct DeviceSet {
    HDEVINFO value = INVALID_HANDLE_VALUE;
    explicit DeviceSet(HDEVINFO h) : value(h) {}
    ~DeviceSet() {
        if (value != INVALID_HANDLE_VALUE)
            SetupDiDestroyDeviceInfoList(value);
    }
    DeviceSet(const DeviceSet &) = delete;
    DeviceSet &operator=(const DeviceSet &) = delete;
};
struct ScHandle {
    SC_HANDLE value = nullptr;
    explicit ScHandle(SC_HANDLE h) : value(h) {}
    ~ScHandle() {
        if (value)
            CloseServiceHandle(value);
    }
    ScHandle(const ScHandle &) = delete;
    ScHandle &operator=(const ScHandle &) = delete;
};
struct InfHandle {
    HINF value = INVALID_HANDLE_VALUE;
    explicit InfHandle(HINF h) : value(h) {}
    ~InfHandle() {
        if (value != INVALID_HANDLE_VALUE)
            SetupCloseInfFile(value);
    }
    InfHandle(const InfHandle &) = delete;
    InfHandle &operator=(const InfHandle &) = delete;
};
} // namespace dha
#endif
