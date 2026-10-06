#include "win_raii.hpp"
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <algorithm>
#include <cstring>
#include <cstdio>
namespace dha {
namespace {
std::vector<BYTE> property(HDEVINFO set, SP_DEVINFO_DATA &info, const DEVPROPKEY &key,
                           DEVPROPTYPE expected, Device &d, const char *label) {
    DEVPROPTYPE type = 0;
    DWORD bytes = 0;
    if (!SetupDiGetDevicePropertyW(set, &info, &key, &type, nullptr, 0, &bytes, 0)) {
        const auto e = GetLastError();
        if (e != ERROR_INSUFFICIENT_BUFFER) {
            d.errors.push_back(std::string(label) + ": " + win_error(e));
            return {};
        }
    }
    if (bytes == 0 || bytes > 1024 * 1024) {
        d.errors.push_back(std::string(label) + ": invalid size");
        return {};
    }
    std::vector<BYTE> buf(bytes + sizeof(wchar_t), 0);
    if (!SetupDiGetDevicePropertyW(set, &info, &key, &type, buf.data(), bytes, &bytes, 0) ||
        type != expected) {
        d.errors.push_back(std::string(label) + ": unavailable or unexpected property type");
        return {};
    }
    buf.resize(bytes);
    return buf;
}
std::wstring strprop(HDEVINFO set, SP_DEVINFO_DATA &info, const DEVPROPKEY &key, Device &d,
                     const char *label) {
    const auto b = property(set, info, key, DEVPROP_TYPE_STRING, d, label);
    if (b.empty())
        return {};
    if (b.size() % sizeof(wchar_t) != 0) {
        d.errors.push_back(std::string(label) + ": malformed string");
        return {};
    }
    std::wstring s(b.size() / sizeof(wchar_t), L'\0');
    memcpy(s.data(), b.data(), b.size());
    const auto end = s.find(L'\0');
    if (end == std::wstring::npos) {
        d.errors.push_back(std::string(label) + ": unterminated string");
        return {};
    }
    s.resize(end);
    return s;
}
} // namespace
std::vector<Device> acquire_devices(const Options &o, std::vector<std::string> &warnings) {
    DeviceSet set(o.device.empty()
                      ? SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
                                             DIGCF_ALLCLASSES | (o.all ? 0 : DIGCF_PRESENT))
                      : SetupDiCreateDeviceInfoList(nullptr, nullptr));
    if (set.value == INVALID_HANDLE_VALUE)
        throw Failure{4, "Device enumeration failed: " + win_error(GetLastError())};
    std::optional<SP_DEVINFO_DATA> selected;
    if (!o.device.empty()) {
        SP_DEVINFO_DATA target{};
        target.cbSize = sizeof(target);
        if (!SetupDiOpenDeviceInfoW(set.value, o.device.c_str(), nullptr, 0, &target)) {
            const auto e = GetLastError();
            if (e == ERROR_INVALID_DEVINST_NAME)
                throw Failure{2, "Windows rejected the device instance ID format"};
            if (e == ERROR_NO_SUCH_DEVINST || e == ERROR_NOT_FOUND)
                throw Failure{3, "Requested device not found"};
            throw Failure{4, "Requested device acquisition failed: " + win_error(e)};
        }
        selected = target;
    }
    std::vector<Device> result;
    for (DWORD i = 0;; ++i) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (selected) {
            if (i != 0)
                break;
            info = *selected;
        } else if (!SetupDiEnumDeviceInfo(set.value, i, &info)) {
            const auto e = GetLastError();
            if (e == ERROR_NO_MORE_ITEMS)
                break;
            throw Failure{4, "Device enumeration interrupted: " + win_error(e)};
        }
        DWORD n = 0;
        SetupDiGetDeviceInstanceIdW(set.value, &info, nullptr, 0, &n);
        if (n == 0 || n > 1024 * 1024) {
            if (selected)
                throw Failure{4, "Requested device instance ID unavailable: " +
                                     win_error(GetLastError())};
            warnings.push_back("Device disappeared or instance ID unavailable: " +
                               win_error(GetLastError()));
            continue;
        }
        std::vector<wchar_t> id(n);
        if (!SetupDiGetDeviceInstanceIdW(set.value, &info, id.data(), n, nullptr)) {
            if (selected)
                throw Failure{4, "Requested device disappeared during acquisition: " +
                                     win_error(GetLastError())};
            warnings.push_back("Instance ID acquisition failed: " + win_error(GetLastError()));
            continue;
        }
        Device d;
        d.id = id.data();
        // FriendlyName is optional; Description is the documented fallback.
        Device optional;
        d.name = strprop(set.value, info, DEVPKEY_Device_FriendlyName, optional, "friendly_name");
        if (d.name.empty())
            d.name = strprop(set.value, info, DEVPKEY_Device_DeviceDesc, d, "description");
        d.class_name = strprop(set.value, info, DEVPKEY_Device_Class, d, "class");
        d.service = strprop(set.value, info, DEVPKEY_Device_Service, optional, "service");
        d.inf = strprop(set.value, info, DEVPKEY_Device_DriverInfPath, d, "inf");
        d.provider = strprop(set.value, info, DEVPKEY_Device_DriverProvider, d, "provider");
        d.version = strprop(set.value, info, DEVPKEY_Device_DriverVersion, d, "version");
        const auto date =
            property(set.value, info, DEVPKEY_Device_DriverDate, DEVPROP_TYPE_FILETIME, d, "date");
        if (date.size() == sizeof(FILETIME)) {
            FILETIME ft{};
            memcpy(&ft, date.data(), sizeof(ft));
            SYSTEMTIME st{};
            if (FileTimeToSystemTime(&ft, &st)) {
                wchar_t b[32]{};
                swprintf_s(b, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
                d.date = b;
            }
        }
        const auto present =
            property(set.value, info, DEVPKEY_Device_IsPresent, DEVPROP_TYPE_BOOLEAN, d, "present");
        if (present.size() == sizeof(DEVPROP_BOOLEAN))
            d.present = present[0] != DEVPROP_FALSE;
        ULONG status = 0, problem = 0;
        const auto cr = CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0);
        if (cr == CR_SUCCESS) {
            d.status = status;
            d.problem = (status & DN_HAS_PROBLEM) ? problem : 0;
        } else {
            d.errors.push_back("CM_Get_DevNode_Status: CONFIGRET " + std::to_string(cr));
        }
        result.push_back(std::move(d));
    }
    if (!o.device.empty() && result.empty())
        throw Failure{3, "Requested device disappeared or was not found"};
    std::sort(result.begin(), result.end(),
              [](const Device &x, const Device &y) { return lower(x.id) < lower(y.id); });
    return result;
}
} // namespace dha
