#ifndef DHA_MODEL_HPP
#define DHA_MODEL_HPP
#include <windows.h>
#include <optional>
#include <string>
#include <vector>
#include <cstdint>
#include <exception>
#include <utility>
namespace dha {
inline constexpr char version[] = "1.0.0";
struct Options {
    bool all = false, json = false, help = false, version_only = false;
    std::wstring device;
};
struct Signature {
    std::string state = "unavailable";
    std::optional<long> status;
    std::wstring signer;
};
struct Service {
    std::wstring name, image, binary;
    std::string state = "unavailable";
    std::optional<unsigned long> type, start;
    std::string binary_state = "unavailable", architecture = "unknown";
    Signature signature;
};
struct Device {
    std::wstring id, name, class_name, service, inf, provider, version, date;
    std::optional<bool> present;
    std::optional<unsigned long> problem;
    std::optional<unsigned long> status;
    std::vector<std::string> errors;
    std::string driver_id;
};
struct Driver {
    std::string id;
    std::wstring inf, provider, version, date, store_inf, catalog, package_provider,
        package_version;
    Signature signature;
    std::string package_state = "unavailable";
    std::vector<std::wstring> devices;
    std::vector<Service> services;
};
struct Finding {
    std::string code, severity, driver_id;
    std::wstring device_id;
    std::string evidence;
};
struct Audit {
    std::vector<Device> devices;
    std::vector<Driver> drivers;
    std::vector<Finding> findings;
    std::vector<std::string> warnings;
    std::string native_arch;
    std::string os_version;
    std::optional<bool> elevated;
};
struct Failure final : std::exception {
    int exit_code;
    std::string message;
    Failure(int code, std::string text) : exit_code(code), message(std::move(text)) {}
    const char *what() const noexcept override {
        return message.c_str();
    }
};
Options parse(const std::vector<std::wstring> &args);
std::string utf8(const std::wstring &text);
std::wstring lower(std::wstring text);
std::string win_error(unsigned long value);
bool driver_problem(unsigned long code);
void correlate(Audit &audit);
void findings(Audit &audit);
bool incomplete(const Device &d);
std::string json(const Audit &audit);
std::string human(const Audit &audit, bool all);
std::vector<Device> acquire_devices(const Options &options, std::vector<std::string> &warnings);
void acquire_package(Driver &driver);
Service acquire_service(const std::wstring &name);
Signature inspect_signature(const std::wstring &path);
std::string inspect_pe(const std::wstring &path);
bool safe_local_path(const std::wstring &path);
std::wstring windows_directory();
Audit acquire(const Options &options);
} // namespace dha
#endif
