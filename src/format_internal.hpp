#ifndef DHA_FORMAT_INTERNAL_HPP
#define DHA_FORMAT_INTERNAL_HPP
#include "dha.hpp"
#include <algorithm>
#include <array>
namespace dha::format_detail {
inline std::string q(const std::string &s) {
    std::string out = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 32) {
                out += "\\u00";
                out += hex[static_cast<unsigned int>(c) >> 4U];
                out += hex[static_cast<unsigned int>(c) & 15U];
            } else
                out += static_cast<char>(c);
        }
    }
    return out + '"';
}
inline std::string text(const std::wstring &s) {
    return s.empty() ? "null" : q(utf8(s));
}
template <class T> std::string number(const std::optional<T> &n) {
    return n ? std::to_string(*n) : "null";
}
inline std::string boolean(const std::optional<bool> &b) {
    return b ? (*b ? "true" : "false") : "null";
}
inline std::string sig(const Signature &s) {
    return "{\"state\":" + q(s.state) + ",\"wintrust_status\":" + number(s.status) +
           ",\"signer\":" + text(s.signer) + "}";
}
inline size_t count_problem(const Audit &a) {
    return static_cast<size_t>(
        std::count_if(a.devices.begin(), a.devices.end(),
                      [](const Device &d) { return d.problem && driver_problem(*d.problem); }));
}
inline size_t count_incomplete(const Audit &a) {
    return static_cast<size_t>(std::count_if(a.devices.begin(), a.devices.end(), incomplete));
}
inline size_t count_trust(const Audit &a) {
    return static_cast<size_t>(
        std::count_if(a.findings.begin(), a.findings.end(), [](const Finding &f) {
            return f.code == "local_signature_problem" || f.code == "trust_unavailable";
        }));
}
inline constexpr std::array<const char *, 7> limits = {
    "No network retrieval. Newer driver availability is unknown.",
    "Driver date and version are facts; age alone is not a health finding.",
    ("Offline Authenticode policy uses local trust state; online revocation is not established. "
     "This is not kernel-mode signing policy validation."),
    ("Catalog signature verification does not establish INF or binary catalog membership. Binary "
     "checks inspect embedded signatures only; no embedded signature does not imply unsigned or "
     "malicious."),
    ("Inventory is device-associated, not an exhaustive inventory of unreferenced staged packages. "
     "Default: present devices; --all: includes retained non-present device records."),
    ("Device enumeration is not atomic. Disappearing devices and unavailable properties produce "
     "partial records or warnings."),
    ("Remote paths, reparse paths, ambiguous service commands and unresolved environment variables "
     "are not inspected. File path checks cannot eliminate races caused by concurrent hostile path "
     "changes.")};
inline std::string printable(const std::wstring &s) {
    auto x = utf8(s);
    std::replace_if(
        x.begin(), x.end(), [](char c) { return static_cast<unsigned char>(c) < 32 || c == 127; },
        '?');
    return x;
}
} // namespace dha::format_detail
#endif
