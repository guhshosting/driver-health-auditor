#include "dha.hpp"
#include <algorithm>
#include <cwctype>
#include <map>
#include <limits>
namespace dha {
std::string utf8(const std::wstring &text) {
    if (text.empty())
        return {};
    if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        throw Failure{5, "Text too large"};
    const int n = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        throw Failure{5, "Unicode conversion failed"};
    std::string out(static_cast<size_t>(n), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n,
                             nullptr, nullptr))
        throw Failure{5, "Unicode conversion failed"};
    return out;
}
std::wstring lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return text;
}
std::string win_error(unsigned long n) {
    return "Windows error " + std::to_string(n);
}
bool incomplete(const Device &d) {
    return d.inf.empty() || d.provider.empty() || d.version.empty() || d.date.empty() ||
           !d.present.has_value() || !d.problem.has_value() || !d.errors.empty();
}
} // namespace dha
