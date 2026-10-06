#include "dha.hpp"
namespace dha {
Options parse(const std::vector<std::wstring> &args) {
    Options o;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto &a = args[i];
        if (a == L"--all" && !o.all)
            o.all = true;
        else if (a == L"--json" && !o.json)
            o.json = true;
        else if (a == L"--help" && !o.help)
            o.help = true;
        else if (a == L"--version" && !o.version_only)
            o.version_only = true;
        else if (a == L"--device" && o.device.empty()) {
            ++i;
            if (i == args.size() || args[i].empty() || args[i].rfind(L"--", 0) == 0)
                throw Failure{2, "--device requires an instance ID"};
            o.device = args[i];
        } else
            throw Failure{2, "Unknown or repeated argument: " + utf8(a)};
    }
    if ((o.help || o.version_only) && args.size() != 1)
        throw Failure{2, "--help and --version must be used alone"};
    if (o.all && !o.device.empty())
        throw Failure{2, "--all and --device are mutually exclusive"};
    return o;
}
} // namespace dha
