#include "dha.hpp"
#include <map>
namespace dha {
void correlate(Audit &a) {
    a.drivers.clear();
    std::map<std::wstring, size_t> index;
    for (auto &d : a.devices) {
        // One group per published INF AND reported identity. Conflicting device metadata stays
        // visible.
        const auto key = d.inf.empty() ? L"missing:" + lower(d.id)
                                       : lower(d.inf) + L"\n" + lower(d.provider) + L"\n" +
                                             d.version + L"\n" + d.date;
        auto it = index.find(key);
        if (it == index.end()) {
            Driver r;
            r.id = "driver-" + std::to_string(a.drivers.size() + 1);
            r.inf = d.inf;
            r.provider = d.provider;
            r.version = d.version;
            r.date = d.date;
            it = index.emplace(key, a.drivers.size()).first;
            a.drivers.push_back(std::move(r));
        }
        auto &r = a.drivers[it->second];
        d.driver_id = r.id;
        r.devices.push_back(d.id);
    }
}
} // namespace dha
