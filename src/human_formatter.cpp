#include "format_internal.hpp"
#include <sstream>
#include <iterator>
namespace dha {
using namespace format_detail;
std::string human(const Audit &a, bool all) {
    std::ostringstream o;
    o << "driver-health-auditor " << version << " | read-only, offline\n"
      << a.devices.size() << " devices examined; " << a.drivers.size()
      << " driver identities correlated; " << count_problem(a)
      << " devices with driver-related problems; " << count_trust(a)
      << " signature/trust findings; " << count_incomplete(a) << " incomplete device records.\n";
    std::vector<const Driver *> order;
    std::transform(a.drivers.begin(), a.drivers.end(), std::back_inserter(order),
                   [](const Driver &r) { return &r; });
    auto warning = [&](const Driver *r) {
        return std::any_of(a.findings.begin(), a.findings.end(), [&](const Finding &f) {
            return f.driver_id == r->id && f.severity == "warning";
        });
    };
    std::stable_sort(order.begin(), order.end(),
                     [&](const Driver *x, const Driver *y) { return warning(x) > warning(y); });
    size_t omitted = 0;
    for (const auto *p : order) {
        const auto &r = *p;
        const bool noteworthy =
            std::any_of(a.findings.begin(), a.findings.end(), [&](const Finding &f) {
                return f.driver_id == r.id && f.code != "shared_driver" &&
                       f.code != "trust_unavailable";
            });
        if (!all && !noteworthy) {
            ++omitted;
            continue;
        }
        o << "\n"
          << r.id << " | " << (r.inf.empty() ? "INF unavailable" : printable(r.inf)) << " | "
          << printable(r.provider) << " | version " << printable(r.version) << " | date "
          << printable(r.date) << "\n  Package: " << r.package_state
          << "; catalog: " << r.signature.state << "; signer: " << printable(r.signature.signer)
          << "\n";
        if (all)
            o << "  Store INF: " << printable(r.store_inf)
              << "\n  Catalog: " << printable(r.catalog) << "\n";
        for (const auto &f : a.findings)
            if (f.driver_id == r.id)
                o << "  [" << f.severity << "] " << f.code << ": " << f.evidence
                  << (f.device_id.empty() ? "" : " Device: " + printable(f.device_id)) << "\n";
        for (const auto &d : a.devices)
            if (d.driver_id == r.id) {
                o << "  Device: " << printable(d.id) << " | " << printable(d.name)
                  << " | present=" << boolean(d.present) << " | problem=" << number(d.problem)
                  << "\n";
                if (all)
                    for (const auto &e : d.errors)
                        o << "    Acquisition: " << e << "\n";
            }
        for (const auto &s : r.services)
            o << "  Service: " << printable(s.name) << " | " << s.state << " | "
              << printable(s.binary) << " | " << s.binary_state << " | " << s.architecture
              << " | embedded signature: " << s.signature.state << "\n";
    }
    if (omitted)
        o << "\n"
          << omitted
          << " driver identities omitted from the focused view; use --all or --json for details.\n";
    for (const auto &w : a.warnings)
        o << "Warning: " << w << "\n";
    o << "\nNo newer-driver comparison is possible offline. Driver age alone is not a "
         "problem.\nTrust uses local offline policy; online revocation and catalog membership are "
         "not established.\nUse --all for all retained device associations; --json for complete "
         "structured evidence.\n";
    return o.str();
}
} // namespace dha
