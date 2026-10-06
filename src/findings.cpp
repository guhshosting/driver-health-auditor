#include "dha.hpp"
#include <map>
#include <set>
namespace dha {
bool driver_problem(unsigned long c) {
    // CM_PROB_* documented driver loading, installation, verification and service failures.
    switch (c) {
    case 2:
    case 3:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 13:
    case 14:
    case 18:
    case 19:
    case 28:
    case 31:
    case 32:
    case 37:
    case 38:
    case 39:
    case 40:
    case 48:
    case 52:
        return true;
    default:
        return false;
    }
}
void findings(Audit &a) {
    a.findings.clear();
    for (const auto &d : a.devices) {
        if (d.problem && driver_problem(*d.problem))
            a.findings.push_back({"pnp_driver_problem", "warning", d.driver_id, d.id,
                                  "Windows reports CM_PROB code " + std::to_string(*d.problem) +
                                      "; this is supporting evidence, not a proven root cause."});
        if (incomplete(d))
            a.findings.push_back({"device_metadata_incomplete", "info", d.driver_id, d.id,
                                  "One or more driver identity or device state properties are "
                                  "unavailable; inspect acquisition_errors."});
    }
    std::map<std::wstring, std::set<std::string>> identities;
    for (const auto &r : a.drivers)
        if (!r.inf.empty())
            identities[lower(r.inf)].insert(r.id);
    for (const auto &r : a.drivers) {
        auto add = [&](const std::string &c, const std::string &s, const std::string &e) {
            a.findings.push_back({c, s, r.id, {}, e});
        };
        if (r.devices.size() > 1)
            add("shared_driver", "info",
                std::to_string(r.devices.size()) +
                    " devices report this driver identity; sharing is normal.");
        if (!r.inf.empty() && identities[lower(r.inf)].size() > 1)
            add("device_identity_inconsistent", "warning",
                "Devices reporting the same published INF report different provider/version/date "
                "identities.");
        if (r.package_state != "available")
            add("package_metadata_unavailable", "info",
                "Installed INF/package metadata could not be fully resolved: " + r.package_state);
        if (!r.package_provider.empty() && !r.provider.empty() &&
            lower(r.package_provider) != lower(r.provider))
            add("provider_inconsistent", "warning",
                "Device provider differs from the INF Version section Provider.");
        const auto comma = r.package_version.find(L',');
        if (comma != std::wstring::npos && !r.version.empty() &&
            r.package_version.substr(comma + 1) != r.version)
            add("package_version_inconsistent", "warning",
                "Device driver version differs from the installed INF DriverVer version field.");
        auto sig = [&](const Signature &s, const std::string &subject) {
            if (s.state == "local_trust_failure" || s.state == "bad_digest")
                add("local_signature_problem", "warning",
                    subject + ": " + s.state + "; WinVerifyTrust status " +
                        (s.status ? std::to_string(*s.status) : "unavailable") +
                        ". Local offline policy only.");
            else if (s.state == "unavailable")
                add("trust_unavailable", "info",
                    subject + ": trust check unavailable. No conclusion about signing or safety.");
        };
        sig(r.signature, "Package catalog signature (does not verify member files)");
        for (const auto &s : r.services) {
            if (s.state != "available")
                add("service_unresolved", "info",
                    "Associated service " + utf8(s.name) + ": " + s.state);
            if (s.binary_state == "missing")
                add("driver_binary_missing", "warning",
                    "SCM driver service " + utf8(s.name) + " resolves to missing local binary " +
                        utf8(s.binary));
            if (s.binary_state == "blocked_path" || s.binary_state == "unavailable")
                add("binary_metadata_unavailable", "info",
                    "Service " + utf8(s.name) + ": binary inspection " + s.binary_state);
            if (s.architecture != "unknown" && !a.native_arch.empty() &&
                a.native_arch != "unknown" && s.architecture != a.native_arch)
                add("architecture_mismatch", "warning",
                    "Driver service " + utf8(s.name) + " PE machine is " + s.architecture +
                        "; native OS architecture is " + a.native_arch + ".");
            if (s.binary_state == "available")
                sig(s.signature, "Service " + utf8(s.name) +
                                     " embedded signature (catalog membership not checked)");
        }
    }
}
} // namespace dha
