#include "format_internal.hpp"
#include <sstream>
#include <iterator>
namespace dha {
using namespace format_detail;
std::string json(const Audit &a) {
    std::ostringstream o;
    o << "{\"schema_version\":\"1.0\",\"application_version\":\"" << version
      << "\",\"host\":{\"os_version\":" << q(a.os_version)
      << ",\"native_architecture\":" << q(a.native_arch) << ",\"elevated\":" << boolean(a.elevated)
      << "},\"summary\":{\"devices_examined\":" << a.devices.size()
      << ",\"drivers_correlated\":" << a.drivers.size()
      << ",\"devices_with_driver_problems\":" << count_problem(a)
      << ",\"signature_trust_findings\":" << count_trust(a)
      << ",\"incomplete_records\":" << count_incomplete(a) << ",\"findings\":" << a.findings.size()
      << "},\"drivers\":[";
    bool first = true;
    for (const auto &r : a.drivers) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"id\":" << q(r.id) << ",\"inf\":" << text(r.inf)
          << ",\"provider\":" << text(r.provider) << ",\"version\":" << text(r.version)
          << ",\"date\":" << text(r.date) << ",\"store_inf\":" << text(r.store_inf)
          << ",\"package_state\":" << q(r.package_state)
          << ",\"package_provider\":" << text(r.package_provider)
          << ",\"package_driverver\":" << text(r.package_version)
          << ",\"catalog\":" << text(r.catalog) << ",\"catalog_signature\":" << sig(r.signature)
          << ",\"device_ids\":[";
        for (size_t i = 0; i < r.devices.size(); ++i) {
            if (i)
                o << ',';
            o << q(utf8(r.devices[i]));
        }
        o << "],\"services\":[";
        for (size_t i = 0; i < r.services.size(); ++i) {
            if (i)
                o << ',';
            const auto &s = r.services[i];
            o << "{\"name\":" << text(s.name) << ",\"state\":" << q(s.state)
              << ",\"type\":" << number(s.type) << ",\"start_type\":" << number(s.start)
              << ",\"image_path\":" << text(s.image) << ",\"binary_path\":" << text(s.binary)
              << ",\"binary_state\":" << q(s.binary_state)
              << ",\"architecture\":" << q(s.architecture)
              << ",\"embedded_signature\":" << sig(s.signature) << "}";
        }
        o << "]}";
    }
    o << "],\"devices\":[";
    first = true;
    for (const auto &d : a.devices) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"instance_id\":" << text(d.id) << ",\"driver_id\":" << q(d.driver_id)
          << ",\"name\":" << text(d.name) << ",\"class\":" << text(d.class_name)
          << ",\"service\":" << text(d.service) << ",\"inf\":" << text(d.inf)
          << ",\"provider\":" << text(d.provider) << ",\"version\":" << text(d.version)
          << ",\"date\":" << text(d.date) << ",\"present\":" << boolean(d.present)
          << ",\"problem_code\":" << number(d.problem) << ",\"devnode_status\":" << number(d.status)
          << ",\"acquisition_errors\":[";
        for (size_t i = 0; i < d.errors.size(); ++i) {
            if (i)
                o << ',';
            o << q(d.errors[i]);
        }
        o << "]}";
    }
    o << "],\"findings\":[";
    first = true;
    for (const auto &f : a.findings) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"code\":" << q(f.code) << ",\"severity\":" << q(f.severity)
          << ",\"driver_id\":" << q(f.driver_id) << ",\"device_id\":" << text(f.device_id)
          << ",\"evidence\":" << q(f.evidence) << "}";
    }
    o << "],\"warnings\":[";
    for (size_t i = 0; i < a.warnings.size(); ++i) {
        if (i)
            o << ',';
        o << q(a.warnings[i]);
    }
    o << "],\"limitations\":[";
    for (size_t i = 0; i < limits.size(); ++i) {
        if (i)
            o << ',';
        o << q(limits[i]);
    }
    o << "]}\n";
    return o.str();
}
} // namespace dha
