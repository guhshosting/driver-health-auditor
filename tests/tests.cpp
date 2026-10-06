#include "dha.hpp"
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cstdio>
namespace {
void check(bool ok, const char *message) {
    if (!ok)
        throw std::runtime_error(message);
}
dha::Device device() {
    dha::Device d;
    d.id = L"ROOT\\测试😀\\1";
    d.name = L"Périphérique";
    d.inf = L"oem1.inf";
    d.provider = L"Example";
    d.version = L"1.2.3.4";
    d.date = L"2000-01-01";
    d.present = true;
    d.problem = 0;
    return d;
}
bool has(const dha::Audit &a, const std::string &c) {
    return std::any_of(a.findings.begin(), a.findings.end(),
                       [&](const dha::Finding &f) { return f.code == c; });
}
dha::Audit healthy() {
    dha::Audit a;
    a.native_arch = "x64";
    a.devices.push_back(device());
    dha::correlate(a);
    a.drivers[0].package_state = "available";
    a.drivers[0].signature.state = "trusted_offline";
    return a;
}
} // namespace
int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--json-fixture") {
            auto fixture = healthy();
            fixture.devices[0].name = L"Périphérique \"quoted\"\\\n测试😀";
            fixture.devices[0].problem = 999;
            fixture.devices[0].errors.push_back("\tcontrol\x01");
            fixture.drivers[0].signature.signer = L"签名者";
            dha::findings(fixture);
            std::cout << dha::json(fixture);
            return 0;
        }
        auto a = healthy();
        dha::findings(a);
        check(a.findings.empty(), "healthy old driver should have no findings");
        a.drivers[0].package_provider = L"Other";
        a.drivers[0].package_version = L"01/01/2000,9.9.9.9";
        dha::findings(a);
        check(has(a, "provider_inconsistent") && has(a, "package_version_inconsistent"),
              "package identity inconsistencies");
        a = healthy();
        a.drivers[0].signature.state = "unavailable";
        dha::findings(a);
        check(dha::human(a, false).find("omitted from the focused view") != std::string::npos,
              "optional trust does not dump inventory");
        a = healthy();
        a.devices[0].problem = 28;
        dha::findings(a);
        check(has(a, "pnp_driver_problem"), "driver problem");
        a.devices[0].problem = 999;
        dha::findings(a);
        check(!has(a, "pnp_driver_problem"), "unknown code must not be diagnosed");
        check(dha::json(a).find("999") != std::string::npos, "unknown code preserved");
        a.devices[0].provider.clear();
        dha::findings(a);
        check(has(a, "device_metadata_incomplete"), "missing metadata");
        a = healthy();
        a.devices[0].present.reset();
        a.devices[0].problem.reset();
        a.devices[0].errors.push_back("device disappeared");
        dha::findings(a);
        check(has(a, "device_metadata_incomplete"), "disappearing device");
        a = healthy();
        auto d = device();
        d.id = L"second";
        a.devices.push_back(d);
        dha::correlate(a);
        check(a.drivers.size() == 1 && a.drivers[0].devices.size() == 2, "sharing correlation");
        dha::findings(a);
        check(has(a, "shared_driver"), "shared finding");
        a.devices[1].version = L"9";
        dha::correlate(a);
        dha::findings(a);
        check(a.drivers.size() == 2 && has(a, "device_identity_inconsistent"),
              "conflicting metadata");
        a = healthy();
        dha::Service s;
        s.name = L"driver";
        s.state = "available";
        s.binary_state = "missing";
        a.drivers[0].services.push_back(s);
        dha::findings(a);
        check(has(a, "driver_binary_missing"), "missing binary");
        a.drivers[0].services[0].binary_state = "available";
        a.drivers[0].services[0].architecture = "x86";
        dha::findings(a);
        check(has(a, "architecture_mismatch"), "architecture");
        for (const std::string state : {"trusted_offline", "no_embedded_signature",
                                        "local_trust_failure", "bad_digest", "unavailable"}) {
            a = healthy();
            a.drivers[0].signature.state = state;
            dha::findings(a);
            check(has(a, "local_signature_problem") ==
                      (state == "local_trust_failure" || state == "bad_digest"),
                  "signature classification");
            check(has(a, "trust_unavailable") == (state == "unavailable"), "trust unavailable");
        }
        a = healthy();
        a.drivers[0].signature.signer = L"测试";
        const auto j = dha::json(a);
        check(j.find(dha::utf8(L"测试😀")) != std::string::npos, "unicode JSON");
        a.devices[0].name = L"\"\\\n\x0001";
        check(dha::json(a).find("\\\"\\\\\\n\\u0001") != std::string::npos, "JSON escaping");
        check(dha::human(a, true).find("2000-01-01") != std::string::npos, "human date");
        check(dha::parse({L"--device", L"ROOT\\测试", L"--json"}).json, "CLI valid");
        for (const std::vector<std::wstring> &args :
             std::vector<std::vector<std::wstring>>{{L"--bogus"},
                                                    {L"--device"},
                                                    {L"--all", L"--device", L"x"},
                                                    {L"--json", L"--json"},
                                                    {L"--help", L"--json"}}) {
            bool fail = false;
            try {
                (void)dha::parse(args);
            } catch (const dha::Failure &e) {
                fail = e.exit_code == 2;
            }
            check(fail, "CLI invalid");
        }
        check(!dha::safe_local_path(L"\\\\server\\share\\driver.sys"), "UNC blocked");
        check(!dha::safe_local_path(L"C:\\Windows\\..\\driver.sys"), "traversal blocked");
        check(!dha::safe_local_path(L"C:\\Windows\\driver.sys:stream"), "ADS blocked");
        check(!dha::safe_local_path(L"C:\\nonexistent-dha-parent\\..\\driver.sys"),
              "missing ancestor traversal blocked");
        check(!dha::safe_local_path(L"C:\\Windows\\driver.sys\\"), "trailing separator blocked");
        check(!dha::safe_local_path(L"\\??\\C:\\Windows\\driver.sys"), "raw namespace blocked");
        std::vector<wchar_t> self(32768);
        check(GetModuleFileNameW(nullptr, self.data(), 32768) > 0, "self path");
#if defined(_M_X64)
        check(dha::inspect_pe(self.data()) == "x64", "real PE header inspection");
#elif defined(_M_ARM64)
        check(dha::inspect_pe(self.data()) == "arm64", "real PE header inspection");
#else
        check(dha::inspect_pe(self.data()) == "x86", "real PE header inspection");
#endif
        check(dha::inspect_pe(L"C:\\nonexistent-dha-parent\\driver.sys") == "unknown",
              "missing PE");
        check(dha::inspect_signature(L"\\\\server\\share\\x.sys").state == "unavailable",
              "remote trust refused");
        std::cout << "Synthetic checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    } catch (...) {
        std::fputs("Unexpected test failure\n", stderr);
        return 1;
    }
}
