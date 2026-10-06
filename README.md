# driver-health-auditor 1.0.0

> Runtime prerequisite for the exact qualified EXE: Microsoft Visual C++ x64 Redistributable is required when the imported runtime DLLs are absent. This supersedes any static-CRT/no-redistributable description of a source build below.


> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A native C++17 Windows command-line auditor for driver identities and their device/service associations. It complements `device-problem-explainer`: the primary records here are drivers, with PnP problem states as supporting evidence. There is no dependency on that utility.

```
driver-health-auditor
driver-health-auditor --all
driver-health-auditor --device "PCI\VEN_1234&DEV_5678\..."
driver-health-auditor --json
driver-health-auditor --help
driver-health-auditor --version
```

Default acquisition examines currently present devices and human output prioritizes warnings, followed by incomplete metadata. `--all` includes retained non-present device records and prints all associations. `--device` selects one exact, case-insensitive instance ID. JSON always contains the full acquired scope, including healthy records. These are device-associated installed packages, not an exhaustive inventory of unreferenced packages staged in the Driver Store. Sharing counts reflect the selected scope. No ambiguous package selector is provided.

Unavailable optional catalog checks and ordinary shared-driver observations alone do not expand the default human report. Their counts and details remain available in JSON and the full inventory. Informational findings describe acquisition limits; warnings describe concrete Windows-reported or locally established evidence.

## Drivers, packages, devices and services

A package has an INF and may have a catalog. A PnP device reports an installed INF, provider, driver version/date and service name. A service is an SCM configuration record; only kernel/filesystem driver service binaries are inspected. A service may be shared across devices or exist without any device represented in this audit. Driver groups use published INF plus reported provider/version/date, so conflicting identities remain visible. IDs are deterministic within a snapshot, not permanent cross-run identifiers.

SetupAPI device properties and CfgMgr32 acquire device evidence. `SetupGetInfDriverStoreLocationW` resolves the installed INF to its supported package location; `SetupOpenInfFileW`, `SetupFindFirstLineW` and `SetupGetStringFieldW` read the INF Version section. There is no Driver Store directory scanning. Package Provider and raw DriverVer are retained separately from device properties. CatalogFile architecture decorations are preferred, then NT and undecorated keys. Absence is reported without inventing data. SCM access is `SC_MANAGER_CONNECT` and `SERVICE_QUERY_CONFIG` only. Device Service is the association evidence; it does not establish every filter-driver relationship.

CM_PROB driver loading, installation and verification codes produce warnings, not root-cause claims. Other codes are retained numerically without guessed explanations. Missing or inaccessible properties produce informational incomplete records. Static PE machine versus native OS architecture can identify a driver binary mismatch. Missing-file warnings require a resolvable driver service image and a file/path-not-found result; access denied is not treated as missing. Unquoted paths are treated as complete file paths, never executable command lines. Only SystemRoot and System32 forms are normalized; arbitrary environment variables are not expanded.

## Signatures and offline trust

`WinVerifyTrust` uses `WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WTD_UI_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`, `WTD_REVOCATION_CHECK_NONE`, `WTD_REVOKE_NONE` and `WTD_DISABLE_MD2_MD4`. The production configuration intentionally prevents trust-provider network retrieval. No online revocation status is established. [Microsoft documents the cache-only flag as necessary to prevent code-signature network retrieval](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

`trusted_offline` means the selected Authenticode policy succeeded using local trust state; it is not a guarantee of safety or Windows kernel load eligibility. `local_trust_failure` means a recognized trust-policy failure, with the raw signed WinVerifyTrust status retained. `bad_digest` records an integrity failure. `no_embedded_signature` means this check found no usable embedded signature; a binary may instead be catalog-signed. `unavailable` means no reliable trust conclusion. Signer display text, when available, comes from the acquired provider state and does not imply trust on its own.

The package check verifies the **catalog's own signature**, not INF or binary catalog membership. Binary checks inspect **embedded signatures only**. No package integrity or complete signing claim is made. Some inbox packages lack a readily resolvable catalog; this is informational. Offline results depend on local certificates, cached data, time and policy. Driver age is reported as a fact and never classified by an arbitrary threshold. The tool cannot know whether a newer driver exists without an authoritative comparison source; it performs no such lookup.

## Safety and privileges

Strictly read-only application behavior: no install, update, removal, rollback, device enable/disable/restart, rescan, SCM modification, Registry write, trust-store modification or reboot. No subprocesses, telemetry, update checks, network APIs or elevation requests. The manifest is `asInvoker`. Normal unelevated execution is supported; denied metadata becomes partial data. Trust libraries may maintain their ordinary Windows-managed local caches; the application does not request trust-store changes.

File inspection accepts local drive-absolute paths and rejects UNC, network drive aliases, SUBST aliases, alternate streams, traversal and reparse components. This also deliberately skips legitimate junction-based configurations. Enumeration and path checking cannot provide an atomic snapshot or eliminate races with concurrent hostile filesystem changes. Run against a stable local system. All handles are scoped; acquisition failures are distinct from findings.

## JSON and exit codes

UTF-8 JSON stdout contains `schema_version` (`1.0`), `application_version`, `host`, `summary`, `drivers`, `devices`, `findings`, `warnings`, and `limitations`. Missing driver/device scalar metadata is `null`; explicit state strings qualify inspection results. Host build text is empty if unavailable. Drivers link to device instance IDs, devices link to driver IDs, and findings link to both when applicable. Problem codes and devnode status are numeric. The [JSON Schema](docs/json-schema.json) defines the contract. Consumers should ignore additional fields within a schema major version. Errors go to stderr; failed audits do not emit a partial success JSON document. Human console output uses Unicode Windows console APIs; redirected output is UTF-8.

Exit codes: 0 completed (even with findings); 2 usage; 3 requested device not found; 4 acquisition failure preventing the requested audit; 5 unexpected internal/output failure. Optional field failures do not make the audit fail.

## Compatibility and build

Intended Windows 10, Windows 11 and corresponding supported Windows Server generations; Windows 8.1 and older are outside scope. MSVC, CMake 3.24+ and Windows SDK are required. Runtime-tested platforms and exact evidence are in [VALIDATION.md](VALIDATION.md); intended compatibility is not a claim of testing every platform.

From an x64 Visual Studio developer shell:

```
cmake -S . -B build -G "Ninja Multi-Config"
cmake --build build --config Debug
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake -S . -B build-analyze -G "Ninja Multi-Config" -DDHA_ANALYZE=ON
cmake --build build-analyze --config Release
cmake -S . -B build-asan -G "Ninja Multi-Config" -DDHA_ASAN=ON
cmake --build build-asan --config RelWithDebInfo
ctest --test-dir build-asan -C RelWithDebInfo --output-on-failure
cmake --install build --config Release --prefix install
```

Visual Studio generators are also supported; select the native platform (for example `-A x64`). Builds must match the native OS architecture to avoid emulated filesystem redirection. `/W4 /WX`, Unicode, C++17 and strict conformance are enabled. `DHA_ANALYZE` adds `/analyze`; `DHA_ASAN` adds MSVC AddressSanitizer, disables incremental linking and copies the matching ASan runtime beside instrumented executables. MSVC ASan validation here uses RelWithDebInfo x64. Normal binaries require the corresponding MSVC C++ runtime.

From a native developer shell, `pwsh -NoProfile -File scripts/build-validation.ps1` reproduces builds, analysis, integration, installation and safety audits, writing logs under `artifacts`. PowerShell is used only to orchestrate development validation; the installed application does not invoke it or any subprocess. Clang-tidy uses the independent Ninja compilation database; Cppcheck covers production and test sources. The integration script independently parses JSON and validates its schema and cross-references. Tests are synthetic and never alter a device. `dha_nonadmin` is an optional validation-only restricted-token launcher, not installed with the application; the recorded primary validation runs use an actual non-administrator token directly.

MIT licensed.
