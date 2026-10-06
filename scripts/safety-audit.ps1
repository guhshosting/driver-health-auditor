param([string]$Executable = 'build-native/Release/driver-health-auditor.exe')
$ErrorActionPreference = 'Stop'
$files = @(rg --files src include -g '*.cpp' -g '*.hpp')
$source = ($files | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n"
$forbidden = '\b(CreateProcess\w*|ShellExecute\w*|WinExec|system|popen|_wpopen|URLDownload\w*|Internet\w*|WinHttp\w*|WSAStartup|socket|connect|getaddrinfo|DnsQuery\w*|RegSet\w*|RegCreate\w*|RegDelete\w*|SetupCopyOEMInf\w*|SetupUninstallOEMInf\w*|DiInstall\w*|DiUninstall\w*|UpdateDriverForPlugAndPlayDevices\w*|SetupDiCallClassInstaller|SetupDiSet\w*|CM_Disable_DevNode|CM_Enable_DevNode|CM_Reenumerate_DevNode|CM_Set_\w*|StartService\w*|ControlService\w*|ChangeServiceConfig\w*|DeleteService|CreateService\w*|CertAdd\w*|CertDelete\w*)\s*\('
if ($source -match $forbidden) { throw "Forbidden production API: $($Matches[0])" }
$signature = Get-Content src/signature.cpp -Raw
foreach ($flag in @('WTD_CACHE_ONLY_URL_RETRIEVAL', 'WTD_REVOCATION_CHECK_NONE', 'WTD_REVOKE_NONE', 'WTD_UI_NONE', 'WTD_STATEACTION_CLOSE')) {
    if (-not $signature.Contains($flag)) { throw "Trust configuration missing $flag" }
}
$imports = Get-Content artifacts/imports.txt -Raw
if ($imports -match '(?i)\b(winhttp|wininet|ws2_32|dnsapi|urlmon)\.dll\b') { throw 'Direct network import' }
$manifest = Get-Content artifacts/embedded.manifest -Raw
if ($manifest -notmatch 'level="asInvoker"') { throw 'Manifest privilege level' }
if ($manifest -match 'requireAdministrator|highestAvailable') { throw 'Elevation manifest' }
$service = Get-Content src/service.cpp -Raw
if (-not $service.Contains('SC_MANAGER_CONNECT') -or -not $service.Contains('SERVICE_QUERY_CONFIG')) { throw 'SCM read-only access missing' }
if ($source -match '\b(GENERIC_WRITE|FILE_WRITE_DATA|KEY_WRITE|SERVICE_ALL_ACCESS|SC_MANAGER_ALL_ACCESS)\b') { throw 'Production write access mask' }
$report = @(
    'PASS: production source has no subprocess, network or listed mutation API calls.',
    'PASS: direct PE imports contain no WinHTTP, WinINet, Winsock, DNS or URLMon DLL.',
    'PASS: trust uses cache-only retrieval, revocation disabled, no UI and scoped state close.',
    'PASS: embedded production manifest is asInvoker.',
    'PASS: local SCM uses connect/query-config access; file inspection uses read access.',
    'REVIEW: SetupAPI/CfgMgr32 enumeration and installed-INF mapping are read-only calls.',
    'REVIEW: remote/reparse/SUBST paths are rejected before local file inspection.',
    'LIMIT: static source/import/configuration audit; no packet capture or whole-system mutation trace.',
    "SHA256: $((Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash)"
)
$report | Tee-Object artifacts/safety-audit.txt
